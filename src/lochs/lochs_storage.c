/*
 * Lochs Storage Management
 * 
 * Implements Copy-on-Write (COW) filesystem for containers using:
 * 1. ZFS (preferred) - if available, uses zfs clone for instant snapshots
 * 2. OverlayFS (fallback) - Linux kernel COW, works on any filesystem
 * 
 * Directory structure:
 *   /var/lib/lochs/
 *   ├── images/           # Base images (read-only)
 *   │   └── <image_id>/
 *   └── containers/       # Per-container storage
 *       └── <name>/
 *           ├── diff/     # Container changes (upperdir)
 *           ├── work/     # OverlayFS work directory
 *           └── merged/   # Combined view (container root)
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <errno.h>
#include "bsdulator/lochs.h"

#define CONTAINERS_DIR "/var/lib/lochs/containers"

/* Helper to safely copy strings */
static void safe_strcpy(char *dst, const char *src, size_t dst_size) {
    if (dst_size == 0) return;
    size_t src_len = strlen(src);
    size_t copy_len = (src_len < dst_size - 1) ? src_len : dst_size - 1;
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
}

/*
 * Check if ZFS is available on this system
 */
int lochs_storage_is_zfs_available(void) {
    /* Check if zfs command exists and works */
    int ret = system("which zfs >/dev/null 2>&1 && zfs list >/dev/null 2>&1");
    return (ret == 0);
}

/*
 * Check if OverlayFS is available
 */
int lochs_storage_is_overlay_available(void) {
    FILE *f = fopen("/proc/filesystems", "r");
    if (!f) return 0;
    
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "overlay")) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

/*
 * Detect which storage backend to use.
 * Priority: LOCHS_STORAGE_BACKEND env > ZFS (if available) > OverlayFS
 */
lochs_storage_backend_t lochs_storage_detect_backend(void) {
    /* Check environment override */
    const char *env = getenv("LOCHS_STORAGE_BACKEND");
    if (env) {
        if (strcasecmp(env, "zfs") == 0)
            return LOCHS_STORAGE_ZFS;
        if (strcasecmp(env, "overlay") == 0 || strcasecmp(env, "overlayfs") == 0)
            return LOCHS_STORAGE_OVERLAY;
    }

    /* Auto-detect: prefer ZFS if available */
    if (lochs_storage_is_zfs_available())
        return LOCHS_STORAGE_ZFS;

    return LOCHS_STORAGE_OVERLAY;
}

/*
 * Initialize storage subsystem
 */
int lochs_storage_init(void) {
    /* Create containers directory */
    mkdir("/var/lib/lochs", 0755);
    mkdir(CONTAINERS_DIR, 0755);

    /* Check what storage backends are available */
    int zfs = lochs_storage_is_zfs_available();
    int overlay = lochs_storage_is_overlay_available();

    if (!zfs && !overlay) {
        fprintf(stderr, "Warning: Neither ZFS nor OverlayFS available.\n");
        fprintf(stderr, "Container filesystem isolation will not work.\n");
        return -1;
    }

    /* Initialize ZFS datasets if ZFS is the active backend */
    if (lochs_storage_detect_backend() == LOCHS_STORAGE_ZFS) {
        if (lochs_zfs_init() != 0) {
            fprintf(stderr, "Warning: ZFS init failed, falling back to OverlayFS.\n");
        }
    }

    return 0;
}

/*
 * Create container storage (COW layer on top of image)
 *
 * Dispatches to ZFS or OverlayFS based on detected backend.
 */
int lochs_storage_create_container(lochs_jail_t *jail, const char *image_path) {
    jail->storage_backend = lochs_storage_detect_backend();

    /* ZFS backend */
    if (jail->storage_backend == LOCHS_STORAGE_ZFS) {
        return lochs_zfs_create_container(jail, image_path);
    }

    /* OverlayFS backend */
    char container_dir[512];
    char cmd[4096];
    int r;

    /* Container storage directory - keep name short */
    snprintf(container_dir, sizeof(container_dir), "%s/%.60s", CONTAINERS_DIR, jail->name);

    /* Store paths in jail structure */
    safe_strcpy(jail->image_path, image_path, sizeof(jail->image_path));

    /* Use safe_strcpy and manual construction to avoid truncation warnings */
    safe_strcpy(jail->diff_path, container_dir, sizeof(jail->diff_path) - 10);
    strcat(jail->diff_path, "/diff");

    safe_strcpy(jail->work_path, container_dir, sizeof(jail->work_path) - 10);
    strcat(jail->work_path, "/work");

    safe_strcpy(jail->merged_path, container_dir, sizeof(jail->merged_path) - 10);
    strcat(jail->merged_path, "/merged");

    jail->overlay_mounted = 0;

    /* Create directory structure */
    snprintf(cmd, sizeof(cmd), "mkdir -p '%s' '%s' '%s'",
             jail->diff_path, jail->work_path, jail->merged_path);
    r = system(cmd);
    if (r != 0) {
        fprintf(stderr, "Error: Failed to create container directories\n");
        return -1;
    }

    /* Update jail->path to point to the merged view */
    safe_strcpy(jail->path, jail->merged_path, sizeof(jail->path));

    return 0;
}

/*
 * Mount the container's filesystem.
 * Dispatches to ZFS or OverlayFS.
 */
int lochs_storage_mount_container(lochs_jail_t *jail) {
    /* ZFS backend */
    if (jail->storage_backend == LOCHS_STORAGE_ZFS) {
        return lochs_zfs_mount_container(jail);
    }

    /* OverlayFS backend */
    char cmd[8192];
    int r;

    if (jail->overlay_mounted) {
        return 0;
    }

    if (!jail->image_path[0] || !jail->diff_path[0]) {
        fprintf(stderr, "Error: Container storage not initialized\n");
        return -1;
    }

    struct stat st;
    if (stat(jail->merged_path, &st) != 0) {
        fprintf(stderr, "Error: Container merged directory doesn't exist: %s\n", jail->merged_path);
        return -1;
    }

    snprintf(cmd, sizeof(cmd),
             "mount -t overlay overlay -o 'lowerdir=%.900s,upperdir=%.900s,workdir=%.900s' '%.900s'",
             jail->image_path, jail->diff_path, jail->work_path, jail->merged_path);

    r = system(cmd);
    if (r != 0) {
        fprintf(stderr, "Error: Failed to mount overlay filesystem\n");
        fprintf(stderr, "Command: %s\n", cmd);
        fprintf(stderr, "Make sure you're running as root and overlay is supported.\n");
        return -1;
    }

    jail->overlay_mounted = 1;
    return 0;
}

/*
 * Unmount the container's filesystem.
 */
int lochs_storage_unmount_container(lochs_jail_t *jail) {
    /* ZFS backend */
    if (jail->storage_backend == LOCHS_STORAGE_ZFS) {
        return lochs_zfs_unmount_container(jail);
    }

    /* OverlayFS backend */
    char cmd[2048];
    int r;

    if (!jail->overlay_mounted) {
        return 0;
    }

    snprintf(cmd, sizeof(cmd), "umount '%s' 2>/dev/null", jail->merged_path);
    r = system(cmd);

    jail->overlay_mounted = 0;

    (void)r;
    return 0;
}

/*
 * Destroy container storage (remove all container-specific data).
 * The base image is NOT touched.
 */
int lochs_storage_destroy_container(lochs_jail_t *jail) {
    /* ZFS backend */
    if (jail->storage_backend == LOCHS_STORAGE_ZFS) {
        return lochs_zfs_destroy_container(jail);
    }

    /* OverlayFS backend */
    char cmd[2048];
    char container_dir[LOCHS_MAX_PATH];
    int r;

    lochs_storage_unmount_container(jail);

    snprintf(container_dir, sizeof(container_dir), "%s/%s", CONTAINERS_DIR, jail->name);

    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", container_dir);
    r = system(cmd);

    jail->image_path[0] = '\0';
    jail->diff_path[0] = '\0';
    jail->work_path[0] = '\0';
    jail->merged_path[0] = '\0';
    jail->overlay_mounted = 0;

    (void)r;
    return 0;
}
