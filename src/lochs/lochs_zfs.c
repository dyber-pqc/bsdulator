/*
 * Lochs ZFS Storage Backend
 *
 * Implements ZFS-based container storage with snapshot, rollback, diff, and clone.
 * Containers with built-in time travel.
 *
 * ZFS dataset hierarchy:
 *   <pool>/lochs/
 *     images/<image_id>/          - One dataset per image, @base snapshot
 *     containers/<name>/          - Cloned from image@base, snapshots here
 *
 * Pool name comes from (in order):
 *   1. LOCHS_ZFS_POOL environment variable
 *   2. /var/lib/lochs/zfs.conf
 *   3. Auto-detect first available pool
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <time.h>
#include "bsdulator/lochs.h"

#define ZFS_CONF_PATH "/var/lib/lochs/zfs.conf"
#define ZFS_BASE_DS   "lochs"
#define ZFS_IMAGES_DS "lochs/images"
#define ZFS_CONTAINERS_DS "lochs/containers"

static char zfs_pool[256] = {0};

/* Run a command and return exit code */
static int zfs_run(const char *cmd) {
    int ret = system(cmd);
    if (ret == -1) return -1;
    return WEXITSTATUS(ret);
}

/* Run a command and capture stdout into buf */
static int zfs_run_capture(const char *cmd, char *buf, size_t bufsz) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;

    size_t total = 0;
    while (total < bufsz - 1) {
        size_t n = fread(buf + total, 1, bufsz - 1 - total, fp);
        if (n == 0) break;
        total += n;
    }
    buf[total] = '\0';

    int status = pclose(fp);
    return WEXITSTATUS(status);
}

/*
 * Detect the ZFS pool to use.
 * Priority: LOCHS_ZFS_POOL env > /var/lib/lochs/zfs.conf > auto-detect
 */
const char *lochs_zfs_get_pool(void) {
    if (zfs_pool[0])
        return zfs_pool;

    /* 1. Environment variable */
    const char *env = getenv("LOCHS_ZFS_POOL");
    if (env && env[0]) {
        snprintf(zfs_pool, sizeof(zfs_pool), "%s", env);
        return zfs_pool;
    }

    /* 2. Config file */
    FILE *f = fopen(ZFS_CONF_PATH, "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            /* Strip newline */
            char *nl = strchr(line, '\n');
            if (nl) *nl = '\0';
            /* Skip comments and empty lines */
            if (line[0] == '#' || line[0] == '\0') continue;
            /* Look for pool= */
            if (strncmp(line, "pool=", 5) == 0 && line[5]) {
                snprintf(zfs_pool, sizeof(zfs_pool), "%s", line + 5);
                fclose(f);
                return zfs_pool;
            }
        }
        fclose(f);
    }

    /* 3. Auto-detect: use first pool from zpool list */
    char buf[512];
    if (zfs_run_capture("zpool list -Ho name 2>/dev/null | head -1", buf, sizeof(buf)) == 0) {
        char *nl = strchr(buf, '\n');
        if (nl) *nl = '\0';
        if (buf[0]) {
            snprintf(zfs_pool, sizeof(zfs_pool), "%s", buf);
            return zfs_pool;
        }
    }

    return NULL;
}

/*
 * Initialize ZFS dataset hierarchy for Lochs.
 * Creates <pool>/lochs, <pool>/lochs/images, <pool>/lochs/containers
 */
int lochs_zfs_init(void) {
    const char *pool = lochs_zfs_get_pool();
    if (!pool) {
        fprintf(stderr, "Error: No ZFS pool found.\n");
        fprintf(stderr, "Set LOCHS_ZFS_POOL or create %s\n", ZFS_CONF_PATH);
        return -1;
    }

    char cmd[512];
    const char *datasets[] = { ZFS_BASE_DS, ZFS_IMAGES_DS, ZFS_CONTAINERS_DS };

    for (int i = 0; i < 3; i++) {
        /* Check if dataset exists */
        snprintf(cmd, sizeof(cmd), "zfs list -Ho name '%s/%s' >/dev/null 2>&1", pool, datasets[i]);
        if (zfs_run(cmd) != 0) {
            /* Create it */
            snprintf(cmd, sizeof(cmd), "zfs create '%s/%s'", pool, datasets[i]);
            if (zfs_run(cmd) != 0) {
                fprintf(stderr, "Error: Failed to create ZFS dataset %s/%s\n", pool, datasets[i]);
                return -1;
            }
        }
    }

    return 0;
}

/*
 * Import an image directory into a ZFS dataset and create @base snapshot.
 * This is called when pulling/building images with ZFS backend active.
 */
int lochs_zfs_import_image(const char *image_path, const char *image_name) {
    const char *pool = lochs_zfs_get_pool();
    if (!pool) return -1;

    char dataset[512];
    char mountpoint[512];
    char cmd[2048];

    snprintf(dataset, sizeof(dataset), "%s/%s/%s", pool, ZFS_IMAGES_DS, image_name);
    snprintf(mountpoint, sizeof(mountpoint), "/var/lib/lochs/zfs/images/%s", image_name);

    /* Check if image dataset already exists */
    snprintf(cmd, sizeof(cmd), "zfs list -Ho name '%s' >/dev/null 2>&1", dataset);
    if (zfs_run(cmd) == 0) {
        /* Already imported */
        return 0;
    }

    /* Create dataset with explicit mountpoint */
    snprintf(cmd, sizeof(cmd),
             "zfs create -o mountpoint='%s' '%s'",
             mountpoint, dataset);
    if (zfs_run(cmd) != 0) {
        fprintf(stderr, "Error: Failed to create image dataset %s\n", dataset);
        return -1;
    }

    /* Copy image contents into the dataset */
    snprintf(cmd, sizeof(cmd), "cp -a '%s'/. '%s'/ 2>/dev/null", image_path, mountpoint);
    if (zfs_run(cmd) != 0) {
        fprintf(stderr, "Error: Failed to copy image data to %s\n", mountpoint);
        return -1;
    }

    /* Create @base snapshot */
    snprintf(cmd, sizeof(cmd), "zfs snapshot '%s@base'", dataset);
    if (zfs_run(cmd) != 0) {
        fprintf(stderr, "Error: Failed to create base snapshot for %s\n", dataset);
        return -1;
    }

    return 0;
}

/*
 * Create a container by cloning an image's @base snapshot.
 */
int lochs_zfs_create_container(lochs_jail_t *jail, const char *image_path) {
    const char *pool = lochs_zfs_get_pool();
    if (!pool) return -1;

    /* Derive image name from image_path (last component) */
    const char *image_name = strrchr(image_path, '/');
    image_name = image_name ? image_name + 1 : image_path;

    /* Import image to ZFS if not already done */
    if (lochs_zfs_import_image(image_path, image_name) != 0) {
        fprintf(stderr, "Error: Failed to import image '%s' to ZFS\n", image_name);
        return -1;
    }

    char origin[512];
    char container_ds[512];
    char mountpoint[512];
    char cmd[2048];

    snprintf(origin, sizeof(origin), "%s/%s/%s@base", pool, ZFS_IMAGES_DS, image_name);
    snprintf(container_ds, sizeof(container_ds), "%s/%s/%s", pool, ZFS_CONTAINERS_DS, jail->name);
    snprintf(mountpoint, sizeof(mountpoint), "/var/lib/lochs/zfs/containers/%s", jail->name);

    /* Check if container dataset already exists */
    snprintf(cmd, sizeof(cmd), "zfs list -Ho name '%s' >/dev/null 2>&1", container_ds);
    if (zfs_run(cmd) == 0) {
        fprintf(stderr, "Error: ZFS dataset already exists for container '%s'\n", jail->name);
        return -1;
    }

    /* Clone from image@base */
    snprintf(cmd, sizeof(cmd),
             "zfs clone -o mountpoint='%s' '%s' '%s'",
             mountpoint, origin, container_ds);
    if (zfs_run(cmd) != 0) {
        fprintf(stderr, "Error: Failed to clone %s -> %s\n", origin, container_ds);
        return -1;
    }

    /* Store ZFS info in jail structure */
    jail->storage_backend = LOCHS_STORAGE_ZFS;
    snprintf(jail->zfs_dataset, sizeof(jail->zfs_dataset), "%s", container_ds);
    snprintf(jail->zfs_mountpoint, sizeof(jail->zfs_mountpoint), "%s", mountpoint);
    snprintf(jail->zfs_origin, sizeof(jail->zfs_origin), "%s", origin);

    /* Also set path and merged_path for compatibility with existing code */
    snprintf(jail->path, sizeof(jail->path), "%s", mountpoint);
    snprintf(jail->merged_path, sizeof(jail->merged_path), "%s", mountpoint);
    snprintf(jail->image_path, sizeof(jail->image_path), "%s", image_path);
    jail->overlay_mounted = 0;

    return 0;
}

/*
 * Mount a ZFS container dataset (ensure it's mounted).
 */
int lochs_zfs_mount_container(lochs_jail_t *jail) {
    if (!jail->zfs_dataset[0]) {
        fprintf(stderr, "Error: No ZFS dataset for container '%s'\n", jail->name);
        return -1;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "zfs mount '%s' 2>/dev/null", jail->zfs_dataset);
    zfs_run(cmd);  /* May already be mounted, that's OK */

    return 0;
}

/*
 * Unmount a ZFS container dataset.
 */
int lochs_zfs_unmount_container(lochs_jail_t *jail) {
    if (!jail->zfs_dataset[0]) return 0;

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "zfs unmount '%s' 2>/dev/null", jail->zfs_dataset);
    zfs_run(cmd);

    return 0;
}

/*
 * Destroy a container's ZFS dataset and all its snapshots.
 */
int lochs_zfs_destroy_container(lochs_jail_t *jail) {
    if (!jail->zfs_dataset[0]) return 0;

    char cmd[512];

    /* Unmount first */
    lochs_zfs_unmount_container(jail);

    /* Destroy recursively (includes all snapshots) */
    snprintf(cmd, sizeof(cmd), "zfs destroy -r '%s'", jail->zfs_dataset);
    if (zfs_run(cmd) != 0) {
        fprintf(stderr, "Warning: Failed to destroy ZFS dataset %s\n", jail->zfs_dataset);
    }

    /* Clear ZFS fields */
    jail->zfs_dataset[0] = '\0';
    jail->zfs_mountpoint[0] = '\0';
    jail->zfs_origin[0] = '\0';

    return 0;
}

/*
 * Create a named snapshot of a container.
 * If snap_name is NULL, generates a timestamp-based name.
 */
int lochs_zfs_snapshot_create(const char *container, const char *snap_name) {
    const char *pool = lochs_zfs_get_pool();
    if (!pool) return -1;

    char dataset[512];
    char cmd[1024];
    char name_buf[128];

    snprintf(dataset, sizeof(dataset), "%s/%s/%s", pool, ZFS_CONTAINERS_DS, container);

    /* Verify dataset exists */
    snprintf(cmd, sizeof(cmd), "zfs list -Ho name '%s' >/dev/null 2>&1", dataset);
    if (zfs_run(cmd) != 0) {
        fprintf(stderr, "Error: No ZFS dataset found for container '%s'\n", container);
        fprintf(stderr, "Is this container using the ZFS storage backend?\n");
        return -1;
    }

    /* Generate name if not provided */
    if (!snap_name || !snap_name[0]) {
        time_t now = time(NULL);
        struct tm *tm = localtime(&now);
        strftime(name_buf, sizeof(name_buf), "snap-%Y%m%d-%H%M%S", tm);
        snap_name = name_buf;
    }

    snprintf(cmd, sizeof(cmd), "zfs snapshot '%s@%s'", dataset, snap_name);
    if (zfs_run(cmd) != 0) {
        fprintf(stderr, "Error: Failed to create snapshot %s@%s\n", dataset, snap_name);
        return -1;
    }

    printf("Created snapshot: %s@%s\n", container, snap_name);
    return 0;
}

/*
 * List all snapshots for a container.
 */
int lochs_zfs_snapshot_list(const char *container) {
    const char *pool = lochs_zfs_get_pool();
    if (!pool) return -1;

    char dataset[512];
    char cmd[1024];

    snprintf(dataset, sizeof(dataset), "%s/%s/%s", pool, ZFS_CONTAINERS_DS, container);

    /* Verify dataset exists */
    snprintf(cmd, sizeof(cmd), "zfs list -Ho name '%s' >/dev/null 2>&1", dataset);
    if (zfs_run(cmd) != 0) {
        fprintf(stderr, "Error: No ZFS dataset found for container '%s'\n", container);
        return -1;
    }

    printf("Snapshots for container '%s':\n\n", container);
    printf("%-30s %-22s %-10s %-10s\n", "NAME", "CREATED", "USED", "REFER");
    printf("%-30s %-22s %-10s %-10s\n", "----", "-------", "----", "-----");

    /* List snapshots with relevant properties */
    snprintf(cmd, sizeof(cmd),
             "zfs list -t snapshot -r -Ho name,creation,used,refer '%s' 2>/dev/null",
             dataset);

    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;

    char line[1024];
    int count = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        /* Parse tab-separated fields: name, creation, used, refer */
        char *name = line;
        char *creation = NULL, *used = NULL, *refer = NULL;

        char *tab = strchr(name, '\t');
        if (tab) { *tab = '\0'; creation = tab + 1; }
        if (creation) { tab = strchr(creation, '\t'); if (tab) { *tab = '\0'; used = tab + 1; } }
        if (used) { tab = strchr(used, '\t'); if (tab) { *tab = '\0'; refer = tab + 1; } }

        /* Extract just the snapshot name (after @) */
        char *at = strchr(name, '@');
        const char *snap = at ? at + 1 : name;

        printf("%-30s %-22s %-10s %-10s\n",
               snap,
               creation ? creation : "-",
               used ? used : "-",
               refer ? refer : "-");
        count++;
    }
    pclose(fp);

    if (count == 0) {
        printf("  (no snapshots)\n");
    }
    printf("\nTotal: %d snapshot(s)\n", count);

    return 0;
}

/*
 * Delete a snapshot.
 */
int lochs_zfs_snapshot_delete(const char *container, const char *snap_name) {
    const char *pool = lochs_zfs_get_pool();
    if (!pool) return -1;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "zfs destroy '%s/%s/%s@%s'",
             pool, ZFS_CONTAINERS_DS, container, snap_name);

    if (zfs_run(cmd) != 0) {
        fprintf(stderr, "Error: Failed to delete snapshot %s@%s\n", container, snap_name);
        return -1;
    }

    printf("Deleted snapshot: %s@%s\n", container, snap_name);
    return 0;
}

/*
 * Rollback a container to a snapshot.
 * WARNING: This destroys all data newer than the snapshot.
 * Container must be stopped.
 */
int lochs_zfs_rollback(const char *container, const char *snap_name) {
    const char *pool = lochs_zfs_get_pool();
    if (!pool) return -1;

    char dataset[512];
    char cmd[1024];

    snprintf(dataset, sizeof(dataset), "%s/%s/%s", pool, ZFS_CONTAINERS_DS, container);

    /* Verify snapshot exists */
    snprintf(cmd, sizeof(cmd), "zfs list -Ho name '%s@%s' >/dev/null 2>&1",
             dataset, snap_name);
    if (zfs_run(cmd) != 0) {
        fprintf(stderr, "Error: Snapshot '%s@%s' does not exist\n", container, snap_name);
        return -1;
    }

    /* Rollback (use -r to destroy newer snapshots) */
    snprintf(cmd, sizeof(cmd), "zfs rollback -r '%s@%s'", dataset, snap_name);
    if (zfs_run(cmd) != 0) {
        fprintf(stderr, "Error: Failed to rollback to %s@%s\n", container, snap_name);
        return -1;
    }

    printf("Rolled back container '%s' to snapshot '%s'\n", container, snap_name);
    printf("Warning: Any snapshots newer than '%s' have been destroyed.\n", snap_name);
    return 0;
}

/*
 * Show differences between a snapshot and current state (or between two snapshots).
 * snap2 can be NULL to diff against current state.
 */
int lochs_zfs_diff(const char *container, const char *snap1, const char *snap2) {
    const char *pool = lochs_zfs_get_pool();
    if (!pool) return -1;

    char dataset[512];
    char cmd[1024];

    snprintf(dataset, sizeof(dataset), "%s/%s/%s", pool, ZFS_CONTAINERS_DS, container);

    if (snap2 && snap2[0]) {
        printf("Changes between %s@%s and %s@%s:\n\n", container, snap1, container, snap2);
        snprintf(cmd, sizeof(cmd), "zfs diff '%s@%s' '%s@%s' 2>&1",
                 dataset, snap1, dataset, snap2);
    } else {
        printf("Changes since %s@%s:\n\n", container, snap1);
        snprintf(cmd, sizeof(cmd), "zfs diff '%s@%s' 2>&1", dataset, snap1);
    }

    /* Stream output directly */
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;

    char line[2048];
    int count = 0;
    while (fgets(line, sizeof(line), fp)) {
        /* zfs diff output format: M\t/path or +\t/path or -\t/path */
        char type = line[0];
        const char *symbol;
        switch (type) {
            case 'M': symbol = "\033[33mM\033[0m"; break;  /* Modified - yellow */
            case '+': symbol = "\033[32m+\033[0m"; break;  /* Added - green */
            case '-': symbol = "\033[31m-\033[0m"; break;  /* Removed - red */
            case 'R': symbol = "\033[34mR\033[0m"; break;  /* Renamed - blue */
            default:  symbol = " "; break;
        }
        /* Print with color-coded type */
        if (line[1] == '\t') {
            printf("  %s %s", symbol, line + 2);
        } else {
            printf("  %s", line);
        }
        count++;
    }
    pclose(fp);

    if (count == 0) {
        printf("  (no changes)\n");
    }
    printf("\n%d change(s)\n", count);

    return 0;
}

/*
 * Clone a container from a snapshot into a new container.
 */
int lochs_zfs_clone(const char *src_container, const char *snap_name, const char *new_name) {
    const char *pool = lochs_zfs_get_pool();
    if (!pool) return -1;

    char src_snap[512];
    char new_ds[512];
    char new_mount[512];
    char cmd[2048];

    snprintf(src_snap, sizeof(src_snap), "%s/%s/%s@%s",
             pool, ZFS_CONTAINERS_DS, src_container, snap_name);
    snprintf(new_ds, sizeof(new_ds), "%s/%s/%s",
             pool, ZFS_CONTAINERS_DS, new_name);
    snprintf(new_mount, sizeof(new_mount), "/var/lib/lochs/zfs/containers/%s", new_name);

    /* Verify snapshot exists */
    snprintf(cmd, sizeof(cmd), "zfs list -Ho name '%s' >/dev/null 2>&1", src_snap);
    if (zfs_run(cmd) != 0) {
        fprintf(stderr, "Error: Snapshot '%s@%s' does not exist\n", src_container, snap_name);
        return -1;
    }

    /* Check new name doesn't conflict */
    snprintf(cmd, sizeof(cmd), "zfs list -Ho name '%s' >/dev/null 2>&1", new_ds);
    if (zfs_run(cmd) == 0) {
        fprintf(stderr, "Error: Container '%s' already exists\n", new_name);
        return -1;
    }

    /* Clone */
    snprintf(cmd, sizeof(cmd),
             "zfs clone -o mountpoint='%s' '%s' '%s'",
             new_mount, src_snap, new_ds);
    if (zfs_run(cmd) != 0) {
        fprintf(stderr, "Error: Failed to clone %s -> %s\n", src_snap, new_ds);
        return -1;
    }

    printf("Cloned %s@%s -> %s\n", src_container, snap_name, new_name);
    return 0;
}
