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
 *
 * Every zfs/cp command runs through lochs_run()/lochs_capture() with an
 * argument vector, and every name that becomes part of a dataset is checked
 * by zfs_name_ok() first.
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
#include "bsdulator/lochs_exec.h"

#define ZFS_CONF_PATH "/var/lib/lochs/zfs.conf"
#define ZFS_BASE_DS   "lochs"
#define ZFS_IMAGES_DS "lochs/images"
#define ZFS_CONTAINERS_DS "lochs/containers"
#define ZFS_VOLUMES_DS "lochs/volumes"

static char zfs_pool[256] = {0};

/*
 * A single dataset or snapshot name component: letters, digits, '_', '-',
 * '.', ':' (the characters ZFS allows), not starting with '-' or '.', and
 * never "..". Rejects '/', '@', quotes and whitespace.
 */
static int zfs_name_ok(const char *s) {
    if (!s || !s[0] || s[0] == '-' || s[0] == '.') return 0;
    if (strlen(s) > 200 || strstr(s, "..")) return 0;
    for (const char *p = s; *p; p++) {
        int ok = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                 (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' ||
                 *p == '.' || *p == ':';
        if (!ok) return 0;
    }
    return 1;
}

static int zfs_reject(const char *what, const char *value) {
    fprintf(stderr, "Error: invalid %s '%s' for ZFS\n", what, value ? value : "");
    return -1;
}

/* 0 if the dataset or snapshot exists */
static int zfs_exists(const char *name) {
    const char *argv[] = { "zfs", "list", "-Ho", "name", name, NULL };
    return lochs_run(argv, LOCHS_RUN_QUIET) == 0 ? 0 : -1;
}

/* zfs create [-o mountpoint=<mp>] <dataset> */
static int zfs_create(const char *dataset, const char *mountpoint) {
    if (mountpoint) {
        char opt[600];
        snprintf(opt, sizeof(opt), "mountpoint=%s", mountpoint);
        const char *argv[] = { "zfs", "create", "-o", opt, dataset, NULL };
        return lochs_run(argv, 0);
    }
    const char *argv[] = { "zfs", "create", dataset, NULL };
    return lochs_run(argv, 0);
}

/* zfs clone -o mountpoint=<mp> <origin> <dataset> */
static int zfs_clone(const char *origin, const char *dataset, const char *mountpoint) {
    char opt[600];
    snprintf(opt, sizeof(opt), "mountpoint=%s", mountpoint);
    const char *argv[] = { "zfs", "clone", "-o", opt, origin, dataset, NULL };
    return lochs_run(argv, 0);
}

/*
 * Detect the ZFS pool to use.
 * Priority: LOCHS_ZFS_POOL env > /var/lib/lochs/zfs.conf > auto-detect
 */
const char *lochs_zfs_get_pool(void) {
    if (zfs_pool[0])
        return zfs_pool;

    char candidate[256] = "";

    /* 1. Environment variable */
    const char *env = getenv("LOCHS_ZFS_POOL");
    if (env && env[0]) {
        snprintf(candidate, sizeof(candidate), "%s", env);
    }

    /* 2. Config file */
    if (!candidate[0]) {
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
                    snprintf(candidate, sizeof(candidate), "%s", line + 5);
                    break;
                }
            }
            fclose(f);
        }
    }

    /* 3. Auto-detect: use first pool from zpool list */
    if (!candidate[0]) {
        char buf[1024];
        const char *argv[] = { "zpool", "list", "-Ho", "name", NULL };
        if (lochs_capture_stdout(argv, buf, sizeof(buf)) == 0) {
            buf[strcspn(buf, "\n")] = '\0';
            buf[sizeof(candidate) - 1] = '\0';
            memcpy(candidate, buf, sizeof(candidate));
        }
    }

    if (!candidate[0]) return NULL;
    if (!zfs_name_ok(candidate)) {
        zfs_reject("pool name", candidate);
        return NULL;
    }
    snprintf(zfs_pool, sizeof(zfs_pool), "%s", candidate);
    return zfs_pool;
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

    char ds[512];
    const char *datasets[] = { ZFS_BASE_DS, ZFS_IMAGES_DS, ZFS_CONTAINERS_DS, ZFS_VOLUMES_DS };

    for (int i = 0; i < 4; i++) {
        snprintf(ds, sizeof(ds), "%s/%s", pool, datasets[i]);
        if (zfs_exists(ds) != 0) {
            if (zfs_create(ds, NULL) != 0) {
                fprintf(stderr, "Error: Failed to create ZFS dataset %s\n", ds);
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
    if (!zfs_name_ok(image_name)) return zfs_reject("image name", image_name);

    char dataset[512];
    char mountpoint[512];
    char snapshot[600];

    snprintf(dataset, sizeof(dataset), "%s/%s/%s", pool, ZFS_IMAGES_DS, image_name);
    snprintf(mountpoint, sizeof(mountpoint), "/var/lib/lochs/zfs/images/%s", image_name);

    /* Check if image dataset already exists */
    if (zfs_exists(dataset) == 0) {
        /* Already imported */
        return 0;
    }

    /* Create dataset with explicit mountpoint */
    if (zfs_create(dataset, mountpoint) != 0) {
        fprintf(stderr, "Error: Failed to create image dataset %s\n", dataset);
        return -1;
    }

    /* Copy image contents into the dataset */
    char src_dot[LOCHS_MAX_PATH + 4];
    snprintf(src_dot, sizeof(src_dot), "%s/.", image_path);
    const char *cp_argv[] = { "cp", "-a", src_dot, mountpoint, NULL };
    if (lochs_run(cp_argv, LOCHS_RUN_QUIET) != 0) {
        fprintf(stderr, "Error: Failed to copy image data to %s\n", mountpoint);
        return -1;
    }

    /* Create @base snapshot */
    snprintf(snapshot, sizeof(snapshot), "%s@base", dataset);
    const char *snap_argv[] = { "zfs", "snapshot", snapshot, NULL };
    if (lochs_run(snap_argv, 0) != 0) {
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
    if (!zfs_name_ok(jail->name)) return zfs_reject("container name", jail->name);

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

    snprintf(origin, sizeof(origin), "%s/%s/%s@base", pool, ZFS_IMAGES_DS, image_name);
    snprintf(container_ds, sizeof(container_ds), "%s/%s/%s", pool, ZFS_CONTAINERS_DS, jail->name);
    snprintf(mountpoint, sizeof(mountpoint), "/var/lib/lochs/zfs/containers/%s", jail->name);

    /* Check if container dataset already exists */
    if (zfs_exists(container_ds) == 0) {
        fprintf(stderr, "Error: ZFS dataset already exists for container '%s'\n", jail->name);
        return -1;
    }

    /* Clone from image@base */
    if (zfs_clone(origin, container_ds, mountpoint) != 0) {
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

    const char *argv[] = { "zfs", "mount", jail->zfs_dataset, NULL };
    lochs_run(argv, LOCHS_RUN_QUIET);  /* May already be mounted, that's OK */

    return 0;
}

/*
 * Unmount a ZFS container dataset.
 */
int lochs_zfs_unmount_container(lochs_jail_t *jail) {
    if (!jail->zfs_dataset[0]) return 0;

    const char *argv[] = { "zfs", "unmount", jail->zfs_dataset, NULL };
    lochs_run(argv, LOCHS_RUN_QUIET);

    return 0;
}

/*
 * Destroy a container's ZFS dataset and all its snapshots.
 */
int lochs_zfs_destroy_container(lochs_jail_t *jail) {
    if (!jail->zfs_dataset[0]) return 0;

    /* Unmount first */
    lochs_zfs_unmount_container(jail);

    /* Destroy recursively (includes all snapshots) */
    const char *argv[] = { "zfs", "destroy", "-r", jail->zfs_dataset, NULL };
    if (lochs_run(argv, 0) != 0) {
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
    if (!zfs_name_ok(container)) return zfs_reject("container name", container);
    if (snap_name && snap_name[0] && !zfs_name_ok(snap_name))
        return zfs_reject("snapshot name", snap_name);

    char dataset[512];
    char snapshot[700];
    char name_buf[128];

    snprintf(dataset, sizeof(dataset), "%s/%s/%s", pool, ZFS_CONTAINERS_DS, container);

    /* Verify dataset exists */
    if (zfs_exists(dataset) != 0) {
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

    snprintf(snapshot, sizeof(snapshot), "%s@%s", dataset, snap_name);
    const char *argv[] = { "zfs", "snapshot", snapshot, NULL };
    if (lochs_run(argv, 0) != 0) {
        fprintf(stderr, "Error: Failed to create snapshot %s\n", snapshot);
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
    if (!zfs_name_ok(container)) return zfs_reject("container name", container);

    char dataset[512];

    snprintf(dataset, sizeof(dataset), "%s/%s/%s", pool, ZFS_CONTAINERS_DS, container);

    /* Verify dataset exists */
    if (zfs_exists(dataset) != 0) {
        fprintf(stderr, "Error: No ZFS dataset found for container '%s'\n", container);
        return -1;
    }

    printf("Snapshots for container '%s':\n\n", container);
    printf("%-30s %-22s %-10s %-10s\n", "NAME", "CREATED", "USED", "REFER");
    printf("%-30s %-22s %-10s %-10s\n", "----", "-------", "----", "-----");

    /* List snapshots with relevant properties */
    size_t bufsz = 256 * 1024;
    char *buf = malloc(bufsz);
    if (!buf) return -1;
    const char *argv[] = { "zfs", "list", "-t", "snapshot", "-r", "-Ho",
                           "name,creation,used,refer", dataset, NULL };
    if (lochs_capture_stdout(argv, buf, bufsz) < 0) {
        free(buf);
        return -1;
    }

    int count = 0;
    char *save = NULL;
    for (char *line = strtok_r(buf, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
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
    free(buf);

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
    if (!zfs_name_ok(container)) return zfs_reject("container name", container);
    if (!zfs_name_ok(snap_name)) return zfs_reject("snapshot name", snap_name);

    char snapshot[700];
    snprintf(snapshot, sizeof(snapshot), "%s/%s/%s@%s",
             pool, ZFS_CONTAINERS_DS, container, snap_name);

    const char *argv[] = { "zfs", "destroy", snapshot, NULL };
    if (lochs_run(argv, 0) != 0) {
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
    if (!zfs_name_ok(container)) return zfs_reject("container name", container);
    if (!zfs_name_ok(snap_name)) return zfs_reject("snapshot name", snap_name);

    char snapshot[700];
    snprintf(snapshot, sizeof(snapshot), "%s/%s/%s@%s",
             pool, ZFS_CONTAINERS_DS, container, snap_name);

    /* Verify snapshot exists */
    if (zfs_exists(snapshot) != 0) {
        fprintf(stderr, "Error: Snapshot '%s@%s' does not exist\n", container, snap_name);
        return -1;
    }

    /* Rollback (use -r to destroy newer snapshots) */
    const char *argv[] = { "zfs", "rollback", "-r", snapshot, NULL };
    if (lochs_run(argv, 0) != 0) {
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
    if (!zfs_name_ok(container)) return zfs_reject("container name", container);
    if (!zfs_name_ok(snap1)) return zfs_reject("snapshot name", snap1);
    if (snap2 && snap2[0] && !zfs_name_ok(snap2))
        return zfs_reject("snapshot name", snap2);

    char from[700], to[700];
    snprintf(from, sizeof(from), "%s/%s/%s@%s", pool, ZFS_CONTAINERS_DS, container, snap1);

    size_t bufsz = 4 * 1024 * 1024;
    char *buf = malloc(bufsz);
    if (!buf) return -1;
    int ret;

    if (snap2 && snap2[0]) {
        printf("Changes between %s@%s and %s@%s:\n\n", container, snap1, container, snap2);
        snprintf(to, sizeof(to), "%s/%s/%s@%s", pool, ZFS_CONTAINERS_DS, container, snap2);
        const char *argv[] = { "zfs", "diff", from, to, NULL };
        ret = lochs_capture(argv, buf, bufsz);
    } else {
        printf("Changes since %s@%s:\n\n", container, snap1);
        const char *argv[] = { "zfs", "diff", from, NULL };
        ret = lochs_capture(argv, buf, bufsz);
    }
    if (ret < 0) {
        free(buf);
        return -1;
    }

    int count = 0;
    char *save = NULL;
    for (char *line = strtok_r(buf, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
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
        if (line[0] && line[1] == '\t') {
            printf("  %s %s\n", symbol, line + 2);
        } else {
            printf("  %s\n", line);
        }
        count++;
    }
    free(buf);

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
    if (!zfs_name_ok(src_container)) return zfs_reject("container name", src_container);
    if (!zfs_name_ok(snap_name)) return zfs_reject("snapshot name", snap_name);
    if (!lochs_valid_name(new_name)) return zfs_reject("container name", new_name);

    char src_snap[700];
    char new_ds[512];
    char new_mount[512];

    snprintf(src_snap, sizeof(src_snap), "%s/%s/%s@%s",
             pool, ZFS_CONTAINERS_DS, src_container, snap_name);
    snprintf(new_ds, sizeof(new_ds), "%s/%s/%s",
             pool, ZFS_CONTAINERS_DS, new_name);
    snprintf(new_mount, sizeof(new_mount), "/var/lib/lochs/zfs/containers/%s", new_name);

    /* Verify snapshot exists */
    if (zfs_exists(src_snap) != 0) {
        fprintf(stderr, "Error: Snapshot '%s@%s' does not exist\n", src_container, snap_name);
        return -1;
    }

    /* Check new name doesn't conflict */
    if (zfs_exists(new_ds) == 0) {
        fprintf(stderr, "Error: Container '%s' already exists\n", new_name);
        return -1;
    }

    /* Clone */
    if (zfs_clone(src_snap, new_ds, new_mount) != 0) {
        fprintf(stderr, "Error: Failed to clone %s -> %s\n", src_snap, new_ds);
        return -1;
    }

    printf("Cloned %s@%s -> %s\n", src_container, snap_name, new_name);
    return 0;
}

/*
 * Create a ZFS dataset for a named volume.
 */
int lochs_zfs_volume_create(const char *name) {
    const char *pool = lochs_zfs_get_pool();
    if (!pool) return -1;
    if (!zfs_name_ok(name)) return zfs_reject("volume name", name);

    char dataset[512];
    char mountpoint[512];

    snprintf(dataset, sizeof(dataset), "%s/%s/%s", pool, ZFS_VOLUMES_DS, name);
    snprintf(mountpoint, sizeof(mountpoint), "/var/lib/lochs/zfs/volumes/%s", name);

    /* Check if already exists */
    if (zfs_exists(dataset) == 0) {
        return 0;  /* Already exists */
    }

    /* Ensure parent dataset exists */
    lochs_zfs_init();

    if (zfs_create(dataset, mountpoint) != 0) {
        fprintf(stderr, "Error: Failed to create ZFS volume dataset %s\n", dataset);
        return -1;
    }

    return 0;
}

/*
 * Destroy a ZFS volume dataset.
 */
int lochs_zfs_volume_destroy(const char *name) {
    const char *pool = lochs_zfs_get_pool();
    if (!pool) return -1;
    if (!zfs_name_ok(name)) return zfs_reject("volume name", name);

    char dataset[512];
    snprintf(dataset, sizeof(dataset), "%s/%s/%s", pool, ZFS_VOLUMES_DS, name);

    const char *argv[] = { "zfs", "destroy", dataset, NULL };
    if (lochs_run(argv, 0) != 0) {
        fprintf(stderr, "Warning: Failed to destroy ZFS volume dataset\n");
        return -1;
    }

    return 0;
}
