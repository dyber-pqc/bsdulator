/*
 * Lochs Named Volume Management
 *
 * Implements Docker-like named volumes for persistent container storage.
 * Named volumes are stored at /var/lib/lochs/volumes/<name>/ and persist
 * across container lifecycle. ZFS-backed volumes use <pool>/lochs/volumes/<name>.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include "bsdulator/lochs.h"

/* Global named volume list */
static lochs_named_volume_t volumes[LOCHS_MAX_NAMED_VOLUMES];
static int volume_count = 0;

#define VOLUME_STATE_FILE "/var/lib/lochs/volumes.dat"
#define VOLUME_BASE_DIR   "/var/lib/lochs/volumes"

/* Helper to safely copy strings */
static void safe_strcpy(char *dst, const char *src, size_t dst_size) {
    if (dst_size == 0) return;
    size_t src_len = strlen(src);
    size_t copy_len = (src_len < dst_size - 1) ? src_len : dst_size - 1;
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
}

/*
 * Validate volume name: only [a-zA-Z0-9_-] allowed
 */
static int validate_volume_name(const char *name) {
    if (!name || !name[0]) return 0;
    if (strlen(name) >= LOCHS_VOLUME_NAME_MAX) return 0;

    for (const char *p = name; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-') {
            return 0;
        }
    }
    return 1;
}

/*
 * Load volume state from disk
 */
int lochs_volumes_load(void) {
    FILE *f = fopen(VOLUME_STATE_FILE, "rb");
    if (!f) return 0;

    size_t r = fread(&volume_count, sizeof(volume_count), 1, f);
    if (r != 1) {
        fclose(f);
        volume_count = 0;
        return -1;
    }

    if (volume_count > LOCHS_MAX_NAMED_VOLUMES) {
        volume_count = LOCHS_MAX_NAMED_VOLUMES;
    }

    r = fread(volumes, sizeof(lochs_named_volume_t), (size_t)volume_count, f);
    if (r != (size_t)volume_count) {
        fclose(f);
        volume_count = 0;
        return -1;
    }

    fclose(f);
    return 0;
}

/*
 * Save volume state to disk
 */
int lochs_volumes_save(void) {
    mkdir("/var/lib/lochs", 0755);

    FILE *f = fopen(VOLUME_STATE_FILE, "wb");
    if (!f) {
        perror("Failed to save volume state");
        return -1;
    }

    fwrite(&volume_count, sizeof(volume_count), 1, f);
    fwrite(volumes, sizeof(lochs_named_volume_t), (size_t)volume_count, f);
    fclose(f);

    return 0;
}

/*
 * Find a named volume by name
 */
lochs_named_volume_t *lochs_volume_find(const char *name) {
    for (int i = 0; i < volume_count; i++) {
        if (volumes[i].active && strcmp(volumes[i].name, name) == 0) {
            return &volumes[i];
        }
    }
    return NULL;
}

/*
 * Get the host path for a named volume
 * Returns NULL if volume doesn't exist
 */
const char *lochs_volume_get_path(const char *name) {
    lochs_named_volume_t *vol = lochs_volume_find(name);
    if (!vol) return NULL;
    return vol->path;
}

/*
 * Check if a named volume is in use by any container
 */
int lochs_volume_is_in_use(const char *name) {
    extern lochs_jail_t lochs_jails[];
    extern int lochs_jail_count;

    for (int i = 0; i < lochs_jail_count; i++) {
        for (int j = 0; j < lochs_jails[i].volume_count; j++) {
            if (strcmp(lochs_jails[i].volumes[j].volume_name, name) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

/*
 * Create a new named volume
 */
int lochs_volume_create(const char *name) {
    if (!validate_volume_name(name)) {
        fprintf(stderr, "Error: invalid volume name '%s'\n", name);
        fprintf(stderr, "  Names must contain only [a-zA-Z0-9_-]\n");
        return -1;
    }

    if (lochs_volume_find(name)) {
        fprintf(stderr, "Error: volume '%s' already exists\n", name);
        return -1;
    }

    if (volume_count >= LOCHS_MAX_NAMED_VOLUMES) {
        fprintf(stderr, "Error: maximum number of volumes reached (%d)\n",
                LOCHS_MAX_NAMED_VOLUMES);
        return -1;
    }

    lochs_named_volume_t *vol = &volumes[volume_count];
    memset(vol, 0, sizeof(*vol));

    safe_strcpy(vol->name, name, sizeof(vol->name));
    vol->created_at = time(NULL);
    vol->active = 1;

    /* Determine storage path */
    if (lochs_storage_detect_backend() == LOCHS_STORAGE_ZFS) {
        /* Try to create ZFS dataset */
        if (lochs_zfs_volume_create(name) == 0) {
            const char *pool = lochs_zfs_get_pool();
            snprintf(vol->zfs_dataset, sizeof(vol->zfs_dataset),
                     "%s/lochs/volumes/%s", pool, name);
            snprintf(vol->path, sizeof(vol->path),
                     "/var/lib/lochs/zfs/volumes/%s", name);
        } else {
            /* Fall back to directory-based */
            snprintf(vol->path, sizeof(vol->path), "%s/%s", VOLUME_BASE_DIR, name);
        }
    } else {
        snprintf(vol->path, sizeof(vol->path), "%s/%s", VOLUME_BASE_DIR, name);
    }

    /* Create directory if not ZFS-backed */
    if (!vol->zfs_dataset[0]) {
        char cmd[2048];
        snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", vol->path);
        if (system(cmd) != 0) {
            fprintf(stderr, "Error: failed to create volume directory '%s'\n", vol->path);
            return -1;
        }
    }

    volume_count++;
    lochs_volumes_save();

    printf("Created volume '%s'\n", name);
    printf("  Path:   %s\n", vol->path);
    if (vol->zfs_dataset[0]) {
        printf("  Driver: zfs (%s)\n", vol->zfs_dataset);
    } else {
        printf("  Driver: local\n");
    }

    return 0;
}

/*
 * Remove a named volume
 */
int lochs_volume_remove(const char *name) {
    lochs_named_volume_t *vol = lochs_volume_find(name);
    if (!vol) {
        fprintf(stderr, "Error: volume '%s' not found\n", name);
        return -1;
    }

    /* Check if any containers are using this volume */
    if (lochs_volume_is_in_use(name)) {
        fprintf(stderr, "Error: volume '%s' is in use by a container\n", name);
        fprintf(stderr, "  Stop and remove the container first.\n");

        /* List which containers use it */
        extern lochs_jail_t lochs_jails[];
        extern int lochs_jail_count;
        for (int i = 0; i < lochs_jail_count; i++) {
            for (int j = 0; j < lochs_jails[i].volume_count; j++) {
                if (strcmp(lochs_jails[i].volumes[j].volume_name, name) == 0) {
                    fprintf(stderr, "  Used by: %s\n", lochs_jails[i].name);
                }
            }
        }
        return -1;
    }

    /* Destroy ZFS dataset if applicable */
    if (vol->zfs_dataset[0]) {
        lochs_zfs_volume_destroy(name);
    } else {
        /* Remove directory */
        char cmd[2048];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", vol->path);
        int r = system(cmd);
        (void)r;
    }

    /* Mark as inactive */
    vol->active = 0;

    /* Compact the array */
    for (int i = 0; i < volume_count; i++) {
        if (!volumes[i].active) {
            memmove(&volumes[i], &volumes[i+1],
                    (size_t)(volume_count - i - 1) * sizeof(lochs_named_volume_t));
            volume_count--;
            i--;
        }
    }

    lochs_volumes_save();
    printf("Removed volume '%s'\n", name);

    return 0;
}

/*
 * List all named volumes
 */
int lochs_volume_list(void) {
    printf("%-20s %-8s %-10s %s\n", "NAME", "DRIVER", "SIZE", "CREATED");
    printf("%-20s %-8s %-10s %s\n", "----", "------", "----", "-------");

    for (int i = 0; i < volume_count; i++) {
        if (volumes[i].active) {
            /* Get volume size using du */
            char size_str[32] = "N/A";
            char cmd[2048];
            snprintf(cmd, sizeof(cmd), "du -sh '%s' 2>/dev/null | cut -f1", volumes[i].path);
            FILE *p = popen(cmd, "r");
            if (p) {
                if (fgets(size_str, sizeof(size_str), p)) {
                    /* Strip newline */
                    char *nl = strchr(size_str, '\n');
                    if (nl) *nl = '\0';
                }
                pclose(p);
            }

            /* Format creation time */
            char time_str[64];
            struct tm *tm = localtime(&volumes[i].created_at);
            if (tm) {
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", tm);
            } else {
                safe_strcpy(time_str, "unknown", sizeof(time_str));
            }

            const char *driver = volumes[i].zfs_dataset[0] ? "zfs" : "local";

            printf("%-20s %-8s %-10s %s\n",
                   volumes[i].name,
                   driver,
                   size_str,
                   time_str);
        }
    }

    if (volume_count == 0) {
        printf("No volumes. Run 'lochs volume create <name>' to create one.\n");
    }

    return 0;
}

/*
 * Inspect a named volume (detailed info)
 */
static int lochs_volume_inspect(const char *name) {
    lochs_named_volume_t *vol = lochs_volume_find(name);
    if (!vol) {
        fprintf(stderr, "Error: volume '%s' not found\n", name);
        return -1;
    }

    /* Format creation time */
    char time_str[64];
    struct tm *tm = localtime(&vol->created_at);
    if (tm) {
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);
    } else {
        safe_strcpy(time_str, "unknown", sizeof(time_str));
    }

    /* Get volume size */
    char size_str[32] = "N/A";
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "du -sh '%s' 2>/dev/null | cut -f1", vol->path);
    FILE *p = popen(cmd, "r");
    if (p) {
        if (fgets(size_str, sizeof(size_str), p)) {
            char *nl = strchr(size_str, '\n');
            if (nl) *nl = '\0';
        }
        pclose(p);
    }

    printf("Name:       %s\n", vol->name);
    printf("Driver:     %s\n", vol->zfs_dataset[0] ? "zfs" : "local");
    printf("Path:       %s\n", vol->path);
    if (vol->zfs_dataset[0]) {
        printf("ZFS:        %s\n", vol->zfs_dataset);
    }
    printf("Size:       %s\n", size_str);
    printf("Created:    %s\n", time_str);

    /* List containers using this volume */
    extern lochs_jail_t lochs_jails[];
    extern int lochs_jail_count;
    int used = 0;

    printf("Used by:\n");
    for (int i = 0; i < lochs_jail_count; i++) {
        for (int j = 0; j < lochs_jails[i].volume_count; j++) {
            if (strcmp(lochs_jails[i].volumes[j].volume_name, name) == 0) {
                printf("  - %s (-> %s%s)\n",
                       lochs_jails[i].name,
                       lochs_jails[i].volumes[j].container_path,
                       lochs_jails[i].volumes[j].readonly ? " ro" : "");
                used++;
            }
        }
    }
    if (!used) {
        printf("  (none)\n");
    }

    return 0;
}

/*
 * lochs volume command handler
 *
 * Usage:
 *   lochs volume create <name>
 *   lochs volume rm <name>
 *   lochs volume ls
 *   lochs volume inspect <name>
 */
int lochs_cmd_volume(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: lochs volume <command> [options]\n\n");
        printf("Commands:\n");
        printf("  create <name>    Create a named volume\n");
        printf("  rm <name>        Remove a named volume\n");
        printf("  ls               List named volumes\n");
        printf("  inspect <name>   Show volume details\n");
        printf("\nNamed volumes provide persistent storage for containers.\n");
        printf("Use -v <name>:/path when creating a container to attach a volume.\n");
        printf("\nExamples:\n");
        printf("  lochs volume create mydata\n");
        printf("  lochs volume ls\n");
        printf("  lochs create myapp -v mydata:/app/data\n");
        return 1;
    }

    /* Load volume state */
    lochs_volumes_load();

    const char *command = argv[1];

    if (strcmp(command, "create") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: volume name required\n");
            return 1;
        }
        return lochs_volume_create(argv[2]) == 0 ? 0 : 1;

    } else if (strcmp(command, "rm") == 0 || strcmp(command, "remove") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: volume name required\n");
            return 1;
        }
        return lochs_volume_remove(argv[2]) == 0 ? 0 : 1;

    } else if (strcmp(command, "ls") == 0 || strcmp(command, "list") == 0) {
        return lochs_volume_list();

    } else if (strcmp(command, "inspect") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: volume name required\n");
            return 1;
        }
        return lochs_volume_inspect(argv[2]) == 0 ? 0 : 1;

    } else {
        fprintf(stderr, "Unknown volume command: %s\n", command);
        return 1;
    }
}
