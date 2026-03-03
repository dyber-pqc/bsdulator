/*
 * lochs export/import - Container filesystem serialization
 *
 * Usage:
 *   lochs export <container> > container.tar
 *   lochs import <file.tar> <name> [-i <image>]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include "bsdulator/lochs.h"

extern lochs_jail_t lochs_jails[];
extern int lochs_jail_count;
#define jails lochs_jails
#define jail_count lochs_jail_count

static void safe_strcpy(char *dst, const char *src, size_t dst_size) {
    if (dst_size == 0) return;
    size_t len = strlen(src);
    if (len >= dst_size) len = dst_size - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/*
 * lochs export <container>
 * Tars the container filesystem to stdout.
 */
int lochs_cmd_export(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: lochs export <container> [> file.tar]\n");
        return 1;
    }

    const char *name = argv[1];
    lochs_jail_t *jail = lochs_jail_find(name);
    if (!jail) {
        fprintf(stderr, "Error: container '%s' not found\n", name);
        return 1;
    }

    if (jail->path[0] == '\0') {
        fprintf(stderr, "Error: container has no filesystem path\n");
        return 1;
    }

    /* Verify path exists */
    struct stat st;
    if (stat(jail->path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: container path '%s' does not exist\n", jail->path);
        return 1;
    }

    /* Write tar to stdout */
    fprintf(stderr, "Exporting container '%s' from %s...\n", name, jail->path);

    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "tar -cf - -C '%s' . 2>/dev/null", jail->path);

    int r = system(cmd);
    if (r != 0) {
        fprintf(stderr, "Error: tar failed\n");
        return 1;
    }

    fprintf(stderr, "Export complete.\n");
    return 0;
}

/*
 * lochs import <file.tar> <name> [-i <image>]
 * Creates a new container from a tar archive.
 */
int lochs_cmd_import(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: lochs import <file.tar> <name> [-i <image>]\n");
        return 1;
    }

    const char *tarfile = argv[1];
    const char *name = argv[2];
    const char *image = "imported";

    /* Parse optional -i flag */
    for (int i = 3; i < argc - 1; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            image = argv[i + 1];
            i++;
        }
    }

    /* Check tar file exists */
    struct stat st;
    if (strcmp(tarfile, "-") != 0 && stat(tarfile, &st) != 0) {
        fprintf(stderr, "Error: file '%s' not found\n", tarfile);
        return 1;
    }

    /* Check name not already taken */
    if (lochs_jail_find(name)) {
        fprintf(stderr, "Error: container '%s' already exists\n", name);
        return 1;
    }

    /* Find a free slot */
    if (jail_count >= LOCHS_MAX_JAILS) {
        fprintf(stderr, "Error: maximum number of containers reached\n");
        return 1;
    }

    /* Create container directory */
    char path[1024];
    snprintf(path, sizeof(path), "/var/lib/lochs/jails/%s", name);

    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", path);
    int r = system(cmd);
    if (r != 0) {
        fprintf(stderr, "Error: failed to create container directory\n");
        return 1;
    }

    /* Extract tar */
    fprintf(stderr, "Importing '%s' as container '%s'...\n", tarfile, name);
    if (strcmp(tarfile, "-") == 0) {
        snprintf(cmd, sizeof(cmd), "tar -xf - -C '%s' 2>/dev/null", path);
    } else {
        snprintf(cmd, sizeof(cmd), "tar -xf '%s' -C '%s' 2>/dev/null", tarfile, path);
    }
    r = system(cmd);
    if (r != 0) {
        fprintf(stderr, "Error: tar extraction failed\n");
        return 1;
    }

    /* Create container entry */
    lochs_jail_t *jail = &jails[jail_count++];
    memset(jail, 0, sizeof(*jail));
    safe_strcpy(jail->name, name, sizeof(jail->name));
    safe_strcpy(jail->path, path, sizeof(jail->path));
    safe_strcpy(jail->image, image, sizeof(jail->image));
    jail->state = JAIL_STATE_CREATED;
    jail->jid = -1;
    jail->created_at = time(NULL);

    lochs_state_save();

    printf("Container '%s' imported successfully from '%s'\n", name, tarfile);
    printf("  Image: %s\n", image);
    printf("  Path:  %s\n", path);
    return 0;
}
