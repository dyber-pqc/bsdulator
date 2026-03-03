/*
 * lochs cp - Copy files between host and container
 *
 * Usage:
 *   lochs cp <container>:<path> <host_path>    (copy from container)
 *   lochs cp <host_path> <container>:<path>    (copy into container)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "bsdulator/lochs.h"

extern lochs_jail_t lochs_jails[];
extern int lochs_jail_count;
#define jails lochs_jails
#define jail_count lochs_jail_count

/* Parse "container:/path" format. Returns 1 if container ref found. */
static int parse_container_path(const char *arg, char *name, size_t name_max,
                                char *path, size_t path_max) {
    const char *colon = strchr(arg, ':');
    if (!colon || colon == arg) return 0;

    /* Check it's not a Windows drive letter like C:\ */
    if (colon == arg + 1) return 0;

    size_t nlen = (size_t)(colon - arg);
    if (nlen >= name_max) nlen = name_max - 1;
    memcpy(name, arg, nlen);
    name[nlen] = '\0';

    const char *p = colon + 1;
    if (*p == '\0') p = "/";
    size_t plen = strlen(p);
    if (plen >= path_max) plen = path_max - 1;
    memcpy(path, p, plen);
    path[plen] = '\0';

    return 1;
}

int lochs_cmd_cp(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: lochs cp <container>:<path> <host_path>\n");
        fprintf(stderr, "       lochs cp <host_path> <container>:<path>\n");
        return 1;
    }

    const char *src = argv[1];
    const char *dst = argv[2];

    char cname[128], cpath[256];
    char resolved_src[1536], resolved_dst[1536];
    int src_is_container = 0, dst_is_container = 0;

    /* Determine direction */
    if (parse_container_path(src, cname, sizeof(cname), cpath, sizeof(cpath))) {
        src_is_container = 1;
    } else if (parse_container_path(dst, cname, sizeof(cname), cpath, sizeof(cpath))) {
        dst_is_container = 1;
    } else {
        fprintf(stderr, "Error: one argument must be in <container>:<path> format\n");
        return 1;
    }

    /* Find the container */
    lochs_jail_t *jail = lochs_jail_find(cname);
    if (!jail) {
        fprintf(stderr, "Error: container '%s' not found\n", cname);
        return 1;
    }

    /* Build the full paths */
    if (src_is_container) {
        snprintf(resolved_src, sizeof(resolved_src), "%s%s%s",
            jail->path, cpath[0] == '/' ? "" : "/", cpath);
        snprintf(resolved_dst, sizeof(resolved_dst), "%s", dst);
    } else {
        snprintf(resolved_src, sizeof(resolved_src), "%s", src);
        snprintf(resolved_dst, sizeof(resolved_dst), "%s%s%s",
            jail->path, cpath[0] == '/' ? "" : "/", cpath);
    }

    /* Check source exists */
    struct stat st;
    if (stat(resolved_src, &st) != 0) {
        fprintf(stderr, "Error: source '%s' not found\n",
            src_is_container ? src : resolved_src);
        return 1;
    }

    /* Copy using cp (preserves attributes, handles directories) */
    char cmd[4096];
    int r;

    if (S_ISDIR(st.st_mode)) {
        snprintf(cmd, sizeof(cmd), "cp -rp '%s' '%s'", resolved_src, resolved_dst);
        r = system(cmd);
    } else {
        /* Ensure parent directory exists for destination */
        snprintf(cmd, sizeof(cmd), "mkdir -p \"$(dirname '%s')\"", resolved_dst);
        r = system(cmd);
        if (r != 0) {
            fprintf(stderr, "Error: failed to create parent directory\n");
            return 1;
        }
        snprintf(cmd, sizeof(cmd), "cp -p '%s' '%s'", resolved_src, resolved_dst);
        r = system(cmd);
    }
    if (r == 0) {
        printf("Copied %s -> %s\n",
            src_is_container ? src : resolved_src,
            dst_is_container ? dst : resolved_dst);
    } else {
        fprintf(stderr, "Error: copy failed\n");
        return 1;
    }

    return 0;
}
