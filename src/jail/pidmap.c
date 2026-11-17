/*
 * pidmap.c - process ids between the host and a container's PID namespace
 * (see include/bsdulator/pidmap.h)
 *
 * /proc/<pid>/status has "NSpid:\t<host> ... <innermost>"; the last value
 * is the id inside the task's own namespace.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "bsdulator/pidmap.h"

/* Innermost NSpid value of host task pid, and how many levels it has */
static pid_t innermost(pid_t pid, int *levels) {
    char path[64], line[256];
    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    pid_t last = -1;
    int n = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "NSpid:", 6) != 0) continue;
        char *p = line + 6, *end;
        for (;;) {
            long v = strtol(p, &end, 10);
            if (end == p) break;
            last = (pid_t)v;
            n++;
            p = end;
        }
        break;
    }
    fclose(f);
    if (levels) *levels = n;
    return last;
}

pid_t pid_to_ns(pid_t host) {
    pid_t v = innermost(host, NULL);
    return v > 0 ? v : host;
}

static int same_pidns(pid_t a, pid_t b) {
    char pa[64], pb[64], la[64] = "", lb[64] = "";
    snprintf(pa, sizeof(pa), "/proc/%d/ns/pid", (int)a);
    snprintf(pb, sizeof(pb), "/proc/%d/ns/pid", (int)b);
    ssize_t na = readlink(pa, la, sizeof(la) - 1);
    ssize_t nb = readlink(pb, lb, sizeof(lb) - 1);
    if (na <= 0 || nb <= 0) return 0;
    la[na] = lb[nb] = '\0';
    return strcmp(la, lb) == 0;
}

pid_t pid_from_ns(pid_t ns, pid_t ref) {
    int levels = 0;
    if (innermost(ref, &levels) < 0 || levels <= 1) return ns;  /* host namespace */
    DIR *d = opendir("/proc");
    if (!d) return -1;
    struct dirent *e;
    pid_t found = -1;
    while (found < 0 && (e = readdir(d))) {
        char *end;
        long h = strtol(e->d_name, &end, 10);
        if (*end || h <= 0 || !same_pidns((pid_t)h, ref)) continue;
        if (innermost((pid_t)h, NULL) == ns) { found = (pid_t)h; break; }
        /* threads are only listed under their process */
        char tdir[64];
        snprintf(tdir, sizeof(tdir), "/proc/%ld/task", h);
        DIR *td = opendir(tdir);
        if (!td) continue;
        struct dirent *te;
        while ((te = readdir(td))) {
            long t = strtol(te->d_name, &end, 10);
            if (*end || t <= 0 || t == h) continue;
            if (innermost((pid_t)t, NULL) == ns) { found = (pid_t)t; break; }
        }
        closedir(td);
    }
    closedir(d);
    return found;
}
