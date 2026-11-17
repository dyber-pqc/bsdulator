/*
 * Lochs Resource Limits - cgroups v2
 *
 * Implements CPU, memory, and PID resource limits for containers
 * using the Linux cgroups v2 unified hierarchy.
 *
 * Cgroup hierarchy:
 *   /sys/fs/cgroup/lochs/              (parent for all containers)
 *   /sys/fs/cgroup/lochs/<name>/       (per-container cgroup)
 *
 * Limits are on by default, so no container (or all of them together)
 * can exhaust the host:
 *   lochs/         memory 3/4 of RAM, swap 1/2 of swap, 3/4 of the
 *                  kernel's thread limit, 90% of all CPUs (set only where
 *                  unset, so an administrator's values stay)
 *   lochs/<name>/  memory 1/2 of RAM and 4096 processes unless set with
 *                  --memory / --pids-limit; CPU shared by weight unless
 *                  --cpus is given
 * The container's holder is put in its cgroup, and every bsdulator run
 * that joins the container (-N) joins it too, so everything running in
 * the container is counted: the tracer, lochs exec, CMD, health checks
 * and build steps.
 *
 * Controllers used:
 *   cpu.max        - CPU bandwidth limit (quota/period microseconds)
 *   cpu.weight     - CPU scheduling weight (1-10000, default 100)
 *   memory.max     - Hard memory limit in bytes
 *   memory.swap.max - Swap limit in bytes
 *   pids.max       - Maximum number of processes
 *
 * Usage:
 *   lochs create myapp -i freebsd:15 --cpus 2 --memory 512m
 *   lochs create myapp -i freebsd:15 --cpus 0.5 --memory 256m --pids-limit 100
 *   lochs stats myapp
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <fcntl.h>
#include "bsdulator/lochs.h"

#define CGROUP_BASE     "/sys/fs/cgroup"
#define CGROUP_LOCHS    "/sys/fs/cgroup/lochs"
#define CPU_PERIOD_US   100000  /* 100ms default period */
#define DEFAULT_PIDS    4096

/* Helper to safely copy strings */
static void safe_strcpy(char *dst, const char *src, size_t dst_size) {
    if (dst_size == 0) return;
    size_t src_len = strlen(src);
    size_t copy_len = (src_len < dst_size - 1) ? src_len : dst_size - 1;
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
}

/*
 * Write a string value to a cgroup file
 */
static int cgroup_write(const char *path, const char *value) {
    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "Error: cannot write to cgroup file '%s': %s\n",
                path, strerror(errno));
        return -1;
    }
    if (fputs(value, f) == EOF) {
        fprintf(stderr, "Error: failed to write '%s' to '%s': %s\n",
                value, path, strerror(errno));
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

/*
 * Read a string value from a cgroup file
 * Returns number of chars read, or -1 on error
 */
static int cgroup_read(const char *path, char *buf, size_t buf_size) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    if (fgets(buf, (int)buf_size, f) == NULL) {
        fclose(f);
        return -1;
    }
    fclose(f);

    /* Strip trailing newline */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
        len--;
    }
    return (int)len;
}

/* Write without complaint (optional controllers, best effort) */
static int cgroup_write_quiet(const char *path, const char *value) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = write(fd, value, strlen(value));
    close(fd);
    return n == (ssize_t)strlen(value) ? 0 : -1;
}

/* A /proc/meminfo field in bytes, or 0 */
static int64_t meminfo_bytes(const char *key) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return 0;
    char line[256];
    size_t kl = strlen(key);
    int64_t v = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, key, kl) == 0 && line[kl] == ':') {
            v = (int64_t)atoll(line + kl + 1) * 1024;
            break;
        }
    }
    fclose(f);
    return v;
}

static long read_long(const char *path) {
    char buf[64];
    if (cgroup_read(path, buf, sizeof(buf)) <= 0) return 0;
    return atol(buf);
}

/* The default memory limit of one container: half the host's RAM */
int64_t lochs_cgroup_default_memory(void) {
    return meminfo_bytes("MemTotal") / 2;
}

int lochs_cgroup_default_pids(void) {
    return DEFAULT_PIDS;
}

/* Set an aggregate limit on lochs/ unless one is set already */
static void parent_limit(const char *file, const char *value) {
    char path[256], cur[64];
    snprintf(path, sizeof(path), "%s/%s", CGROUP_LOCHS, file);
    if (cgroup_read(path, cur, sizeof(cur)) > 0 && strncmp(cur, "max", 3) == 0)
        cgroup_write_quiet(path, value);
}

/*
 * Check if cgroups v2 (unified hierarchy) is available
 */
int lochs_cgroup_is_v2(void) {
    struct stat st;

    /* Check for cgroup2 mount at /sys/fs/cgroup */
    if (stat(CGROUP_BASE "/cgroup.controllers", &st) == 0) {
        return 1;
    }

    /* Alternative: check /proc/mounts for cgroup2 */
    FILE *f = fopen("/proc/mounts", "r");
    if (!f) return 0;

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "cgroup2") && strstr(line, "/sys/fs/cgroup")) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

/*
 * Initialize the lochs cgroup parent directory: cpu, memory and pids for
 * its children, and the aggregate limits for all containers together.
 */
int lochs_cgroup_init(void) {
    if (!lochs_cgroup_is_v2()) {
        fprintf(stderr, "Warning: cgroups v2 not available, resource limits disabled\n");
        return -1;
    }

    /* Create the lochs parent cgroup */
    if (mkdir(CGROUP_LOCHS, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "Error: cannot create cgroup directory '%s': %s\n",
                CGROUP_LOCHS, strerror(errno));
        return -1;
    }

    /* Controllers one at a time: one the kernel lacks must not stop the
     * others (each may already be on) */
    static const char *ctl[] = { "+cpu", "+memory", "+pids", NULL };
    for (int i = 0; ctl[i]; i++) {
        cgroup_write_quiet(CGROUP_BASE "/cgroup.subtree_control", ctl[i]);
        cgroup_write_quiet(CGROUP_LOCHS "/cgroup.subtree_control", ctl[i]);
    }

    /* All containers together */
    char v[64];
    int64_t mem = meminfo_bytes("MemTotal");
    if (mem > 0) {
        snprintf(v, sizeof(v), "%lld", (long long)(mem / 4 * 3));
        parent_limit("memory.max", v);
    }
    int64_t swap = meminfo_bytes("SwapTotal");
    snprintf(v, sizeof(v), "%lld", (long long)(swap / 2));
    parent_limit("memory.swap.max", v);
    long threads = read_long("/proc/sys/kernel/threads-max");
    long pid_max = read_long("/proc/sys/kernel/pid_max");
    if (pid_max > 0 && (threads <= 0 || pid_max < threads)) threads = pid_max;
    if (threads > 0) {
        snprintf(v, sizeof(v), "%ld", threads / 4 * 3);
        parent_limit("pids.max", v);
    }
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu > 0) {
        snprintf(v, sizeof(v), "%ld %d", ncpu * CPU_PERIOD_US / 10 * 9, CPU_PERIOD_US);
        parent_limit("cpu.max", v);
    }
    return 0;
}

/*
 * Create a cgroup for a container
 */
int lochs_cgroup_create(const char *container_name) {
    if (lochs_cgroup_init() != 0) return -1;

    char cgroup_dir[512];
    snprintf(cgroup_dir, sizeof(cgroup_dir), "%s/%s", CGROUP_LOCHS, container_name);

    if (mkdir(cgroup_dir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "Error: cannot create cgroup '%s': %s\n",
                cgroup_dir, strerror(errno));
        return -1;
    }

    return 0;
}

/*
 * A container's cgroup with its limits; 0 means the default for each
 * (memory: half the RAM; pids: 4096; CPU: no cap, weight 100). swap as
 * for lochs_cgroup_set_memory when memory is given, else no own limit
 * (the aggregate one applies).
 */
int lochs_cgroup_setup(const char *name, int millicores, int weight,
                       int64_t memory, int64_t swap, int pids) {
    if (lochs_cgroup_create(name) != 0) return -1;
    char path[512], v[64];

    int rc = 0;
    if (lochs_cgroup_set_cpu(name, millicores, weight > 0 ? weight : 100) != 0) rc = -1;

    if (memory > 0) {
        if (lochs_cgroup_set_memory(name, memory, swap) != 0) rc = -1;
    } else {
        snprintf(path, sizeof(path), "%s/%s/memory.max", CGROUP_LOCHS, name);
        snprintf(v, sizeof(v), "%lld", (long long)lochs_cgroup_default_memory());
        if (lochs_cgroup_default_memory() <= 0 || cgroup_write(path, v) != 0) rc = -1;
        snprintf(path, sizeof(path), "%s/%s/memory.swap.max", CGROUP_LOCHS, name);
        cgroup_write_quiet(path, "max");
    }

    if (lochs_cgroup_set_pids(name, pids > 0 ? pids : DEFAULT_PIDS) != 0) rc = -1;
    return rc;
}

/*
 * Put the calling process in a container's cgroup (its children follow).
 * 0 if it has none (cgroups unavailable).
 */
int lochs_cgroup_join(const char *name) {
    char path[512], v[32];
    struct stat st;
    snprintf(path, sizeof(path), "%s/%s", CGROUP_LOCHS, name);
    if (stat(path, &st) != 0) return 0;
    snprintf(path, sizeof(path), "%s/%s/cgroup.procs", CGROUP_LOCHS, name);
    snprintf(v, sizeof(v), "%d", (int)getpid());
    return cgroup_write_quiet(path, v);
}

/*
 * Set CPU limits for a container
 *
 * millicores: CPU limit in millicores (1000 = 1 CPU, 500 = 0.5 CPU)
 *             0 = no limit (writes "max" to cpu.max)
 * weight:     CPU scheduling weight 1-10000 (0 = use default 100)
 */
int lochs_cgroup_set_cpu(const char *container_name, int millicores, int weight) {
    char path[512];
    char value[64];

    /* Set CPU bandwidth limit */
    snprintf(path, sizeof(path), "%s/%s/cpu.max", CGROUP_LOCHS, container_name);

    if (millicores > 0) {
        /* Convert millicores to quota/period
         * 1000 millicores = 1 CPU = 100000us quota / 100000us period
         * 2000 millicores = 2 CPUs = 200000us quota / 100000us period
         * 500 millicores = 0.5 CPU = 50000us quota / 100000us period
         */
        int quota = (millicores * CPU_PERIOD_US) / 1000;
        if (quota < 1000) quota = 1000;  /* Minimum 1ms */
        snprintf(value, sizeof(value), "%d %d", quota, CPU_PERIOD_US);
    } else {
        safe_strcpy(value, "max 100000", sizeof(value));
    }

    if (cgroup_write(path, value) != 0) {
        return -1;
    }

    /* Set CPU weight (scheduling priority) */
    if (weight > 0) {
        if (weight < 1) weight = 1;
        if (weight > 10000) weight = 10000;

        snprintf(path, sizeof(path), "%s/%s/cpu.weight", CGROUP_LOCHS, container_name);
        snprintf(value, sizeof(value), "%d", weight);
        cgroup_write(path, value);  /* Non-fatal if fails */
    }

    return 0;
}

/*
 * Set memory limits for a container
 *
 * limit: memory limit in bytes (0 = unlimited)
 * swap:  swap limit in bytes (0 = no swap, -1 = same as memory limit)
 */
int lochs_cgroup_set_memory(const char *container_name, int64_t limit, int64_t swap) {
    char path[512];
    char value[64];

    /* Set memory limit */
    snprintf(path, sizeof(path), "%s/%s/memory.max", CGROUP_LOCHS, container_name);

    if (limit > 0) {
        snprintf(value, sizeof(value), "%lld", (long long)limit);
    } else {
        safe_strcpy(value, "max", sizeof(value));
    }

    if (cgroup_write(path, value) != 0) {
        return -1;
    }

    /* Set swap limit */
    snprintf(path, sizeof(path), "%s/%s/memory.swap.max", CGROUP_LOCHS, container_name);

    if (swap == -1 && limit > 0) {
        /* Same as memory limit */
        snprintf(value, sizeof(value), "%lld", (long long)limit);
    } else if (swap > 0) {
        snprintf(value, sizeof(value), "%lld", (long long)swap);
    } else if (limit > 0) {
        /* Default: no swap when memory limit is set */
        safe_strcpy(value, "0", sizeof(value));
    } else {
        safe_strcpy(value, "max", sizeof(value));
    }

    /* Non-fatal if swap controller not available */
    cgroup_write(path, value);

    return 0;
}

/*
 * Set PID limit for a container
 *
 * limit: max number of processes (0 = unlimited)
 */
int lochs_cgroup_set_pids(const char *container_name, int limit) {
    char path[512];
    char value[64];

    snprintf(path, sizeof(path), "%s/%s/pids.max", CGROUP_LOCHS, container_name);

    if (limit > 0) {
        snprintf(value, sizeof(value), "%d", limit);
    } else {
        safe_strcpy(value, "max", sizeof(value));
    }

    return cgroup_write(path, value);
}

/*
 * Add a process to a container's cgroup
 */
int lochs_cgroup_add_pid(const char *container_name, pid_t pid) {
    char path[512];
    char value[32];

    snprintf(path, sizeof(path), "%s/%s/cgroup.procs", CGROUP_LOCHS, container_name);
    snprintf(value, sizeof(value), "%d", pid);

    return cgroup_write(path, value);
}

/*
 * Destroy a container's cgroup, ending anything left in it.
 */
int lochs_cgroup_destroy(const char *container_name) {
    char cgroup_dir[256];
    snprintf(cgroup_dir, sizeof(cgroup_dir), "%s/%s", CGROUP_LOCHS, container_name);
    struct stat st;
    if (stat(cgroup_dir, &st) != 0) return 0;

    /* cgroup.kill (5.14+) ends every process in it at once; else one by one */
    char path[512];
    snprintf(path, sizeof(path), "%s/cgroup.kill", cgroup_dir);
    if (cgroup_write_quiet(path, "1") != 0) {
        snprintf(path, sizeof(path), "%s/cgroup.procs", cgroup_dir);
        FILE *f = fopen(path, "r");
        if (f) {
            char line[32];
            while (fgets(line, sizeof(line), f)) {
                pid_t pid = (pid_t)atoi(line);
                if (pid > 0) kill(pid, SIGKILL);
            }
            fclose(f);
        }
    }

    /* Removable once the last process is gone */
    for (int i = 0; i < 100; i++) {
        if (rmdir(cgroup_dir) == 0 || errno == ENOENT) return 0;
        usleep(20000);
    }
    fprintf(stderr, "Warning: could not remove cgroup '%s': %s\n",
            cgroup_dir, strerror(errno));
    return -1;
}

/*
 * Apply the container's resource limits: the ones it was created with,
 * defaults for the rest. Called during lochs start, before its namespaces
 * are made (the holder joins the cgroup). Returns 0 on success, -1 on
 * error.
 */
int lochs_cgroup_apply_limits(lochs_jail_t *jail) {
    if (!lochs_cgroup_is_v2()) {
        fprintf(stderr, "Warning: cgroups v2 not available, no resource limits for '%s'\n",
                jail->name);
        return -1;
    }

    if (lochs_cgroup_setup(jail->name, jail->cpus_millicores, jail->cpu_weight,
                           jail->memory_limit, jail->memory_swap_limit,
                           jail->pids_limit) != 0) {
        fprintf(stderr, "Warning: resource limits for '%s' are incomplete\n", jail->name);
    }

    char mem_str[32];
    int64_t mem = jail->memory_limit > 0 ? jail->memory_limit : lochs_cgroup_default_memory();
    if (mem >= (int64_t)1024 * 1024 * 1024)
        snprintf(mem_str, sizeof(mem_str), "%.1fG", (double)mem / (1024.0 * 1024.0 * 1024.0));
    else
        snprintf(mem_str, sizeof(mem_str), "%lldM", (long long)(mem / (1024 * 1024)));
    printf("Resource limits: memory %s%s, %d processes%s",
           mem_str, jail->memory_limit > 0 ? "" : " (default)",
           jail->pids_limit > 0 ? jail->pids_limit : DEFAULT_PIDS,
           jail->pids_limit > 0 ? "" : " (default)");
    if (jail->cpus_millicores > 0)
        printf(", CPU %d.%d", jail->cpus_millicores / 1000, (jail->cpus_millicores % 1000) / 100);
    if (jail->cpu_weight > 0)
        printf(", CPU weight %d", jail->cpu_weight);
    printf("\n");

    jail->cgroup_applied = 1;
    return 0;
}

/*
 * Clean up cgroup for a container.
 * Called during lochs stop.
 */
int lochs_cgroup_cleanup(lochs_jail_t *jail) {
    lochs_cgroup_destroy(jail->name);
    jail->cgroup_applied = 0;

    return 0;
}

/*
 * Format bytes as a human-readable string
 */
static void format_bytes(int64_t bytes, char *buf, size_t buf_size) {
    if (bytes < 0) {
        safe_strcpy(buf, "N/A", buf_size);
    } else if (bytes >= (int64_t)1024 * 1024 * 1024) {
        snprintf(buf, buf_size, "%.1f GiB",
                 (double)bytes / (1024.0 * 1024.0 * 1024.0));
    } else if (bytes >= 1024 * 1024) {
        snprintf(buf, buf_size, "%.1f MiB", (double)bytes / (1024.0 * 1024.0));
    } else if (bytes >= 1024) {
        snprintf(buf, buf_size, "%.1f KiB", (double)bytes / 1024.0);
    } else {
        snprintf(buf, buf_size, "%lld B", (long long)bytes);
    }
}

/*
 * Display live cgroup statistics for a container
 */
int lochs_cgroup_get_stats(const char *container_name) {
    char path[512];
    char buf[256];

    /* Check if cgroup exists */
    snprintf(path, sizeof(path), "%s/%s", CGROUP_LOCHS, container_name);
    struct stat st;
    if (stat(path, &st) != 0) {
        printf("  No cgroup (cgroups v2 unavailable)\n");
        return 0;
    }

    printf("  Resource Usage:\n");

    /* CPU stats */
    snprintf(path, sizeof(path), "%s/%s/cpu.stat", CGROUP_LOCHS, container_name);
    FILE *f = fopen(path, "r");
    if (f) {
        int64_t usage_usec = 0;
        int64_t user_usec = 0;
        int64_t system_usec = 0;
        int nr_periods = 0;
        int nr_throttled = 0;
        int64_t throttled_usec = 0;

        while (fgets(buf, sizeof(buf), f)) {
            if (strncmp(buf, "usage_usec ", 11) == 0) {
                usage_usec = atoll(buf + 11);
            } else if (strncmp(buf, "user_usec ", 10) == 0) {
                user_usec = atoll(buf + 10);
            } else if (strncmp(buf, "system_usec ", 12) == 0) {
                system_usec = atoll(buf + 12);
            } else if (strncmp(buf, "nr_periods ", 11) == 0) {
                nr_periods = atoi(buf + 11);
            } else if (strncmp(buf, "nr_throttled ", 13) == 0) {
                nr_throttled = atoi(buf + 13);
            } else if (strncmp(buf, "throttled_usec ", 15) == 0) {
                throttled_usec = atoll(buf + 15);
            }
        }
        fclose(f);

        printf("    CPU total:     %.3f sec\n", (double)usage_usec / 1000000.0);
        printf("    CPU user:      %.3f sec\n", (double)user_usec / 1000000.0);
        printf("    CPU system:    %.3f sec\n", (double)system_usec / 1000000.0);
        if (nr_periods > 0) {
            printf("    Periods:       %d (throttled: %d, %.1f%%)\n",
                   nr_periods, nr_throttled,
                   nr_periods > 0 ? (100.0 * nr_throttled / nr_periods) : 0.0);
            printf("    Throttled:     %.3f sec\n", (double)throttled_usec / 1000000.0);
        }
    }

    /* CPU limit */
    snprintf(path, sizeof(path), "%s/%s/cpu.max", CGROUP_LOCHS, container_name);
    if (cgroup_read(path, buf, sizeof(buf)) > 0) {
        printf("    CPU limit:     %s\n", buf);
    }

    /* Memory stats */
    snprintf(path, sizeof(path), "%s/%s/memory.current", CGROUP_LOCHS, container_name);
    if (cgroup_read(path, buf, sizeof(buf)) > 0) {
        int64_t mem_current = atoll(buf);
        char mem_str[32];
        format_bytes(mem_current, mem_str, sizeof(mem_str));
        printf("    Memory used:   %s\n", mem_str);
    }

    snprintf(path, sizeof(path), "%s/%s/memory.max", CGROUP_LOCHS, container_name);
    if (cgroup_read(path, buf, sizeof(buf)) > 0) {
        if (strcmp(buf, "max") == 0) {
            printf("    Memory limit:  unlimited\n");
        } else {
            int64_t mem_max = atoll(buf);
            char mem_str[32];
            format_bytes(mem_max, mem_str, sizeof(mem_str));
            printf("    Memory limit:  %s\n", mem_str);

            /* Calculate percentage */
            snprintf(path, sizeof(path), "%s/%s/memory.current",
                     CGROUP_LOCHS, container_name);
            if (cgroup_read(path, buf, sizeof(buf)) > 0) {
                int64_t mem_current = atoll(buf);
                if (mem_max > 0) {
                    printf("    Memory %%:      %.1f%%\n",
                           100.0 * (double)mem_current / (double)mem_max);
                }
            }
        }
    }

    /* Memory swap */
    snprintf(path, sizeof(path), "%s/%s/memory.swap.current", CGROUP_LOCHS, container_name);
    if (cgroup_read(path, buf, sizeof(buf)) > 0) {
        int64_t swap_current = atoll(buf);
        char swap_str[32];
        format_bytes(swap_current, swap_str, sizeof(swap_str));
        printf("    Swap used:     %s\n", swap_str);
    }

    /* Memory peak (if available, Linux 5.19+) */
    snprintf(path, sizeof(path), "%s/%s/memory.peak", CGROUP_LOCHS, container_name);
    if (cgroup_read(path, buf, sizeof(buf)) > 0) {
        int64_t mem_peak = atoll(buf);
        char peak_str[32];
        format_bytes(mem_peak, peak_str, sizeof(peak_str));
        printf("    Memory peak:   %s\n", peak_str);
    }

    /* OOM events */
    snprintf(path, sizeof(path), "%s/%s/memory.events", CGROUP_LOCHS, container_name);
    f = fopen(path, "r");
    if (f) {
        int oom_count = 0;
        int oom_kill_count = 0;
        while (fgets(buf, sizeof(buf), f)) {
            if (strncmp(buf, "oom ", 4) == 0) {
                oom_count = atoi(buf + 4);
            } else if (strncmp(buf, "oom_kill ", 9) == 0) {
                oom_kill_count = atoi(buf + 9);
            }
        }
        fclose(f);
        if (oom_count > 0 || oom_kill_count > 0) {
            printf("    OOM events:    %d (kills: %d)\n", oom_count, oom_kill_count);
        }
    }

    /* PID stats */
    snprintf(path, sizeof(path), "%s/%s/pids.current", CGROUP_LOCHS, container_name);
    if (cgroup_read(path, buf, sizeof(buf)) > 0) {
        printf("    PIDs current:  %s\n", buf);
    }

    snprintf(path, sizeof(path), "%s/%s/pids.max", CGROUP_LOCHS, container_name);
    if (cgroup_read(path, buf, sizeof(buf)) > 0) {
        printf("    PIDs limit:    %s\n", buf);
    }

    /* Process list */
    snprintf(path, sizeof(path), "%s/%s/cgroup.procs", CGROUP_LOCHS, container_name);
    f = fopen(path, "r");
    if (f) {
        int proc_count = 0;
        printf("    Processes:     ");
        while (fgets(buf, sizeof(buf), f)) {
            int pid = atoi(buf);
            if (pid > 0) {
                if (proc_count > 0) printf(", ");
                if (proc_count >= 10) {
                    printf("...");
                    break;
                }
                printf("%d", pid);
                proc_count++;
            }
        }
        if (proc_count == 0) printf("(none)");
        printf("\n");
        fclose(f);
    }

    return 0;
}

/*
 * Parse a memory size string with optional suffix
 * Supports: k/K (KiB), m/M (MiB), g/G (GiB), t/T (TiB)
 * Also supports: kb, mb, gb (case-insensitive)
 * Returns bytes, or -1 on error
 */
int64_t lochs_parse_memory_size(const char *str) {
    if (!str || !str[0]) return -1;

    char *endptr = NULL;
    double val = strtod(str, &endptr);

    if (endptr == str || val < 0) return -1;

    int64_t multiplier = 1;

    if (endptr && *endptr) {
        char suffix = (char)tolower((unsigned char)*endptr);
        switch (suffix) {
            case 'k':
                multiplier = 1024;
                break;
            case 'm':
                multiplier = 1024LL * 1024;
                break;
            case 'g':
                multiplier = 1024LL * 1024 * 1024;
                break;
            case 't':
                multiplier = 1024LL * 1024 * 1024 * 1024;
                break;
            case 'b':
                multiplier = 1;  /* bytes */
                break;
            default:
                return -1;  /* Unknown suffix */
        }
    }

    int64_t result = (int64_t)(val * (double)multiplier);
    if (result <= 0) return -1;

    return result;
}

/*
 * Parse a CPU count string (e.g., "2", "0.5", "1.5")
 * Returns millicores (1000 = 1 CPU), or -1 on error
 */
int lochs_parse_cpus(const char *str) {
    if (!str || !str[0]) return -1;

    char *endptr = NULL;
    double val = strtod(str, &endptr);

    if (endptr == str || val <= 0 || val > 1024) return -1;

    /* Convert to millicores */
    int millicores = (int)(val * 1000.0);
    if (millicores < 1) millicores = 1;

    return millicores;
}

/*
 * lochs stats <name>
 *
 * Show live resource usage statistics for a container.
 */
int lochs_cmd_stats(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: lochs stats <container>\n\n");
        printf("Show live resource usage for a container.\n");
        printf("Resource limits are set with --cpus, --memory, --pids-limit\n");
        printf("during 'lochs create'.\n");
        return 1;
    }

    const char *name = argv[1];

    /* Find the container */
    lochs_jail_t *jail = lochs_jail_find(name);
    if (!jail) {
        fprintf(stderr, "Error: container '%s' not found\n", name);
        return 1;
    }

    printf("Container: %s\n", jail->name);
    printf("Status:    %s\n",
           jail->state == JAIL_STATE_RUNNING ? "running" :
           jail->state == JAIL_STATE_CREATED ? "created" : "stopped");

    /* Show configured limits */
    printf("\n  Configured Limits:\n");
    int has_limits = 0;

    if (jail->cpus_millicores > 0) {
        int whole = jail->cpus_millicores / 1000;
        int frac = (jail->cpus_millicores % 1000) / 100;
        if (frac > 0) {
            printf("    CPU:         %d.%d cores\n", whole, frac);
        } else {
            printf("    CPU:         %d core%s\n", whole, whole == 1 ? "" : "s");
        }
        has_limits = 1;
    }

    if (jail->cpu_weight > 0) {
        printf("    CPU weight:  %d\n", jail->cpu_weight);
        has_limits = 1;
    }

    if (jail->memory_limit > 0) {
        char mem_str[32];
        format_bytes(jail->memory_limit, mem_str, sizeof(mem_str));
        printf("    Memory:      %s\n", mem_str);
        has_limits = 1;
    }

    if (jail->memory_swap_limit > 0) {
        char swap_str[32];
        format_bytes(jail->memory_swap_limit, swap_str, sizeof(swap_str));
        printf("    Swap:        %s\n", swap_str);
        has_limits = 1;
    } else if (jail->memory_swap_limit == -1 && jail->memory_limit > 0) {
        printf("    Swap:        same as memory\n");
        has_limits = 1;
    }

    if (jail->pids_limit > 0) {
        printf("    PIDs:        %d max\n", jail->pids_limit);
        has_limits = 1;
    }

    if (!has_limits) {
        printf("    (none set: defaults apply)\n");
    }

    /* Show live stats if container is running and has a cgroup */
    if (jail->state == JAIL_STATE_RUNNING) {
        printf("\n  Live Statistics:\n");
        lochs_cgroup_get_stats(jail->name);
    } else {
        printf("\n  Container is not running. Start it to see live statistics.\n");
    }

    return 0;
}
