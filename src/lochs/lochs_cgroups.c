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
#include "bsdulator/lochs.h"

#define CGROUP_BASE     "/sys/fs/cgroup"
#define CGROUP_LOCHS    "/sys/fs/cgroup/lochs"
#define CPU_PERIOD_US   100000  /* 100ms default period */

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
 * Initialize the lochs cgroup parent directory.
 * Enables cpu, memory, pids controllers for child cgroups.
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

    /*
     * Enable controllers in the parent so children can use them.
     * We need to enable them at the root level first, then in our parent.
     *
     * Write to /sys/fs/cgroup/cgroup.subtree_control
     */
    char subtree_path[256];
    snprintf(subtree_path, sizeof(subtree_path),
             "%s/cgroup.subtree_control", CGROUP_BASE);

    /* Try to enable each controller (may already be enabled) */
    /* Ignore errors - controller might already be active or not available */
    FILE *f = fopen(subtree_path, "w");
    if (f) {
        fputs("+cpu +memory +pids", f);
        fclose(f);
    }

    /* Also enable in the lochs parent for child containers */
    snprintf(subtree_path, sizeof(subtree_path),
             "%s/cgroup.subtree_control", CGROUP_LOCHS);
    f = fopen(subtree_path, "w");
    if (f) {
        fputs("+cpu +memory +pids", f);
        fclose(f);
    }

    return 0;
}

/*
 * Create a cgroup for a container
 */
int lochs_cgroup_create(const char *container_name) {
    /* Initialize parent if needed */
    lochs_cgroup_init();

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
 * Destroy a container's cgroup
 * All processes must have exited first.
 */
int lochs_cgroup_destroy(const char *container_name) {
    char cgroup_dir[256];
    snprintf(cgroup_dir, sizeof(cgroup_dir), "%s/%s", CGROUP_LOCHS, container_name);

    /* First, try to kill any remaining processes in the cgroup */
    char procs_path[512];
    snprintf(procs_path, sizeof(procs_path), "%s/%s/cgroup.procs", CGROUP_LOCHS, container_name);

    FILE *f = fopen(procs_path, "r");
    if (f) {
        char line[32];
        while (fgets(line, sizeof(line), f)) {
            pid_t pid = (pid_t)atoi(line);
            if (pid > 0) {
                kill(pid, 9);  /* SIGKILL remaining processes */
            }
        }
        fclose(f);
    }

    /* Wait a moment for processes to exit */
    usleep(100000);  /* 100ms */

    /* Remove the cgroup directory (must be empty of processes) */
    if (rmdir(cgroup_dir) != 0 && errno != ENOENT) {
        /* Try again after a short delay */
        usleep(500000);  /* 500ms */
        if (rmdir(cgroup_dir) != 0 && errno != ENOENT) {
            fprintf(stderr, "Warning: could not remove cgroup '%s': %s\n",
                    cgroup_dir, strerror(errno));
            return -1;
        }
    }

    return 0;
}

/*
 * Apply all configured resource limits for a container.
 * Called during lochs start after cgroup creation.
 * Returns 0 on success, -1 on error.
 */
int lochs_cgroup_apply_limits(lochs_jail_t *jail) {
    int has_limits = (jail->cpus_millicores > 0 ||
                      jail->memory_limit > 0 ||
                      jail->pids_limit > 0 ||
                      jail->cpu_weight > 0);

    if (!has_limits) return 0;

    if (!lochs_cgroup_is_v2()) {
        fprintf(stderr, "Warning: cgroups v2 not available, skipping resource limits\n");
        return -1;
    }

    /* Create the cgroup */
    if (lochs_cgroup_create(jail->name) != 0) {
        fprintf(stderr, "Error: failed to create cgroup for '%s'\n", jail->name);
        return -1;
    }

    printf("  Resource limits:\n");

    /* Apply CPU limits */
    if (jail->cpus_millicores > 0 || jail->cpu_weight > 0) {
        if (lochs_cgroup_set_cpu(jail->name, jail->cpus_millicores, jail->cpu_weight) == 0) {
            if (jail->cpus_millicores > 0) {
                int whole = jail->cpus_millicores / 1000;
                int frac = (jail->cpus_millicores % 1000) / 100;
                if (frac > 0) {
                    printf("    CPU:     %d.%d cores\n", whole, frac);
                } else {
                    printf("    CPU:     %d core%s\n", whole, whole == 1 ? "" : "s");
                }
            }
            if (jail->cpu_weight > 0) {
                printf("    CPU wt:  %d\n", jail->cpu_weight);
            }
        } else {
            fprintf(stderr, "    Warning: failed to set CPU limits\n");
        }
    }

    /* Apply memory limits */
    if (jail->memory_limit > 0) {
        if (lochs_cgroup_set_memory(jail->name, jail->memory_limit,
                                     jail->memory_swap_limit) == 0) {
            /* Human-readable memory display */
            char mem_str[32];
            if (jail->memory_limit >= (int64_t)1024 * 1024 * 1024) {
                snprintf(mem_str, sizeof(mem_str), "%.1fG",
                         (double)jail->memory_limit / (1024.0 * 1024.0 * 1024.0));
            } else if (jail->memory_limit >= 1024 * 1024) {
                snprintf(mem_str, sizeof(mem_str), "%lldM",
                         (long long)(jail->memory_limit / (1024 * 1024)));
            } else if (jail->memory_limit >= 1024) {
                snprintf(mem_str, sizeof(mem_str), "%lldK",
                         (long long)(jail->memory_limit / 1024));
            } else {
                snprintf(mem_str, sizeof(mem_str), "%lldB",
                         (long long)jail->memory_limit);
            }
            printf("    Memory:  %s\n", mem_str);
        } else {
            fprintf(stderr, "    Warning: failed to set memory limits\n");
        }
    }

    /* Apply PID limits */
    if (jail->pids_limit > 0) {
        if (lochs_cgroup_set_pids(jail->name, jail->pids_limit) == 0) {
            printf("    PIDs:    %d max\n", jail->pids_limit);
        } else {
            fprintf(stderr, "    Warning: failed to set PID limit\n");
        }
    }

    jail->cgroup_applied = 1;
    return 0;
}

/*
 * Clean up cgroup for a container.
 * Called during lochs stop.
 */
int lochs_cgroup_cleanup(lochs_jail_t *jail) {
    if (!jail->cgroup_applied) return 0;

    printf("  Cgroup: cleaning up\n");
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
        printf("  No cgroup active (no resource limits configured)\n");
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
        printf("    (none)\n");
    }

    /* Show live stats if container is running and has a cgroup */
    if (jail->state == JAIL_STATE_RUNNING && jail->cgroup_applied) {
        printf("\n  Live Statistics:\n");
        lochs_cgroup_get_stats(jail->name);
    } else if (jail->state == JAIL_STATE_RUNNING) {
        printf("\n  No cgroup active (resource limits not configured)\n");
    } else {
        printf("\n  Container is not running. Start it to see live statistics.\n");
    }

    return 0;
}
