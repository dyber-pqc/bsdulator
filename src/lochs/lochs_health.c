/*
 * Lochs Health Check Monitor
 *
 * Implements Docker-style health checks for FreeBSD jails.
 * The monitor runs as a forked background process, periodically
 * executing a health command inside the jail via bsdulator jexec.
 *
 * Status is persisted to /var/lib/lochs/health/<name>.status
 * as a simple key=value text file (avoids corrupting jails.dat).
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>
#include "bsdulator/lochs.h"

#define HEALTH_DIR "/var/lib/lochs/health"
#define MAX_HEALTH_RESTARTS 5   /* Cap auto-restarts to prevent infinite loops */

/* Safe string copy */
static void safe_strcpy(char *dst, const char *src, size_t dst_size) {
    if (dst_size == 0) return;
    size_t len = strlen(src);
    if (len >= dst_size) len = dst_size - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/* ─── State string conversion ─── */

const char *lochs_health_state_str(lochs_health_state_t state) {
    switch (state) {
        case HEALTH_HEALTHY:   return "healthy";
        case HEALTH_UNHEALTHY: return "unhealthy";
        case HEALTH_STARTING:  return "starting";
        default:               return "none";
    }
}

static lochs_health_state_t parse_health_state(const char *s) {
    if (strcmp(s, "healthy") == 0)   return HEALTH_HEALTHY;
    if (strcmp(s, "unhealthy") == 0) return HEALTH_UNHEALTHY;
    if (strcmp(s, "starting") == 0)  return HEALTH_STARTING;
    return HEALTH_NONE;
}

/* ─── Status file I/O ─── */

/*
 * Write health status to /var/lib/lochs/health/<name>.status
 * Uses atomic write (write to .tmp, rename) to prevent partial reads.
 */
static int health_status_write(const char *container_name,
                               lochs_health_state_t state,
                               int consecutive_failures,
                               time_t last_check,
                               const char *last_output,
                               int total_checks,
                               int total_failures,
                               int restart_count) {
    /* Ensure directory exists */
    mkdir("/var/lib/lochs", 0755);
    mkdir(HEALTH_DIR, 0755);

    char path[512];
    char tmp_path[520];
    snprintf(path, sizeof(path), "%s/%s.status", HEALTH_DIR, container_name);
    snprintf(tmp_path, sizeof(tmp_path), "%s/.%s.status.tmp", HEALTH_DIR, container_name);

    FILE *f = fopen(tmp_path, "w");
    if (!f) return -1;

    fprintf(f, "state=%s\n", lochs_health_state_str(state));
    fprintf(f, "consecutive_failures=%d\n", consecutive_failures);
    fprintf(f, "last_check=%ld\n", (long)last_check);
    fprintf(f, "last_output=%s\n", last_output ? last_output : "");
    fprintf(f, "total_checks=%d\n", total_checks);
    fprintf(f, "total_failures=%d\n", total_failures);
    fprintf(f, "restart_count=%d\n", restart_count);
    fclose(f);

    /* Atomic rename */
    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

/*
 * Read health status from file. All out-params are nullable.
 * Returns 0 on success, -1 if file doesn't exist.
 */
int lochs_health_status_read(const char *container_name,
                             lochs_health_state_t *state,
                             int *consecutive_failures,
                             time_t *last_check,
                             char *last_output, size_t output_size,
                             int *total_checks,
                             int *total_failures,
                             int *restart_count) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.status", HEALTH_DIR, container_name);

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        /* Remove trailing newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';

        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line;
        char *value = eq + 1;

        if (strcmp(key, "state") == 0 && state) {
            *state = parse_health_state(value);
        } else if (strcmp(key, "consecutive_failures") == 0 && consecutive_failures) {
            *consecutive_failures = atoi(value);
        } else if (strcmp(key, "last_check") == 0 && last_check) {
            *last_check = (time_t)atol(value);
        } else if (strcmp(key, "last_output") == 0 && last_output) {
            safe_strcpy(last_output, value, output_size);
        } else if (strcmp(key, "total_checks") == 0 && total_checks) {
            *total_checks = atoi(value);
        } else if (strcmp(key, "total_failures") == 0 && total_failures) {
            *total_failures = atoi(value);
        } else if (strcmp(key, "restart_count") == 0 && restart_count) {
            *restart_count = atoi(value);
        }
    }

    fclose(f);
    return 0;
}

/* Remove status and PID files for a container */
static void health_cleanup_files(const char *container_name) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.status", HEALTH_DIR, container_name);
    unlink(path);
    snprintf(path, sizeof(path), "%s/%s.pid", HEALTH_DIR, container_name);
    unlink(path);
}

/* ─── Health check execution ─── */

/* SIGALRM handler for timeout */
static volatile sig_atomic_t check_timed_out = 0;

static void alarm_handler(int sig) {
    (void)sig;
    check_timed_out = 1;
}

/*
 * Execute a health check command inside the jail.
 * Uses popen() to capture output. Enforces timeout via alarm().
 * Returns exit code: 0 = healthy, non-zero = unhealthy.
 */
static int health_exec_check(const lochs_jail_t *jail,
                             char *output, size_t output_size) {
    char cmd[4096];

    /* Build jexec command through bsdulator */
    if (jail->netns[0]) {
        snprintf(cmd, sizeof(cmd),
            "./bsdulator --netns %s %s/libexec/ld-elf.so.1 %s/usr/sbin/jexec %s /bin/sh -c '%s' 2>&1",
            jail->netns, jail->path, jail->path, jail->name, jail->healthcheck.cmd);
    } else {
        snprintf(cmd, sizeof(cmd),
            "./bsdulator %s/libexec/ld-elf.so.1 %s/usr/sbin/jexec %s /bin/sh -c '%s' 2>&1",
            jail->path, jail->path, jail->name, jail->healthcheck.cmd);
    }

    /* Set up timeout */
    check_timed_out = 0;
    struct sigaction sa, old_sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alarm_handler;
    sa.sa_flags = 0;
    sigaction(SIGALRM, &sa, &old_sa);
    alarm((unsigned)jail->healthcheck.timeout);

    /* Execute and capture output */
    FILE *p = popen(cmd, "r");
    if (!p) {
        alarm(0);
        sigaction(SIGALRM, &old_sa, NULL);
        if (output && output_size > 0)
            safe_strcpy(output, "popen failed", output_size);
        return 1;
    }

    /* Read output */
    if (output && output_size > 0) {
        output[0] = '\0';
        size_t total = 0;
        char buf[256];
        while (fgets(buf, sizeof(buf), p) && !check_timed_out) {
            size_t blen = strlen(buf);
            if (total + blen < output_size - 1) {
                memcpy(output + total, buf, blen);
                total += blen;
                output[total] = '\0';
            }
        }
        /* Trim trailing newline */
        if (total > 0 && output[total - 1] == '\n') {
            output[total - 1] = '\0';
        }
    } else {
        /* Drain pipe */
        char buf[256];
        while (fgets(buf, sizeof(buf), p) && !check_timed_out) {}
    }

    int status = pclose(p);
    alarm(0);
    sigaction(SIGALRM, &old_sa, NULL);

    if (check_timed_out) {
        if (output && output_size > 0)
            safe_strcpy(output, "health check timed out", output_size);
        return 1;
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return 1;
}

/* ─── Auto-restart ─── */

/*
 * Restart a container by invoking lochs stop + lochs start.
 * Uses system() so each invocation loads fresh state.
 */
static int health_restart_container(const char *container_name) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "lochs stop %s && lochs start %s",
             container_name, container_name);
    int ret = system(cmd);
    return WIFEXITED(ret) ? WEXITSTATUS(ret) : -1;
}

/* ─── Monitor loop (runs in forked child) ─── */

static volatile sig_atomic_t monitor_running = 1;

static void monitor_sigterm(int sig) {
    (void)sig;
    monitor_running = 0;
}

static void health_monitor_loop(const lochs_jail_t *jail) {
    /* Detach from parent */
    setsid();

    /* Set up signal handling */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = monitor_sigterm;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    /* Write PID file */
    {
        char pid_path[512];
        snprintf(pid_path, sizeof(pid_path), "%s/%s.pid", HEALTH_DIR, jail->name);
        FILE *pf = fopen(pid_path, "w");
        if (pf) {
            fprintf(pf, "%d\n", getpid());
            fclose(pf);
        }
    }

    int consecutive_failures = 0;
    int total_checks = 0;
    int total_failures = 0;
    int restart_count = 0;

    /* Start-period grace window */
    if (jail->healthcheck.start_period > 0) {
        health_status_write(jail->name, HEALTH_STARTING, 0, time(NULL),
                           "waiting for start period", 0, 0, 0);

        /* Sleep in small increments so we can respond to SIGTERM */
        int remaining = jail->healthcheck.start_period;
        while (remaining > 0 && monitor_running) {
            int chunk = remaining > 5 ? 5 : remaining;
            sleep((unsigned)chunk);
            remaining -= chunk;
        }
    }

    /* Main health check loop */
    while (monitor_running) {
        /* Sleep between checks (in small increments for SIGTERM responsiveness) */
        int remaining = jail->healthcheck.interval;
        while (remaining > 0 && monitor_running) {
            int chunk = remaining > 5 ? 5 : remaining;
            sleep((unsigned)chunk);
            remaining -= chunk;
        }

        if (!monitor_running) break;

        /* Execute health check */
        char output[512] = "";
        int result = health_exec_check(jail, output, sizeof(output));
        total_checks++;

        if (result == 0) {
            /* Healthy */
            consecutive_failures = 0;
            health_status_write(jail->name, HEALTH_HEALTHY, 0,
                               time(NULL), output, total_checks, total_failures,
                               restart_count);
        } else {
            /* Failed */
            consecutive_failures++;
            total_failures++;

            if (consecutive_failures >= jail->healthcheck.retries) {
                /* Unhealthy — threshold reached */
                health_status_write(jail->name, HEALTH_UNHEALTHY,
                                   consecutive_failures, time(NULL), output,
                                   total_checks, total_failures, restart_count);

                if (restart_count < MAX_HEALTH_RESTARTS) {
                    /* Auto-restart */
                    restart_count++;
                    health_restart_container(jail->name);
                    consecutive_failures = 0;

                    /* Re-enter start period after restart */
                    if (jail->healthcheck.start_period > 0) {
                        health_status_write(jail->name, HEALTH_STARTING, 0,
                                           time(NULL), "restarted, waiting",
                                           total_checks, total_failures,
                                           restart_count);
                        remaining = jail->healthcheck.start_period;
                        while (remaining > 0 && monitor_running) {
                            int chunk = remaining > 5 ? 5 : remaining;
                            sleep((unsigned)chunk);
                            remaining -= chunk;
                        }
                    }
                }
                /* else: stay unhealthy, keep checking but don't restart */
            } else {
                /* Accumulating failures but not yet at threshold */
                health_status_write(jail->name, HEALTH_HEALTHY,
                                   consecutive_failures, time(NULL), output,
                                   total_checks, total_failures, restart_count);
            }
        }
    }

    /* Cleanup on exit */
    {
        char pid_path[512];
        snprintf(pid_path, sizeof(pid_path), "%s/%s.pid", HEALTH_DIR, jail->name);
        unlink(pid_path);
    }

    _exit(0);
}

/* ─── Public API ─── */

/*
 * Start the health monitor for a container.
 * Forks a child process that runs health_monitor_loop().
 */
int lochs_health_monitor_start(lochs_jail_t *jail) {
    if (!jail->healthcheck.enabled || !jail->healthcheck.cmd[0]) {
        return -1;
    }

    /* Ensure health directory exists */
    mkdir("/var/lib/lochs", 0755);
    mkdir(HEALTH_DIR, 0755);

    /* Check for stale monitor and clean up */
    if (jail->health_monitor_pid > 0) {
        if (kill(jail->health_monitor_pid, 0) == 0) {
            /* Still running — stop it first */
            lochs_health_monitor_stop(jail);
        }
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        /* Child process — run the monitor loop */
        /* Close stdin/stdout/stderr to fully detach */
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        health_monitor_loop(jail);
        /* Never reaches here */
        _exit(0);
    }

    /* Parent */
    jail->health_monitor_pid = pid;

    /* Write initial status */
    health_status_write(jail->name,
                       jail->healthcheck.start_period > 0 ? HEALTH_STARTING : HEALTH_HEALTHY,
                       0, time(NULL), "monitor started", 0, 0, 0);

    return 0;
}

/*
 * Stop the health monitor for a container.
 * Sends SIGTERM, waits briefly, then SIGKILL if needed.
 */
int lochs_health_monitor_stop(lochs_jail_t *jail) {
    if (jail->health_monitor_pid <= 0) return 0;

    /* Also try to read PID from file in case struct is stale */
    pid_t target_pid = jail->health_monitor_pid;

    /* Send SIGTERM */
    if (kill(target_pid, SIGTERM) == 0) {
        /* Wait up to 3 seconds */
        for (int i = 0; i < 6; i++) {
            int status;
            pid_t result = waitpid(target_pid, &status, WNOHANG);
            if (result == target_pid || result < 0) {
                goto done;
            }
            usleep(500000);  /* 0.5 seconds */
        }

        /* Still alive — force kill */
        kill(target_pid, SIGKILL);
        waitpid(target_pid, NULL, 0);
    }

done:
    jail->health_monitor_pid = 0;
    health_cleanup_files(jail->name);
    return 0;
}

/* ─── Manual health check command ─── */

/*
 * lochs health <name> [--status]
 *
 * Without --status: Run a single health check and print result.
 * With --status: Just show current status from status file.
 */
int lochs_cmd_health(int argc, char **argv) {
    int status_only = 0;

    static struct option long_options[] = {
        {"status", no_argument, 0, 's'},
        {"help",   no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    optind = 1;

    while ((opt = getopt_long(argc, argv, "sh", long_options, NULL)) != -1) {
        switch (opt) {
            case 's': status_only = 1; break;
            case 'h':
                printf("Usage: lochs health <container> [options]\n\n");
                printf("Run a health check or view health status.\n\n");
                printf("Options:\n");
                printf("  -s, --status    Show current status only (don't run check)\n");
                printf("  -h, --help      Show this help\n");
                return 0;
            default:
                return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: container name required\n");
        fprintf(stderr, "Usage: lochs health <container> [--status]\n");
        return 1;
    }

    const char *name = argv[optind];
    lochs_jail_t *jail = lochs_jail_find(name);

    if (!jail) {
        fprintf(stderr, "Error: container '%s' not found\n", name);
        return 1;
    }

    if (!jail->healthcheck.enabled) {
        printf("Container '%s' has no health check configured.\n", name);
        return 0;
    }

    /* Show current status */
    lochs_health_state_t hstate = HEALTH_NONE;
    int cons_fail = 0, tot_chk = 0, tot_fail = 0, restarts = 0;
    time_t last_chk = 0;
    char last_out[256] = "";

    if (lochs_health_status_read(name, &hstate, &cons_fail, &last_chk,
                                  last_out, sizeof(last_out),
                                  &tot_chk, &tot_fail, &restarts) == 0) {
        const char *color = "";
        const char *reset = "\033[0m";
        switch (hstate) {
            case HEALTH_HEALTHY:   color = "\033[32m"; break;
            case HEALTH_UNHEALTHY: color = "\033[31m"; break;
            case HEALTH_STARTING:  color = "\033[33m"; break;
            default:               reset = ""; break;
        }

        printf("Container: %s\n", name);
        printf("  Status:     %s%s%s\n", color, lochs_health_state_str(hstate), reset);
        printf("  Failures:   %d consecutive, %d total\n", cons_fail, tot_fail);
        printf("  Checks:     %d total\n", tot_chk);
        printf("  Restarts:   %d\n", restarts);
        if (last_chk > 0) {
            char time_buf[64];
            struct tm *tm = localtime(&last_chk);
            strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm);
            printf("  Last check: %s\n", time_buf);
        }
        if (last_out[0]) {
            printf("  Output:     %s\n", last_out);
        }
        printf("  Config:     every %ds, timeout %ds, %d retries\n",
               jail->healthcheck.interval, jail->healthcheck.timeout,
               jail->healthcheck.retries);
        if (jail->health_monitor_pid > 0) {
            printf("  Monitor:    pid=%d\n", jail->health_monitor_pid);
        }
    } else {
        printf("Container: %s\n", name);
        printf("  Status:     no health data (monitor not running?)\n");
        printf("  Config:     every %ds, timeout %ds, %d retries\n",
               jail->healthcheck.interval, jail->healthcheck.timeout,
               jail->healthcheck.retries);
    }

    if (status_only) return 0;

    /* Run a single check */
    if (jail->state != JAIL_STATE_RUNNING) {
        printf("\nContainer is not running — cannot execute health check.\n");
        return 1;
    }

    printf("\nRunning health check: %s\n", jail->healthcheck.cmd);

    char output[512] = "";
    int result = health_exec_check(jail, output, sizeof(output));

    if (result == 0) {
        printf("  Result: \033[32mhealthy\033[0m (exit 0)\n");
    } else {
        printf("  Result: \033[31munhealthy\033[0m (exit %d)\n", result);
    }
    if (output[0]) {
        printf("  Output: %s\n", output);
    }

    return result;
}
