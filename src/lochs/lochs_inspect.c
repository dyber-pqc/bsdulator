/*
 * Lochs Container Inspection
 *
 * Displays full container configuration and state in JSON or
 * human-readable format. Equivalent to 'docker inspect'.
 *
 * Usage:
 *   lochs inspect <container>          JSON output (default)
 *   lochs inspect -H <container>       Human-readable output
 *   lochs inspect --format human <c>   Human-readable output
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include "bsdulator/lochs.h"

/* Helper to safely copy strings */
static void safe_strcpy(char *dst, const char *src, size_t dst_size) {
    if (dst_size == 0) return;
    size_t src_len = strlen(src);
    size_t copy_len = (src_len < dst_size - 1) ? src_len : dst_size - 1;
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
}

/*
 * Escape a string for JSON output.
 * Handles: " \ / \n \r \t and control characters.
 */
static void json_escape(const char *src, char *dst, size_t dst_size) {
    if (dst_size == 0) return;
    size_t di = 0;

    for (const char *p = src; *p && di < dst_size - 1; p++) {
        switch (*p) {
            case '"':
                if (di + 2 < dst_size) { dst[di++] = '\\'; dst[di++] = '"'; }
                break;
            case '\\':
                if (di + 2 < dst_size) { dst[di++] = '\\'; dst[di++] = '\\'; }
                break;
            case '\n':
                if (di + 2 < dst_size) { dst[di++] = '\\'; dst[di++] = 'n'; }
                break;
            case '\r':
                if (di + 2 < dst_size) { dst[di++] = '\\'; dst[di++] = 'r'; }
                break;
            case '\t':
                if (di + 2 < dst_size) { dst[di++] = '\\'; dst[di++] = 't'; }
                break;
            default:
                if ((unsigned char)*p < 0x20) {
                    /* Control character - skip */
                } else {
                    dst[di++] = *p;
                }
                break;
        }
    }
    dst[di] = '\0';
}

/*
 * Convert jail state to string
 */
static const char *state_to_string(jail_state_t state) {
    switch (state) {
        case JAIL_STATE_CREATED: return "created";
        case JAIL_STATE_RUNNING: return "running";
        case JAIL_STATE_STOPPED: return "stopped";
        case JAIL_STATE_REMOVED: return "removed";
        default: return "unknown";
    }
}

/*
 * Format a time_t as ISO 8601 string
 */
static void format_iso_time(time_t t, char *buf, size_t buf_size) {
    if (t == 0) {
        safe_strcpy(buf, "", buf_size);
        return;
    }
    struct tm *tm = localtime(&t);
    if (tm) {
        strftime(buf, buf_size, "%Y-%m-%dT%H:%M:%S", tm);
    } else {
        safe_strcpy(buf, "", buf_size);
    }
}

/*
 * Format a time_t as human-readable string
 */
static void format_human_time(time_t t, char *buf, size_t buf_size) {
    if (t == 0) {
        safe_strcpy(buf, "(never)", buf_size);
        return;
    }
    struct tm *tm = localtime(&t);
    if (tm) {
        strftime(buf, buf_size, "%Y-%m-%d %H:%M:%S", tm);
    } else {
        safe_strcpy(buf, "unknown", buf_size);
    }
}

/*
 * Format bytes as human-readable string
 */
static void format_bytes(int64_t bytes, char *buf, size_t buf_size) {
    if (bytes <= 0) {
        safe_strcpy(buf, "unlimited", buf_size);
    } else if (bytes >= (int64_t)1024 * 1024 * 1024) {
        snprintf(buf, buf_size, "%.1f GiB",
                 (double)bytes / (1024.0 * 1024.0 * 1024.0));
    } else if (bytes >= 1024 * 1024) {
        snprintf(buf, buf_size, "%lld MiB",
                 (long long)(bytes / (1024 * 1024)));
    } else if (bytes >= 1024) {
        snprintf(buf, buf_size, "%lld KiB",
                 (long long)(bytes / 1024));
    } else {
        snprintf(buf, buf_size, "%lld B", (long long)bytes);
    }
}

/* ====================================================================
 * JSON Output
 * ==================================================================== */

static void inspect_json(lochs_jail_t *jail) {
    char esc[2048];
    char time_buf[64];

    printf("{\n");

    /* Basic info */
    json_escape(jail->name, esc, sizeof(esc));
    printf("  \"Name\": \"%s\",\n", esc);
    printf("  \"Jid\": %d,\n", jail->jid);
    json_escape(jail->image, esc, sizeof(esc));
    printf("  \"Image\": \"%s\",\n", esc);

    /* State */
    printf("  \"State\": {\n");
    printf("    \"Status\": \"%s\",\n", state_to_string(jail->state));
    printf("    \"Pid\": %d,\n", (int)jail->pid);
    format_iso_time(jail->created_at, time_buf, sizeof(time_buf));
    printf("    \"CreatedAt\": \"%s\",\n", time_buf);
    format_iso_time(jail->started_at, time_buf, sizeof(time_buf));
    printf("    \"StartedAt\": \"%s\"\n", time_buf);
    printf("  },\n");

    /* Config */
    printf("  \"Config\": {\n");
    json_escape(jail->cmd, esc, sizeof(esc));
    printf("    \"Cmd\": \"%s\",\n", esc);
    json_escape(jail->entrypoint, esc, sizeof(esc));
    printf("    \"Entrypoint\": \"%s\",\n", esc);
    json_escape(jail->workdir, esc, sizeof(esc));
    printf("    \"WorkingDir\": \"%s\",\n", esc);
    printf("    \"Env\": [");
    for (int i = 0; i < jail->env_count; i++) {
        char env_str[384];
        snprintf(env_str, sizeof(env_str), "%s=%s",
                 jail->env_keys[i], jail->env_values[i]);
        json_escape(env_str, esc, sizeof(esc));
        printf("%s\n      \"%s\"", i > 0 ? "," : "", esc);
    }
    if (jail->env_count > 0) printf("\n    ");
    printf("]\n");
    printf("  },\n");

    /* Network settings */
    printf("  \"NetworkSettings\": {\n");
    json_escape(jail->ip4_addr, esc, sizeof(esc));
    printf("    \"IPAddress\": \"%s\",\n", esc);
    json_escape(jail->network, esc, sizeof(esc));
    printf("    \"Network\": \"%s\",\n", esc);
    json_escape(jail->netns, esc, sizeof(esc));
    printf("    \"Namespace\": \"%s\",\n", esc);
    printf("    \"Vnet\": %s\n", jail->vnet ? "true" : "false");
    printf("  },\n");

    /* Mounts (volumes) */
    printf("  \"Mounts\": [");
    for (int i = 0; i < jail->volume_count; i++) {
        lochs_volume_t *v = &jail->volumes[i];
        printf("%s\n    {", i > 0 ? "," : "");
        if (v->volume_name[0]) {
            printf("\n      \"Type\": \"named\",");
            json_escape(v->volume_name, esc, sizeof(esc));
            printf("\n      \"Name\": \"%s\",", esc);
        } else {
            printf("\n      \"Type\": \"bind\",");
            printf("\n      \"Name\": \"\",");
        }
        json_escape(v->host_path, esc, sizeof(esc));
        printf("\n      \"Source\": \"%s\",", esc);
        json_escape(v->container_path, esc, sizeof(esc));
        printf("\n      \"Destination\": \"%s\",", esc);
        printf("\n      \"ReadOnly\": %s", v->readonly ? "true" : "false");
        printf("\n    }");
    }
    if (jail->volume_count > 0) printf("\n  ");
    printf("],\n");

    /* Ports */
    printf("  \"Ports\": [");
    for (int i = 0; i < jail->port_count; i++) {
        lochs_port_map_t *p = &jail->ports[i];
        printf("%s\n    {", i > 0 ? "," : "");
        printf("\n      \"HostPort\": %d,", p->host_port);
        printf("\n      \"ContainerPort\": %d,", p->container_port);
        json_escape(p->protocol, esc, sizeof(esc));
        printf("\n      \"Protocol\": \"%s\",", esc);
        printf("\n      \"ForwarderPid\": %d", (int)p->forwarder_pid);
        printf("\n    }");
    }
    if (jail->port_count > 0) printf("\n  ");
    printf("],\n");

    /* Host config (resource limits) */
    printf("  \"HostConfig\": {\n");
    printf("    \"CpuMillicores\": %d,\n", jail->cpus_millicores);
    printf("    \"CpuWeight\": %d,\n", jail->cpu_weight);
    printf("    \"Memory\": %lld,\n", (long long)jail->memory_limit);
    printf("    \"MemorySwap\": %lld,\n", (long long)jail->memory_swap_limit);
    printf("    \"PidsLimit\": %d,\n", jail->pids_limit);
    printf("    \"CgroupApplied\": %s\n", jail->cgroup_applied ? "true" : "false");
    printf("  },\n");

    /* Health */
    printf("  \"Health\": {\n");
    if (jail->healthcheck.enabled) {
        lochs_health_state_t hstate = HEALTH_NONE;
        int cons_fail = 0, tot_chk = 0, tot_fail = 0, restarts = 0;
        time_t last_chk = 0;
        char last_out[256] = "";
        lochs_health_status_read(jail->name, &hstate, &cons_fail, &last_chk,
                                  last_out, sizeof(last_out),
                                  &tot_chk, &tot_fail, &restarts);

        printf("    \"Status\": \"%s\",\n", lochs_health_state_str(hstate));
        printf("    \"FailingStreak\": %d,\n", cons_fail);

        format_iso_time(last_chk, time_buf, sizeof(time_buf));
        printf("    \"LastCheck\": \"%s\",\n", time_buf);

        json_escape(last_out, esc, sizeof(esc));
        printf("    \"LastOutput\": \"%s\",\n", esc);
        printf("    \"TotalChecks\": %d,\n", tot_chk);
        printf("    \"TotalFailures\": %d,\n", tot_fail);
        printf("    \"RestartCount\": %d,\n", restarts);
        printf("    \"MonitorPid\": %d,\n", (int)jail->health_monitor_pid);
        printf("    \"Config\": {\n");

        json_escape(jail->healthcheck.cmd, esc, sizeof(esc));
        printf("      \"Test\": \"%s\",\n", esc);
        printf("      \"Interval\": %d,\n", jail->healthcheck.interval);
        printf("      \"Timeout\": %d,\n", jail->healthcheck.timeout);
        printf("      \"Retries\": %d,\n", jail->healthcheck.retries);
        printf("      \"StartPeriod\": %d\n", jail->healthcheck.start_period);
        printf("    }\n");
    } else {
        printf("    \"Status\": \"none\"\n");
    }
    printf("  },\n");

    /* Storage */
    printf("  \"Storage\": {\n");
    printf("    \"Backend\": \"%s\",\n",
           jail->storage_backend == LOCHS_STORAGE_ZFS ? "zfs" : "overlay");
    json_escape(jail->path, esc, sizeof(esc));
    printf("    \"Path\": \"%s\",\n", esc);
    json_escape(jail->image_path, esc, sizeof(esc));
    printf("    \"ImagePath\": \"%s\",\n", esc);
    json_escape(jail->diff_path, esc, sizeof(esc));
    printf("    \"DiffPath\": \"%s\",\n", esc);
    json_escape(jail->work_path, esc, sizeof(esc));
    printf("    \"WorkPath\": \"%s\",\n", esc);
    json_escape(jail->merged_path, esc, sizeof(esc));
    printf("    \"MergedPath\": \"%s\",\n", esc);
    printf("    \"OverlayMounted\": %s,\n", jail->overlay_mounted ? "true" : "false");
    json_escape(jail->zfs_dataset, esc, sizeof(esc));
    printf("    \"ZfsDataset\": \"%s\",\n", esc);
    json_escape(jail->zfs_mountpoint, esc, sizeof(esc));
    printf("    \"ZfsMountpoint\": \"%s\",\n", esc);
    json_escape(jail->zfs_origin, esc, sizeof(esc));
    printf("    \"ZfsOrigin\": \"%s\"\n", esc);
    printf("  }\n");

    printf("}\n");
}

/* ====================================================================
 * Human-Readable Output
 * ==================================================================== */

static void inspect_human(lochs_jail_t *jail) {
    char time_buf[64];

    printf("Container: %s\n", jail->name);

    /* State */
    if (jail->jid > 0) {
        printf("  State:       %s (jid=%d)\n", state_to_string(jail->state), jail->jid);
    } else {
        printf("  State:       %s\n", state_to_string(jail->state));
    }
    printf("  Image:       %s\n", jail->image);
    format_human_time(jail->created_at, time_buf, sizeof(time_buf));
    printf("  Created:     %s\n", time_buf);
    format_human_time(jail->started_at, time_buf, sizeof(time_buf));
    printf("  Started:     %s\n", time_buf);
    if (jail->pid > 0) {
        printf("  PID:         %d\n", (int)jail->pid);
    }

    /* Health check */
    if (jail->healthcheck.enabled) {
        printf("\n  Health Check:\n");

        lochs_health_state_t hstate = HEALTH_NONE;
        int cons_fail = 0, tot_chk = 0, tot_fail = 0, restarts = 0;
        time_t last_chk = 0;
        char last_out[256] = "";

        if (lochs_health_status_read(jail->name, &hstate, &cons_fail, &last_chk,
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
            printf("    Status:    %s%s%s (%d checks, %d failures, %d restarts)\n",
                   color, lochs_health_state_str(hstate), reset,
                   tot_chk, tot_fail, restarts);
            if (last_chk > 0) {
                format_human_time(last_chk, time_buf, sizeof(time_buf));
                printf("    Last:      %s", time_buf);
                if (last_out[0]) printf(" — %s", last_out);
                printf("\n");
            }
        } else {
            printf("    Status:    no health data\n");
        }
        printf("    Command:   %s\n", jail->healthcheck.cmd);
        printf("    Schedule:  every %ds, timeout %ds, %d retries\n",
               jail->healthcheck.interval, jail->healthcheck.timeout,
               jail->healthcheck.retries);
        if (jail->healthcheck.start_period > 0) {
            printf("    Start:     %ds grace period\n", jail->healthcheck.start_period);
        }
        if (jail->health_monitor_pid > 0) {
            printf("    Monitor:   pid=%d\n", (int)jail->health_monitor_pid);
        }
    }

    /* Network */
    printf("\n  Network:\n");
    if (jail->ip4_addr[0]) {
        printf("    IP:        %s\n", jail->ip4_addr);
    } else {
        printf("    IP:        (none)\n");
    }
    if (jail->network[0]) {
        printf("    Network:   %s\n", jail->network);
    }
    if (jail->netns[0]) {
        printf("    Namespace: %s\n", jail->netns);
    }
    printf("    Vnet:      %s\n", jail->vnet ? "yes" : "no");

    /* Ports */
    if (jail->port_count > 0) {
        printf("\n  Ports:\n");
        for (int i = 0; i < jail->port_count; i++) {
            lochs_port_map_t *p = &jail->ports[i];
            printf("    %d -> %d/%s", p->host_port, p->container_port, p->protocol);
            if (p->forwarder_pid > 0) {
                printf(" (pid=%d)", (int)p->forwarder_pid);
            }
            printf("\n");
        }
    }

    /* Volumes */
    if (jail->volume_count > 0) {
        printf("\n  Volumes:\n");
        for (int i = 0; i < jail->volume_count; i++) {
            lochs_volume_t *v = &jail->volumes[i];
            if (v->volume_name[0]) {
                printf("    %s -> %s (named, %s)\n",
                       v->volume_name, v->container_path,
                       v->readonly ? "ro" : "rw");
                if (v->host_path[0]) {
                    printf("      resolved: %s\n", v->host_path);
                }
            } else {
                printf("    %s -> %s (bind, %s)\n",
                       v->host_path, v->container_path,
                       v->readonly ? "ro" : "rw");
            }
        }
    }

    /* Environment */
    if (jail->env_count > 0) {
        printf("\n  Environment:\n");
        for (int i = 0; i < jail->env_count; i++) {
            printf("    %s=%s\n", jail->env_keys[i], jail->env_values[i]);
        }
    }

    /* Resource limits */
    if (jail->cpus_millicores > 0 || jail->memory_limit > 0 ||
        jail->pids_limit > 0 || jail->cpu_weight > 0) {
        char mem_str[32];
        printf("\n  Resource Limits:\n");
        if (jail->cpus_millicores > 0) {
            int whole = jail->cpus_millicores / 1000;
            int frac = (jail->cpus_millicores % 1000) / 100;
            if (frac > 0) {
                printf("    CPU:       %d.%d cores\n", whole, frac);
            } else {
                printf("    CPU:       %d core%s\n", whole, whole == 1 ? "" : "s");
            }
        }
        if (jail->cpu_weight > 0) {
            printf("    CPU wt:    %d\n", jail->cpu_weight);
        }
        if (jail->memory_limit > 0) {
            format_bytes(jail->memory_limit, mem_str, sizeof(mem_str));
            printf("    Memory:    %s\n", mem_str);
        }
        if (jail->memory_swap_limit > 0) {
            format_bytes(jail->memory_swap_limit, mem_str, sizeof(mem_str));
            printf("    Swap:      %s\n", mem_str);
        } else if (jail->memory_swap_limit == -1) {
            printf("    Swap:      same as memory\n");
        }
        if (jail->pids_limit > 0) {
            printf("    PIDs:      %d max\n", jail->pids_limit);
        }
        printf("    Cgroup:    %s\n", jail->cgroup_applied ? "active" : "inactive");
    }

    /* Storage */
    printf("\n  Storage:\n");
    printf("    Backend:   %s\n",
           jail->storage_backend == LOCHS_STORAGE_ZFS ? "zfs" : "overlay");
    if (jail->image_path[0]) {
        printf("    Image:     %s\n", jail->image_path);
    }
    printf("    Root:      %s\n", jail->path);
    if (jail->storage_backend == LOCHS_STORAGE_ZFS) {
        if (jail->zfs_dataset[0]) printf("    Dataset:   %s\n", jail->zfs_dataset);
        if (jail->zfs_mountpoint[0]) printf("    Mountpt:   %s\n", jail->zfs_mountpoint);
        if (jail->zfs_origin[0]) printf("    Origin:    %s\n", jail->zfs_origin);
    } else {
        if (jail->diff_path[0]) printf("    Diff:      %s\n", jail->diff_path);
        if (jail->work_path[0]) printf("    Work:      %s\n", jail->work_path);
        if (jail->merged_path[0]) printf("    Merged:    %s\n", jail->merged_path);
        printf("    Overlay:   %s\n", jail->overlay_mounted ? "mounted" : "unmounted");
    }

    /* Command */
    if (jail->cmd[0] || jail->entrypoint[0] || jail->workdir[0]) {
        printf("\n  Command:\n");
        if (jail->cmd[0]) printf("    CMD:       %s\n", jail->cmd);
        if (jail->entrypoint[0]) printf("    Entrypt:   %s\n", jail->entrypoint);
        if (jail->workdir[0]) printf("    Workdir:   %s\n", jail->workdir);
    }
}

/* ====================================================================
 * Command Handler
 * ==================================================================== */

/*
 * lochs inspect [options] <container>
 *
 * Options:
 *   -H, --human           Human-readable output (default: JSON)
 *   --format <fmt>        Output format: json (default) or human
 */
int lochs_cmd_inspect(int argc, char **argv) {
    int human = 0;

    static struct option long_options[] = {
        {"human",  no_argument,       0, 'H'},
        {"format", required_argument, 0, 'f'},
        {"help",   no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    optind = 1;

    while ((opt = getopt_long(argc, argv, "Hf:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'H':
                human = 1;
                break;
            case 'f':
                if (strcmp(optarg, "human") == 0 || strcmp(optarg, "text") == 0) {
                    human = 1;
                } else if (strcmp(optarg, "json") == 0) {
                    human = 0;
                } else {
                    fprintf(stderr, "Error: unknown format '%s'\n", optarg);
                    fprintf(stderr, "Valid formats: json, human\n");
                    return 1;
                }
                break;
            case 'h':
                printf("Usage: lochs inspect [options] <container>\n\n");
                printf("Show detailed container configuration and state.\n\n");
                printf("Options:\n");
                printf("  -H, --human           Human-readable output\n");
                printf("  -f, --format <fmt>    Output format: json (default) or human\n");
                printf("\nExamples:\n");
                printf("  lochs inspect myapp               JSON output\n");
                printf("  lochs inspect -H myapp             Human-readable\n");
                printf("  lochs inspect --format json myapp  Explicit JSON\n");
                return 0;
            default:
                return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: container name required\n");
        fprintf(stderr, "Usage: lochs inspect [options] <container>\n");
        return 1;
    }

    const char *name = argv[optind];
    lochs_jail_t *jail = lochs_jail_find(name);

    if (!jail) {
        fprintf(stderr, "Error: container '%s' not found\n", name);
        return 1;
    }

    if (human) {
        inspect_human(jail);
    } else {
        inspect_json(jail);
    }

    return 0;
}
