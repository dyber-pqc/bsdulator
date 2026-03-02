/*
 * Lochs Web Dashboard
 *
 * Embedded HTTP server serving a single-page management UI.
 * Provides REST API endpoints for container, image, and network data.
 *
 * Usage:
 *   lochs dashboard                Start dashboard (default port 8420)
 *   lochs dashboard --port 9000    Custom port
 *   lochs dashboard --foreground   Run in foreground (no fork)
 *   lochs dashboard stop           Stop the dashboard
 *   lochs dashboard status         Check if running
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include "bsdulator/lochs.h"
#include "lochs_dashboard_html.h"

#define DASHBOARD_DEFAULT_PORT  8420
#define DASHBOARD_PID_FILE      "/var/lib/lochs/dashboard.pid"
#define DASHBOARD_LOG_FILE      "/var/lib/lochs/dashboard.log"
#define DASHBOARD_MAX_REQUEST   8192
#define DASHBOARD_MAX_RESPONSE  131072

#define IMAGES_DB_FILE     "/var/lib/lochs/images.dat"
#define IMAGES_MAGIC       0x4C494D47
#define NETWORKS_DB_FILE   "/var/lib/lochs/networks.dat"
#define VOLUMES_DB_FILE    "/var/lib/lochs/volumes.dat"
#define LOG_DIR            "/var/lib/lochs/logs"
#define CGROUP_LOCHS       "/sys/fs/cgroup/lochs"

/* Access the global jail state from lochs_commands.c */
extern lochs_jail_t lochs_jails[];
extern int lochs_jail_count;

/* Image struct mirroring lochs_images.c layout for binary file reading */
typedef struct {
    char repository[64];
    char tag[32];
    char id[65];
    char path[512];
    size_t size;
    time_t created;
    time_t pulled;
} dashboard_image_t;

static volatile sig_atomic_t dashboard_running = 1;

/* ====================================================================
 * Helpers
 * ==================================================================== */

static void safe_strcpy(char *dst, const char *src, size_t dst_size) {
    if (dst_size == 0) return;
    size_t src_len = strlen(src);
    size_t copy_len = (src_len < dst_size - 1) ? src_len : dst_size - 1;
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
}

/* Bounded append to a response buffer */
static int jappend(char *buf, int pos, int max, const char *fmt, ...) {
    if (pos >= max - 1) return pos;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + pos, (size_t)(max - pos), fmt, ap);
    va_end(ap);
    if (n < 0) return pos;
    if (n >= max - pos) return max - 1;
    return pos + n;
}

/* JSON-escape a string into a buffer, return length written */
static int json_esc(char *out, int max, const char *s) {
    int i = 0;
    if (!s) { if (max > 0) out[0] = '\0'; return 0; }
    for (const char *p = s; *p && i < max - 2; p++) {
        switch (*p) {
            case '"':  if (i+2<max){out[i++]='\\';out[i++]='"';}  break;
            case '\\': if (i+2<max){out[i++]='\\';out[i++]='\\';} break;
            case '\n': if (i+2<max){out[i++]='\\';out[i++]='n';}  break;
            case '\r': if (i+2<max){out[i++]='\\';out[i++]='r';}  break;
            case '\t': if (i+2<max){out[i++]='\\';out[i++]='t';}  break;
            default:
                if ((unsigned char)*p >= 0x20) out[i++] = *p;
                break;
        }
    }
    if (i < max) out[i] = '\0';
    return i;
}

static const char *state_str(jail_state_t s) {
    switch (s) {
        case JAIL_STATE_CREATED: return "created";
        case JAIL_STATE_RUNNING: return "running";
        case JAIL_STATE_STOPPED: return "stopped";
        case JAIL_STATE_REMOVED: return "removed";
        default: return "unknown";
    }
}

/* Read a single value from a cgroup file, return -1 on error */
static long long cgroup_read_ll(const char *container, const char *file) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s/%s", CGROUP_LOCHS, container, file);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    long long val = 0;
    if (fscanf(f, "%lld", &val) != 1) val = -1;
    fclose(f);
    return val;
}

/* Read CPU usage_usec from cpu.stat */
static long long cgroup_read_cpu_usec(const char *container) {
    char path[512];
    char buf[256];
    snprintf(path, sizeof(path), "%s/%s/cpu.stat", CGROUP_LOCHS, container);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    long long usec = -1;
    while (fgets(buf, sizeof(buf), f)) {
        if (strncmp(buf, "usage_usec ", 11) == 0) {
            usec = atoll(buf + 11);
            break;
        }
    }
    fclose(f);
    return usec;
}

/* ====================================================================
 * HTTP helpers
 * ==================================================================== */

typedef struct {
    char method[8];
    char path[512];
    int content_length;
} http_request_t;

static int parse_request(const char *raw, int raw_len, http_request_t *req) {
    (void)raw_len;
    memset(req, 0, sizeof(*req));

    /* Parse request line: METHOD /path HTTP/1.x */
    const char *sp1 = strchr(raw, ' ');
    if (!sp1) return -1;
    size_t mlen = (size_t)(sp1 - raw);
    if (mlen >= sizeof(req->method)) mlen = sizeof(req->method) - 1;
    memcpy(req->method, raw, mlen);
    req->method[mlen] = '\0';

    const char *path_start = sp1 + 1;
    const char *sp2 = strchr(path_start, ' ');
    if (!sp2) sp2 = strchr(path_start, '\r');
    if (!sp2) sp2 = path_start + strlen(path_start);
    size_t plen = (size_t)(sp2 - path_start);
    if (plen >= sizeof(req->path)) plen = sizeof(req->path) - 1;
    memcpy(req->path, path_start, plen);
    req->path[plen] = '\0';

    /* Strip query string */
    char *q = strchr(req->path, '?');
    if (q) *q = '\0';

    /* Strip trailing slash (except root) */
    size_t pl = strlen(req->path);
    if (pl > 1 && req->path[pl - 1] == '/') req->path[pl - 1] = '\0';

    return 0;
}

static void send_response(int fd, int status, const char *content_type,
                           const char *body, int body_len) {
    char header[512];
    const char *reason = "OK";
    if (status == 404) reason = "Not Found";
    else if (status == 400) reason = "Bad Request";
    else if (status == 500) reason = "Internal Server Error";

    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n"
        "Connection: close\r\n"
        "\r\n",
        status, reason, content_type, body_len);

    /* Send header */
    ssize_t w = write(fd, header, (size_t)hlen);
    (void)w;

    /* Send body in chunks */
    int sent = 0;
    while (sent < body_len) {
        int chunk = body_len - sent;
        if (chunk > 32768) chunk = 32768;
        w = write(fd, body + sent, (size_t)chunk);
        if (w <= 0) break;
        sent += (int)w;
    }
}

static void send_json(int fd, int status, const char *json, int len) {
    send_response(fd, status, "application/json", json, len);
}

static void send_error(int fd, int status, const char *msg) {
    char buf[256];
    char esc[128];
    json_esc(esc, sizeof(esc), msg);
    int len = snprintf(buf, sizeof(buf), "{\"ok\":false,\"error\":\"%s\"}", esc);
    send_json(fd, status, buf, len);
}

/* ====================================================================
 * API Handlers
 * ==================================================================== */

/* GET /api/system */
static void api_system_info(int fd) {
    int running = 0, stopped = 0, created = 0;
    for (int i = 0; i < lochs_jail_count; i++) {
        switch (lochs_jails[i].state) {
            case JAIL_STATE_RUNNING: running++; break;
            case JAIL_STATE_STOPPED: stopped++; break;
            case JAIL_STATE_CREATED: created++; break;
            default: break;
        }
    }

    /* Count images from file */
    int img_count = 0;
    FILE *f = fopen(IMAGES_DB_FILE, "rb");
    if (f) {
        uint32_t magic = 0;
        if (fread(&magic, sizeof(magic), 1, f) == 1 && magic == IMAGES_MAGIC) {
            int cnt = 0;
            if (fread(&cnt, sizeof(cnt), 1, f) == 1) img_count = cnt;
        }
        fclose(f);
    }

    /* Count networks from file */
    int net_count = 0;
    f = fopen(NETWORKS_DB_FILE, "rb");
    if (f) {
        int cnt = 0;
        if (fread(&cnt, sizeof(cnt), 1, f) == 1) net_count = cnt;
        fclose(f);
    }

    char buf[512];
    int len = snprintf(buf, sizeof(buf),
        "{\"version\":\"%s\",\"containers_total\":%d,"
        "\"containers_running\":%d,\"containers_stopped\":%d,"
        "\"containers_created\":%d,\"images_total\":%d,"
        "\"networks_total\":%d}",
        LOCHS_VERSION, lochs_jail_count,
        running, stopped, created, img_count, net_count);
    send_json(fd, 200, buf, len);
}

/* Serialize a single container to JSON, appending to buf at pos */
static int serialize_container(char *buf, int pos, int max, lochs_jail_t *j) {
    char esc[1024];
    time_t now = time(NULL);

    pos = jappend(buf, pos, max, "{");
    json_esc(esc, sizeof(esc), j->name);
    pos = jappend(buf, pos, max, "\"name\":\"%s\",", esc);
    pos = jappend(buf, pos, max, "\"jid\":%d,", j->jid);
    json_esc(esc, sizeof(esc), j->image);
    pos = jappend(buf, pos, max, "\"image\":\"%s\",", esc);
    pos = jappend(buf, pos, max, "\"state\":\"%s\",", state_str(j->state));
    pos = jappend(buf, pos, max, "\"pid\":%d,", (int)j->pid);
    pos = jappend(buf, pos, max, "\"created_at\":%ld,", (long)j->created_at);
    pos = jappend(buf, pos, max, "\"started_at\":%ld,", (long)j->started_at);

    json_esc(esc, sizeof(esc), j->ip4_addr);
    pos = jappend(buf, pos, max, "\"ip4_addr\":\"%s\",", esc);
    json_esc(esc, sizeof(esc), j->network);
    pos = jappend(buf, pos, max, "\"network\":\"%s\",", esc);
    pos = jappend(buf, pos, max, "\"storage_backend\":\"%s\",",
                  j->storage_backend == LOCHS_STORAGE_ZFS ? "zfs" : "overlay");

    /* CMD */
    json_esc(esc, sizeof(esc), j->cmd);
    pos = jappend(buf, pos, max, "\"cmd\":\"%s\",", esc);

    /* Health */
    if (j->healthcheck.enabled && j->state == JAIL_STATE_RUNNING) {
        lochs_health_state_t hstate = HEALTH_NONE;
        int cons_fail = 0;
        lochs_health_status_read(j->name, &hstate, &cons_fail, NULL, NULL, 0,
                                  NULL, NULL, NULL);
        pos = jappend(buf, pos, max, "\"health\":\"%s\",",
                      lochs_health_state_str(hstate));
        pos = jappend(buf, pos, max, "\"health_failures\":%d,", cons_fail);
        json_esc(esc, sizeof(esc), j->healthcheck.cmd);
        pos = jappend(buf, pos, max, "\"health_cmd\":\"%s\",", esc);
    } else {
        pos = jappend(buf, pos, max, "\"health\":\"none\",\"health_failures\":0,\"health_cmd\":\"\",");
    }

    /* Resource limits */
    pos = jappend(buf, pos, max, "\"cpus_millicores\":%d,", j->cpus_millicores);
    pos = jappend(buf, pos, max, "\"memory_limit\":%lld,", (long long)j->memory_limit);
    pos = jappend(buf, pos, max, "\"pids_limit\":%d,", j->pids_limit);

    /* Uptime */
    long uptime = 0;
    if (j->state == JAIL_STATE_RUNNING && j->started_at > 0) {
        uptime = (long)(now - j->started_at);
        if (uptime < 0) uptime = 0;
    }
    pos = jappend(buf, pos, max, "\"uptime_seconds\":%ld,", uptime);

    /* Ports */
    pos = jappend(buf, pos, max, "\"ports\":[");
    for (int p = 0; p < j->port_count; p++) {
        if (p > 0) pos = jappend(buf, pos, max, ",");
        json_esc(esc, sizeof(esc), j->ports[p].protocol);
        pos = jappend(buf, pos, max,
            "{\"host\":%d,\"container\":%d,\"protocol\":\"%s\"}",
            j->ports[p].host_port, j->ports[p].container_port, esc);
    }
    pos = jappend(buf, pos, max, "],");

    /* Volumes */
    pos = jappend(buf, pos, max, "\"volumes\":[");
    for (int v = 0; v < j->volume_count; v++) {
        if (v > 0) pos = jappend(buf, pos, max, ",");
        char hesc[1024], cesc[1024];
        json_esc(hesc, sizeof(hesc), j->volumes[v].host_path);
        json_esc(cesc, sizeof(cesc), j->volumes[v].container_path);
        pos = jappend(buf, pos, max,
            "{\"host\":\"%s\",\"container\":\"%s\",\"readonly\":%s}",
            hesc, cesc, j->volumes[v].readonly ? "true" : "false");
    }
    pos = jappend(buf, pos, max, "],");

    /* Env count */
    pos = jappend(buf, pos, max, "\"env_count\":%d", j->env_count);
    pos = jappend(buf, pos, max, "}");
    return pos;
}

/* GET /api/containers */
static void api_containers_list(int fd) {
    char *buf = malloc(DASHBOARD_MAX_RESPONSE);
    if (!buf) { send_error(fd, 500, "out of memory"); return; }

    int pos = 0, max = DASHBOARD_MAX_RESPONSE;
    pos = jappend(buf, pos, max, "{\"containers\":[");

    for (int i = 0; i < lochs_jail_count; i++) {
        if (i > 0) pos = jappend(buf, pos, max, ",");
        pos = serialize_container(buf, pos, max, &lochs_jails[i]);
    }

    pos = jappend(buf, pos, max, "],\"total\":%d}", lochs_jail_count);
    send_json(fd, 200, buf, pos);
    free(buf);
}

/* GET /api/containers/<name> */
static void api_container_detail(int fd, const char *name) {
    lochs_jail_t *j = lochs_jail_find(name);
    if (!j) { send_error(fd, 404, "container not found"); return; }

    char *buf = malloc(DASHBOARD_MAX_RESPONSE);
    if (!buf) { send_error(fd, 500, "out of memory"); return; }

    int pos = serialize_container(buf, 0, DASHBOARD_MAX_RESPONSE, j);
    send_json(fd, 200, buf, pos);
    free(buf);
}

/* POST /api/containers/<name>/<action> */
static void api_container_action(int fd, const char *path_after) {
    /* path_after is "<name>/<action>" */
    char name[LOCHS_MAX_NAME];
    char action[16];

    const char *slash = strchr(path_after, '/');
    if (!slash) { send_error(fd, 400, "missing action"); return; }

    size_t nlen = (size_t)(slash - path_after);
    if (nlen >= sizeof(name)) nlen = sizeof(name) - 1;
    memcpy(name, path_after, nlen);
    name[nlen] = '\0';

    safe_strcpy(action, slash + 1, sizeof(action));

    /* Validate action */
    if (strcmp(action, "start") != 0 &&
        strcmp(action, "stop") != 0 &&
        strcmp(action, "rm") != 0 &&
        strcmp(action, "restart") != 0) {
        send_error(fd, 400, "invalid action");
        return;
    }

    /* For restart: stop then start */
    char cmd[512];
    if (strcmp(action, "restart") == 0) {
        snprintf(cmd, sizeof(cmd), "lochs stop %s 2>&1 && lochs start %s 2>&1", name, name);
    } else {
        snprintf(cmd, sizeof(cmd), "lochs %s %s 2>&1", action, name);
    }

    char output[4096] = "";
    int out_pos = 0;
    FILE *fp = popen(cmd, "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp) && out_pos < (int)sizeof(output) - 256) {
            out_pos += snprintf(output + out_pos, sizeof(output) - (size_t)out_pos, "%s", line);
        }
        int ret = pclose(fp);
        int ok = (WIFEXITED(ret) && WEXITSTATUS(ret) == 0);

        char esc[4096];
        json_esc(esc, sizeof(esc), output);
        char buf[8192];
        int len = snprintf(buf, sizeof(buf),
            "{\"ok\":%s,\"output\":\"%s\"}", ok ? "true" : "false", esc);
        send_json(fd, 200, buf, len);
    } else {
        send_error(fd, 500, "failed to execute command");
    }
}

/* GET /api/logs/<name> */
static void api_container_logs(int fd, const char *name) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, name);

    FILE *f = fopen(path, "r");
    if (!f) {
        send_json(fd, 200, "{\"container\":\"\",\"lines\":[],\"total_lines\":0}", 44);
        return;
    }

    /* Read last 200 lines using a ring buffer */
    #define MAX_LOG_LINES 200
    char lines[MAX_LOG_LINES][1024];
    int idx = 0, count = 0;

    while (fgets(lines[idx], 1024, f)) {
        /* Strip trailing newline */
        size_t len = strlen(lines[idx]);
        if (len > 0 && lines[idx][len - 1] == '\n') lines[idx][len - 1] = '\0';
        idx = (idx + 1) % MAX_LOG_LINES;
        if (count < MAX_LOG_LINES) count++;
    }
    fclose(f);

    char *buf = malloc(DASHBOARD_MAX_RESPONSE);
    if (!buf) { send_error(fd, 500, "out of memory"); return; }

    int pos = 0, max = DASHBOARD_MAX_RESPONSE;
    char esc_name[128];
    json_esc(esc_name, sizeof(esc_name), name);
    pos = jappend(buf, pos, max, "{\"container\":\"%s\",\"lines\":[", esc_name);

    /* Output from ring buffer in order */
    int start = (count == MAX_LOG_LINES) ? idx : 0;
    for (int i = 0; i < count; i++) {
        int li = (start + i) % MAX_LOG_LINES;
        char esc[2048];
        json_esc(esc, sizeof(esc), lines[li]);
        if (i > 0) pos = jappend(buf, pos, max, ",");
        pos = jappend(buf, pos, max, "\"%s\"", esc);
    }

    pos = jappend(buf, pos, max, "],\"total_lines\":%d}", count);
    send_json(fd, 200, buf, pos);
    free(buf);
    #undef MAX_LOG_LINES
}

/* GET /api/stats/<name> */
static void api_container_stats(int fd, const char *name) {
    long long cpu_usec = cgroup_read_cpu_usec(name);
    long long mem = cgroup_read_ll(name, "memory.current");
    long long mem_max = cgroup_read_ll(name, "memory.max");
    long long swap = cgroup_read_ll(name, "memory.swap.current");
    long long pids = cgroup_read_ll(name, "pids.current");
    long long pids_max = cgroup_read_ll(name, "pids.max");

    /* Treat "max" as 0 (unlimited) */
    if (mem_max < 0 || mem_max > (long long)1024 * 1024 * 1024 * 1024) mem_max = 0;
    if (pids_max < 0 || pids_max > 1000000) pids_max = 0;

    char buf[512];
    int len = snprintf(buf, sizeof(buf),
        "{\"container\":\"%s\",\"cpu_usage_usec\":%lld,"
        "\"memory_bytes\":%lld,\"memory_limit_bytes\":%lld,"
        "\"swap_bytes\":%lld,\"pids\":%lld,\"pids_limit\":%lld}",
        name,
        cpu_usec > 0 ? cpu_usec : 0,
        mem > 0 ? mem : 0,
        mem_max,
        swap > 0 ? swap : 0,
        pids > 0 ? pids : 0,
        pids_max);
    send_json(fd, 200, buf, len);
}

/* GET /api/images */
static void api_images_list(int fd) {
    dashboard_image_t images[128];
    int img_count = 0;

    FILE *f = fopen(IMAGES_DB_FILE, "rb");
    if (f) {
        uint32_t magic = 0;
        if (fread(&magic, sizeof(magic), 1, f) == 1 && magic == IMAGES_MAGIC) {
            int cnt = 0;
            if (fread(&cnt, sizeof(cnt), 1, f) == 1) {
                if (cnt > 128) cnt = 128;
                for (int i = 0; i < cnt; i++) {
                    if (fread(&images[i], sizeof(dashboard_image_t), 1, f) != 1) break;
                    img_count++;
                }
            }
        }
        fclose(f);
    }

    char *buf = malloc(DASHBOARD_MAX_RESPONSE);
    if (!buf) { send_error(fd, 500, "out of memory"); return; }

    int pos = 0, max = DASHBOARD_MAX_RESPONSE;
    pos = jappend(buf, pos, max, "{\"images\":[");

    for (int i = 0; i < img_count; i++) {
        char repo_esc[128], tag_esc[64], id_esc[128];
        json_esc(repo_esc, sizeof(repo_esc), images[i].repository);
        json_esc(tag_esc, sizeof(tag_esc), images[i].tag);
        json_esc(id_esc, sizeof(id_esc), images[i].id);
        if (i > 0) pos = jappend(buf, pos, max, ",");
        pos = jappend(buf, pos, max,
            "{\"repository\":\"%s\",\"tag\":\"%s\",\"id\":\"%s\","
            "\"size\":%zu,\"created\":%ld,\"pulled\":%ld}",
            repo_esc, tag_esc, id_esc,
            images[i].size, (long)images[i].created, (long)images[i].pulled);
    }

    pos = jappend(buf, pos, max, "],\"total\":%d}", img_count);
    send_json(fd, 200, buf, pos);
    free(buf);
}

/* GET /api/networks */
static void api_networks_list(int fd) {
    lochs_network_t nets[LOCHS_MAX_NETWORKS];
    int net_count = 0;

    FILE *f = fopen(NETWORKS_DB_FILE, "rb");
    if (f) {
        int cnt = 0;
        if (fread(&cnt, sizeof(cnt), 1, f) == 1) {
            if (cnt > LOCHS_MAX_NETWORKS) cnt = LOCHS_MAX_NETWORKS;
            for (int i = 0; i < cnt; i++) {
                if (fread(&nets[i], sizeof(lochs_network_t), 1, f) != 1) break;
                net_count++;
            }
        }
        fclose(f);
    }

    char *buf = malloc(32768);
    if (!buf) { send_error(fd, 500, "out of memory"); return; }

    int pos = 0, max = 32768;
    pos = jappend(buf, pos, max, "{\"networks\":[");

    for (int i = 0; i < net_count; i++) {
        char name_esc[128], sub_esc[128], gw_esc[128], br_esc[64];
        json_esc(name_esc, sizeof(name_esc), nets[i].name);
        json_esc(sub_esc, sizeof(sub_esc), nets[i].subnet);
        json_esc(gw_esc, sizeof(gw_esc), nets[i].gateway);
        json_esc(br_esc, sizeof(br_esc), nets[i].bridge);
        if (i > 0) pos = jappend(buf, pos, max, ",");
        pos = jappend(buf, pos, max,
            "{\"name\":\"%s\",\"subnet\":\"%s\",\"gateway\":\"%s\","
            "\"bridge\":\"%s\",\"active\":%s}",
            name_esc, sub_esc, gw_esc, br_esc,
            nets[i].active ? "true" : "false");
    }

    pos = jappend(buf, pos, max, "],\"total\":%d}", net_count);
    send_json(fd, 200, buf, pos);
    free(buf);
}

/* ====================================================================
 * Request Router
 * ==================================================================== */

static void handle_request(int client_fd, http_request_t *req) {
    /* Reload state on every request for freshness */
    lochs_state_load();

    /* Handle CORS preflight */
    if (strcmp(req->method, "OPTIONS") == 0) {
        send_response(client_fd, 200, "text/plain", "", 0);
        return;
    }

    if (strcmp(req->method, "GET") == 0) {
        /* Dashboard HTML */
        if (strcmp(req->path, "/") == 0) {
            send_response(client_fd, 200, "text/html; charset=utf-8",
                          DASHBOARD_HTML, (int)sizeof(DASHBOARD_HTML) - 1);
            return;
        }

        /* API endpoints */
        if (strcmp(req->path, "/api/system") == 0) {
            api_system_info(client_fd);
            return;
        }
        if (strcmp(req->path, "/api/containers") == 0) {
            api_containers_list(client_fd);
            return;
        }
        if (strcmp(req->path, "/api/images") == 0) {
            api_images_list(client_fd);
            return;
        }
        if (strcmp(req->path, "/api/networks") == 0) {
            api_networks_list(client_fd);
            return;
        }

        /* /api/containers/<name> */
        if (strncmp(req->path, "/api/containers/", 16) == 0) {
            const char *rest = req->path + 16;
            if (rest[0] && !strchr(rest, '/')) {
                api_container_detail(client_fd, rest);
                return;
            }
        }

        /* /api/logs/<name> */
        if (strncmp(req->path, "/api/logs/", 10) == 0 && req->path[10]) {
            api_container_logs(client_fd, req->path + 10);
            return;
        }

        /* /api/stats/<name> */
        if (strncmp(req->path, "/api/stats/", 11) == 0 && req->path[11]) {
            api_container_stats(client_fd, req->path + 11);
            return;
        }
    }

    if (strcmp(req->method, "POST") == 0) {
        /* /api/containers/<name>/<action> */
        if (strncmp(req->path, "/api/containers/", 16) == 0) {
            const char *rest = req->path + 16;
            if (rest[0] && strchr(rest, '/')) {
                api_container_action(client_fd, rest);
                return;
            }
        }
    }

    send_error(client_fd, 404, "not found");
}

/* ====================================================================
 * Server Loop
 * ==================================================================== */

static void dashboard_signal(int sig) {
    (void)sig;
    dashboard_running = 0;
}

static int dashboard_serve(int port) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 5) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    signal(SIGTERM, dashboard_signal);
    signal(SIGINT, dashboard_signal);
    signal(SIGPIPE, SIG_IGN);

    fprintf(stderr, "Dashboard listening on port %d\n", port);

    while (dashboard_running) {
        /* Use select with 1 second timeout to check running flag */
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(server_fd, &fds);
        struct timeval tv = {1, 0};

        int sel = select(server_fd + 1, &fds, NULL, NULL, &tv);
        if (sel <= 0) continue;

        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) continue;

        /* Set read timeout on client */
        struct timeval client_tv = {5, 0};
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &client_tv, sizeof(client_tv));

        /* Read request */
        char raw[DASHBOARD_MAX_REQUEST];
        ssize_t n = read(client_fd, raw, sizeof(raw) - 1);
        if (n <= 0) {
            close(client_fd);
            continue;
        }
        raw[n] = '\0';

        /* Parse and handle */
        http_request_t req;
        if (parse_request(raw, (int)n, &req) == 0) {
            handle_request(client_fd, &req);
        } else {
            send_error(client_fd, 400, "bad request");
        }

        close(client_fd);
    }

    close(server_fd);
    unlink(DASHBOARD_PID_FILE);
    fprintf(stderr, "Dashboard stopped\n");
    return 0;
}

/* ====================================================================
 * Daemon Management
 * ==================================================================== */

static int dashboard_start(int port, int foreground) {
    /* Check if already running */
    FILE *pf = fopen(DASHBOARD_PID_FILE, "r");
    if (pf) {
        pid_t existing = 0;
        if (fscanf(pf, "%d", &existing) == 1) {
            if (kill(existing, 0) == 0) {
                printf("\033[1;31m\xf0\x9f\x8f\x94\xef\xb8\x8f  Lochs Dashboard\033[0m\n\n");
                printf("  Already running (pid=%d)\n", existing);
                printf("  http://localhost:%d\n\n", port);
                fclose(pf);
                return 0;
            }
        }
        fclose(pf);
    }

    if (foreground) {
        printf("\033[1;31m\xf0\x9f\x8f\x94\xef\xb8\x8f  Lochs Dashboard\033[0m\n\n");
        printf("  Running at: \033[1mhttp://localhost:%d\033[0m\n", port);
        printf("  Press Ctrl+C to stop\n\n");
        return dashboard_serve(port);
    }

    /* Fork daemon */
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid > 0) {
        /* Parent: print info and exit */
        printf("\033[1;31m\xf0\x9f\x8f\x94\xef\xb8\x8f  Lochs Dashboard\033[0m\n\n");
        printf("  Dashboard running at: \033[1mhttp://localhost:%d\033[0m\n", port);
        printf("  PID: %d\n", pid);
        printf("\n  Stop with: lochs dashboard stop\n\n");

        /* Write PID file */
        mkdir("/var/lib/lochs", 0755);
        FILE *f = fopen(DASHBOARD_PID_FILE, "w");
        if (f) {
            fprintf(f, "%d\n", pid);
            fclose(f);
        }
        return 0;
    }

    /* Child: become daemon */
    setsid();

    /* Redirect stdio */
    FILE *log = fopen(DASHBOARD_LOG_FILE, "a");
    if (log) {
        dup2(fileno(log), STDOUT_FILENO);
        dup2(fileno(log), STDERR_FILENO);
        fclose(log);
    }
    fclose(stdin);

    /* Write our own PID (fork gives parent the child pid, but after setsid
     * the child is its own session leader with the same pid) */
    FILE *f = fopen(DASHBOARD_PID_FILE, "w");
    if (f) {
        fprintf(f, "%d\n", getpid());
        fclose(f);
    }

    return dashboard_serve(port);
}

static int dashboard_stop(void) {
    FILE *f = fopen(DASHBOARD_PID_FILE, "r");
    if (!f) {
        printf("Dashboard is not running.\n");
        return 1;
    }

    pid_t pid = 0;
    if (fscanf(f, "%d", &pid) != 1 || pid <= 0) {
        fclose(f);
        unlink(DASHBOARD_PID_FILE);
        printf("Dashboard is not running.\n");
        return 1;
    }
    fclose(f);

    if (kill(pid, SIGTERM) == 0) {
        printf("Dashboard stopped (pid=%d)\n", pid);
        /* Wait briefly for clean shutdown */
        usleep(200000);
    } else {
        printf("Dashboard process %d not found.\n", pid);
    }

    unlink(DASHBOARD_PID_FILE);
    return 0;
}

static int dashboard_status(void) {
    FILE *f = fopen(DASHBOARD_PID_FILE, "r");
    if (!f) {
        printf("Dashboard: \033[31mstopped\033[0m\n");
        return 1;
    }

    pid_t pid = 0;
    if (fscanf(f, "%d", &pid) != 1) {
        fclose(f);
        printf("Dashboard: \033[31mstopped\033[0m\n");
        return 1;
    }
    fclose(f);

    if (kill(pid, 0) == 0) {
        printf("Dashboard: \033[32mrunning\033[0m (pid=%d)\n", pid);
        return 0;
    }

    printf("Dashboard: \033[31mstopped\033[0m (stale pid file)\n");
    unlink(DASHBOARD_PID_FILE);
    return 1;
}

/* ====================================================================
 * Command Entry Point
 * ==================================================================== */

int lochs_cmd_dashboard(int argc, char **argv) {
    int port = DASHBOARD_DEFAULT_PORT;
    int foreground = 0;

    /* Simple argument parsing (no getopt for this subcommand-based interface) */
    int i = 1;
    while (i < argc) {
        if (strcmp(argv[i], "stop") == 0) {
            return dashboard_stop();
        }
        if (strcmp(argv[i], "status") == 0) {
            return dashboard_status();
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: lochs dashboard [command] [options]\n\n");
            printf("Start a web-based management dashboard.\n\n");
            printf("Commands:\n");
            printf("  start             Start the dashboard (default)\n");
            printf("  stop              Stop the dashboard\n");
            printf("  status            Check dashboard status\n");
            printf("\nOptions:\n");
            printf("  -p, --port <n>    Port to listen on (default: %d)\n",
                   DASHBOARD_DEFAULT_PORT);
            printf("  --foreground      Run in foreground (don't daemonize)\n");
            printf("\nExamples:\n");
            printf("  lochs dashboard                    Start on port %d\n",
                   DASHBOARD_DEFAULT_PORT);
            printf("  lochs dashboard --port 9000        Custom port\n");
            printf("  lochs dashboard --foreground        Debug mode\n");
            printf("  lochs dashboard stop               Stop dashboard\n");
            printf("  lochs dashboard status             Check status\n");
            return 0;
        }
        if ((strcmp(argv[i], "--port") == 0 || strcmp(argv[i], "-p") == 0) && i + 1 < argc) {
            port = atoi(argv[i + 1]);
            if (port < 1 || port > 65535) {
                fprintf(stderr, "Error: invalid port number\n");
                return 1;
            }
            i += 2;
            continue;
        }
        if (strcmp(argv[i], "--foreground") == 0) {
            foreground = 1;
            i++;
            continue;
        }
        if (strcmp(argv[i], "start") == 0) {
            i++;
            continue;
        }
        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return 1;
    }

    return dashboard_start(port, foreground);
}
