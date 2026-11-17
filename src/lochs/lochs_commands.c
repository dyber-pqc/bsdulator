/*
 * Lochs command implementations
 * 
 * Lochs uses FreeBSD's real jail system via BSDulator.
 * 
 * Architecture:
 *   lochs start myjail
 *       └── BSDulator
 *           └── FreeBSD jail binary (from container image)
 *               └── Creates real FreeBSD jail (translated to Linux namespaces)
 *
 *   lochs exec myjail /bin/sh
 *       └── BSDulator  
 *           └── FreeBSD jexec binary (from container image)
 *               └── Attaches to jail and runs command
 */

#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <stdint.h>
#include <signal.h>
#include <netinet/in.h>  /* For struct in_addr, in6_addr */
#include <arpa/inet.h>   /* For inet_pton */
#include "bsdulator/lochs.h"
#include "bsdulator/lochs_exec.h"
#include "bsdulator/lochs_ns.h"
#include "lochs_compose.h"

/* Global jail list - exposed for network module */
lochs_jail_t lochs_jails[LOCHS_MAX_JAILS];
int lochs_jail_count = 0;

/* Legacy aliases for internal use */
#define jails lochs_jails
#define jail_count lochs_jail_count

#define STATE_FILE "/var/lib/lochs/jails.dat"
#define IMAGES_DIR "/var/lib/lochs/images"
#define BSDULATOR_JAIL_STATE "/tmp/bsdulator_jails.dat"

/* BSDulator jail state file format */
#define JAIL_STATE_MAGIC 0x4A41494C  /* 'JAIL' */

typedef struct {
    uint32_t magic;
    uint32_t version;
    int32_t  next_jid;
    int32_t  jail_count;
} bsd_jail_header_t;

/*
 * bsd_jail_t structure layout from jail.h - MUST match exactly!
 * We need the full structure to read the state file correctly.
 */
typedef struct {
    int             jid;                        /* Jail ID (1-based) */
    int             parent_jid;                 /* Parent jail ID (0 = host) */
    char            name[256];                  /* Jail name */
    char            path[1024];                 /* Root path */
    char            hostname[256];              /* Hostname */
    char            domainname[256];            /* Domain name */
    
    /* IPv4 addresses */
    int             ip4_count;
    struct in_addr  ip4_addrs[16];
    
    /* IPv6 addresses */
    int             ip6_count;
    struct in6_addr ip6_addrs[16];
    
    /* Security settings */
    int             securelevel;
    int             devfs_ruleset;
    int             enforce_statfs;
    int             children_max;
    int             children_cur;
    
    /* Allow flags */
    int             allow_set_hostname;
    int             allow_sysvipc;
    int             allow_raw_sockets;
    int             allow_chflags;
    int             allow_mount;
    int             allow_quotas;
    int             allow_socket_af;
    int             vnet;

    /* State */
    int             active;                     /* Is this slot in use? */
    int             persist;
    int             dying;
    pid_t           creator_pid;
    int             attached_count;
    
    /* Linux namespace FDs */
    int             ns_pid;
    int             ns_mnt;
    int             ns_uts;
    int             ns_net;
    int             ns_user;
    int             ns_ipc;
} bsd_jail_entry_t;

/*
 * Read the actual JID from BSDulator's jail state file.
 * Returns the JID if found, -1 if not found.
 */
static int get_bsdulator_jid(const char *jail_name) {
    FILE *f = fopen(BSDULATOR_JAIL_STATE, "rb");
    if (!f) return -1;
    
    bsd_jail_header_t header;
    if (fread(&header, sizeof(header), 1, f) != 1) {
        fclose(f);
        return -1;
    }
    
    if (header.magic != JAIL_STATE_MAGIC) {
        fclose(f);
        return -1;
    }
    
    /* Read each jail entry looking for our name */
    for (int i = 0; i < header.jail_count; i++) {
        bsd_jail_entry_t entry;
        if (fread(&entry, sizeof(entry), 1, f) != 1) {
            break;
        }
        
        if (entry.active && strcmp(entry.name, jail_name) == 0) {
            fclose(f);
            return entry.jid;
        }
    }
    
    fclose(f);
    return -1;
}

/* Helper to safely copy strings */
static void safe_strcpy(char *dst, const char *src, size_t dst_size) {
    if (dst_size == 0) return;
    size_t src_len = strlen(src);
    size_t copy_len = (src_len < dst_size - 1) ? src_len : dst_size - 1;
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
}

/* Check if a file exists */
static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

/*
 * Parse volume mapping string "/host:/container" or "/host:/container:ro"
 * Returns 0 on success, -1 on error
 */
static int parse_volume_mapping(const char *str, lochs_volume_t *vol) {
    char buf[1024];
    safe_strcpy(buf, str, sizeof(buf));

    vol->readonly = 0;
    vol->volume_name[0] = '\0';

    /* Check for :ro suffix */
    char *ro = strstr(buf, ":ro");
    if (ro && (ro[3] == '\0' || ro[3] == ':')) {
        vol->readonly = 1;
        *ro = '\0';
    }

    /* Parse source:container */
    char *colon = strchr(buf, ':');
    if (!colon) {
        /* No colon - use same path for both (only valid for absolute paths) */
        safe_strcpy(vol->host_path, buf, sizeof(vol->host_path));
        safe_strcpy(vol->container_path, buf, sizeof(vol->container_path));
    } else {
        *colon = '\0';
        safe_strcpy(vol->container_path, colon + 1, sizeof(vol->container_path));

        if (buf[0] == '/') {
            /* Absolute path = bind mount */
            safe_strcpy(vol->host_path, buf, sizeof(vol->host_path));
        } else {
            /* Non-absolute path = named volume */
            safe_strcpy(vol->volume_name, buf, sizeof(vol->volume_name));
            vol->host_path[0] = '\0';  /* Resolved at start time */
        }
    }

    /* Validate container path starts with / */
    if (vol->container_path[0] != '/') {
        return -1;
    }

    /* For bind mounts, validate host path starts with / */
    if (vol->volume_name[0] == '\0' && vol->host_path[0] != '/') {
        return -1;
    }

    return 0;
}

/*
 * Parse environment variable "KEY=value"
 * Returns 0 on success, -1 on error
 */
/* Environment variable names: [A-Za-z_][A-Za-z0-9_]* */
static int env_key_valid(const char *key) {
    if (!key[0]) return 0;
    for (const char *p = key; *p; p++) {
        int alpha = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || *p == '_';
        int digit = (*p >= '0' && *p <= '9');
        if (!alpha && !(digit && p != key)) return 0;
    }
    return 1;
}

static int parse_env_var(const char *str, char *key, size_t key_size, char *value, size_t value_size) {
    const char *eq = strchr(str, '=');
    if (!eq) {
        /* Just a key, value is empty */
        if (strlen(str) >= key_size) return -1;
        safe_strcpy(key, str, key_size);
        value[0] = '\0';
        return env_key_valid(key) ? 0 : -1;
    }
    
    size_t klen = (size_t)(eq - str);
    if (klen == 0 || klen >= key_size) return -1;
    memcpy(key, str, klen);
    key[klen] = '\0';

    safe_strcpy(value, eq + 1, value_size);
    return env_key_valid(key) ? 0 : -1;
}

/*
 * Parse port mapping string "host:container" or "host:container/proto"
 * Returns 0 on success, -1 on error
 */
static int parse_port_mapping(const char *str, lochs_port_map_t *port) {
    char buf[64];
    safe_strcpy(buf, str, sizeof(buf));
    
    /* Default protocol */
    strcpy(port->protocol, "tcp");
    port->forwarder_pid = 0;
    
    /* Check for protocol suffix */
    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        safe_strcpy(port->protocol, slash + 1, sizeof(port->protocol));
    }
    
    /* Parse host:container */
    char *colon = strchr(buf, ':');
    if (!colon) {
        /* Just a port number - use same for host and container */
        port->host_port = atoi(buf);
        port->container_port = port->host_port;
    } else {
        *colon = '\0';
        port->host_port = atoi(buf);
        port->container_port = atoi(colon + 1);
    }
    
    if (port->host_port <= 0 || port->host_port > 65535 ||
        port->container_port <= 0 || port->container_port > 65535) {
        return -1;
    }
    
    return 0;
}

/*
 * Load image metadata from .lochs_image.conf
 * Reads CMD, ENTRYPOINT, WORKDIR from built images
 */
static void load_image_metadata(lochs_jail_t *jail, const char *image_path) {
    char conf_path[LOCHS_MAX_PATH + 32];
    snprintf(conf_path, sizeof(conf_path), "%s/.lochs_image.conf", image_path);
    
    FILE *f = fopen(conf_path, "r");
    if (!f) return;  /* No metadata file - that's OK for pulled images */
    
    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n') continue;
        
        /* Remove trailing newline */
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';
        
        /* Parse key=value */
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line;
        char *value = eq + 1;
        
        if (strcmp(key, "cmd") == 0) {
            safe_strcpy(jail->cmd, value, sizeof(jail->cmd));
        } else if (strcmp(key, "entrypoint") == 0) {
            safe_strcpy(jail->entrypoint, value, sizeof(jail->entrypoint));
        } else if (strcmp(key, "workdir") == 0) {
            safe_strcpy(jail->workdir, value, sizeof(jail->workdir));
        } else if (strcmp(key, "healthcheck.cmd") == 0) {
            safe_strcpy(jail->healthcheck.cmd, value, sizeof(jail->healthcheck.cmd));
            jail->healthcheck.enabled = 1;
        } else if (strcmp(key, "healthcheck.interval") == 0) {
            jail->healthcheck.interval = atoi(value);
        } else if (strcmp(key, "healthcheck.timeout") == 0) {
            jail->healthcheck.timeout = atoi(value);
        } else if (strcmp(key, "healthcheck.retries") == 0) {
            jail->healthcheck.retries = atoi(value);
        } else if (strcmp(key, "healthcheck.start_period") == 0) {
            jail->healthcheck.start_period = atoi(value);
        } else if (strcmp(key, "healthcheck.none") == 0) {
            jail->healthcheck.enabled = 0;
        }
    }
    
    fclose(f);
}

/*
 * lochs create <n> [options]
 */
int lochs_cmd_create(int argc, char **argv) {
    char *name = NULL;
    char *image = "freebsd:15";
    char *ip = NULL;
    char *path = NULL;
    char *network = NULL;
    int vnet = 0;
    lochs_port_map_t ports[LOCHS_MAX_PORTS];
    int port_count = 0;
    lochs_volume_t volumes[LOCHS_MAX_VOLUMES];
    int volume_count = 0;
    char env_keys[LOCHS_MAX_ENV][64];
    char env_values[LOCHS_MAX_ENV][256];
    int env_count = 0;

    /* Resource limits */
    int cpus_millicores = 0;
    int64_t memory_limit = 0;
    int64_t memory_swap_limit = 0;
    int pids_limit = 0;
    int cpu_weight = 0;

    /* Health check overrides */
    char *health_cmd = NULL;
    int health_interval = 0, health_timeout = 0, health_retries = 0, health_start_period = 0;
    int no_healthcheck = 0;

    static struct option long_options[] = {
        {"image",       required_argument, 0, 'i'},
        {"ip",          required_argument, 0, 'I'},
        {"publish",     required_argument, 0, 'p'},
        {"path",        required_argument, 0, 'P'},
        {"volume",      required_argument, 0, 'v'},
        {"env",         required_argument, 0, 'e'},
        {"network",     required_argument, 0, 'N'},
        {"vnet",        no_argument,       0, 'n'},
        {"cpus",        required_argument, 0, 'c'},
        {"memory",      required_argument, 0, 'm'},
        {"memory-swap", required_argument, 0, 'S'},
        {"pids-limit",  required_argument, 0, 'L'},
        {"cpu-weight",  required_argument, 0, 'w'},
        {"health-cmd",          required_argument, 0, 1001},
        {"health-interval",     required_argument, 0, 1002},
        {"health-timeout",      required_argument, 0, 1003},
        {"health-retries",      required_argument, 0, 1004},
        {"health-start-period", required_argument, 0, 1005},
        {"no-healthcheck",      no_argument,       0, 1006},
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    optind = 1;

    while ((opt = getopt_long(argc, argv, "i:I:p:P:v:e:N:nc:m:S:L:w:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i': image = optarg; break;
            case 'I': ip = optarg; break;
            case 'p':
                if (port_count < LOCHS_MAX_PORTS) {
                    if (parse_port_mapping(optarg, &ports[port_count]) == 0) {
                        port_count++;
                    } else {
                        fprintf(stderr, "Error: Invalid port mapping '%s'\n", optarg);
                        return 1;
                    }
                }
                break;
            case 'v':
                if (volume_count < LOCHS_MAX_VOLUMES) {
                    if (parse_volume_mapping(optarg, &volumes[volume_count]) == 0) {
                        volume_count++;
                    } else {
                        fprintf(stderr, "Error: Invalid volume mapping '%s'\n", optarg);
                        fprintf(stderr, "Format: /host/path:/container/path[:ro]\n");
                        return 1;
                    }
                }
                break;
            case 'e':
                if (env_count < LOCHS_MAX_ENV) {
                    if (parse_env_var(optarg, env_keys[env_count], sizeof(env_keys[0]),
                                     env_values[env_count], sizeof(env_values[0])) == 0) {
                        env_count++;
                    } else {
                        fprintf(stderr, "Error: invalid environment variable '%s' "
                                "(name must match [A-Za-z_][A-Za-z0-9_]*)\n", optarg);
                        return 1;
                    }
                }
                break;
            case 'N': network = optarg; break;
            case 'P': path = optarg; break;
            case 'n': vnet = 1; break;
            case 'c':
                cpus_millicores = lochs_parse_cpus(optarg);
                if (cpus_millicores < 0) {
                    fprintf(stderr, "Error: invalid CPU value '%s'\n", optarg);
                    fprintf(stderr, "Examples: --cpus 2, --cpus 0.5, --cpus 1.5\n");
                    return 1;
                }
                break;
            case 'm':
                memory_limit = lochs_parse_memory_size(optarg);
                if (memory_limit < 0) {
                    fprintf(stderr, "Error: invalid memory value '%s'\n", optarg);
                    fprintf(stderr, "Examples: --memory 512m, --memory 1g, --memory 256k\n");
                    return 1;
                }
                break;
            case 'S':
                memory_swap_limit = lochs_parse_memory_size(optarg);
                if (memory_swap_limit < 0) {
                    fprintf(stderr, "Error: invalid swap value '%s'\n", optarg);
                    return 1;
                }
                break;
            case 'L':
                pids_limit = atoi(optarg);
                if (pids_limit <= 0) {
                    fprintf(stderr, "Error: invalid PID limit '%s'\n", optarg);
                    return 1;
                }
                break;
            case 'w':
                cpu_weight = atoi(optarg);
                if (cpu_weight < 1 || cpu_weight > 10000) {
                    fprintf(stderr, "Error: CPU weight must be 1-10000\n");
                    return 1;
                }
                break;
            case 1001: health_cmd = optarg; break;
            case 1002: health_interval = atoi(optarg); break;
            case 1003: health_timeout = atoi(optarg); break;
            case 1004: health_retries = atoi(optarg); break;
            case 1005: health_start_period = atoi(optarg); break;
            case 1006: no_healthcheck = 1; break;
            case 'h':
                printf("Usage: lochs create <n> [options]\n\n");
                printf("Options:\n");
                printf("  -i, --image <image>       Base image (default: freebsd:15)\n");
                printf("  -I, --ip <addr>           IPv4 address for jail\n");
                printf("  -p, --publish <port>      Publish port (host:container)\n");
                printf("  -v, --volume <vol>        Mount volume (name:/path or /host:/container[:ro])\n");
                printf("  -e, --env <var>           Set environment variable (KEY=value)\n");
                printf("  -N, --network <net>       Connect to network\n");
                printf("  -P, --path <path>         Root filesystem path\n");
                printf("  -n, --vnet                Enable virtual networking\n");
                printf("\nResource Limits (cgroups v2):\n");
                printf("  -c, --cpus <n>            CPU limit (e.g., 2, 0.5, 1.5)\n");
                printf("  -m, --memory <size>       Memory limit (e.g., 512m, 1g, 256k)\n");
                printf("      --memory-swap <size>  Swap limit (default: 0 when memory set)\n");
                printf("      --pids-limit <n>      Max number of processes\n");
                printf("      --cpu-weight <n>      CPU scheduling weight (1-10000)\n");
                printf("\nHealth Checks:\n");
                printf("      --health-cmd <cmd>        Health check command\n");
                printf("      --health-interval <s>     Check interval in seconds (default: 30)\n");
                printf("      --health-timeout <s>      Check timeout in seconds (default: 30)\n");
                printf("      --health-retries <n>      Failures before unhealthy (default: 3)\n");
                printf("      --health-start-period <s> Grace period after start (default: 0)\n");
                printf("      --no-healthcheck          Disable image healthcheck\n");
                printf("\nExamples:\n");
                printf("  lochs create web -i freebsd:15 -p 8080:80\n");
                printf("  lochs create app -v /data:/app/data -e DEBUG=1\n");
                printf("  lochs create db --cpus 2 --memory 512m --pids-limit 200\n");
                printf("  lochs create worker -c 0.5 -m 256m\n");
                return 0;
            default:
                return 1;
        }
    }
    
    if (optind >= argc) {
        fprintf(stderr, "Error: container name required\n");
        fprintf(stderr, "Usage: lochs create <n> [options]\n");
        return 1;
    }
    
    name = argv[optind];

    if (!lochs_valid_name(name)) {
        lochs_reject_name("container name", name);
        return 1;
    }
    if (!lochs_valid_image_ref(image)) {
        fprintf(stderr, "Error: invalid image reference '%s'\n", image);
        return 1;
    }
    if (network && !lochs_valid_name(network)) {
        lochs_reject_name("network name", network);
        return 1;
    }
    if (ip) {
        struct in_addr probe;
        if (inet_pton(AF_INET, ip, &probe) != 1) {
            fprintf(stderr, "Error: invalid IPv4 address '%s'\n", ip);
            return 1;
        }
    }

    if (lochs_jail_find(name) != NULL) {
        fprintf(stderr, "Error: container '%s' already exists\n", name);
        return 1;
    }

    /* Determine root path */
    char root_path[LOCHS_MAX_PATH];
    if (path) {
        snprintf(root_path, sizeof(root_path), "%s", path);
    } else {
        char *img_path = lochs_image_get_path(image);
        if (!img_path) {
            fprintf(stderr, "Error: image '%s' not found\n", image);
            fprintf(stderr, "Run 'lochs pull %s' first, or use --path\n", image);
            return 1;
        }
        snprintf(root_path, sizeof(root_path), "%s", img_path);
        free(img_path);
    }
    
    /* Verify path exists */
    struct stat st;
    if (stat(root_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: path '%s' does not exist\n", root_path);
        return 1;
    }
    
    /* Check for required FreeBSD binaries in the image */
    char check_path[2048];
    snprintf(check_path, sizeof(check_path), "%s/libexec/ld-elf.so.1", root_path);
    if (!file_exists(check_path)) {
        fprintf(stderr, "Error: image missing /libexec/ld-elf.so.1\n");
        fprintf(stderr, "This doesn't appear to be a valid FreeBSD image.\n");
        return 1;
    }
    
    /* Create container entry */
    lochs_jail_t jail = {0};
    safe_strcpy(jail.name, name, sizeof(jail.name));
    safe_strcpy(jail.image, image, sizeof(jail.image));
    if (ip) safe_strcpy(jail.ip4_addr, ip, sizeof(jail.ip4_addr));
    jail.vnet = vnet;
    jail.state = JAIL_STATE_CREATED;
    jail.created_at = time(NULL);
    jail.jid = -1;
    
    /*
     * Set up container storage using OverlayFS COW.
     * This creates per-container directories for isolated filesystem.
     */
    if (lochs_storage_create_container(&jail, root_path) != 0) {
        fprintf(stderr, "Error: failed to create container storage\n");
        return 1;
    }
    /* jail.path is now set to the merged overlay path */

    /* Load image metadata (CMD, ENTRYPOINT, WORKDIR, HEALTHCHECK) */
    load_image_metadata(&jail, root_path);

    /* CLI health flags override image healthcheck */
    if (no_healthcheck) {
        memset(&jail.healthcheck, 0, sizeof(jail.healthcheck));
    } else if (health_cmd) {
        safe_strcpy(jail.healthcheck.cmd, health_cmd, sizeof(jail.healthcheck.cmd));
        jail.healthcheck.enabled = 1;
        jail.healthcheck.interval = health_interval > 0 ? health_interval : 30;
        jail.healthcheck.timeout = health_timeout > 0 ? health_timeout : 30;
        jail.healthcheck.retries = health_retries > 0 ? health_retries : 3;
        jail.healthcheck.start_period = health_start_period;
    } else if (jail.healthcheck.enabled) {
        /* Set defaults for image healthcheck if values missing */
        if (jail.healthcheck.interval <= 0) jail.healthcheck.interval = 30;
        if (jail.healthcheck.timeout <= 0) jail.healthcheck.timeout = 30;
        if (jail.healthcheck.retries <= 0) jail.healthcheck.retries = 3;
    }

    /* Copy port mappings */
    jail.port_count = port_count;
    for (int i = 0; i < port_count; i++) {
        jail.ports[i] = ports[i];
    }
    
    /* Copy volume mappings */
    jail.volume_count = volume_count;
    for (int i = 0; i < volume_count; i++) {
        jail.volumes[i] = volumes[i];
    }
    
    /* Copy environment variables */
    jail.env_count = env_count;
    for (int i = 0; i < env_count; i++) {
        safe_strcpy(jail.env_keys[i], env_keys[i], sizeof(jail.env_keys[0]));
        safe_strcpy(jail.env_values[i], env_values[i], sizeof(jail.env_values[0]));
    }
    
    /* Store network */
    if (network) {
        safe_strcpy(jail.network, network, sizeof(jail.network));
    }

    /* Store resource limits */
    jail.cpus_millicores = cpus_millicores;
    jail.memory_limit = memory_limit;
    jail.memory_swap_limit = memory_swap_limit;
    jail.pids_limit = pids_limit;
    jail.cpu_weight = cpu_weight;
    jail.cgroup_applied = 0;

    if (lochs_jail_add(&jail) != 0) {
        fprintf(stderr, "Error: failed to register container\n");
        return 1;
    }

    printf("Created container '%s'\n", name);
    printf("  Image: %s\n", image);
    printf("  Base:  %s\n", jail.image_path);
    printf("  Root:  %s (overlay)\n", jail.path);
    if (ip) printf("  IP:    %s\n", ip);
    if (port_count > 0) {
        printf("  Ports: ");
        for (int i = 0; i < port_count; i++) {
            printf("%d->%d/%s%s", ports[i].host_port, ports[i].container_port,
                   ports[i].protocol, (i < port_count - 1) ? ", " : "");
        }
        printf("\n");
    }
    if (volume_count > 0) {
        printf("  Volumes:\n");
        for (int i = 0; i < volume_count; i++) {
            if (volumes[i].volume_name[0]) {
                printf("    %s -> %s%s (named volume)\n",
                       volumes[i].volume_name, volumes[i].container_path,
                       volumes[i].readonly ? " (ro)" : "");
            } else {
                printf("    %s -> %s%s\n", volumes[i].host_path, volumes[i].container_path,
                       volumes[i].readonly ? " (ro)" : "");
            }
        }
    }
    if (env_count > 0) {
        printf("  Env:   ");
        for (int i = 0; i < env_count; i++) {
            printf("%s=%s%s", env_keys[i], env_values[i], (i < env_count - 1) ? ", " : "");
        }
        printf("\n");
    }
    if (network) {
        printf("  Network: %s\n", network);
    }
    if (cpus_millicores > 0 || memory_limit > 0 || pids_limit > 0) {
        printf("  Limits:");
        if (cpus_millicores > 0) {
            int whole = cpus_millicores / 1000;
            int frac = (cpus_millicores % 1000) / 100;
            if (frac > 0) {
                printf(" cpu=%d.%d", whole, frac);
            } else {
                printf(" cpu=%d", whole);
            }
        }
        if (memory_limit > 0) {
            if (memory_limit >= (int64_t)1024 * 1024 * 1024) {
                printf(" mem=%.1fG",
                       (double)memory_limit / (1024.0 * 1024.0 * 1024.0));
            } else if (memory_limit >= 1024 * 1024) {
                printf(" mem=%lldM",
                       (long long)(memory_limit / (1024 * 1024)));
            } else {
                printf(" mem=%lldK",
                       (long long)(memory_limit / 1024));
            }
        }
        if (pids_limit > 0) {
            printf(" pids=%d", pids_limit);
        }
        printf("\n");
    }
    if (jail.healthcheck.enabled) {
        printf("  Health: every %ds, timeout %ds, %d retries\n",
               jail.healthcheck.interval, jail.healthcheck.timeout,
               jail.healthcheck.retries);
        if (jail.healthcheck.start_period > 0)
            printf("          start-period %ds\n", jail.healthcheck.start_period);
    }
    printf("\nRun 'lochs start %s' to start the container.\n", name);

    return 0;
}

/*
 * Start port forwarding using socat
 * Returns PID of forwarder process, or -1 on error
 */
static pid_t start_port_forward(int host_port, int container_port, const char *protocol,
                                const char *target_ip) {
    /* TCP: socat TCP-LISTEN:host,fork,reuseaddr TCP:127.0.0.1:container */
    /* UDP: socat UDP-LISTEN:host,fork,reuseaddr UDP:127.0.0.1:container */
    char listen_spec[64], connect_spec[64];
    int udp = (strcmp(protocol, "udp") == 0);

    snprintf(listen_spec, sizeof(listen_spec), "%s-LISTEN:%d,fork,reuseaddr",
             udp ? "UDP" : "TCP", host_port);
    snprintf(connect_spec, sizeof(connect_spec), "%s:%s:%d",
             udp ? "UDP" : "TCP", target_ip ? target_ip : "127.0.0.1", container_port);

    const char *argv[] = { "socat", listen_spec, connect_spec, NULL };
    int pid = lochs_run(argv, LOCHS_RUN_NOWAIT | LOCHS_RUN_DETACH);
    return pid > 0 ? (pid_t)pid : -1;
}

/* Build "<jail path><suffix>" into buf. */
static const char *jail_subpath(char *buf, size_t size,
                                const lochs_jail_t *jail, const char *suffix) {
    snprintf(buf, size, "%s%s", jail->path, suffix);
    return buf;
}

/*
 * Stop port forwarding
 */
static void stop_port_forward(pid_t pid) {
    if (pid > 0) {
        kill(pid, SIGTERM);
    }
}

/*
 * Set up /dev devices inside the container filesystem.
 * Uses bind mounts from the host so we don't need CAP_MKNOD.
 * Called from lochs_cmd_start() after overlay mount.
 */
static int lochs_devfs_setup(lochs_jail_t *jail) {
    char p1[LOCHS_MAX_PATH + 32], p2[LOCHS_MAX_PATH + 32], p3[LOCHS_MAX_PATH + 32];

    /* Create /dev directory tree */
    {
        const char *argv[] = { "mkdir", "-p",
            jail_subpath(p1, sizeof(p1), jail, "/dev/pts"),
            jail_subpath(p3, sizeof(p3), jail, "/dev/shm"), NULL };
        if (lochs_run(argv, LOCHS_RUN_AS_CROOT) != 0) {
            fprintf(stderr, "Warning: failed to create /dev directories\n");
            return -1;
        }
    }

    /* Bind-mount standard devices from host */
    static const char *devices[] = {
        "null", "zero", "random", "urandom", "tty", NULL
    };
    for (int i = 0; devices[i]; i++) {
        char host_dev[64], suffix[64];
        snprintf(host_dev, sizeof(host_dev), "/dev/%s", devices[i]);
        snprintf(suffix, sizeof(suffix), "/dev/%s", devices[i]);
        jail_subpath(p1, sizeof(p1), jail, suffix);

        /* Create target file for bind mount */
        const char *touch_argv[] = { "touch", p1, NULL };
        lochs_run(touch_argv, LOCHS_RUN_QUIET | LOCHS_RUN_AS_CROOT);
        /* Bind mount from host */
        const char *mount_argv[] = { "mount", "--bind", host_dev, p1, NULL };
        if (lochs_run(mount_argv, LOCHS_RUN_QUIET) != 0) {
            fprintf(stderr, "  Warning: failed to mount /dev/%s\n", devices[i]);
        }
    }

    /* Mount devpts for PTY support */
    {
        const char *argv[] = { "mount", "-t", "devpts", "devpts",
            jail_subpath(p1, sizeof(p1), jail, "/dev/pts"),
            "-o", "newinstance,ptmxmode=0666", NULL };
        lochs_run(argv, LOCHS_RUN_QUIET);
    }

    /* /dev/ptmx and convenience symlinks */
    static const char *links[][2] = {
        { "pts/ptmx",         "/dev/ptmx" },
        { "/proc/self/fd",    "/dev/fd" },
        { "/proc/self/fd/0",  "/dev/stdin" },
        { "/proc/self/fd/1",  "/dev/stdout" },
        { "/proc/self/fd/2",  "/dev/stderr" },
    };
    /* Older lochs made /dev/fd a directory, and the link went inside it */
    {
        struct stat st;
        jail_subpath(p1, sizeof(p1), jail, "/dev/fd");
        if (lstat(p1, &st) == 0 && S_ISDIR(st.st_mode)) {
            jail_subpath(p2, sizeof(p2), jail, "/dev/fd/fd");
            lochs_croot_enter();
            unlink(p2);
            rmdir(p1);
            lochs_croot_leave();
        }
    }
    for (size_t i = 0; i < sizeof(links) / sizeof(links[0]); i++) {
        const char *argv[] = { "ln", "-sf", links[i][0],
            jail_subpath(p1, sizeof(p1), jail, links[i][1]), NULL };
        lochs_run(argv, LOCHS_RUN_QUIET | LOCHS_RUN_AS_CROOT);
    }

    /* /proc is mounted by the container's PID 1 (lochs_ns.c), so it
     * shows the container's processes and not the host's */
    {
        const char *mk_argv[] = { "mkdir", "-p",
            jail_subpath(p1, sizeof(p1), jail, "/proc"), NULL };
        lochs_run(mk_argv, LOCHS_RUN_AS_CROOT);
    }

    printf("  Devices: /dev mounted\n");
    return 0;
}

/*
 * Tear down /dev devices and /proc inside the container filesystem.
 * Called from lochs_cmd_stop() before unmounting volumes/overlay.
 */
static void lochs_devfs_teardown(lochs_jail_t *jail) {
    char p[LOCHS_MAX_PATH + 32];

    /* Unmount /proc, devpts, then the individual devices */
    static const char *targets[] = {
        "/proc", "/dev/pts", "/dev/null", "/dev/zero", "/dev/random",
        "/dev/urandom", "/dev/tty", NULL
    };
    for (int i = 0; targets[i]; i++) {
        const char *argv[] = { "umount",
            jail_subpath(p, sizeof(p), jail, targets[i]), NULL };
        lochs_run(argv, LOCHS_RUN_QUIET);
    }

    printf("  Devices: /dev unmounted\n");
}

/*
 * lochs start <n>
 *
 * Starts a FreeBSD jail using the jail binary from the container's image.
 */
int lochs_cmd_start(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: lochs start <n>\n");
        return 1;
    }
    
    const char *name = argv[1];
    lochs_jail_t *jail = lochs_jail_find(name);
    
    if (!jail) {
        fprintf(stderr, "Error: container '%s' not found\n", name);
        return 1;
    }
    
    if (jail->state == JAIL_STATE_RUNNING) {
        printf("Container '%s' is already running (jid=%d)\n", name, jail->jid);
        return 0;
    }
    
    /* Verify the container path exists */
    struct stat st;
    if (stat(jail->path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: container path '%s' does not exist\n", jail->path);
        return 1;
    }
    
    printf("Starting container '%s'...\n", name);
    
    /*
     * The container's id range (user namespace). With idmapped layers each
     * container has its own and the layers keep container ids on disk;
     * otherwise all share LOCHS_ID_BASE and the layers are chown-shifted
     * into it (see lochs_ns.c).
     */
    lochs_storage_lockdown();
    int layered = jail->image_path[0] && jail->merged_path[0];
    int overlay = layered && jail->storage_backend != LOCHS_STORAGE_ZFS;
    int idmapped = overlay && lochs_idmap_supported();
    uid_t ids = idmapped ? lochs_ids_alloc(jail->name) : (uid_t)LOCHS_ID_BASE;
    if (overlay && !idmapped)
        fprintf(stderr, "Note: this kernel cannot mount idmapped layers (Linux 5.19+); "
                        "'%s' shares id range %d with other containers\n", name, LOCHS_ID_BASE);
    if (layered) {
        lochs_image_ids(jail->image_path, idmapped ? 0 : (uid_t)LOCHS_ID_BASE);
        if (jail->diff_path[0]) {
            if (idmapped) lochs_idshift_tree(jail->diff_path, LOCHS_ID_BASE, 0);
            else lochs_idshift_tree(jail->diff_path, 0, LOCHS_ID_BASE);
        }
    } else if (jail->path[0]) {
        lochs_image_ids(jail->path, LOCHS_ID_BASE);
    }
    lochs_ns_set_base(jail->name, ids);
    lochs_croot_set(ids);

    /* Mount overlay filesystem if using COW storage */
    if (jail->image_path[0] && jail->merged_path[0]) {
        int mr;
        if (idmapped) {
            /* A mount left from before (another range, or none) is
             * replaced, never reused */
            umount2(jail->merged_path, MNT_DETACH);
            char cdir[LOCHS_MAX_PATH];
            snprintf(cdir, sizeof(cdir), "%s", jail->diff_path);
            char *slash = strrchr(cdir, '/');
            if (slash) *slash = '\0';
            mr = lochs_idmap_mount_overlay(jail->name, ids, jail->image_path, cdir,
                                           jail->merged_path);
            if (mr == 0) jail->overlay_mounted = 1;
        } else {
            mr = lochs_storage_mount_container(jail);
        }
        if (mr != 0) {
            fprintf(stderr, "Error: failed to mount container filesystem\n");
            return 1;
        }
        if (idmapped)
            printf("  Overlay: mounted (ids %u-%u)\n", (unsigned)ids,
                   (unsigned)(ids + LOCHS_ID_COUNT - 1));
        else
            printf("  Overlay: mounted\n");
    }
    
    /* Without a lochs network, the container gets its own network
     * namespace and IP; -p forwards to that IP */
    if (!jail->network[0]) {
        if (lochs_ns_net_up(jail->name, jail->netns, sizeof(jail->netns)) == 0)
            printf("  Network: %s (%s)\n", jail->netns, lochs_ns_ip(jail->name));
        else
            fprintf(stderr, "Warning: could not create a network namespace for '%s'\n", name);
    }

    /* Set up network if configured */
    if (jail->network[0]) {
        lochs_networks_load();
        if (lochs_network_setup_container(name, jail->network) != 0) {
            fprintf(stderr, "Warning: failed to set up network\n");
        }
    }
    
    /* Resolve named volumes before mounting */
    if (jail->volume_count > 0) {
        lochs_volumes_load();
        for (int i = 0; i < jail->volume_count; i++) {
            lochs_volume_t *v = &jail->volumes[i];
            if (v->volume_name[0] && v->host_path[0] == '\0') {
                /* Named volume - resolve to host path */
                const char *vpath = lochs_volume_get_path(v->volume_name);
                if (!vpath) {
                    /* Auto-create on first use (Docker behavior) */
                    printf("  Creating volume '%s'...\n", v->volume_name);
                    if (lochs_volume_create(v->volume_name) != 0) {
                        fprintf(stderr, "Error: failed to create volume '%s'\n",
                                v->volume_name);
                        continue;
                    }
                    vpath = lochs_volume_get_path(v->volume_name);
                }
                if (vpath) {
                    safe_strcpy(v->host_path, vpath, sizeof(v->host_path));
                }
            }
        }
    }

    /* Mount volumes before starting jail */
    if (jail->volume_count > 0) {
        printf("Mounting volumes...\n");
        for (int i = 0; i < jail->volume_count; i++) {
            lochs_volume_t *v = &jail->volumes[i];
            char mount_point[2048];

            /* Skip volumes that couldn't be resolved */
            if (v->host_path[0] == '\0') {
                fprintf(stderr, "  Warning: skipping unresolved volume '%s'\n",
                        v->volume_name);
                continue;
            }

            /* Create mount point in container */
            snprintf(mount_point, sizeof(mount_point), "%s%s", jail->path, v->container_path);
            const char *mkdir_argv[] = { "mkdir", "-p", mount_point, NULL };
            lochs_run(mkdir_argv, LOCHS_RUN_AS_CROOT);

            /*
             * Ownership (see lochs_ns.c). A named volume keeps container
             * ids on disk, like the layers, and is mounted idmapped into
             * the container's range. A host directory is mapped to its
             * owner only: that host user is container root there, so the
             * container gets no more than the owner's rights (nosuid,
             * nodev). One owned by host root keeps host ids: mapping it
             * would make container root host root in it.
             */
            const char *how = "";
            int done = 0;
            if (v->volume_name[0]) {
                char key[160];
                snprintf(key, sizeof(key), "volume.%s", v->volume_name);
                if (idmapped) {
                    lochs_tree_ids(key, v->host_path, 0);
                    done = lochs_idmap_bind(v->host_path, mount_point, 0, 0, ids,
                                            LOCHS_ID_COUNT, v->readonly, 0) == 0;
                    if (!done)
                        fprintf(stderr, "  Warning: cannot idmap volume '%s' (%s)\n",
                                v->volume_name, strerror(errno));
                } else {
                    lochs_tree_ids(key, v->host_path, LOCHS_ID_BASE);
                }
            } else {
                struct stat vst;
                if (stat(v->host_path, &vst) != 0) {
                    fprintf(stderr, "  Warning: %s: %s\n", v->host_path, strerror(errno));
                } else if (idmapped && vst.st_uid != 0) {
                    done = lochs_idmap_bind(v->host_path, mount_point, vst.st_uid, vst.st_gid,
                                            ids, 1, v->readonly, 1) == 0;
                    if (done)
                        how = " (its owner is container root)";
                    else
                        how = " (host ids: the filesystem cannot be idmapped)";
                } else if (idmapped) {
                    how = " (host ids: owned by host root)";
                }
            }

            if (!done) {
                const char *bind_argv[] = { "mount", "--bind", v->host_path, mount_point, NULL };
                if (lochs_run(bind_argv, 0) != 0) {
                    fprintf(stderr, "  Warning: Failed to mount %s\n", v->host_path);
                    continue;
                }
                /* Make read-only if requested */
                if (v->readonly) {
                    const char *ro_argv[] = { "mount", "-o", "remount,ro,bind",
                                              mount_point, NULL };
                    lochs_run(ro_argv, 0);
                }
                done = 1;
            }
            if (v->volume_name[0]) {
                printf("  %s (%s) -> %s%s\n", v->volume_name, v->host_path,
                       v->container_path, v->readonly ? " (ro)" : "");
            } else {
                printf("  %s -> %s%s%s\n", v->host_path, v->container_path,
                       v->readonly ? " (ro)" : "", how);
            }
        }
    }
    
    /* Apply cgroup resource limits before starting the jail */
    if (jail->cpus_millicores > 0 || jail->memory_limit > 0 ||
        jail->pids_limit > 0 || jail->cpu_weight > 0) {
        lochs_cgroup_apply_limits(jail);
    }

    /* Write environment file for container */
    if (jail->env_count > 0) {
        char env_file[2048];
        snprintf(env_file, sizeof(env_file), "%s/.lochs_env", jail->path);
        lochs_croot_enter();
        FILE *ef = fopen(env_file, "w");
        lochs_croot_leave();
        if (ef) {
            for (int i = 0; i < jail->env_count; i++) {
                /* Quote the value so the jail's shell reads it literally */
                fprintf(ef, "export %s=", jail->env_keys[i]);
                lochs_fprint_shell_quoted(ef, jail->env_values[i]);
                fputc('\n', ef);
            }
            fclose(ef);
            printf("Environment: %d variable(s) set\n", jail->env_count);
        }
    }

    /* Set up /dev devices inside the container */
    lochs_devfs_setup(jail);

    /* The container's own user, PID, mount, UTS and IPC namespaces: every
     * bsdulator run below joins them */
    if (lochs_ns_start(jail->name, jail->path) < 0)
        fprintf(stderr, "Warning: could not create namespaces for '%s'; running without them\n", name);
    char ns_arg[16];

    /*
     * Build the jail command using binaries FROM THE CONTAINER IMAGE.
     *
     * If container has network namespace, pass --netns to bsdulator.
     * BSDulator will enter the namespace in the child process AFTER
     * ptrace setup but BEFORE execve, avoiding ptrace conflicts.
     *
     * If resource limits are active, we prefix the command with a
     * cgroup migration: "echo $$ > /sys/fs/cgroup/lochs/<name>/cgroup.procs && ..."
     * This moves the shell (and all child processes) into the cgroup
     * BEFORE launching bsdulator, so the jail and all its processes
     * inherit the resource limits.
     *
     * Format: bsdulator [--netns <ns>] <ld-elf.so.1> <jail> -c name=X path=Y persist
     *
     * Each value is its own argument (no shell), and the child joins the
     * cgroup itself before exec when limits are active.
     */
    char ld_path[LOCHS_MAX_PATH + 32], jail_bin[LOCHS_MAX_PATH + 32];
    char name_arg[LOCHS_MAX_NAME + 8], path_arg[LOCHS_MAX_PATH + 8];
    char ip_arg[128], cgroup_procs[LOCHS_MAX_NAME + 64];
    const char *jargv[20];
    int ja = 0;

    jail_subpath(ld_path, sizeof(ld_path), jail, "/libexec/ld-elf.so.1");
    jail_subpath(jail_bin, sizeof(jail_bin), jail, "/usr/sbin/jail");
    snprintf(name_arg, sizeof(name_arg), "name=%s", jail->name);
    snprintf(path_arg, sizeof(path_arg), "path=%s", jail->path);

    jargv[ja++] = lochs_bsdulator_path();
    /* Resolve FreeBSD paths (libraries, ld-elf) against this container */
    jargv[ja++] = "-r";
    jargv[ja++] = jail->path;
    lochs_ns_add_args(jail->name, jargv, &ja, ns_arg, sizeof(ns_arg));
    if (jail->netns[0]) {
        jargv[ja++] = "--netns";
        jargv[ja++] = jail->netns;
    }
    jargv[ja++] = ld_path;
    jargv[ja++] = jail_bin;
    jargv[ja++] = "-c";
    jargv[ja++] = name_arg;
    jargv[ja++] = path_arg;
    if (jail->ip4_addr[0]) {
        snprintf(ip_arg, sizeof(ip_arg), "ip4.addr=%s", jail->ip4_addr);
        jargv[ja++] = ip_arg;
    }
    if (jail->vnet) jargv[ja++] = "vnet";
    jargv[ja++] = "persist";
    jargv[ja] = NULL;

    snprintf(cgroup_procs, sizeof(cgroup_procs),
             "/sys/fs/cgroup/lochs/%s/cgroup.procs", jail->name);

    int ret = lochs_run_in_cgroup(jargv,
                                  jail->cgroup_applied ? cgroup_procs : NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "Failed to start container '%s': could not run bsdulator\n", name);
        return 1;
    }
    
    /* Get the actual JID from BSDulator's jail state */
    int actual_jid = get_bsdulator_jid(jail->name);
    if (actual_jid > 0) {
        jail->jid = actual_jid;
    } else {
        /* Fallback - jail may have been created but we can't read the JID */
        jail->jid = 1;
    }
    
    jail->state = JAIL_STATE_RUNNING;
    jail->started_at = time(NULL);
    
    /* Start port forwarding */
    if (jail->port_count > 0) {
        printf("Setting up port forwarding...\n");
        for (int i = 0; i < jail->port_count; i++) {
            lochs_port_map_t *p = &jail->ports[i];
            p->forwarder_pid = start_port_forward(p->host_port, p->container_port, p->protocol,
                                                  lochs_ns_ip(jail->name));
            if (p->forwarder_pid > 0) {
                printf("  %d -> %d/%s (pid=%d)\n", 
                       p->host_port, p->container_port, p->protocol, p->forwarder_pid);
            } else {
                fprintf(stderr, "  Warning: Failed to forward %d -> %d/%s\n",
                        p->host_port, p->container_port, p->protocol);
            }
        }
    }
    
    printf("Container '%s' started (jid=%d)\n", name, jail->jid);

    /* Auto-start CMD if configured */
    if (jail->cmd[0]) {
        printf("Running CMD: %s\n", jail->cmd);

        /* Run CMD in the background through the jail's own /bin/sh, so
         * the host never parses it; join the cgroup first if active. */
        char jexec_bin[LOCHS_MAX_PATH + 32];
        const char *cargv[20];
        int ca = 0;

        jail_subpath(jexec_bin, sizeof(jexec_bin), jail, "/usr/sbin/jexec");
        cargv[ca++] = lochs_bsdulator_path();
        cargv[ca++] = "-r";
        cargv[ca++] = jail->path;
        lochs_ns_add_args(jail->name, cargv, &ca, ns_arg, sizeof(ns_arg));
        if (jail->netns[0]) {
            cargv[ca++] = "--netns";
            cargv[ca++] = jail->netns;
        }
        cargv[ca++] = ld_path;
        cargv[ca++] = jexec_bin;
        cargv[ca++] = jail->name;
        cargv[ca++] = "/bin/sh";
        cargv[ca++] = "-c";
        cargv[ca++] = jail->cmd;
        cargv[ca] = NULL;

        if (lochs_run_in_cgroup(cargv, jail->cgroup_applied ? cgroup_procs : NULL,
                                LOCHS_RUN_NOWAIT | LOCHS_RUN_DETACH) < 0)
            fprintf(stderr, "  Warning: failed to launch CMD\n");
    }

    /* Start health check monitor if configured */
    if (jail->healthcheck.enabled && jail->healthcheck.cmd[0]) {
        if (lochs_health_monitor_start(jail) == 0) {
            printf("  Health monitor: started (interval=%ds, retries=%d)\n",
                   jail->healthcheck.interval, jail->healthcheck.retries);
        } else {
            fprintf(stderr, "  Warning: Failed to start health monitor\n");
        }
    }

    /* Save state with updated JID and port PIDs */
    lochs_state_save();
    
    return 0;
}

/*
 * lochs stop <n>
 * 
 * Stops a FreeBSD jail using jail -r.
 */
int lochs_cmd_stop(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: lochs stop <n>\n");
        return 1;
    }
    
    const char *name = argv[1];
    lochs_jail_t *jail = lochs_jail_find(name);
    
    if (!jail) {
        fprintf(stderr, "Error: container '%s' not found\n", name);
        return 1;
    }
    
    if (jail->state != JAIL_STATE_RUNNING) {
        fprintf(stderr, "Container '%s' is not running\n", name);
        return 1;
    }
    
    printf("Stopping container '%s'...\n", name);

    /* Stop health check monitor */
    if (jail->health_monitor_pid > 0) {
        lochs_health_monitor_stop(jail);
        printf("  Health monitor: stopped\n");
    }

    /* Stop port forwarders first */
    if (jail->port_count > 0) {
        printf("Stopping port forwarding...\n");
        for (int i = 0; i < jail->port_count; i++) {
            lochs_port_map_t *p = &jail->ports[i];
            if (p->forwarder_pid > 0) {
                stop_port_forward(p->forwarder_pid);
                p->forwarder_pid = 0;
            }
        }
    }
    
    /* Tear down /dev devices */
    lochs_devfs_teardown(jail);

    /* Unmount volumes */
    if (jail->volume_count > 0) {
        printf("Unmounting volumes...\n");
        for (int i = jail->volume_count - 1; i >= 0; i--) {
            lochs_volume_t *v = &jail->volumes[i];
            char mount_point[2048];

            snprintf(mount_point, sizeof(mount_point), "%s%s", jail->path, v->container_path);
            const char *umount_argv[] = { "umount", mount_point, NULL };
            lochs_run(umount_argv, LOCHS_RUN_QUIET);
        }
    }
    
    /* Tear down network */
    if (jail->network[0]) {
        lochs_network_teardown_container(name);
    }

    /* Use jail -r from the container image */
    char ld_path[LOCHS_MAX_PATH + 32], jail_bin[LOCHS_MAX_PATH + 32];
    jail_subpath(ld_path, sizeof(ld_path), jail, "/libexec/ld-elf.so.1");
    jail_subpath(jail_bin, sizeof(jail_bin), jail, "/usr/sbin/jail");
    const char *rargv[] = { lochs_bsdulator_path(), "-r", jail->path,
                            ld_path, jail_bin, "-r", jail->name, NULL };

    int ret = lochs_run(rargv, 0);

    /* Ends every process still in the container */
    lochs_ns_stop(jail->name);

    /* Volumes are mounts inside the overlay: off before it */
    for (int i = 0; i < jail->volume_count; i++) {
        char mp[2048];
        snprintf(mp, sizeof(mp), "%s%s", jail->path, jail->volumes[i].container_path);
        umount2(mp, MNT_DETACH);
    }
    if (!jail->network[0] && strncmp(jail->netns, "lochs-", 6) == 0) {
        lochs_ns_net_down(jail->name);
        jail->netns[0] = '\0';
    }

    if (ret == 0) {
        jail->state = JAIL_STATE_STOPPED;
        jail->jid = -1;
        printf("Container '%s' stopped\n", name);
    } else {
        /* Even if jail -r fails, mark as stopped */
        jail->state = JAIL_STATE_STOPPED;
        jail->jid = -1;
        fprintf(stderr, "Warning: jail -r returned error, but marking as stopped\n");
    }

    /* Clean up cgroup resource limits */
    if (jail->cgroup_applied) {
        lochs_cgroup_cleanup(jail);
    }

    /* Unmount overlay filesystem */
    if (jail->overlay_mounted) {
        lochs_storage_unmount_container(jail);
        printf("  Overlay: unmounted\n");
    }
    lochs_idmap_unmount(jail->name);
    
    /* Save state */
    lochs_state_save();
    
    return 0;
}

/*
 * lochs rm [-f] <n>
 */
int lochs_cmd_rm(int argc, char **argv) {
    int force = 0;
    int idx = 1;
    
    if (argc >= 2 && (strcmp(argv[1], "-f") == 0 || strcmp(argv[1], "--force") == 0)) {
        force = 1;
        idx = 2;
    }
    
    if (idx >= argc) {
        fprintf(stderr, "Usage: lochs rm [-f] <n>\n");
        return 1;
    }
    
    const char *name = argv[idx];
    lochs_jail_t *jail = lochs_jail_find(name);
    
    if (!jail) {
        fprintf(stderr, "Error: container '%s' not found\n", name);
        return 1;
    }
    
    if (jail->state == JAIL_STATE_RUNNING) {
        if (force) {
            printf("Force stopping container '%s'...\n", name);
            char *stop_argv[] = {"stop", (char*)name, NULL};
            lochs_cmd_stop(2, stop_argv);
        } else {
            fprintf(stderr, "Error: container '%s' is running. Stop it first or use -f\n", name);
            return 1;
        }
    }
    
    /* Destroy container storage (overlay directories) */
    lochs_storage_destroy_container(jail);
    lochs_ids_free(name);
    
    if (lochs_jail_remove(name) == 0) {
        printf("Removed container '%s'\n", name);
        lochs_state_save();
    } else {
        fprintf(stderr, "Failed to remove container '%s'\n", name);
        return 1;
    }
    
    return 0;
}

/*
 * lochs exec <n> <command...>
 * 
 * Execute a command in a running jail using jexec from the container image.
 */
int lochs_cmd_exec(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: lochs exec <n> <command> [args...]\n");
        return 1;
    }
    
    const char *name = argv[1];
    lochs_jail_t *jail = lochs_jail_find(name);
    
    if (!jail) {
        fprintf(stderr, "Error: container '%s' not found\n", name);
        return 1;
    }
    
    if (jail->state != JAIL_STATE_RUNNING) {
        fprintf(stderr, "Error: container '%s' is not running\n", name);
        fprintf(stderr, "Run 'lochs start %s' first.\n", name);
        return 1;
    }
    
    /*
     * Run jexec using binaries FROM THE CONTAINER IMAGE, passing the
     * user's command and arguments through unchanged (no host shell).
     * Format: bsdulator [--netns <ns>] <ld-elf.so.1> <jexec> <jail-name> <command...>
     */
    char ld_path[LOCHS_MAX_PATH + 32], jexec_bin[LOCHS_MAX_PATH + 32];
    jail_subpath(ld_path, sizeof(ld_path), jail, "/libexec/ld-elf.so.1");
    jail_subpath(jexec_bin, sizeof(jexec_bin), jail, "/usr/sbin/jexec");

    const char **eargv = calloc((size_t)argc + 12, sizeof(*eargv));
    char ns_arg[16];
    if (!eargv) {
        fprintf(stderr, "Error: out of memory\n");
        return 1;
    }
    int ea = 0;
    eargv[ea++] = lochs_bsdulator_path();
    eargv[ea++] = "-r";
    eargv[ea++] = jail->path;
    lochs_ns_add_args(jail->name, eargv, &ea, ns_arg, sizeof(ns_arg));
    if (jail->netns[0]) {
        eargv[ea++] = "--netns";
        eargv[ea++] = jail->netns;
    }
    eargv[ea++] = ld_path;
    eargv[ea++] = jexec_bin;
    eargv[ea++] = jail->name;
    for (int i = 2; i < argc; i++)
        eargv[ea++] = argv[i];
    eargv[ea] = NULL;

    /* Show output and append it to the container's log */
    char log_path[LOCHS_MAX_NAME + 64];
    mkdir("/var/lib/lochs", 0755);
    mkdir("/var/lib/lochs/logs", 0755);
    snprintf(log_path, sizeof(log_path), "/var/lib/lochs/logs/%s.log", jail->name);

    int ret = lochs_run_tee(eargv, log_path);
    free(eargv);
    if (ret < 0) {
        fprintf(stderr, "Error: could not run bsdulator\n");
        return 1;
    }
    return ret;
}

/*
 * lochs ps - List containers
 * 
 * Syncs state with BSDulator's jail state to show accurate JIDs and status.
 */
int lochs_cmd_ps(int argc, char **argv) {
    (void)argc; (void)argv;
    
    /* Sync JIDs with BSDulator state */
    int state_changed = 0;
    for (int i = 0; i < jail_count; i++) {
        lochs_jail_t *j = &jails[i];
        if (j->state == JAIL_STATE_RUNNING) {
            int actual_jid = get_bsdulator_jid(j->name);
            if (actual_jid > 0) {
                if (j->jid != actual_jid) {
                    j->jid = actual_jid;
                    state_changed = 1;
                }
            } else {
                /* Jail no longer exists in BSDulator - mark as stopped */
                j->state = JAIL_STATE_STOPPED;
                j->jid = -1;
                state_changed = 1;
            }
        }
    }
    
    printf("%-15s %-6s %-20s %-15s %-12s %-20s %-15s %s\n",
           "NAME", "JID", "IMAGE", "STATUS", "HEALTH", "PORTS", "LIMITS", "PATH");
    printf("%-15s %-6s %-20s %-15s %-12s %-20s %-15s %s\n",
           "----", "---", "-----", "------", "------", "-----", "------", "----");

    for (int i = 0; i < jail_count; i++) {
        lochs_jail_t *j = &jails[i];
        const char *state_str;

        switch (j->state) {
            case JAIL_STATE_CREATED: state_str = "created"; break;
            case JAIL_STATE_RUNNING: state_str = "\033[32mrunning\033[0m"; break;
            case JAIL_STATE_STOPPED: state_str = "stopped"; break;
            default: state_str = "unknown"; break;
        }

        char jid_str[16];
        if (j->jid > 0) {
            snprintf(jid_str, sizeof(jid_str), "%d", j->jid);
        } else {
            strcpy(jid_str, "-");
        }

        /* Build ports string */
        char ports_str[64] = "-";
        if (j->port_count > 0) {
            int ppos = 0;
            for (int p = 0; p < j->port_count && ppos < (int)sizeof(ports_str) - 10; p++) {
                if (p > 0) ppos += snprintf(ports_str + ppos, sizeof(ports_str) - (size_t)ppos, ",");
                ppos += snprintf(ports_str + ppos, sizeof(ports_str) - (size_t)ppos,
                               "%d->%d", j->ports[p].host_port, j->ports[p].container_port);
            }
        }

        /* Build resource limits string */
        char limits_str[64] = "-";
        if (j->cpus_millicores > 0 || j->memory_limit > 0 || j->pids_limit > 0) {
            int lpos = 0;
            if (j->cpus_millicores > 0) {
                int whole = j->cpus_millicores / 1000;
                int frac = (j->cpus_millicores % 1000) / 100;
                if (frac > 0) {
                    lpos += snprintf(limits_str + lpos, sizeof(limits_str) - (size_t)lpos,
                                     "%d.%dc", whole, frac);
                } else {
                    lpos += snprintf(limits_str + lpos, sizeof(limits_str) - (size_t)lpos,
                                     "%dc", whole);
                }
            }
            if (j->memory_limit > 0) {
                if (lpos > 0) limits_str[lpos++] = '/';
                if (j->memory_limit >= (int64_t)1024 * 1024 * 1024) {
                    lpos += snprintf(limits_str + lpos, sizeof(limits_str) - (size_t)lpos,
                                     "%.0fG", (double)j->memory_limit / (1024.0*1024.0*1024.0));
                } else if (j->memory_limit >= 1024 * 1024) {
                    lpos += snprintf(limits_str + lpos, sizeof(limits_str) - (size_t)lpos,
                                     "%lldM", (long long)(j->memory_limit / (1024*1024)));
                } else {
                    lpos += snprintf(limits_str + lpos, sizeof(limits_str) - (size_t)lpos,
                                     "%lldK", (long long)(j->memory_limit / 1024));
                }
            }
            if (j->pids_limit > 0) {
                if (lpos > 0) limits_str[lpos++] = '/';
                snprintf(limits_str + lpos, sizeof(limits_str) - (size_t)lpos,
                         "%dp", j->pids_limit);
            }
        }

        /* Build health status string */
        char health_str[32] = "-";
        if (j->healthcheck.enabled && j->state == JAIL_STATE_RUNNING) {
            lochs_health_state_t hstate;
            if (lochs_health_status_read(j->name, &hstate, NULL, NULL,
                                          NULL, 0, NULL, NULL, NULL) == 0) {
                switch (hstate) {
                    case HEALTH_HEALTHY:
                        snprintf(health_str, sizeof(health_str), "\033[32mhealthy\033[0m");
                        break;
                    case HEALTH_UNHEALTHY:
                        snprintf(health_str, sizeof(health_str), "\033[31munhealthy\033[0m");
                        break;
                    case HEALTH_STARTING:
                        snprintf(health_str, sizeof(health_str), "\033[33mstarting\033[0m");
                        break;
                    default:
                        strcpy(health_str, "-");
                        break;
                }
            }
        } else if (j->healthcheck.enabled) {
            strcpy(health_str, "off");
        }

        printf("%-15s %-6s %-20s %-15s %-12s %-20s %-15s %s\n",
               j->name,
               jid_str,
               j->image,
               state_str,
               health_str,
               ports_str,
               limits_str,
               j->path);
    }

    if (jail_count == 0) {
        printf("No containers. Run 'lochs create <n>' to create one.\n");
    }
    
    /* Save state if anything changed */
    if (state_changed) {
        lochs_state_save();
    }
    
    return 0;
}

/*
 * lochs version
 */
int lochs_cmd_version(int argc, char **argv) {
    (void)argc; (void)argv;
    
    printf("lochs version %s\n", LOCHS_VERSION);
    printf("FreeBSD jails on Linux via BSDulator\n");
    return 0;
}

/*
 * State persistence
 */
int lochs_state_load(void) {
    FILE *f = fopen(STATE_FILE, "rb");
    if (!f) return 0;
    
    size_t r = fread(&jail_count, sizeof(jail_count), 1, f);
    if (r != 1) {
        fclose(f);
        jail_count = 0;
        return -1;
    }
    
    if (jail_count > LOCHS_MAX_JAILS) {
        jail_count = LOCHS_MAX_JAILS;
    }
    
    r = fread(jails, sizeof(lochs_jail_t), (size_t)jail_count, f);
    if (r != (size_t)jail_count) {
        fclose(f);
        jail_count = 0;
        return -1;
    }
    
    fclose(f);
    return 0;
}

int lochs_state_save(void) {
    mkdir("/var/lib/lochs", 0755);
    mkdir("/var/lib/lochs/logs", 0755);
    
    FILE *f = fopen(STATE_FILE, "wb");
    if (!f) {
        perror("Failed to save state");
        return -1;
    }
    
    fwrite(&jail_count, sizeof(jail_count), 1, f);
    fwrite(jails, sizeof(lochs_jail_t), (size_t)jail_count, f);
    fclose(f);
    
    return 0;
}

lochs_jail_t *lochs_jail_find(const char *name) {
    for (int i = 0; i < jail_count; i++) {
        if (strcmp(jails[i].name, name) == 0) {
            return &jails[i];
        }
    }
    return NULL;
}

int lochs_jail_add(lochs_jail_t *jail) {
    if (jail_count >= LOCHS_MAX_JAILS) return -1;
    memcpy(&jails[jail_count++], jail, sizeof(lochs_jail_t));
    lochs_state_save();
    return 0;
}

int lochs_jail_remove(const char *name) {
    for (int i = 0; i < jail_count; i++) {
        if (strcmp(jails[i].name, name) == 0) {
            memmove(&jails[i], &jails[i+1], 
                    (size_t)(jail_count - i - 1) * sizeof(lochs_jail_t));
            jail_count--;
            return 0;
        }
    }
    return -1;
}

/*
 * lochs images
 */
int lochs_cmd_images(int argc, char **argv) {
    (void)argc; (void)argv;
    return lochs_image_list_local();
}

/*
 * lochs pull
 */
int lochs_cmd_pull(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: lochs pull <image>\n");
        fprintf(stderr, "\nExamples:\n");
        fprintf(stderr, "  lochs pull freebsd:15\n");
        fprintf(stderr, "  lochs pull freebsd:15-minimal\n");
        return 1;
    }
    return lochs_image_pull(argv[1]);
}

/*
 * lochs build
 */
int lochs_cmd_build(int argc, char **argv) {
    char *lochfile = "Lochfile";
    char *tag = NULL;
    char *context = ".";
    
    static struct option long_options[] = {
        {"file", required_argument, 0, 'f'},
        {"tag",  required_argument, 0, 't'},
        {"help", no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    optind = 1;
    
    while ((opt = getopt_long(argc, argv, "f:t:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'f': lochfile = optarg; break;
            case 't': tag = optarg; break;
            case 'h':
                printf("Usage: lochs build [options] <context>\n\n");
                printf("Options:\n");
                printf("  -f, --file <file>   Lochfile (default: Lochfile)\n");
                printf("  -t, --tag <tag>     Image tag\n");
                return 0;
            default:
                return 1;
        }
    }
    
    if (optind < argc) {
        context = argv[optind];
    }

    if (tag && !lochs_valid_image_ref(tag)) {
        fprintf(stderr, "Error: invalid tag '%s'\n", tag);
        return 1;
    }

    return lochs_build_from_lochfile(lochfile, context, tag);
}

/*
 * lochs search
 */
int lochs_cmd_search(int argc, char **argv) {
    const char *query = (argc > 1) ? argv[1] : NULL;
    return lochs_image_search(query);
}

/*
 * lochs rmi
 */
int lochs_cmd_rmi(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: lochs rmi <image>\n");
        return 1;
    }
    return lochs_image_remove(argv[1]);
}

/*
 * lochs compose - Multi-container orchestration
 * 
 * Usage:
 *   lochs compose up [-d]     Start all services
 *   lochs compose down        Stop all services
 *   lochs compose ps          List services
 *   lochs compose exec <svc>  Execute command in service
 */
int lochs_cmd_compose(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: lochs compose <command> [options]\n\n");
        printf("Commands:\n");
        printf("  up [-d]              Start all services\n");
        printf("  down                 Stop and remove all services\n");
        printf("  ps                   List services\n");
        printf("  exec <service> <cmd> Execute command in service\n");
        printf("\nOptions:\n");
        printf("  -f, --file <file>    Compose file (default: lochs.yml)\n");
        return 1;
    }
    
    const char *compose_file = "lochs.yml";
    const char *command = argv[1];
    int cmd_arg_start = 2;
    
    /* Check for -f flag */
    if (argc >= 4 && (strcmp(argv[1], "-f") == 0 || strcmp(argv[1], "--file") == 0)) {
        compose_file = argv[2];
        command = argv[3];
        cmd_arg_start = 4;
    }
    
    /* Parse compose file */
    compose_file_t compose;
    if (compose_parse_file(compose_file, &compose) != 0) {
        return 1;
    }
    
    int ret = 0;
    
    if (strcmp(command, "up") == 0) {
        int detach = 0;
        if (cmd_arg_start < argc && strcmp(argv[cmd_arg_start], "-d") == 0) {
            detach = 1;
        }
        ret = compose_up(&compose, detach);
    } else if (strcmp(command, "down") == 0) {
        ret = compose_down(&compose);
    } else if (strcmp(command, "ps") == 0) {
        ret = compose_ps(&compose);
    } else if (strcmp(command, "exec") == 0) {
        if (cmd_arg_start >= argc) {
            fprintf(stderr, "Usage: lochs compose exec <service> <command>\n");
            ret = 1;
        } else {
            const char *service = argv[cmd_arg_start];
            ret = compose_exec(&compose, service, argc - cmd_arg_start - 1, 
                              &argv[cmd_arg_start + 1]);
        }
    } else if (strcmp(command, "logs") == 0) {
        const char *service = (cmd_arg_start < argc) ? argv[cmd_arg_start] : NULL;
        ret = compose_logs(&compose, service);
    } else {
        fprintf(stderr, "Unknown compose command: %s\n", command);
        ret = 1;
    }
    
    compose_free(&compose);
    return ret;
}

/*
 * lochs logs [-f] [-n lines] <container>
 * 
 * View container logs (stdout/stderr captured during execution)
 */
int lochs_cmd_logs(int argc, char **argv) {
    int follow = 0;
    int lines = 50;
    const char *name = NULL;
    
    static struct option long_options[] = {
        {"follow", no_argument,       0, 'f'},
        {"tail",   required_argument, 0, 'n'},
        {"help",   no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    optind = 1;
    
    while ((opt = getopt_long(argc, argv, "fn:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'f': follow = 1; break;
            case 'n': lines = atoi(optarg); break;
            case 'h':
                printf("Usage: lochs logs [options] <container>\n\n");
                printf("Options:\n");
                printf("  -f, --follow      Follow log output\n");
                printf("  -n, --tail <N>    Number of lines to show (default: 50)\n");
                return 0;
            default:
                return 1;
        }
    }
    
    if (optind >= argc) {
        fprintf(stderr, "Error: container name required\n");
        fprintf(stderr, "Usage: lochs logs [options] <container>\n");
        return 1;
    }
    
    name = argv[optind];
    lochs_jail_t *jail = lochs_jail_find(name);
    
    if (!jail) {
        fprintf(stderr, "Error: container '%s' not found\n", name);
        return 1;
    }
    
    /* Log file is stored in /var/lib/lochs/logs/<name>.log */
    char log_path[1024];
    snprintf(log_path, sizeof(log_path), "/var/lib/lochs/logs/%s.log", name);
    
    /* Check if log file exists */
    struct stat st;
    if (stat(log_path, &st) != 0) {
        printf("No logs available for container '%s'\n", name);
        printf("(Logs are captured when running commands with output)\n");
        return 0;
    }
    
    if (follow) {
        /* Use tail -f for following */
        const char *targv[] = { "tail", "-f", log_path, NULL };
        return lochs_run(targv, 0);
    } else {
        /* Show last N lines */
        char nbuf[32];
        snprintf(nbuf, sizeof(nbuf), "%d", lines);
        const char *targv[] = { "tail", "-n", nbuf, log_path, NULL };
        return lochs_run(targv, 0);
    }
}

/* ============================================================================
 * ZFS Snapshot Commands
 * ============================================================================ */

static int require_zfs_backend(lochs_jail_t *jail) {
    if (jail->storage_backend != LOCHS_STORAGE_ZFS) {
        fprintf(stderr, "Error: Container '%s' is not using ZFS storage backend.\n", jail->name);
        fprintf(stderr, "ZFS commands require containers created with ZFS backend.\n");
        fprintf(stderr, "Set LOCHS_STORAGE_BACKEND=zfs or ensure ZFS is available.\n");
        return -1;
    }
    return 0;
}

/*
 * lochs snapshot create <container> [name]
 * lochs snapshot ls <container>
 * lochs snapshot rm <container> <name>
 */
int lochs_cmd_snapshot(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: lochs snapshot <command> <container> [options]\n\n");
        printf("Commands:\n");
        printf("  create <container> [name]  Create a snapshot (auto-names if omitted)\n");
        printf("  ls <container>             List snapshots\n");
        printf("  rm <container> <name>      Delete a snapshot\n");
        return 1;
    }

    const char *subcmd = argv[1];
    const char *container = argv[2];

    if (strcmp(subcmd, "create") == 0) {
        lochs_jail_t *jail = lochs_jail_find(container);
        if (!jail) {
            fprintf(stderr, "Error: container '%s' not found\n", container);
            return 1;
        }
        if (require_zfs_backend(jail) != 0) return 1;

        const char *snap_name = (argc > 3) ? argv[3] : NULL;
        return lochs_zfs_snapshot_create(container, snap_name);

    } else if (strcmp(subcmd, "ls") == 0 || strcmp(subcmd, "list") == 0) {
        lochs_jail_t *jail = lochs_jail_find(container);
        if (!jail) {
            fprintf(stderr, "Error: container '%s' not found\n", container);
            return 1;
        }
        if (require_zfs_backend(jail) != 0) return 1;

        return lochs_zfs_snapshot_list(container);

    } else if (strcmp(subcmd, "rm") == 0 || strcmp(subcmd, "delete") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: lochs snapshot rm <container> <snapshot-name>\n");
            return 1;
        }
        lochs_jail_t *jail = lochs_jail_find(container);
        if (!jail) {
            fprintf(stderr, "Error: container '%s' not found\n", container);
            return 1;
        }
        if (require_zfs_backend(jail) != 0) return 1;

        return lochs_zfs_snapshot_delete(container, argv[3]);

    } else {
        fprintf(stderr, "Unknown snapshot command: %s\n", subcmd);
        fprintf(stderr, "Valid commands: create, ls, rm\n");
        return 1;
    }
}

/*
 * lochs rollback <container> <snapshot>
 */
int lochs_cmd_rollback(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: lochs rollback <container> <snapshot>\n\n");
        printf("Rollback a container to a previous snapshot.\n");
        printf("WARNING: The container must be stopped. All changes newer\n");
        printf("than the snapshot will be destroyed.\n");
        return 1;
    }

    const char *container = argv[1];
    const char *snap_name = argv[2];

    lochs_jail_t *jail = lochs_jail_find(container);
    if (!jail) {
        fprintf(stderr, "Error: container '%s' not found\n", container);
        return 1;
    }
    if (require_zfs_backend(jail) != 0) return 1;

    if (jail->state == JAIL_STATE_RUNNING) {
        fprintf(stderr, "Error: container '%s' is running.\n", container);
        fprintf(stderr, "Stop it first with: lochs stop %s\n", container);
        return 1;
    }

    return lochs_zfs_rollback(container, snap_name);
}

/*
 * lochs diff <container> <snapshot> [snapshot2]
 */
int lochs_cmd_diff(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: lochs diff <container> <snapshot> [snapshot2]\n\n");
        printf("Show file changes since a snapshot, or between two snapshots.\n");
        printf("  M = Modified, + = Added, - = Removed, R = Renamed\n");
        return 1;
    }

    const char *container = argv[1];
    const char *snap1 = argv[2];
    const char *snap2 = (argc > 3) ? argv[3] : NULL;

    lochs_jail_t *jail = lochs_jail_find(container);
    if (!jail) {
        fprintf(stderr, "Error: container '%s' not found\n", container);
        return 1;
    }
    if (require_zfs_backend(jail) != 0) return 1;

    return lochs_zfs_diff(container, snap1, snap2);
}

/*
 * lochs clone <source-container> <snapshot> <new-name>
 */
int lochs_cmd_clone(int argc, char **argv) {
    if (argc < 4) {
        printf("Usage: lochs clone <source> <snapshot> <new-name>\n\n");
        printf("Create a new container by cloning a snapshot.\n");
        printf("The new container inherits the source's configuration.\n");
        return 1;
    }

    const char *src = argv[1];
    const char *snap = argv[2];
    const char *new_name = argv[3];

    lochs_jail_t *src_jail = lochs_jail_find(src);
    if (!src_jail) {
        fprintf(stderr, "Error: source container '%s' not found\n", src);
        return 1;
    }
    if (require_zfs_backend(src_jail) != 0) return 1;

    /* Check new name doesn't conflict */
    if (lochs_jail_find(new_name)) {
        fprintf(stderr, "Error: container '%s' already exists\n", new_name);
        return 1;
    }

    /* Do the ZFS clone */
    if (lochs_zfs_clone(src, snap, new_name) != 0)
        return 1;

    /* Create a new jail entry copying source config */
    lochs_jail_t new_jail;
    memcpy(&new_jail, src_jail, sizeof(lochs_jail_t));

    /* Override name and state */
    snprintf(new_jail.name, sizeof(new_jail.name), "%s", new_name);
    new_jail.state = JAIL_STATE_CREATED;
    new_jail.jid = -1;
    new_jail.pid = 0;
    new_jail.created_at = time(NULL);
    new_jail.started_at = 0;
    new_jail.overlay_mounted = 0;

    /* Update ZFS paths for the new container */
    const char *pool = lochs_zfs_get_pool();
    if (pool) {
        snprintf(new_jail.zfs_dataset, sizeof(new_jail.zfs_dataset),
                 "%s/lochs/containers/%s", pool, new_name);
        snprintf(new_jail.zfs_mountpoint, sizeof(new_jail.zfs_mountpoint),
                 "/var/lib/lochs/zfs/containers/%s", new_name);
        snprintf(new_jail.path, sizeof(new_jail.path),
                 "%s", new_jail.zfs_mountpoint);
        snprintf(new_jail.merged_path, sizeof(new_jail.merged_path),
                 "%s", new_jail.zfs_mountpoint);
    }

    /* Clear port forwarder PIDs */
    for (int i = 0; i < new_jail.port_count; i++) {
        new_jail.ports[i].forwarder_pid = 0;
    }

    lochs_jail_add(&new_jail);
    printf("Container '%s' created from %s@%s\n", new_name, src, snap);

    return 0;
}
