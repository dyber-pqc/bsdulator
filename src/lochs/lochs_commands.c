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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <sys/stat.h>
#include <stdint.h>
#include <signal.h>
#include <netinet/in.h>  /* For struct in_addr, in6_addr */
#include "bsdulator/lochs.h"
#include "lochs_compose.h"

/* Global jail list */
static lochs_jail_t jails[LOCHS_MAX_JAILS];
static int jail_count = 0;

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
 * lochs create <n> [options]
 */
int lochs_cmd_create(int argc, char **argv) {
    char *name = NULL;
    char *image = "freebsd:15";
    char *ip = NULL;
    char *path = NULL;
    int vnet = 0;
    lochs_port_map_t ports[LOCHS_MAX_PORTS];
    int port_count = 0;
    
    static struct option long_options[] = {
        {"image",   required_argument, 0, 'i'},
        {"ip",      required_argument, 0, 'I'},
        {"publish", required_argument, 0, 'p'},
        {"path",    required_argument, 0, 'P'},
        {"vnet",    no_argument,       0, 'n'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    optind = 1;
    
    while ((opt = getopt_long(argc, argv, "i:I:p:P:nh", long_options, NULL)) != -1) {
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
            case 'P': path = optarg; break;
            case 'n': vnet = 1; break;
            case 'h':
                printf("Usage: lochs create <n> [options]\n\n");
                printf("Options:\n");
                printf("  -i, --image <image>   Base image (default: freebsd:15)\n");
                printf("  -I, --ip <addr>       IPv4 address for jail\n");
                printf("  -p, --publish <port>  Publish port (host:container or host:container/proto)\n");
                printf("  -P, --path <path>     Root filesystem path\n");
                printf("  -n, --vnet            Enable virtual networking\n");
                printf("\nExamples:\n");
                printf("  lochs create web -i freebsd:15 -p 8080:80\n");
                printf("  lochs create db -p 5432:5432/tcp -p 5433:5433/tcp\n");
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
    safe_strcpy(jail.path, root_path, sizeof(jail.path));
    safe_strcpy(jail.image, image, sizeof(jail.image));
    if (ip) safe_strcpy(jail.ip4_addr, ip, sizeof(jail.ip4_addr));
    jail.vnet = vnet;
    jail.state = JAIL_STATE_CREATED;
    jail.created_at = time(NULL);
    jail.jid = -1;
    
    /* Copy port mappings */
    jail.port_count = port_count;
    for (int i = 0; i < port_count; i++) {
        jail.ports[i] = ports[i];
    }
    
    if (lochs_jail_add(&jail) != 0) {
        fprintf(stderr, "Error: failed to register container\n");
        return 1;
    }
    
    printf("Created container '%s'\n", name);
    printf("  Image: %s\n", image);
    printf("  Path:  %s\n", root_path);
    if (ip) printf("  IP:    %s\n", ip);
    if (port_count > 0) {
        printf("  Ports: ");
        for (int i = 0; i < port_count; i++) {
            printf("%d->%d/%s%s", ports[i].host_port, ports[i].container_port,
                   ports[i].protocol, (i < port_count - 1) ? ", " : "");
        }
        printf("\n");
    }
    printf("\nRun 'lochs start %s' to start the container.\n", name);
    
    return 0;
}

/*
 * Start port forwarding using socat
 * Returns PID of forwarder process, or -1 on error
 */
static pid_t start_port_forward(int host_port, int container_port, const char *protocol) {
    char cmd[512];
    
    /* Use socat for port forwarding */
    /* TCP: socat TCP-LISTEN:host,fork,reuseaddr TCP:127.0.0.1:container */
    /* UDP: socat UDP-LISTEN:host,fork,reuseaddr UDP:127.0.0.1:container */
    
    if (strcmp(protocol, "udp") == 0) {
        snprintf(cmd, sizeof(cmd),
            "socat UDP-LISTEN:%d,fork,reuseaddr UDP:127.0.0.1:%d &"
            " echo $!",
            host_port, container_port);
    } else {
        snprintf(cmd, sizeof(cmd),
            "socat TCP-LISTEN:%d,fork,reuseaddr TCP:127.0.0.1:%d &"
            " echo $!",
            host_port, container_port);
    }
    
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    
    pid_t pid = 0;
    if (fscanf(fp, "%d", &pid) != 1) {
        pid = -1;
    }
    pclose(fp);
    
    return pid;
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
     * Build the jail command using binaries FROM THE CONTAINER IMAGE.
     * 
     * Format: ./bsdulator <ld-elf.so.1> <jail> -c name=X path=Y persist
     */
    char cmd[4096];
    int pos = snprintf(cmd, sizeof(cmd),
        "./bsdulator %s/libexec/ld-elf.so.1 %s/usr/sbin/jail -c name=%s path=%s",
        jail->path,   /* ld-elf.so.1 from container */
        jail->path,   /* jail binary from container */
        jail->name,
        jail->path);
    
    if (jail->ip4_addr[0]) {
        pos += snprintf(cmd + pos, sizeof(cmd) - (size_t)pos, 
            " ip4.addr=%s", jail->ip4_addr);
    }
    
    if (jail->vnet) {
        pos += snprintf(cmd + pos, sizeof(cmd) - (size_t)pos, " vnet");
    }
    
    snprintf(cmd + pos, sizeof(cmd) - (size_t)pos, " persist");
    
    int ret = system(cmd);
    
    /* system() returns wait status; check if command exited normally */
    if (ret == -1) {
        fprintf(stderr, "Failed to start container '%s': system() error\n", name);
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
            p->forwarder_pid = start_port_forward(p->host_port, p->container_port, p->protocol);
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
    
    /* Use jail -r from the container image */
    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
        "./bsdulator %s/libexec/ld-elf.so.1 %s/usr/sbin/jail -r %s",
        jail->path,
        jail->path,
        jail->name);
    
    int ret = system(cmd);
    
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
     * Build jexec command using binaries FROM THE CONTAINER IMAGE.
     * 
     * Format: ./bsdulator <ld-elf.so.1> <jexec> <jail-name> <command...>
     */
    char cmd[4096];
    int pos = snprintf(cmd, sizeof(cmd),
        "./bsdulator %s/libexec/ld-elf.so.1 %s/usr/sbin/jexec %s",
        jail->path,   /* ld-elf.so.1 from container */
        jail->path,   /* jexec binary from container */
        jail->name);  /* jail name to attach to */
    
    /* Add the command and arguments */
    for (int i = 2; i < argc && pos < (int)sizeof(cmd) - 1; i++) {
        pos += snprintf(cmd + pos, sizeof(cmd) - (size_t)pos, " %s", argv[i]);
    }
    
    return system(cmd);
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
    
    printf("%-15s %-6s %-20s %-15s %-20s %s\n", 
           "NAME", "JID", "IMAGE", "STATUS", "PORTS", "PATH");
    printf("%-15s %-6s %-20s %-15s %-20s %s\n",
           "----", "---", "-----", "------", "-----", "----");
    
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
            int pos = 0;
            for (int p = 0; p < j->port_count && pos < (int)sizeof(ports_str) - 10; p++) {
                if (p > 0) pos += snprintf(ports_str + pos, sizeof(ports_str) - (size_t)pos, ",");
                pos += snprintf(ports_str + pos, sizeof(ports_str) - (size_t)pos, 
                               "%d->%d", j->ports[p].host_port, j->ports[p].container_port);
            }
        }
        
        printf("%-15s %-6s %-20s %-15s %-20s %s\n",
               j->name,
               jid_str,
               j->image,
               state_str,
               ports_str,
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
