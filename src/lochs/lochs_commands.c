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
    
    /* Check for :ro suffix */
    char *ro = strstr(buf, ":ro");
    if (ro && (ro[3] == '\0' || ro[3] == ':')) {
        vol->readonly = 1;
        *ro = '\0';
    }
    
    /* Parse host:container */
    char *colon = strchr(buf, ':');
    if (!colon) {
        /* No colon - use same path for both */
        safe_strcpy(vol->host_path, buf, sizeof(vol->host_path));
        safe_strcpy(vol->container_path, buf, sizeof(vol->container_path));
    } else {
        *colon = '\0';
        safe_strcpy(vol->host_path, buf, sizeof(vol->host_path));
        safe_strcpy(vol->container_path, colon + 1, sizeof(vol->container_path));
    }
    
    /* Validate paths start with / */
    if (vol->host_path[0] != '/' || vol->container_path[0] != '/') {
        return -1;
    }
    
    return 0;
}

/*
 * Parse environment variable "KEY=value"
 * Returns 0 on success, -1 on error
 */
static int parse_env_var(const char *str, char *key, size_t key_size, char *value, size_t value_size) {
    const char *eq = strchr(str, '=');
    if (!eq) {
        /* Just a key, value is empty */
        safe_strcpy(key, str, key_size);
        value[0] = '\0';
        return 0;
    }
    
    size_t klen = (size_t)(eq - str);
    if (klen >= key_size) klen = key_size - 1;
    memcpy(key, str, klen);
    key[klen] = '\0';
    
    safe_strcpy(value, eq + 1, value_size);
    return 0;
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
    char *network = NULL;
    int vnet = 0;
    lochs_port_map_t ports[LOCHS_MAX_PORTS];
    int port_count = 0;
    lochs_volume_t volumes[LOCHS_MAX_VOLUMES];
    int volume_count = 0;
    char env_keys[LOCHS_MAX_ENV][64];
    char env_values[LOCHS_MAX_ENV][256];
    int env_count = 0;
    
    static struct option long_options[] = {
        {"image",   required_argument, 0, 'i'},
        {"ip",      required_argument, 0, 'I'},
        {"publish", required_argument, 0, 'p'},
        {"path",    required_argument, 0, 'P'},
        {"volume",  required_argument, 0, 'v'},
        {"env",     required_argument, 0, 'e'},
        {"network", required_argument, 0, 'N'},
        {"vnet",    no_argument,       0, 'n'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    optind = 1;
    
    while ((opt = getopt_long(argc, argv, "i:I:p:P:v:e:N:nh", long_options, NULL)) != -1) {
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
                    }
                }
                break;
            case 'N': network = optarg; break;
            case 'P': path = optarg; break;
            case 'n': vnet = 1; break;
            case 'h':
                printf("Usage: lochs create <n> [options]\n\n");
                printf("Options:\n");
                printf("  -i, --image <image>   Base image (default: freebsd:15)\n");
                printf("  -I, --ip <addr>       IPv4 address for jail\n");
                printf("  -p, --publish <port>  Publish port (host:container)\n");
                printf("  -v, --volume <vol>    Mount volume (/host:/container[:ro])\n");
                printf("  -e, --env <var>       Set environment variable (KEY=value)\n");
                printf("  -N, --network <net>   Connect to network\n");
                printf("  -P, --path <path>     Root filesystem path\n");
                printf("  -n, --vnet            Enable virtual networking\n");
                printf("\nExamples:\n");
                printf("  lochs create web -i freebsd:15 -p 8080:80\n");
                printf("  lochs create app -v /data:/app/data -e DEBUG=1\n");
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
            printf("    %s -> %s%s\n", volumes[i].host_path, volumes[i].container_path,
                   volumes[i].readonly ? " (ro)" : "");
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
    
    /* Mount overlay filesystem if using COW storage */
    if (jail->image_path[0] && jail->merged_path[0]) {
        if (lochs_storage_mount_container(jail) != 0) {
            fprintf(stderr, "Error: failed to mount container filesystem\n");
            return 1;
        }
        printf("  Overlay: mounted\n");
    }
    
    /* Set up network if configured */
    if (jail->network[0]) {
        lochs_networks_load();
        if (lochs_network_setup_container(name, jail->network) != 0) {
            fprintf(stderr, "Warning: failed to set up network\n");
        }
    }
    
    /* Mount volumes before starting jail */
    if (jail->volume_count > 0) {
        printf("Mounting volumes...\n");
        for (int i = 0; i < jail->volume_count; i++) {
            lochs_volume_t *v = &jail->volumes[i];
            char mount_point[1024];
            char mount_cmd[2048];
            
            /* Create mount point in container */
            snprintf(mount_point, sizeof(mount_point), "%s%s", jail->path, v->container_path);
            snprintf(mount_cmd, sizeof(mount_cmd), "mkdir -p '%s'", mount_point);
            int r = system(mount_cmd);
            (void)r;
            
            /* Bind mount the host path */
            snprintf(mount_cmd, sizeof(mount_cmd), 
                "mount --bind '%s' '%s'", v->host_path, mount_point);
            if (system(mount_cmd) == 0) {
                printf("  %s -> %s%s\n", v->host_path, v->container_path,
                       v->readonly ? " (ro)" : "");
                
                /* Make read-only if requested */
                if (v->readonly) {
                    snprintf(mount_cmd, sizeof(mount_cmd),
                        "mount -o remount,ro,bind '%s'", mount_point);
                    r = system(mount_cmd);
                    (void)r;
                }
            } else {
                fprintf(stderr, "  Warning: Failed to mount %s\n", v->host_path);
            }
        }
    }
    
    /* Write environment file for container */
    if (jail->env_count > 0) {
        char env_file[1024];
        snprintf(env_file, sizeof(env_file), "%s/.lochs_env", jail->path);
        FILE *ef = fopen(env_file, "w");
        if (ef) {
            for (int i = 0; i < jail->env_count; i++) {
                fprintf(ef, "export %s='%s'\n", jail->env_keys[i], jail->env_values[i]);
            }
            fclose(ef);
            printf("Environment: %d variable(s) set\n", jail->env_count);
        }
    }
    
    /*
     * Build the jail command using binaries FROM THE CONTAINER IMAGE.
     * 
     * If container has network namespace, pass --netns to bsdulator.
     * BSDulator will enter the namespace in the child process AFTER
     * ptrace setup but BEFORE execve, avoiding ptrace conflicts.
     * 
     * Format: ./bsdulator [--netns <ns>] <ld-elf.so.1> <jail> -c name=X path=Y persist
     */
    char cmd[4096];
    int pos = 0;
    
    /* Start with bsdulator and optional netns */
    if (jail->netns[0]) {
        pos = snprintf(cmd, sizeof(cmd),
            "./bsdulator --netns %s %s/libexec/ld-elf.so.1 %s/usr/sbin/jail -c name=%s path=%s",
            jail->netns,
            jail->path,
            jail->path,
            jail->name,
            jail->path);
    } else {
        pos = snprintf(cmd, sizeof(cmd),
            "./bsdulator %s/libexec/ld-elf.so.1 %s/usr/sbin/jail -c name=%s path=%s",
            jail->path,
            jail->path,
            jail->name,
            jail->path);
    }
    
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
    
    /* Unmount volumes */
    if (jail->volume_count > 0) {
        printf("Unmounting volumes...\n");
        for (int i = jail->volume_count - 1; i >= 0; i--) {
            lochs_volume_t *v = &jail->volumes[i];
            char mount_point[1024];
            char umount_cmd[2048];
            
            snprintf(mount_point, sizeof(mount_point), "%s%s", jail->path, v->container_path);
            snprintf(umount_cmd, sizeof(umount_cmd), "umount '%s' 2>/dev/null", mount_point);
            int r = system(umount_cmd);
            (void)r;
        }
    }
    
    /* Tear down network */
    if (jail->network[0]) {
        lochs_network_teardown_container(name);
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
    
    /* Unmount overlay filesystem */
    if (jail->overlay_mounted) {
        lochs_storage_unmount_container(jail);
        printf("  Overlay: unmounted\n");
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
    
    /* Destroy container storage (overlay directories) */
    lochs_storage_destroy_container(jail);
    
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
     * If container has network namespace, pass --netns to bsdulator.
     * Format: ./bsdulator [--netns <ns>] <ld-elf.so.1> <jexec> <jail-name> <command...>
     */
    char cmd[4096];
    int pos;
    
    if (jail->netns[0]) {
        pos = snprintf(cmd, sizeof(cmd),
            "./bsdulator --netns %s %s/libexec/ld-elf.so.1 %s/usr/sbin/jexec %s",
            jail->netns,
            jail->path,
            jail->path,
            jail->name);
    } else {
        pos = snprintf(cmd, sizeof(cmd),
            "./bsdulator %s/libexec/ld-elf.so.1 %s/usr/sbin/jexec %s",
            jail->path,
            jail->path,
            jail->name);
    }
    
    /* Add the command and arguments */
    for (int i = 2; i < argc && pos < (int)sizeof(cmd) - 1; i++) {
        pos += snprintf(cmd + pos, sizeof(cmd) - (size_t)pos, " %s", argv[i]);
    }
    
    /* Capture output to log file as well as displaying it */
    char log_cmd[4200];
    snprintf(log_cmd, sizeof(log_cmd), 
        "mkdir -p /var/lib/lochs/logs && %s 2>&1 | tee -a /var/lib/lochs/logs/%s.log",
        cmd, name);
    
    return system(log_cmd);
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
        char cmd[1200];
        snprintf(cmd, sizeof(cmd), "tail -f '%s'", log_path);
        return system(cmd);
    } else {
        /* Show last N lines */
        char cmd[1200];
        snprintf(cmd, sizeof(cmd), "tail -n %d '%s'", lines, log_path);
        return system(cmd);
    }
}
