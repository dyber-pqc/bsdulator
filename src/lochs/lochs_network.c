/*
 * Lochs Network Management
 * 
 * Implements Docker-like container networking using Linux bridges and veth pairs.
 * Containers on the same network can communicate by name via /etc/hosts injection.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <getopt.h>
#include "bsdulator/lochs.h"

/* Global network list */
static lochs_network_t networks[LOCHS_MAX_NETWORKS];
static int network_count = 0;

#define NETWORK_STATE_FILE "/var/lib/lochs/networks.dat"

/* Helper to safely copy strings */
static void safe_strcpy(char *dst, const char *src, size_t dst_size) {
    if (dst_size == 0) return;
    size_t src_len = strlen(src);
    size_t copy_len = (src_len < dst_size - 1) ? src_len : dst_size - 1;
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
}

/*
 * Load network state from disk
 */
int lochs_networks_load(void) {
    FILE *f = fopen(NETWORK_STATE_FILE, "rb");
    if (!f) return 0;
    
    size_t r = fread(&network_count, sizeof(network_count), 1, f);
    if (r != 1) {
        fclose(f);
        network_count = 0;
        return -1;
    }
    
    if (network_count > LOCHS_MAX_NETWORKS) {
        network_count = LOCHS_MAX_NETWORKS;
    }
    
    r = fread(networks, sizeof(lochs_network_t), (size_t)network_count, f);
    if (r != (size_t)network_count) {
        fclose(f);
        network_count = 0;
        return -1;
    }
    
    fclose(f);
    return 0;
}

/*
 * Save network state to disk
 */
int lochs_networks_save(void) {
    mkdir("/var/lib/lochs", 0755);
    
    FILE *f = fopen(NETWORK_STATE_FILE, "wb");
    if (!f) {
        perror("Failed to save network state");
        return -1;
    }
    
    fwrite(&network_count, sizeof(network_count), 1, f);
    fwrite(networks, sizeof(lochs_network_t), (size_t)network_count, f);
    fclose(f);
    
    return 0;
}

/*
 * Find a network by name
 */
lochs_network_t *lochs_network_find(const char *name) {
    for (int i = 0; i < network_count; i++) {
        if (networks[i].active && strcmp(networks[i].name, name) == 0) {
            return &networks[i];
        }
    }
    return NULL;
}

/*
 * Generate bridge name from network name
 * e.g., "mynet" -> "lochs_mynet"
 */
static void generate_bridge_name(const char *network_name, char *bridge, size_t size) {
    snprintf(bridge, size, "lochs_%s", network_name);
    /* Truncate to fit Linux interface name limit (15 chars) */
    if (strlen(bridge) > 15) {
        bridge[15] = '\0';
    }
}

/*
 * Parse subnet string to extract base IP and prefix
 * e.g., "172.20.0.0/16" -> base="172.20.0", prefix=16
 */
static int parse_subnet(const char *subnet, char *base, size_t base_size, int *prefix) {
    char buf[64];
    safe_strcpy(buf, subnet, sizeof(buf));
    
    char *slash = strchr(buf, '/');
    if (!slash) {
        *prefix = 24;  /* Default */
    } else {
        *slash = '\0';
        *prefix = atoi(slash + 1);
    }
    
    /* Extract base (first 3 octets) */
    char *last_dot = strrchr(buf, '.');
    if (last_dot) {
        *last_dot = '\0';
    }
    safe_strcpy(base, buf, base_size);
    
    return 0;
}

/*
 * Create a new network
 */
int lochs_network_create(const char *name, const char *subnet) {
    if (lochs_network_find(name)) {
        fprintf(stderr, "Error: network '%s' already exists\n", name);
        return -1;
    }
    
    if (network_count >= LOCHS_MAX_NETWORKS) {
        fprintf(stderr, "Error: maximum number of networks reached\n");
        return -1;
    }
    
    /* Use default subnet if not specified */
    const char *use_subnet = subnet;
    char default_subnet[32];
    if (!use_subnet || !use_subnet[0]) {
        /* Generate subnet based on network count: 172.20.0.0/24, 172.21.0.0/24, etc. */
        snprintf(default_subnet, sizeof(default_subnet), "172.%d.0.0/24", 20 + network_count);
        use_subnet = default_subnet;
    }
    
    /* Create network entry */
    lochs_network_t *net = &networks[network_count];
    memset(net, 0, sizeof(*net));
    
    safe_strcpy(net->name, name, sizeof(net->name));
    safe_strcpy(net->subnet, use_subnet, sizeof(net->subnet));
    generate_bridge_name(name, net->bridge, sizeof(net->bridge));
    
    /* Parse subnet to get gateway */
    char base[32];
    int prefix;
    parse_subnet(use_subnet, base, sizeof(base), &prefix);
    snprintf(net->gateway, sizeof(net->gateway), "%s.1", base);
    
    net->next_ip = 2;  /* Start assigning from .2 */
    net->active = 1;
    
    /* Create Linux bridge */
    char cmd[256];
    
    /* Create bridge interface */
    snprintf(cmd, sizeof(cmd), "ip link add %s type bridge 2>/dev/null", net->bridge);
    int r = system(cmd);
    (void)r;
    
    /* Assign gateway IP to bridge */
    snprintf(cmd, sizeof(cmd), "ip addr add %s/%d dev %s 2>/dev/null", 
             net->gateway, prefix, net->bridge);
    r = system(cmd);
    
    /* Bring bridge up */
    snprintf(cmd, sizeof(cmd), "ip link set %s up", net->bridge);
    r = system(cmd);
    
    /* Enable IP forwarding */
    r = system("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1");
    
    /* Add iptables NAT rule for this subnet */
    snprintf(cmd, sizeof(cmd), 
        "iptables -t nat -A POSTROUTING -s %s -j MASQUERADE 2>/dev/null",
        use_subnet);
    r = system(cmd);
    
    network_count++;
    lochs_networks_save();
    
    printf("Created network '%s'\n", name);
    printf("  Subnet:  %s\n", net->subnet);
    printf("  Gateway: %s\n", net->gateway);
    printf("  Bridge:  %s\n", net->bridge);
    
    return 0;
}

/*
 * Remove a network
 */
int lochs_network_remove(const char *name) {
    lochs_network_t *net = lochs_network_find(name);
    if (!net) {
        fprintf(stderr, "Error: network '%s' not found\n", name);
        return -1;
    }
    
    /* TODO: Check if any containers are using this network */
    
    /* Remove iptables NAT rule */
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -D POSTROUTING -s %s -j MASQUERADE 2>/dev/null",
        net->subnet);
    int r = system(cmd);
    (void)r;
    
    /* Bring bridge down and delete */
    snprintf(cmd, sizeof(cmd), "ip link set %s down 2>/dev/null", net->bridge);
    r = system(cmd);
    
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", net->bridge);
    r = system(cmd);
    
    /* Mark as inactive */
    net->active = 0;
    
    /* Compact the array */
    for (int i = 0; i < network_count; i++) {
        if (!networks[i].active) {
            memmove(&networks[i], &networks[i+1],
                    (size_t)(network_count - i - 1) * sizeof(lochs_network_t));
            network_count--;
            i--;
        }
    }
    
    lochs_networks_save();
    printf("Removed network '%s'\n", name);
    
    return 0;
}

/*
 * List all networks
 */
int lochs_network_list(void) {
    printf("%-20s %-20s %-16s %-16s\n", "NAME", "SUBNET", "GATEWAY", "BRIDGE");
    printf("%-20s %-20s %-16s %-16s\n", "----", "------", "-------", "------");
    
    for (int i = 0; i < network_count; i++) {
        if (networks[i].active) {
            printf("%-20s %-20s %-16s %-16s\n",
                   networks[i].name,
                   networks[i].subnet,
                   networks[i].gateway,
                   networks[i].bridge);
        }
    }
    
    if (network_count == 0) {
        printf("No networks. Run 'lochs network create <name>' to create one.\n");
    }
    
    return 0;
}

/*
 * Assign an IP address from a network
 * Returns allocated string with IP address, caller must free
 */
char *lochs_network_assign_ip(const char *network_name) {
    lochs_network_t *net = lochs_network_find(network_name);
    if (!net) {
        return NULL;
    }
    
    /* Parse subnet base */
    char base[32];
    int prefix;
    parse_subnet(net->subnet, base, sizeof(base), &prefix);
    
    /* Assign next IP */
    char *ip = malloc(20);
    if (!ip) return NULL;
    
    snprintf(ip, 20, "%.12s.%d", base, net->next_ip);
    net->next_ip++;
    
    /* Save updated state */
    lochs_networks_save();
    
    return ip;
}

/*
 * Set up networking for a container
 * Creates network namespace, veth pair, connects to bridge, assigns IP
 * 
 * Full network namespace isolation:
 * 1. Create netns named after container
 * 2. Create veth pair
 * 3. Move container end into netns
 * 4. Configure IP inside netns
 * 5. BSDulator enters netns via --netns option before execve
 */
int lochs_network_setup_container(const char *container_name, const char *network_name) {
    lochs_network_t *net = lochs_network_find(network_name);
    if (!net) {
        fprintf(stderr, "Error: network '%s' not found\n", network_name);
        return -1;
    }
    
    lochs_jail_t *jail = lochs_jail_find(container_name);
    if (!jail) {
        fprintf(stderr, "Error: container '%s' not found\n", container_name);
        return -1;
    }
    
    /* Assign IP if not already assigned */
    char *assigned_ip = NULL;
    if (!jail->ip4_addr[0]) {
        assigned_ip = lochs_network_assign_ip(network_name);
        if (assigned_ip) {
            safe_strcpy(jail->ip4_addr, assigned_ip, sizeof(jail->ip4_addr));
        }
    }
    
    /* Store network name */
    safe_strcpy(jail->network, network_name, sizeof(jail->network));
    
    /* Generate network namespace name */
    char netns_name[32];
    snprintf(netns_name, sizeof(netns_name), "lochs_%.20s", container_name);
    
    /* Store netns name in jail for later use */
    safe_strcpy(jail->netns, netns_name, sizeof(jail->netns));
    
    /* Create veth pair names */
    char veth_host[20], veth_container[20];
    snprintf(veth_host, sizeof(veth_host), "veth_%.8s", container_name);
    snprintf(veth_container, sizeof(veth_container), "veth_%.6sp", container_name);  /* Peer name */
    veth_host[15] = '\0';  /* Truncate to Linux interface name limit */
    veth_container[15] = '\0';
    
    char cmd[512];
    int r;
    
    /* Step 1: Create network namespace */
    snprintf(cmd, sizeof(cmd), "ip netns add %s 2>/dev/null", netns_name);
    r = system(cmd);
    (void)r;
    
    /* Step 2: Delete any existing veth pair first */
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", veth_host);
    r = system(cmd);
    (void)r;
    
    /* Step 3: Create veth pair */
    snprintf(cmd, sizeof(cmd), 
        "ip link add %s type veth peer name %s",
        veth_host, veth_container);
    r = system(cmd);
    if (r != 0) {
        fprintf(stderr, "Warning: Failed to create veth pair %s <-> %s\n", veth_host, veth_container);
    }
    
    /* Step 4: Move container end to network namespace FIRST (before attaching to bridge) */
    snprintf(cmd, sizeof(cmd), 
        "ip link set %s netns %s",
        veth_container, netns_name);
    r = system(cmd);
    if (r != 0) {
        fprintf(stderr, "Warning: Failed to move %s to netns %s\n", veth_container, netns_name);
    }
    
    /* Step 5: Rename to eth0 inside the namespace */
    snprintf(cmd, sizeof(cmd), 
        "ip netns exec %s ip link set %s name eth0",
        netns_name, veth_container);
    r = system(cmd);
    
    /* Step 5b: Set unique MAC address based on assigned IP */
    /* Use locally administered MAC: 02:00:00:XX:XX:XX where XX comes from IP */
    unsigned int ip_last_octet = 0;
    const char *last_dot = strrchr(jail->ip4_addr, '.');
    if (last_dot) {
        ip_last_octet = (unsigned int)atoi(last_dot + 1);
    }
    snprintf(cmd, sizeof(cmd),
        "ip netns exec %s ip link set eth0 address 02:00:00:00:00:%02x",
        netns_name, ip_last_octet & 0xFF);
    r = system(cmd);
    
    /* Step 6: Attach host end to bridge */
    snprintf(cmd, sizeof(cmd), 
        "ip link set %s master %s",
        veth_host, net->bridge);
    r = system(cmd);
    
    /* Step 7: Bring host end up */
    snprintf(cmd, sizeof(cmd), "ip link set %s up", veth_host);
    r = system(cmd);
    
    /* Step 8: Configure interface inside namespace */
    char base[32];
    int prefix;
    parse_subnet(net->subnet, base, sizeof(base), &prefix);
    
    /* Bring up loopback */
    snprintf(cmd, sizeof(cmd), 
        "ip netns exec %s ip link set lo up",
        netns_name);
    r = system(cmd);
    
    /* Assign IP to eth0 (interface was renamed to eth0 in step 5) */
    snprintf(cmd, sizeof(cmd), 
        "ip netns exec %s ip addr add %s/%d dev eth0",
        netns_name, jail->ip4_addr, prefix);
    r = system(cmd);
    
    /* Bring eth0 up */
    snprintf(cmd, sizeof(cmd), 
        "ip netns exec %s ip link set eth0 up",
        netns_name);
    r = system(cmd);
    
    /* Add default route via gateway */
    snprintf(cmd, sizeof(cmd), 
        "ip netns exec %s ip route add default via %s",
        netns_name, net->gateway);
    r = system(cmd);
    
    /*
     * Update /etc/hosts for container networking.
     * 
     * Since multiple containers may share the same image path (no COW yet),
     * we create a per-container hosts file in /var/lib/lochs/hosts/ and
     * then copy it into the container's /etc/hosts.
     * 
     * This writes a CLEAN hosts file, not appending.
     */
    
    /* Create hosts directory */
    mkdir("/var/lib/lochs/hosts", 0755);
    
    /* Write container-specific hosts file */
    char hosts_src[256];
    snprintf(hosts_src, sizeof(hosts_src), "/var/lib/lochs/hosts/%s", container_name);
    
    FILE *hosts = fopen(hosts_src, "w");  /* Truncate/create fresh */
    if (hosts) {
        /* Standard FreeBSD /etc/hosts header */
        fprintf(hosts, "#\n");
        fprintf(hosts, "# Host Database\n");
        fprintf(hosts, "#\n");
        fprintf(hosts, "::1\t\t\tlocalhost localhost.lochs.local\n");
        fprintf(hosts, "127.0.0.1\t\tlocalhost localhost.lochs.local\n");
        fprintf(hosts, "\n# Lochs network: %s\n", network_name);
        fprintf(hosts, "%s\t%s\n", jail->ip4_addr, container_name);
        
        /* Add entries for other containers on this network */
        extern lochs_jail_t lochs_jails[];
        extern int lochs_jail_count;
        for (int i = 0; i < lochs_jail_count; i++) {
            if (strcmp(lochs_jails[i].network, network_name) == 0 &&
                strcmp(lochs_jails[i].name, container_name) != 0 &&
                lochs_jails[i].ip4_addr[0]) {
                fprintf(hosts, "%s\t%s\n", lochs_jails[i].ip4_addr, lochs_jails[i].name);
            }
        }
        
        fclose(hosts);
        
        /* Copy to container's /etc/hosts */
        char hosts_dst[2048];
        snprintf(hosts_dst, sizeof(hosts_dst), "%s/etc/hosts", jail->path);
        
        char cp_cmd[2400];
        snprintf(cp_cmd, sizeof(cp_cmd), "cp '%s' '%s'", hosts_src, hosts_dst);
        r = system(cp_cmd);
        (void)r;
    }
    
    /*
     * Update hosts files for OTHER containers on this network.
     * Each container gets its own hosts file regenerated with all peers.
     */
    extern lochs_jail_t lochs_jails[];
    extern int lochs_jail_count;
    for (int i = 0; i < lochs_jail_count; i++) {
        if (strcmp(lochs_jails[i].network, network_name) == 0 &&
            strcmp(lochs_jails[i].name, container_name) != 0 &&
            lochs_jails[i].ip4_addr[0]) {
            
            /* Regenerate hosts file for this peer */
            char peer_hosts_src[256];
            snprintf(peer_hosts_src, sizeof(peer_hosts_src), 
                     "/var/lib/lochs/hosts/%s", lochs_jails[i].name);
            
            FILE *peer_hosts = fopen(peer_hosts_src, "w");
            if (peer_hosts) {
                fprintf(peer_hosts, "#\n");
                fprintf(peer_hosts, "# Host Database\n");
                fprintf(peer_hosts, "#\n");
                fprintf(peer_hosts, "::1\t\t\tlocalhost localhost.lochs.local\n");
                fprintf(peer_hosts, "127.0.0.1\t\tlocalhost localhost.lochs.local\n");
                fprintf(peer_hosts, "\n# Lochs network: %s\n", network_name);
                
                /* Add this peer's own entry */
                fprintf(peer_hosts, "%s\t%s\n", 
                        lochs_jails[i].ip4_addr, lochs_jails[i].name);
                
                /* Add all other containers on this network */
                for (int j = 0; j < lochs_jail_count; j++) {
                    if (strcmp(lochs_jails[j].network, network_name) == 0 &&
                        strcmp(lochs_jails[j].name, lochs_jails[i].name) != 0 &&
                        lochs_jails[j].ip4_addr[0]) {
                        fprintf(peer_hosts, "%s\t%s\n", 
                                lochs_jails[j].ip4_addr, lochs_jails[j].name);
                    }
                }
                
                fclose(peer_hosts);
                
                /* Copy to peer container's /etc/hosts */
                char peer_hosts_dst[2048];
                snprintf(peer_hosts_dst, sizeof(peer_hosts_dst), 
                         "%s/etc/hosts", lochs_jails[i].path);
                
                char cp_cmd[2400];
                snprintf(cp_cmd, sizeof(cp_cmd), "cp '%s' '%s'", 
                         peer_hosts_src, peer_hosts_dst);
                r = system(cp_cmd);
            }
        }
    }
    
    if (assigned_ip) {
        printf("  Network: %s (%s) [netns: %s]\n", network_name, assigned_ip, netns_name);
        free(assigned_ip);
    }
    
    /* Save state with netns info */
    lochs_state_save();
    
    return 0;
}

/*
 * Tear down networking for a container
 * Removes network namespace and veth pair
 */
int lochs_network_teardown_container(const char *container_name) {
    char cmd[256];
    int r;
    
    /* Delete veth pair (deleting host end removes both) */
    char veth_host[20];
    snprintf(veth_host, sizeof(veth_host), "veth_%.8s", container_name);
    veth_host[15] = '\0';
    
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", veth_host);
    r = system(cmd);
    (void)r;
    
    /* Delete network namespace */
    char netns_name[32];
    snprintf(netns_name, sizeof(netns_name), "lochs_%.20s", container_name);
    
    snprintf(cmd, sizeof(cmd), "ip netns del %s 2>/dev/null", netns_name);
    r = system(cmd);
    
    return 0;
}

/*
 * lochs network command handler
 * 
 * Usage:
 *   lochs network create <name> [--subnet <cidr>]
 *   lochs network rm <name>
 *   lochs network ls
 *   lochs network inspect <name>
 */
int lochs_cmd_network(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: lochs network <command> [options]\n\n");
        printf("Commands:\n");
        printf("  create <name>    Create a network\n");
        printf("  rm <name>        Remove a network\n");
        printf("  ls               List networks\n");
        printf("  inspect <name>   Show network details\n");
        printf("\nOptions:\n");
        printf("  --subnet <cidr>  Subnet in CIDR notation (e.g., 172.20.0.0/24)\n");
        printf("\nExamples:\n");
        printf("  lochs network create mynet\n");
        printf("  lochs network create backend --subnet 10.0.0.0/24\n");
        printf("  lochs network ls\n");
        return 1;
    }
    
    /* Load network state */
    lochs_networks_load();
    
    const char *command = argv[1];
    
    if (strcmp(command, "create") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: network name required\n");
            return 1;
        }
        
        const char *name = argv[2];
        const char *subnet = NULL;
        
        /* Parse --subnet option */
        for (int i = 3; i < argc - 1; i++) {
            if (strcmp(argv[i], "--subnet") == 0) {
                subnet = argv[i + 1];
                break;
            }
        }
        
        return lochs_network_create(name, subnet);
        
    } else if (strcmp(command, "rm") == 0 || strcmp(command, "remove") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: network name required\n");
            return 1;
        }
        return lochs_network_remove(argv[2]);
        
    } else if (strcmp(command, "ls") == 0 || strcmp(command, "list") == 0) {
        return lochs_network_list();
        
    } else if (strcmp(command, "inspect") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: network name required\n");
            return 1;
        }
        
        lochs_network_t *net = lochs_network_find(argv[2]);
        if (!net) {
            fprintf(stderr, "Error: network '%s' not found\n", argv[2]);
            return 1;
        }
        
        printf("Name:    %s\n", net->name);
        printf("Subnet:  %s\n", net->subnet);
        printf("Gateway: %s\n", net->gateway);
        printf("Bridge:  %s\n", net->bridge);
        printf("Next IP: .%d\n", net->next_ip);
        return 0;
        
    } else {
        fprintf(stderr, "Unknown network command: %s\n", command);
        return 1;
    }
}
