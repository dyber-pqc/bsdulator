/*
 * BSDulator - Netlink Socket Emulation
 * 
 * FreeBSD doesn't have netlink - it uses different mechanisms:
 * - routing sockets (AF_ROUTE) for routing table manipulation
 * - sysctl for reading network interface information
 * - ioctl for interface configuration
 * 
 * When FreeBSD programs (like ifconfig) try to get network info, they use
 * sysctl or ioctl. However, some programs may try to use routing sockets
 * which we need to translate to Linux netlink.
 * 
 * This module provides:
 * 1. Detection of netlink socket creation attempts
 * 2. Translation of FreeBSD routing socket operations to Linux netlink
 * 3. Emulation of interface listing via /proc/net and /sys/class/net
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

#include "bsdulator.h"

/*
 * FreeBSD socket domains that need translation
 */
#define FBSD_AF_ROUTE    17   /* FreeBSD routing socket */
#define FBSD_AF_NETLINK  38   /* If FreeBSD ever adds netlink (it won't) */

/*
 * FreeBSD routing socket message types
 */
#define FBSD_RTM_ADD        0x1
#define FBSD_RTM_DELETE     0x2
#define FBSD_RTM_CHANGE     0x3
#define FBSD_RTM_GET        0x4
#define FBSD_RTM_LOSING     0x5
#define FBSD_RTM_REDIRECT   0x6
#define FBSD_RTM_MISS       0x7
#define FBSD_RTM_LOCK       0x8
#define FBSD_RTM_RESOLVE    0xb
#define FBSD_RTM_NEWADDR    0xc
#define FBSD_RTM_DELADDR    0xd
#define FBSD_RTM_IFINFO     0xe
#define FBSD_RTM_NEWMADDR   0xf
#define FBSD_RTM_DELMADDR   0x10
#define FBSD_RTM_IFANNOUNCE 0x11
#define FBSD_RTM_IEEE80211  0x12

/*
 * FreeBSD interface flags (from net/if.h)
 */
#define FBSD_IFF_UP          0x1
#define FBSD_IFF_BROADCAST   0x2
#define FBSD_IFF_DEBUG       0x4
#define FBSD_IFF_LOOPBACK    0x8
#define FBSD_IFF_POINTOPOINT 0x10
#define FBSD_IFF_RUNNING     0x40
#define FBSD_IFF_NOARP       0x80
#define FBSD_IFF_PROMISC     0x100
#define FBSD_IFF_ALLMULTI    0x200
#define FBSD_IFF_MULTICAST   0x8000

/*
 * FreeBSD rt_msghdr structure (routing message header)
 */
struct fbsd_rt_msghdr {
    uint16_t rtm_msglen;    /* Length of message including header */
    uint8_t  rtm_version;   /* Routing message version (RTM_VERSION = 5) */
    uint8_t  rtm_type;      /* Message type */
    uint16_t rtm_index;     /* Interface index */
    uint16_t rtm_pad;       /* Padding */
    int      rtm_flags;     /* Flags */
    int      rtm_addrs;     /* Bitmask identifying sockaddrs in message */
    pid_t    rtm_pid;       /* PID of sender */
    int      rtm_seq;       /* Sequence number */
    int      rtm_errno;     /* Error code */
    int      rtm_fmask;     /* Bitmask used in RTM_CHANGE */
    uint32_t rtm_inits;     /* Metric values to initialize */
    /* Followed by rt_metrics and sockaddrs */
};

/*
 * FreeBSD if_msghdr structure (interface message header)
 */
struct fbsd_if_msghdr {
    uint16_t ifm_msglen;    /* Length of message including header */
    uint8_t  ifm_version;   /* Version (RTM_VERSION = 5) */
    uint8_t  ifm_type;      /* Message type (RTM_IFINFO) */
    int      ifm_addrs;     /* Bitmask of present addresses */
    int      ifm_flags;     /* Interface flags */
    uint16_t ifm_index;     /* Interface index */
    uint16_t ifm_pad;       /* Padding */
    /* Followed by if_data structure */
};

/*
 * FreeBSD if_data structure
 */
struct fbsd_if_data {
    uint8_t  ifi_type;       /* Interface type */
    uint8_t  ifi_physical;   /* Physical type */
    uint8_t  ifi_addrlen;    /* Media address length */
    uint8_t  ifi_hdrlen;     /* Media header length */
    uint8_t  ifi_link_state; /* Link state */
    uint8_t  ifi_vhid;       /* CARP vhid */
    uint16_t ifi_datalen;    /* Length of this data struct */
    uint32_t ifi_mtu;        /* MTU */
    uint32_t ifi_metric;     /* Routing metric */
    uint64_t ifi_baudrate;   /* Line speed */
    /* Statistics follow... */
    uint64_t ifi_ipackets;
    uint64_t ifi_ierrors;
    uint64_t ifi_opackets;
    uint64_t ifi_oerrors;
    uint64_t ifi_collisions;
    uint64_t ifi_ibytes;
    uint64_t ifi_obytes;
    uint64_t ifi_imcasts;
    uint64_t ifi_omcasts;
    uint64_t ifi_iqdrops;
    uint64_t ifi_oqdrops;
    uint64_t ifi_noproto;
    uint64_t ifi_hwassist;
    /* Timestamps */
    int64_t  ifi_epoch;
    int64_t  ifi_lastchange_sec;
    int64_t  ifi_lastchange_usec;
};

/*
 * FreeBSD ifa_msghdr structure (interface address message)
 */
struct fbsd_ifa_msghdr {
    uint16_t ifam_msglen;   /* Length of message */
    uint8_t  ifam_version;  /* Version */
    uint8_t  ifam_type;     /* Message type (RTM_NEWADDR/RTM_DELADDR) */
    int      ifam_addrs;    /* Bitmask of addresses */
    int      ifam_flags;    /* Flags */
    uint16_t ifam_index;    /* Interface index */
    uint16_t ifam_pad;      /* Padding */
    int      ifam_metric;   /* Metric */
};

/*
 * Address bitmask values (RTA_*)
 */
#define FBSD_RTA_DST       0x1
#define FBSD_RTA_GATEWAY   0x2
#define FBSD_RTA_NETMASK   0x4
#define FBSD_RTA_GENMASK   0x8
#define FBSD_RTA_IFP       0x10
#define FBSD_RTA_IFA       0x20
#define FBSD_RTA_AUTHOR    0x40
#define FBSD_RTA_BRD       0x80

/*
 * Interface information cache
 * We cache interface info to avoid repeated /sys reads
 */
#define MAX_INTERFACES 64

typedef struct {
    char name[IFNAMSIZ];
    int index;
    int flags;
    int mtu;
    uint8_t hwaddr[6];
    int hwaddr_len;
    struct in_addr ipv4_addr;
    struct in_addr ipv4_netmask;
    struct in_addr ipv4_broadcast;
    int has_ipv4;
} interface_info_t;

static interface_info_t if_cache[MAX_INTERFACES];
static int if_cache_count = 0;
static int if_cache_valid = 0;

/*
 * Read interface information from /sys/class/net and /proc/net
 */
static int refresh_interface_cache(void) {
    DIR *dir;
    struct dirent *entry;
    int count = 0;
    
    dir = opendir("/sys/class/net");
    if (!dir) {
        BSD_ERROR("netlink: failed to open /sys/class/net: %s", strerror(errno));
        return -1;
    }
    
    while ((entry = readdir(dir)) != NULL && count < MAX_INTERFACES) {
        if (entry->d_name[0] == '.') continue;
        
        /* Skip names that are too long for interface name */
        size_t namelen = strlen(entry->d_name);
        if (namelen >= IFNAMSIZ) continue;
        
        interface_info_t *iface = &if_cache[count];
        memset(iface, 0, sizeof(*iface));
        
        memcpy(iface->name, entry->d_name, namelen);
        iface->name[namelen] = '\0';
        iface->index = if_nametoindex(entry->d_name);
        
        /* Read flags */
        char path[512];
        snprintf(path, sizeof(path), "/sys/class/net/%s/flags", iface->name);
        FILE *f = fopen(path, "r");
        if (f) {
            unsigned int flags;
            if (fscanf(f, "%x", &flags) == 1) {
                /* Translate Linux flags to FreeBSD flags */
                iface->flags = 0;
                if (flags & IFF_UP) iface->flags |= FBSD_IFF_UP;
                if (flags & IFF_BROADCAST) iface->flags |= FBSD_IFF_BROADCAST;
                if (flags & IFF_DEBUG) iface->flags |= FBSD_IFF_DEBUG;
                if (flags & IFF_LOOPBACK) iface->flags |= FBSD_IFF_LOOPBACK;
                if (flags & IFF_POINTOPOINT) iface->flags |= FBSD_IFF_POINTOPOINT;
                if (flags & IFF_RUNNING) iface->flags |= FBSD_IFF_RUNNING;
                if (flags & IFF_NOARP) iface->flags |= FBSD_IFF_NOARP;
                if (flags & IFF_PROMISC) iface->flags |= FBSD_IFF_PROMISC;
                if (flags & IFF_ALLMULTI) iface->flags |= FBSD_IFF_ALLMULTI;
                if (flags & IFF_MULTICAST) iface->flags |= FBSD_IFF_MULTICAST;
            }
            fclose(f);
        }
        
        /* Read MTU */
        snprintf(path, sizeof(path), "/sys/class/net/%s/mtu", iface->name);
        f = fopen(path, "r");
        if (f) {
            if (fscanf(f, "%d", &iface->mtu) != 1) {
                iface->mtu = 1500;
            }
            fclose(f);
        } else {
            iface->mtu = 1500;
        }
        
        /* Read MAC address */
        snprintf(path, sizeof(path), "/sys/class/net/%s/address", iface->name);
        f = fopen(path, "r");
        if (f) {
            unsigned int mac[6];
            if (fscanf(f, "%x:%x:%x:%x:%x:%x", 
                       &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
                for (int i = 0; i < 6; i++) {
                    iface->hwaddr[i] = (uint8_t)mac[i];
                }
                iface->hwaddr_len = 6;
            }
            fclose(f);
        }
        
        /* Get IPv4 address using ioctl */
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock >= 0) {
            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            memcpy(ifr.ifr_name, iface->name, namelen);
            ifr.ifr_name[namelen] = '\0';
            
            if (ioctl(sock, SIOCGIFADDR, &ifr) == 0) {
                iface->ipv4_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
                iface->has_ipv4 = 1;
                
                if (ioctl(sock, SIOCGIFNETMASK, &ifr) == 0) {
                    iface->ipv4_netmask = ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr;
                }
                
                if (ioctl(sock, SIOCGIFBRDADDR, &ifr) == 0) {
                    iface->ipv4_broadcast = ((struct sockaddr_in *)&ifr.ifr_broadaddr)->sin_addr;
                }
            }
            close(sock);
        }
        
        BSD_TRACE("netlink: cached interface %s index=%d flags=0x%x mtu=%d ip=%s",
                  iface->name, iface->index, iface->flags, iface->mtu,
                  iface->has_ipv4 ? inet_ntoa(iface->ipv4_addr) : "none");
        
        count++;
    }
    
    closedir(dir);
    if_cache_count = count;
    if_cache_valid = 1;
    
    return count;
}

/*
 * Get interface by index (used by future IFINFO lookups)
 */
__attribute__((unused))
static interface_info_t *get_interface_by_index(int index) {
    if (!if_cache_valid) {
        refresh_interface_cache();
    }
    
    for (int i = 0; i < if_cache_count; i++) {
        if (if_cache[i].index == index) {
            return &if_cache[i];
        }
    }
    return NULL;
}

/*
 * Get interface by name (used by future IFINFO lookups)
 */
__attribute__((unused))
static interface_info_t *get_interface_by_name(const char *name) {
    if (!if_cache_valid) {
        refresh_interface_cache();
    }
    
    for (int i = 0; i < if_cache_count; i++) {
        if (strcmp(if_cache[i].name, name) == 0) {
            return &if_cache[i];
        }
    }
    return NULL;
}

/*
 * Build a FreeBSD RTM_IFINFO message for an interface
 */
static int build_ifinfo_message(interface_info_t *iface, uint8_t *buf, size_t bufsize) {
    if (bufsize < sizeof(struct fbsd_if_msghdr) + sizeof(struct fbsd_if_data) + 32) {
        return -1;
    }
    
    struct fbsd_if_msghdr *ifm = (struct fbsd_if_msghdr *)buf;
    struct fbsd_if_data *ifd = (struct fbsd_if_data *)(buf + sizeof(struct fbsd_if_msghdr));
    
    memset(buf, 0, sizeof(struct fbsd_if_msghdr) + sizeof(struct fbsd_if_data));
    
    /* Fill if_msghdr */
    ifm->ifm_version = 5;  /* RTM_VERSION */
    ifm->ifm_type = FBSD_RTM_IFINFO;
    ifm->ifm_flags = iface->flags;
    ifm->ifm_index = iface->index;
    ifm->ifm_addrs = FBSD_RTA_IFP;  /* Interface link-layer address present */
    
    /* Fill if_data */
    ifd->ifi_type = 6;  /* IFT_ETHER */
    ifd->ifi_addrlen = iface->hwaddr_len;
    ifd->ifi_hdrlen = 14;  /* Ethernet header */
    ifd->ifi_link_state = (iface->flags & FBSD_IFF_UP) ? 2 : 0;  /* LINK_STATE_UP */
    ifd->ifi_datalen = sizeof(struct fbsd_if_data);
    ifd->ifi_mtu = iface->mtu;
    ifd->ifi_metric = 0;
    ifd->ifi_baudrate = 1000000000;  /* 1 Gbps */
    
    /* Add interface name as sockaddr_dl after if_data */
    /* FreeBSD sockaddr_dl: len(1) + family(1) + index(2) + type(1) + nlen(1) + alen(1) + slen(1) + data */
    uint8_t *sdl = buf + sizeof(struct fbsd_if_msghdr) + sizeof(struct fbsd_if_data);
    int nlen = strlen(iface->name);
    int sdl_len = 8 + nlen + iface->hwaddr_len;
    sdl_len = (sdl_len + 3) & ~3;  /* Round up to 4-byte boundary */
    
    sdl[0] = sdl_len;           /* sdl_len */
    sdl[1] = 18;                /* AF_LINK */
    sdl[2] = iface->index & 0xFF;
    sdl[3] = (iface->index >> 8) & 0xFF;
    sdl[4] = 6;                 /* IFT_ETHER */
    sdl[5] = nlen;              /* sdl_nlen */
    sdl[6] = iface->hwaddr_len; /* sdl_alen */
    sdl[7] = 0;                 /* sdl_slen */
    memcpy(sdl + 8, iface->name, nlen);
    memcpy(sdl + 8 + nlen, iface->hwaddr, iface->hwaddr_len);
    
    ifm->ifm_msglen = sizeof(struct fbsd_if_msghdr) + sizeof(struct fbsd_if_data) + sdl_len;
    
    return ifm->ifm_msglen;
}

/*
 * Build a FreeBSD RTM_NEWADDR message for an interface address
 */
static int build_newaddr_message(interface_info_t *iface, uint8_t *buf, size_t bufsize) {
    if (!iface->has_ipv4) {
        return 0;  /* No address to report */
    }
    
    if (bufsize < sizeof(struct fbsd_ifa_msghdr) + 128) {
        return -1;
    }
    
    struct fbsd_ifa_msghdr *ifam = (struct fbsd_ifa_msghdr *)buf;
    memset(buf, 0, sizeof(struct fbsd_ifa_msghdr));
    
    ifam->ifam_version = 5;
    ifam->ifam_type = FBSD_RTM_NEWADDR;
    ifam->ifam_addrs = FBSD_RTA_IFA | FBSD_RTA_NETMASK;
    if (iface->flags & FBSD_IFF_BROADCAST) {
        ifam->ifam_addrs |= FBSD_RTA_BRD;
    }
    ifam->ifam_flags = iface->flags;
    ifam->ifam_index = iface->index;
    ifam->ifam_metric = 0;
    
    /* Add sockaddrs after header */
    uint8_t *ptr = buf + sizeof(struct fbsd_ifa_msghdr);
    
    /* RTA_IFA - interface address */
    struct sockaddr_in *sin = (struct sockaddr_in *)ptr;
    sin->sin_family = AF_INET;
    sin->sin_addr = iface->ipv4_addr;
    /* FreeBSD sockaddr_in is 16 bytes */
    ptr += 16;
    
    /* RTA_NETMASK */
    sin = (struct sockaddr_in *)ptr;
    sin->sin_family = AF_INET;
    sin->sin_addr = iface->ipv4_netmask;
    ptr += 16;
    
    /* RTA_BRD - broadcast address */
    if (iface->flags & FBSD_IFF_BROADCAST) {
        sin = (struct sockaddr_in *)ptr;
        sin->sin_family = AF_INET;
        sin->sin_addr = iface->ipv4_broadcast;
        ptr += 16;
    }
    
    ifam->ifam_msglen = ptr - buf;
    return ifam->ifam_msglen;
}

/*
 * Handle sysctl for network interface information
 * This is how FreeBSD programs typically get interface info
 * 
 * NET_RT_IFLIST: List all interfaces
 * NET_RT_IFLISTL: List all interfaces (long format)
 */
int netlink_handle_sysctl_iflist(pid_t pid, uint64_t buf_addr, size_t *buflen, int af) {
    BSD_TRACE("netlink: handling NET_RT_IFLIST sysctl, af=%d", af);
    
    /* Refresh interface cache */
    refresh_interface_cache();
    
    /* Calculate required buffer size */
    size_t needed = 0;
    for (int i = 0; i < if_cache_count; i++) {
        /* Skip interfaces that don't match address family filter */
        if (af != 0 && af != AF_INET && !if_cache[i].has_ipv4) {
            continue;
        }
        
        /* RTM_IFINFO message */
        needed += sizeof(struct fbsd_if_msghdr) + sizeof(struct fbsd_if_data) + 64;
        
        /* RTM_NEWADDR message for each address */
        if (if_cache[i].has_ipv4) {
            needed += sizeof(struct fbsd_ifa_msghdr) + 64;
        }
    }
    
    /* If buf_addr is 0 or buflen is less than needed, return size */
    if (buf_addr == 0 || *buflen < needed) {
        *buflen = needed;
        BSD_TRACE("netlink: NET_RT_IFLIST needs %zu bytes", needed);
        return 0;
    }
    
    /* Build response */
    uint8_t *response = malloc(needed);
    if (!response) {
        return -ENOMEM;
    }
    
    uint8_t *ptr = response;
    for (int i = 0; i < if_cache_count; i++) {
        interface_info_t *iface = &if_cache[i];
        
        if (af != 0 && af != AF_INET && !iface->has_ipv4) {
            continue;
        }
        
        /* Build RTM_IFINFO */
        int len = build_ifinfo_message(iface, ptr, needed - (ptr - response));
        if (len > 0) {
            ptr += len;
        }
        
        /* Build RTM_NEWADDR for each address */
        if (iface->has_ipv4) {
            len = build_newaddr_message(iface, ptr, needed - (ptr - response));
            if (len > 0) {
                ptr += len;
            }
        }
    }
    
    size_t actual = ptr - response;
    
    /* Write to child's memory */
    struct iovec local = { response, actual };
    struct iovec remote = { (void *)buf_addr, actual };
    ssize_t written = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    
    free(response);
    
    if (written < 0) {
        BSD_ERROR("netlink: failed to write iflist to child: %s", strerror(errno));
        return -EFAULT;
    }
    
    *buflen = actual;
    BSD_TRACE("netlink: NET_RT_IFLIST returned %zu bytes for %d interfaces", actual, if_cache_count);
    
    return 0;
}

/*
 * Translate socket() call for routing sockets
 * FreeBSD: socket(AF_ROUTE, SOCK_RAW, 0)
 * Linux: socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)
 */
int netlink_translate_socket(int *domain, int *type __attribute__((unused)), int *protocol) {
    if (*domain == FBSD_AF_ROUTE) {
        BSD_TRACE("netlink: translating AF_ROUTE socket to AF_NETLINK");
        *domain = AF_NETLINK;
        *protocol = NETLINK_ROUTE;
        return 1;  /* Translated */
    }
    return 0;  /* Not a routing socket */
}

/*
 * Handle routing socket read operations
 * When a FreeBSD program reads from a routing socket expecting FreeBSD format,
 * we need to intercept and provide FreeBSD-formatted data.
 */
int netlink_needs_read_translation(int fd) {
    /* Check if this fd is a netlink socket we created */
    /* For now, return 0 - we'll handle this via sysctl instead */
    (void)fd;
    return 0;
}

/*
 * Invalidate interface cache (call when network config changes)
 */
void netlink_invalidate_cache(void) {
    if_cache_valid = 0;
}

/*
 * Initialize netlink emulation
 */
int netlink_init(void) {
    BSD_TRACE("netlink: initializing emulation layer");
    refresh_interface_cache();
    return 0;
}
