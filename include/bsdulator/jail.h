/*
 * BSDulator - FreeBSD Jail Emulation
 * 
 * Emulates FreeBSD jail syscalls using Linux namespaces.
 * This is the core of the Jailhouse.io vision - bringing FreeBSD jails to Linux.
 * 
 * FreeBSD Jail Syscalls:
 *   - jail()        (338) - Legacy jail creation API
 *   - jail_attach() (436) - Attach process to existing jail
 *   - jail_get()    (506) - Get jail parameters
 *   - jail_set()    (507) - Set jail parameters / create jail
 *   - jail_remove() (508) - Remove a jail
 */

#ifndef BSDULATOR_JAIL_H
#define BSDULATOR_JAIL_H

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>

/*
 * Maximum limits
 */
#define JAIL_MAX_JAILS      256     /* Maximum number of jails */
#define JAIL_MAX_NAME       256     /* Maximum jail name length */
#define JAIL_MAX_PATH       1024    /* Maximum path length */
#define JAIL_MAX_HOSTNAME   256     /* Maximum hostname length */
#define JAIL_MAX_IPS        16      /* Maximum IPs per jail */

/*
 * FreeBSD jail flags (from sys/jail.h)
 */
#define JAIL_CREATE         0x0001  /* Create jail if it doesn't exist */
#define JAIL_UPDATE         0x0002  /* Update parameters of existing jail */
#define JAIL_ATTACH         0x0004  /* Attach to jail upon creation */
#define JAIL_DYING          0x0008  /* Allow dying jail */
#define JAIL_SET_MASK       0x000f  /* Flags for jail_set */
#define JAIL_GET_MASK       0x0008  /* Flags for jail_get */

/* Internal flags */
#define JAIL_SYS_INHERIT    0x0001  /* Inherit parent's securelevel */
#define JAIL_SYS_NEW        0x0002  /* Use new securelevel */
#define JAIL_SYS_DISABLE    0x0000  /* Disable securelevel */

/*
 * Jail parameters (strings used with jail_set/jail_get iovec interface)
 */
#define JAIL_PARAM_JID              "jid"
#define JAIL_PARAM_PARENT           "parent"
#define JAIL_PARAM_NAME             "name"
#define JAIL_PARAM_PATH             "path"
#define JAIL_PARAM_HOSTNAME         "host.hostname"
#define JAIL_PARAM_DOMAINNAME       "host.domainname"
#define JAIL_PARAM_HOSTUUID         "host.hostuuid"
#define JAIL_PARAM_IP4_ADDR         "ip4.addr"
#define JAIL_PARAM_IP6_ADDR         "ip6.addr"
#define JAIL_PARAM_SECURELEVEL      "securelevel"
#define JAIL_PARAM_DEVFS_RULESET    "devfs_ruleset"
#define JAIL_PARAM_ENFORCE_STATFS   "enforce_statfs"
#define JAIL_PARAM_CHILDREN_MAX     "children.max"
#define JAIL_PARAM_CHILDREN_CUR     "children.cur"
#define JAIL_PARAM_PERSIST          "persist"
#define JAIL_PARAM_DYING            "dying"
#define JAIL_PARAM_NOPERSIST        "nopersist"
#define JAIL_PARAM_ALLOW_SET_HOSTNAME "allow.set_hostname"
#define JAIL_PARAM_ALLOW_SYSVIPC    "allow.sysvipc"
#define JAIL_PARAM_ALLOW_RAW_SOCKETS "allow.raw_sockets"
#define JAIL_PARAM_ALLOW_CHFLAGS    "allow.chflags"
#define JAIL_PARAM_ALLOW_MOUNT      "allow.mount"
#define JAIL_PARAM_ALLOW_QUOTAS     "allow.quotas"
#define JAIL_PARAM_ALLOW_SOCKET_AF  "allow.socket_af"

/*
 * FreeBSD jail structure (legacy API - syscall 338)
 * This is the version 2 structure (JAIL_API_VERSION = 2)
 */
struct freebsd_jail {
    uint32_t    version;        /* Version of this structure */
    char        *path;          /* Chroot path */
    char        *hostname;      /* Hostname */
    char        *jailname;      /* Jail name (v2) */
    uint32_t    ip4s;           /* Number of IPv4 addresses */
    uint32_t    ip6s;           /* Number of IPv6 addresses */
    struct in_addr *ip4;        /* IPv4 addresses */
    struct in6_addr *ip6;       /* IPv6 addresses */
};

#define JAIL_API_VERSION    2

/*
 * BSDulator jail state
 * Internal structure to track emulated jails
 */
typedef struct bsd_jail {
    int             jid;                        /* Jail ID (1-based) */
    int             parent_jid;                 /* Parent jail ID (0 = host) */
    char            name[JAIL_MAX_NAME];        /* Jail name */
    char            path[JAIL_MAX_PATH];        /* Root path */
    char            hostname[JAIL_MAX_HOSTNAME];/* Hostname */
    char            domainname[JAIL_MAX_HOSTNAME]; /* Domain name */
    
    /* IPv4 addresses */
    int             ip4_count;
    struct in_addr  ip4_addrs[JAIL_MAX_IPS];
    
    /* IPv6 addresses */
    int             ip6_count;
    struct in6_addr ip6_addrs[JAIL_MAX_IPS];
    
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
    int             vnet;                       /* Use virtual network stack */

    /* State */
    int             active;                     /* Is this slot in use? */
    int             persist;                    /* Persist after last process exits? */
    int             dying;                      /* Jail is being destroyed */
    pid_t           creator_pid;                /* PID that created this jail */
    int             attached_count;             /* Number of attached processes */
    
    /* Linux namespace FDs (for future full implementation) */
    int             ns_pid;                     /* PID namespace fd (-1 if not used) */
    int             ns_mnt;                     /* Mount namespace fd */
    int             ns_uts;                     /* UTS namespace fd */
    int             ns_net;                     /* Network namespace fd */
    int             ns_user;                    /* User namespace fd */
    int             ns_ipc;                     /* IPC namespace fd */
    
} bsd_jail_t;

/*
 * Jail subsystem initialization
 */
int jail_subsystem_init(void);
void jail_subsystem_cleanup(void);

/*
 * Jail management functions
 */

/* Create a new jail, returns jid on success or -errno on failure */
int jail_create(const char *name, const char *path, const char *hostname, int flags);

/* Find jail by ID */
bsd_jail_t *jail_find_by_id(int jid);

/* Find jail by name */
bsd_jail_t *jail_find_by_name(const char *name);

/* Attach calling process to jail */
int jail_attach_process(pid_t pid, int jid);

/* Remove a jail */
int jail_remove(int jid);

/* Get jail parameter */
int jail_get_param(int jid, const char *name, void *value, size_t *len);

/* Set jail parameter */
int jail_set_param(int jid, const char *name, const void *value, size_t len);

/* Get next available jail ID */
int jail_get_next_jid(void);

/* Get jail for a process (returns 0 if not jailed) */
int jail_get_process_jid(pid_t pid);

/*
 * Syscall handlers
 * These are called from syscall_table.c
 */

/* jail() syscall 338 - Legacy API */
long emul_jail(pid_t pid, uint64_t args[6]);

/* jail_attach() syscall 436 */
long emul_jail_attach(pid_t pid, uint64_t args[6]);

/* jail_get() syscall 506 */
long emul_jail_get(pid_t pid, uint64_t args[6]);

/* jail_set() syscall 507 */
long emul_jail_set(pid_t pid, uint64_t args[6]);

/* jail_remove() syscall 508 */
long emul_jail_remove(pid_t pid, uint64_t args[6]);

/*
 * Helper functions
 */

/* Parse iovec parameters from jail_set/jail_get */
int jail_parse_iov(pid_t pid, uint64_t iov_addr, int iovcnt, 
                   int (*callback)(const char *name, void *value, size_t len, void *ctx),
                   void *ctx);

/* Debug: dump jail info */
void jail_dump(const bsd_jail_t *jail);

/* Debug: list all jails */
void jail_list_all(void);

/* Get first active jail (for enumeration) */
bsd_jail_t *jail_get_first(void);

/* Get next active jail after the given JID */
bsd_jail_t *jail_get_next(int after_jid);

#endif /* BSDULATOR_JAIL_H */
