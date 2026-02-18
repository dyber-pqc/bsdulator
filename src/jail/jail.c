/*
 * BSDulator - FreeBSD Jail Emulation Implementation
 * 
 * This implements FreeBSD jail syscalls using Linux primitives.
 * Currently provides state tracking with stubs for namespace isolation.
 * Future versions will integrate Linux namespaces for real isolation.
 * 
 * Copyright (c) 2024-2026 Jailhouse.io
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <arpa/inet.h>

#include "bsdulator.h"
#include "bsdulator/jail.h"

/*
 * Global jail table
 */
static bsd_jail_t jail_table[JAIL_MAX_JAILS];
static int jail_initialized = 0;
static int jail_next_jid = 1;  /* Next jail ID to assign */

/* Process-to-jail mapping (simplified - tracks which processes are in which jails) */
#define MAX_JAILED_PROCS 1024
static struct {
    pid_t pid;
    int jid;
} jailed_procs[MAX_JAILED_PROCS];
static int jailed_proc_count = 0;

/*
 * Initialize jail subsystem
 */
int jail_subsystem_init(void) {
    if (jail_initialized) {
        return 0;
    }
    
    BSD_INFO("Initializing jail subsystem");
    
    /* Clear jail table */
    memset(jail_table, 0, sizeof(jail_table));
    memset(jailed_procs, 0, sizeof(jailed_procs));
    
    /* Mark all slots as inactive */
    for (int i = 0; i < JAIL_MAX_JAILS; i++) {
        jail_table[i].jid = 0;
        jail_table[i].active = 0;
        jail_table[i].ns_pid = -1;
        jail_table[i].ns_mnt = -1;
        jail_table[i].ns_uts = -1;
        jail_table[i].ns_net = -1;
        jail_table[i].ns_user = -1;
        jail_table[i].ns_ipc = -1;
    }
    
    jail_initialized = 1;
    BSD_INFO("Jail subsystem initialized (max %d jails)", JAIL_MAX_JAILS);
    
    return 0;
}

/*
 * Cleanup jail subsystem
 */
void jail_subsystem_cleanup(void) {
    BSD_INFO("Cleaning up jail subsystem");
    
    /* Close any open namespace FDs */
    for (int i = 0; i < JAIL_MAX_JAILS; i++) {
        if (jail_table[i].active) {
            if (jail_table[i].ns_pid >= 0) close(jail_table[i].ns_pid);
            if (jail_table[i].ns_mnt >= 0) close(jail_table[i].ns_mnt);
            if (jail_table[i].ns_uts >= 0) close(jail_table[i].ns_uts);
            if (jail_table[i].ns_net >= 0) close(jail_table[i].ns_net);
            if (jail_table[i].ns_user >= 0) close(jail_table[i].ns_user);
            if (jail_table[i].ns_ipc >= 0) close(jail_table[i].ns_ipc);
        }
    }
    
    jail_initialized = 0;
}

/*
 * Get next available jail ID
 */
int jail_get_next_jid(void) {
    /* Find first free slot and assign next JID */
    for (int i = 0; i < JAIL_MAX_JAILS; i++) {
        if (!jail_table[i].active) {
            return jail_next_jid++;
        }
    }
    return -ENOMEM;
}

/*
 * Find jail by ID
 */
bsd_jail_t *jail_find_by_id(int jid) {
    if (jid <= 0 || jid >= JAIL_MAX_JAILS * 2) {
        return NULL;
    }
    
    for (int i = 0; i < JAIL_MAX_JAILS; i++) {
        if (jail_table[i].active && jail_table[i].jid == jid) {
            return &jail_table[i];
        }
    }
    
    return NULL;
}

/*
 * Find jail by name
 */
bsd_jail_t *jail_find_by_name(const char *name) {
    if (!name || !*name) {
        return NULL;
    }
    
    for (int i = 0; i < JAIL_MAX_JAILS; i++) {
        if (jail_table[i].active && strcmp(jail_table[i].name, name) == 0) {
            return &jail_table[i];
        }
    }
    
    return NULL;
}

/*
 * Create a new jail
 * Returns jid on success, -errno on failure
 */
int jail_create(const char *name, const char *path, const char *hostname, int flags) {
    (void)flags;  /* TODO: Handle flags */
    
    if (!jail_initialized) {
        jail_subsystem_init();
    }
    
    /* Check if name already exists */
    if (name && *name && jail_find_by_name(name)) {
        BSD_WARN("jail_create: jail '%s' already exists", name);
        return -EEXIST;
    }
    
    /* Find free slot */
    int slot = -1;
    for (int i = 0; i < JAIL_MAX_JAILS; i++) {
        if (!jail_table[i].active) {
            slot = i;
            break;
        }
    }
    
    if (slot < 0) {
        BSD_ERROR("jail_create: no free jail slots");
        return -ENOMEM;
    }
    
    /* Initialize jail */
    bsd_jail_t *jail = &jail_table[slot];
    memset(jail, 0, sizeof(*jail));
    
    jail->jid = jail_next_jid++;
    jail->parent_jid = 0;  /* Created from host */
    jail->active = 1;
    jail->creator_pid = getpid();
    jail->attached_count = 0;
    
    /* Set name */
    if (name && *name) {
        strncpy(jail->name, name, JAIL_MAX_NAME - 1);
    } else {
        snprintf(jail->name, JAIL_MAX_NAME, "jail%d", jail->jid);
    }
    
    /* Set path */
    if (path && *path) {
        strncpy(jail->path, path, JAIL_MAX_PATH - 1);
    } else {
        strncpy(jail->path, "/", JAIL_MAX_PATH - 1);
    }
    
    /* Set hostname */
    if (hostname && *hostname) {
        strncpy(jail->hostname, hostname, JAIL_MAX_HOSTNAME - 1);
    } else {
        strncpy(jail->hostname, jail->name, JAIL_MAX_HOSTNAME - 1);
    }
    
    /* Default security settings */
    jail->securelevel = -1;
    jail->devfs_ruleset = 0;
    jail->enforce_statfs = 2;
    jail->children_max = 0;
    jail->children_cur = 0;
    
    /* Default allow flags (permissive for now) */
    jail->allow_set_hostname = 1;
    jail->allow_sysvipc = 0;
    jail->allow_raw_sockets = 0;
    jail->allow_chflags = 0;
    jail->allow_mount = 0;
    jail->allow_quotas = 0;
    jail->allow_socket_af = 1;
    
    /* Namespace FDs not used yet */
    jail->ns_pid = -1;
    jail->ns_mnt = -1;
    jail->ns_uts = -1;
    jail->ns_net = -1;
    jail->ns_user = -1;
    jail->ns_ipc = -1;
    
    BSD_INFO("Created jail jid=%d name='%s' path='%s' hostname='%s'",
             jail->jid, jail->name, jail->path, jail->hostname);
    
    return jail->jid;
}

/*
 * Attach process to jail
 */
int jail_attach_process(pid_t pid, int jid) {
    bsd_jail_t *jail = jail_find_by_id(jid);
    if (!jail) {
        BSD_WARN("jail_attach: jail %d not found", jid);
        return -EINVAL;
    }
    
    /* Record the mapping */
    if (jailed_proc_count < MAX_JAILED_PROCS) {
        jailed_procs[jailed_proc_count].pid = pid;
        jailed_procs[jailed_proc_count].jid = jid;
        jailed_proc_count++;
        jail->attached_count++;
    }
    
    BSD_INFO("Attached pid %d to jail %d (%s)", pid, jid, jail->name);
    
    /*
     * TODO: For real isolation, we would:
     * 1. Use setns() to enter the jail's namespaces
     * 2. chroot() to the jail's path
     * 3. Set hostname to jail's hostname
     * 
     * For now, we just track the mapping.
     */
    
    return 0;
}

/*
 * Get jail for a process
 */
int jail_get_process_jid(pid_t pid) {
    for (int i = 0; i < jailed_proc_count; i++) {
        if (jailed_procs[i].pid == pid) {
            return jailed_procs[i].jid;
        }
    }
    return 0;  /* Not in a jail */
}

/*
 * Remove a jail
 */
int jail_remove(int jid) {
    bsd_jail_t *jail = jail_find_by_id(jid);
    if (!jail) {
        BSD_WARN("jail_remove: jail %d not found", jid);
        return -EINVAL;
    }
    
    if (jail->attached_count > 0 && !jail->dying) {
        BSD_WARN("jail_remove: jail %d has %d attached processes", 
                 jid, jail->attached_count);
        return -EBUSY;
    }
    
    BSD_INFO("Removing jail %d (%s)", jid, jail->name);
    
    /* Close namespace FDs */
    if (jail->ns_pid >= 0) close(jail->ns_pid);
    if (jail->ns_mnt >= 0) close(jail->ns_mnt);
    if (jail->ns_uts >= 0) close(jail->ns_uts);
    if (jail->ns_net >= 0) close(jail->ns_net);
    if (jail->ns_user >= 0) close(jail->ns_user);
    if (jail->ns_ipc >= 0) close(jail->ns_ipc);
    
    /* Remove process mappings for this jail */
    for (int i = 0; i < jailed_proc_count; i++) {
        if (jailed_procs[i].jid == jid) {
            /* Shift remaining entries */
            memmove(&jailed_procs[i], &jailed_procs[i+1], 
                    (jailed_proc_count - i - 1) * sizeof(jailed_procs[0]));
            jailed_proc_count--;
            i--;  /* Re-check this index */
        }
    }
    
    /* Mark slot as free */
    jail->active = 0;
    jail->jid = 0;
    
    return 0;
}

/*
 * Get jail parameter
 */
int jail_get_param(int jid, const char *name, void *value, size_t *len) {
    bsd_jail_t *jail = jail_find_by_id(jid);
    if (!jail) {
        return -EINVAL;
    }
    
    if (!name || !value || !len) {
        return -EINVAL;
    }
    
    /* Handle known parameters */
    if (strcmp(name, JAIL_PARAM_JID) == 0) {
        if (*len < sizeof(int)) return -EINVAL;
        *(int *)value = jail->jid;
        *len = sizeof(int);
        return 0;
    }
    
    if (strcmp(name, JAIL_PARAM_PARENT) == 0) {
        if (*len < sizeof(int)) return -EINVAL;
        *(int *)value = jail->parent_jid;
        *len = sizeof(int);
        return 0;
    }
    
    if (strcmp(name, JAIL_PARAM_NAME) == 0) {
        size_t slen = strlen(jail->name) + 1;
        if (*len < slen) return -EINVAL;
        strcpy((char *)value, jail->name);
        *len = slen;
        return 0;
    }
    
    if (strcmp(name, JAIL_PARAM_PATH) == 0) {
        size_t slen = strlen(jail->path) + 1;
        if (*len < slen) return -EINVAL;
        strcpy((char *)value, jail->path);
        *len = slen;
        return 0;
    }
    
    if (strcmp(name, JAIL_PARAM_HOSTNAME) == 0) {
        size_t slen = strlen(jail->hostname) + 1;
        if (*len < slen) return -EINVAL;
        strcpy((char *)value, jail->hostname);
        *len = slen;
        return 0;
    }
    
    if (strcmp(name, JAIL_PARAM_SECURELEVEL) == 0) {
        if (*len < sizeof(int)) return -EINVAL;
        *(int *)value = jail->securelevel;
        *len = sizeof(int);
        return 0;
    }
    
    if (strcmp(name, JAIL_PARAM_CHILDREN_MAX) == 0) {
        if (*len < sizeof(int)) return -EINVAL;
        *(int *)value = jail->children_max;
        *len = sizeof(int);
        return 0;
    }
    
    if (strcmp(name, JAIL_PARAM_CHILDREN_CUR) == 0) {
        if (*len < sizeof(int)) return -EINVAL;
        *(int *)value = jail->children_cur;
        *len = sizeof(int);
        return 0;
    }
    
    if (strcmp(name, JAIL_PARAM_PERSIST) == 0) {
        if (*len < sizeof(int)) return -EINVAL;
        *(int *)value = jail->persist;
        *len = sizeof(int);
        return 0;
    }
    
    if (strcmp(name, JAIL_PARAM_DYING) == 0) {
        if (*len < sizeof(int)) return -EINVAL;
        *(int *)value = jail->dying;
        *len = sizeof(int);
        return 0;
    }
    
    /* Unknown parameter */
    BSD_WARN("jail_get_param: unknown parameter '%s'", name);
    return -ENOENT;
}

/*
 * Set jail parameter
 */
int jail_set_param(int jid, const char *name, const void *value, size_t len) {
    bsd_jail_t *jail = jail_find_by_id(jid);
    if (!jail) {
        return -EINVAL;
    }
    
    if (!name || !value) {
        return -EINVAL;
    }
    
    /* Handle known parameters */
    if (strcmp(name, JAIL_PARAM_NAME) == 0) {
        strncpy(jail->name, (const char *)value, JAIL_MAX_NAME - 1);
        return 0;
    }
    
    if (strcmp(name, JAIL_PARAM_PATH) == 0) {
        strncpy(jail->path, (const char *)value, JAIL_MAX_PATH - 1);
        return 0;
    }
    
    if (strcmp(name, JAIL_PARAM_HOSTNAME) == 0) {
        strncpy(jail->hostname, (const char *)value, JAIL_MAX_HOSTNAME - 1);
        return 0;
    }
    
    if (strcmp(name, JAIL_PARAM_SECURELEVEL) == 0) {
        if (len < sizeof(int)) return -EINVAL;
        jail->securelevel = *(const int *)value;
        return 0;
    }
    
    if (strcmp(name, JAIL_PARAM_CHILDREN_MAX) == 0) {
        if (len < sizeof(int)) return -EINVAL;
        jail->children_max = *(const int *)value;
        return 0;
    }
    
    if (strcmp(name, JAIL_PARAM_PERSIST) == 0) {
        if (len < sizeof(int)) return -EINVAL;
        jail->persist = *(const int *)value;
        return 0;
    }
    
    if (strcmp(name, JAIL_PARAM_ALLOW_SET_HOSTNAME) == 0) {
        if (len < sizeof(int)) return -EINVAL;
        jail->allow_set_hostname = *(const int *)value;
        return 0;
    }
    
    if (strcmp(name, JAIL_PARAM_ALLOW_SYSVIPC) == 0) {
        if (len < sizeof(int)) return -EINVAL;
        jail->allow_sysvipc = *(const int *)value;
        return 0;
    }
    
    if (strcmp(name, JAIL_PARAM_ALLOW_RAW_SOCKETS) == 0) {
        if (len < sizeof(int)) return -EINVAL;
        jail->allow_raw_sockets = *(const int *)value;
        return 0;
    }
    
    /* Unknown parameter - ignore silently for compatibility */
    BSD_TRACE("jail_set_param: ignoring unknown parameter '%s'", name);
    return 0;
}

/*
 * Debug: dump jail info
 */
void jail_dump(const bsd_jail_t *jail) {
    if (!jail) return;
    
    BSD_INFO("Jail %d:", jail->jid);
    BSD_INFO("  name:     %s", jail->name);
    BSD_INFO("  path:     %s", jail->path);
    BSD_INFO("  hostname: %s", jail->hostname);
    BSD_INFO("  parent:   %d", jail->parent_jid);
    BSD_INFO("  attached: %d", jail->attached_count);
    BSD_INFO("  persist:  %d", jail->persist);
    BSD_INFO("  dying:    %d", jail->dying);
}

/*
 * Debug: list all jails
 */
void jail_list_all(void) {
    BSD_INFO("Active jails:");
    int count = 0;
    for (int i = 0; i < JAIL_MAX_JAILS; i++) {
        if (jail_table[i].active) {
            jail_dump(&jail_table[i]);
            count++;
        }
    }
    if (count == 0) {
        BSD_INFO("  (none)");
    }
}

/*
 * Helper: Read string from child process memory
 */
static int read_child_string(pid_t pid, uint64_t addr, char *buf, size_t maxlen) {
    if (addr == 0) {
        buf[0] = '\0';
        return 0;
    }
    
    struct iovec local = { buf, maxlen };
    struct iovec remote = { (void *)addr, maxlen };
    
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n < 0) {
        /* Fallback to ptrace */
        for (size_t i = 0; i < maxlen; i++) {
            long word = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
            buf[i] = (char)(word & 0xFF);
            if (buf[i] == '\0') break;
        }
    }
    
    buf[maxlen - 1] = '\0';
    return 0;
}

/*
 * Helper: Write integer to child process memory
 */
static int write_child_int(pid_t pid, uint64_t addr, int value) {
    struct iovec local = { &value, sizeof(value) };
    struct iovec remote = { (void *)addr, sizeof(value) };
    
    ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (n < 0) {
        /* Fallback to ptrace */
        ptrace(PTRACE_POKEDATA, pid, addr, (void *)(long)value);
    }
    
    return 0;
}

/*
 * =============================================================================
 * SYSCALL HANDLERS
 * =============================================================================
 */

/*
 * jail() syscall 338 - Legacy API
 * 
 * int jail(struct jail *jail)
 * 
 * Creates a new jail using the legacy structure.
 * Returns jail ID on success, -1 on error.
 */
long emul_jail(pid_t pid, uint64_t args[6]) {
    uint64_t jail_addr = args[0];
    
    BSD_INFO("jail(): struct at 0x%lx", jail_addr);
    
    if (!jail_initialized) {
        jail_subsystem_init();
    }
    
    if (jail_addr == 0) {
        BSD_WARN("jail(): NULL jail structure");
        return -EFAULT;
    }
    
    /* Read the jail structure from child memory */
    struct {
        uint32_t version;
        uint64_t path;
        uint64_t hostname;
        uint64_t jailname;
        uint32_t ip4s;
        uint32_t ip6s;
        uint64_t ip4;
        uint64_t ip6;
    } fbsd_jail;
    
    struct iovec local = { &fbsd_jail, sizeof(fbsd_jail) };
    struct iovec remote = { (void *)jail_addr, sizeof(fbsd_jail) };
    
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n < 0) {
        BSD_WARN("jail(): failed to read jail structure");
        return -EFAULT;
    }
    
    BSD_TRACE("jail(): version=%u path=0x%lx hostname=0x%lx name=0x%lx ip4s=%u",
              fbsd_jail.version, fbsd_jail.path, fbsd_jail.hostname, 
              fbsd_jail.jailname, fbsd_jail.ip4s);
    
    /* Read strings from child memory */
    char path[JAIL_MAX_PATH] = "/";
    char hostname[JAIL_MAX_HOSTNAME] = "";
    char jailname[JAIL_MAX_NAME] = "";
    
    if (fbsd_jail.path) {
        read_child_string(pid, fbsd_jail.path, path, sizeof(path));
    }
    if (fbsd_jail.hostname) {
        read_child_string(pid, fbsd_jail.hostname, hostname, sizeof(hostname));
    }
    if (fbsd_jail.version >= 2 && fbsd_jail.jailname) {
        read_child_string(pid, fbsd_jail.jailname, jailname, sizeof(jailname));
    }
    
    BSD_INFO("jail(): path='%s' hostname='%s' name='%s'", path, hostname, jailname);
    
    /* Create the jail */
    int jid = jail_create(jailname[0] ? jailname : NULL, 
                          path[0] ? path : "/",
                          hostname[0] ? hostname : NULL,
                          JAIL_CREATE | JAIL_ATTACH);
    
    if (jid < 0) {
        BSD_WARN("jail(): creation failed: %d", jid);
        return jid;
    }
    
    /* Attach the calling process */
    jail_attach_process(pid, jid);
    
    BSD_INFO("jail(): created and attached to jail %d", jid);
    return jid;
}

/*
 * jail_attach() syscall 436
 * 
 * int jail_attach(int jid)
 * 
 * Attaches the current process to an existing jail.
 */
long emul_jail_attach(pid_t pid, uint64_t args[6]) {
    int jid = (int)args[0];
    
    BSD_INFO("jail_attach(): jid=%d pid=%d", jid, pid);
    
    if (!jail_initialized) {
        jail_subsystem_init();
    }
    
    bsd_jail_t *jail = jail_find_by_id(jid);
    if (!jail) {
        BSD_WARN("jail_attach(): jail %d not found", jid);
        return -EINVAL;
    }
    
    int ret = jail_attach_process(pid, jid);
    if (ret < 0) {
        return ret;
    }
    
    return 0;
}

/*
 * Context for jail_set/jail_get parameter parsing
 */
typedef struct {
    pid_t pid;
    int jid;
    int flags;
    bsd_jail_t *jail;
    char name[JAIL_MAX_NAME];
    char path[JAIL_MAX_PATH];
    char hostname[JAIL_MAX_HOSTNAME];
    int has_jid;
    int has_name;
    int has_path;
    int has_hostname;
} jail_params_t;

/*
 * jail_get() syscall 506
 * 
 * int jail_get(struct iovec *iov, u_int niov, int flags)
 * 
 * Gets jail parameters. The iovec array contains name/value pairs.
 */
long emul_jail_get(pid_t pid, uint64_t args[6]) {
    uint64_t iov_addr = args[0];
    unsigned int niov = (unsigned int)args[1];
    int flags = (int)args[2];
    
    BSD_INFO("jail_get(): iov=0x%lx niov=%u flags=0x%x", iov_addr, niov, flags);
    
    if (!jail_initialized) {
        jail_subsystem_init();
    }
    
    if (iov_addr == 0 || niov == 0 || niov > 100) {
        return -EINVAL;
    }
    
    /* Read iovec array from child */
    struct iovec *iovs = malloc(niov * sizeof(struct iovec));
    if (!iovs) {
        return -ENOMEM;
    }
    
    struct iovec local = { iovs, niov * sizeof(struct iovec) };
    struct iovec remote = { (void *)iov_addr, niov * sizeof(struct iovec) };
    
    if (process_vm_readv(pid, &local, 1, &remote, 1, 0) < 0) {
        free(iovs);
        return -EFAULT;
    }
    
    /* First pass: find the jail (by jid or name) */
    int jid = 0;
    char jailname[JAIL_MAX_NAME] = "";
    
    for (unsigned int i = 0; i < niov; i += 2) {
        if (i + 1 >= niov) break;
        
        char param_name[256] = "";
        read_child_string(pid, (uint64_t)iovs[i].iov_base, param_name, sizeof(param_name));
        
        if (strcmp(param_name, "jid") == 0 && iovs[i+1].iov_len >= sizeof(int)) {
            struct iovec l = { &jid, sizeof(jid) };
            struct iovec r = { iovs[i+1].iov_base, sizeof(jid) };
            process_vm_readv(pid, &l, 1, &r, 1, 0);
        } else if (strcmp(param_name, "name") == 0) {
            read_child_string(pid, (uint64_t)iovs[i+1].iov_base, jailname, sizeof(jailname));
        }
    }
    
    /* Find the jail */
    bsd_jail_t *jail = NULL;
    if (jid > 0) {
        jail = jail_find_by_id(jid);
    } else if (jailname[0]) {
        jail = jail_find_by_name(jailname);
    } else {
        /* Return first active jail */
        for (int i = 0; i < JAIL_MAX_JAILS; i++) {
            if (jail_table[i].active) {
                jail = &jail_table[i];
                break;
            }
        }
    }
    
    if (!jail) {
        BSD_WARN("jail_get(): no matching jail found (jid=%d name='%s')", jid, jailname);
        free(iovs);
        return -ENOENT;
    }
    
    BSD_TRACE("jail_get(): found jail %d (%s)", jail->jid, jail->name);
    
    /* Second pass: fill in requested parameters */
    for (unsigned int i = 0; i < niov; i += 2) {
        if (i + 1 >= niov) break;
        
        char param_name[256] = "";
        read_child_string(pid, (uint64_t)iovs[i].iov_base, param_name, sizeof(param_name));
        
        if (strcmp(param_name, "jid") == 0 && iovs[i+1].iov_len >= sizeof(int)) {
            write_child_int(pid, (uint64_t)iovs[i+1].iov_base, jail->jid);
        } else if (strcmp(param_name, "name") == 0) {
            struct iovec l = { jail->name, strlen(jail->name) + 1 };
            struct iovec r = { iovs[i+1].iov_base, iovs[i+1].iov_len };
            process_vm_writev(pid, &l, 1, &r, 1, 0);
        } else if (strcmp(param_name, "path") == 0) {
            struct iovec l = { jail->path, strlen(jail->path) + 1 };
            struct iovec r = { iovs[i+1].iov_base, iovs[i+1].iov_len };
            process_vm_writev(pid, &l, 1, &r, 1, 0);
        } else if (strcmp(param_name, "host.hostname") == 0) {
            struct iovec l = { jail->hostname, strlen(jail->hostname) + 1 };
            struct iovec r = { iovs[i+1].iov_base, iovs[i+1].iov_len };
            process_vm_writev(pid, &l, 1, &r, 1, 0);
        } else if (strcmp(param_name, "parent") == 0 && iovs[i+1].iov_len >= sizeof(int)) {
            write_child_int(pid, (uint64_t)iovs[i+1].iov_base, jail->parent_jid);
        } else if (strcmp(param_name, "children.cur") == 0 && iovs[i+1].iov_len >= sizeof(int)) {
            write_child_int(pid, (uint64_t)iovs[i+1].iov_base, jail->children_cur);
        } else if (strcmp(param_name, "children.max") == 0 && iovs[i+1].iov_len >= sizeof(int)) {
            write_child_int(pid, (uint64_t)iovs[i+1].iov_base, jail->children_max);
        } else if (strcmp(param_name, "securelevel") == 0 && iovs[i+1].iov_len >= sizeof(int)) {
            write_child_int(pid, (uint64_t)iovs[i+1].iov_base, jail->securelevel);
        } else if (strcmp(param_name, "persist") == 0 && iovs[i+1].iov_len >= sizeof(int)) {
            write_child_int(pid, (uint64_t)iovs[i+1].iov_base, jail->persist);
        } else if (strcmp(param_name, "dying") == 0 && iovs[i+1].iov_len >= sizeof(int)) {
            write_child_int(pid, (uint64_t)iovs[i+1].iov_base, jail->dying);
        }
        /* Silently ignore unknown parameters */
    }
    
    free(iovs);
    return jail->jid;
}

/*
 * jail_set() syscall 507
 * 
 * int jail_set(struct iovec *iov, u_int niov, int flags)
 * 
 * Creates or updates a jail. The iovec array contains name/value pairs.
 * Returns jail ID on success.
 */
long emul_jail_set(pid_t pid, uint64_t args[6]) {
    uint64_t iov_addr = args[0];
    unsigned int niov = (unsigned int)args[1];
    int flags = (int)args[2];
    
    BSD_INFO("jail_set(): iov=0x%lx niov=%u flags=0x%x", iov_addr, niov, flags);
    
    if (!jail_initialized) {
        jail_subsystem_init();
    }
    
    if (iov_addr == 0 || niov == 0 || niov > 100) {
        return -EINVAL;
    }
    
    /* Read iovec array from child */
    struct iovec *iovs = malloc(niov * sizeof(struct iovec));
    if (!iovs) {
        return -ENOMEM;
    }
    
    struct iovec local = { iovs, niov * sizeof(struct iovec) };
    struct iovec remote = { (void *)iov_addr, niov * sizeof(struct iovec) };
    
    if (process_vm_readv(pid, &local, 1, &remote, 1, 0) < 0) {
        free(iovs);
        return -EFAULT;
    }
    
    /* Parse parameters */
    jail_params_t params = {0};
    params.pid = pid;
    params.flags = flags;
    strcpy(params.path, "/");
    
    for (unsigned int i = 0; i < niov; i += 2) {
        if (i + 1 >= niov) break;
        
        char param_name[256] = "";
        read_child_string(pid, (uint64_t)iovs[i].iov_base, param_name, sizeof(param_name));
        
        BSD_TRACE("jail_set(): param '%s' len=%zu", param_name, iovs[i+1].iov_len);
        
        if (strcmp(param_name, "jid") == 0 && iovs[i+1].iov_len >= sizeof(int)) {
            struct iovec l = { &params.jid, sizeof(params.jid) };
            struct iovec r = { iovs[i+1].iov_base, sizeof(params.jid) };
            process_vm_readv(pid, &l, 1, &r, 1, 0);
            params.has_jid = 1;
            BSD_TRACE("jail_set(): jid=%d", params.jid);
        } else if (strcmp(param_name, "name") == 0) {
            read_child_string(pid, (uint64_t)iovs[i+1].iov_base, params.name, sizeof(params.name));
            params.has_name = 1;
            BSD_TRACE("jail_set(): name='%s'", params.name);
        } else if (strcmp(param_name, "path") == 0) {
            read_child_string(pid, (uint64_t)iovs[i+1].iov_base, params.path, sizeof(params.path));
            params.has_path = 1;
            BSD_TRACE("jail_set(): path='%s'", params.path);
        } else if (strcmp(param_name, "host.hostname") == 0) {
            read_child_string(pid, (uint64_t)iovs[i+1].iov_base, params.hostname, sizeof(params.hostname));
            params.has_hostname = 1;
            BSD_TRACE("jail_set(): hostname='%s'", params.hostname);
        }
        /* TODO: Handle more parameters (ip4.addr, securelevel, allow.*, etc.) */
    }
    
    /* Determine operation: create or update */
    bsd_jail_t *jail = NULL;
    
    if (params.has_jid && params.jid > 0) {
        /* Update existing jail */
        jail = jail_find_by_id(params.jid);
        if (!jail && !(flags & JAIL_CREATE)) {
            BSD_WARN("jail_set(): jail %d not found", params.jid);
            free(iovs);
            return -ENOENT;
        }
    } else if (params.has_name && params.name[0]) {
        /* Find by name */
        jail = jail_find_by_name(params.name);
    }
    
    if (jail && (flags & JAIL_UPDATE)) {
        /* Update existing jail */
        BSD_INFO("jail_set(): updating jail %d", jail->jid);
        
        if (params.has_path && params.path[0]) {
            memset(jail->path, 0, JAIL_MAX_PATH);
            memcpy(jail->path, params.path, strlen(params.path));
        }
        if (params.has_hostname && params.hostname[0]) {
            memset(jail->hostname, 0, JAIL_MAX_HOSTNAME);
            memcpy(jail->hostname, params.hostname, strlen(params.hostname));
        }
        
        free(iovs);
        
        if (flags & JAIL_ATTACH) {
            jail_attach_process(pid, jail->jid);
        }
        
        return jail->jid;
    }
    
    if (flags & JAIL_CREATE) {
        /* Create new jail */
        int jid = jail_create(
            params.has_name ? params.name : NULL,
            params.has_path ? params.path : "/",
            params.has_hostname ? params.hostname : NULL,
            flags
        );
        
        if (jid < 0) {
            BSD_WARN("jail_set(): creation failed: %d", jid);
            free(iovs);
            return jid;
        }
        
        if (flags & JAIL_ATTACH) {
            jail_attach_process(pid, jid);
        }
        
        free(iovs);
        return jid;
    }
    
    BSD_WARN("jail_set(): invalid flags or jail not found");
    free(iovs);
    return -EINVAL;
}

/*
 * jail_remove() syscall 508
 * 
 * int jail_remove(int jid)
 * 
 * Removes a jail by ID.
 */
long emul_jail_remove(pid_t pid, uint64_t args[6]) {
    (void)pid;
    int jid = (int)args[0];
    
    BSD_INFO("jail_remove(): jid=%d", jid);
    
    if (!jail_initialized) {
        jail_subsystem_init();
    }
    
    return jail_remove(jid);
}
