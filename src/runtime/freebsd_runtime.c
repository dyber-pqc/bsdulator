/*
 * BSDulator - FreeBSD Runtime Emulation Implementation
 * Provides FreeBSD-compatible sysctl and auxv emulation
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <elf.h>

#include "freebsd_runtime.h"
#include "bsdulator.h"
#include "bsdulator/jail.h"

/* Global runtime state */
freebsd_runtime_t g_freebsd_runtime = {0};

/*
 * Read memory from traced process
 */
static ssize_t read_process_mem(pid_t pid, void *local, const void *remote, size_t len) {
    struct iovec local_iov = { local, len };
    struct iovec remote_iov = { (void *)remote, len };
    return syscall(SYS_process_vm_readv, pid, &local_iov, 1, &remote_iov, 1, 0);
}

/*
 * Write memory to traced process
 */
static ssize_t write_process_mem(pid_t pid, const void *local, void *remote, size_t len) {
    struct iovec local_iov = { (void *)local, len };
    struct iovec remote_iov = { remote, len };
    return syscall(SYS_process_vm_writev, pid, &local_iov, 1, &remote_iov, 1, 0);
}

/*
 * Generate random canary for stack protection.
 * FreeBSD uses 64 bytes of random data from /dev/urandom.
 * The canary should not contain null bytes to prevent
 * string-based buffer overflow exploitation.
 */
static void generate_canary(uint8_t *canary, size_t len) {
    FILE *f = fopen("/dev/urandom", "r");
    if (f) {
        size_t n = fread(canary, 1, len, f);
        fclose(f);
        if (n == len) {
            /* Replace any null bytes - FreeBSD convention */
            for (size_t i = 0; i < len; i++) {
                if (canary[i] == 0) canary[i] = 0x42;
            }
            return;
        }
    }
    /* Fallback to time-based */
    srand((unsigned int)time(NULL) ^ getpid());
    for (size_t i = 0; i < len; i++) {
        canary[i] = (uint8_t)(rand() & 0xFF);
        if (canary[i] == 0) canary[i] = 0x42;
    }
}

int freebsd_runtime_init(void) {
    if (g_freebsd_runtime.initialized) {
        return 0;
    }
    
    BSD_TRACE("Initializing FreeBSD runtime emulation");
    
    /* Set default OS information */
    g_freebsd_runtime.osreldate = FREEBSD_DEFAULT_OSRELDATE;
    strncpy(g_freebsd_runtime.ostype, "FreeBSD", sizeof(g_freebsd_runtime.ostype) - 1);
    strncpy(g_freebsd_runtime.osrelease, "15.0-RELEASE", sizeof(g_freebsd_runtime.osrelease) - 1);
    strncpy(g_freebsd_runtime.version, 
            "FreeBSD 15.0-RELEASE (BSDulator emulation)", 
            sizeof(g_freebsd_runtime.version) - 1);
    strncpy(g_freebsd_runtime.machine, "amd64", sizeof(g_freebsd_runtime.machine) - 1);
    strncpy(g_freebsd_runtime.machine_arch, "amd64", sizeof(g_freebsd_runtime.machine_arch) - 1);
    
    /* Set hardware info */
    g_freebsd_runtime.ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (g_freebsd_runtime.ncpus < 1) {
        g_freebsd_runtime.ncpus = FREEBSD_DEFAULT_NCPUS;
    }
    g_freebsd_runtime.pagesize = sysconf(_SC_PAGESIZE);
    if (g_freebsd_runtime.pagesize < 1) {
        g_freebsd_runtime.pagesize = FREEBSD_DEFAULT_PAGESIZE;
    }
    
    /* Default user stack (will be updated when process starts) */
    g_freebsd_runtime.usrstack = 0x7FFFFFFFE000ULL;
    
    /* Generate stack canary */
    generate_canary(g_freebsd_runtime.canary, sizeof(g_freebsd_runtime.canary));
    
    g_freebsd_runtime.initialized = 1;
    
    BSD_INFO("FreeBSD runtime: osreldate=%d, ncpus=%d, pagesize=%d",
             g_freebsd_runtime.osreldate,
             g_freebsd_runtime.ncpus,
             g_freebsd_runtime.pagesize);
    
    return 0;
}

void freebsd_runtime_set_execpath(const char *path) {
    if (path) {
        /* Get absolute path */
        char *abs = realpath(path, NULL);
        if (abs) {
            strncpy(g_freebsd_runtime.execpath, abs, sizeof(g_freebsd_runtime.execpath) - 1);
            free(abs);
        } else {
            strncpy(g_freebsd_runtime.execpath, path, sizeof(g_freebsd_runtime.execpath) - 1);
        }
    }
}

/*
 * Handle kern.* sysctl queries
 */
static long handle_kern_sysctl(int mib1, pid_t pid, uint64_t oldp_addr, uint64_t oldlenp_addr) {
    size_t oldlen = 0;
    
    /* Read oldlenp from process if provided */
    if (oldlenp_addr) {
        if (read_process_mem(pid, &oldlen, (void *)oldlenp_addr, sizeof(oldlen)) < 0) {
            BSD_ERROR("Failed to read oldlenp from process");
            return -EFAULT;
        }
    }
    
    switch (mib1) {
        case KERN_OSTYPE: {
            const char *val = g_freebsd_runtime.ostype;
            size_t len = strlen(val) + 1;
            BSD_TRACE("sysctl: kern.ostype = \"%s\"", val);
            
            if (oldlenp_addr) {
                if (write_process_mem(pid, &len, (void *)oldlenp_addr, sizeof(len)) < 0) {
                    return -EFAULT;
                }
            }
            if (oldp_addr && oldlen >= len) {
                if (write_process_mem(pid, val, (void *)oldp_addr, len) < 0) {
                    return -EFAULT;
                }
            }
            return 0;
        }
        
        case KERN_OSRELEASE: {
            const char *val = g_freebsd_runtime.osrelease;
            size_t len = strlen(val) + 1;
            BSD_TRACE("sysctl: kern.osrelease = \"%s\"", val);
            
            if (oldlenp_addr) {
                if (write_process_mem(pid, &len, (void *)oldlenp_addr, sizeof(len)) < 0) {
                    return -EFAULT;
                }
            }
            if (oldp_addr && oldlen >= len) {
                if (write_process_mem(pid, val, (void *)oldp_addr, len) < 0) {
                    return -EFAULT;
                }
            }
            return 0;
        }
        
        case KERN_OSRELDATE: {
            int val = g_freebsd_runtime.osreldate;
            size_t len = sizeof(val);
            BSD_TRACE("sysctl: kern.osreldate = %d", val);
            
            if (oldlenp_addr) {
                if (write_process_mem(pid, &len, (void *)oldlenp_addr, sizeof(len)) < 0) {
                    return -EFAULT;
                }
            }
            if (oldp_addr && oldlen >= len) {
                if (write_process_mem(pid, &val, (void *)oldp_addr, len) < 0) {
                    return -EFAULT;
                }
            }
            return 0;
        }
        
        case KERN_VERSION: {
            const char *val = g_freebsd_runtime.version;
            size_t len = strlen(val) + 1;
            BSD_TRACE("sysctl: kern.version = \"%s\"", val);
            
            if (oldlenp_addr) {
                if (write_process_mem(pid, &len, (void *)oldlenp_addr, sizeof(len)) < 0) {
                    return -EFAULT;
                }
            }
            if (oldp_addr && oldlen >= len) {
                if (write_process_mem(pid, val, (void *)oldp_addr, len) < 0) {
                    return -EFAULT;
                }
            }
            return 0;
        }
        
        case KERN_HOSTNAME: {
            char hostname[256];
            if (gethostname(hostname, sizeof(hostname)) < 0) {
                strcpy(hostname, "bsdulator");
            }
            size_t len = strlen(hostname) + 1;
            BSD_TRACE("sysctl: kern.hostname = \"%s\"", hostname);
            
            if (oldlenp_addr) {
                if (write_process_mem(pid, &len, (void *)oldlenp_addr, sizeof(len)) < 0) {
                    return -EFAULT;
                }
            }
            if (oldp_addr && oldlen >= len) {
                if (write_process_mem(pid, hostname, (void *)oldp_addr, len) < 0) {
                    return -EFAULT;
                }
            }
            return 0;
        }
        
        case KERN_USRSTACK: {
            uint64_t val = g_freebsd_runtime.usrstack;
            size_t len = sizeof(val);
            BSD_TRACE("sysctl: kern.usrstack = 0x%llx", (unsigned long long)val);
            
            if (oldlenp_addr) {
                if (write_process_mem(pid, &len, (void *)oldlenp_addr, sizeof(len)) < 0) {
                    return -EFAULT;
                }
            }
            if (oldp_addr && oldlen >= len) {
                if (write_process_mem(pid, &val, (void *)oldp_addr, len) < 0) {
                    return -EFAULT;
                }
            }
            return 0;
        }
        
        case KERN_ARND: {
            /* Return random bytes */
            BSD_TRACE("sysctl: kern.arnd (random data), len=%zu", oldlen);
            if (oldp_addr && oldlen > 0) {
                uint8_t *randbuf = malloc(oldlen);
                if (!randbuf) return -ENOMEM;
                
                FILE *f = fopen("/dev/urandom", "r");
                if (f) {
                    size_t n = fread(randbuf, 1, oldlen, f);
                    fclose(f);
                    if (n != oldlen) {
                        free(randbuf);
                        return -EIO;
                    }
                } else {
                    /* Fallback */
                    for (size_t i = 0; i < oldlen; i++) {
                        randbuf[i] = (uint8_t)(rand() & 0xFF);
                    }
                }
                
                if (write_process_mem(pid, randbuf, (void *)oldp_addr, oldlen) < 0) {
                    free(randbuf);
                    return -EFAULT;
                }
                free(randbuf);
            }
            return 0;
        }
        
        default:
            BSD_WARN("Unhandled kern sysctl: %d", mib1);
            return -ENOENT;
    }
}

/*
 * Handle hw.* sysctl queries
 */
static long handle_hw_sysctl(int mib1, pid_t pid, uint64_t oldp_addr, uint64_t oldlenp_addr) {
    size_t oldlen = 0;
    
    if (oldlenp_addr) {
        if (read_process_mem(pid, &oldlen, (void *)oldlenp_addr, sizeof(oldlen)) < 0) {
            return -EFAULT;
        }
    }
    
    switch (mib1) {
        case HW_MACHINE: {
            const char *val = g_freebsd_runtime.machine;
            size_t len = strlen(val) + 1;
            BSD_TRACE("sysctl: hw.machine = \"%s\"", val);
            
            if (oldlenp_addr) {
                write_process_mem(pid, &len, (void *)oldlenp_addr, sizeof(len));
            }
            if (oldp_addr && oldlen >= len) {
                write_process_mem(pid, val, (void *)oldp_addr, len);
            }
            return 0;
        }
        
        case HW_MACHINE_ARCH: {
            const char *val = g_freebsd_runtime.machine_arch;
            size_t len = strlen(val) + 1;
            BSD_TRACE("sysctl: hw.machine_arch = \"%s\"", val);
            
            if (oldlenp_addr) {
                write_process_mem(pid, &len, (void *)oldlenp_addr, sizeof(len));
            }
            if (oldp_addr && oldlen >= len) {
                write_process_mem(pid, val, (void *)oldp_addr, len);
            }
            return 0;
        }
        
        case HW_NCPU: {
            int val = g_freebsd_runtime.ncpus;
            size_t len = sizeof(val);
            BSD_TRACE("sysctl: hw.ncpu = %d", val);
            
            if (oldlenp_addr) {
                write_process_mem(pid, &len, (void *)oldlenp_addr, sizeof(len));
            }
            if (oldp_addr && oldlen >= len) {
                write_process_mem(pid, &val, (void *)oldp_addr, len);
            }
            return 0;
        }
        
        case HW_PAGESIZE: {
            int val = g_freebsd_runtime.pagesize;
            size_t len = sizeof(val);
            BSD_TRACE("sysctl: hw.pagesize = %d", val);
            
            if (oldlenp_addr) {
                write_process_mem(pid, &len, (void *)oldlenp_addr, sizeof(len));
            }
            if (oldp_addr && oldlen >= len) {
                write_process_mem(pid, &val, (void *)oldp_addr, len);
            }
            return 0;
        }
        
        default:
            BSD_WARN("Unhandled hw sysctl: %d", mib1);
            return -ENOENT;
    }
}

/*
 * Jail parameter OID table for CTL_SYSCTL name2oid lookups.
 * These are fake OIDs that we recognize when queried.
 * Real FreeBSD uses dynamically assigned OIDs, but we use fixed ones.
 */
typedef struct {
    const char *name;
    int oid[8];
    int oidlen;
    char format;  /* 'I'=int, 'S'=string, 'L'=long */
    size_t size;  /* 0 = variable length string */
} jail_param_oid_t;

/* CTLTYPE values from FreeBSD sys/sysctl.h */
#define CTLTYPE_INT     2   /* integer */
#define CTLTYPE_STRING  3   /* string */
#define CTLTYPE_STRUCT  5   /* structure/opaque */

/* CTLFLAG values */
#define CTLFLAG_RD      0x80000000  /* Read-only */
#define CTLFLAG_WR      0x40000000  /* Write-only */
#define CTLFLAG_RW      (CTLFLAG_RD|CTLFLAG_WR)

static const jail_param_oid_t jail_param_oids[] = {
    { "security.jail.param.jid",           {14, 1, 1, 1}, 4, 'I', sizeof(int) },
    { "security.jail.param.name",          {14, 1, 1, 2}, 4, 'S', 256 },
    { "security.jail.param.path",          {14, 1, 1, 3}, 4, 'S', 1024 },
    { "security.jail.param.host.hostname", {14, 1, 1, 4}, 4, 'S', 256 },
    { "security.jail.param.ip4.addr",      {14, 1, 1, 5}, 4, 'S', 256 },
    { "security.jail.param.ip6.addr",      {14, 1, 1, 6}, 4, 'S', 256 },
    { "security.jail.param.securelevel",   {14, 1, 1, 7}, 4, 'I', sizeof(int) },
    { "security.jail.param.children.max",  {14, 1, 1, 8}, 4, 'I', sizeof(int) },
    { "security.jail.param.children.cur",  {14, 1, 1, 9}, 4, 'I', sizeof(int) },
    { "security.jail.param.persist",       {14, 1, 1, 10}, 4, 'I', sizeof(int) },
    { "security.jail.param.dying",         {14, 1, 1, 11}, 4, 'I', sizeof(int) },
    { "security.jail.param.parent",        {14, 1, 1, 12}, 4, 'I', sizeof(int) },
    { "security.jail.param.allow.set_hostname",  {14, 1, 1, 20}, 4, 'I', sizeof(int) },
    { "security.jail.param.allow.sysvipc",       {14, 1, 1, 21}, 4, 'I', sizeof(int) },
    { "security.jail.param.allow.raw_sockets",   {14, 1, 1, 22}, 4, 'I', sizeof(int) },
    { "security.jail.param.cpuset.id",             {14, 1, 1, 30}, 4, 'I', sizeof(int) },
    { "security.jail.param.osreldate",             {14, 1, 1, 31}, 4, 'I', sizeof(int) },
    { "security.jail.param.osrelease",             {14, 1, 1, 32}, 4, 'S', 32 },
    { "security.jail.param.ip4",                   {14, 1, 1, 33}, 4, 'I', sizeof(int) },
    { "security.jail.param.ip6",                   {14, 1, 1, 34}, 4, 'I', sizeof(int) },
    { "security.jail.param.vnet",                  {14, 1, 1, 35}, 4, 'I', sizeof(int) },
    { NULL, {0}, 0, 0, 0 }
};

/*
 * Handle CTL_SYSCTL (category 0) operations.
 * This is used for sysctl name-to-OID conversion and OID format queries.
 */
static long handle_sysctl_sysctl(int *mib, unsigned int namelen, pid_t pid,
                                  uint64_t oldp_addr, uint64_t oldlenp_addr,
                                  uint64_t newp_addr, size_t newlen) {
    size_t oldlen = 0;
    
    if (oldlenp_addr) {
        if (read_process_mem(pid, &oldlen, (void *)oldlenp_addr, sizeof(oldlen)) < 0) {
            return -EFAULT;
        }
    }
    
    switch (mib[1]) {
        case CTL_SYSCTL_NAME2OID: {
            /* Convert sysctl name to OID */
            /* newp contains the name string, newlen is its length */
            if (newp_addr == 0 || newlen == 0) {
                BSD_WARN("sysctl.name2oid: no name provided");
                return -EINVAL;
            }
            
            char name[256];
            if (newlen >= sizeof(name)) newlen = sizeof(name) - 1;
            
            if (read_process_mem(pid, name, (void *)newp_addr, newlen) < 0) {
                return -EFAULT;
            }
            name[newlen] = '\0';
            
            BSD_TRACE("sysctl.name2oid: looking up '%s'", name);
            
            /* Look up the name in our jail parameter table */
            for (const jail_param_oid_t *p = jail_param_oids; p->name; p++) {
                if (strcmp(name, p->name) == 0) {
                    /* Found - return the OID */
                    size_t oid_size = p->oidlen * sizeof(int);
                    BSD_TRACE("sysctl.name2oid: found '%s' -> oid len=%d", name, p->oidlen);
                    
                    if (oldlenp_addr) {
                        if (write_process_mem(pid, &oid_size, (void *)oldlenp_addr, sizeof(oid_size)) < 0) {
                            return -EFAULT;
                        }
                    }
                    if (oldp_addr && oldlen >= oid_size) {
                        if (write_process_mem(pid, p->oid, (void *)oldp_addr, oid_size) < 0) {
                            return -EFAULT;
                        }
                    }
                    return 0;
                }
            }
            
            /* Check for kern.features.* which jls queries */
            if (strncmp(name, "kern.features.", 14) == 0) {
                BSD_TRACE("sysctl.name2oid: kern.features.* - returning not found");
                return -ENOENT;
            }
            
            BSD_WARN("sysctl.name2oid: '%s' not found", name);
            return -ENOENT;
        }
        
        case CTL_SYSCTL_OIDFMT: {
            /* Get the format of an OID */
            /* The MIB contains: [0, 4, oid[0], oid[1], ...] */
            if (namelen < 3) {
                BSD_WARN("sysctl.oidfmt: namelen too short");
                return -EINVAL;
            }
            
            BSD_TRACE("sysctl.oidfmt: looking up oid[%d,%d,...] len=%u",
                      mib[2], namelen > 3 ? mib[3] : 0, namelen - 2);
            
            /* Find matching OID in our table */
            for (const jail_param_oid_t *p = jail_param_oids; p->name; p++) {
                if (p->oidlen == (int)(namelen - 2)) {
                    int match = 1;
                    for (int i = 0; i < p->oidlen && match; i++) {
                        if (p->oid[i] != mib[i + 2]) match = 0;
                    }
                    if (match) {
                        /* Found - return format info */
                        /* Format is: 4 bytes kind + format string */
                        /* kind = CTLFLAG_* | CTLTYPE_* */
                        struct {
                            uint32_t kind;
                            char fmt[4];
                        } __attribute__((packed)) result;
                        
                        /* Set kind based on format type */
                        uint32_t ctltype;
                        switch (p->format) {
                            case 'I': ctltype = CTLTYPE_INT; break;
                            case 'S': ctltype = CTLTYPE_STRING; break;
                            default:  ctltype = CTLTYPE_STRUCT; break;
                        }
                        result.kind = CTLFLAG_RD | ctltype;
                        result.fmt[0] = p->format;
                        result.fmt[1] = '\0';
                        
                        size_t result_size = sizeof(result.kind) + 2;
                        
                        BSD_TRACE("sysctl.oidfmt: found '%s' format='%c' kind=0x%x", 
                                  p->name, p->format, result.kind);
                        
                        if (oldlenp_addr) {
                            write_process_mem(pid, &result_size, (void *)oldlenp_addr, sizeof(result_size));
                        }
                        if (oldp_addr && oldlen >= result_size) {
                            write_process_mem(pid, &result, (void *)oldp_addr, result_size);
                        }
                        return 0;
                    }
                }
            }
            
            BSD_WARN("sysctl.oidfmt: OID not found");
            return -ENOENT;
        }
        
        default:
            BSD_WARN("sysctl.sysctl: unhandled operation %d", mib[1]);
            return -ENOENT;
    }
}

long freebsd_handle_sysctl(pid_t pid, uint64_t args[6]) {
    /*
     * FreeBSD __sysctl(2):
     *   int __sysctl(const int *name, u_int namelen, void *oldp, 
     *                size_t *oldlenp, const void *newp, size_t newlen);
     */
    uint64_t name_addr = args[0];
    unsigned int namelen = (unsigned int)args[1];
    uint64_t oldp_addr = args[2];
    uint64_t oldlenp_addr = args[3];
    uint64_t newp_addr = args[4];
    size_t newlen = args[5];
    
    if (namelen < 2 || namelen > 24) {
        BSD_WARN("sysctl: invalid namelen %u", namelen);
        return -EINVAL;
    }
    
    /* Read MIB from process */
    int mib[24];
    if (read_process_mem(pid, mib, (void *)name_addr, namelen * sizeof(int)) < 0) {
        BSD_ERROR("Failed to read sysctl MIB from process");
        return -EFAULT;
    }
    
    BSD_TRACE("sysctl: mib[0]=%d mib[1]=%d namelen=%u", mib[0], mib[1], namelen);
    
    switch (mib[0]) {
        case CTL_SYSCTL:
            return handle_sysctl_sysctl(mib, namelen, pid, oldp_addr, oldlenp_addr, newp_addr, newlen);
            
        case CTL_KERN:
            return handle_kern_sysctl(mib[1], pid, oldp_addr, oldlenp_addr);
            
        case CTL_HW:
            return handle_hw_sysctl(mib[1], pid, oldp_addr, oldlenp_addr);
        
        case CTL_SECURITY: {
            /* security.jail.* sysctls for jail parameter queries */
            /* mib = {14, 1, 1, param_id} for jail params */
            BSD_TRACE("sysctl: security.jail query mib[2]=%d mib[3]=%d", 
                      namelen > 2 ? mib[2] : 0, namelen > 3 ? mib[3] : 0);
            
            size_t oldlen = 0;
            if (oldlenp_addr) {
                read_process_mem(pid, &oldlen, (void *)oldlenp_addr, sizeof(oldlen));
            }
            
            /*
             * When queried directly, jail params return the MAXIMUM SIZE for strings.
             * This tells libjail how much buffer to allocate.
             * Match the OID to find the size.
             */
            for (const jail_param_oid_t *p = jail_param_oids; p->name; p++) {
                if (p->oidlen == (int)namelen) {
                    int match = 1;
                    for (int i = 0; i < p->oidlen && match; i++) {
                        if (p->oid[i] != mib[i]) match = 0;
                    }
                    if (match && p->size > 0) {
                        /* Return the size as an ASCII string (e.g., "256\0") */
                        char size_str[32];
                        int str_len = snprintf(size_str, sizeof(size_str), "%zu", p->size);
                        size_t len = str_len + 1;  /* Include null terminator */
                        BSD_TRACE("sysctl: security.jail.param '%s' -> size '%s' (%zu bytes)", p->name, size_str, len);
                        
                        if (oldlenp_addr) {
                            write_process_mem(pid, &len, (void *)oldlenp_addr, sizeof(len));
                        }
                        if (oldp_addr && oldlen >= len) {
                            write_process_mem(pid, size_str, (void *)oldp_addr, len);
                        }
                        return 0;
                    }
                }
            }
            
            /* Unknown jail param - return 0 size */
            size_t zero = 0;
            if (oldlenp_addr) {
                write_process_mem(pid, &zero, (void *)oldlenp_addr, sizeof(zero));
            }
            
            /* Return success - indicates "no jails" not "error" */
            return 0;
        }
            
        default:
            BSD_WARN("Unhandled sysctl category: %d", mib[0]);
            return -ENOENT;
    }
}

/*
 * Lookup table for sysctlbyname
 */
typedef struct {
    const char *name;
    int mib[4];
    int miblen;
} sysctl_name_entry_t;

static const sysctl_name_entry_t sysctl_names[] = {
    { "kern.ostype",      { CTL_KERN, KERN_OSTYPE },     2 },
    { "kern.osrelease",   { CTL_KERN, KERN_OSRELEASE },  2 },
    { "kern.osreldate",   { CTL_KERN, KERN_OSRELDATE },  2 },
    { "kern.version",     { CTL_KERN, KERN_VERSION },    2 },
    { "kern.hostname",    { CTL_KERN, KERN_HOSTNAME },   2 },
    { "kern.usrstack",    { CTL_KERN, KERN_USRSTACK },   2 },
    { "kern.arandom",     { CTL_KERN, KERN_ARND },       2 },
    { "hw.machine",       { CTL_HW, HW_MACHINE },        2 },
    { "hw.machine_arch",  { CTL_HW, HW_MACHINE_ARCH },   2 },
    { "hw.ncpu",          { CTL_HW, HW_NCPU },           2 },
    { "hw.pagesize",      { CTL_HW, HW_PAGESIZE },       2 },
    { NULL, {0}, 0 }
};

long freebsd_handle_sysctlbyname(pid_t pid, uint64_t args[6]) {
    /*
     * FreeBSD sysctlbyname(3) via syscall 570:
     *   int __sysctlbyname(const char *name, size_t namelen,
     *                      void *oldp, size_t *oldlenp,
     *                      const void *newp, size_t newlen);
     */
    uint64_t name_addr = args[0];
    size_t name_len = args[1];
    uint64_t oldp_addr = args[2];
    uint64_t oldlenp_addr = args[3];
    
    if (name_len > 256) {
        return -ENAMETOOLONG;
    }
    
    /* Read name from process */
    char name[257];
    if (read_process_mem(pid, name, (void *)name_addr, name_len) < 0) {
        return -EFAULT;
    }
    name[name_len] = '\0';
    
    BSD_TRACE("sysctlbyname: \"%s\"", name);
    
    /* Look up the name */
    for (const sysctl_name_entry_t *e = sysctl_names; e->name; e++) {
        if (strcmp(name, e->name) == 0) {
            /* Found - dispatch to numeric handler */
            switch (e->mib[0]) {
                case CTL_KERN:
                    return handle_kern_sysctl(e->mib[1], pid, oldp_addr, oldlenp_addr);
                case CTL_HW:
                    return handle_hw_sysctl(e->mib[1], pid, oldp_addr, oldlenp_addr);
            }
        }
    }
    
    BSD_WARN("sysctlbyname: unknown name \"%s\"", name);
    return -ENOENT;
}

int freebsd_build_auxv(uint64_t *auxv, int max_entries,
                       uint64_t entry, uint64_t phdr,
                       int phent, int phnum) {
    int i = 0;
    
    if (max_entries < 20) return -1;
    
    /* FBSD_AT_PHDR - Program headers */
    auxv[i++] = FBSD_AT_PHDR;
    auxv[i++] = phdr;
    
    /* FBSD_AT_PHENT - Size of program header entry */
    auxv[i++] = FBSD_AT_PHENT;
    auxv[i++] = phent;
    
    /* FBSD_AT_PHNUM - Number of program headers */
    auxv[i++] = FBSD_AT_PHNUM;
    auxv[i++] = phnum;
    
    /* FBSD_AT_PAGESZ - Page size */
    auxv[i++] = FBSD_AT_PAGESZ;
    auxv[i++] = g_freebsd_runtime.pagesize;
    
    /* FBSD_AT_ENTRY - Entry point */
    auxv[i++] = FBSD_AT_ENTRY;
    auxv[i++] = entry;
    
    /* FBSD_AT_BASE - No interpreter */
    auxv[i++] = FBSD_AT_BASE;
    auxv[i++] = 0;
    
    /* FBSD_AT_FLAGS */
    auxv[i++] = FBSD_AT_FLAGS;
    auxv[i++] = 0;
    
    /* FBSD_AT_OSRELDATE - Critical for FreeBSD! */
    auxv[i++] = FBSD_AT_OSRELDATE;
    auxv[i++] = g_freebsd_runtime.osreldate;
    
    /* FBSD_AT_NCPUS */
    auxv[i++] = FBSD_AT_NCPUS;
    auxv[i++] = g_freebsd_runtime.ncpus;
    
    /* FBSD_AT_PAGESIZES */
    auxv[i++] = FBSD_AT_PAGESIZES;
    auxv[i++] = g_freebsd_runtime.pagesize;
    
    /* FBSD_AT_PAGESIZESLEN */
    auxv[i++] = FBSD_AT_PAGESIZESLEN;
    auxv[i++] = 1;
    
    /* FBSD_AT_STACKPROT - Stack protection */
    auxv[i++] = FBSD_AT_STACKPROT;
    auxv[i++] = 7;  /* PROT_READ | PROT_WRITE | PROT_EXEC */
    
    /* FBSD_AT_NULL - Terminator */
    auxv[i++] = FBSD_AT_NULL;
    auxv[i++] = 0;
    
    return i / 2;  /* Return number of entries */
}

/*
 * Rewrite the auxiliary vector on the process stack from Linux to FreeBSD format.
 * 
 * CRITICAL: Linux and FreeBSD use DIFFERENT auxv type numbers!
 * 
 * | Type# | Linux meaning      | FreeBSD meaning    |
 * |-------|--------------------|--------------------|
 * | 15    | AT_PLATFORM        | AT_EXECPATH        |
 * | 16    | AT_HWCAP (CPU!)    | AT_CANARY (ptr!)   |
 * | 17    | AT_CLKTCK          | AT_CANARYLEN       |
 * | 23    | AT_SECURE          | AT_STACKPROT       |
 * | 25    | AT_RANDOM          | AT_HWCAP           |
 * 
 * If we pass Linux's AT_HWCAP=16 with CPU flags like 0x178bfbff,
 * FreeBSD interprets it as AT_CANARY (a pointer!) and crashes!
 * 
 * Additionally, AT_PAGESIZES must be a POINTER to an array of page sizes,
 * not the raw page size value.
 * 
 * Stack layout at process entry:
 *   RSP -> argc
 *          argv[0], argv[1], ..., NULL
 *          envp[0], envp[1], ..., NULL
 *          auxv[0].type, auxv[0].value
 *          auxv[1].type, auxv[1].value
 *          ...
 *          AT_NULL, 0
 */
int freebsd_setup_stack(pid_t pid, uint64_t entry, uint64_t phdr,
                        int phent, int phnum) {
    BSD_TRACE("Setting up FreeBSD stack environment (auxv rewrite)");
    
    /* Get RSP using PTRACE_GETREGS */
    struct user_regs_struct uregs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &uregs) < 0) {
        BSD_ERROR("Failed to get registers: %s", strerror(errno));
        return -1;
    }
    
    uint64_t stack_ptr = uregs.rsp;
    uint64_t argc_ptr = (uregs.rsp % 16 == 8) ? uregs.rsp + 8 : uregs.rsp;
    BSD_TRACE("Stack pointer: 0x%llx", (unsigned long long)stack_ptr);
    
    /* Read argc */
    uint64_t argc;
    if (read_process_mem(pid, &argc, (void *)argc_ptr, sizeof(argc)) < 0) {
        BSD_ERROR("Failed to read argc");
        return -1;
    }
    BSD_TRACE("argc = %llu", (unsigned long long)argc);
    
    /* Skip argc and argv (argc+1 pointers including NULL terminator) */
    uint64_t envp_start = argc_ptr + 8 + (argc + 1) * 8;
    
    /* Scan for end of envp (look for NULL) */
    uint64_t ptr = envp_start;
    uint64_t val;
    int envp_count = 0;
    while (envp_count < 1000) {  /* Safety limit */
        if (read_process_mem(pid, &val, (void *)ptr, sizeof(val)) < 0) {
            BSD_ERROR("Failed to read envp");
            return -1;
        }
        if (val == 0) break;
        ptr += 8;
        envp_count++;
    }
    BSD_TRACE("envp count = %d", envp_count);
    
    /* Now ptr points to NULL terminator of envp, auxv starts after */
    uint64_t auxv_start = ptr + 8;
    BSD_TRACE("auxv starts at 0x%llx", (unsigned long long)auxv_start);
    
    /* Read existing Linux auxv to get values we need */
    uint64_t linux_phdr = 0, linux_entry = 0;
    int linux_phent = 0, linux_phnum = 0;
    uint64_t linux_execfn = 0;  /* AT_EXECFN from Linux (type 31) */
    uint64_t linux_base = 0;    /* AT_BASE from Linux (type 7) - interpreter load address */
    uint64_t linux_random = 0;  /* AT_RANDOM from Linux (type 25) - we'll reuse this location */
    
    ptr = auxv_start;
    int auxv_count = 0;
    while (auxv_count < 100) {  /* Safety limit */
        uint64_t type, value;
        if (read_process_mem(pid, &type, (void *)ptr, sizeof(type)) < 0) break;
        if (read_process_mem(pid, &value, (void *)(ptr + 8), sizeof(value)) < 0) break;
        
        if (type == AT_NULL) {
            auxv_count++;  /* Count the NULL terminator */
            break;
        }
        
        /* 
         * Extract values we need from Linux auxv.
         * NOTE: We use Linux AT_* constants here (from <elf.h>).
         * Types 0-14 are the same between Linux and FreeBSD.
         */
        switch (type) {
            case 3:   linux_phdr = value; break;   /* AT_PHDR - same on both */
            case 4:   linux_phent = (int)value; break;  /* AT_PHENT - same */
            case 5:   linux_phnum = (int)value; break;  /* AT_PHNUM - same */
            case 7:   linux_base = value; break;   /* AT_BASE - interpreter base */
            case 9:   linux_entry = value; break;  /* AT_ENTRY - same */
            case 25:  linux_random = value; break; /* Linux AT_RANDOM - points to 16 bytes in info block */
            case 31:  linux_execfn = value; break; /* Linux AT_EXECFN */
        }
        
        ptr += 16;
        auxv_count++;
    }
    
    /* Calculate maximum bytes we can write (don't exceed Linux auxv size) */
    size_t linux_auxv_bytes = auxv_count * 16;
    BSD_TRACE("Linux auxv: %d entries, %zu bytes", auxv_count, linux_auxv_bytes);
    
    BSD_TRACE("Linux auxv: phdr=0x%llx entry=0x%llx phent=%d phnum=%d execfn=0x%llx",
              (unsigned long long)linux_phdr,
              (unsigned long long)linux_entry,
              linux_phent, linux_phnum,
              (unsigned long long)linux_execfn);
    
    /* Use values from Linux auxv if not provided */
    if (phdr == 0) phdr = linux_phdr;
    if (entry == 0) entry = linux_entry;
    if (phent == 0) phent = linux_phent;
    if (phnum == 0) phnum = linux_phnum;
    
    /*
     * CRITICAL FIX: Place canary and pagesizes in the INFORMATION BLOCK
     * (above auxv), NOT below RSP where the stack will overwrite them!
     * 
     * Stack layout:
     *   High addresses:
     *     Information block (strings, AT_RANDOM data, etc.)  <- PUT DATA HERE
     *     auxv entries
     *     envp pointers
     *     argv pointers
     *     argc                    <- RSP
     *   Low addresses (stack grows down):
     *     function frames...      <- Will overwrite anything below RSP!
     * 
     * We reuse the AT_RANDOM location from Linux (16 bytes) and extend it
     * to hold our canary (64 bytes) + pagesizes (24 bytes).
     * AT_RANDOM is at a high address in the info block, safe from stack growth.
     */
    uint64_t canary_addr = 0;
    uint64_t pagesizes_addr = 0;
    
    if (linux_random != 0) {
        /* 
         * Reuse Linux AT_RANDOM location for our canary.
         * AT_RANDOM points to 16 bytes of random data in the info block.
         * We'll write 64 bytes of canary there, and pagesizes right after.
         * This is safe because:
         *   1. It's in the info block (high addresses, above auxv)
         *   2. Linux AT_RANDOM data isn't needed by FreeBSD binaries
         *   3. The info block isn't touched by stack operations
         *
         * CRITICAL: Align to 8 bytes! FreeBSD reads canary as uint64_t.
         */
        canary_addr = (linux_random + 7) & ~7UL;  /* Round UP to 8-byte boundary */
        pagesizes_addr = canary_addr + 64;  /* After canary */
        BSD_TRACE("Using Linux AT_RANDOM location 0x%llx -> aligned 0x%llx for canary",
                  (unsigned long long)linux_random, (unsigned long long)canary_addr);
    } else {
        /*
         * Fallback: Find space ABOVE auxv end.
         * Calculate auxv end and place data after it.
         */
        uint64_t auxv_end = auxv_start + (auxv_count * 16);
        canary_addr = (auxv_end + 0x100) & ~0xFUL;  /* 256 bytes above auxv, aligned */
        pagesizes_addr = canary_addr + 64;
        BSD_TRACE("Fallback: placing canary at 0x%llx (above auxv)",
                  (unsigned long long)canary_addr);
    }
    
    /* Write canary to process memory */
    if (write_process_mem(pid, g_freebsd_runtime.canary, (void *)canary_addr, 64) < 0) {
        BSD_WARN("Failed to write canary to process memory");
        canary_addr = 0;  /* Don't include in auxv */
    } else {
        /* Print canary value for debugging */
        uint64_t canary_val;
        memcpy(&canary_val, g_freebsd_runtime.canary, sizeof(canary_val));
        BSD_TRACE("Canary written at 0x%llx: value=0x%llx (first 8 bytes)",
                  (unsigned long long)canary_addr, (unsigned long long)canary_val);
        
        /* Read back and verify */
        uint64_t readback = 0;
        if (read_process_mem(pid, &readback, (void *)canary_addr, sizeof(readback)) > 0) {
            if (readback != canary_val) {
                BSD_ERROR("CANARY MISMATCH at AT_CANARY! wrote=0x%llx read=0x%llx",
                          (unsigned long long)canary_val, (unsigned long long)readback);
            } else {
                BSD_TRACE("Canary verified at AT_CANARY location");
            }
        }
    }
    
    /*
     * Write pagesizes array to process memory.
     * FreeBSD supports multiple page sizes: 4KB, 2MB, 1GB on amd64.
     * AT_PAGESIZES points to this array, AT_PAGESIZESLEN is the byte count.
     */
    uint64_t pagesizes_array[3] = {
        0x1000,      /* 4KB - standard page */
        0x200000,    /* 2MB - large page */
        0x40000000   /* 1GB - huge page */
    };
    if (write_process_mem(pid, pagesizes_array, (void *)pagesizes_addr, sizeof(pagesizes_array)) < 0) {
        BSD_WARN("Failed to write pagesizes array");
        pagesizes_addr = 0;
    } else {
        BSD_TRACE("Pagesizes array written at 0x%llx", (unsigned long long)pagesizes_addr);
    }
    
    /* 
     * AT_EXECPATH - Path to the executable.
     * CRITICAL for rtld (dynamic linker) when run directly!
     * We use linux_execfn which points to the executed binary path.
     */
    uint64_t execpath_addr = linux_execfn;  /* Use Linux's AT_EXECFN location */
    
    /* 
     * Build FreeBSD auxv with CORRECT FreeBSD type numbers!
     * 
     * CRITICAL: We must use FBSD_AT_* constants which have FreeBSD's type numbers.
     * DO NOT use Linux AT_* constants for anything above type 14!
     */
    uint64_t fbsd_auxv[80];  /* Max 40 entries */
    int idx = 0;
    int max_entries = linux_auxv_bytes / 16;  /* Each entry is 16 bytes */
    
    BSD_TRACE("Building FreeBSD auxv (max %d entries)", max_entries);
    
    /* Helper macro to add auxv entry if space permits */
#define ADD_AUXV(t, v) do { \
        if ((idx/2) < (max_entries - 1)) { \
            fbsd_auxv[idx++] = (t); \
            fbsd_auxv[idx++] = (v); \
            BSD_TRACE("  auxv[%d]: type=%llu val=0x%llx", (idx/2)-1, \
                      (unsigned long long)(t), (unsigned long long)(v)); \
        } else { \
            BSD_WARN("  auxv FULL - skipping type=%llu", (unsigned long long)(t)); \
        } \
    } while(0)
    
    /*
     * PRIORITIZED auxv entries for 21-entry limit.
     * 
     * We have space for ~20 entries + NULL terminator.
     * Removed less critical entries:
     *   - AT_BASE (7) - always 0 for static binary
     *   - AT_FLAGS (8) - usually 0
     *   - AT_UID/EUID/GID/EGID (11-14) - programs can syscall for these
     *   - AT_EHDRFLAGS (24) - usually 0
     *   - AT_EXECPATH (15) - programs can use other methods
     * 
     * Keeping critical entries for libthr:
     *   - ELF headers: PHDR, PHENT, PHNUM, PAGESZ, ENTRY (5)
     *   - Stack protection: CANARY, CANARYLEN (2)
     *   - FreeBSD identity: OSRELDATE, NCPUS, BSDFLAGS (3)
     *   - Memory: PAGESIZES, PAGESIZESLEN, STACKPROT (3)
     *   - Arguments: ARGC, ARGV, ENVC, ENVV (4)
     *   - Stack bounds: USRSTACKBASE, USRSTACKLIM (2)
     *   Total: 19 entries + NULL = 20
     */
    
    /* Essential ELF info (types 3-9, same on Linux and FreeBSD) */
    ADD_AUXV(FBSD_AT_PHDR, phdr);
    ADD_AUXV(FBSD_AT_PHENT, phent);
    ADD_AUXV(FBSD_AT_PHNUM, phnum);
    ADD_AUXV(FBSD_AT_PAGESZ, g_freebsd_runtime.pagesize);
    ADD_AUXV(FBSD_AT_ENTRY, entry);
    /* AT_BASE - interpreter load address (critical for dynamic binaries!) 
     * When running ld-elf.so.1 directly, linux_base is 0 because there's no
     * separate interpreter. But rtld NEEDS AT_BASE to know where it's loaded.
     * We can derive it from AT_PHDR - the phdr is typically at load_addr + 0x40.
     */
    if (linux_base != 0) {
        ADD_AUXV(FBSD_AT_BASE, linux_base);
    } else if (phdr != 0) {
        /* Running interpreter directly - derive base from phdr */
        uint64_t derived_base = phdr & ~0xFFFULL;  /* Round down to page */
        if ((phdr & 0xFFF) == 0x40) {
            /* Standard ELF layout: phdr at base + 0x40 */
            derived_base = phdr - 0x40;
        }
        BSD_TRACE("Derived AT_BASE=0x%llx from phdr=0x%llx", 
                  (unsigned long long)derived_base, (unsigned long long)phdr);
        ADD_AUXV(FBSD_AT_BASE, derived_base);
    }
    
    /* AT_EXECPATH = 15 - Path to executable (CRITICAL for rtld!) */
    if (execpath_addr != 0) {
        ADD_AUXV(FBSD_AT_EXECPATH, execpath_addr);
    }
    
    /* AT_CANARY = 16 - POINTER to stack canary (CRITICAL for SSP!) */
    if (canary_addr) {
        ADD_AUXV(FBSD_AT_CANARY, canary_addr);
        ADD_AUXV(FBSD_AT_CANARYLEN, 64);
    }
    
    /* AT_OSRELDATE = 18 - Critical for FreeBSD version checks */
    ADD_AUXV(FBSD_AT_OSRELDATE, g_freebsd_runtime.osreldate);
    
    /* AT_NCPUS = 19 - Used by libthr for thread scheduling */
    ADD_AUXV(FBSD_AT_NCPUS, g_freebsd_runtime.ncpus);
    
    /* AT_PAGESIZES = 20 - POINTER to array of page sizes */
    if (pagesizes_addr) {
        ADD_AUXV(FBSD_AT_PAGESIZES, pagesizes_addr);
        ADD_AUXV(FBSD_AT_PAGESIZESLEN, 24);  /* 3 * 8 bytes */
    }
    
    /* AT_STACKPROT = 23 - Initial stack protection */
    ADD_AUXV(FBSD_AT_STACKPROT, 3);  /* PROT_READ | PROT_WRITE (no exec) */
    
    /* AT_BSDFLAGS = 27 - Indicates FreeBSD binary */
    ADD_AUXV(FBSD_AT_BSDFLAGS, 1);
    
    /* AT_ARGC = 28, AT_ARGV = 29 - CRITICAL for libthr initialization */
    ADD_AUXV(FBSD_AT_ARGC, argc);
    ADD_AUXV(FBSD_AT_ARGV, stack_ptr + 8);  /* argv starts right after argc */
    
    /* AT_ENVC = 30, AT_ENVV = 31 - Environment access */
    ADD_AUXV(FBSD_AT_ENVC, envp_count);
    ADD_AUXV(FBSD_AT_ENVV, envp_start);
    
    /* AT_USRSTACKBASE = 35, AT_USRSTACKLIM = 36 - Stack bounds checking */
    ADD_AUXV(FBSD_AT_USRSTACKBASE, stack_ptr + 0x1000);
    ADD_AUXV(FBSD_AT_USRSTACKLIM, 0x20000000);  /* 512MB stack limit */
    
#undef ADD_AUXV
    
    /* Always add terminator */
    fbsd_auxv[idx++] = FBSD_AT_NULL;
    fbsd_auxv[idx++] = 0;
    
    /* Write FreeBSD auxv to process stack - DON'T exceed Linux auxv size! */
    size_t auxv_size = idx * sizeof(uint64_t);
    if (auxv_size > linux_auxv_bytes) {
        BSD_WARN("FreeBSD auxv (%zu bytes) exceeds Linux auxv (%zu bytes) - truncating",
                 auxv_size, linux_auxv_bytes);
        auxv_size = linux_auxv_bytes;
    }
    BSD_TRACE("Writing %zu bytes of FreeBSD auxv at 0x%llx", 
              auxv_size, (unsigned long long)auxv_start);
    
    if (write_process_mem(pid, fbsd_auxv, (void *)auxv_start, auxv_size) < 0) {
        BSD_ERROR("Failed to write FreeBSD auxv to process");
        return -1;
    }
    
    BSD_INFO("FreeBSD auxv installed: osreldate=%d, ncpus=%d, canary=0x%llx, pagesizes=0x%llx",
             g_freebsd_runtime.osreldate,
             g_freebsd_runtime.ncpus,
             (unsigned long long)canary_addr,
             (unsigned long long)pagesizes_addr);
    
    return 0;
}
