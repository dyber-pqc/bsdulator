/*
 * BSDulator - FreeBSD Runtime Emulation
 * Provides FreeBSD-compatible environment for binaries
 */

#ifndef FREEBSD_RUNTIME_H
#define FREEBSD_RUNTIME_H

#include <stdint.h>
#include <sys/types.h>

/*
 * FreeBSD Auxiliary Vector Types
 * From FreeBSD sys/elf_common.h
 * Prefixed with FBSD_ to avoid conflicts with Linux elf.h
 */
#define FBSD_AT_NULL         0   /* Terminates the vector */
#define FBSD_AT_IGNORE       1   /* Ignored entry */
#define FBSD_AT_EXECFD       2   /* File descriptor of program */
#define FBSD_AT_PHDR         3   /* Program headers for program */
#define FBSD_AT_PHENT        4   /* Size of program header entry */
#define FBSD_AT_PHNUM        5   /* Number of program headers */
#define FBSD_AT_PAGESZ       6   /* System page size */
#define FBSD_AT_BASE         7   /* Base address of interpreter */
#define FBSD_AT_FLAGS        8   /* Flags */
#define FBSD_AT_ENTRY        9   /* Entry point of program */
#define FBSD_AT_NOTELF       10  /* Program is not ELF */
#define FBSD_AT_UID          11  /* Real uid */
#define FBSD_AT_EUID         12  /* Effective uid */
#define FBSD_AT_GID          13  /* Real gid */
#define FBSD_AT_EGID         14  /* Effective gid */
#define FBSD_AT_EXECPATH     15  /* Path to the executable */
#define FBSD_AT_CANARY       16  /* Canary for SSP */
#define FBSD_AT_CANARYLEN    17  /* Length of the canary */
#define FBSD_AT_OSRELDATE    18  /* OSRELDATE */
#define FBSD_AT_NCPUS        19  /* Number of CPUs */
#define FBSD_AT_PAGESIZES    20  /* Pagesizes */
#define FBSD_AT_PAGESIZESLEN 21  /* Number of pagesizes */
#define FBSD_AT_TIMEKEEP     22  /* Pointer to timehands */
#define FBSD_AT_STACKPROT    23  /* Initial stack protection */
#define FBSD_AT_EHDRFLAGS    24  /* e_flags from ELF header */
#define FBSD_AT_HWCAP        25  /* CPU feature flags */
#define FBSD_AT_HWCAP2       26  /* CPU feature flags 2 */
#define FBSD_AT_BSDFLAGS     27  /* ELF BSD flags */
#define FBSD_AT_ARGC         28  /* Argument count */
#define FBSD_AT_ARGV         29  /* Argument vector */
#define FBSD_AT_ENVC         30  /* Environment count */
#define FBSD_AT_ENVV         31  /* Environment vector */
#define FBSD_AT_PS_STRINGS   32  /* struct ps_strings */
#define FBSD_AT_FXRNG        33  /* Pointer to root RNG seed version */
#define FBSD_AT_KPRELOAD     34  /* Base of vdso */
#define FBSD_AT_USRSTACKBASE 35  /* Top of user stack */
#define FBSD_AT_USRSTACKLIM  36  /* Stacksize limit */

/* FreeBSD OS release dates */
#define FREEBSD_OSRELDATE_14_0  1400097
#define FREEBSD_OSRELDATE_15_0  1500023

/* Default values */
#define FREEBSD_DEFAULT_OSRELDATE   FREEBSD_OSRELDATE_15_0
#define FREEBSD_DEFAULT_PAGESIZE    4096
#define FREEBSD_DEFAULT_NCPUS       4

/*
 * FreeBSD sysctl MIB identifiers
 * From FreeBSD sys/sysctl.h
 */
#define CTL_SYSCTL      0   /* Sysctl internal operations */
#define CTL_KERN        1   /* Kernel */
#define CTL_HW          6   /* Hardware */

/* CTL_SYSCTL operations (mib[1] when mib[0]=0) */
#define CTL_SYSCTL_NAME2OID     3   /* Convert name to OID */
#define CTL_SYSCTL_OIDFMT       4   /* Get OID format */

/* Security sysctl (for jail parameters) */
#define CTL_SECURITY    14  /* Security */
#define SECURITY_JAIL   1   /* security.jail */

/* kern.* */
#define KERN_OSTYPE         1   /* string: system type */
#define KERN_OSRELEASE      2   /* string: release version */
#define KERN_OSREV          3   /* int: system revision */
#define KERN_VERSION        4   /* string: compile version */
#define KERN_HOSTNAME       10  /* string: hostname */
#define KERN_OSRELDATE      24  /* int: OS release date */
#define KERN_PROC           14  /* Process info */
#define KERN_ARND           37  /* Random data */
#define KERN_USRSTACK       33  /* User stack address */

/* hw.* */
#define HW_MACHINE      1   /* string: machine type */
#define HW_MODEL        2   /* string: model */
#define HW_NCPU         3   /* int: number of cpus */
#define HW_PAGESIZE     7   /* int: page size */
#define HW_MACHINE_ARCH 11  /* string: machine architecture */

/* net.* - CTL_NET = 4 */
#define CTL_NET         4   /* Network */

/* net.route.* */
#define NET_RT_DUMP     1   /* Dump routing table entries */
#define NET_RT_FLAGS    2   /* by flags */
#define NET_RT_IFLIST   3   /* Survey interface list */
#define NET_RT_IFMALIST 4   /* Multicast address list */
#define NET_RT_IFLISTL  5   /* Survey interface list (extended) */

/* Address families used with NET_RT_IFLIST */
#define NET_RT_AF_UNSPEC  0
#define NET_RT_AF_INET    2
#define NET_RT_AF_INET6   28
#define NET_RT_AF_LINK    18

/*
 * FreeBSD runtime state
 */
typedef struct {
    /* Emulated OS information */
    int osreldate;
    char ostype[32];
    char osrelease[32];
    char version[256];
    char machine[32];
    char machine_arch[32];
    
    /* Hardware info */
    int ncpus;
    int pagesize;
    
    /* Process info */
    uint64_t usrstack;
    char execpath[1024];
    
    /* Stack canary (FreeBSD uses 64 bytes) */
    uint8_t canary[64];
    
    /* Initialized flag */
    int initialized;
} freebsd_runtime_t;

/* Global runtime state */
extern freebsd_runtime_t g_freebsd_runtime;

/*
 * Initialize FreeBSD runtime
 */
int freebsd_runtime_init(void);

/*
 * Set executable path for runtime
 */
void freebsd_runtime_set_execpath(const char *path);

/*
 * Handle FreeBSD sysctl syscall
 * Returns: result to return to process, or -1 if not handled
 */
long freebsd_sysctl_emulate(pid_t pid, const int *name, unsigned int namelen,
                            void *oldp, size_t *oldlenp,
                            const void *newp, size_t newlen);

/*
 * Handle FreeBSD __sysctl syscall (syscall 202)
 * Wrapper that extracts arguments from process memory
 */
long freebsd_handle_sysctl(pid_t pid, uint64_t args[6]);

/*
 * Handle FreeBSD sysctlbyname syscall (syscall 570)
 */
long freebsd_handle_sysctlbyname(pid_t pid, uint64_t args[6]);

/*
 * Rewrite process stack to include FreeBSD auxv
 * Called after execve, before first instruction
 */
int freebsd_setup_stack(pid_t pid, uint64_t entry, uint64_t phdr,
                        int phent, int phnum);

/*
 * Get the FreeBSD auxv that should be on the stack
 */
int freebsd_build_auxv(uint64_t *auxv, int max_entries,
                       uint64_t entry, uint64_t phdr,
                       int phent, int phnum);

#endif /* FREEBSD_RUNTIME_H */
