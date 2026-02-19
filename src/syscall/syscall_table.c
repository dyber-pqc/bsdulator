/*
 * BSDulator - Syscall Translation Table
 * Maps FreeBSD syscall numbers to Linux equivalents
 * 
 * This table is based on FreeBSD 14.x and Linux 6.x syscall tables.
 * Some syscalls have direct mappings, others require emulation.
 */

/* _GNU_SOURCE must be defined FIRST, before any includes */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <fcntl.h>  /* For open, O_PATH, O_NOFOLLOW */
#include <sys/uio.h>
#include <sys/vfs.h>  /* For struct statfs */
#include <sys/ioctl.h>  /* For ioctl */
#include <termios.h>  /* For struct termios */
#include <time.h>
#include <sys/epoll.h>  /* For kqueue emulation */
#include <asm/prctl.h>  /* For ARCH_SET_FS, etc. */
#include "bsdulator.h"
#include "../runtime/freebsd_runtime.h"

/* Forward declarations for emulation handlers */
static long emul_getdtablesize(pid_t pid, uint64_t args[6]);
static long emul_sysctl(pid_t pid, uint64_t args[6]);
static long emul_syscall(pid_t pid, uint64_t args[6]);
static long emul_sysctlbyname(pid_t pid, uint64_t args[6]);
/* Jail syscalls are now implemented in src/jail/jail.c
 * Declarations are in include/bsdulator/jail.h
 */
static long emul_kqueue(pid_t pid, uint64_t args[6]);
static long emul_kevent(pid_t pid, uint64_t args[6]);
static long emul_issetugid(pid_t pid, uint64_t args[6]);
static long emul_yield(pid_t pid, uint64_t args[6]);
static long emul_rfork(pid_t pid, uint64_t args[6]);
static long emul_cap_enter(pid_t pid, uint64_t args[6]);
static long emul_cap_getmode(pid_t pid, uint64_t args[6]);
static long emul_cap_rights_limit(pid_t pid, uint64_t args[6]);
static long emul_cap_ioctls_limit(pid_t pid, uint64_t args[6]);
static long emul_cap_fcntls_limit(pid_t pid, uint64_t args[6]);
static long emul_seteuid(pid_t pid, uint64_t args[6]);
static long emul_setegid(pid_t pid, uint64_t args[6]);
static long emul_mkfifo(pid_t pid, uint64_t args[6]);
static long emul_thr_self(pid_t pid, uint64_t args[6]);
static long emul_thr_exit(pid_t pid, uint64_t args[6]);
static long emul_thr_kill(pid_t pid, uint64_t args[6]);
static long emul_thr_wake(pid_t pid, uint64_t args[6]);
static long emul_clock_gettime(pid_t pid, uint64_t args[6]);
static long emul_sigprocmask(pid_t pid, uint64_t args[6]);
static long emul_sigaction(pid_t pid, uint64_t args[6]);
static long emul_sigfastblock(pid_t pid, uint64_t args[6]);
static long emul_cpuset_getaffinity(pid_t pid, uint64_t args[6]);
static long emul_minherit(pid_t pid, uint64_t args[6]);
static long emul_rtprio_thread(pid_t pid, uint64_t args[6]);
static long emul_umtx_op(pid_t pid, uint64_t args[6]);
static long emul_getcontext(pid_t pid, uint64_t args[6]);
static long emul_sysarch(pid_t pid, uint64_t args[6]);
static long emul_pathconf(pid_t pid, uint64_t args[6]);
static long emul_fpathconf(pid_t pid, uint64_t args[6]);
static long emul_lpathconf(pid_t pid, uint64_t args[6]);
static long emul_fstatfs(pid_t pid, uint64_t args[6]);
static long emul_ioctl(pid_t pid, uint64_t args[6]);

/* Maximum FreeBSD syscall number */
#define MAX_SYSCALL 600

/* 
 * Syscall translation table
 * Format: { freebsd_nr, linux_nr, "name", type, handler, needs_arg_xlat, needs_ret_xlat }
 */
static syscall_entry_t syscall_table[MAX_SYSCALL];

/* Table initialization flag */
static int table_initialized = 0;

/* Helper to add an entry */
static void add_entry(int fbsd_nr, int linux_nr, const char *name, 
                      syscall_result_t type, syscall_handler_t handler) {
    if (fbsd_nr >= 0 && fbsd_nr < MAX_SYSCALL) {
        syscall_table[fbsd_nr].freebsd_nr = fbsd_nr;
        syscall_table[fbsd_nr].linux_nr = linux_nr;
        syscall_table[fbsd_nr].name = name;
        syscall_table[fbsd_nr].type = type;
        syscall_table[fbsd_nr].handler = handler;
        syscall_table[fbsd_nr].needs_arg_xlat = 0;
        syscall_table[fbsd_nr].needs_ret_xlat = 0;
    }
}

/* Shorthand macros */
#define TRANS(f, l, n)    add_entry(f, l, n, SYSCALL_TRANSLATED, NULL)
#define PASS(f, l, n)     add_entry(f, l, n, SYSCALL_PASSTHROUGH, NULL)
#define EMUL(f, n, h)     add_entry(f, -1, n, SYSCALL_EMULATED, h)
#define UNSUP(f, n)       add_entry(f, -1, n, SYSCALL_UNSUPPORTED, NULL)

int syscall_init(void) {
    if (table_initialized) {
        return 0;
    }
    
    BSD_TRACE("Initializing syscall translation table");
    
    /* Initialize FreeBSD runtime */
    freebsd_runtime_init();
    
    /* Clear table */
    memset(syscall_table, 0, sizeof(syscall_table));
    
    /* Mark all as unsupported initially */
    for (int i = 0; i < MAX_SYSCALL; i++) {
        syscall_table[i].freebsd_nr = i;
        syscall_table[i].linux_nr = -1;
        syscall_table[i].type = SYSCALL_UNSUPPORTED;
    }
    
    /*
     * Process control syscalls
     */
    EMUL(FBSD_SYS_syscall, "syscall", emul_syscall);
    TRANS(FBSD_SYS_exit, SYS_exit, "exit");
    TRANS(FBSD_SYS_fork, SYS_fork, "fork");
    TRANS(FBSD_SYS_vfork, SYS_vfork, "vfork");
    TRANS(FBSD_SYS_execve, SYS_execve, "execve");
    TRANS(FBSD_SYS_wait4, SYS_wait4, "wait4");
    TRANS(FBSD_SYS_kill, SYS_kill, "kill");
    TRANS(FBSD_SYS_getpid, SYS_getpid, "getpid");
    TRANS(FBSD_SYS_getppid, SYS_getppid, "getppid");
    TRANS(FBSD_SYS_getpgrp, SYS_getpgrp, "getpgrp");
    TRANS(FBSD_SYS_setpgid, SYS_setpgid, "setpgid");
    TRANS(FBSD_SYS_setsid, SYS_setsid, "setsid");
    TRANS(FBSD_SYS_getsid, SYS_getsid, "getsid");
    TRANS(FBSD_SYS_getpgid, SYS_getpgid, "getpgid");
    
    /*
     * File I/O syscalls
     */
    TRANS(FBSD_SYS_read, SYS_read, "read");
    TRANS(FBSD_SYS_write, SYS_write, "write");
    TRANS(FBSD_SYS_open, SYS_open, "open");
    TRANS(FBSD_SYS_close, SYS_close, "close");
    TRANS(FBSD_SYS_link, SYS_link, "link");
    TRANS(FBSD_SYS_unlink, SYS_unlink, "unlink");
    TRANS(FBSD_SYS_chdir, SYS_chdir, "chdir");
    TRANS(FBSD_SYS_fchdir, SYS_fchdir, "fchdir");
    TRANS(FBSD_SYS_chmod, SYS_chmod, "chmod");
    TRANS(FBSD_SYS_chown, SYS_chown, "chown");
    TRANS(FBSD_SYS_lchown, SYS_lchown, "lchown");
    TRANS(FBSD_SYS_fchown, SYS_fchown, "fchown");
    TRANS(FBSD_SYS_fchmod, SYS_fchmod, "fchmod");
    TRANS(FBSD_SYS_access, SYS_access, "access");
    TRANS(FBSD_SYS_symlink, SYS_symlink, "symlink");
    TRANS(FBSD_SYS_readlink, SYS_readlink, "readlink");
    TRANS(FBSD_SYS_umask, SYS_umask, "umask");
    TRANS(FBSD_SYS_chroot, SYS_chroot, "chroot");
    TRANS(FBSD_SYS_rename, SYS_rename, "rename");
    TRANS(FBSD_SYS_mkdir, SYS_mkdir, "mkdir");
    TRANS(FBSD_SYS_rmdir, SYS_rmdir, "rmdir");
    /* mkfifo needs emulation - uses mknod on Linux */
    EMUL(FBSD_SYS_mkfifo, "mkfifo", emul_mkfifo);
    TRANS(FBSD_SYS_dup, SYS_dup, "dup");
    TRANS(FBSD_SYS_dup2, SYS_dup2, "dup2");
    TRANS(FBSD_SYS_fcntl, SYS_fcntl, "fcntl");
    TRANS(FBSD_SYS_flock, SYS_flock, "flock");
    TRANS(FBSD_SYS_fsync, SYS_fsync, "fsync");
    TRANS(FBSD_SYS_fdatasync, SYS_fdatasync, "fdatasync");
    TRANS(FBSD_SYS_sync, SYS_sync, "sync");
    TRANS(FBSD_SYS_readv, SYS_readv, "readv");
    TRANS(FBSD_SYS_writev, SYS_writev, "writev");
    TRANS(FBSD_SYS_pread, SYS_pread64, "pread");
    TRANS(FBSD_SYS_pwrite, SYS_pwrite64, "pwrite");
    TRANS(FBSD_SYS_preadv, SYS_preadv, "preadv");
    TRANS(FBSD_SYS_pwritev, SYS_pwritev, "pwritev");
    TRANS(FBSD_SYS_lseek, SYS_lseek, "lseek");
    TRANS(FBSD_SYS_truncate, SYS_truncate, "truncate");
    TRANS(FBSD_SYS_ftruncate, SYS_ftruncate, "ftruncate");
    EMUL(FBSD_SYS_ioctl, "ioctl", emul_ioctl);
    TRANS(FBSD_SYS_select, SYS_select, "select");
    TRANS(FBSD_SYS_pselect, SYS_pselect6, "pselect");
    TRANS(FBSD_SYS_poll, SYS_poll, "poll");
    TRANS(FBSD_SYS_ppoll, SYS_ppoll, "ppoll");
    
    /* *at syscalls */
    TRANS(FBSD_SYS_openat, SYS_openat, "openat");
    TRANS(FBSD_SYS_faccessat, SYS_faccessat, "faccessat");
    TRANS(FBSD_SYS_fchmodat, SYS_fchmodat, "fchmodat");
    TRANS(FBSD_SYS_fchownat, SYS_fchownat, "fchownat");
    TRANS(FBSD_SYS_linkat, SYS_linkat, "linkat");
    TRANS(FBSD_SYS_mkdirat, SYS_mkdirat, "mkdirat");
    TRANS(FBSD_SYS_mknodat, SYS_mknodat, "mknodat");
    TRANS(FBSD_SYS_readlinkat, SYS_readlinkat, "readlinkat");
    TRANS(FBSD_SYS_renameat, SYS_renameat, "renameat");
    TRANS(FBSD_SYS_symlinkat, SYS_symlinkat, "symlinkat");
    TRANS(FBSD_SYS_unlinkat, SYS_unlinkat, "unlinkat");
    TRANS(FBSD_SYS_futimesat, SYS_futimesat, "futimesat");
    TRANS(FBSD_SYS_utimensat, SYS_utimensat, "utimensat");
    
    /* stat family */
    TRANS(FBSD_SYS_fstat, SYS_fstat, "fstat");
    TRANS(FBSD_SYS_fstatat, SYS_newfstatat, "fstatat");
    TRANS(FBSD_SYS_statfs, SYS_statfs, "statfs");
    /* Skip fstatfs - return success with minimal data */
    /* TRANS(FBSD_SYS_fstatfs, SYS_fstatfs, "fstatfs"); */
    EMUL(FBSD_SYS_fstatfs, "fstatfs", emul_fstatfs);
    TRANS(FBSD_SYS_getdirentries, SYS_getdents64, "getdirentries");
    
    /*
     * User/group ID syscalls
     */
    TRANS(FBSD_SYS_getuid, SYS_getuid, "getuid");
    TRANS(FBSD_SYS_geteuid, SYS_geteuid, "geteuid");
    TRANS(FBSD_SYS_getgid, SYS_getgid, "getgid");
    TRANS(FBSD_SYS_getegid, SYS_getegid, "getegid");
    TRANS(FBSD_SYS_setuid, SYS_setuid, "setuid");
    TRANS(FBSD_SYS_setgid, SYS_setgid, "setgid");
    /* seteuid/setegid need emulation via setresuid/setresgid */
    EMUL(FBSD_SYS_seteuid, "seteuid", emul_seteuid);
    EMUL(FBSD_SYS_setegid, "setegid", emul_setegid);
    TRANS(FBSD_SYS_setreuid, SYS_setreuid, "setreuid");
    TRANS(FBSD_SYS_setregid, SYS_setregid, "setregid");
    TRANS(FBSD_SYS_setresuid, SYS_setresuid, "setresuid");
    TRANS(FBSD_SYS_setresgid, SYS_setresgid, "setresgid");
    TRANS(FBSD_SYS_getresuid, SYS_getresuid, "getresuid");
    TRANS(FBSD_SYS_getresgid, SYS_getresgid, "getresgid");
    TRANS(FBSD_SYS_getgroups, SYS_getgroups, "getgroups");
    TRANS(FBSD_SYS_setgroups, SYS_setgroups, "setgroups");
    
    /*
     * Memory management syscalls
     */
    TRANS(FBSD_SYS_mmap, SYS_mmap, "mmap");
    TRANS(FBSD_SYS_munmap, SYS_munmap, "munmap");
    TRANS(FBSD_SYS_mprotect, SYS_mprotect, "mprotect");
    TRANS(FBSD_SYS_madvise, SYS_madvise, "madvise");
    TRANS(FBSD_SYS_msync, SYS_msync, "msync");
    TRANS(FBSD_SYS_mlock, SYS_mlock, "mlock");
    TRANS(FBSD_SYS_munlock, SYS_munlock, "munlock");
    TRANS(FBSD_SYS_mlockall, SYS_mlockall, "mlockall");
    TRANS(FBSD_SYS_munlockall, SYS_munlockall, "munlockall");
    TRANS(FBSD_SYS_mincore, SYS_mincore, "mincore");
    TRANS(FBSD_SYS_break, SYS_brk, "break");
    
    /*
     * Socket/Network syscalls
     */
    TRANS(FBSD_SYS_socket, SYS_socket, "socket");
    TRANS(FBSD_SYS_bind, SYS_bind, "bind");
    TRANS(FBSD_SYS_listen, SYS_listen, "listen");
    TRANS(FBSD_SYS_accept, SYS_accept, "accept");
    TRANS(FBSD_SYS_accept4, SYS_accept4, "accept4");
    TRANS(FBSD_SYS_connect, SYS_connect, "connect");
    TRANS(FBSD_SYS_shutdown, SYS_shutdown, "shutdown");
    TRANS(FBSD_SYS_socketpair, SYS_socketpair, "socketpair");
    TRANS(FBSD_SYS_sendto, SYS_sendto, "sendto");
    TRANS(FBSD_SYS_recvfrom, SYS_recvfrom, "recvfrom");
    TRANS(FBSD_SYS_sendmsg, SYS_sendmsg, "sendmsg");
    TRANS(FBSD_SYS_recvmsg, SYS_recvmsg, "recvmsg");
    TRANS(FBSD_SYS_getsockopt, SYS_getsockopt, "getsockopt");
    TRANS(FBSD_SYS_setsockopt, SYS_setsockopt, "setsockopt");
    TRANS(FBSD_SYS_getsockname, SYS_getsockname, "getsockname");
    TRANS(FBSD_SYS_getpeername, SYS_getpeername, "getpeername");
    TRANS(FBSD_SYS_sendfile, SYS_sendfile, "sendfile");
    
    /*
     * Time syscalls - clock_gettime needs clock ID translation
     */
    TRANS(FBSD_SYS_gettimeofday, SYS_gettimeofday, "gettimeofday");
    TRANS(FBSD_SYS_settimeofday, SYS_settimeofday, "settimeofday");
    EMUL(FBSD_SYS_clock_gettime, "clock_gettime", emul_clock_gettime);
    TRANS(FBSD_SYS_clock_settime, SYS_clock_settime, "clock_settime");
    TRANS(FBSD_SYS_clock_getres, SYS_clock_getres, "clock_getres");
    TRANS(FBSD_SYS_clock_nanosleep, SYS_clock_nanosleep, "clock_nanosleep");
    TRANS(FBSD_SYS_nanosleep, SYS_nanosleep, "nanosleep");
    TRANS(FBSD_SYS_getitimer, SYS_getitimer, "getitimer");
    TRANS(FBSD_SYS_setitimer, SYS_setitimer, "setitimer");
    TRANS(FBSD_SYS_utimes, SYS_utimes, "utimes");
    TRANS(FBSD_SYS_futimes, SYS_futimesat, "futimes");
    TRANS(FBSD_SYS_futimens, SYS_utimensat, "futimens");
    
    /* Timer syscalls */
    TRANS(FBSD_SYS_ktimer_create, SYS_timer_create, "timer_create");
    TRANS(FBSD_SYS_ktimer_delete, SYS_timer_delete, "timer_delete");
    TRANS(FBSD_SYS_ktimer_settime, SYS_timer_settime, "timer_settime");
    TRANS(FBSD_SYS_ktimer_gettime, SYS_timer_gettime, "timer_gettime");
    TRANS(FBSD_SYS_ktimer_getoverrun, SYS_timer_getoverrun, "timer_getoverrun");
    TRANS(FBSD_SYS_timerfd_create, SYS_timerfd_create, "timerfd_create");
    TRANS(FBSD_SYS_timerfd_gettime, SYS_timerfd_gettime, "timerfd_gettime");
    TRANS(FBSD_SYS_timerfd_settime, SYS_timerfd_settime, "timerfd_settime");
    
    /*
     * Signal syscalls - need emulation due to different sigset_t sizes
     * FreeBSD sigset_t = 16 bytes (128 signals)
     * Linux sigset_t = 8 bytes (64 signals)
     */
    EMUL(FBSD_SYS_sigaction, "sigaction", emul_sigaction);
    EMUL(FBSD_SYS_sigprocmask, "sigprocmask", emul_sigprocmask);
    TRANS(FBSD_SYS_sigpending, SYS_rt_sigpending, "sigpending");
    TRANS(FBSD_SYS_sigsuspend, SYS_rt_sigsuspend, "sigsuspend");
    TRANS(FBSD_SYS_sigaltstack, SYS_sigaltstack, "sigaltstack");
    TRANS(FBSD_SYS_sigwait, SYS_rt_sigtimedwait, "sigwait");
    TRANS(FBSD_SYS_sigtimedwait, SYS_rt_sigtimedwait, "sigtimedwait");
    TRANS(FBSD_SYS_sigwaitinfo, SYS_rt_sigtimedwait, "sigwaitinfo");
    TRANS(FBSD_SYS_sigqueue, SYS_rt_sigqueueinfo, "sigqueue");
    EMUL(FBSD_SYS_sigfastblock, "sigfastblock", emul_sigfastblock);
    
    /*
     * Resource limit syscalls
     */
    TRANS(FBSD_SYS_getrlimit, SYS_getrlimit, "getrlimit");
    TRANS(FBSD_SYS_setrlimit, SYS_setrlimit, "setrlimit");
    TRANS(FBSD_SYS_getrusage, SYS_getrusage, "getrusage");
    TRANS(FBSD_SYS_setpriority, SYS_setpriority, "setpriority");
    TRANS(FBSD_SYS_getpriority, SYS_getpriority, "getpriority");
    
    /*
     * Scheduler syscalls
     */
    TRANS(FBSD_SYS_sched_setparam, SYS_sched_setparam, "sched_setparam");
    TRANS(FBSD_SYS_sched_getparam, SYS_sched_getparam, "sched_getparam");
    TRANS(FBSD_SYS_sched_setscheduler, SYS_sched_setscheduler, "sched_setscheduler");
    TRANS(FBSD_SYS_sched_getscheduler, SYS_sched_getscheduler, "sched_getscheduler");
    TRANS(FBSD_SYS_sched_yield, SYS_sched_yield, "sched_yield");
    TRANS(FBSD_SYS_sched_get_priority_max, SYS_sched_get_priority_max, "sched_get_priority_max");
    TRANS(FBSD_SYS_sched_get_priority_min, SYS_sched_get_priority_min, "sched_get_priority_min");
    TRANS(FBSD_SYS_sched_rr_get_interval, SYS_sched_rr_get_interval, "sched_rr_get_interval");
    TRANS(FBSD_SYS_sched_getcpu, SYS_getcpu, "sched_getcpu");
    
    /*
     * IPC syscalls
     */
    TRANS(FBSD_SYS_semget, SYS_semget, "semget");
    TRANS(FBSD_SYS_semop, SYS_semop, "semop");
    TRANS(FBSD_SYS___semctl, SYS_semctl, "semctl");
    TRANS(FBSD_SYS_msgget, SYS_msgget, "msgget");
    TRANS(FBSD_SYS_msgsnd, SYS_msgsnd, "msgsnd");
    TRANS(FBSD_SYS_msgrcv, SYS_msgrcv, "msgrcv");
    TRANS(FBSD_SYS_msgctl, SYS_msgctl, "msgctl");
    TRANS(FBSD_SYS_shmget, SYS_shmget, "shmget");
    TRANS(FBSD_SYS_shmat, SYS_shmat, "shmat");
    TRANS(FBSD_SYS_shmdt, SYS_shmdt, "shmdt");
    TRANS(FBSD_SYS_shmctl, SYS_shmctl, "shmctl");
    
    /*
     * Pipe syscalls
     */
    TRANS(FBSD_SYS_pipe2, SYS_pipe2, "pipe2");
    
    /*
     * Threading syscalls - needed for libthr
     */
    EMUL(FBSD_SYS_thr_self, "thr_self", emul_thr_self);
    EMUL(FBSD_SYS_thr_exit, "thr_exit", emul_thr_exit);
    EMUL(FBSD_SYS_thr_kill, "thr_kill", emul_thr_kill);
    EMUL(FBSD_SYS_thr_wake, "thr_wake", emul_thr_wake);
    EMUL(FBSD_SYS_rtprio_thread, "rtprio_thread", emul_rtprio_thread);
    EMUL(FBSD_SYS__umtx_op, "_umtx_op", emul_umtx_op);
    
    /*
     * CPU affinity - FreeBSD syscall 487
     */
    EMUL(FBSD_SYS_cpuset_getaffinity, "cpuset_getaffinity", emul_cpuset_getaffinity);
    
    /*
     * Memory inheritance - FreeBSD syscall 250
     */
    EMUL(FBSD_SYS_minherit, "minherit", emul_minherit);
    
    /*
     * Context syscalls
     */
    EMUL(FBSD_SYS_getcontext, "getcontext", emul_getcontext);
    
    /*
     * Misc syscalls
     */
    TRANS(FBSD_SYS___getcwd, SYS_getcwd, "__getcwd");
    TRANS(FBSD_SYS_acct, SYS_acct, "acct");
    TRANS(FBSD_SYS_mount, SYS_mount, "mount");
    TRANS(FBSD_SYS_unmount, SYS_umount2, "unmount");
    TRANS(FBSD_SYS_swapon, SYS_swapon, "swapon");
    TRANS(FBSD_SYS_swapoff, SYS_swapoff, "swapoff");
    TRANS(FBSD_SYS_reboot, SYS_reboot, "reboot");
    TRANS(FBSD_SYS_quotactl, SYS_quotactl, "quotactl");
    TRANS(FBSD_SYS_ptrace, SYS_ptrace, "ptrace");
    TRANS(FBSD_SYS_getrandom, SYS_getrandom, "getrandom");
    TRANS(FBSD_SYS_copy_file_range, SYS_copy_file_range, "copy_file_range");
    TRANS(FBSD_SYS_close_range, SYS_close_range, "close_range");
    TRANS(FBSD_SYS_membarrier, SYS_membarrier, "membarrier");
    TRANS(FBSD_SYS_kcmp, SYS_kcmp, "kcmp");
    TRANS(FBSD_SYS_posix_fallocate, SYS_fallocate, "posix_fallocate");
    TRANS(FBSD_SYS_posix_fadvise, SYS_fadvise64, "posix_fadvise");
    
    /*
     * Emulated syscalls - FreeBSD specific
     */
    EMUL(FBSD_SYS_getdtablesize, "getdtablesize", emul_getdtablesize);
    EMUL(FBSD_SYS___sysctl, "__sysctl", emul_sysctl);
    EMUL(FBSD_SYS___sysctlbyname, "__sysctlbyname", emul_sysctlbyname);
    EMUL(FBSD_SYS_issetugid, "issetugid", emul_issetugid);
    EMUL(FBSD_SYS_yield, "yield", emul_yield);
    EMUL(FBSD_SYS_rfork, "rfork", emul_rfork);
    
    /* Jail syscalls - core of Jailhouse */
    EMUL(FBSD_SYS_jail, "jail", emul_jail);
    EMUL(FBSD_SYS_jail_attach, "jail_attach", emul_jail_attach);
    EMUL(FBSD_SYS_jail_get, "jail_get", emul_jail_get);
    EMUL(FBSD_SYS_jail_set, "jail_set", emul_jail_set);
    EMUL(FBSD_SYS_jail_remove, "jail_remove", emul_jail_remove);
    
    /* kqueue - needs epoll translation */
    EMUL(FBSD_SYS_kqueue, "kqueue", emul_kqueue);
    EMUL(FBSD_SYS_kevent, "kevent", emul_kevent);
    
    /* Capsicum */
    EMUL(FBSD_SYS_cap_enter, "cap_enter", emul_cap_enter);
    EMUL(FBSD_SYS_cap_getmode, "cap_getmode", emul_cap_getmode);
    EMUL(FBSD_SYS_cap_rights_limit, "cap_rights_limit", emul_cap_rights_limit);
    EMUL(FBSD_SYS_cap_ioctls_limit, "cap_ioctls_limit", emul_cap_ioctls_limit);
    EMUL(FBSD_SYS_cap_fcntls_limit, "cap_fcntls_limit", emul_cap_fcntls_limit);
    
    /* Unsupported FreeBSD-specific syscalls */
    UNSUP(FBSD_SYS_chflags, "chflags");
    UNSUP(FBSD_SYS_fchflags, "fchflags");
    UNSUP(FBSD_SYS_lchflags, "lchflags");
    UNSUP(FBSD_SYS_revoke, "revoke");
    UNSUP(FBSD_SYS_ktrace, "ktrace");
    UNSUP(FBSD_SYS_getlogin, "getlogin");
    UNSUP(FBSD_SYS_setlogin, "setlogin");
    UNSUP(FBSD_SYS_profil, "profil");
    EMUL(FBSD_SYS_sysarch, "sysarch", emul_sysarch);
    UNSUP(FBSD_SYS_rtprio, "rtprio");
    UNSUP(FBSD_SYS_ntp_adjtime, "ntp_adjtime");
    UNSUP(FBSD_SYS_ntp_gettime, "ntp_gettime");
    UNSUP(FBSD_SYS_undelete, "undelete");
    EMUL(FBSD_SYS_pathconf, "pathconf", emul_pathconf);
    EMUL(FBSD_SYS_fpathconf, "fpathconf", emul_fpathconf);
    EMUL(FBSD_SYS_lpathconf, "lpathconf", emul_lpathconf);
    
    table_initialized = 1;
    BSD_INFO("Syscall table initialized with %d entries", MAX_SYSCALL);
    
    return 0;
}

syscall_result_t syscall_translate(int freebsd_nr, int *linux_nr) {
    if (freebsd_nr < 0 || freebsd_nr >= MAX_SYSCALL) {
        *linux_nr = -1;
        return SYSCALL_UNSUPPORTED;
    }
    
    *linux_nr = syscall_table[freebsd_nr].linux_nr;
    return syscall_table[freebsd_nr].type;
}

const syscall_entry_t *syscall_get_entry(int freebsd_nr) {
    if (freebsd_nr < 0 || freebsd_nr >= MAX_SYSCALL) {
        return NULL;
    }
    return &syscall_table[freebsd_nr];
}

const char *syscall_name(int freebsd_nr) {
    if (freebsd_nr < 0 || freebsd_nr >= MAX_SYSCALL) {
        return "unknown";
    }
    const char *name = syscall_table[freebsd_nr].name;
    return name ? name : "unknown";
}

int syscall_translate_args(int freebsd_nr, uint64_t *args) {
    /* 
     * Some syscalls need argument translation
     * Return 1 if args were modified, 0 otherwise
     */
    switch (freebsd_nr) {
        case FBSD_SYS_open:
            /* open(path, flags, mode) - flags at args[1] */
            args[1] = abi_translate_open_flags(args[1]);
            return 1;
        case FBSD_SYS_openat:
            /* openat(dirfd, path, flags, mode) - flags at args[2] */
            args[2] = abi_translate_open_flags(args[2]);
            return 1;
            
        case FBSD_SYS_mmap:
            /* Translate mmap flags and prot */
            args[2] = abi_translate_mmap_prot(args[2]);
            args[3] = abi_translate_mmap_flags(args[3]);
            if ((int)args[4] == -1 && !(args[3] & 0x20)) {
                args[3] |= 0x20;
            }
            return 1;
            
        case FBSD_SYS_kill:
        case FBSD_SYS_sigaction:
        case FBSD_SYS_sigprocmask:
            /* Translate signal number */
            args[0] = abi_translate_signal(args[0]);
            return 1;
            
        case FBSD_SYS_fcntl:
            /* Translate fcntl command */
            BSD_WARN("fcntl: fd=%d cmd=%lu (0x%lx)", (int)args[0], args[1], args[1]);
            args[1] = abi_translate_fcntl_cmd(args[1]);
            return 1;
            
        case FBSD_SYS_fstatat:
        case FBSD_SYS_faccessat:
        case FBSD_SYS_fchmodat:
        case FBSD_SYS_fchownat:
        case FBSD_SYS_unlinkat:
            /* Translate AT_ flags (arg[3] for most *at syscalls) */
            args[3] = abi_translate_at_flags(args[3]);
            return 1;
        default:
            return 0;
    }
}

long syscall_translate_return(int freebsd_nr, long retval) {
    (void)freebsd_nr;  /* Currently unused, but reserved for future use */
    
    /* 
     * Some syscalls need return value translation
     * Particularly error codes
     */
    if (retval < 0 && retval > -4096) {
        /* This is an error - translate errno */
        return -abi_translate_errno(-retval);
    }
    return retval;
}

long syscall_execute(pid_t pid, int freebsd_nr, uint64_t args[6]) {
    const syscall_entry_t *entry = syscall_get_entry(freebsd_nr);
    
    if (!entry) {
        return -ENOSYS;
    }
    
    if (entry->type == SYSCALL_EMULATED && entry->handler) {
        return entry->handler(pid, args);
    }
    
    return -ENOSYS;
}

/*
 * Emulation handlers
 */

static long emul_getdtablesize(pid_t pid, uint64_t args[6]) {
    (void)pid;
    (void)args;
    
    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
        return -errno;
    }
    return (long)rlim.rlim_cur;
}

static long emul_syscall(pid_t pid, uint64_t args[6]) {
    /* FreeBSD indirect syscall - arg0 is real syscall number, others shift */
    int real_syscall = (int)args[0];

    BSD_WARN("indirect syscall: real syscall = %d", real_syscall);

    /* Look up the real syscall */
    const syscall_entry_t *entry = syscall_get_entry(real_syscall);
    if (!entry || entry->type == SYSCALL_UNSUPPORTED) {
        BSD_WARN("indirect syscall %d unsupported", real_syscall);
        return -ENOSYS;
    }

    /*
     * For fork/vfork/clone, we can't execute from BSDulator's context.
     * Instead, rewrite the child's registers to execute the real syscall.
     */
    if (real_syscall == FBSD_SYS_fork || real_syscall == FBSD_SYS_vfork ||
        entry->linux_nr == SYS_fork || entry->linux_nr == SYS_vfork || 
        entry->linux_nr == SYS_clone) {
        
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
            BSD_ERROR("indirect syscall: failed to get regs");
            return -ENOSYS;
        }

        /* Change syscall number from 0 (indirect) to the real Linux syscall */
        regs.orig_rax = entry->linux_nr;
        regs.rax = entry->linux_nr;
        
        /* Shift arguments: arg1->arg0, arg2->arg1, etc. */
        regs.rdi = args[1];
        regs.rsi = args[2];
        regs.rdx = args[3];
        regs.r10 = args[4];
        regs.r8 = args[5];
        regs.r9 = 0;

        if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
            BSD_ERROR("indirect syscall: failed to set regs");
            return -ENOSYS;
        }

        BSD_WARN("indirect syscall: rewrote syscall 0 -> %d (Linux %d) for fork/vfork",
                 real_syscall, entry->linux_nr);
        
        /* Return special value to indicate "don't skip, let it execute" */
        return -EAGAIN;  /* Special: means "execute normally" */
    }

    /* For other translated syscalls, execute directly (they don't fork) */
    if (entry->type == SYSCALL_TRANSLATED || entry->type == SYSCALL_PASSTHROUGH) {
        uint64_t shifted_args[6] = { args[1], args[2], args[3], args[4], args[5], 0 };
        return syscall(entry->linux_nr, shifted_args[0], shifted_args[1],
                       shifted_args[2], shifted_args[3], shifted_args[4], shifted_args[5]);
    }

    /* For emulated syscalls, call handler with shifted args */
    if (entry->type == SYSCALL_EMULATED && entry->handler) {
        uint64_t shifted_args[6] = { args[1], args[2], args[3], args[4], args[5], 0 };
        return entry->handler(pid, shifted_args);
    }

    return -ENOSYS;
}

static long emul_sysctl(pid_t pid, uint64_t args[6]) {
    /*
     * FreeBSD __sysctl(2) emulation using our runtime
     */
    BSD_TRACE("Emulating __sysctl syscall");
    return freebsd_handle_sysctl(pid, args);
}

static long emul_sysctlbyname(pid_t pid, uint64_t args[6]) {
    /*
     * FreeBSD sysctlbyname(3) emulation (syscall 570)
     */
    BSD_TRACE("Emulating __sysctlbyname syscall");
    return freebsd_handle_sysctlbyname(pid, args);
}

static long emul_issetugid(pid_t pid, uint64_t args[6]) {
    (void)pid;
    (void)args;
    
    /* Check if running setuid/setgid */
    return (getuid() != geteuid() || getgid() != getegid()) ? 1 : 0;
}

static long emul_yield(pid_t pid, uint64_t args[6]) {
    (void)pid;
    (void)args;
    
    return sched_yield();
}

static long emul_rfork(pid_t pid, uint64_t args[6]) {
    (void)pid;
    (void)args;
    
    /*
     * rfork is similar to Linux clone()
     * TODO: Implement proper flag translation
     */
    BSD_WARN("rfork not implemented, using fork()");
    return fork();
}

static long emul_seteuid(pid_t pid, uint64_t args[6]) {
    (void)pid;
    
    /* seteuid(euid) -> setresuid(-1, euid, -1) */
    uid_t euid = (uid_t)args[0];
    return syscall(SYS_setresuid, -1, euid, -1);
}

static long emul_setegid(pid_t pid, uint64_t args[6]) {
    (void)pid;
    
    /* setegid(egid) -> setresgid(-1, egid, -1) */
    gid_t egid = (gid_t)args[0];
    return syscall(SYS_setresgid, -1, egid, -1);
}

static long emul_mkfifo(pid_t pid, uint64_t args[6]) {
    (void)pid;
    
    /* mkfifo(path, mode) -> mknod(path, mode | S_IFIFO, 0) */
    const char *path = (const char *)args[0];
    mode_t mode = (mode_t)args[1];
    return syscall(SYS_mknod, path, mode | 0010000 /* S_IFIFO */, 0);
}

/*
 * Threading syscall emulation
 * FIXED: thr_self writes to a pointer in CHILD's memory!
 */

static long emul_thr_self(pid_t pid, uint64_t args[6]) {
    /*
     * FreeBSD: int thr_self(long *id)
     * Stores thread ID at the pointer, returns 0 on success
     * FIXED: For a single-threaded process, the TID equals the PID.
     * We use the child's PID, not our (BSDulator's) TID!
     */
    uint64_t id_addr = args[0];  /* Pointer in CHILD's memory */
    
    /* For single-threaded process, TID == PID */
    long tid = (long)pid;
    
    BSD_TRACE("thr_self: writing tid=%ld (child pid) to addr=0x%lx", tid, id_addr);
    
    if (id_addr != 0) {
        /* Write thread ID to CHILD's memory */
        struct iovec local_iov = { &tid, sizeof(tid) };
        struct iovec remote_iov = { (void *)id_addr, sizeof(tid) };
        
        ssize_t written = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
        if (written < 0) {
            /* Fallback to ptrace */
            if (ptrace(PTRACE_POKEDATA, pid, id_addr, tid) < 0) {
                return -errno;
            }
        }
    }
    
    return 0;  /* Success */
}

static long emul_thr_exit(pid_t pid, uint64_t args[6]) {
    (void)pid;
    
    /* Thread exit - translate to exit_group or exit */
    long *state = (long *)args[0];
    (void)state;  /* FreeBSD writes exit state here */
    
    /* Just exit the thread */
    return syscall(SYS_exit, 0);
}

/*
 * thr_wake - wake a thread
 * FreeBSD: int thr_wake(long id)
 * Returns 0 on success, or ESRCH if thread not found
 */
static long emul_thr_wake(pid_t pid, uint64_t args[6]) {
    (void)pid;
    
    long tid = (long)args[0];
    
    BSD_TRACE("thr_wake: tid=%ld", tid);
    
    /* Special case: -1 means wake any waiting thread */
    if (tid == -1) {
        /* This is normal - just return ESRCH like FreeBSD does */
        return -ESRCH;
    }
    
    /* For single-threaded apps, this is a no-op */
    /* A full implementation would use futex to wake the thread */
    return 0;
}

/*
 * rtprio_thread - get/set thread realtime priority
 * FreeBSD: int rtprio_thread(int function, lwpid_t lwpid, struct rtprio *rtp)
 */
static long emul_rtprio_thread(pid_t pid, uint64_t args[6]) {
    (void)pid;
    
    int function = (int)args[0];
    /* lwpid_t lwpid = (lwpid_t)args[1]; */
    /* struct rtprio *rtp = (struct rtprio *)args[2]; */
    
    BSD_TRACE("rtprio_thread: function=%d (stub)", function);
    
    /* 
     * RTP_LOOKUP = 0, RTP_SET = 1
     * For now, just return success - thread priority is not critical for basic operation
     */
    return 0;
}

/*
 * _umtx_op - userspace mutex operations
 * This is critical for threading but complex to implement
 */
static long emul_umtx_op(pid_t pid, uint64_t args[6]) {
    (void)pid;
    
    /* void *obj = (void *)args[0]; */
    int op = (int)args[1];
    /* unsigned long val = args[2]; */
    /* void *uaddr = (void *)args[3]; */
    /* void *uaddr2 = (void *)args[4]; */
    
    BSD_TRACE("_umtx_op: op=%d (stub)", op);
    
    /*
     * FreeBSD umtx operations:
     * UMTX_OP_WAKE = 3 - wake threads waiting on address
     * For basic single-threaded operation, we can stub this
     */
    
    /* Return success for wake operations */
    if (op == 3) {  /* UMTX_OP_WAKE */
        return 0;
    }
    
    /* For other operations, return success but warn */
    return 0;
}

/*
 * Jail syscall emulation - implemented in src/jail/jail.c
 * These are critical for the Jailhouse.io project!
 */

/*
 * kqueue emulation using epoll
 * 
 * kqueue() creates an event notification queue, similar to Linux epoll.
 * We create an epoll instance and return its fd.
 */

static long emul_kqueue(pid_t pid, uint64_t args[6]) {
    (void)pid;
    (void)args;
    
    /*
     * Create an epoll instance to back the kqueue.
     * epoll_create1(0) is equivalent to kqueue() for basic usage.
     */
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        BSD_WARN("kqueue(): epoll_create1 failed: %s", strerror(errno));
        return -errno;
    }
    
    BSD_INFO("kqueue(): created epoll fd %d as kqueue", epfd);
    return epfd;
}

/*
 * kevent emulation - this is more complex as kevent has different semantics
 * than epoll_ctl/epoll_wait. For now, provide a stub that allows basic usage.
 */
static long emul_kevent(pid_t pid, uint64_t args[6]) {
    (void)pid;
    int kq = (int)args[0];
    /* const struct kevent *changelist = (void *)args[1]; */
    int nchanges = (int)args[2];
    /* struct kevent *eventlist = (void *)args[3]; */
    int nevents = (int)args[4];
    /* const struct timespec *timeout = (void *)args[5]; */
    
    BSD_TRACE("kevent(): kq=%d nchanges=%d nevents=%d", kq, nchanges, nevents);
    
    /*
     * For jail utility's basic usage, kevent is used to wait for child processes.
     * Return 0 (no events) to let the utility fall back to other mechanisms
     * or continue without event notification.
     */
    if (nevents > 0) {
        /* Waiting for events - return 0 (timeout/no events) */
        return 0;
    }
    
    /* Registering changes - return success */
    return 0;
}

/*
 * Capsicum emulation (security framework)
 */

static int in_capability_mode = 0;

static long emul_cap_enter(pid_t pid, uint64_t args[6]) {
    (void)pid;
    (void)args;
    BSD_TRACE("cap_enter() - returning ENOSYS (Capsicum not supported)");
    /* Return ENOSYS so caph_enter() treats it as "not supported" */
    return -ENOSYS;
}

static long emul_cap_getmode(pid_t pid, uint64_t args[6]) {
    (void)pid;
    (void)args;
    BSD_TRACE("cap_getmode() - returning %d", in_capability_mode);
    return in_capability_mode;
}
/*
 * cap_rights_limit - limit capability rights on a file descriptor
 * FreeBSD: int cap_rights_limit(int fd, const cap_rights_t *rights)
 */
static long emul_cap_rights_limit(pid_t pid, uint64_t args[6]) {
    (void)pid;
    
    int fd = (int)args[0];
    /* const cap_rights_t *rights = (const cap_rights_t *)args[1]; */
    
    BSD_TRACE("cap_rights_limit: fd=%d returning ENOSYS", fd);
    
    /* Just return success - we don't actually limit anything */
    return -ENOSYS;
}

/*
 * cap_ioctls_limit - limit ioctls on a file descriptor
 * FreeBSD: int cap_ioctls_limit(int fd, const unsigned long *cmds, size_t ncmds)
 */
static long emul_cap_ioctls_limit(pid_t pid, uint64_t args[6]) {
    (void)pid;
    
    int fd = (int)args[0];
    /* const unsigned long *cmds = (const unsigned long *)args[1]; */
    /* size_t ncmds = (size_t)args[2]; */
    
    BSD_TRACE("cap_ioctls_limit: fd=%d returning ENOSYS", fd);
    
    return -ENOSYS;
}

/*
 * cap_fcntls_limit - limit fcntl commands on a file descriptor
 * FreeBSD: int cap_fcntls_limit(int fd, uint32_t fcntlrights)
 */
static long emul_cap_fcntls_limit(pid_t pid, uint64_t args[6]) {
    (void)pid;
    
    int fd = (int)args[0];
    /* uint32_t fcntlrights = (uint32_t)args[1]; */
    
    BSD_TRACE("cap_fcntls_limit: fd=%d returning ENOSYS", fd);
    
    return -ENOSYS;
}

/*
 * thr_kill - send signal to a specific thread
 * FIXED: Use child's pid, not BSDulator's getpid()!
 */
static long emul_thr_kill(pid_t pid, uint64_t args[6]) {
    /* thr_kill(long id, int sig) -> tgkill(tgid, tid, sig) */
    long tid = (long)args[0];
    int sig = (int)args[1];
    
    BSD_TRACE("thr_kill: child_pid=%d tid=%ld sig=%d", pid, tid, sig);
    
    /* Translate signal number */
    sig = abi_translate_signal(sig);
    
    /* Use tgkill - send signal to specific thread in the CHILD process */
    return syscall(SYS_tgkill, pid, tid, sig);
}

/*
 * clock_gettime - translate FreeBSD clock IDs to Linux
 * FIXED: The result must be written to the CHILD's memory, not ours!
 */
static long emul_clock_gettime(pid_t pid, uint64_t args[6]) {
    int fbsd_clockid = (int)args[0];
    uint64_t tp_addr = args[1];  /* Address in CHILD's memory */
    int linux_clockid;
    
    /* Translate FreeBSD clock ID to Linux */
    switch (fbsd_clockid) {
        case 0:  /* CLOCK_REALTIME */
            linux_clockid = 0;
            break;
        case 4:  /* FreeBSD CLOCK_MONOTONIC */
            linux_clockid = 1;
            break;
        case 5:  /* FreeBSD CLOCK_UPTIME */
        case 7:  /* FreeBSD CLOCK_UPTIME_PRECISE */
        case 8:  /* FreeBSD CLOCK_UPTIME_FAST */
            linux_clockid = 7;  /* Linux CLOCK_BOOTTIME */
            break;
        case 9:  /* FreeBSD CLOCK_REALTIME_PRECISE */
            linux_clockid = 0;
            break;
        case 10: /* FreeBSD CLOCK_REALTIME_FAST */
        case 13: /* FreeBSD CLOCK_SECOND */
            linux_clockid = 5;  /* Linux CLOCK_REALTIME_COARSE */
            break;
        case 11: /* FreeBSD CLOCK_MONOTONIC_PRECISE */
            linux_clockid = 1;
            break;
        case 12: /* FreeBSD CLOCK_MONOTONIC_FAST */
            linux_clockid = 6;  /* Linux CLOCK_MONOTONIC_COARSE */
            break;
        case 14: /* FreeBSD CLOCK_THREAD_CPUTIME_ID */
            linux_clockid = 3;
            break;
        case 15: /* FreeBSD CLOCK_PROCESS_CPUTIME_ID */
            linux_clockid = 2;
            break;
        default:
            linux_clockid = 0;
            break;
    }
    
    BSD_TRACE("clock_gettime: FreeBSD clock %d -> Linux clock %d", fbsd_clockid, linux_clockid);
    
    /* Get time in OUR process */
    struct timespec ts;
    long ret = clock_gettime(linux_clockid, &ts);
    
    if (ret == 0 && tp_addr != 0) {
        /* Write the result to the CHILD's memory */
        struct iovec local_iov = { &ts, sizeof(ts) };
        struct iovec remote_iov = { (void *)tp_addr, sizeof(ts) };
        
        ssize_t written = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
        if (written < 0) {
            /* Fallback to ptrace if process_vm_writev fails */
            ptrace(PTRACE_POKEDATA, pid, tp_addr, ts.tv_sec);
            ptrace(PTRACE_POKEDATA, pid, tp_addr + 8, ts.tv_nsec);
        }
    }
    
    return ret;
}

/*
 * sigprocmask - FreeBSD uses 16-byte sigset_t, Linux uses 8-byte
 * FIXED: Must read/write from CHILD's memory!
 * FIXED: Translate 'how' parameter (FreeBSD uses 1/2/3, Linux uses 0/1/2)
 */
static long emul_sigprocmask(pid_t pid, uint64_t args[6]) {
    int fbsd_how = (int)args[0];
    uint64_t set_addr = args[1];     /* Pointer in CHILD's memory */
    uint64_t oldset_addr = args[2];  /* Pointer in CHILD's memory */
    
    /*
     * Translate 'how' parameter:
     * FreeBSD: SIG_BLOCK=1, SIG_UNBLOCK=2, SIG_SETMASK=3
     * Linux:   SIG_BLOCK=0, SIG_UNBLOCK=1, SIG_SETMASK=2
     */
    int linux_how;
    if (fbsd_how >= 1 && fbsd_how <= 3) {
        linux_how = fbsd_how - 1;
    } else {
        BSD_ERROR("sigprocmask: invalid how=%d", fbsd_how);
        return -EINVAL;
    }
    
    BSD_TRACE("sigprocmask: fbsd_how=%d -> linux_how=%d set=0x%lx oldset=0x%lx", 
              fbsd_how, linux_how, set_addr, oldset_addr);
    
    /* FreeBSD sigset_t is 16 bytes (128 bits), Linux is 8 bytes (64 bits) */
    uint64_t fbsd_set[2] = {0, 0};
    uint64_t linux_set = 0;
    uint64_t linux_oldset = 0;
    
    /* Read set from child's memory if provided */
    if (set_addr != 0) {
        struct iovec local_iov = { fbsd_set, sizeof(fbsd_set) };
        struct iovec remote_iov = { (void *)set_addr, sizeof(fbsd_set) };
        
        ssize_t nread = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
        if (nread < 0) {
            /* Fallback to ptrace */
            fbsd_set[0] = ptrace(PTRACE_PEEKDATA, pid, set_addr, NULL);
            fbsd_set[1] = ptrace(PTRACE_PEEKDATA, pid, set_addr + 8, NULL);
        }
        linux_set = fbsd_set[0];  /* Use first 64 bits */
    }
    
    /* Call Linux sigprocmask with TRANSLATED how value */
    long ret = syscall(SYS_rt_sigprocmask, linux_how, 
                       set_addr ? &linux_set : NULL, 
                       oldset_addr ? &linux_oldset : NULL, 
                       sizeof(linux_set));
    
    /* Write oldset to child's memory if requested */
    if (ret == 0 && oldset_addr != 0) {
        uint64_t fbsd_oldset[2] = { linux_oldset, 0 };
        
        struct iovec local_iov = { fbsd_oldset, sizeof(fbsd_oldset) };
        struct iovec remote_iov = { (void *)oldset_addr, sizeof(fbsd_oldset) };
        
        ssize_t written = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
        if (written < 0) {
            /* Fallback to ptrace */
            ptrace(PTRACE_POKEDATA, pid, oldset_addr, fbsd_oldset[0]);
            ptrace(PTRACE_POKEDATA, pid, oldset_addr + 8, fbsd_oldset[1]);
        }
    }
    
    return ret;
}

/*
 * sigaction - FreeBSD struct sigaction differs from Linux
 */
static long emul_sigaction(pid_t pid, uint64_t args[6]) {
    int sig = (int)args[0];
    uint64_t act_addr = args[1];     /* FreeBSD sigaction in child's memory */
    uint64_t oldact_addr = args[2];  /* FreeBSD sigaction in child's memory */
    
    /* Translate signal number */
    /* SIGTHR (32) is FreeBSD threading signal - stub it */
    if (sig == 32) {
        BSD_TRACE("sigaction: SIGTHR stubbed");
        return 0;
    }
    /* SIGINFO (29) has no Linux equivalent - stub it */
    if (sig == 29) {
        BSD_TRACE("sigaction: SIGINFO stubbed (no Linux equivalent)");
        return 0;
    }
    /* SIGEMT (7) has no Linux equivalent - stub it */
    if (sig == 7) {
        BSD_TRACE("sigaction: SIGEMT stubbed (no Linux equivalent)");
        return 0;
    }
    
    int linux_sig = abi_translate_signal(sig);
    BSD_TRACE("sigaction: sig=%d -> linux_sig=%d", sig, linux_sig);
    
    /*
     * FreeBSD and Linux sigaction structures are different:
     * FreeBSD: { handler(8), flags(4), mask(16) } = 28 bytes
     * Linux:   { handler(8), flags(8), restorer(8), mask(128) } = 152 bytes
     * 
     * We need to translate between them properly.
     */
    
    struct {
        uint64_t sa_handler;
        uint64_t sa_flags;
        void (*sa_restorer)(void);
        uint64_t sa_mask[16];  /* 128 bytes for 1024 signals */
    } linux_act, linux_oldact;
    
    memset(&linux_act, 0, sizeof(linux_act));
    memset(&linux_oldact, 0, sizeof(linux_oldact));
    
    if (act_addr) {
        /* Read FreeBSD sigaction from child memory */
        uint8_t fbsd_act[32];
        struct iovec local = { fbsd_act, sizeof(fbsd_act) };
        struct iovec remote = { (void *)act_addr, sizeof(fbsd_act) };
        if (process_vm_readv(pid, &local, 1, &remote, 1, 0) > 0) {
            /* FreeBSD layout: handler(8) + flags(4) + mask(16) */
            memcpy(&linux_act.sa_handler, fbsd_act, 8);
            uint32_t fbsd_flags;
            memcpy(&fbsd_flags, fbsd_act + 8, 4);
            linux_act.sa_flags = fbsd_flags;  /* Flags are mostly compatible */
            /* Copy first 16 bytes of mask (128 signals) */
            memcpy(&linux_act.sa_mask, fbsd_act + 12, 16);
            BSD_TRACE("sigaction: read fbsd act: handler=0x%lx flags=0x%x",
                      linux_act.sa_handler, fbsd_flags);
        } else {
            BSD_WARN("sigaction: failed to read act from child");
        }
    }
    
    long ret = syscall(SYS_rt_sigaction, linux_sig, 
                       act_addr ? &linux_act : NULL,
                       oldact_addr ? &linux_oldact : NULL,
                       8);  /* Linux expects 8 bytes (64 signals) for sigset size */
    
    BSD_TRACE("sigaction: rt_sigaction returned %ld", ret);
    
    if (ret == 0 && oldact_addr) {
        /* Write back FreeBSD sigaction to child memory */
        uint8_t fbsd_oldact[32];
        memset(fbsd_oldact, 0, sizeof(fbsd_oldact));
        memcpy(fbsd_oldact, &linux_oldact.sa_handler, 8);
        uint32_t fbsd_flags = (uint32_t)linux_oldact.sa_flags;
        memcpy(fbsd_oldact + 8, &fbsd_flags, 4);
        memcpy(fbsd_oldact + 12, &linux_oldact.sa_mask, 16);
        
        struct iovec local = { fbsd_oldact, sizeof(fbsd_oldact) };
        struct iovec remote = { (void *)oldact_addr, sizeof(fbsd_oldact) };
        process_vm_writev(pid, &local, 1, &remote, 1, 0);
    }
    
    return ret;
}

/*
 * sigfastblock - fast signal blocking for userspace threading
 * FreeBSD: int sigfastblock(int cmd, void *ptr)
 */
static long emul_sigfastblock(pid_t pid, uint64_t args[6]) {
    (void)pid;
    
    int cmd = (int)args[0];
    /* void *ptr = (void *)args[1]; */
    
    BSD_TRACE("sigfastblock: cmd=%d (stub)", cmd);
    
    /*
     * This is used by libthr for fast signal blocking without syscalls.
     * We can't really implement this on Linux, but returning success
     * should allow single-threaded programs to work.
     */
    return 0;
}

/*
 * getcontext - get user context
 * FreeBSD: int getcontext(ucontext_t *ucp)
 */
static long emul_getcontext(pid_t pid, uint64_t args[6]) {
    (void)pid;
    
    uint64_t ucp_addr = args[0];
    
    BSD_TRACE("getcontext: ucp=0x%lx (stub)", ucp_addr);
    
    /*
     * getcontext saves the current context for later use with setcontext.
     * This is complex to implement properly as it needs to save all registers.
     * For now, just return success - this is used for setjmp/longjmp style code
     * which may still work if not actually used.
     */
    return 0;
}

/*
 * cpuset_getaffinity - get CPU affinity
 * FIXED: Must write to CHILD's memory!
 */
static long emul_cpuset_getaffinity(pid_t pid, uint64_t args[6]) {
    /* FreeBSD cpuset_getaffinity(cpulevel_t level, cpuwhich_t which, 
     *                            id_t id, size_t setsize, cpuset_t *mask)
     */
    /* int level = (int)args[0]; */
    /* int which = (int)args[1]; */
    /* id_t id = (id_t)args[2]; */
    size_t setsize = (size_t)args[3];
    uint64_t mask_addr = args[4];  /* Pointer in CHILD's memory */
    
    BSD_TRACE("cpuset_getaffinity: setsize=%zu mask=0x%lx", setsize, mask_addr);
    
    if (mask_addr != 0 && setsize >= sizeof(uint64_t)) {
        /* Set all CPUs as available (up to 64) */
        uint64_t mask = 0xFFFFFFFFFFFFFFFFULL;
        
        /* Write to CHILD's memory */
        struct iovec local_iov = { &mask, sizeof(mask) };
        struct iovec remote_iov = { (void *)mask_addr, sizeof(mask) };
        
        ssize_t written = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
        if (written < 0) {
            /* Fallback to ptrace */
            ptrace(PTRACE_POKEDATA, pid, mask_addr, mask);
        }
        
        /* If setsize > 8, zero out the rest */
        if (setsize > sizeof(uint64_t)) {
            uint64_t zero = 0;
            for (size_t i = sizeof(uint64_t); i < setsize; i += sizeof(uint64_t)) {
                struct iovec local_z = { &zero, sizeof(zero) };
                struct iovec remote_z = { (void *)(mask_addr + i), sizeof(zero) };
                process_vm_writev(pid, &local_z, 1, &remote_z, 1, 0);
            }
        }
    }
    
    return 0;
}

/*
 * minherit - set memory inheritance for mmap regions
 */
static long emul_minherit(pid_t pid, uint64_t args[6]) {
    (void)pid;
    (void)args;
    
    /* minherit(void *addr, size_t len, int inherit)
     * 
     * Linux doesn't have a direct equivalent.
     * For now, return success as this is typically used for
     * fork optimization which we can ignore.
     */
    BSD_TRACE("minherit: returning success (stub)");
    return 0;
}

/*
 * sysarch - architecture-specific system call
 * FreeBSD: int sysarch(int op, void *parms)
 * Used for TLS setup (AMD64_SET_FSBASE, etc.)
 */

/* FreeBSD AMD64 sysarch operations */
#define AMD64_GET_FSBASE    128
#define AMD64_SET_FSBASE    129
#define AMD64_GET_GSBASE    130
#define AMD64_SET_GSBASE    131

static long emul_sysarch(pid_t pid, uint64_t args[6]) {
    int op = (int)args[0];
    uint64_t parms_addr = args[1];  /* Pointer to parameter in CHILD's memory */
    
    BSD_TRACE("sysarch: op=%d parms=0x%lx", op, parms_addr);
    
    switch (op) {
        case AMD64_SET_FSBASE: {
            /* Read the base address from child's memory */
            uint64_t base = 0;
            struct iovec local_iov = { &base, sizeof(base) };
            struct iovec remote_iov = { (void *)parms_addr, sizeof(base) };
            
            ssize_t nread = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
            if (nread < 0) {
                /* Fallback to ptrace */
                base = ptrace(PTRACE_PEEKDATA, pid, parms_addr, NULL);
            }
            
            BSD_TRACE("sysarch: AMD64_SET_FSBASE base=0x%lx", base);
            
            /* Actually set FS base using PTRACE_ARCH_PRCTL */
            errno = 0;
            long ret = ptrace(PTRACE_ARCH_PRCTL, pid, (void*)base, (void*)(long)ARCH_SET_FS);
            if (ret < 0 && errno != 0) {
                BSD_ERROR("sysarch: PTRACE_ARCH_PRCTL failed: %s", strerror(errno));
                /* Try alternative: modify fs_base in registers */
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == 0) {
                    regs.fs_base = base;
                    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
                    BSD_TRACE("sysarch: Set fs_base via SETREGS");
                }
            } else {
                BSD_TRACE("sysarch: FS base set successfully via ARCH_PRCTL");
            }
            
            return 0;
        }
        
        case AMD64_GET_FSBASE: {
            /* Get current FS base from registers */
            struct user_regs_struct regs;
            uint64_t base = 0;
            
            if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == 0) {
                base = regs.fs_base;
            }
            
            /* Write to child's memory */
            struct iovec local_iov = { &base, sizeof(base) };
            struct iovec remote_iov = { (void *)parms_addr, sizeof(base) };
            
            process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
            
            BSD_TRACE("sysarch: AMD64_GET_FSBASE returning 0x%lx", base);
            return 0;
        }
        
        case AMD64_SET_GSBASE: {
            uint64_t base = 0;
            struct iovec local_iov = { &base, sizeof(base) };
            struct iovec remote_iov = { (void *)parms_addr, sizeof(base) };
            process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
            
            BSD_TRACE("sysarch: AMD64_SET_GSBASE base=0x%lx (stub)", base);
            return 0;
        }
        
        case AMD64_GET_GSBASE: {
            uint64_t base = 0;
            struct iovec local_iov = { &base, sizeof(base) };
            struct iovec remote_iov = { (void *)parms_addr, sizeof(base) };
            process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
            
            BSD_TRACE("sysarch: AMD64_GET_GSBASE returning 0");
            return 0;
        case 132: /* AMD64_GET_XFPUSTATE */
            BSD_TRACE("sysarch: AMD64_GET_XFPUSTATE (stub)");
            return 0;
        }
            
        default:
            BSD_WARN("sysarch: unknown op %d", op);
            return -EINVAL;
    }
}

/*
 * pathconf/fpathconf/lpathconf - query filesystem limits
 * FreeBSD: long pathconf(const char *path, int name)
 * FreeBSD: long fpathconf(int fd, int name)
 * FreeBSD: long lpathconf(const char *path, int name)
 */

/* FreeBSD pathconf names - map to Linux equivalents */
static int translate_pathconf_name(int fbsd_name) {
    switch (fbsd_name) {
        case 1:  return _PC_LINK_MAX;
        case 2:  return _PC_MAX_CANON;
        case 3:  return _PC_MAX_INPUT;
        case 4:  return _PC_NAME_MAX;
        case 5:  return _PC_PATH_MAX;
        case 6:  return _PC_PIPE_BUF;
        case 7:  return _PC_CHOWN_RESTRICTED;
        case 8:  return _PC_NO_TRUNC;
        case 9:  return _PC_VDISABLE;
        case 14: return _PC_FILESIZEBITS;
        case 15: return _PC_SYMLINK_MAX;
        default: return fbsd_name;  /* Try direct mapping */
    }
}

static long emul_pathconf(pid_t pid, uint64_t args[6]) {
    uint64_t path_addr = args[0];
    int name = (int)args[1];
    
    /* Read path from child's memory */
    char path[1024];
    size_t i;
    for (i = 0; i < sizeof(path) - 1; i++) {
        long word = ptrace(PTRACE_PEEKDATA, pid, path_addr + i, NULL);
        path[i] = (char)(word & 0xFF);
        if (path[i] == '\0') break;
    }
    path[sizeof(path) - 1] = '\0';
    
    int linux_name = translate_pathconf_name(name);
    BSD_TRACE("pathconf: path=%s name=%d->%d", path, name, linux_name);
    
    long ret = pathconf(path, linux_name);
    if (ret < 0) return -errno;
    return ret;
}

static long emul_fpathconf(pid_t pid, uint64_t args[6]) {
    int fd = (int)args[0];
    int name = (int)args[1];
    
    /* We can't use the child's fd directly - need to use /proc/pid/fd/N */
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/fd/%d", pid, fd);
    
    int linux_name = translate_pathconf_name(name);
    BSD_TRACE("fpathconf: fd=%d name=%d->%d", fd, name, linux_name);
    
    /* Open the child's fd via /proc and call fpathconf on that */
    int our_fd = open(proc_path, O_RDONLY);
    if (our_fd < 0) {
        BSD_WARN("fpathconf: failed to open %s: %s", proc_path, strerror(errno));
        return -errno;
    }
    
    long ret = fpathconf(our_fd, linux_name);
    int saved_errno = errno;
    close(our_fd);
    
    if (ret < 0) {
        BSD_WARN("fpathconf: fpathconf failed: %s", strerror(saved_errno));
        return -saved_errno;
    }
    BSD_TRACE("fpathconf: returning %ld", ret);
    return ret;
}

static long emul_lpathconf(pid_t pid, uint64_t args[6]) {
    uint64_t path_addr = args[0];
    int name = (int)args[1];
    
    /* Read path from child's memory */
    char path[1024];
    size_t i;
    for (i = 0; i < sizeof(path) - 1; i++) {
        long word = ptrace(PTRACE_PEEKDATA, pid, path_addr + i, NULL);
        path[i] = (char)(word & 0xFF);
        if (path[i] == '\0') break;
    }
    path[sizeof(path) - 1] = '\0';
    
    int linux_name = translate_pathconf_name(name);
    BSD_TRACE("lpathconf: path=%s name=%d->%d", path, name, linux_name);
    
    /* lpathconf doesn't follow symlinks - use lstat to check, then pathconf */
    /* Linux doesn't have lpathconf, so we open with O_NOFOLLOW|O_PATH and use fpathconf */
    int fd = open(path, O_PATH | O_NOFOLLOW);
    if (fd < 0) {
        /* If O_NOFOLLOW fails on symlink, that's expected - just use pathconf */
        long ret = pathconf(path, linux_name);
        if (ret < 0) return -errno;
        return ret;
    }
    
    long ret = fpathconf(fd, linux_name);
    int saved_errno = errno;
    close(fd);
    
    if (ret < 0) return -saved_errno;
    return ret;
}

/*
 * fstatfs - FreeBSD struct statfs differs significantly from Linux
 * FreeBSD: ~2344 bytes with version, iosize, sync counters, long path names
 * Linux: 120 bytes with basic filesystem info
 *
 * NOTE: We can't call fstatfs directly because fd belongs to the CHILD process.
 * Instead, we use /proc/pid/fd/N to get the path and call statfs on it.
 */
static long emul_fstatfs(pid_t pid, uint64_t args[6]) {
    /*
     * FreeBSD statfs structure layout (from real FreeBSD 15 dump):
     * Offset 0x00 (0):   f_version   uint32_t   = 0x20140518
     * Offset 0x04 (4):   f_type      uint32_t   = filesystem type (0xde for ZFS)
     * Offset 0x08 (8):   f_flags     uint64_t   = mount flags
     * Offset 0x10 (16):  f_bsize     uint64_t   = block size (512 for ZFS)
     * Offset 0x18 (24):  f_iosize    uint64_t   = optimal I/O size (131072)
     * Offset 0x20 (32):  f_blocks    uint64_t   = total blocks
     * Offset 0x28 (40):  f_bfree     uint64_t   = free blocks
     * Offset 0x30 (48):  f_bavail    int64_t    = available blocks
     * Offset 0x38 (56):  f_files     uint64_t   = total files
     * Offset 0x40 (64):  f_ffree     int64_t    = free files
     * Offset 0x48 (72):  f_syncwrites  uint64_t
     * Offset 0x50 (80):  f_asyncwrites uint64_t
     * Offset 0x58 (88):  f_syncreads   uint64_t
     * Offset 0x60 (96):  f_asyncreads  uint64_t
     * Offset 0x68 (104): f_spare[10]   uint64_t[10] (80 bytes)
     * Offset 0xb8 (184): f_namemax   uint32_t   = 255
     * Offset 0xbc (188): f_owner     uid_t      = 0
     * Offset 0xc0 (192): f_fsid      fsid_t     = 8 bytes
     * Offset 0xc8 (200): f_charspare[80]         (80 bytes)
     * Offset 0x118 (280): f_fstypename[16]       = "ufs" or "zfs"
     * Offset 0x128 (296): f_mntfromname[1024]    = device name
     * Offset 0x528 (1320): f_mntonname[1024]     = mount point
     * Total: 2344 bytes
     */
    uint64_t buf_addr = args[1];
    
    BSD_WARN("fstatfs: returning valid statfs (fd=%d)", (int)args[0]);
    
    /* Build FreeBSD statfs structure (2344 bytes) */
    uint8_t fbsd_buf[2344];
    memset(fbsd_buf, 0, sizeof(fbsd_buf));
    
    /* f_version at offset 0 (4 bytes) */
    uint32_t version = 0x20140518;
    memcpy(fbsd_buf + 0, &version, 4);
    
    /* f_type at offset 4 (4 bytes) - use UFS type */
    uint32_t type = 0x11954;  /* UFS magic */
    memcpy(fbsd_buf + 4, &type, 4);
    
    /* f_flags at offset 8 (8 bytes) */
    uint64_t flags = 0x10005010;  /* typical mount flags */
    memcpy(fbsd_buf + 8, &flags, 8);
    
    /* f_bsize at offset 16 (8 bytes) - MUST be non-zero */
    uint64_t bsize = 512;  /* Match real FreeBSD ZFS */
    memcpy(fbsd_buf + 16, &bsize, 8);
    
    /* f_iosize at offset 24 (8 bytes) - MUST be non-zero */
    uint64_t iosize = 131072;  /* 128KB, typical for ZFS */
    memcpy(fbsd_buf + 24, &iosize, 8);
    
    /* f_blocks at offset 32 (8 bytes) */
    uint64_t blocks = 51798552;
    memcpy(fbsd_buf + 32, &blocks, 8);
    
    /* f_bfree at offset 40 (8 bytes) */
    uint64_t bfree = 47775384;
    memcpy(fbsd_buf + 40, &bfree, 8);
    
    /* f_bavail at offset 48 (8 bytes) */
    int64_t bavail = 47775384;
    memcpy(fbsd_buf + 48, &bavail, 8);
    
    /* f_files at offset 56 (8 bytes) */
    uint64_t files = 47803683;
    memcpy(fbsd_buf + 56, &files, 8);
    
    /* f_ffree at offset 64 (8 bytes) */
    int64_t ffree = 47775384;
    memcpy(fbsd_buf + 64, &ffree, 8);
    
    /* f_syncwrites, f_asyncwrites, f_syncreads, f_asyncreads at offsets 72-103 */
    /* Leave as zeros */
    
    /* f_spare[10] at offset 104 (80 bytes) - leave as zeros */
    
    /* f_namemax at offset 184 (4 bytes) */
    uint32_t namemax = 255;
    memcpy(fbsd_buf + 184, &namemax, 4);
    
    /* f_owner at offset 188 (4 bytes) - leave as 0 */
    
    /* f_fsid at offset 192 (8 bytes) */
    uint64_t fsid = 0x50bc93de4cd50717ULL;  /* example fsid */
    memcpy(fbsd_buf + 192, &fsid, 8);
    
    /* f_charspare at offset 200 (80 bytes) - leave as zeros */
    
    /* f_fstypename at offset 280 (16 bytes) */
    strncpy((char *)(fbsd_buf + 280), "ufs", 16);
    
    /* f_mntfromname at offset 296 (1024 bytes) */
    strncpy((char *)(fbsd_buf + 296), "/dev/ada0s1a", 1024);
    
    /* f_mntonname at offset 1320 (1024 bytes) */
    strncpy((char *)(fbsd_buf + 1320), "/", 1024);
    
    /* Write to child memory */
    struct iovec local = { fbsd_buf, sizeof(fbsd_buf) };
    struct iovec remote = { (void *)buf_addr, sizeof(fbsd_buf) };
    ssize_t written = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    
    if (written < 0) {
        BSD_WARN("fstatfs: failed to write: %s", strerror(errno));
        return -EFAULT;
    }
    
    BSD_TRACE("fstatfs: wrote %zd bytes", written);
    BSD_TRACE("fstatfs: first 32 bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
              fbsd_buf[0], fbsd_buf[1], fbsd_buf[2], fbsd_buf[3],
              fbsd_buf[4], fbsd_buf[5], fbsd_buf[6], fbsd_buf[7],
              fbsd_buf[8], fbsd_buf[9], fbsd_buf[10], fbsd_buf[11],
              fbsd_buf[12], fbsd_buf[13], fbsd_buf[14], fbsd_buf[15]);
    BSD_TRACE("fstatfs:                  %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
    fbsd_buf[16], fbsd_buf[17], fbsd_buf[18], fbsd_buf[19],
    fbsd_buf[20], fbsd_buf[21], fbsd_buf[22], fbsd_buf[23],
    fbsd_buf[24], fbsd_buf[25], fbsd_buf[26], fbsd_buf[27],
    fbsd_buf[28], fbsd_buf[29], fbsd_buf[30], fbsd_buf[31]);

    /* Verify by reading back from child memory */
    uint8_t readback[32];
    struct iovec rb_local = { readback, sizeof(readback) };
    struct iovec rb_remote = { (void *)buf_addr, sizeof(readback) };
    if (process_vm_readv(pid, &rb_local, 1, &rb_remote, 1, 0) > 0) {
        BSD_TRACE("fstatfs: READBACK bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                  readback[0], readback[1], readback[2], readback[3],
                  readback[4], readback[5], readback[6], readback[7],
                  readback[8], readback[9], readback[10], readback[11],
                  readback[12], readback[13], readback[14], readback[15]);
    }

    return 0;
}

/*
 * ioctl - translate FreeBSD terminal ioctls to Linux equivalents
 * FreeBSD and Linux have different ioctl command numbers and termios structs
 */

/* FreeBSD terminal ioctl commands */
#define FBSD_TIOCGETA      0x402c7413  /* Get termios */
#define FBSD_TIOCSETA      0x802c7414  /* Set termios */
#define FBSD_TIOCSETAW     0x802c7415  /* Set termios, drain first */
#define FBSD_TIOCSETAF     0x802c7416  /* Set termios, flush first */
#define FBSD_TIOCGWINSZ    0x40087468  /* Get window size */
#define FBSD_TIOCSWINSZ    0x80087467  /* Set window size */
#define FBSD_TIOCGPGRP     0x40047477  /* Get process group */
#define FBSD_TIOCSPGRP     0x80047476  /* Set process group */
#define FBSD_TIOCSCTTY     0x20007461  /* Set controlling terminal */
#define FBSD_TIOCNOTTY     0x20007471  /* Release controlling terminal */
#define FBSD_FIONREAD      0x4004667f  /* Get # bytes to read */
#define FBSD_FIONBIO       0x8004667e  /* Set/clear non-blocking I/O */
#define FBSD_FIOASYNC      0x8004667d  /* Set/clear async I/O */

/* Linux terminal ioctl commands */
#define LINUX_TCGETS       0x5401
#define LINUX_TCSETS       0x5402
#define LINUX_TCSETSW      0x5403
#define LINUX_TCSETSF      0x5404
#define LINUX_TIOCGWINSZ   0x5413
#define LINUX_TIOCSWINSZ   0x5414
#define LINUX_TIOCGPGRP    0x540f
#define LINUX_TIOCSPGRP    0x5410
#define LINUX_TIOCSCTTY    0x540e
#define LINUX_TIOCNOTTY    0x5422
#define LINUX_FIONREAD     0x541b
#define LINUX_FIONBIO      0x5421
#define LINUX_FIOASYNC     0x5452

/* FreeBSD termios structure (44 bytes) */
struct fbsd_termios {
    uint32_t c_iflag;      /* input flags */
    uint32_t c_oflag;      /* output flags */
    uint32_t c_cflag;      /* control flags */
    uint32_t c_lflag;      /* local flags */
    uint8_t  c_cc[20];     /* control characters */
    uint32_t c_ispeed;     /* input speed */
    uint32_t c_ospeed;     /* output speed */
};

static long emul_ioctl(pid_t pid, uint64_t args[6]) {
    int fd = (int)args[0];
    unsigned long request = args[1];
    uint64_t argp = args[2];
    
    /* Access child's fd via /proc */
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/fd/%d", pid, fd);
    
    int our_fd = open(proc_path, O_RDWR | O_NOCTTY);
    if (our_fd < 0) {
        /* Try read-only */
        our_fd = open(proc_path, O_RDONLY);
        if (our_fd < 0) {
            BSD_WARN("ioctl: failed to open %s: %s", proc_path, strerror(errno));
            return -errno;
        }
    }
    
    long ret = 0;
    int saved_errno = 0;
    
    switch (request) {
        case FBSD_TIOCGETA: {
            /* Get termios - translate Linux to FreeBSD format */
            struct termios linux_termios;
            ret = ioctl(our_fd, LINUX_TCGETS, &linux_termios);
            saved_errno = errno;
            
            if (ret == 0 && argp != 0) {
                /* Convert Linux termios to FreeBSD format */
                struct fbsd_termios fbsd_termios = {0};
                fbsd_termios.c_iflag = linux_termios.c_iflag;
                fbsd_termios.c_oflag = linux_termios.c_oflag;
                fbsd_termios.c_cflag = linux_termios.c_cflag;
                fbsd_termios.c_lflag = linux_termios.c_lflag;
                /* Copy control characters (Linux has more, FreeBSD has 20) */
                memcpy(fbsd_termios.c_cc, linux_termios.c_cc, 
                       sizeof(fbsd_termios.c_cc) < NCCS ? sizeof(fbsd_termios.c_cc) : NCCS);
                fbsd_termios.c_ispeed = cfgetispeed(&linux_termios);
                fbsd_termios.c_ospeed = cfgetospeed(&linux_termios);
                
                /* Write to child's memory */
                struct iovec local = { &fbsd_termios, sizeof(fbsd_termios) };
                struct iovec remote = { (void *)argp, sizeof(fbsd_termios) };
                if (process_vm_writev(pid, &local, 1, &remote, 1, 0) < 0) {
                    close(our_fd);
                    return -EFAULT;
                }
            }
            BSD_TRACE("ioctl: TIOCGETA fd=%d ret=%ld", fd, ret);
            break;
        }
        
        case FBSD_TIOCSETA:
        case FBSD_TIOCSETAW:
        case FBSD_TIOCSETAF: {
            /* Set termios - translate FreeBSD to Linux format */
            struct fbsd_termios fbsd_termios;
            struct iovec local = { &fbsd_termios, sizeof(fbsd_termios) };
            struct iovec remote = { (void *)argp, sizeof(fbsd_termios) };
            if (process_vm_readv(pid, &local, 1, &remote, 1, 0) < 0) {
                close(our_fd);
                return -EFAULT;
            }
            
            struct termios linux_termios = {0};
            linux_termios.c_iflag = fbsd_termios.c_iflag;
            linux_termios.c_oflag = fbsd_termios.c_oflag;
            linux_termios.c_cflag = fbsd_termios.c_cflag;
            linux_termios.c_lflag = fbsd_termios.c_lflag;
            memcpy(linux_termios.c_cc, fbsd_termios.c_cc,
                   sizeof(fbsd_termios.c_cc) < NCCS ? sizeof(fbsd_termios.c_cc) : NCCS);
            cfsetispeed(&linux_termios, fbsd_termios.c_ispeed);
            cfsetospeed(&linux_termios, fbsd_termios.c_ospeed);
            
            unsigned long linux_req = LINUX_TCSETS;
            if (request == FBSD_TIOCSETAW) linux_req = LINUX_TCSETSW;
            if (request == FBSD_TIOCSETAF) linux_req = LINUX_TCSETSF;
            
            ret = ioctl(our_fd, linux_req, &linux_termios);
            saved_errno = errno;
            BSD_TRACE("ioctl: TIOCSETA fd=%d ret=%ld", fd, ret);
            break;
        }
        
        case FBSD_TIOCGWINSZ: {
            struct winsize ws;
            ret = ioctl(our_fd, LINUX_TIOCGWINSZ, &ws);
            saved_errno = errno;
            if (ret == 0 && argp != 0) {
                struct iovec local = { &ws, sizeof(ws) };
                struct iovec remote = { (void *)argp, sizeof(ws) };
                if (process_vm_writev(pid, &local, 1, &remote, 1, 0) < 0) {
                    close(our_fd);
                    return -EFAULT;
                }
            }
            BSD_TRACE("ioctl: TIOCGWINSZ fd=%d ret=%ld (%dx%d)", fd, ret, ws.ws_col, ws.ws_row);
            break;
        }
        
        case FBSD_TIOCSWINSZ: {
            struct winsize ws;
            struct iovec local = { &ws, sizeof(ws) };
            struct iovec remote = { (void *)argp, sizeof(ws) };
            if (process_vm_readv(pid, &local, 1, &remote, 1, 0) < 0) {
                close(our_fd);
                return -EFAULT;
            }
            ret = ioctl(our_fd, LINUX_TIOCSWINSZ, &ws);
            saved_errno = errno;
            BSD_TRACE("ioctl: TIOCSWINSZ fd=%d ret=%ld", fd, ret);
            break;
        }
        
        case FBSD_TIOCGPGRP: {
            pid_t pgrp;
            ret = ioctl(our_fd, LINUX_TIOCGPGRP, &pgrp);
            saved_errno = errno;
            if (ret == 0 && argp != 0) {
                struct iovec local = { &pgrp, sizeof(pgrp) };
                struct iovec remote = { (void *)argp, sizeof(pgrp) };
                process_vm_writev(pid, &local, 1, &remote, 1, 0);
            }
            BSD_TRACE("ioctl: TIOCGPGRP fd=%d ret=%ld pgrp=%d", fd, ret, pgrp);
            break;
        }
        
        case FBSD_TIOCSPGRP: {
            pid_t pgrp;
            struct iovec local = { &pgrp, sizeof(pgrp) };
            struct iovec remote = { (void *)argp, sizeof(pgrp) };
            if (process_vm_readv(pid, &local, 1, &remote, 1, 0) < 0) {
                close(our_fd);
                return -EFAULT;
            }
            ret = ioctl(our_fd, LINUX_TIOCSPGRP, &pgrp);
            saved_errno = errno;
            BSD_TRACE("ioctl: TIOCSPGRP fd=%d ret=%ld pgrp=%d", fd, ret, pgrp);
            break;
        }
        
        case FBSD_TIOCSCTTY: {
            ret = ioctl(our_fd, LINUX_TIOCSCTTY, (int)argp);
            saved_errno = errno;
            BSD_TRACE("ioctl: TIOCSCTTY fd=%d ret=%ld", fd, ret);
            break;
        }
        
        case FBSD_TIOCNOTTY: {
            ret = ioctl(our_fd, LINUX_TIOCNOTTY, 0);
            saved_errno = errno;
            BSD_TRACE("ioctl: TIOCNOTTY fd=%d ret=%ld", fd, ret);
            break;
        }
        
        case FBSD_FIONREAD: {
            int nbytes;
            ret = ioctl(our_fd, LINUX_FIONREAD, &nbytes);
            saved_errno = errno;
            if (ret == 0 && argp != 0) {
                struct iovec local = { &nbytes, sizeof(nbytes) };
                struct iovec remote = { (void *)argp, sizeof(nbytes) };
                process_vm_writev(pid, &local, 1, &remote, 1, 0);
            }
            BSD_TRACE("ioctl: FIONREAD fd=%d ret=%ld nbytes=%d", fd, ret, nbytes);
            break;
        }
        
        case FBSD_FIONBIO: {
            int flag;
            struct iovec local = { &flag, sizeof(flag) };
            struct iovec remote = { (void *)argp, sizeof(flag) };
            if (process_vm_readv(pid, &local, 1, &remote, 1, 0) < 0) {
                close(our_fd);
                return -EFAULT;
            }
            ret = ioctl(our_fd, LINUX_FIONBIO, &flag);
            saved_errno = errno;
            BSD_TRACE("ioctl: FIONBIO fd=%d ret=%ld flag=%d", fd, ret, flag);
            break;
        }
        
        default:
            BSD_WARN("ioctl: unhandled request 0x%lx on fd=%d", request, fd);
            close(our_fd);
            return -ENOTTY;
    }
    
    close(our_fd);
    
    if (ret < 0) {
        return -saved_errno;
    }
    return ret;
}
