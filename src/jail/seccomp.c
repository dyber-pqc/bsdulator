/*
 * seccomp.c - syscall filter for container processes
 *
 * Seccomp runs after the ptrace syscall-entry stop (Linux 4.8+), so it
 * sees the Linux syscall the engine actually issues, after translation.
 * The filter:
 *   - kills the process for any syscall that is not native x86-64 (the
 *     32-bit int 0x80 interface uses other numbers and would bypass the
 *     translation), and refuses x32 syscalls;
 *   - refuses (EPERM) syscalls a container never needs and that act on
 *     the whole host: mounting and filesystem handles, modules and kexec,
 *     reboot and swap, clock setting, ptrace and other processes' memory,
 *     io_uring (it would bypass the tracer), BPF, perf, userfaultfd, the
 *     kernel keyring, and creating or joining namespaces (unshare, setns,
 *     clone or clone3 with namespace flags).
 * Everything else is allowed: FreeBSD programs reach Linux only through
 * the engine's translation.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "bsdulator/seccomp.h"

#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif
#define NS_FLAGS (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | \
                  CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWCGROUP | CLONE_NEWTIME)
#define X32_BIT 0x40000000u

static const int denied[] = {
    SYS_mount, SYS_umount2, SYS_pivot_root,
#ifdef SYS_open_tree
    SYS_open_tree, SYS_move_mount, SYS_fsopen, SYS_fsconfig, SYS_fsmount, SYS_fspick,
#endif
#ifdef SYS_mount_setattr
    SYS_mount_setattr,
#endif
    SYS_name_to_handle_at, SYS_open_by_handle_at,
    SYS_init_module, SYS_finit_module, SYS_delete_module,
    SYS_kexec_load,
#ifdef SYS_kexec_file_load
    SYS_kexec_file_load,
#endif
    SYS_reboot, SYS_swapon, SYS_swapoff, SYS_acct, SYS_syslog,
    SYS_settimeofday, SYS_clock_settime, SYS_clock_adjtime, SYS_adjtimex,
    SYS_iopl, SYS_ioperm, SYS_quotactl,
    SYS_ptrace, SYS_process_vm_readv, SYS_process_vm_writev, SYS_kcmp,
#ifdef SYS_pidfd_getfd
    SYS_pidfd_getfd,
#endif
#ifdef SYS_io_uring_setup
    SYS_io_uring_setup, SYS_io_uring_enter, SYS_io_uring_register,
#endif
    SYS_bpf, SYS_perf_event_open, SYS_userfaultfd,
    SYS_add_key, SYS_request_key, SYS_keyctl,
    SYS_unshare, SYS_setns, SYS_vhangup, SYS_lookup_dcookie,
};

#define DENIED_COUNT (sizeof(denied) / sizeof(denied[0]))

int container_seccomp_install(void) {
    /* 6 header + 2 per denied syscall + 5 for clone + 2 for clone3 + 1 */
    struct sock_filter f[8 + 2 * DENIED_COUNT + 8];
    unsigned n = 0;
#define ADD(stmt) (f[n++] = (struct sock_filter)stmt)

    /* Native x86-64 only */
    ADD(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)));
    ADD(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    ADD(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    ADD(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)));
    /* -1: a syscall the engine emulated and skipped; its result is set */
    ADD(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xffffffffu, 0, 1));
    ADD(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    ADD(BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_BIT, 0, 1));
    ADD(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)));

    for (size_t i = 0; i < DENIED_COUNT; i++) {
        ADD(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)denied[i], 0, 1));
        ADD(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)));
    }

    /* clone with namespace flags (flags are the first argument) */
    ADD(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 4));
    ADD(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])));
    ADD(BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, NS_FLAGS, 0, 1));
    ADD(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)));
    ADD(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

#ifdef SYS_clone3
    /* clone3 passes flags in memory the filter cannot read: refuse it
     * (ENOSYS, so callers fall back to clone) */
    ADD(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1));
    ADD(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)));
#endif

    ADD(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
#undef ADD

    struct sock_fprog prog = { .len = (unsigned short)n, .filter = f };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}
