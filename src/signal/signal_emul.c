/*
 * signal_emul.c - FreeBSD signal semantics for traced processes
 *
 * See include/bsdulator/signal_emul.h for the model. In short: the tracer
 * owns each process's FreeBSD signal state, and delivers a signal by
 * writing a FreeBSD signal frame on the process's stack and pointing the
 * registers at the handler, as FreeBSD's sendsig() does.
 *
 * FreeBSD amd64 layouts used here (sys/amd64/include/ucontext.h,
 * sys/sys/_ucontext.h, sys/sys/signal.h):
 *   siginfo_t    80 bytes
 *   mcontext_t  800 bytes
 *   ucontext_t  880 bytes
 *   struct sigaction  { handler (8), sa_flags (4), sa_mask (16) }
 *   stack_t     { ss_sp (8), ss_size (8), ss_flags (4) }
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <dirent.h>
#include <stdio.h>

#include "bsdulator.h"
#include "bsdulator/interceptor.h"
#include "bsdulator/syscall.h"
#include "bsdulator/signal_emul.h"
#include "bsdulator/kqueue_emul.h"

/* ---------------------------------------------------------------------
 * FreeBSD constants and structures
 * ------------------------------------------------------------------- */

#define FBSD_NSIG           128

#define FBSD_SIG_DFL        0
#define FBSD_SIG_IGN        1

#define FBSD_SA_ONSTACK     0x0001
#define FBSD_SA_RESTART     0x0002
#define FBSD_SA_RESETHAND   0x0004
#define FBSD_SA_NOCLDSTOP   0x0008
#define FBSD_SA_NODEFER     0x0010
#define FBSD_SA_SIGINFO     0x0040

#define FBSD_SIG_BLOCK      1
#define FBSD_SIG_UNBLOCK    2
#define FBSD_SIG_SETMASK    3

#define FBSD_SS_ONSTACK     0x0001
#define FBSD_SS_DISABLE     0x0004
#define FBSD_MINSIGSTKSZ    2048

#define FBSD_SIGHUP   1
#define FBSD_SIGILL   4
#define FBSD_SIGTRAP  5
#define FBSD_SIGFPE   8
#define FBSD_SIGKILL  9
#define FBSD_SIGBUS   10
#define FBSD_SIGSEGV  11
#define FBSD_SIGURG   16
#define FBSD_SIGSTOP  17
#define FBSD_SIGCONT  19
#define FBSD_SIGCHLD  20
#define FBSD_SIGIO    23
#define FBSD_SIGWINCH 28
#define FBSD_SIGINFO  29
#define FBSD_SIGTHR   32
#define FBSD_SIGLIBRT 33

/* si_code values that differ from Linux */
#define FBSD_SI_USER     0x10001
#define FBSD_SI_QUEUE    0x10002
#define FBSD_SI_TIMER    0x10003
#define FBSD_SI_MESGQ    0x10004
#define FBSD_SI_ASYNCIO  0x10005
#define FBSD_SI_KERNEL   0x10006
#define FBSD_SI_LWP      0x10007

/* mcontext_t flags and FPU formats */
#define FBSD_MC_HASSEGS        0x1
#define FBSD_MC_HASBASES       0x2
#define FBSD_MC_FPFMT_NODEV    0x10000
#define FBSD_MC_FPFMT_XMM      0x10002
#define FBSD_MC_FPOWNED_NONE   0x20000
#define FBSD_MC_FPOWNED_FPU    0x20001

/* sigfastblock(2) */
#define FBSD_SIGFASTBLOCK_SETPTR   1
#define FBSD_SIGFASTBLOCK_UNBLOCK  2
#define FBSD_SIGFASTBLOCK_UNSETPTR 3
#define FBSD_SIGFASTBLOCK_PEND     0x1
#define FBSD_SIGFASTBLOCK_FLAGS    0xf

/* wait4 options and status */
#define FBSD_WNOHANG      1
#define FBSD_WUNTRACED    2
#define FBSD_WCONTINUED   4
#define FBSD_WLINUXCLONE  0x80000000ULL
#define FBSD_W_CONTINUED  0x13

/* Linux kernel-internal restart codes */
#define L_ERESTARTSYS            512
#define L_ERESTARTNOINTR         513
#define L_ERESTARTNOHAND         514
#define L_ERESTART_RESTARTBLOCK  516
#define L_NR_restart_syscall     219

/* User-changeable rflags: CF PF AF ZF SF DF OF */
#define RFLAGS_USER  0x0cd5ULL
#define RFLAGS_TF    0x0100ULL
#define RFLAGS_DF    0x0400ULL
#define RFLAGS_CF    0x0001ULL

typedef struct {
    uint32_t bits[4];
} fset_t;

struct fbsd_sigaction {
    uint64_t handler;
    int32_t  flags;
    fset_t   mask;
} __attribute__((packed));
_Static_assert(sizeof(struct fbsd_sigaction) == 28, "FreeBSD struct sigaction");

struct fbsd_stack {
    uint64_t ss_sp;
    uint64_t ss_size;
    int32_t  ss_flags;
    int32_t  pad;
};
_Static_assert(sizeof(struct fbsd_stack) == 24, "FreeBSD stack_t");

struct fbsd_siginfo {
    int32_t  fs_signo;
    int32_t  fs_errno;
    int32_t  fs_code;
    int32_t  fs_pid;
    uint32_t fs_uid;
    int32_t  fs_status;
    uint64_t fs_addr;
    uint64_t fs_value;
    int32_t  fs_reason[10];
};
_Static_assert(sizeof(struct fbsd_siginfo) == 80, "FreeBSD siginfo_t");

struct fbsd_mcontext {
    uint64_t mc_onstack;
    uint64_t mc_rdi, mc_rsi, mc_rdx, mc_rcx, mc_r8, mc_r9, mc_rax;
    uint64_t mc_rbx, mc_rbp, mc_r10, mc_r11, mc_r12, mc_r13, mc_r14, mc_r15;
    uint32_t mc_trapno;
    uint16_t mc_fs, mc_gs;
    uint64_t mc_addr;
    uint32_t mc_flags;
    uint16_t mc_es, mc_ds;
    uint64_t mc_err;
    uint64_t mc_rip, mc_cs, mc_rflags, mc_rsp, mc_ss;
    int64_t  mc_len;
    int64_t  mc_fpformat;
    int64_t  mc_ownedfp;
    uint8_t  mc_fpstate[512] __attribute__((aligned(16)));
    uint64_t mc_fsbase, mc_gsbase;
    uint64_t mc_xfpustate, mc_xfpustate_len;
    int64_t  mc_spare[4];
} __attribute__((aligned(16)));
_Static_assert(sizeof(struct fbsd_mcontext) == 800, "FreeBSD mcontext_t");
_Static_assert(offsetof(struct fbsd_mcontext, mc_rip) == 160, "mc_rip");
_Static_assert(offsetof(struct fbsd_mcontext, mc_fpstate) == 224, "mc_fpstate");

struct fbsd_ucontext {
    fset_t               uc_sigmask;
    struct fbsd_mcontext uc_mcontext;
    uint64_t             uc_link;
    struct fbsd_stack    uc_stack;
    int32_t              uc_flags;
    int32_t              spare[4];
} __attribute__((aligned(16)));
_Static_assert(offsetof(struct fbsd_ucontext, uc_mcontext) == 16, "uc_mcontext");
_Static_assert(offsetof(struct fbsd_ucontext, uc_link) == 816, "uc_link");
_Static_assert(sizeof(struct fbsd_ucontext) == 880, "FreeBSD ucontext_t");

/* ---------------------------------------------------------------------
 * Signal numbers
 * ------------------------------------------------------------------- */

int sig_fbsd_to_linux(int s) {
    static const signed char map[34] = {
        0,
        1, 2, 3, 4, 5, 6,   /* HUP INT QUIT ILL TRAP ABRT */
        0,                  /* EMT: none */
        8, 9,               /* FPE KILL */
        7,                  /* BUS */
        11,                 /* SEGV */
        31,                 /* SYS */
        13, 14, 15,         /* PIPE ALRM TERM */
        23,                 /* URG */
        19, 20, 18, 17,     /* STOP TSTP CONT CHLD */
        21, 22,             /* TTIN TTOU */
        29,                 /* IO */
        24, 25, 26, 27,     /* XCPU XFSZ VTALRM PROF */
        28,                 /* WINCH */
        30,                 /* INFO -> PWR */
        10, 12,             /* USR1 USR2 */
        32, 33,             /* THR LIBRT */
    };
    if (s >= 1 && s <= 33) return map[s];
    if (s >= 65 && s <= 65 + 30) return 34 + (s - 65);  /* SIGRTMIN.. */
    return 0;
}

int sig_linux_to_fbsd(int s) {
    static const signed char map[34] = {
        0,
        1, 2, 3, 4, 5, 6,   /* HUP INT QUIT ILL TRAP ABRT */
        10,                 /* BUS */
        8, 9,               /* FPE KILL */
        30,                 /* USR1 */
        11,                 /* SEGV */
        31,                 /* USR2 */
        13, 14, 15,         /* PIPE ALRM TERM */
        0,                  /* STKFLT: none */
        20, 19, 17, 18,     /* CHLD CONT STOP TSTP */
        21, 22,             /* TTIN TTOU */
        16,                 /* URG */
        24, 25, 26, 27,     /* XCPU XFSZ VTALRM PROF */
        28,                 /* WINCH */
        23,                 /* IO */
        29,                 /* PWR -> INFO */
        12,                 /* SYS */
        32, 33,
    };
    if (s >= 1 && s <= 33) return map[s];
    if (s >= 34 && s <= 64) return 65 + (s - 34);
    return 0;
}

/* Signals whose FreeBSD default action is to ignore them. */
static int default_ignored(int fsig) {
    switch (fsig) {
        case FBSD_SIGURG: case FBSD_SIGCONT: case FBSD_SIGCHLD:
        case FBSD_SIGIO: case FBSD_SIGWINCH: case FBSD_SIGINFO:
        case FBSD_SIGTHR: case FBSD_SIGLIBRT:
            return 1;
        default:
            return 0;
    }
}

/* ---------------------------------------------------------------------
 * Signal sets
 * ------------------------------------------------------------------- */

static int fs_has(const fset_t *s, int sig) {
    if (sig < 1 || sig > FBSD_NSIG) return 0;
    return (s->bits[(sig - 1) >> 5] >> ((sig - 1) & 31)) & 1;
}
static void fs_add(fset_t *s, int sig) {
    if (sig >= 1 && sig <= FBSD_NSIG) s->bits[(sig - 1) >> 5] |= 1u << ((sig - 1) & 31);
}
static void fs_del(fset_t *s, int sig) {
    if (sig >= 1 && sig <= FBSD_NSIG) s->bits[(sig - 1) >> 5] &= ~(1u << ((sig - 1) & 31));
}
static void fs_or(fset_t *d, const fset_t *s) {
    for (int i = 0; i < 4; i++) d->bits[i] |= s->bits[i];
}
static void fs_andnot(fset_t *d, const fset_t *s) {
    for (int i = 0; i < 4; i++) d->bits[i] &= ~s->bits[i];
}
/* SIGKILL and SIGSTOP can never be blocked. */
static void fs_sanitize(fset_t *s) {
    fs_del(s, FBSD_SIGKILL);
    fs_del(s, FBSD_SIGSTOP);
}

/* ---------------------------------------------------------------------
 * Per-process state
 * ------------------------------------------------------------------- */

typedef struct {
    pid_t    pid;
    uint64_t handler[FBSD_NSIG + 1];
    int32_t  flags[FBSD_NSIG + 1];
    fset_t   hmask[FBSD_NSIG + 1];
    fset_t   blocked;
    fset_t   pending;
    struct fbsd_siginfo pinfo[FBSD_NSIG + 1];
    struct fbsd_stack   altstack;
    uint64_t fastblock_ptr;
    int      in_sigsuspend;   /* blocked is sigsuspend's temporary mask */
    fset_t   saved_mask;      /* mask to restore after sigsuspend */
    uint64_t restore_uc;      /* sigreturn/setcontext to finish at exit */
    int      restart_block;   /* next restart_syscall is the kernel's */
    int      wait_kind;       /* sigwait family in progress (WAIT_*) */
    fset_t   waitset;
    uint64_t wait_out;
} sig_proc_t;

enum { WAIT_NONE, WAIT_SIGWAIT, WAIT_TIMEDWAIT };

#define MAX_SIG_PROCS 512
static sig_proc_t *procs[MAX_SIG_PROCS];

static sig_proc_t *find_proc(pid_t pid) {
    for (int i = 0; i < MAX_SIG_PROCS; i++)
        if (procs[i] && procs[i]->pid == pid) return procs[i];
    return NULL;
}

static sig_proc_t *new_proc(pid_t pid) {
    for (int i = 0; i < MAX_SIG_PROCS; i++) {
        if (!procs[i]) {
            sig_proc_t *p = calloc(1, sizeof(*p));
            if (!p) return NULL;
            p->pid = pid;
            p->altstack.ss_flags = FBSD_SS_DISABLE;
            procs[i] = p;
            return p;
        }
    }
    BSD_WARN("signal: process table full, pid %d gets default signal handling", pid);
    return NULL;
}

static sig_proc_t *get_proc(pid_t pid) {
    sig_proc_t *p = find_proc(pid);
    return p ? p : new_proc(pid);
}

void sig_proc_start(pid_t pid) {
    (void)get_proc(pid);
}

void sig_proc_fork(pid_t parent, pid_t child) {
    if (find_proc(child)) return;  /* already set up (child stopped first) */
    sig_proc_t *pp = find_proc(parent);
    sig_proc_t *c = new_proc(child);
    if (!c || !pp) return;
    /* fork(2): dispositions, mask and alternate stack are inherited;
     * pending signals are not. */
    memcpy(c->handler, pp->handler, sizeof(c->handler));
    memcpy(c->flags, pp->flags, sizeof(c->flags));
    memcpy(c->hmask, pp->hmask, sizeof(c->hmask));
    c->blocked = pp->in_sigsuspend ? pp->saved_mask : pp->blocked;
    c->altstack = pp->altstack;
    c->fastblock_ptr = pp->fastblock_ptr;
}

void sig_proc_exec(pid_t pid) {
    sig_proc_t *p = get_proc(pid);
    if (!p) return;
    /* execve(2): caught signals revert to SIG_DFL, ignored stay ignored;
     * the mask and pending set survive; the alternate stack is reset. */
    for (int s = 1; s <= FBSD_NSIG; s++) {
        if (p->handler[s] != FBSD_SIG_IGN) p->handler[s] = FBSD_SIG_DFL;
        p->flags[s] = 0;
        memset(&p->hmask[s], 0, sizeof(fset_t));
    }
    p->altstack.ss_sp = 0;
    p->altstack.ss_size = 0;
    p->altstack.ss_flags = FBSD_SS_DISABLE;
    p->fastblock_ptr = 0;
    p->in_sigsuspend = 0;
    p->restore_uc = 0;
    p->restart_block = 0;
    p->wait_kind = WAIT_NONE;
}

void sig_proc_exit(pid_t pid) {
    for (int i = 0; i < MAX_SIG_PROCS; i++) {
        if (procs[i] && procs[i]->pid == pid) {
            free(procs[i]);
            procs[i] = NULL;
            return;
        }
    }
}

/* ---------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------- */

static int rd(pid_t pid, void *dst, uint64_t addr, size_t len) {
    return interceptor_read_mem(pid, dst, (const void *)addr, len) == (ssize_t)len ? 0 : -1;
}
static int wr(pid_t pid, const void *src, uint64_t addr, size_t len) {
    return interceptor_write_mem(pid, src, (void *)addr, len) == (ssize_t)len ? 0 : -1;
}

static int on_altstack(const sig_proc_t *p, uint64_t sp) {
    if (p->altstack.ss_flags & FBSD_SS_DISABLE) return 0;
    return sp > p->altstack.ss_sp && sp <= p->altstack.ss_sp + p->altstack.ss_size;
}

/* True if the process's sigfastblock word defers signals right now; then
 * the PEND flag is set so libc calls sigfastblock(UNBLOCK) when done. */
static int fastblocked(pid_t pid, sig_proc_t *p) {
    if (!p->fastblock_ptr) return 0;
    uint32_t word;
    if (rd(pid, &word, p->fastblock_ptr, sizeof(word)) < 0) return 0;
    if ((word & ~(uint32_t)FBSD_SIGFASTBLOCK_FLAGS) == 0) return 0;
    if (!(word & FBSD_SIGFASTBLOCK_PEND)) {
        word |= FBSD_SIGFASTBLOCK_PEND;
        (void)wr(pid, &word, p->fastblock_ptr, sizeof(word));
    }
    return 1;
}

static void convert_siginfo(const siginfo_t *l, int have, int fsig,
                            struct fbsd_siginfo *f) {
    memset(f, 0, sizeof(*f));
    f->fs_signo = fsig;
    if (!have) {
        f->fs_code = FBSD_SI_USER;
        return;
    }
    int c = l->si_code;
    f->fs_errno = l->si_errno;
    switch (c) {
        case SI_USER:    f->fs_code = FBSD_SI_USER; break;
        case SI_QUEUE:   f->fs_code = FBSD_SI_QUEUE; break;
        case SI_TIMER:   f->fs_code = FBSD_SI_TIMER; break;
        case SI_MESGQ:   f->fs_code = FBSD_SI_MESGQ; break;
        case SI_ASYNCIO: f->fs_code = FBSD_SI_ASYNCIO; break;
        case SI_TKILL:   f->fs_code = FBSD_SI_LWP; break;
        case SI_KERNEL:  f->fs_code = FBSD_SI_KERNEL; break;
        default:         f->fs_code = c > 0 ? c : FBSD_SI_KERNEL; break;
    }
    if (c <= 0) {
        f->fs_pid = l->si_pid;
        f->fs_uid = l->si_uid;
        f->fs_value = (uint64_t)(uintptr_t)l->si_value.sival_ptr;
        if (c == SI_TIMER) {
            f->fs_reason[0] = l->si_timerid;
            f->fs_reason[1] = l->si_overrun;
        }
        return;
    }
    switch (fsig) {
        case FBSD_SIGCHLD:
            f->fs_pid = l->si_pid;
            f->fs_uid = l->si_uid;
            f->fs_status = c == CLD_EXITED ? l->si_status : sig_linux_to_fbsd(l->si_status);
            break;
        case FBSD_SIGFPE:
            /* Linux FPE_INTDIV=1, FPE_INTOVF=2; FreeBSD the other way */
            if (c == 1) f->fs_code = 2;
            else if (c == 2) f->fs_code = 1;
            f->fs_addr = (uint64_t)(uintptr_t)l->si_addr;
            break;
        case FBSD_SIGSEGV: case FBSD_SIGBUS: case FBSD_SIGILL: case FBSD_SIGTRAP:
            f->fs_addr = (uint64_t)(uintptr_t)l->si_addr;
            break;
        default:
            break;
    }
}

static void fill_mcontext(pid_t pid, struct fbsd_mcontext *mc,
                          const struct user_regs_struct *r, uint64_t addr) {
    memset(mc, 0, sizeof(*mc));
    mc->mc_rdi = r->rdi; mc->mc_rsi = r->rsi; mc->mc_rdx = r->rdx;
    mc->mc_rcx = r->rcx; mc->mc_r8 = r->r8;   mc->mc_r9 = r->r9;
    mc->mc_rax = r->rax; mc->mc_rbx = r->rbx; mc->mc_rbp = r->rbp;
    mc->mc_r10 = r->r10; mc->mc_r11 = r->r11; mc->mc_r12 = r->r12;
    mc->mc_r13 = r->r13; mc->mc_r14 = r->r14; mc->mc_r15 = r->r15;
    mc->mc_fs = (uint16_t)r->fs; mc->mc_gs = (uint16_t)r->gs;
    mc->mc_es = (uint16_t)r->es; mc->mc_ds = (uint16_t)r->ds;
    mc->mc_addr = addr;
    mc->mc_flags = FBSD_MC_HASSEGS | FBSD_MC_HASBASES;
    mc->mc_rip = r->rip; mc->mc_cs = r->cs; mc->mc_rflags = r->eflags;
    mc->mc_rsp = r->rsp; mc->mc_ss = r->ss;
    mc->mc_len = sizeof(*mc);
    mc->mc_fsbase = r->fs_base;
    mc->mc_gsbase = r->gs_base;

    struct user_fpregs_struct fp;
    if (ptrace(PTRACE_GETFPREGS, pid, NULL, &fp) == 0) {
        _Static_assert(sizeof(fp) == 512, "fxsave area");
        memcpy(mc->mc_fpstate, &fp, sizeof(fp));
        mc->mc_fpformat = FBSD_MC_FPFMT_XMM;
        mc->mc_ownedfp = FBSD_MC_FPOWNED_FPU;
    } else {
        mc->mc_fpformat = FBSD_MC_FPFMT_NODEV;
        mc->mc_ownedfp = FBSD_MC_FPOWNED_NONE;
    }
}

/*
 * Restore a FreeBSD ucontext_t at uc_addr into the process (sigreturn,
 * setcontext). Returns 0, or -1 if it could not be read.
 */
static int restore_context(pid_t pid, sig_proc_t *p, uint64_t uc_addr) {
    struct fbsd_ucontext uc;
    if (rd(pid, &uc, uc_addr, sizeof(uc)) < 0) {
        BSD_WARN("signal: cannot read ucontext at 0x%lx", (unsigned long)uc_addr);
        return -1;
    }
    struct fbsd_mcontext *mc = &uc.uc_mcontext;
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r) < 0) return -1;
    r.rdi = mc->mc_rdi; r.rsi = mc->mc_rsi; r.rdx = mc->mc_rdx;
    r.rcx = mc->mc_rcx; r.r8 = mc->mc_r8;   r.r9 = mc->mc_r9;
    r.rax = mc->mc_rax; r.rbx = mc->mc_rbx; r.rbp = mc->mc_rbp;
    r.r10 = mc->mc_r10; r.r11 = mc->mc_r11; r.r12 = mc->mc_r12;
    r.r13 = mc->mc_r13; r.r14 = mc->mc_r14; r.r15 = mc->mc_r15;
    r.rip = mc->mc_rip;
    r.rsp = mc->mc_rsp;
    r.eflags = (r.eflags & ~RFLAGS_USER) | (mc->mc_rflags & RFLAGS_USER);
    if ((mc->mc_flags & FBSD_MC_HASBASES) && mc->mc_fsbase) r.fs_base = mc->mc_fsbase;
    r.orig_rax = (uint64_t)-1;  /* not in a syscall: no restart */
    if (ptrace(PTRACE_SETREGS, pid, NULL, &r) < 0) return -1;

    if (mc->mc_fpformat == FBSD_MC_FPFMT_XMM) {
        struct user_fpregs_struct fp;
        memcpy(&fp, mc->mc_fpstate, sizeof(fp));
        fp.mxcsr &= 0xffff;  /* reserved high bits must be clear */
        (void)ptrace(PTRACE_SETFPREGS, pid, NULL, &fp);
    }

    if (p) {
        p->blocked = uc.uc_sigmask;
        fs_sanitize(&p->blocked);
        p->in_sigsuspend = 0;
    }
    return 0;
}

/*
 * Start the handler for fsig: write a FreeBSD signal frame below the
 * current stack (or on the alternate stack) and set the registers.
 * r holds the current registers and is updated. Returns 0, or -1 if the
 * frame could not be written.
 */
static int deliver(pid_t pid, sig_proc_t *p, int fsig,
                   const struct fbsd_siginfo *si, struct user_regs_struct *r) {
    uint64_t handler = p->handler[fsig];
    int fl = p->flags[fsig];
    struct user_regs_struct saved = *r;

    /* Interrupted syscall: restart it after the handler, or fail it
     * with EINTR, as FreeBSD does for SA_RESTART. orig_rax holds the
     * FreeBSD number (put back at syscall exit). */
    if ((int64_t)r->orig_rax >= 0) {
        int64_t rv = (int64_t)r->rax;
        if (rv == -L_ERESTARTNOINTR ||
            (rv == -L_ERESTARTSYS && (fl & FBSD_SA_RESTART))) {
            saved.rax = r->orig_rax;
            saved.rip -= 2;  /* back to the syscall instruction */
        } else if (rv == -L_ERESTARTSYS || rv == -L_ERESTARTNOHAND ||
                   rv == -L_ERESTART_RESTARTBLOCK) {
            saved.rax = 4;              /* EINTR */
            saved.eflags |= RFLAGS_CF;  /* FreeBSD error convention */
        }
        p->restart_block = 0;
    }

    int was_on_alt = on_altstack(p, r->rsp);
    uint64_t sp;
    int onstack;
    if ((fl & FBSD_SA_ONSTACK) && !(p->altstack.ss_flags & FBSD_SS_DISABLE) &&
        p->altstack.ss_size && !was_on_alt) {
        sp = p->altstack.ss_sp + p->altstack.ss_size;
        onstack = 1;
    } else {
        sp = r->rsp - 128;  /* skip the red zone */
        onstack = was_on_alt;
    }
    sp -= sizeof(struct fbsd_siginfo);
    sp &= ~15ULL;
    uint64_t frame_si = sp;
    sp -= sizeof(struct fbsd_ucontext);
    sp &= ~63ULL;
    uint64_t uc_addr = sp;
    sp -= 8;  /* return address: handler entry sees rsp % 16 == 8 */

    struct fbsd_ucontext uc;
    memset(&uc, 0, sizeof(uc));
    uc.uc_sigmask = p->in_sigsuspend ? p->saved_mask : p->blocked;
    fill_mcontext(pid, &uc.uc_mcontext, &saved, si->fs_addr);
    uc.uc_mcontext.mc_onstack = (uint64_t)onstack;
    uc.uc_stack = p->altstack;
    if (onstack) uc.uc_stack.ss_flags |= FBSD_SS_ONSTACK;

    uint64_t ret = SIG_RETURN_MAGIC;
    if (wr(pid, si, frame_si, sizeof(*si)) < 0 ||
        wr(pid, &uc, uc_addr, sizeof(uc)) < 0 ||
        wr(pid, &ret, sp, sizeof(ret)) < 0) {
        BSD_WARN("signal: cannot write frame for signal %d at 0x%lx", fsig, (unsigned long)sp);
        return -1;
    }

    r->rip = handler;
    r->rsp = sp;
    r->rdi = (uint64_t)fsig;
    r->rsi = (fl & FBSD_SA_SIGINFO) ? frame_si : (uint64_t)(int64_t)si->fs_code;
    r->rdx = uc_addr;
    r->rcx = si->fs_addr;
    r->rax = 0;
    r->eflags &= ~(RFLAGS_DF | RFLAGS_TF);
    r->orig_rax = (uint64_t)-1;  /* no syscall restart by the kernel */
    if (ptrace(PTRACE_SETREGS, pid, NULL, r) < 0) return -1;

    /* Mask while the handler runs */
    p->in_sigsuspend = 0;
    fs_or(&p->blocked, &p->hmask[fsig]);
    if (!(fl & FBSD_SA_NODEFER)) fs_add(&p->blocked, fsig);
    fs_sanitize(&p->blocked);
    if (fl & FBSD_SA_RESETHAND) {
        p->handler[fsig] = FBSD_SIG_DFL;
        p->flags[fsig] &= ~FBSD_SA_SIGINFO;
    }
    BSD_TRACE("signal: delivered %d to pid %d, handler 0x%lx", fsig, pid, (unsigned long)handler);
    return 0;
}

static void pend(sig_proc_t *p, int fsig, const struct fbsd_siginfo *si) {
    fs_add(&p->pending, fsig);
    p->pinfo[fsig] = *si;
}

/* Lowest pending, unblocked signal that still needs action; pending
 * signals that are now ignored are dropped. 0 if none. */
static int next_ready(sig_proc_t *p) {
    for (int s = 1; s <= FBSD_NSIG; s++) {
        if (!fs_has(&p->pending, s) || fs_has(&p->blocked, s)) continue;
        uint64_t h = p->handler[s];
        if (h == FBSD_SIG_IGN || (h == FBSD_SIG_DFL && default_ignored(s))) {
            fs_del(&p->pending, s);
            continue;
        }
        return s;
    }
    return 0;
}

/* Deliver one pending signal that is no longer blocked. */
static void deliver_pending(pid_t pid, sig_proc_t *p) {
    int s = next_ready(p);
    if (s < 1 || s > FBSD_NSIG || fastblocked(pid, p) || kq_busy(pid)) return;
    fs_del(&p->pending, s);
    if (p->handler[s] == FBSD_SIG_DFL) {
        /* Default action (terminate, stop): let the kernel do it. */
        int lsig = sig_fbsd_to_linux(s);
        if (lsig) syscall(SYS_tgkill, pid, pid, lsig);
        return;
    }
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r) < 0) return;
    if (deliver(pid, p, s, &p->pinfo[s], &r) < 0) syscall(SYS_tgkill, pid, pid, SIGSEGV);
}

/* A signal the process is waiting for in sigwait/sigtimedwait arrived:
 * make the syscall return it. */
static void complete_wait(pid_t pid, sig_proc_t *p, int fsig,
                          const struct fbsd_siginfo *si) {
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r) < 0) return;
    if (p->wait_kind == WAIT_SIGWAIT) {
        int32_t v = fsig;
        if (p->wait_out) (void)wr(pid, &v, p->wait_out, sizeof(v));
        r.rax = 0;
    } else {
        if (p->wait_out) (void)wr(pid, si, p->wait_out, sizeof(*si));
        r.rax = (uint64_t)fsig;
    }
    r.eflags &= ~RFLAGS_CF;
    r.orig_rax = (uint64_t)-1;
    (void)ptrace(PTRACE_SETREGS, pid, NULL, &r);
    p->wait_kind = WAIT_NONE;
}

/* ---------------------------------------------------------------------
 * Tracer hooks
 * ------------------------------------------------------------------- */

int sig_on_signal(pid_t pid, int lsig) {
    sig_proc_t *p = get_proc(pid);
    if (!p) return lsig;

    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r) < 0) return lsig;

    /* A handler returned: finish its sigreturn. */
    if (lsig == SIGSEGV && r.rip == SIG_RETURN_MAGIC) {
        if (restore_context(pid, p, r.rsp) < 0) return SIGSEGV;
        deliver_pending(pid, p);
        return 0;
    }
    if (lsig == SIGKILL || lsig == SIGSTOP) return lsig;

    int fsig = sig_linux_to_fbsd(lsig);
    if (!fsig) return lsig;

    siginfo_t lsi;
    int have = ptrace(PTRACE_GETSIGINFO, pid, NULL, &lsi) == 0;
    struct fbsd_siginfo si;
    convert_siginfo(&lsi, have, fsig, &si);

    if (p->wait_kind && fs_has(&p->waitset, fsig)) {
        complete_wait(pid, p, fsig, &si);
        return 0;
    }

    uint64_t h = p->handler[fsig];
    int fault = have && lsi.si_code > 0 &&
                (fsig == FBSD_SIGSEGV || fsig == FBSD_SIGBUS || fsig == FBSD_SIGILL ||
                 fsig == FBSD_SIGFPE || fsig == FBSD_SIGTRAP);
    /* A blocked or ignored fault cannot be deferred: default action. */
    if (fault && (fs_has(&p->blocked, fsig) || h == FBSD_SIG_IGN)) return lsig;

    if (h == FBSD_SIG_IGN) return 0;
    if (fsig == FBSD_SIGCHLD && (p->flags[fsig] & FBSD_SA_NOCLDSTOP) && have &&
        (lsi.si_code == CLD_STOPPED || lsi.si_code == CLD_CONTINUED))
        return 0;
    if (fs_has(&p->blocked, fsig)) {
        pend(p, fsig, &si);
        return 0;
    }
    if (h == FBSD_SIG_DFL) return default_ignored(fsig) ? 0 : lsig;
    if (fastblocked(pid, p) || kq_busy(pid)) {
        /* Deferred: delivered when the process leaves the critical
         * section, or when its kevent() chain returns. */
        pend(p, fsig, &si);
        return 0;
    }
    if (deliver(pid, p, fsig, &si, &r) < 0) return SIGSEGV;
    return 0;
}

int sig_on_syscall_entry(pid_t pid, uint64_t nr) {
    sig_proc_t *p = find_proc(pid);
    if (!p) return 0;
    if (p->restart_block) {
        p->restart_block = 0;
        if (nr == L_NR_restart_syscall) return 1;
    }
    /* sigsuspend's temporary mask ends when the process moves on */
    if (p->in_sigsuspend && nr != FBSD_SYS_sigsuspend) {
        p->blocked = p->saved_mask;
        p->in_sigsuspend = 0;
    }
    p->wait_kind = WAIT_NONE;
    return 0;
}

void sig_note_restart_block(pid_t pid) {
    sig_proc_t *p = find_proc(pid);
    if (p) p->restart_block = 1;
}

static int fbsd_wait_status(int st) {
    int low = st & 0x7f;
    if ((st & 0xffff) == 0xffff) return FBSD_W_CONTINUED;
    if (low == 0) return st;                                   /* exited */
    if (low == 0x7f)                                           /* stopped */
        return (st & ~0xff00) | (sig_linux_to_fbsd((st >> 8) & 0xff) << 8);
    return (st & ~0x7f) | sig_linux_to_fbsd(low);              /* killed */
}

uint64_t sig_wait_options_to_linux(uint64_t o) {
    uint64_t l = 0;
    if (o & FBSD_WNOHANG)     l |= 1;           /* WNOHANG */
    if (o & FBSD_WUNTRACED)   l |= 2;           /* WUNTRACED */
    if (o & FBSD_WCONTINUED)  l |= 8;           /* WCONTINUED */
    if (o & FBSD_WLINUXCLONE) l |= 0x80000000;  /* __WCLONE */
    return l;
}

static void finish_wait6(pid_t pid, const uint64_t args[6]);
static void finish_fcntl(pid_t pid, const uint64_t args[6]);

void sig_after_syscall(pid_t pid, uint64_t nr, const uint64_t args[6]) {
    if ((nr == FBSD_SYS_wait4 || nr == FBSD_SYS_wait6) && args[1]) {
        struct user_regs_struct r;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &r) == 0 &&
            !(r.eflags & RFLAGS_CF) && (int64_t)r.rax > 0) {
            int32_t st;
            if (rd(pid, &st, args[1], sizeof(st)) == 0) {
                int32_t f = fbsd_wait_status(st);
                if (f != st) (void)wr(pid, &f, args[1], sizeof(f));
            }
        }
    }
    if (nr == FBSD_SYS_wait6) finish_wait6(pid, args);
    if (nr == FBSD_SYS_fcntl) finish_fcntl(pid, args);
    if (nr == FBSD_SYS_sigwait) {
        /* sigwait(2) returns an error number as its value, not -1/errno */
        struct user_regs_struct r;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &r) == 0 && (r.eflags & RFLAGS_CF)) {
            r.eflags &= ~RFLAGS_CF;
            (void)ptrace(PTRACE_SETREGS, pid, NULL, &r);
        }
    }

    sig_proc_t *p = find_proc(pid);
    if (!p) return;
    if (p->restore_uc) {
        uint64_t uc = p->restore_uc;
        p->restore_uc = 0;
        if (restore_context(pid, p, uc) < 0) syscall(SYS_tgkill, pid, pid, SIGSEGV);
    }
    deliver_pending(pid, p);
}

/* ---------------------------------------------------------------------
 * Emulated syscalls
 * ------------------------------------------------------------------- */

long sig_emul_sigaction(pid_t pid, uint64_t args[6]) {
    int sig = (int)args[0];
    uint64_t act = args[1], oact = args[2];
    sig_proc_t *p = get_proc(pid);
    if (!p) return -ENOMEM;
    if (sig < 1 || sig > FBSD_NSIG) return -EINVAL;

    struct fbsd_sigaction na;
    if (act) {
        if (rd(pid, &na, act, sizeof(na)) < 0) return -EFAULT;
        if (sig == FBSD_SIGKILL || sig == FBSD_SIGSTOP) return -EINVAL;
    }
    if (oact) {
        struct fbsd_sigaction oa;
        oa.handler = p->handler[sig];
        oa.flags = p->flags[sig];
        oa.mask = p->hmask[sig];
        if (wr(pid, &oa, oact, sizeof(oa)) < 0) return -EFAULT;
    }
    if (act) {
        p->handler[sig] = na.handler;
        p->flags[sig] = na.flags;
        p->hmask[sig] = na.mask;
        fs_sanitize(&p->hmask[sig]);
        /* Setting SIG_IGN (or SIG_DFL for a default-ignored signal)
         * discards it if pending. */
        if (na.handler == FBSD_SIG_IGN ||
            (na.handler == FBSD_SIG_DFL && default_ignored(sig)))
            fs_del(&p->pending, sig);
        BSD_TRACE("sigaction: pid %d sig %d handler 0x%lx flags 0x%x",
                  pid, sig, (unsigned long)na.handler, na.flags);
    }
    return 0;
}

long sig_emul_sigprocmask(pid_t pid, uint64_t args[6]) {
    int how = (int)args[0];
    uint64_t set = args[1], oset = args[2];
    sig_proc_t *p = get_proc(pid);
    if (!p) return -ENOMEM;

    fset_t old = p->blocked;
    if (set) {
        fset_t s;
        if (rd(pid, &s, set, sizeof(s)) < 0) return -EFAULT;
        switch (how) {
            case FBSD_SIG_BLOCK:   fs_or(&p->blocked, &s); break;
            case FBSD_SIG_UNBLOCK: fs_andnot(&p->blocked, &s); break;
            case FBSD_SIG_SETMASK: p->blocked = s; break;
            default: return -EINVAL;
        }
        fs_sanitize(&p->blocked);
    }
    if (oset && wr(pid, &old, oset, sizeof(old)) < 0) return -EFAULT;
    /* Signals it unblocked are delivered at syscall exit. */
    return 0;
}

long sig_emul_sigpending(pid_t pid, uint64_t args[6]) {
    sig_proc_t *p = get_proc(pid);
    if (!p) return -ENOMEM;
    fset_t s = p->pending;
    if (args[0] && wr(pid, &s, args[0], sizeof(s)) < 0) return -EFAULT;
    return 0;
}

/* An empty Linux sigset_t below the stack, for the Linux syscall that
 * does the blocking. Returns its address or 0. */
static uint64_t scratch_empty_set(pid_t pid) {
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r) < 0) return 0;
    uint64_t addr = (r.rsp - 1024) & ~15ULL;
    uint64_t zero = 0;
    if (wr(pid, &zero, addr, sizeof(zero)) < 0) return 0;
    return addr;
}

long sig_emul_sigsuspend(pid_t pid, uint64_t args[6]) {
    sig_proc_t *p = get_proc(pid);
    if (!p) return -ENOMEM;
    fset_t mask;
    if (rd(pid, &mask, args[0], sizeof(mask)) < 0) return -EFAULT;
    if (!p->in_sigsuspend) {
        p->saved_mask = p->blocked;
        p->in_sigsuspend = 1;
    }
    p->blocked = mask;
    fs_sanitize(&p->blocked);

    /* A signal is already waiting: return EINTR, deliver it at exit. */
    if (next_ready(p)) return -EINTR;

    /* Wait in the kernel until any signal arrives. The tracer decides at
     * the signal stop whether it ends the wait; if not, the kernel
     * restarts this syscall. */
    uint64_t empty = scratch_empty_set(pid);
    if (!empty) return -EFAULT;
    args[0] = empty;
    args[1] = 8;
    return -EAGAIN;  /* run Linux rt_sigsuspend */
}

long sig_emul_sigreturn(pid_t pid, uint64_t args[6]) {
    sig_proc_t *p = get_proc(pid);
    if (!p) return -ENOMEM;
    if (!args[0]) return -EFAULT;
    p->restore_uc = args[0];  /* finished at syscall exit */
    return 0;
}

long sig_emul_setcontext(pid_t pid, uint64_t args[6]) {
    return sig_emul_sigreturn(pid, args);
}

/* Save the current context (as of the instruction after the syscall,
 * returning 0) into a FreeBSD ucontext_t at ucp. */
static long save_context(pid_t pid, sig_proc_t *p, uint64_t ucp) {
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r) < 0) return -EFAULT;
    r.rax = 0;
    r.eflags &= ~RFLAGS_CF;
    struct fbsd_ucontext uc;
    memset(&uc, 0, sizeof(uc));
    uc.uc_sigmask = p->blocked;
    fill_mcontext(pid, &uc.uc_mcontext, &r, 0);
    uc.uc_mcontext.mc_onstack = (uint64_t)on_altstack(p, r.rsp);
    uc.uc_stack = p->altstack;
    if (wr(pid, &uc, ucp, sizeof(uc)) < 0) return -EFAULT;
    return 0;
}

long sig_emul_getcontext(pid_t pid, uint64_t args[6]) {
    sig_proc_t *p = get_proc(pid);
    if (!p) return -ENOMEM;
    if (!args[0]) return -EINVAL;
    return save_context(pid, p, args[0]);
}

long sig_emul_swapcontext(pid_t pid, uint64_t args[6]) {
    sig_proc_t *p = get_proc(pid);
    if (!p) return -ENOMEM;
    if (!args[0] || !args[1]) return -EINVAL;
    long rv = save_context(pid, p, args[0]);
    if (rv < 0) return rv;
    p->restore_uc = args[1];
    return 0;
}

long sig_emul_sigaltstack(pid_t pid, uint64_t args[6]) {
    sig_proc_t *p = get_proc(pid);
    if (!p) return -ENOMEM;
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r) < 0) return -EFAULT;
    int onstack = on_altstack(p, r.rsp);

    struct fbsd_stack ns;
    if (args[0] && rd(pid, &ns, args[0], sizeof(ns)) < 0) return -EFAULT;
    if (args[1]) {
        struct fbsd_stack os = p->altstack;
        if (onstack) os.ss_flags |= FBSD_SS_ONSTACK;
        if (wr(pid, &os, args[1], sizeof(os)) < 0) return -EFAULT;
    }
    if (args[0]) {
        if (onstack) return -EPERM;
        if (ns.ss_flags & ~FBSD_SS_DISABLE) return -EINVAL;
        if (ns.ss_flags & FBSD_SS_DISABLE) {
            p->altstack.ss_flags = FBSD_SS_DISABLE;
        } else {
            if (ns.ss_size < FBSD_MINSIGSTKSZ) return -ENOMEM;
            p->altstack = ns;
            p->altstack.ss_flags = 0;
        }
    }
    return 0;
}

long sig_emul_sigfastblock(pid_t pid, uint64_t args[6]) {
    sig_proc_t *p = get_proc(pid);
    if (!p) return -ENOMEM;
    switch ((int)args[0]) {
        case FBSD_SIGFASTBLOCK_SETPTR:
            if (p->fastblock_ptr) return -EBUSY;
            if (args[1] & 3) return -EINVAL;
            p->fastblock_ptr = args[1];
            return 0;
        case FBSD_SIGFASTBLOCK_UNBLOCK: {
            if (!p->fastblock_ptr) return -EINVAL;
            uint32_t word;
            if (rd(pid, &word, p->fastblock_ptr, sizeof(word)) < 0) return -EFAULT;
            if (word & ~(uint32_t)FBSD_SIGFASTBLOCK_FLAGS) return -EBUSY;
            word &= ~(uint32_t)FBSD_SIGFASTBLOCK_PEND;
            if (wr(pid, &word, p->fastblock_ptr, sizeof(word)) < 0) return -EFAULT;
            return 0;  /* deferred signals are delivered at exit */
        }
        case FBSD_SIGFASTBLOCK_UNSETPTR:
            if (!p->fastblock_ptr) return -EINVAL;
            p->fastblock_ptr = 0;
            return 0;
        default:
            return -EINVAL;
    }
}

/* Common part of sigwait, sigtimedwait and sigwaitinfo. */
static long wait_common(pid_t pid, uint64_t args[6], int kind,
                        uint64_t out, uint64_t timeout) {
    sig_proc_t *p = get_proc(pid);
    if (!p) return -ENOMEM;
    fset_t set;
    if (rd(pid, &set, args[0], sizeof(set)) < 0) return -EFAULT;
    fs_sanitize(&set);

    for (int s = 1; s <= FBSD_NSIG; s++) {
        if (fs_has(&set, s) && fs_has(&p->pending, s)) {
            fs_del(&p->pending, s);
            if (kind == WAIT_SIGWAIT) {
                int32_t v = s;
                if (out && wr(pid, &v, out, sizeof(v)) < 0) return -EFAULT;
                return 0;
            }
            if (out && wr(pid, &p->pinfo[s], out, sizeof(p->pinfo[s])) < 0) return -EFAULT;
            return s;
        }
    }

    uint64_t empty = scratch_empty_set(pid);
    if (!empty) return -EFAULT;
    p->wait_kind = kind;
    p->waitset = set;
    p->wait_out = out;
    /* Linux rt_sigtimedwait(empty set, NULL, timeout, 8): sleeps until a
     * signal arrives or the timeout ends; the tracer completes it at the
     * signal stop if the signal is in set. */
    args[0] = empty;
    args[1] = 0;
    args[2] = timeout;
    args[3] = 8;
    return -EAGAIN;  /* run Linux rt_sigtimedwait */
}

long sig_emul_sigwait(pid_t pid, uint64_t args[6]) {
    return wait_common(pid, args, WAIT_SIGWAIT, args[1], 0);
}

long sig_emul_sigtimedwait(pid_t pid, uint64_t args[6]) {
    return wait_common(pid, args, WAIT_TIMEDWAIT, args[1], args[2]);
}

long sig_emul_sigwaitinfo(pid_t pid, uint64_t args[6]) {
    return wait_common(pid, args, WAIT_TIMEDWAIT, args[1], 0);
}

/* ---------------------------------------------------------------------
 * procctl(2): the reaper commands (used by timeout(1), daemon(8), and
 * service supervisors) and PROC_PDEATHSIG_CTL
 * ------------------------------------------------------------------- */

#define FBSD_PROC_REAP_ACQUIRE    2
#define FBSD_PROC_REAP_RELEASE    3
#define FBSD_PROC_REAP_STATUS     4
#define FBSD_PROC_REAP_KILL       6
#define FBSD_PROC_PDEATHSIG_CTL   11
#define FBSD_REAPER_STATUS_OWNED  0x1
#define FBSD_REAPER_KILL_CHILDREN 0x1
#define FBSD_REAPER_KILL_SUBTREE  0x2
#define L_PR_SET_PDEATHSIG        1
#define L_PR_SET_CHILD_SUBREAPER  36

struct fbsd_reaper_status {
    uint32_t rs_flags, rs_children, rs_descendants;
    int32_t  rs_reaper, rs_pid;
    uint32_t rs_pad0[15];
};
_Static_assert(sizeof(struct fbsd_reaper_status) == 80, "procctl_reaper_status");

struct fbsd_reaper_kill {
    int32_t  rk_sig;
    uint32_t rk_flags;
    int32_t  rk_subtree;
    uint32_t rk_killed;
    int32_t  rk_fpid;
    uint32_t rk_pad0[15];
};
_Static_assert(sizeof(struct fbsd_reaper_kill) == 80, "procctl_reaper_kill");

#define MAX_REAPERS 64
static pid_t reapers[MAX_REAPERS];

static int is_reaper(pid_t pid) {
    for (int i = 0; i < MAX_REAPERS; i++) if (reapers[i] == pid) return 1;
    return 0;
}
static void set_reaper(pid_t pid, int on) {
    for (int i = 0; i < MAX_REAPERS; i++) {
        if (on && reapers[i] == 0) { reapers[i] = pid; return; }
        if (!on && reapers[i] == pid) { reapers[i] = 0; return; }
    }
}

/* All processes with their parents, from /proc. Returns the count. */
static int list_processes(pid_t *pids, pid_t *ppids, int max) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    int n = 0;
    struct dirent *e;
    while (n < max && (e = readdir(d))) {
        char *end;
        long v = strtol(e->d_name, &end, 10);
        if (*end || v <= 0) continue;
        char path[64], line[128];
        snprintf(path, sizeof(path), "/proc/%ld/status", v);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        pid_t pp = 0;
        while (fgets(line, sizeof(line), f))
            if (strncmp(line, "PPid:", 5) == 0) { pp = (pid_t)atoi(line + 5); break; }
        fclose(f);
        pids[n] = (pid_t)v;
        ppids[n] = pp;
        n++;
    }
    closedir(d);
    return n;
}

/* Descendants of root (children first when children_only). */
static int descendants(pid_t root, int children_only, pid_t *out, int max) {
    enum { N = 4096 };
    static pid_t pids[N], ppids[N];
    int n = list_processes(pids, ppids, N);
    int cnt = 0;
    pid_t queue[N];
    int qh = 0, qt = 0;
    queue[qt++] = root;
    while (qh < qt && cnt < max) {
        pid_t cur = queue[qh++];
        for (int i = 0; i < n && cnt < max; i++) {
            if (ppids[i] != cur) continue;
            out[cnt++] = pids[i];
            if (!children_only && qt < N) queue[qt++] = pids[i];
        }
    }
    return cnt;
}

long sig_emul_procctl(pid_t pid, uint64_t args[6]) {
    int cmd = (int)args[2];
    uint64_t data = args[3];
    pid_t target = (args[1] == 0) ? pid : (pid_t)args[1];

    switch (cmd) {
        case FBSD_PROC_REAP_ACQUIRE:
        case FBSD_PROC_REAP_RELEASE:
            if (target != pid) return -EINVAL;
            set_reaper(pid, cmd == FBSD_PROC_REAP_ACQUIRE);
            /* The process itself must become a Linux child subreaper */
            args[0] = L_PR_SET_CHILD_SUBREAPER;
            args[1] = cmd == FBSD_PROC_REAP_ACQUIRE;
            args[2] = args[3] = args[4] = 0;
            return -EAGAIN;  /* run Linux prctl */

        case FBSD_PROC_REAP_STATUS: {
            struct fbsd_reaper_status rs;
            memset(&rs, 0, sizeof(rs));
            pid_t kids[1024];
            int nc = descendants(target, 1, kids, 1024);
            pid_t all[4096];
            int nd = descendants(target, 0, all, 4096);
            rs.rs_flags = is_reaper(target) ? FBSD_REAPER_STATUS_OWNED : 0;
            rs.rs_children = (uint32_t)nc;
            rs.rs_descendants = (uint32_t)nd;
            rs.rs_reaper = is_reaper(target) ? target : 1;
            rs.rs_pid = nc > 0 ? kids[0] : -1;
            if (wr(pid, &rs, data, sizeof(rs)) < 0) return -EFAULT;
            return 0;
        }

        case FBSD_PROC_REAP_KILL: {
            struct fbsd_reaper_kill rk;
            if (rd(pid, &rk, data, sizeof(rk)) < 0) return -EFAULT;
            int lsig = sig_fbsd_to_linux(rk.rk_sig);
            if (!lsig) return -EINVAL;
            pid_t victims[4096];
            int nv = descendants(target, (rk.rk_flags & FBSD_REAPER_KILL_CHILDREN) != 0,
                                 victims, 4096);
            rk.rk_killed = 0;
            rk.rk_fpid = -1;
            for (int i = 0; i < nv; i++) {
                if (kill(victims[i], lsig) == 0) rk.rk_killed++;
                else if (rk.rk_fpid == -1) rk.rk_fpid = victims[i];
            }
            if (wr(pid, &rk, data, sizeof(rk)) < 0) return -EFAULT;
            return 0;
        }

        case FBSD_PROC_PDEATHSIG_CTL: {
            int32_t fsig;
            if (target != pid) return -EINVAL;
            if (rd(pid, &fsig, data, sizeof(fsig)) < 0) return -EFAULT;
            int lsig = fsig ? sig_fbsd_to_linux(fsig) : 0;
            if (fsig && !lsig) return -EINVAL;
            args[0] = L_PR_SET_PDEATHSIG;
            args[1] = (uint64_t)lsig;
            args[2] = args[3] = args[4] = 0;
            return -EAGAIN;  /* run Linux prctl */
        }

        default:
            return -EINVAL;
    }
}

/* ---------------------------------------------------------------------
 * wait6(2): FreeBSD libc's waitpid() and waitid() use it
 * ------------------------------------------------------------------- */

#define FBSD_P_PID   0
#define FBSD_P_PGID  2
#define FBSD_P_ALL   7

/* siginfo_t pointer of a wait6 in progress, per process */
#define MAX_WAIT6 64
static struct { pid_t pid; uint64_t info; } wait6_info[MAX_WAIT6];

static void set_wait6_info(pid_t pid, uint64_t info) {
    int free_slot = -1;
    for (int i = 0; i < MAX_WAIT6; i++) {
        if (wait6_info[i].pid == pid) { wait6_info[i].info = info; return; }
        if (free_slot < 0 && wait6_info[i].pid == 0) free_slot = i;
    }
    if (free_slot >= 0) { wait6_info[free_slot].pid = pid; wait6_info[free_slot].info = info; }
}

static uint64_t take_wait6_info(pid_t pid) {
    for (int i = 0; i < MAX_WAIT6; i++) {
        if (wait6_info[i].pid == pid) {
            uint64_t v = wait6_info[i].info;
            wait6_info[i].pid = 0;
            wait6_info[i].info = 0;
            return v;
        }
    }
    return 0;
}

long sig_emul_wait6(pid_t pid, uint64_t args[6]) {
    /* wait6(idtype, id, status, options, wrusage, info) */
    int idtype = (int)args[0];
    int64_t id = (int64_t)args[1];
    int64_t lpid;
    switch (idtype) {
        case FBSD_P_PID:  lpid = id; break;
        case FBSD_P_PGID: lpid = id ? -id : 0; break;
        case FBSD_P_ALL:  lpid = -1; break;
        default: return -EINVAL;
    }
    set_wait6_info(pid, args[5]);
    uint64_t status = args[2], options = args[3], wrusage = args[4];
    /* Linux wait4(pid, status, options, rusage): wru_self is the first
     * member of FreeBSD's struct __wrusage and has the same layout. */
    args[0] = (uint64_t)lpid;
    args[1] = status;
    args[2] = sig_wait_options_to_linux(options);
    args[3] = wrusage;
    args[4] = args[5] = 0;
    return -EAGAIN;  /* run Linux wait4 */
}

/* At wait6 exit: status was fixed like wait4's; fill siginfo if asked. */
static void finish_wait6(pid_t pid, const uint64_t args[6]) {
    uint64_t info = take_wait6_info(pid);
    if (!info) return;
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r) < 0) return;
    if ((r.eflags & RFLAGS_CF) || (int64_t)r.rax <= 0) return;
    struct fbsd_siginfo si;
    memset(&si, 0, sizeof(si));
    int32_t st = 0;
    if (args[1]) (void)rd(pid, &st, args[1], sizeof(st));  /* already FreeBSD form */
    si.fs_signo = FBSD_SIGCHLD;
    si.fs_pid = (int32_t)r.rax;
    if (st == FBSD_W_CONTINUED) {
        si.fs_code = CLD_CONTINUED;
        si.fs_status = FBSD_SIGCONT;
    } else if ((st & 0x7f) == 0) {
        si.fs_code = CLD_EXITED;
        si.fs_status = (st >> 8) & 0xff;
    } else if ((st & 0x7f) == 0x7f) {
        si.fs_code = CLD_STOPPED;
        si.fs_status = (st >> 8) & 0xff;
    } else {
        si.fs_code = (st & 0x80) ? CLD_DUMPED : CLD_KILLED;
        si.fs_status = st & 0x7f;
    }
    (void)wr(pid, &si, info, sizeof(si));
}

/* ---------------------------------------------------------------------
 * fcntl(2): command numbers, F_GETFL/F_SETFL flags and struct flock
 * differ from Linux. (Kept here because it needs the after-syscall hook.)
 * ------------------------------------------------------------------- */

#define FBSD_F_GETFL     3
#define FBSD_F_SETFL     4
#define FBSD_F_GETOWN    5
#define FBSD_F_SETOWN    6
#define FBSD_F_OGETLK    7
#define FBSD_F_OSETLK    8
#define FBSD_F_OSETLKW   9
#define FBSD_F_GETLK     11
#define FBSD_F_SETLK     12
#define FBSD_F_SETLKW    13
#define FBSD_F_READAHEAD 15
#define FBSD_F_RDAHEAD   16
#define FBSD_F_DUPFD_CLOEXEC 17
#define FBSD_F_ADD_SEALS 19
#define FBSD_F_GET_SEALS 20

#define L_F_GETFL   3
#define L_F_GETLK   5
#define L_F_SETLK   6
#define L_F_SETLKW  7

struct fbsd_flock {           /* struct flock; __oflock is the first 24 bytes */
    int64_t l_start;
    int64_t l_len;
    int32_t l_pid;
    int16_t l_type;
    int16_t l_whence;
    int32_t l_sysid;
    int32_t pad;
};
_Static_assert(sizeof(struct fbsd_flock) == 32, "FreeBSD struct flock");

struct linux_flock {
    int16_t l_type;
    int16_t l_whence;
    int32_t pad0;
    int64_t l_start;
    int64_t l_len;
    int32_t l_pid;
    int32_t pad1;
};
_Static_assert(sizeof(struct linux_flock) == 32, "Linux struct flock");

/* A lock buffer converted to Linux layout for a call in progress */
#define MAX_FLOCK 64
static struct { pid_t pid; uint64_t addr; int old; int32_t sysid; } flock_conv[MAX_FLOCK];

static int find_flock(pid_t pid) {
    for (int i = 0; i < MAX_FLOCK; i++) if (flock_conv[i].pid == pid) return i;
    return -1;
}

int abi_translate_open_flags(int freebsd_flags);
int abi_translate_open_flags_to_freebsd(int linux_flags);

long sig_emul_fcntl(pid_t pid, uint64_t args[6]) {
    int cmd = (int)args[1];
    int lcmd;
    switch (cmd) {
        case 0: case 1: case 2: case 3: lcmd = cmd; break;  /* DUPFD GETFD SETFD GETFL */
        case FBSD_F_SETFL:
            args[2] = (uint64_t)(uint32_t)abi_translate_open_flags((int)args[2]);
            lcmd = 4;
            break;
        case FBSD_F_GETOWN: lcmd = 9; break;
        case FBSD_F_SETOWN: lcmd = 8; break;
        case FBSD_F_DUPFD_CLOEXEC: lcmd = 1030; break;
        case FBSD_F_ADD_SEALS: lcmd = 1033; break;
        case FBSD_F_GET_SEALS: lcmd = 1034; break;
        case FBSD_F_READAHEAD: case FBSD_F_RDAHEAD:
            return 0;  /* advisory; nothing to do */
        case FBSD_F_GETLK: case FBSD_F_OGETLK: lcmd = L_F_GETLK; break;
        case FBSD_F_SETLK: case FBSD_F_OSETLK: lcmd = L_F_SETLK; break;
        case FBSD_F_SETLKW: case FBSD_F_OSETLKW: lcmd = L_F_SETLKW; break;
        default:
            return -EINVAL;
    }

    if (lcmd == L_F_GETLK || lcmd == L_F_SETLK || lcmd == L_F_SETLKW) {
        int old = cmd == FBSD_F_OGETLK || cmd == FBSD_F_OSETLK || cmd == FBSD_F_OSETLKW;
        int i = find_flock(pid);
        /* A restarted call finds the buffer already converted */
        if (i < 0 || flock_conv[i].addr != args[2]) {
            struct fbsd_flock f;
            memset(&f, 0, sizeof(f));
            if (rd(pid, &f, args[2], old ? 24 : 32) < 0) return -EFAULT;
            struct linux_flock l;
            memset(&l, 0, sizeof(l));
            switch (f.l_type) {
                case 1: l.l_type = 0; break;  /* F_RDLCK */
                case 2: l.l_type = 2; break;  /* F_UNLCK */
                case 3: l.l_type = 1; break;  /* F_WRLCK */
                default: return -EINVAL;
            }
            l.l_whence = f.l_whence;
            l.l_start = f.l_start;
            l.l_len = f.l_len;
            l.l_pid = f.l_pid;
            if (old) {
                /* The old struct is only 24 bytes: the converted copy
                 * would overflow it, so it goes below the stack. */
                return -EINVAL;
            }
            if (wr(pid, &l, args[2], sizeof(l)) < 0) return -EFAULT;
            if (i < 0) {
                for (i = 0; i < MAX_FLOCK && flock_conv[i].pid; i++) {}
                if (i == MAX_FLOCK) i = 0;
            }
            flock_conv[i].pid = pid;
            flock_conv[i].addr = args[2];
            flock_conv[i].old = old;
            flock_conv[i].sysid = f.l_sysid;
        }
    }
    args[1] = (uint64_t)lcmd;
    return -EAGAIN;  /* run Linux fcntl */
}

static void finish_fcntl(pid_t pid, const uint64_t args[6]) {
    int lcmd = (int)args[1];
    struct user_regs_struct r;
    if (lcmd == L_F_GETFL) {
        if (ptrace(PTRACE_GETREGS, pid, NULL, &r) == 0 && !(r.eflags & RFLAGS_CF)) {
            r.rax = (uint64_t)(uint32_t)abi_translate_open_flags_to_freebsd((int)r.rax);
            (void)ptrace(PTRACE_SETREGS, pid, NULL, &r);
        }
        return;
    }
    if (lcmd != L_F_GETLK && lcmd != L_F_SETLK && lcmd != L_F_SETLKW) return;
    int i = find_flock(pid);
    if (i < 0) return;
    uint64_t addr = flock_conv[i].addr;
    int32_t sysid = flock_conv[i].sysid;
    flock_conv[i].pid = 0;
    struct linux_flock l;
    if (rd(pid, &l, addr, sizeof(l)) < 0) return;
    struct fbsd_flock f;
    memset(&f, 0, sizeof(f));
    switch (l.l_type) {
        case 0: f.l_type = 1; break;
        case 1: f.l_type = 3; break;
        default: f.l_type = 2; break;
    }
    f.l_whence = l.l_whence;
    f.l_start = l.l_start;
    f.l_len = l.l_len;
    f.l_pid = l.l_pid;
    f.l_sysid = sysid;
    (void)wr(pid, &f, addr, sizeof(f));
}
