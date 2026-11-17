/*
 * thread_emul.c - FreeBSD threads (thr_*, _umtx_op) on Linux clone/futex
 *
 * FreeBSD layouts (sys/thr.h, sys/umtx.h, sys/_umtx.h):
 *   struct thr_param  start_func, arg, stack_base, stack_size, tls_base,
 *                     tls_size, child_tid, parent_tid, flags, rtp, spare
 *   struct umutex     m_owner (u32, thread id | UMUTEX_CONTESTED), m_flags
 *   struct ucond      c_has_waiters, c_flags, c_clockid, c_spare[1]
 *   struct urwlock    rw_state, rw_flags, blocked readers/writers
 *   struct _usem2     _count (| USEM_HAS_WAITERS), _flags
 *
 * Thread ids are Linux tids, so a umutex owner word has the same format as
 * a Linux PI futex word (tid | FUTEX_WAITERS == UMUTEX_CONTESTED).
 *
 * Kernel-side waits are futex waits on the same words. Where FreeBSD's
 * kernel sets a "waiters" bit before sleeping, the bit is set atomically
 * in the thread with FUTEX_WAKE_OP (OR), then FUTEX_WAIT sleeps on the
 * value that includes it, so a concurrent unlock is never missed.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>

#include "bsdulator.h"
#include "bsdulator/interceptor.h"
#include "bsdulator/syscall.h"
#include "bsdulator/chain.h"
#include "bsdulator/signal_emul.h"
#include "bsdulator/thread_emul.h"
#include "bsdulator/pidmap.h"

/* Linux futex */
#define F_WAIT          0
#define F_WAKE          1
#define F_WAKE_OP       5
#define F_LOCK_PI       6
#define F_UNLOCK_PI     7
#define F_TRYLOCK_PI    8
#define F_WAIT_BITSET   9
#define F_CLOCK_RT      256
#define FOP(op, oparg, cmp, cmparg) \
    ((((uint32_t)(op) & 0xf) << 28) | (((uint32_t)(cmp) & 0xf) << 24) | \
     (((uint32_t)(oparg) & 0xfff) << 12) | ((uint32_t)(cmparg) & 0xfff))
#define FO_SET   0
#define FO_ADD   1
#define FO_OR    2
#define FO_ANDN  3
#define FO_SHIFT 8      /* oparg is a shift count: 1 << oparg */
#define FC_EQ    0
#define FC_LT    2

/* FreeBSD umtx */
enum {
    UMTX_OP_WAIT = 2, UMTX_OP_WAKE = 3, UMTX_OP_MUTEX_TRYLOCK = 4,
    UMTX_OP_MUTEX_LOCK = 5, UMTX_OP_MUTEX_UNLOCK = 6, UMTX_OP_SET_CEILING = 7,
    UMTX_OP_CV_WAIT = 8, UMTX_OP_CV_SIGNAL = 9, UMTX_OP_CV_BROADCAST = 10,
    UMTX_OP_WAIT_UINT = 11, UMTX_OP_RW_RDLOCK = 12, UMTX_OP_RW_WRLOCK = 13,
    UMTX_OP_RW_UNLOCK = 14, UMTX_OP_WAIT_UINT_PRIVATE = 15,
    UMTX_OP_WAKE_PRIVATE = 16, UMTX_OP_MUTEX_WAIT = 17,
    UMTX_OP_MUTEX_WAKE = 18, UMTX_OP_NWAKE_PRIVATE = 21,
    UMTX_OP_MUTEX_WAKE2 = 22, UMTX_OP_SEM2_WAIT = 23, UMTX_OP_SEM2_WAKE = 24,
    UMTX_OP_SHM = 25, UMTX_OP_ROBUST_LISTS = 26,
    UMTX_OP_GET_MIN_TIMEOUT = 27, UMTX_OP_SET_MIN_TIMEOUT = 28,
};
#define UMUTEX_CONTESTED      0x80000000u
#define UMUTEX_PRIO_INHERIT   0x0004u
#define UMUTEX_PRIO_PROTECT   0x0008u
#define URWLOCK_WRITE_OWNER   0x80000000u
#define URWLOCK_WRITE_WAITERS 0x40000000u
#define URWLOCK_READ_WAITERS  0x20000000u
#define URWLOCK_MAX_READERS   0x1fffffffu
#define URWLOCK_PREFER_READER 0x0002u
#define USEM_HAS_WAITERS      0x80000000u
#define USEM_COUNT_MASK       0x7fffffffu
#define UMTX_ABSTIME          0x1u
#define CVWAIT_ABSTIME        0x02u
#define CVWAIT_CLOCKID        0x04u
#define FBSD_CLOCK_REALTIME   0

/* Linux clone flags for a thread */
#define THREAD_CLONE_FLAGS (0x100 | 0x200 | 0x400 | 0x800 | 0x10000 | 0x40000) /* VM FS FILES SIGHAND THREAD SYSVSEM */
#define L_CLONE_SETTLS 0x80000

static int rd(pid_t pid, void *d, uint64_t a, size_t n) {
    return interceptor_read_mem(pid, d, (const void *)a, n) == (ssize_t)n ? 0 : -1;
}
static int wr(pid_t pid, const void *s, uint64_t a, size_t n) {
    return interceptor_write_mem(pid, s, (void *)a, n) == (ssize_t)n ? 0 : -1;
}

pid_t thr_tgid(pid_t pid) {
    char path[64], line[128];
    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return pid;
    pid_t tgid = pid;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Tgid:", 5) == 0) { tgid = (pid_t)atoi(line + 5); break; }
    }
    fclose(f);
    return tgid;
}

/* ---------------------------------------------------------------------
 * thr_new / thread start
 * ------------------------------------------------------------------- */

struct fbsd_thr_param {
    uint64_t start_func, arg, stack_base, stack_size, tls_base, tls_size;
    uint64_t child_tid, parent_tid;
    int32_t  flags, pad;
    uint64_t rtp;
    uint64_t spare[3];
};
_Static_assert(sizeof(struct fbsd_thr_param) == 104, "FreeBSD struct thr_param");

#define MAX_PENDING 128
static struct {
    int used;
    pid_t parent, child;
    uint64_t start, arg, sp, ctid, ptid;
} pend[MAX_PENDING];

long thr_emul_new(pid_t pid, uint64_t args[6]) {
    struct fbsd_thr_param tp;
    memset(&tp, 0, sizeof(tp));
    size_t sz = (size_t)args[1];
    if (sz < offsetof(struct fbsd_thr_param, flags) || sz > 4096) return -EINVAL;
    if (sz > sizeof(tp)) sz = sizeof(tp);
    if (rd(pid, &tp, args[0], sz) < 0) return -EFAULT;
    if (!tp.start_func || !tp.stack_base || tp.stack_size < 4096) return -EINVAL;

    int k = -1;
    for (int i = 0; i < MAX_PENDING; i++) if (!pend[i].used) { k = i; break; }
    if (k < 0) return -ENOMEM;

    /* As FreeBSD's cpu_set_upcall(): 16-byte aligned top, minus a
     * return-address slot */
    uint64_t sp = ((tp.stack_base + tp.stack_size) & ~15ULL) - 8;
    pend[k].used = 1;
    pend[k].parent = pid;
    pend[k].child = 0;
    pend[k].start = tp.start_func;
    pend[k].arg = tp.arg;
    pend[k].sp = sp;
    pend[k].ctid = tp.child_tid;
    pend[k].ptid = tp.parent_tid;

    /* Linux clone(flags, stack, parent_tid, child_tid, tls) */
    args[0] = THREAD_CLONE_FLAGS | (tp.tls_base ? L_CLONE_SETTLS : 0);
    args[1] = sp;
    args[2] = 0;
    args[3] = 0;
    args[4] = tp.tls_base;
    args[5] = 0;
    BSD_TRACE("thr_new: pid %d start 0x%lx arg 0x%lx sp 0x%lx tls 0x%lx",
              pid, (unsigned long)tp.start_func, (unsigned long)tp.arg,
              (unsigned long)sp, (unsigned long)tp.tls_base);
    return -EAGAIN;  /* run Linux clone */
}

static void write_tids(pid_t writer, int k, pid_t tid) {
    int64_t v = pid_to_ns(tid);  /* the id the program knows */
    if (pend[k].ctid) (void)wr(writer, &v, pend[k].ctid, sizeof(v));
    if (pend[k].ptid) (void)wr(writer, &v, pend[k].ptid, sizeof(v));
}

static void start_thread(pid_t tid, int k) {
    write_tids(tid, k, tid);
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, tid, NULL, &r) == 0) {
        r.rip = pend[k].start;
        r.rdi = pend[k].arg;
        r.rsp = pend[k].sp;
        r.rax = 0;
        r.orig_rax = (uint64_t)-1;
        (void)ptrace(PTRACE_SETREGS, tid, NULL, &r);
        BSD_INFO("thread %d starts at 0x%lx", tid, (unsigned long)pend[k].start);
    }
    pend[k].used = 0;
}

void thr_on_clone(pid_t parent, pid_t child) {
    for (int i = 0; i < MAX_PENDING; i++) {
        if (pend[i].used && pend[i].parent == parent && pend[i].child == 0) {
            pend[i].child = child;
            /* FreeBSD sets the ids before the thread can run */
            write_tids(parent, i, child);
            return;
        }
    }
}

int thr_on_first_stop(pid_t pid) {
    for (int i = 0; i < MAX_PENDING; i++) {
        if (pend[i].used && pend[i].child == pid) { start_thread(pid, i); return 1; }
    }
    /* The new thread can stop before its creator's clone event: match it
     * by the stack it was created with. */
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r) < 0) return 0;
    for (int i = 0; i < MAX_PENDING; i++) {
        if (pend[i].used && pend[i].child == 0 && pend[i].sp == r.rsp) {
            pend[i].child = pid;
            start_thread(pid, i);
            return 1;
        }
    }
    return 0;
}

void thr_rfork_after_syscall(pid_t pid);

void thr_after_syscall(pid_t pid, uint64_t nr) {
    if (nr == FBSD_SYS_rfork) { thr_rfork_after_syscall(pid); return; }
    if (nr != FBSD_SYS_thr_new) return;
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r) < 0) return;
    if (r.eflags & 1) {
        /* clone failed: drop the start record */
        for (int i = 0; i < MAX_PENDING; i++)
            if (pend[i].used && pend[i].parent == pid && pend[i].child == 0) pend[i].used = 0;
        return;
    }
    r.rax = 0;  /* thr_new returns 0; the id went to child_tid/parent_tid */
    (void)ptrace(PTRACE_SETREGS, pid, NULL, &r);
}

/* ---------------------------------------------------------------------
 * thr_exit / thr_kill
 * ------------------------------------------------------------------- */

static long fin_zero(pid_t pid, const long *res, int n, const uint64_t ctx[4]) {
    (void)pid; (void)res; (void)n; (void)ctx;
    return 0;
}

long thr_emul_exit(pid_t pid, uint64_t args[6]) {
    /* thr_exit(long *state): *state = 1, wake its waiters, end the thread
     * (the process, if it is the last thread) */
    chain_step_t s[2];
    int n = 0;
    if (args[0]) {
        int64_t one = 1;
        (void)wr(pid, &one, args[0], sizeof(one));
        s[n].nr = SYS_futex;
        s[n].a[0] = args[0]; s[n].a[1] = F_WAKE; s[n].a[2] = INT_MAX;
        s[n].a[3] = s[n].a[4] = s[n].a[5] = 0;
        n++;
    }
    s[n].nr = SYS_exit;
    memset(s[n].a, 0, sizeof(s[n].a));
    n++;
    return chain_begin(pid, s, n, fin_zero, NULL);
}

long thr_emul_kill(pid_t pid, uint64_t args[6]) {
    /* thr_kill(long id, int sig) */
    long tid = (long)args[0];
    int fsig = (int)args[1];
    int lsig = fsig ? sig_fbsd_to_linux(fsig) : 0;
    if (fsig && !lsig) return -EINVAL;
    pid_t tgid = thr_tgid(pid);
    if (tid == -1) return kill(tgid, lsig) < 0 ? -errno : 0;
    pid_t htid = pid_from_ns((pid_t)tid, pid);
    if (htid < 0) return -ESRCH;
    return syscall(SYS_tgkill, tgid, htid, lsig) < 0 ? -errno : 0;
}

long thr_emul_kill2(pid_t pid, uint64_t args[6]) {
    /* thr_kill2(pid_t pid, long id, int sig) */
    int fsig = (int)args[2];
    int lsig = fsig ? sig_fbsd_to_linux(fsig) : 0;
    if (fsig && !lsig) return -EINVAL;
    pid_t hp = pid_from_ns((pid_t)args[0], pid), ht = pid_from_ns((pid_t)args[1], pid);
    if (hp < 0 || ht < 0) return -ESRCH;
    return syscall(SYS_tgkill, hp, ht, lsig) < 0 ? -errno : 0;
}

/* ---------------------------------------------------------------------
 * _umtx_op
 * ------------------------------------------------------------------- */

static void step(chain_step_t *s, long nr, uint64_t a0, uint64_t a1, uint64_t a2,
                 uint64_t a3, uint64_t a4, uint64_t a5) {
    s->nr = nr;
    s->a[0] = a0; s->a[1] = a1; s->a[2] = a2; s->a[3] = a3; s->a[4] = a4; s->a[5] = a5;
}

/* futex(obj, WAKE_OP, nr_wake, 0, obj, op): atomic op on *obj, then wake */
static void wake_op(chain_step_t *s, uint64_t obj, uint32_t nr_wake, uint32_t op) {
    step(s, SYS_futex, obj, F_WAKE_OP, nr_wake, 0, obj, op);
}

/*
 * FreeBSD timeout -> futex wait parameters. size/ptr follow _umtx_op's
 * convention (uaddr = sizeof the timeout struct, uaddr2 = pointer).
 * Sets *fop (F_WAIT or F_WAIT_BITSET|clock), *tsp (timespec to pass or 0)
 * and *val3. Returns 0 or -errno.
 */
static int wait_timeout(pid_t pid, uint64_t size, uint64_t ptr,
                        uint64_t *fop, uint64_t *tsp, uint64_t *val3) {
    *fop = F_WAIT;
    *tsp = 0;
    *val3 = 0;
    if (!ptr) return 0;
    if (size == 16) {           /* struct timespec: relative */
        *tsp = ptr;
        return 0;
    }
    if (size >= 24) {           /* struct _umtx_time */
        uint32_t fl[2];
        if (rd(pid, fl, ptr + 16, sizeof(fl)) < 0) return -EFAULT;
        *tsp = ptr;             /* the timespec is first */
        if (fl[0] & UMTX_ABSTIME) {
            *fop = F_WAIT_BITSET | (fl[1] == FBSD_CLOCK_REALTIME ? F_CLOCK_RT : 0);
            *val3 = 0xffffffffu;
        }
        return 0;
    }
    return -EINVAL;
}

/* Result of a sleep: woken or value changed -> 0; timeout; signal -> EINTR */
static long map_wait(long rv) {
    if (rv == 0 || rv == -EAGAIN) return 0;
    if (rv == -ETIMEDOUT) return -ETIMEDOUT;
    if (rv == -EINTR || rv == -512 || rv == -513 || rv == -514 || rv == -516) return -EINTR;
    return rv;
}

static long fin_last_wait(pid_t pid, const long *res, int n, const uint64_t ctx[4]) {
    (void)pid; (void)ctx;
    return map_wait(res[n - 1]);
}

/* rwlock waits always return EINTR (or ETIMEDOUT): libthr then retries
 * the lock in userland, which is where FreeBSD's kernel would acquire it */
static long fin_rw_wait(pid_t pid, const long *res, int n, const uint64_t ctx[4]) {
    (void)pid; (void)ctx;
    long rv = map_wait(res[n - 1]);
    return rv == -ETIMEDOUT ? -ETIMEDOUT : -EINTR;
}

static long fin_pi(pid_t pid, const long *res, int n, const uint64_t ctx[4]) {
    (void)pid;
    long rv = res[n - 1];
    if (rv == -EAGAIN && ctx[0]) return -EBUSY;  /* trylock */
    if (rv == -512 || rv == -513 || rv == -514 || rv == -516) return -EINTR;
    return rv;
}

/* Absolute CLOCK_REALTIME deadline for FUTEX_LOCK_PI from a FreeBSD
 * timeout, written below the stack. Returns its address, 0 for none. */
static uint64_t pi_deadline(pid_t pid, uint64_t size, uint64_t ptr, int *err) {
    *err = 0;
    if (!ptr) return 0;
    struct timespec t;
    uint32_t fl[2] = {0, 0};
    if (rd(pid, &t, ptr, sizeof(t)) < 0) { *err = -EFAULT; return 0; }
    if (size >= 24 && rd(pid, fl, ptr + 16, sizeof(fl)) < 0) { *err = -EFAULT; return 0; }
    struct timespec now, out;
    if (!(fl[0] & UMTX_ABSTIME)) {
        clock_gettime(CLOCK_REALTIME, &now);
        out.tv_sec = now.tv_sec + t.tv_sec;
        out.tv_nsec = now.tv_nsec + t.tv_nsec;
    } else if (fl[1] == FBSD_CLOCK_REALTIME) {
        out = t;
    } else {
        struct timespec mono;
        clock_gettime(CLOCK_MONOTONIC, &mono);
        clock_gettime(CLOCK_REALTIME, &now);
        out.tv_sec = now.tv_sec + (t.tv_sec - mono.tv_sec);
        out.tv_nsec = now.tv_nsec + (t.tv_nsec - mono.tv_nsec);
    }
    while (out.tv_nsec >= 1000000000L) { out.tv_nsec -= 1000000000L; out.tv_sec++; }
    while (out.tv_nsec < 0) { out.tv_nsec += 1000000000L; out.tv_sec--; }
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r) < 0) { *err = -EFAULT; return 0; }
    uint64_t addr = (r.rsp - 2048) & ~15ULL;
    if (wr(pid, &out, addr, sizeof(out)) < 0) { *err = -EFAULT; return 0; }
    return addr;
}

long thr_emul_umtx_op(pid_t pid, uint64_t args[6]) {
    uint64_t obj = args[0];
    int op = (int)args[1];
    uint64_t val = args[2], uaddr = args[3], uaddr2 = args[4];
    chain_step_t s[CHAIN_MAX_STEPS];
    uint64_t fop, tsp, v3;
    int e;

    switch (op) {
        case UMTX_OP_WAIT:
        case UMTX_OP_WAIT_UINT:
        case UMTX_OP_WAIT_UINT_PRIVATE:
            /* Sleep while *obj == val (WAIT compares a long; the futex
             * compares its low 32 bits) */
            if ((e = wait_timeout(pid, uaddr, uaddr2, &fop, &tsp, &v3)) < 0) return e;
            step(&s[0], SYS_futex, obj, fop, (uint32_t)val, tsp, 0, v3);
            return chain_begin(pid, s, 1, fin_last_wait, NULL);

        case UMTX_OP_WAKE:
        case UMTX_OP_WAKE_PRIVATE:
            step(&s[0], SYS_futex, obj, F_WAKE, val > INT_MAX ? INT_MAX : val, 0, 0, 0);
            return chain_begin(pid, s, 1, fin_zero, NULL);

        case UMTX_OP_NWAKE_PRIVATE: {
            /* obj: array of val addresses to wake */
            int n = (int)val;
            if (n <= 0) return 0;
            if (n > CHAIN_MAX_STEPS) n = CHAIN_MAX_STEPS;
            uint64_t addrs[CHAIN_MAX_STEPS];
            if (rd(pid, addrs, obj, (size_t)n * sizeof(uint64_t)) < 0) return -EFAULT;
            for (int i = 0; i < n; i++) step(&s[i], SYS_futex, addrs[i], F_WAKE, INT_MAX, 0, 0, 0);
            return chain_begin(pid, s, n, fin_zero, NULL);
        }

        case UMTX_OP_MUTEX_WAIT: {
            /* Sleep until the mutex is released (do not take it) */
            uint32_t owner;
            if (rd(pid, &owner, obj, sizeof(owner)) < 0) return -EFAULT;
            if ((owner & ~UMUTEX_CONTESTED) == 0) return 0;
            if ((e = wait_timeout(pid, uaddr, uaddr2, &fop, &tsp, &v3)) < 0) return e;
            wake_op(&s[0], obj, 0, FOP(FO_OR | FO_SHIFT, 31, FC_EQ, 0));   /* set CONTESTED */
            step(&s[1], SYS_futex, obj, fop, owner | UMUTEX_CONTESTED, tsp, 0, v3);
            return chain_begin(pid, s, 2, fin_last_wait, NULL);
        }

        case UMTX_OP_MUTEX_WAKE:
        case UMTX_OP_MUTEX_WAKE2:
            /* Waiters retry the lock; wake them all, losers sleep again
             * and set CONTESTED again */
            step(&s[0], SYS_futex, obj, F_WAKE, INT_MAX, 0, 0, 0);
            return chain_begin(pid, s, 1, fin_zero, NULL);

        case UMTX_OP_MUTEX_LOCK:
        case UMTX_OP_MUTEX_TRYLOCK: {
            uint64_t ctx[4] = { op == UMTX_OP_MUTEX_TRYLOCK, 0, 0, 0 };
            if (op == UMTX_OP_MUTEX_TRYLOCK) {
                step(&s[0], SYS_futex, obj, F_TRYLOCK_PI, 0, 0, 0, 0);
            } else {
                uint64_t dl = pi_deadline(pid, uaddr, uaddr2, &e);
                if (e < 0) return e;
                step(&s[0], SYS_futex, obj, F_LOCK_PI, 0, dl, 0, 0);
            }
            return chain_begin(pid, s, 1, fin_pi, ctx);
        }

        case UMTX_OP_MUTEX_UNLOCK: {
            uint64_t ctx[4] = { 0, 0, 0, 0 };
            step(&s[0], SYS_futex, obj, F_UNLOCK_PI, 0, 0, 0, 0);
            return chain_begin(pid, s, 1, fin_pi, ctx);
        }

        case UMTX_OP_SET_CEILING:
            return 0;

        case UMTX_OP_CV_WAIT: {
            /* cv_wait(ucond *obj, flags val, umutex *uaddr, timespec *uaddr2):
             * mark waiters, release the mutex, sleep on the sequence word
             * (c_spare[0]) read before the release */
            uint32_t one = 1, seq, mflags;
            if (wr(pid, &one, obj, sizeof(one)) < 0) return -EFAULT;          /* c_has_waiters */
            if (rd(pid, &seq, obj + 12, sizeof(seq)) < 0) return -EFAULT;      /* c_spare[0] */
            if (rd(pid, &mflags, uaddr + 4, sizeof(mflags)) < 0) return -EFAULT;
            if (mflags & (UMUTEX_PRIO_INHERIT | UMUTEX_PRIO_PROTECT))
                step(&s[0], SYS_futex, uaddr, F_UNLOCK_PI, 0, 0, 0, 0);
            else    /* *m = 0 and, if it was contested (negative), wake all */
                step(&s[0], SYS_futex, uaddr, F_WAKE_OP, 0, INT_MAX, uaddr,
                     FOP(FO_SET, 0, FC_LT, 0));
            fop = F_WAIT; tsp = uaddr2; v3 = 0;
            if (uaddr2 && (val & CVWAIT_ABSTIME)) {
                uint32_t clk = FBSD_CLOCK_REALTIME;
                if (val & CVWAIT_CLOCKID) (void)rd(pid, &clk, obj + 8, sizeof(clk));
                fop = F_WAIT_BITSET | (clk == FBSD_CLOCK_REALTIME ? F_CLOCK_RT : 0);
                v3 = 0xffffffffu;
            }
            step(&s[1], SYS_futex, obj + 12, fop, seq, tsp, 0, v3);
            return chain_begin(pid, s, 2, fin_last_wait, NULL);
        }

        case UMTX_OP_CV_SIGNAL:
        case UMTX_OP_CV_BROADCAST:
            /* bump the sequence word and wake one / all */
            step(&s[0], SYS_futex, obj + 12, F_WAKE_OP,
                 op == UMTX_OP_CV_SIGNAL ? 1 : INT_MAX, 0, obj + 12, FOP(FO_ADD, 1, FC_EQ, 0));
            return chain_begin(pid, s, 1, fin_zero, NULL);

        case UMTX_OP_RW_RDLOCK:
        case UMTX_OP_RW_WRLOCK: {
            uint32_t st, rwflags;
            if (rd(pid, &st, obj, sizeof(st)) < 0 || rd(pid, &rwflags, obj + 4, sizeof(rwflags)) < 0)
                return -EFAULT;
            uint32_t bit;
            if (op == UMTX_OP_RW_RDLOCK) {
                uint32_t blockers = (val & URWLOCK_PREFER_READER) || (rwflags & URWLOCK_PREFER_READER)
                                        ? URWLOCK_WRITE_OWNER
                                        : (URWLOCK_WRITE_OWNER | URWLOCK_WRITE_WAITERS);
                if (!(st & blockers)) return -EINTR;    /* free now: retry */
                bit = 29;   /* READ_WAITERS */
            } else {
                if (!(st & URWLOCK_WRITE_OWNER) && (st & URWLOCK_MAX_READERS) == 0) return -EINTR;
                bit = 30;   /* WRITE_WAITERS */
            }
            if ((e = wait_timeout(pid, uaddr, uaddr2, &fop, &tsp, &v3)) < 0) return e;
            wake_op(&s[0], obj, 0, FOP(FO_OR | FO_SHIFT, bit, FC_EQ, 0));
            step(&s[1], SYS_futex, obj, fop, st | (1u << bit), tsp, 0, v3);
            return chain_begin(pid, s, 2, fin_rw_wait, NULL);
        }

        case UMTX_OP_RW_UNLOCK: {
            uint32_t st;
            if (rd(pid, &st, obj, sizeof(st)) < 0) return -EFAULT;
            uint32_t rel;
            if (st & URWLOCK_WRITE_OWNER) rel = FOP(FO_ANDN | FO_SHIFT, 31, FC_EQ, 0);
            else if (st & URWLOCK_MAX_READERS) rel = FOP(FO_ADD, -1, FC_EQ, 0);
            else return -EPERM;
            /* clear both waiter bits (waiters set them again), release,
             * wake everyone */
            wake_op(&s[0], obj, 0, FOP(FO_ANDN | FO_SHIFT, 29, FC_EQ, 0));
            wake_op(&s[1], obj, 0, FOP(FO_ANDN | FO_SHIFT, 30, FC_EQ, 0));
            wake_op(&s[2], obj, INT_MAX, rel);
            return chain_begin(pid, s, 3, fin_zero, NULL);
        }

        case UMTX_OP_SEM2_WAIT: {
            uint32_t cnt;
            if (rd(pid, &cnt, obj, sizeof(cnt)) < 0) return -EFAULT;
            if (cnt & USEM_COUNT_MASK) return 0;
            if ((e = wait_timeout(pid, uaddr, uaddr2, &fop, &tsp, &v3)) < 0) return e;
            wake_op(&s[0], obj, 0, FOP(FO_OR | FO_SHIFT, 31, FC_EQ, 0));   /* HAS_WAITERS */
            step(&s[1], SYS_futex, obj, fop, cnt | USEM_HAS_WAITERS, tsp, 0, v3);
            return chain_begin(pid, s, 2, fin_last_wait, NULL);
        }

        case UMTX_OP_SEM2_WAKE:
            step(&s[0], SYS_futex, obj, F_WAKE, INT_MAX, 0, 0, 0);
            return chain_begin(pid, s, 1, fin_zero, NULL);

        case UMTX_OP_ROBUST_LISTS:
        case UMTX_OP_GET_MIN_TIMEOUT:
        case UMTX_OP_SET_MIN_TIMEOUT:
            if (op == UMTX_OP_GET_MIN_TIMEOUT && uaddr) {
                int64_t z = 0;
                (void)wr(pid, &z, uaddr, sizeof(z));
            }
            return 0;

        default:
            BSD_WARN("_umtx_op: unsupported op %d", op);
            return -EINVAL;
    }
}

/* ---------------------------------------------------------------------
 * rfork(2)
 *
 * posix_spawn() uses rfork_thread(RFSPAWN, stack, fn, arg), which tells
 * child from parent by %rdx (1 in the child, 0 in the parent) and then
 * switches the child to its own stack. Linux leaves %rdx alone, so both
 * are set here: the parent's at syscall exit, the child's at its first
 * stop.
 * ------------------------------------------------------------------- */

#define RF_FDG     (1u << 2)
#define RF_PROC    (1u << 4)
#define RF_MEM     (1u << 5)
#define RF_CFDG    (1u << 12)
#define RF_PPWAIT  (1u << 31)   /* also RFSPAWN */
#define L_CLONE_VM     0x100
#define L_CLONE_VFORK  0x4000
#define L_SIGCHLD      17

#define MAX_RFORK 64
static pid_t rfork_parents[MAX_RFORK];
static uint64_t rfork_rsi[MAX_RFORK];   /* rfork_thread passes the child stack here */

long thr_emul_rfork(pid_t pid, uint64_t args[6]) {
    uint32_t fl = (uint32_t)args[0];
    if (!(fl & (RF_PROC | RF_PPWAIT))) return 0;  /* changes to this process only */
    uint64_t cf = L_SIGCHLD;
    if (fl & RF_MEM) cf |= L_CLONE_VM;
    if (fl & RF_PPWAIT) cf |= L_CLONE_VM | L_CLONE_VFORK;
    for (int i = 0; i < MAX_RFORK; i++)
        if (!rfork_parents[i]) { rfork_parents[i] = pid; rfork_rsi[i] = args[1]; break; }
    /* Linux clone(flags, stack = same, ptid, ctid, tls) */
    args[0] = cf;
    args[1] = 0;
    args[2] = args[3] = args[4] = args[5] = 0;
    return -EAGAIN;  /* run Linux clone */
}

static int take_rfork_parent(pid_t parent) {
    for (int i = 0; i < MAX_RFORK; i++)
        if (rfork_parents[i] == parent) { rfork_parents[i] = 0; return 1; }
    return 0;
}

/* Child of an rfork: %rdx = 1 at its first stop */
int thr_rfork_child_first_stop(pid_t child) {
    char path[64], line[128];
    snprintf(path, sizeof(path), "/proc/%d/status", (int)child);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    pid_t ppid = 0;
    while (fgets(line, sizeof(line), f))
        if (strncmp(line, "PPid:", 5) == 0) { ppid = (pid_t)atoi(line + 5); break; }
    fclose(f);
    int found = -1;
    for (int i = 0; i < MAX_RFORK; i++) if (rfork_parents[i] == ppid) { found = i; break; }
    if (found < 0) return 0;
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, child, NULL, &r) < 0) return 0;
    r.rdx = 1;
    r.rax = 0;
    r.rsi = rfork_rsi[found];  /* the clone rewrite replaced it */
    (void)ptrace(PTRACE_SETREGS, child, NULL, &r);
    return 1;
}

void thr_rfork_after_syscall(pid_t pid) {
    uint64_t rsi = 0;
    for (int i = 0; i < MAX_RFORK; i++) if (rfork_parents[i] == pid) { rsi = rfork_rsi[i]; break; }
    (void)take_rfork_parent(pid);
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r) < 0) return;
    r.rsi = rsi;
    if (!(r.eflags & 1)) r.rdx = 0;  /* the parent */
    (void)ptrace(PTRACE_SETREGS, pid, NULL, &r);
}
