/*
 * kqueue_emul.c - FreeBSD kqueue/kevent on Linux epoll, in the traced process
 *
 * See include/bsdulator/kqueue_emul.h. Each kevent() call is a small state
 * machine in the tracer that runs Linux syscalls in the process, one step
 * per syscall stop:
 *
 *   changes   for each change: update the knote, then epoll_ctl (or
 *             eventfd2/write/close for EVFILT_USER)
 *   sync      epoll_ctl for descriptors whose knotes changed after a
 *             one-shot event was reported
 *   wait      epoll_wait (blocks in the process, not the tracer)
 *   drain     read() the eventfds of EV_CLEAR user events
 *
 * Between steps the process is pointed back at its syscall instruction
 * with the next syscall; at the end the registers are restored with
 * kevent's return value.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>

#include "bsdulator.h"
#include "bsdulator/interceptor.h"
#include "bsdulator/syscall.h"
#include "bsdulator/kqueue_emul.h"
#include "bsdulator/thread_emul.h"

int abi_translate_errno(int linux_errno);

/* FreeBSD filters and flags (sys/event.h) */
#define EVFILT_READ_    (-1)
#define EVFILT_WRITE_   (-2)
#define EVFILT_USER_    (-11)

#define EV_ADD_         0x0001
#define EV_DELETE_      0x0002
#define EV_ENABLE_      0x0004
#define EV_DISABLE_     0x0008
#define EV_ONESHOT_     0x0010
#define EV_CLEAR_       0x0020
#define EV_RECEIPT_     0x0040
#define EV_DISPATCH_    0x0080
#define EV_ERROR_       0x4000
#define EV_EOF_         0x8000

#define NOTE_FFNOP_       0x00000000u
#define NOTE_FFAND_       0x40000000u
#define NOTE_FFOR_        0x80000000u
#define NOTE_FFCOPY_      0xc0000000u
#define NOTE_FFCTRLMASK_  0xc0000000u
#define NOTE_FFLAGSMASK_  0x00ffffffu
#define NOTE_TRIGGER_     0x01000000u

/* Linux */
#define L_EPOLLIN       0x001u
#define L_EPOLLOUT      0x004u
#define L_EPOLLERR      0x008u
#define L_EPOLLHUP      0x010u
#define L_EPOLLRDHUP    0x2000u
#define L_EPOLLET       0x80000000u
#define L_EPOLL_CTL_ADD 1
#define L_EPOLL_CTL_DEL 2
#define L_EPOLL_CTL_MOD 3
#define L_EPOLL_CLOEXEC 0x80000
#define L_EFD_CLOEXEC   0x80000
#define L_EFD_NONBLOCK  0x800

/* Readable/writable byte count reported in kevent data (epoll does not
 * give one; nginx only needs it to be non-zero while data may remain). */
#define KQ_DATA_GUESS   65536

#define USER_MARK       (1ULL << 63)

/* Scratch memory in the process: [0,16) epoll_event for epoll_ctl,
 * [16,24) eventfd buffer, [64, end) epoll_wait events. */
#define SCRATCH_SIZE    65536
#define SCRATCH_EV      0
#define SCRATCH_U64     16
#define SCRATCH_EVENTS  64
#define MAX_WAIT_EVENTS ((SCRATCH_SIZE - SCRATCH_EVENTS) / 12)

#define CF_FLAG         0x1ULL

struct fbsd_kevent {
    uint64_t ident;
    int16_t  filter;
    uint16_t flags;
    uint32_t fflags;
    int64_t  data;
    uint64_t udata;
    uint64_t ext[4];
};
_Static_assert(sizeof(struct fbsd_kevent) == 64, "FreeBSD struct kevent");

struct linux_epoll_event {
    uint32_t events;
    uint64_t data;
} __attribute__((packed));
_Static_assert(sizeof(struct linux_epoll_event) == 12, "Linux epoll_event");

typedef struct {
    int      used;
    int      kq;
    uint64_t ident;
    int16_t  filter;
    uint16_t flags;     /* EV_CLEAR, EV_ONESHOT, EV_DISPATCH */
    uint64_t udata;
    int      enabled;
    int      efd;       /* EVFILT_USER: backing eventfd */
    uint32_t ufflags;   /* EVFILT_USER fflags */
} knote_t;

typedef struct {
    int      used;
    int      kq;
    int      fd;
    uint32_t mask;      /* registered with epoll (0 = not registered) */
    int      dirty;
} fdstate_t;

typedef struct {
    int kq;
    struct fbsd_kevent ev;
} left_t;

enum { CALL_NONE, CALL_KQUEUE, CALL_KEVENT };
enum { P_SCRATCH, P_CHANGES, P_SYNC, P_WAIT, P_DRAIN, P_DONE };
enum { OP_NONE, OP_CREATE, OP_MMAP, OP_CTL, OP_EVENTFD, OP_UADD, OP_TRIGGER,
       OP_UDEL, OP_UCLOSE, OP_SYNC, OP_WAIT, OP_DRAIN, OP_SCRATCH };

/* Knotes and epoll registrations: per process, shared by its threads */
typedef struct {
    pid_t tgid;
    int refs;
    knote_t   *kn;  int nkn;
    fdstate_t *fs;  int nfs;
    left_t    *left; int nleft;
} kqshared_t;

/* Per thread: scratch memory and the call in progress */
typedef struct {
    pid_t pid;
    uint64_t scratch;
    kqshared_t *sh;

    /* call in progress */
    int call;
    struct user_regs_struct entry;
    int kq;
    struct fbsd_kevent *changes; int nchanges; int ci;
    uint64_t eventlist; int nevents;
    struct fbsd_kevent *out; int nout;
    int64_t timeout_ms;
    uint64_t timeout_ptr;
    int phase;
    int op;
    int op_kn;          /* knote of the op */
    int op_fd;
    int op_ctl;         /* EPOLL_CTL_* of the op */
    uint32_t op_mask;
    int op_new_kn;      /* the change created op_kn */
    int created_fd;
    int *drain; int ndrain; int drain_i;
    long final;         /* result when the call finished at entry */
} kqproc_t;

#define MAX_KQ_PROCS 256
static kqproc_t *procs[MAX_KQ_PROCS];

static kqproc_t *find_proc(pid_t pid) {
    for (int i = 0; i < MAX_KQ_PROCS; i++)
        if (procs[i] && procs[i]->pid == pid) return procs[i];
    return NULL;
}

static kqproc_t *get_proc(pid_t pid) {
    kqproc_t *p = find_proc(pid);
    if (p) return p;
    pid_t tgid = thr_tgid(pid);
    kqshared_t *sh = NULL;
    for (int i = 0; i < MAX_KQ_PROCS; i++)
        if (procs[i] && procs[i]->sh->tgid == tgid) { sh = procs[i]->sh; break; }
    for (int i = 0; i < MAX_KQ_PROCS; i++) {
        if (!procs[i]) {
            p = calloc(1, sizeof(*p));
            if (!p) return NULL;
            if (!sh) {
                sh = calloc(1, sizeof(*sh));
                if (!sh) { free(p); return NULL; }
                sh->tgid = tgid;
            }
            sh->refs++;
            p->sh = sh;
            p->pid = pid;
            procs[i] = p;
            return p;
        }
    }
    return NULL;
}

static void free_call(kqproc_t *p) {
    free(p->changes); p->changes = NULL;
    free(p->out); p->out = NULL;
    free(p->drain); p->drain = NULL;
    p->nchanges = p->nout = p->ndrain = 0;
    p->call = CALL_NONE;
    p->op = OP_NONE;
}

static void free_proc(kqproc_t *p) {
    free_call(p);
    if (--p->sh->refs == 0) {
        free(p->sh->kn);
        free(p->sh->fs);
        free(p->sh->left);
        free(p->sh);
    }
    free(p);
}

void kq_proc_exit(pid_t pid) {
    for (int i = 0; i < MAX_KQ_PROCS; i++) {
        if (procs[i] && procs[i]->pid == pid) {
            free_proc(procs[i]);
            procs[i] = NULL;
        }
    }
}

void kq_proc_exec(pid_t pid) {
    kq_proc_exit(pid);  /* kqueues and the scratch mapping are gone */
}

int kq_on_syscall_entry(pid_t pid) {
    kqproc_t *p = find_proc(pid);
    return p && p->call != CALL_NONE;
}

int kq_busy(pid_t pid) {
    return kq_on_syscall_entry(pid);
}

static int rd(pid_t pid, void *dst, uint64_t addr, size_t len) {
    return interceptor_read_mem(pid, dst, (const void *)addr, len) == (ssize_t)len ? 0 : -1;
}
static int wr(pid_t pid, const void *src, uint64_t addr, size_t len) {
    return interceptor_write_mem(pid, src, (void *)addr, len) == (ssize_t)len ? 0 : -1;
}

/* ---------------------------------------------------------------------
 * Registry
 * ------------------------------------------------------------------- */

static int kn_find(kqproc_t *p, int kq, uint64_t ident, int16_t filter) {
    for (int i = 0; i < p->sh->nkn; i++)
        if (p->sh->kn[i].used && p->sh->kn[i].kq == kq && p->sh->kn[i].ident == ident &&
            p->sh->kn[i].filter == filter)
            return i;
    return -1;
}

static int kn_new(kqproc_t *p) {
    for (int i = 0; i < p->sh->nkn; i++)
        if (!p->sh->kn[i].used) { memset(&p->sh->kn[i], 0, sizeof(knote_t)); p->sh->kn[i].used = 1; return i; }
    knote_t *n = realloc(p->sh->kn, (size_t)(p->sh->nkn + 16) * sizeof(knote_t));
    if (!n) return -1;
    memset(n + p->sh->nkn, 0, 16 * sizeof(knote_t));
    p->sh->kn = n;
    p->sh->nkn += 16;
    return kn_new(p);
}

static fdstate_t *fs_get(kqproc_t *p, int kq, int fd, int create) {
    int free_i = -1;
    for (int i = 0; i < p->sh->nfs; i++) {
        if (p->sh->fs[i].used && p->sh->fs[i].kq == kq && p->sh->fs[i].fd == fd) return &p->sh->fs[i];
        if (!p->sh->fs[i].used && free_i < 0) free_i = i;
    }
    if (!create) return NULL;
    if (free_i < 0) {
        fdstate_t *n = realloc(p->sh->fs, (size_t)(p->sh->nfs + 16) * sizeof(fdstate_t));
        if (!n) return NULL;
        memset(n + p->sh->nfs, 0, 16 * sizeof(fdstate_t));
        p->sh->fs = n;
        free_i = p->sh->nfs;
        p->sh->nfs += 16;
    }
    fdstate_t *f = &p->sh->fs[free_i];
    memset(f, 0, sizeof(*f));
    f->used = 1;
    f->kq = kq;
    f->fd = fd;
    return f;
}

/* epoll mask wanted for fd from its READ/WRITE knotes */
static uint32_t wanted_mask(kqproc_t *p, int kq, int fd) {
    uint32_t m = 0;
    int r = kn_find(p, kq, (uint64_t)fd, EVFILT_READ_);
    int w = kn_find(p, kq, (uint64_t)fd, EVFILT_WRITE_);
    if (r >= 0 && p->sh->kn[r].enabled) {
        m |= L_EPOLLIN | L_EPOLLRDHUP;
        if (p->sh->kn[r].flags & EV_CLEAR_) m |= L_EPOLLET;
    }
    if (w >= 0 && p->sh->kn[w].enabled) {
        m |= L_EPOLLOUT;
        if (p->sh->kn[w].flags & EV_CLEAR_) m |= L_EPOLLET;
    }
    return m;
}

/* Forget everything about kq, or about fd in all kqueues (it was closed;
 * the kernel already dropped it from epoll). */
static void forget_kq(kqproc_t *p, int kq) {
    for (int i = 0; i < p->sh->nkn; i++) if (p->sh->kn[i].used && p->sh->kn[i].kq == kq) p->sh->kn[i].used = 0;
    for (int i = 0; i < p->sh->nfs; i++) if (p->sh->fs[i].used && p->sh->fs[i].kq == kq) p->sh->fs[i].used = 0;
    int j = 0;
    for (int i = 0; i < p->sh->nleft; i++) if (p->sh->left[i].kq != kq) p->sh->left[j++] = p->sh->left[i];
    p->sh->nleft = j;
}

static void forget_fd(kqproc_t *p, int fd) {
    for (int i = 0; i < p->sh->nkn; i++)
        if (p->sh->kn[i].used && p->sh->kn[i].filter != EVFILT_USER_ && p->sh->kn[i].ident == (uint64_t)fd)
            p->sh->kn[i].used = 0;
    for (int i = 0; i < p->sh->nfs; i++)
        if (p->sh->fs[i].used && p->sh->fs[i].fd == fd) p->sh->fs[i].used = 0;
    int j = 0;
    for (int i = 0; i < p->sh->nleft; i++)
        if (!(p->sh->left[i].ev.filter != EVFILT_USER_ && p->sh->left[i].ev.ident == (uint64_t)fd))
            p->sh->left[j++] = p->sh->left[i];
    p->sh->nleft = j;
}

void kq_after_syscall(pid_t pid, uint64_t nr, const uint64_t args[6]) {
    if (nr != FBSD_SYS_close) return;
    kqproc_t *p = find_proc(pid);
    if (!p) return;
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r) < 0 || (r.eflags & CF_FLAG)) return;
    int fd = (int)args[0];
    forget_fd(p, fd);
    forget_kq(p, fd);
}

/* ---------------------------------------------------------------------
 * Running syscalls in the process
 * ------------------------------------------------------------------- */

static int issue(pid_t pid, kqproc_t *p, int at_entry, long nr,
                 uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                 uint64_t a4, uint64_t a5) {
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r) < 0) return -1;
    if (at_entry) {
        r.orig_rax = (uint64_t)nr;
    } else {
        /* Back to the syscall instruction, with the next syscall */
        r.rip = p->entry.rip - 2;
        r.rax = (uint64_t)nr;
        r.orig_rax = (uint64_t)-1;
    }
    r.rdi = a0; r.rsi = a1; r.rdx = a2; r.r10 = a3; r.r8 = a4; r.r9 = a5;
    return ptrace(PTRACE_SETREGS, pid, NULL, &r) < 0 ? -1 : 0;
}

/* Return from kevent/kqueue with ret (>= 0) or -linux_errno. */
static void finish(pid_t pid, kqproc_t *p, long ret) {
    struct user_regs_struct r = p->entry;
    if (ret < 0) {
        r.rax = (uint64_t)abi_translate_errno((int)-ret);
        r.eflags |= CF_FLAG;
    } else {
        r.rax = (uint64_t)ret;
        r.eflags &= ~CF_FLAG;
    }
    r.orig_rax = (uint64_t)-1;
    (void)ptrace(PTRACE_SETREGS, pid, NULL, &r);
    free_call(p);
}

static void add_out(kqproc_t *p, const struct fbsd_kevent *ev) {
    if (p->nout < p->nevents) {
        p->out[p->nout++] = *ev;
        return;
    }
    left_t *n = realloc(p->sh->left, (size_t)(p->sh->nleft + 1) * sizeof(left_t));
    if (!n) return;
    p->sh->left = n;
    p->sh->left[p->sh->nleft].kq = p->kq;
    p->sh->left[p->sh->nleft].ev = *ev;
    p->sh->nleft++;
}

/* A change failed: report it as EV_ERROR (FreeBSD errno in data). */
static void add_error(kqproc_t *p, const struct fbsd_kevent *c, int linux_errno) {
    struct fbsd_kevent e = *c;
    e.flags = EV_ERROR_;
    e.data = linux_errno ? abi_translate_errno(linux_errno) : 0;
    if (p->nout < p->nevents) p->out[p->nout++] = e;
}

/* ---------------------------------------------------------------------
 * The kevent state machine
 * ------------------------------------------------------------------- */

static int ctl(pid_t pid, kqproc_t *p, int at_entry, int op, int fd, uint32_t mask, uint64_t data) {
    struct linux_epoll_event ev = { mask, data };
    if (op != L_EPOLL_CTL_DEL && wr(pid, &ev, p->scratch + SCRATCH_EV, sizeof(ev)) < 0) return -1;
    p->op_ctl = op;
    p->op_fd = fd;
    p->op_mask = mask;
    return issue(pid, p, at_entry, SYS_epoll_ctl, (uint64_t)p->kq, (uint64_t)op,
                 (uint64_t)fd, op == L_EPOLL_CTL_DEL ? 0 : p->scratch + SCRATCH_EV, 0, 0);
}

/* Apply change ci to the registry; issue its syscall if one is needed.
 * Returns 1 if a syscall was issued, 0 if the change is complete. */
static int apply_change(pid_t pid, kqproc_t *p, int at_entry) {
    struct fbsd_kevent *c = &p->changes[p->ci];
    int16_t filter = c->filter;
    uint16_t fl = c->flags;
    p->op_new_kn = 0;

    if (filter != EVFILT_READ_ && filter != EVFILT_WRITE_ && filter != EVFILT_USER_) {
        add_error(p, c, EINVAL);
        p->ci++;
        return 0;
    }
    int k = kn_find(p, p->kq, c->ident, filter);
    if (k < 0 && !(fl & EV_ADD_)) {
        add_error(p, c, ENOENT);
        p->ci++;
        return 0;
    }
    if (k < 0) {
        k = kn_new(p);
        if (k < 0) { add_error(p, c, ENOMEM); p->ci++; return 0; }
        knote_t *n = &p->sh->kn[k];
        n->kq = p->kq;
        n->ident = c->ident;
        n->filter = filter;
        n->efd = -1;
        n->enabled = 1;
        p->op_new_kn = 1;
    }
    knote_t *n = &p->sh->kn[k];
    p->op_kn = k;

    if (fl & EV_ADD_) {
        n->flags = fl & (EV_CLEAR_ | EV_ONESHOT_ | EV_DISPATCH_);
        n->udata = c->udata;
        n->enabled = 1;
    }
    if (fl & EV_ENABLE_) n->enabled = 1;
    if (fl & EV_DISABLE_) n->enabled = 0;

    if (filter == EVFILT_USER_) {
        uint32_t ctrl = c->fflags & NOTE_FFCTRLMASK_, val = c->fflags & NOTE_FFLAGSMASK_;
        if (ctrl == NOTE_FFAND_) n->ufflags &= val;
        else if (ctrl == NOTE_FFOR_) n->ufflags |= val;
        else if (ctrl == NOTE_FFCOPY_) n->ufflags = val;
        if (fl & EV_DELETE_) {
            if (n->efd < 0) { n->used = 0; p->ci++; return 0; }
            p->op = OP_UDEL;
            return ctl(pid, p, at_entry, L_EPOLL_CTL_DEL, n->efd, 0, 0) == 0;
        }
        if (n->efd < 0) {
            p->op = OP_EVENTFD;
            return issue(pid, p, at_entry, SYS_eventfd2, 0,
                         L_EFD_NONBLOCK | L_EFD_CLOEXEC, 0, 0, 0, 0) == 0;
        }
        if (c->fflags & NOTE_TRIGGER_) {
            uint64_t one = 1;
            if (wr(pid, &one, p->scratch + SCRATCH_U64, 8) < 0) { p->ci++; return 0; }
            p->op = OP_TRIGGER;
            return issue(pid, p, at_entry, SYS_write, (uint64_t)n->efd,
                         p->scratch + SCRATCH_U64, 8, 0, 0, 0) == 0;
        }
        if (fl & EV_RECEIPT_) add_error(p, c, 0);
        p->ci++;
        return 0;
    }

    /* READ / WRITE */
    int fd = (int)c->ident;
    if (fl & EV_DELETE_) n->used = 0;
    fdstate_t *f = fs_get(p, p->kq, fd, 1);
    if (!f) { add_error(p, c, ENOMEM); p->ci++; return 0; }
    uint32_t want = wanted_mask(p, p->kq, fd);
    int op;
    if (want == 0) {
        if (f->mask == 0) { f->used = 0; p->ci++; if (fl & EV_RECEIPT_) add_error(p, c, 0); return 0; }
        op = L_EPOLL_CTL_DEL;
    } else {
        /* Always re-arm on EV_ADD: the descriptor may have been closed and
         * reopened since, which drops it from epoll silently. */
        op = f->mask ? L_EPOLL_CTL_MOD : L_EPOLL_CTL_ADD;
        if (want == f->mask && !(fl & EV_ADD_)) { p->ci++; if (fl & EV_RECEIPT_) add_error(p, c, 0); return 0; }
    }
    p->op = OP_CTL;
    return ctl(pid, p, at_entry, op, fd, want, (uint64_t)(uint32_t)fd) == 0;
}

static int kq_run(pid_t pid, kqproc_t *p, int at_entry);

/* A step's syscall returned rv (raw Linux). */
static int kq_complete(pid_t pid, kqproc_t *p, long rv) {
    int op = p->op;
    p->op = OP_NONE;
    switch (op) {
        case OP_CREATE:
            if (rv < 0) { finish(pid, p, rv); return 2; }
            p->created_fd = (int)rv;
            forget_kq(p, (int)rv);
            if (!p->scratch) {
                p->op = OP_MMAP;
                if (issue(pid, p, 0, SYS_mmap, 0, SCRATCH_SIZE, 3 /* RW */,
                          0x22 /* PRIVATE|ANON */, (uint64_t)-1, 0) < 0) {
                    finish(pid, p, -EFAULT);
                    return 2;
                }
                return 1;
            }
            finish(pid, p, p->created_fd);
            return 2;

        case OP_MMAP:
            if (rv < 0 && rv > -4096) { finish(pid, p, rv); return 2; }
            p->scratch = (uint64_t)rv;
            finish(pid, p, p->created_fd);
            return 2;

        case OP_CTL: {
            struct fbsd_kevent *c = &p->changes[p->ci];
            fdstate_t *f = fs_get(p, p->kq, p->op_fd, 0);
            if (rv == -EEXIST && p->op_ctl == L_EPOLL_CTL_ADD) {
                p->op = OP_CTL;
                if (ctl(pid, p, 0, L_EPOLL_CTL_MOD, p->op_fd, p->op_mask, (uint64_t)(uint32_t)p->op_fd) == 0) return 1;
            } else if (rv == -ENOENT && p->op_ctl == L_EPOLL_CTL_MOD) {
                p->op = OP_CTL;
                if (ctl(pid, p, 0, L_EPOLL_CTL_ADD, p->op_fd, p->op_mask, (uint64_t)(uint32_t)p->op_fd) == 0) return 1;
            } else if (rv < 0 && p->op_ctl != L_EPOLL_CTL_DEL) {
                add_error(p, c, (int)-rv);
                if (p->op_new_kn) p->sh->kn[p->op_kn].used = 0;
                if (f && f->mask == 0) f->used = 0;
            } else {
                if (f) {
                    f->mask = p->op_ctl == L_EPOLL_CTL_DEL ? 0 : p->op_mask;
                    f->dirty = 0;
                    if (f->mask == 0) f->used = 0;
                }
                if (c->flags & EV_RECEIPT_) add_error(p, c, 0);
            }
            p->ci++;
            break;
        }

        case OP_EVENTFD: {
            struct fbsd_kevent *c = &p->changes[p->ci];
            knote_t *n = &p->sh->kn[p->op_kn];
            if (rv < 0) {
                add_error(p, c, (int)-rv);
                n->used = 0;
                p->ci++;
                break;
            }
            n->efd = (int)rv;
            p->op = OP_UADD;
            uint32_t m = L_EPOLLIN | ((n->flags & EV_CLEAR_) ? L_EPOLLET : 0);
            if (ctl(pid, p, 0, L_EPOLL_CTL_ADD, n->efd, m, USER_MARK | (uint64_t)p->op_kn) == 0) return 1;
            p->ci++;
            break;
        }

        case OP_UADD: {
            struct fbsd_kevent *c = &p->changes[p->ci];
            if (rv < 0) add_error(p, c, (int)-rv);
            else if (c->fflags & NOTE_TRIGGER_) {
                uint64_t one = 1;
                knote_t *n = &p->sh->kn[p->op_kn];
                if (wr(pid, &one, p->scratch + SCRATCH_U64, 8) == 0) {
                    p->op = OP_TRIGGER;
                    if (issue(pid, p, 0, SYS_write, (uint64_t)n->efd, p->scratch + SCRATCH_U64, 8, 0, 0, 0) == 0)
                        return 1;
                }
            } else if (c->flags & EV_RECEIPT_) add_error(p, c, 0);
            p->ci++;
            break;
        }

        case OP_TRIGGER: {
            struct fbsd_kevent *c = &p->changes[p->ci];
            if (rv < 0 && rv != -EAGAIN) add_error(p, c, (int)-rv);
            else if (c->flags & EV_RECEIPT_) add_error(p, c, 0);
            p->ci++;
            break;
        }

        case OP_UDEL: {
            knote_t *n = &p->sh->kn[p->op_kn];
            int efd = n->efd;
            n->used = 0;
            p->op = OP_UCLOSE;
            if (issue(pid, p, 0, SYS_close, (uint64_t)efd, 0, 0, 0, 0, 0) == 0) return 1;
            p->ci++;
            break;
        }

        case OP_UCLOSE:
            p->ci++;
            break;

        case OP_SYNC: {
            fdstate_t *f = fs_get(p, p->kq, p->op_fd, 0);
            if (f) {
                f->dirty = 0;
                if (rv >= 0 || p->op_ctl == L_EPOLL_CTL_DEL) f->mask = p->op_ctl == L_EPOLL_CTL_DEL ? 0 : p->op_mask;
                if (f->mask == 0) f->used = 0;
            }
            break;
        }

        case OP_WAIT: {
            if (rv < 0) {
                /* EINTR from a signal: kevent fails with EINTR */
                finish(pid, p, rv);
                return 2;
            }
            int n = (int)rv;
            struct linux_epoll_event *evs = NULL;
            if (n > 0) {
                evs = malloc((size_t)n * sizeof(*evs));
                if (!evs || rd(pid, evs, p->scratch + SCRATCH_EVENTS, (size_t)n * sizeof(*evs)) < 0) {
                    free(evs);
                    finish(pid, p, -EFAULT);
                    return 2;
                }
            }
            p->drain = calloc((size_t)(n > 0 ? n : 1), sizeof(int));
            for (int i = 0; i < n; i++) {
                uint32_t e = evs[i].events;
                uint64_t d = evs[i].data;
                if (d & USER_MARK) {
                    int k = (int)(d & 0xffffffffu);
                    if (k >= p->sh->nkn || !p->sh->kn[k].used || p->sh->kn[k].kq != p->kq) continue;
                    knote_t *kn = &p->sh->kn[k];
                    if (kn->flags & EV_CLEAR_ && p->drain) p->drain[p->ndrain++] = kn->efd;
                    if (!kn->enabled) continue;
                    struct fbsd_kevent o;
                    memset(&o, 0, sizeof(o));
                    o.ident = kn->ident;
                    o.filter = EVFILT_USER_;
                    o.flags = kn->flags;
                    o.fflags = kn->ufflags;
                    o.udata = kn->udata;
                    add_out(p, &o);
                    if (kn->flags & EV_CLEAR_) kn->ufflags = 0;
                    if (kn->flags & EV_DISPATCH_) kn->enabled = 0;
                    continue;
                }
                int fd = (int)(uint32_t)d;
                for (int pass = 0; pass < 2; pass++) {
                    int16_t filt = pass == 0 ? EVFILT_READ_ : EVFILT_WRITE_;
                    uint32_t trig = pass == 0 ? (L_EPOLLIN | L_EPOLLRDHUP | L_EPOLLHUP | L_EPOLLERR)
                                              : (L_EPOLLOUT | L_EPOLLHUP | L_EPOLLERR);
                    if (!(e & trig)) continue;
                    int k = kn_find(p, p->kq, (uint64_t)fd, filt);
                    if (k < 0 || !p->sh->kn[k].enabled) continue;
                    knote_t *kn = &p->sh->kn[k];
                    struct fbsd_kevent o;
                    memset(&o, 0, sizeof(o));
                    o.ident = (uint64_t)fd;
                    o.filter = filt;
                    o.flags = kn->flags;
                    if (e & (L_EPOLLHUP | L_EPOLLERR | (pass == 0 ? L_EPOLLRDHUP : 0)))
                        o.flags |= EV_EOF_;
                    o.data = KQ_DATA_GUESS;
                    o.udata = kn->udata;
                    add_out(p, &o);
                    if (kn->flags & (EV_ONESHOT_ | EV_DISPATCH_)) {
                        if (kn->flags & EV_ONESHOT_) kn->used = 0;
                        else kn->enabled = 0;
                        fdstate_t *f = fs_get(p, p->kq, fd, 0);
                        if (f) f->dirty = 1;
                    }
                }
            }
            free(evs);
            p->phase = P_DRAIN;
            p->drain_i = 0;
            break;
        }

        case OP_DRAIN:
            p->drain_i++;
            break;

        case OP_SCRATCH:
            if (rv < 0 && rv > -4096) { finish(pid, p, rv); return 2; }
            p->scratch = (uint64_t)rv;
            p->phase = P_CHANGES;
            break;

        default:
            break;
    }
    return kq_run(pid, p, 0) ? 1 : 2;
}

/* Advance until a syscall is issued (returns 1) or the call is finished
 * (returns 0; registers already hold the result). */
static int kq_run(pid_t pid, kqproc_t *p, int at_entry) {
    for (;;) {
        switch (p->phase) {
            case P_SCRATCH:
                /* This thread's scratch memory (threads share kqueues) */
                p->op = OP_SCRATCH;
                if (issue(pid, p, at_entry, SYS_mmap, 0, SCRATCH_SIZE, 3,
                          0x22, (uint64_t)-1, 0) == 0)
                    return 1;
                p->phase = P_DONE;
                continue;

            case P_CHANGES:
                if (p->ci >= p->nchanges) { p->phase = P_SYNC; continue; }
                if (apply_change(pid, p, at_entry)) return 1;
                continue;

            case P_SYNC:
                for (int i = 0; i < p->sh->nfs; i++) {
                    fdstate_t *f = &p->sh->fs[i];
                    if (!f->used || f->kq != p->kq || !f->dirty) continue;
                    uint32_t want = wanted_mask(p, p->kq, f->fd);
                    f->dirty = 0;
                    if (want == f->mask) continue;
                    int op = want == 0 ? L_EPOLL_CTL_DEL : (f->mask ? L_EPOLL_CTL_MOD : L_EPOLL_CTL_ADD);
                    p->op = OP_SYNC;
                    if (ctl(pid, p, at_entry, op, f->fd, want, (uint64_t)(uint32_t)f->fd) == 0) return 1;
                }
                p->phase = P_WAIT;
                continue;

            case P_WAIT: {
                /* Events that did not fit last time come first */
                int j = 0;
                for (int i = 0; i < p->sh->nleft; i++) {
                    if (p->sh->left[i].kq == p->kq && p->nout < p->nevents) p->out[p->nout++] = p->sh->left[i].ev;
                    else p->sh->left[j++] = p->sh->left[i];
                }
                p->sh->nleft = j;
                if (p->nout > 0 || p->nevents == 0) { p->phase = P_DONE; continue; }
                int maxev = p->nevents < MAX_WAIT_EVENTS ? p->nevents : MAX_WAIT_EVENTS;
                p->op = OP_WAIT;
                if (issue(pid, p, at_entry, SYS_epoll_wait, (uint64_t)p->kq,
                          p->scratch + SCRATCH_EVENTS, (uint64_t)maxev,
                          (uint64_t)p->timeout_ms, 0, 0) < 0) {
                    p->phase = P_DONE;
                    continue;
                }
                return 1;
            }

            case P_DRAIN:
                if (p->drain && p->drain_i < p->ndrain) {
                    p->op = OP_DRAIN;
                    if (issue(pid, p, at_entry, SYS_read, (uint64_t)p->drain[p->drain_i],
                              p->scratch + SCRATCH_U64, 8, 0, 0, 0) == 0)
                        return 1;
                    p->drain_i++;
                    continue;
                }
                p->phase = P_DONE;
                continue;

            case P_DONE:
            default: {
                long res = p->nout;
                if (p->nout > 0 && p->eventlist &&
                    wr(pid, p->out, p->eventlist, (size_t)p->nout * sizeof(struct fbsd_kevent)) < 0)
                    res = -EFAULT;
                if (at_entry) {
                    /* Nothing ran in the kernel: the handler returns it */
                    p->final = res;
                    return 0;
                }
                finish(pid, p, res);
                return 0;
            }
        }
    }
}

int kq_on_syscall_exit(pid_t pid) {
    kqproc_t *p = find_proc(pid);
    if (!p || p->call == CALL_NONE) return 0;
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r) < 0) return 0;
    return kq_complete(pid, p, (long)(int64_t)r.rax);
}

/* ---------------------------------------------------------------------
 * Syscall handlers
 * ------------------------------------------------------------------- */

long kq_emul_kqueue(pid_t pid, uint64_t args[6]) {
    (void)args;
    kqproc_t *p = get_proc(pid);
    if (!p) return -ENOMEM;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &p->entry) < 0) return -EFAULT;
    p->call = CALL_KQUEUE;
    p->op = OP_CREATE;
    if (issue(pid, p, 1, SYS_epoll_create1, L_EPOLL_CLOEXEC, 0, 0, 0, 0, 0) < 0) {
        free_call(p);
        return -EFAULT;
    }
    return -EAGAIN;
}

long kq_emul_kevent(pid_t pid, uint64_t args[6]) {
    /* kevent(kq, changelist, nchanges, eventlist, nevents, timeout) */
    kqproc_t *p = get_proc(pid);
    if (!p) return -ENOMEM;
    int nchanges = (int)args[2], nevents = (int)args[4];
    if (nchanges < 0 || nevents < 0) return -EINVAL;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &p->entry) < 0) return -EFAULT;
    p->kq = (int)args[0];
    p->nchanges = nchanges;
    p->ci = 0;
    p->eventlist = args[3];
    p->nevents = nevents;
    p->nout = 0;
    p->ndrain = 0;
    p->changes = nchanges ? malloc((size_t)nchanges * sizeof(struct fbsd_kevent)) : NULL;
    p->out = malloc((size_t)(nevents ? nevents : 1) * sizeof(struct fbsd_kevent));
    if ((nchanges && !p->changes) || !p->out) { free_call(p); return -ENOMEM; }
    if (nchanges && rd(pid, p->changes, args[1], (size_t)nchanges * sizeof(struct fbsd_kevent)) < 0) {
        free_call(p);
        return -EFAULT;
    }
    p->timeout_ms = -1;
    if (args[5]) {
        int64_t ts[2];
        if (rd(pid, ts, args[5], sizeof(ts)) < 0) { free_call(p); return -EFAULT; }
        if (ts[0] < 0 || ts[1] < 0 || ts[1] >= 1000000000) { free_call(p); return -EINVAL; }
        int64_t ms = ts[0] * 1000 + (ts[1] + 999999) / 1000000;
        p->timeout_ms = ms > 0x7fffffff ? 0x7fffffff : ms;
    }
    p->phase = p->scratch ? P_CHANGES : P_SCRATCH;
    p->call = CALL_KEVENT;

    if (kq_run(pid, p, 1)) return -EAGAIN;  /* first step issued */

    /* Finished without a syscall */
    long n = p->final;
    free_call(p);
    return n;
}
