/*
 * chain.c - run a short sequence of Linux syscalls in a traced thread
 * (see include/bsdulator/chain.h)
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

#include "bsdulator.h"
#include "bsdulator/chain.h"

int abi_translate_errno(int linux_errno);

typedef struct {
    pid_t pid;
    struct user_regs_struct entry;
    chain_step_t steps[CHAIN_MAX_STEPS];
    long results[CHAIN_MAX_STEPS];
    int n, i;
    chain_finish_t finish;
    uint64_t ctx[4];
} chain_t;

#define MAX_CHAINS 512
static chain_t *chains[MAX_CHAINS];

static int find(pid_t pid) {
    for (int i = 0; i < MAX_CHAINS; i++)
        if (chains[i] && chains[i]->pid == pid) return i;
    return -1;
}

static void set_args(struct user_regs_struct *r, const chain_step_t *s) {
    r->rdi = s->a[0]; r->rsi = s->a[1]; r->rdx = s->a[2];
    r->r10 = s->a[3]; r->r8 = s->a[4]; r->r9 = s->a[5];
}

long chain_begin(pid_t pid, const chain_step_t *steps, int n,
                 chain_finish_t finish, const uint64_t ctx[4]) {
    if (n < 1 || n > CHAIN_MAX_STEPS) return -EINVAL;
    if (find(pid) >= 0) return -EBUSY;
    int slot = -1;
    for (int i = 0; i < MAX_CHAINS; i++) if (!chains[i]) { slot = i; break; }
    if (slot < 0) return -ENOMEM;
    chain_t *c = calloc(1, sizeof(*c));
    if (!c) return -ENOMEM;
    c->pid = pid;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &c->entry) < 0) { free(c); return -EFAULT; }
    memcpy(c->steps, steps, (size_t)n * sizeof(*steps));
    c->n = n;
    c->finish = finish;
    if (ctx) memcpy(c->ctx, ctx, sizeof(c->ctx));

    /* First step: replace the FreeBSD syscall that is entering */
    struct user_regs_struct r = c->entry;
    r.orig_rax = (uint64_t)steps[0].nr;
    set_args(&r, &steps[0]);
    if (ptrace(PTRACE_SETREGS, pid, NULL, &r) < 0) { free(c); return -EFAULT; }
    chains[slot] = c;
    return -EAGAIN;
}

int chain_busy(pid_t pid) {
    return find(pid) >= 0;
}

int chain_on_exit(pid_t pid) {
    int k = find(pid);
    if (k < 0) return 0;
    chain_t *c = chains[k];
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r) < 0) return 0;
    c->results[c->i++] = (long)(int64_t)r.rax;

    if (c->i < c->n) {
        /* Back to the syscall instruction with the next step */
        r.rip = c->entry.rip - 2;
        r.rax = (uint64_t)c->steps[c->i].nr;
        r.orig_rax = (uint64_t)-1;
        set_args(&r, &c->steps[c->i]);
        if (ptrace(PTRACE_SETREGS, pid, NULL, &r) == 0) return 1;
        c->results[c->i++] = -EFAULT;
        while (c->i < c->n) c->results[c->i++] = -EFAULT;
    }

    long ret = c->finish ? c->finish(pid, c->results, c->n, c->ctx) : 0;
    r = c->entry;
    if (ret < 0) {
        r.rax = (uint64_t)abi_translate_errno((int)-ret);
        r.eflags |= 1;   /* CF: error */
    } else {
        r.rax = (uint64_t)ret;
        r.eflags &= ~1ULL;
    }
    r.orig_rax = (uint64_t)-1;  /* no syscall restart */
    (void)ptrace(PTRACE_SETREGS, pid, NULL, &r);
    free(c);
    chains[k] = NULL;
    return 2;
}

void chain_proc_exit(pid_t pid) {
    int k = find(pid);
    if (k >= 0) {
        free(chains[k]);
        chains[k] = NULL;
    }
}
