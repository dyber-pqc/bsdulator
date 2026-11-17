/*
 * chain.h - run a short sequence of Linux syscalls in a traced thread
 *
 * Some FreeBSD syscalls need several Linux syscalls in the calling thread
 * (thr_exit: wake joiners, then exit; _umtx_op: set a bit atomically,
 * then sleep). A syscall handler calls chain_begin() at syscall entry with
 * the steps; the first runs in place of the FreeBSD syscall, and at each
 * exit the thread is pointed back at its syscall instruction with the
 * next step. After the last step, finish() turns the step results into
 * the FreeBSD syscall's return value.
 */

#ifndef BSDULATOR_CHAIN_H
#define BSDULATOR_CHAIN_H

#include <stdint.h>
#include <sys/types.h>

#define CHAIN_MAX_STEPS 136

typedef struct {
    long     nr;        /* Linux syscall number */
    uint64_t a[6];
} chain_step_t;

/* Returns the FreeBSD syscall's result: >= 0, or -linux_errno. */
typedef long (*chain_finish_t)(pid_t pid, const long *results, int n,
                               const uint64_t ctx[4]);

/* Start a chain at syscall entry. Returns -EAGAIN when the first step is
 * issued (the handler returns it), or -errno on failure. */
long chain_begin(pid_t pid, const chain_step_t *steps, int n,
                 chain_finish_t finish, const uint64_t ctx[4]);

/* 1 while pid runs a chain (its syscalls are Linux and not translated) */
int chain_busy(pid_t pid);

/* At syscall exit, before other processing: 0 if not a chain step;
 * 1 if the next step was issued; 2 if the chain finished. */
int chain_on_exit(pid_t pid);

void chain_proc_exit(pid_t pid);

#endif /* BSDULATOR_CHAIN_H */
