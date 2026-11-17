/*
 * thread_emul.h - FreeBSD threads (thr_*, _umtx_op) on Linux clone/futex
 *
 * thr_new() becomes clone() with CLONE_THREAD; the tracer points the new
 * thread at start_func(arg) on its stack at its first stop. _umtx_op()
 * maps FreeBSD's umtx objects onto Linux futexes on the same words; the
 * operations that need several steps run as a syscall chain (chain.h).
 */

#ifndef BSDULATOR_THREAD_EMUL_H
#define BSDULATOR_THREAD_EMUL_H

#include <stdint.h>
#include <sys/types.h>

long thr_emul_new(pid_t pid, uint64_t args[6]);     /* -EAGAIN: run clone */
long thr_emul_exit(pid_t pid, uint64_t args[6]);    /* chain */
long thr_emul_kill(pid_t pid, uint64_t args[6]);
long thr_emul_kill2(pid_t pid, uint64_t args[6]);
long thr_emul_umtx_op(pid_t pid, uint64_t args[6]); /* chain or result */
long thr_emul_rfork(pid_t pid, uint64_t args[6]);    /* -EAGAIN: run clone */

/* rfork: the child sees %rdx = 1, the parent %rdx = 0 */
int thr_rfork_child_first_stop(pid_t child);
void thr_rfork_after_syscall(pid_t pid);

/* PTRACE_EVENT_CLONE in the creating thread */
void thr_on_clone(pid_t parent, pid_t child);

/* First stop of a new task: 1 if it is a thr_new thread now set up to
 * run its start function. */
int thr_on_first_stop(pid_t pid);

/* At syscall exit: thr_new returns 0, not the thread id */
void thr_after_syscall(pid_t pid, uint64_t nr);

/* Thread group id of a task (from /proc), or pid if unknown */
pid_t thr_tgid(pid_t pid);

#endif /* BSDULATOR_THREAD_EMUL_H */
