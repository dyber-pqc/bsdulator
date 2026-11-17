/*
 * kqueue_emul.h - FreeBSD kqueue/kevent on Linux epoll, in the traced process
 *
 * kqueue() is an epoll instance in the traced process. kevent() becomes a
 * short chain of Linux syscalls run by the process itself (epoll_ctl for
 * each change, then epoll_wait), so a blocking kevent blocks only that
 * process, never the tracer. The tracer keeps the knotes (filters, flags,
 * udata) and converts epoll events back to FreeBSD struct kevent.
 *
 * The chain works at syscall stops: at the exit of one step the tracer
 * points the process back at its syscall instruction with the next
 * syscall's number and arguments.
 *
 * Supported filters: EVFILT_READ, EVFILT_WRITE, EVFILT_USER (eventfd).
 */

#ifndef BSDULATOR_KQUEUE_EMUL_H
#define BSDULATOR_KQUEUE_EMUL_H

#include <stdint.h>
#include <sys/types.h>

/* Syscall table handlers; both return -EAGAIN after setting the first
 * Linux syscall of their chain themselves (or a final result). */
long kq_emul_kqueue(pid_t pid, uint64_t args[6]);
long kq_emul_kevent(pid_t pid, uint64_t args[6]);

/* At syscall entry: 1 if pid is running a step of a kqueue chain (the
 * syscall is Linux and must not be translated). */
int kq_on_syscall_entry(pid_t pid);

/* At syscall exit, before any other processing: 0 if the exit is not
 * part of a kqueue chain; 1 if the next step was issued; 2 if the call
 * finished (registers hold its result). */
int kq_on_syscall_exit(pid_t pid);

/* 1 while pid is inside a kevent/kqueue chain: signal handlers must
 * wait until it returns. */
int kq_busy(pid_t pid);

/* After any syscall exit: forget knotes of descriptors that close() freed
 * (the kernel drops them from epoll by itself). */
void kq_after_syscall(pid_t pid, uint64_t nr, const uint64_t args[6]);

/* Process lifecycle */
void kq_proc_exec(pid_t pid);
void kq_proc_exit(pid_t pid);

#endif /* BSDULATOR_KQUEUE_EMUL_H */
