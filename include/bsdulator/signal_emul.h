/*
 * signal_emul.h - FreeBSD signal semantics for traced processes
 *
 * The Linux kernel delivers every signal of a traced process to the
 * tracer first (signal-delivery-stop). bsdulator keeps each process's
 * FreeBSD signal state (handlers, mask, pending set, alternate stack) and
 * delivers signals the way the FreeBSD kernel does: it builds a FreeBSD
 * signal frame (siginfo_t + ucontext_t) on the process's stack and starts
 * the handler. The handler returns to SIG_RETURN_MAGIC, an address that is
 * never mapped; the resulting fault tells the tracer to restore the saved
 * context (like FreeBSD's sigreturn).
 *
 * The real Linux signal mask and dispositions of the process are left
 * alone (empty mask, default actions), so every signal reaches the tracer.
 */

#ifndef BSDULATOR_SIGNAL_EMUL_H
#define BSDULATOR_SIGNAL_EMUL_H

#include <stdint.h>
#include <sys/types.h>

/* Return address of handlers. Below mmap_min_addr, so never mapped. */
#define SIG_RETURN_MAGIC 0x5160ULL

/* Signal number translation (FreeBSD <-> Linux), including real-time
 * signals (FreeBSD 65.. <-> Linux 34..). 0 if there is no equivalent. */
int sig_fbsd_to_linux(int fbsd_sig);
int sig_linux_to_fbsd(int linux_sig);

/* Process lifecycle */
void sig_proc_start(pid_t pid);
void sig_proc_fork(pid_t parent, pid_t child);
void sig_proc_exec(pid_t pid);
void sig_proc_exit(pid_t pid);

/*
 * At a signal-delivery-stop: decide what happens to linux_sig. May build
 * a handler frame (changing the registers). Returns the Linux signal to
 * inject when resuming (0 = none).
 */
int sig_on_signal(pid_t pid, int linux_sig);

/*
 * At syscall entry, before translation. Returns 1 if this is the kernel's
 * restart_syscall for an interrupted sleep and must run untranslated.
 */
int sig_on_syscall_entry(pid_t pid, uint64_t nr);

/* At syscall exit with -ERESTART_RESTARTBLOCK. */
void sig_note_restart_block(pid_t pid);

/*
 * At the end of syscall exit processing (return value already set):
 * finishes sigreturn/setcontext, fixes wait4 status, and delivers a
 * pending signal that the syscall unblocked.
 */
void sig_after_syscall(pid_t pid, uint64_t fbsd_nr, const uint64_t args[6]);

/* Translate wait4 options (FreeBSD -> Linux). */
uint64_t sig_wait_options_to_linux(uint64_t fbsd_options);

/* Emulated syscalls (syscall table handlers). -EAGAIN means the handler
 * rewrote the arguments and the Linux syscall named by
 * sig_emul_linux_nr() must run. */
long sig_emul_sigaction(pid_t pid, uint64_t args[6]);
long sig_emul_sigprocmask(pid_t pid, uint64_t args[6]);
long sig_emul_sigpending(pid_t pid, uint64_t args[6]);
long sig_emul_sigsuspend(pid_t pid, uint64_t args[6]);
long sig_emul_sigreturn(pid_t pid, uint64_t args[6]);
long sig_emul_sigaltstack(pid_t pid, uint64_t args[6]);
long sig_emul_sigfastblock(pid_t pid, uint64_t args[6]);
long sig_emul_sigwait(pid_t pid, uint64_t args[6]);
long sig_emul_sigtimedwait(pid_t pid, uint64_t args[6]);
long sig_emul_sigwaitinfo(pid_t pid, uint64_t args[6]);
long sig_emul_getcontext(pid_t pid, uint64_t args[6]);
long sig_emul_setcontext(pid_t pid, uint64_t args[6]);
long sig_emul_swapcontext(pid_t pid, uint64_t args[6]);
long sig_emul_procctl(pid_t pid, uint64_t args[6]);   /* -EAGAIN: run prctl */
long sig_emul_wait6(pid_t pid, uint64_t args[6]);     /* -EAGAIN: run wait4 */
long sig_emul_fcntl(pid_t pid, uint64_t args[6]);     /* -EAGAIN: run fcntl */

#endif /* BSDULATOR_SIGNAL_EMUL_H */
