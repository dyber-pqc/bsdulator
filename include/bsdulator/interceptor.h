/*
 * BSDulator - Syscall Interceptor
 * ptrace-based syscall interception for FreeBSD binaries
 */

#ifndef BSDULATOR_INTERCEPTOR_H
#define BSDULATOR_INTERCEPTOR_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

/* Interceptor event types */
typedef enum {
    EVENT_NONE,
    EVENT_SYSCALL_ENTER,
    EVENT_SYSCALL_EXIT,
    EVENT_SIGNAL,
    EVENT_EXIT,
    EVENT_FORK,
    EVENT_VFORK,
    EVENT_EXEC,
    EVENT_CLONE
} event_type_t;

/* Register state (x86_64) */
typedef struct {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rbp;
    uint64_t rsp;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
    uint64_t orig_rax;
    uint64_t eflags;
} regs_t;

/* Interceptor state for a traced process */
typedef struct {
    pid_t pid;               /* Traced process PID */
    bool running;            /* Is the process running? */
    bool in_syscall;         /* At syscall entry (true) or exit (false)? */
    bool skip_post_exec;     /* Skip phantom syscall stop after exec */
    event_type_t last_event; /* Last event type */
    
    /* Current syscall info */
    uint64_t syscall_nr;     /* Syscall number (FreeBSD) */
    uint64_t args[6];        /* Syscall arguments */
    int64_t retval;          /* Syscall return value */
    
    /* Signal info */
    int signal;              /* Signal number if EVENT_SIGNAL */
    
    /* Exit info */
    int exit_code;           /* Exit code if EVENT_EXIT */
    
    /* Statistics */
    uint64_t syscall_count;  /* Total syscalls intercepted */
    uint64_t translated_count; /* Successfully translated */
    uint64_t emulated_count; /* Emulated in userspace */
    uint64_t failed_count;   /* Failed/unsupported */
} interceptor_state_t;

/* Initialize interceptor subsystem */
int interceptor_init(void);

/* Cleanup interceptor */
void interceptor_cleanup(void);

/* Fork and exec a binary under trace */
pid_t interceptor_spawn(const char *binary, char *const argv[], char *const envp[]);

/* Attach to an existing process */
int interceptor_attach(pid_t pid);

/* Detach from a traced process */
int interceptor_detach(pid_t pid);

/* Wait for next event from traced process */
int interceptor_wait(interceptor_state_t *state);

/* Continue traced process to next syscall */
int interceptor_continue(interceptor_state_t *state);

/* Continue with signal delivery */
int interceptor_continue_signal(interceptor_state_t *state, int signal);

/* Get current register state */
int interceptor_get_regs(pid_t pid, regs_t *regs);

/* Set register state */
int interceptor_set_regs(pid_t pid, const regs_t *regs);

/* Modify syscall number */
int interceptor_set_syscall(pid_t pid, uint64_t syscall_nr);

/* Modify syscall arguments */
int interceptor_set_args(pid_t pid, uint64_t args[6]);

/* Modify syscall return value */
int interceptor_set_return(pid_t pid, int64_t retval);

/* Skip current syscall (make it return immediately) */
int interceptor_skip_syscall(pid_t pid, int64_t retval);

/* Read memory from traced process */
ssize_t interceptor_read_mem(pid_t pid, void *local, const void *remote, size_t len);

/* Write memory to traced process */
ssize_t interceptor_write_mem(pid_t pid, const void *local, void *remote, size_t len);

/* Read null-terminated string from traced process */
ssize_t interceptor_read_string(pid_t pid, char *local, const void *remote, size_t maxlen);

/* Main interception loop - runs until process exits */
int interceptor_run(interceptor_state_t *state);

/* Print statistics */
void interceptor_print_stats(const interceptor_state_t *state);

#endif /* BSDULATOR_INTERCEPTOR_H */
