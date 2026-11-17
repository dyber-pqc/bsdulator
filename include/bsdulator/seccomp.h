/*
 * seccomp.h - syscall filter for container processes
 */

#ifndef BSDULATOR_SECCOMP_H
#define BSDULATOR_SECCOMP_H

/*
 * Install the container filter on the calling process (inherited by
 * everything it starts). Sets no_new_privs. Returns 0, or -1 with errno.
 */
int container_seccomp_install(void);

/* The same for a tracer running in the container: its tracees can still
 * be traced and read (ptrace, process_vm_readv/writev) */
int container_seccomp_install_tracer(void);

#endif /* BSDULATOR_SECCOMP_H */
