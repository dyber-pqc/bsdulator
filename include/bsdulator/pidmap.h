/*
 * pidmap.h - process ids between the host and a container's PID namespace
 *
 * The tracer runs in the host PID namespace and sees host ids (waitpid,
 * PTRACE_GETEVENTMSG). A containerized process sees ids in its own
 * namespace. Ids the tracer hands to a process (thr_self, thread ids,
 * procctl results) must be the process's view; ids a process passes to an
 * emulated syscall (thr_kill, kern.proc.pathname) must be mapped back.
 * Outside a container both views are the same.
 */

#ifndef BSDULATOR_PIDMAP_H
#define BSDULATOR_PIDMAP_H

#include <sys/types.h>

/* The id of host task `host` as seen inside its own PID namespace */
pid_t pid_to_ns(pid_t host);

/* The host id of the task that `ref` (a host id) knows as `ns`; ns itself
 * if ref is not in a child namespace, or -1 if no such task */
pid_t pid_from_ns(pid_t ns, pid_t ref);

#endif /* BSDULATOR_PIDMAP_H */
