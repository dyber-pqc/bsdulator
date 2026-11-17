/*
 * lochs_ns.h - per-container PID, mount, UTS and IPC namespaces
 */

#ifndef LOCHS_NS_H
#define LOCHS_NS_H

#include <stddef.h>
#include <sys/types.h>

/* Create the container's namespaces (holder process); returns its host
 * pid, the existing one if already running, or -1 */
pid_t lochs_ns_start(const char *name);

/* Holder pid of a running container, or 0 */
pid_t lochs_ns_pid(const char *name);

/* End the container's namespaces and every process in them */
void lochs_ns_stop(const char *name);

/* Append "-N <pid>" to a bsdulator argv if the container has namespaces.
 * buf holds the pid text and must outlive argv. Returns 1 if added. */
int lochs_ns_add_args(const char *name, const char **argv, int *n, char *buf, size_t bufsz);

#endif /* LOCHS_NS_H */
