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

/* Container uid/gid 0..LOCHS_ID_COUNT-1 is host LOCHS_ID_BASE + id */
#define LOCHS_ID_BASE  100000
#define LOCHS_ID_COUNT 65536

/* Shift ownership of a tree into the container id range (files already
 * shifted are left alone). With use_marker, a tree done once is skipped. */
int lochs_idshift_tree(const char *dir, int use_marker);

/* The container's own network namespace ("lochs-<name>") with a veth
 * pair, a private IP and outbound NAT. netns receives its name. */
int lochs_ns_net_up(const char *name, char *netns, size_t netns_sz);
void lochs_ns_net_down(const char *name);

/* The container's IP from lochs_ns_net_up, or NULL */
const char *lochs_ns_ip(const char *name);

#endif /* LOCHS_NS_H */
