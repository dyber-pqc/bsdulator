/*
 * lochs_ns.h - per-container PID, mount, UTS and IPC namespaces
 */

#ifndef LOCHS_NS_H
#define LOCHS_NS_H

#include <stddef.h>
#include <sys/types.h>

/* Create the container's namespaces (holder process); returns its host
 * pid, the existing one if already running, or -1 */
pid_t lochs_ns_start(const char *name, const char *root);

/* Holder pid of a running container, or 0 */
pid_t lochs_ns_pid(const char *name);

/* End the container's namespaces and every process in them */
void lochs_ns_stop(const char *name);

/* Append "-N <pid>" to a bsdulator argv if the container has namespaces.
 * buf holds the pid text and must outlive argv. Returns 1 if added. */
int lochs_ns_add_args(const char *name, const char **argv, int *n, char *buf, size_t bufsz);

/* Container uid/gid N is host <base> + N. Each container has its own base
 * (LOCHS_ID_BASE + k * LOCHS_ID_COUNT, k >= 1); LOCHS_ID_BASE itself is the
 * range shared by all containers on kernels without idmapped layers. */
#define LOCHS_ID_BASE  100000
#define LOCHS_ID_COUNT 65536

/* The container's own range: allocated at first use, kept until freed
 * (lochs rm). Returns its base. */
uid_t lochs_ids_alloc(const char *name);
void lochs_ids_free(const char *name);

/* The range a running container uses (set at start, before
 * lochs_ns_start, which maps it); LOCHS_ID_BASE if unset */
void lochs_ns_set_base(const char *name, uid_t base);
uid_t lochs_ns_base(const char *name);

/* Move ownership in a tree from ids from..from+COUNT-1 to to..; other
 * owners and device nodes are left alone */
int lochs_idshift_tree(const char *dir, uid_t from, uid_t to);

/* Bring an image layer (shared by containers) to ids want..: 0 for
 * container ids on disk (idmapped mounts), LOCHS_ID_BASE for the shared
 * range. Remembers the image's state; lochs_image_ids_forget drops it. */
int lochs_image_ids(const char *image_path, uid_t want);
void lochs_image_ids_forget(const char *image_path);
/* Record an image's current form without shifting it (a fresh copy) */
int lochs_image_ids_set(const char *image_path, uid_t state);

/* The same for any shared tree, under a state key ("volume.<name>") */
int lochs_tree_ids(const char *key, const char *path, uid_t want);
void lochs_tree_ids_forget(const char *key);

/* Make lochs storage (images, containers, volumes) root-only: it holds
 * files owned by host ids 0.. that host users must not reach */
void lochs_storage_lockdown(void);

/* Bind src at dst idmapped: on-disk ids uid_first../gid_first.. (count of
 * each) become host ids host.. Optionally read-only, nosuid and nodev.
 * Returns 0, or -1 with errno (the filesystem may not support it). */
int lochs_idmap_bind(const char *src, const char *dst, uid_t uid_first, gid_t gid_first,
                     uid_t host, unsigned count, int readonly, int nosuid);

/* Can this kernel mount an overlay over idmapped layers? */
int lochs_idmap_supported(void);

/* Mount the container's overlay at merged over idmapped views of image and
 * cdir (holding diff/ and work/), for ids base..; and undo it */
int lochs_idmap_mount_overlay(const char *name, uid_t base, const char *image,
                              const char *cdir, const char *merged);
void lochs_idmap_unmount(const char *name);

/* The container's own network namespace ("lochs-<name>") with a veth
 * pair, a private IP and outbound NAT. netns receives its name. */
int lochs_ns_net_up(const char *name, char *netns, size_t netns_sz);
void lochs_ns_net_down(const char *name);

/* The container's IP from lochs_ns_net_up, or NULL */
const char *lochs_ns_ip(const char *name);

#endif /* LOCHS_NS_H */
