/*
 * BSDulator - Netlink Socket Emulation Header
 */

#ifndef BSDULATOR_NETLINK_H
#define BSDULATOR_NETLINK_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* FreeBSD socket domains */
#define FBSD_AF_ROUTE    17   /* FreeBSD routing socket */

/* FreeBSD sysctl NET_RT_* values */
#define FBSD_NET_RT_DUMP      1   /* Dump routing table */
#define FBSD_NET_RT_FLAGS     2   /* Routing entries by flags */
#define FBSD_NET_RT_IFLIST    3   /* Interface list */
#define FBSD_NET_RT_IFMALIST  4   /* Multicast address list */
#define FBSD_NET_RT_IFLISTL   5   /* Interface list (long) */

/* Initialize netlink emulation */
int netlink_init(void);

/* Handle sysctl for interface list (NET_RT_IFLIST) */
int netlink_handle_sysctl_iflist(pid_t pid, uint64_t buf_addr, size_t *buflen, int af);

/* Translate socket() call for routing sockets */
int netlink_translate_socket(int *domain, int *type, int *protocol);

/* Check if fd needs read translation */
int netlink_needs_read_translation(int fd);

/* Invalidate interface cache */
void netlink_invalidate_cache(void);

#endif /* BSDULATOR_NETLINK_H */
