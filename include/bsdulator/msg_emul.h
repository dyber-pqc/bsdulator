/*
 * msg_emul.h - sendmsg/recvmsg structure and MSG_* flag translation
 */

#ifndef BSDULATOR_MSG_EMUL_H
#define BSDULATOR_MSG_EMUL_H

#include <stdint.h>
#include <sys/types.h>

/* FreeBSD MSG_* flags to Linux */
uint32_t msg_flags_to_linux(uint32_t fbsd_flags);

/* Syscall handlers: -EAGAIN after pointing the call at a Linux msghdr */
long msg_emul_sendmsg(pid_t pid, uint64_t args[6]);
long msg_emul_recvmsg(pid_t pid, uint64_t args[6]);

/* At syscall exit: convert recvmsg results back to FreeBSD layout */
void msg_after_syscall(pid_t pid, uint64_t nr);

#endif /* BSDULATOR_MSG_EMUL_H */
