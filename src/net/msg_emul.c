/*
 * msg_emul.c - sendmsg/recvmsg and MSG_* flags
 *
 * FreeBSD and Linux differ in:
 *   struct msghdr   FreeBSD: msg_iovlen and msg_controllen are 32-bit
 *                   (48 bytes); Linux: size_t (56 bytes)
 *   struct cmsghdr  FreeBSD: cmsg_len is 32-bit, header padded to 16;
 *                   Linux: cmsg_len is size_t (16 bytes). Data offset is
 *                   16 on both, so SCM_RIGHTS payloads line up.
 *   SOL_SOCKET      FreeBSD 0xffff, Linux 1
 *   MSG_* flags     several values differ
 *   sockaddr        sa_len byte; AF_INET6 28 vs 10
 *
 * Each call gets a Linux msghdr (and converted name and control data)
 * below the process's stack; recvmsg results are converted back at exit.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>

#include "bsdulator.h"
#include "bsdulator/interceptor.h"
#include "bsdulator/syscall.h"
#include "bsdulator/msg_emul.h"

#define FBSD_SOL_SOCKET 0xffff
#define L_SOL_SOCKET    1
#define CTL_MAX         4096
#define NAME_MAX_       128

struct fbsd_msghdr {
    uint64_t msg_name;
    uint32_t msg_namelen;
    uint32_t pad0;
    uint64_t msg_iov;
    int32_t  msg_iovlen;
    int32_t  pad1;
    uint64_t msg_control;
    uint32_t msg_controllen;
    int32_t  msg_flags;
};
_Static_assert(sizeof(struct fbsd_msghdr) == 48, "FreeBSD struct msghdr");

struct linux_msghdr {
    uint64_t msg_name;
    uint32_t msg_namelen;
    uint32_t pad0;
    uint64_t msg_iov;
    uint64_t msg_iovlen;
    uint64_t msg_control;
    uint64_t msg_controllen;
    int32_t  msg_flags;
    int32_t  pad1;
};
_Static_assert(sizeof(struct linux_msghdr) == 56, "Linux struct msghdr");

static const struct { uint32_t f, l; } flag_map[] = {
    { 0x00001, 0x00001 },        /* MSG_OOB */
    { 0x00002, 0x00002 },        /* MSG_PEEK */
    { 0x00004, 0x00004 },        /* MSG_DONTROUTE */
    { 0x00008, 0x00080 },        /* MSG_EOR */
    { 0x00010, 0x00020 },        /* MSG_TRUNC */
    { 0x00020, 0x00008 },        /* MSG_CTRUNC */
    { 0x00040, 0x00100 },        /* MSG_WAITALL */
    { 0x00080, 0x00040 },        /* MSG_DONTWAIT */
    { 0x20000, 0x04000 },        /* MSG_NOSIGNAL */
    { 0x40000, 0x40000000 },     /* MSG_CMSG_CLOEXEC */
    { 0x80000, 0x10000 },        /* MSG_WAITFORONE */
};

uint32_t msg_flags_to_linux(uint32_t f) {
    uint32_t l = 0;
    for (size_t i = 0; i < sizeof(flag_map) / sizeof(flag_map[0]); i++)
        if (f & flag_map[i].f) l |= flag_map[i].l;
    return l;
}

static uint32_t msg_flags_to_fbsd(uint32_t l) {
    uint32_t f = 0;
    for (size_t i = 0; i < sizeof(flag_map) / sizeof(flag_map[0]); i++)
        if (l & flag_map[i].l) f |= flag_map[i].f;
    return f;
}

static int rd(pid_t pid, void *d, uint64_t a, size_t n) {
    return interceptor_read_mem(pid, d, (const void *)a, n) == (ssize_t)n ? 0 : -1;
}
static int wr(pid_t pid, const void *s, uint64_t a, size_t n) {
    return interceptor_write_mem(pid, s, (void *)a, n) == (ssize_t)n ? 0 : -1;
}

/* Control messages: same payload offsets; rewrite each header. */
static size_t cmsgs_to_linux(const uint8_t *in, size_t len, uint8_t *out) {
    size_t i = 0;
    while (i + 12 <= len) {
        uint32_t clen;
        int32_t level, type;
        memcpy(&clen, in + i, 4);
        memcpy(&level, in + i + 4, 4);
        memcpy(&type, in + i + 8, 4);
        if (clen < 16 || i + clen > len) break;
        uint64_t l64 = clen;
        int32_t ll = level == FBSD_SOL_SOCKET ? L_SOL_SOCKET : level;
        memcpy(out + i, &l64, 8);
        memcpy(out + i + 8, &ll, 4);
        memcpy(out + i + 12, &type, 4);
        memcpy(out + i + 16, in + i + 16, clen - 16);
        i += (clen + 7) & ~(size_t)7;
    }
    return i < len ? i : len;
}

static size_t cmsgs_to_fbsd(const uint8_t *in, size_t len, uint8_t *out) {
    size_t i = 0;
    while (i + 16 <= len) {
        uint64_t clen;
        int32_t level, type;
        memcpy(&clen, in + i, 8);
        memcpy(&level, in + i + 8, 4);
        memcpy(&type, in + i + 12, 4);
        if (clen < 16 || i + clen > len) break;
        uint32_t c32 = (uint32_t)clen;
        int32_t fl = level == L_SOL_SOCKET ? FBSD_SOL_SOCKET : level;
        memset(out + i, 0, 16);
        memcpy(out + i, &c32, 4);
        memcpy(out + i + 4, &fl, 4);
        memcpy(out + i + 8, &type, 4);
        memcpy(out + i + 16, in + i + 16, clen - 16);
        i += (clen + 7) & ~(size_t)7;
    }
    return i < len ? i : len;
}

/* recvmsg in progress, per process */
#define MAX_MSG 64
static struct {
    pid_t pid;
    uint64_t fmsg;      /* program's FreeBSD msghdr */
    uint64_t lmsg;      /* our Linux msghdr */
    uint64_t name, ctl; /* program's buffers */
    uint64_t lname, lctl;
} pend[MAX_MSG];

static int slot(pid_t pid, int create) {
    int f = -1;
    for (int i = 0; i < MAX_MSG; i++) {
        if (pend[i].pid == pid) return i;
        if (f < 0 && pend[i].pid == 0) f = i;
    }
    if (!create) return -1;
    if (f < 0) f = 0;
    memset(&pend[f], 0, sizeof(pend[f]));
    pend[f].pid = pid;
    return f;
}

/* Lay out a Linux msghdr (+ name + control) below the stack. */
static long build(pid_t pid, uint64_t fmsg_addr, int for_recv,
                  uint64_t *lmsg_out, struct fbsd_msghdr *fm,
                  uint64_t *lname_out, uint64_t *lctl_out) {
    if (rd(pid, fm, fmsg_addr, sizeof(*fm)) < 0) return -EFAULT;
    if (fm->msg_iovlen < 0 || fm->msg_controllen > CTL_MAX || fm->msg_namelen > NAME_MAX_)
        return -EINVAL;

    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r) < 0) return -EFAULT;
    uint64_t base = (r.rsp - 4096 - (sizeof(struct linux_msghdr) + NAME_MAX_ + CTL_MAX)) & ~15ULL;
    uint64_t lmsg = base;
    uint64_t lname = base + 64;
    uint64_t lctl = lname + NAME_MAX_;

    struct linux_msghdr lm;
    memset(&lm, 0, sizeof(lm));
    lm.msg_iov = fm->msg_iov;
    lm.msg_iovlen = (uint64_t)fm->msg_iovlen;
    lm.msg_flags = 0;

    if (fm->msg_name && fm->msg_namelen) {
        lm.msg_name = lname;
        lm.msg_namelen = fm->msg_namelen;
        if (!for_recv) {
            uint8_t f[NAME_MAX_], l[NAME_MAX_];
            memset(l, 0, sizeof(l));
            if (rd(pid, f, fm->msg_name, fm->msg_namelen) < 0) return -EFAULT;
            uint16_t fam = f[1] == 28 ? 10 : f[1];
            memcpy(l, &fam, 2);
            if (fm->msg_namelen > 2) memcpy(l + 2, f + 2, fm->msg_namelen - 2);
            if (wr(pid, l, lname, fm->msg_namelen) < 0) return -EFAULT;
        }
    }
    if (fm->msg_control && fm->msg_controllen) {
        lm.msg_control = lctl;
        lm.msg_controllen = fm->msg_controllen;
        if (!for_recv) {
            uint8_t in[CTL_MAX], out[CTL_MAX];
            memset(out, 0, sizeof(out));
            if (rd(pid, in, fm->msg_control, fm->msg_controllen) < 0) return -EFAULT;
            lm.msg_controllen = cmsgs_to_linux(in, fm->msg_controllen, out);
            if (wr(pid, out, lctl, fm->msg_controllen) < 0) return -EFAULT;
        }
    }
    if (wr(pid, &lm, lmsg, sizeof(lm)) < 0) return -EFAULT;
    *lmsg_out = lmsg;
    *lname_out = lname;
    *lctl_out = lctl;
    return 0;
}

long msg_emul_sendmsg(pid_t pid, uint64_t args[6]) {
    /* sendmsg(s, msg, flags) */
    struct fbsd_msghdr fm;
    uint64_t lmsg, lname, lctl;
    long rv = build(pid, args[1], 0, &lmsg, &fm, &lname, &lctl);
    if (rv < 0) return rv;
    args[1] = lmsg;
    args[2] = msg_flags_to_linux((uint32_t)args[2]);
    return -EAGAIN;  /* run Linux sendmsg */
}

long msg_emul_recvmsg(pid_t pid, uint64_t args[6]) {
    /* recvmsg(s, msg, flags) */
    struct fbsd_msghdr fm;
    uint64_t lmsg, lname, lctl;
    long rv = build(pid, args[1], 1, &lmsg, &fm, &lname, &lctl);
    if (rv < 0) return rv;
    int i = slot(pid, 1);
    pend[i].fmsg = args[1];
    pend[i].lmsg = lmsg;
    pend[i].name = fm.msg_name;
    pend[i].ctl = fm.msg_control;
    pend[i].lname = lname;
    pend[i].lctl = lctl;
    args[1] = lmsg;
    args[2] = msg_flags_to_linux((uint32_t)args[2]);
    return -EAGAIN;  /* run Linux recvmsg */
}

void msg_after_syscall(pid_t pid, uint64_t nr) {
    if (nr != FBSD_SYS_recvmsg) return;
    int i = slot(pid, 0);
    if (i < 0) return;
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &r) < 0 || (r.eflags & 1)) { pend[i].pid = 0; return; }

    struct linux_msghdr lm;
    struct fbsd_msghdr fm;
    if (rd(pid, &lm, pend[i].lmsg, sizeof(lm)) < 0 || rd(pid, &fm, pend[i].fmsg, sizeof(fm)) < 0) {
        pend[i].pid = 0;
        return;
    }
    if (pend[i].name && lm.msg_namelen >= 2 && lm.msg_namelen <= NAME_MAX_) {
        uint8_t a[NAME_MAX_];
        if (rd(pid, a, pend[i].lname, lm.msg_namelen) == 0) {
            uint16_t fam;
            memcpy(&fam, a, 2);
            a[0] = (uint8_t)lm.msg_namelen;
            a[1] = fam == 10 ? 28 : (uint8_t)fam;
            (void)wr(pid, a, pend[i].name, lm.msg_namelen);
        }
        fm.msg_namelen = lm.msg_namelen;
    } else if (pend[i].name) {
        fm.msg_namelen = 0;
    }
    if (pend[i].ctl && lm.msg_controllen && lm.msg_controllen <= CTL_MAX) {
        uint8_t in[CTL_MAX], out[CTL_MAX];
        memset(out, 0, sizeof(out));
        if (rd(pid, in, pend[i].lctl, lm.msg_controllen) == 0) {
            size_t n = cmsgs_to_fbsd(in, lm.msg_controllen, out);
            (void)wr(pid, out, pend[i].ctl, n);
            fm.msg_controllen = (uint32_t)n;
        }
    } else {
        fm.msg_controllen = 0;
    }
    fm.msg_flags = (int32_t)msg_flags_to_fbsd((uint32_t)lm.msg_flags);
    (void)wr(pid, &fm, pend[i].fmsg, sizeof(fm));
    pend[i].pid = 0;
}
