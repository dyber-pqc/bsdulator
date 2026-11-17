/*
 * syscall_fuzz.c - hostile arguments for the syscalls bsdulator parses
 *
 * A FreeBSD program (build it with FreeBSD's cc, e.g. inside a lochs
 * container) that hands the tracer bad pointers, structures running into
 * an unmapped page, huge counts and random structure contents with planted
 * pointers, for the syscalls whose arguments the tracer reads: thr_new,
 * kevent, sendmsg/recvmsg, sockaddrs, sigreturn and signal frames,
 * sysctl, jail_set/jail_get, readv/writev, _umtx_op, ioctl, execve argv,
 * paths, and more (plus random calls from an allowlist).
 *
 * The program itself is expected to crash often: each batch runs in a
 * forked child with an alarm, and the parent only counts how children
 * ended. What is being tested is the tracer: the run must end with the
 * "done" line, and a sanitizer build of bsdulator must report nothing.
 *
 *   syscall_fuzz [seed [batches [calls-per-batch]]]
 *   syscall_fuzz -v seed batch        (one batch, every call logged)
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/thr.h>
#include <sys/ucontext.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define PAGE        4096
#define ARENA_PAGES 64
#define ARENA_SIZE  (ARENA_PAGES * PAGE)

static uint64_t rs;
static char *arena;     /* ARENA_SIZE bytes, followed by an unmapped page */
static char *edge;      /* arena + ARENA_SIZE: first byte of the guard page */
static int verbose;
/* Shared with the parent: how many calls the children made, per target */
static struct { uint64_t calls; uint64_t by[64]; } *stats;
static int fds[8];      /* a few real descriptors to aim at */

static uint64_t rnd(void) {
    rs ^= rs << 13;
    rs ^= rs >> 7;
    rs ^= rs << 17;
    return rs;
}

static uint64_t pick(uint64_t n) { return n ? rnd() % n : 0; }

/* Raw FreeBSD syscall: no libc wrapper, no errno (TLS may be broken) */
static long sc(long n, uint64_t a1, uint64_t a2, uint64_t a3,
               uint64_t a4, uint64_t a5, uint64_t a6) {
    long ret;
    unsigned char cf;
    register uint64_t r10 __asm__("r10") = a4;
    register uint64_t r8 __asm__("r8") = a5;
    register uint64_t r9 __asm__("r9") = a6;
    __asm__ volatile("syscall; setc %1"
                     : "=a"(ret), "=r"(cf), "+D"(a1), "+S"(a2), "+d"(a3),
                       "+r"(r10), "+r"(r8), "+r"(r9)
                     : "a"(n)
                     : "rcx", "r11", "memory");
    return cf ? -ret : ret;
}

/* Where sigreturn and new threads land: exit without touching the stack */
extern void fz_exit_proc(void);
extern void fz_exit_thread(void);
__asm__(".text\n"
        ".globl fz_exit_proc\nfz_exit_proc:\n"
        "  mov $1, %eax\n  xor %edi, %edi\n  syscall\n  hlt\n"
        ".globl fz_exit_thread\nfz_exit_thread:\n"
        "  mov $431, %eax\n  xor %edi, %edi\n  syscall\n"
        "  mov $1, %eax\n  xor %edi, %edi\n  syscall\n  hlt\n");

/* ------------------------------------------------------------------ */
/* Hostile values                                                       */

/* A pointer for a want-byte object: often valid, often not */
static uint64_t ptr(size_t want) {
    if (want > ARENA_SIZE) want = ARENA_SIZE;
    switch (pick(12)) {
    case 0: return 0;
    case 1: return 1 + pick(PAGE);                          /* low, unmapped */
    case 2: return 0xffff800000000000ull + pick(1 << 20);   /* kernel half */
    case 3: return (uint64_t)-1 - pick(64);                 /* wraps */
    case 4: case 5:                                         /* runs into the guard */
        return (uint64_t)(edge - pick(want + 1));
    case 6: return (uint64_t)(arena + pick(ARENA_SIZE));    /* misaligned */
    case 7: return 0x00007ffffffff000ull + pick(PAGE);      /* top of user space */
    default:
        return (uint64_t)(arena + (pick(ARENA_SIZE - want + 1) & ~7ull));
    }
}

/* A length or count around a sane value */
static uint64_t len(uint64_t sane) {
    switch (pick(12)) {
    case 0: return 0;
    case 1: return 1;
    case 2: return sane ? sane - 1 : 0;
    case 3: return sane + 1;
    case 4: return pick(65536);
    case 5: return 0x7fffffff;
    case 6: return 0x80000000u;
    case 7: return (uint64_t)-1;
    case 8: return 1ull << 40;
    case 9: return 0xffffffffu;
    default: return sane;
    }
}

/* An interesting machine word: what a planted field might hold */
static uint64_t word(void) {
    switch (pick(10)) {
    case 0: return 0;
    case 1: return pick(64);
    case 2: return (uint64_t)-1;
    case 3: return 0x7fffffff;
    case 4: return 0x80000000u;
    case 5: case 6: return ptr(64);
    case 7: return (uint64_t)(edge - pick(64));
    default: return rnd();
    }
}

/* Refill the arena: random bytes with planted words */
static void churn(void) {
    uint64_t *w = (uint64_t *)arena;
    size_t n = ARENA_SIZE / 8;
    for (int i = 0; i < 512; i++) w[pick(n)] = word();
    for (int i = 0; i < 128; i++) arena[pick(ARENA_SIZE)] = (char)rnd();
}

/* A string with no terminator that ends at the guard page */
static char *unterminated(size_t n) {
    if (n > ARENA_SIZE) n = ARENA_SIZE;
    char *s = edge - n;
    for (size_t i = 0; i < n; i++) s[i] = 'a' + (char)(i % 26);
    return s;
}

/* A string: valid, empty, long, unterminated or a bad pointer */
static uint64_t str(void) {
    static const char *names[] = { "/", "/tmp", "/nonexistent/x", ".", "..",
                                   "/dev/null", "/etc/passwd", "name", "path",
                                   "host.hostname", "ip4.addr", "persist", "" };
    switch (pick(6)) {
    case 0: return (uint64_t)unterminated(1 + pick(PAGE * 2));
    case 1: return ptr(16);
    case 2: {
        size_t n = 1 + pick(PAGE * 3);
        char *s = arena + pick(ARENA_SIZE - n - 1);
        memset(s, '/', n);
        s[n] = 0;
        return (uint64_t)s;
    }
    default: {
        const char *src = names[pick(sizeof(names) / sizeof(names[0]))];
        char *s = arena + (pick(ARENA_SIZE - 64) & ~7ull);
        strcpy(s, src);
        return (uint64_t)s;
    }
    }
}

static uint64_t fd(void) {
    switch (pick(6)) {
    case 0: return (uint64_t)-1;
    case 1: return pick(1024);
    case 2: return rnd();
    default: return (uint64_t)fds[pick(8)];
    }
}

static void *slot(size_t n) {
    if (n > ARENA_SIZE) n = ARENA_SIZE;
    if (pick(4) == 0) return edge - n + pick(n ? n : 1);   /* cut off */
    return arena + (pick(ARENA_SIZE - n + 1) & ~15ull);
}

/* ------------------------------------------------------------------ */
/* Shaped structures                                                    */

static uint64_t make_iovs(uint64_t *count) {
    size_t n = 1 + pick(16);
    struct iovec *v = slot(n * sizeof(*v));
    if ((char *)(v + n) <= edge)
        for (size_t i = 0; i < n; i++) {
            v[i].iov_base = (void *)ptr(64);
            v[i].iov_len = len(64);
        }
    *count = len(n);
    return (uint64_t)v;
}

static uint64_t make_sockaddr(uint64_t *salen) {
    static const int fams[] = { AF_UNIX, AF_INET, AF_INET6, AF_UNSPEC, 18 /* AF_LINK */, 255 };
    size_t room = sizeof(struct sockaddr_storage);
    struct sockaddr *sa = slot(room);
    size_t have = (size_t)(edge - (char *)sa);
    if (have > room) have = room;
    for (size_t i = 0; i < have; i++) ((char *)sa)[i] = (char)rnd();
    if (have >= 2) {
        sa->sa_len = (uint8_t)(pick(3) ? pick(130) : rnd());
        sa->sa_family = (sa_family_t)fams[pick(sizeof(fams) / sizeof(fams[0]))];
    }
    if (have >= 2 && sa->sa_family == AF_UNIX && pick(2)) {
        /* path with no terminator, possibly up to the guard page */
        memset((char *)sa + 2, 'p', have - 2);
    }
    if (have >= 8 && sa->sa_family == AF_INET && pick(2)) {
        struct sockaddr_in *in = (struct sockaddr_in *)sa;
        in->sin_port = htons(40000 + (uint16_t)pick(100));
        in->sin_addr.s_addr = htonl(0x7f000001);
    }
    *salen = len(pick(2) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_un));
    return (uint64_t)sa;
}

static uint64_t make_msghdr(void) {
    struct msghdr *m = slot(sizeof(*m));
    if ((char *)(m + 1) > edge) return (uint64_t)m;
    uint64_t salen = 0, cnt = 0;
    m->msg_name = pick(3) ? (void *)make_sockaddr(&salen) : NULL;
    m->msg_namelen = (socklen_t)salen;
    m->msg_iov = (struct iovec *)make_iovs(&cnt);
    m->msg_iovlen = (int)cnt;
    m->msg_flags = (int)rnd();
    /* control: a run of cmsghdrs with hostile lengths */
    size_t clen = 16 + pick(256);
    char *c = slot(clen);
    size_t have = (size_t)(edge - c) < clen ? (size_t)(edge - c) : clen;
    for (size_t off = 0; off + sizeof(struct cmsghdr) <= have;) {
        struct cmsghdr *h = (struct cmsghdr *)(c + off);
        static const int types[] = { SCM_RIGHTS, SCM_CREDS, SCM_TIMESTAMP, SCM_BINTIME, 99 };
        h->cmsg_len = (socklen_t)(pick(3) ? sizeof(struct cmsghdr) + pick(64) : (uint32_t)rnd());
        h->cmsg_level = pick(4) ? SOL_SOCKET : (int)rnd();
        h->cmsg_type = types[pick(5)];
        for (size_t i = sizeof(*h); i < h->cmsg_len && off + i < have; i++)
            c[off + i] = (char)(pick(3) ? fds[pick(8)] : rnd());
        size_t step = (h->cmsg_len + 7) & ~7u;
        if (step < sizeof(*h) || step > have) break;
        off += step;
    }
    m->msg_control = pick(4) ? (void *)c : (void *)ptr(32);
    m->msg_controllen = (socklen_t)len(clen);
    return (uint64_t)m;
}

static uint64_t make_kevents(uint64_t *count) {
    size_t n = 1 + pick(32);
    struct kevent *k = slot(n * sizeof(*k));
    for (size_t i = 0; i < n && (char *)(k + i + 1) <= edge; i++) {
        k[i].ident = pick(3) ? (uintptr_t)fds[pick(8)] : rnd();
        k[i].filter = (short)(pick(4) ? -(int)(1 + pick(16)) : (int)rnd());
        k[i].flags = (unsigned short)(pick(2) ? (EV_ADD | (pick(2) ? EV_ENABLE : EV_DELETE)) : rnd());
        k[i].fflags = (unsigned)(pick(2) ? pick(8) : rnd());
        k[i].data = (int64_t)word();
        k[i].udata = (void *)word();
        for (int e = 0; e < 4; e++) k[i].ext[e] = word();
    }
    *count = len(n);
    return (uint64_t)k;
}

static uint64_t make_thr_param(void) {
    struct thr_param *p = slot(sizeof(*p));
    if ((char *)(p + 1) > edge) return (uint64_t)p;
    p->start_func = pick(4) ? (void (*)(void *))fz_exit_thread : (void (*)(void *))word();
    p->arg = (void *)word();
    p->stack_size = len(PAGE * 4);
    p->stack_base = pick(3) ? arena + (pick(ARENA_PAGES / 2) * PAGE) : (char *)ptr(PAGE);
    if (pick(2)) p->stack_size = PAGE * 2;
    p->tls_base = (char *)word();
    p->tls_size = len(64);
    p->child_tid = (long *)ptr(8);
    p->parent_tid = (long *)ptr(8);
    p->flags = pick(2) ? 0 : (int)rnd();
    p->rtp = pick(2) ? NULL : (struct rtprio *)ptr(4);
    return (uint64_t)p;
}

static uint64_t make_ucontext(void) {
    ucontext_t *u = slot(sizeof(*u));
    size_t have = (size_t)(edge - (char *)u);
    if (have > sizeof(*u)) have = sizeof(*u);
    for (size_t i = 0; i < have; i++) ((char *)u)[i] = (char)rnd();
    if (have == sizeof(*u)) {
        mcontext_t *m = &u->uc_mcontext;
        if (pick(3)) {
            /* plausible: lands on fz_exit_proc with a usable stack */
            m->mc_rip = (register_t)fz_exit_proc;
            m->mc_rsp = (register_t)(arena + ARENA_SIZE / 2);
            m->mc_cs = 0x43;
            m->mc_ss = 0x3b;
            m->mc_rflags = 0x202;
        }
        m->mc_len = pick(2) ? (long)sizeof(*m) : (long)rnd();
        m->mc_fpformat = pick(2) ? 0x10002 : (int)rnd();
        m->mc_ownedfp = pick(2) ? 0x20001 : (int)rnd();
        m->mc_flags = (uint32_t)rnd();
        m->mc_xfpustate = (register_t)word();
        m->mc_xfpustate_len = (register_t)len(512);
        u->uc_flags = (int)rnd();
    }
    return (uint64_t)u;
}

static uint64_t make_jail_iovs(uint64_t *count) {
    size_t pairs = 1 + pick(12);
    struct iovec *v = slot(pairs * 2 * sizeof(*v));
    for (size_t i = 0; i < pairs * 2 && (char *)(v + i + 1) <= edge; i++) {
        if (i % 2 == 0) {
            v[i].iov_base = (void *)str();
            v[i].iov_len = pick(3) ? 1 + pick(32) : len(16);
        } else {
            v[i].iov_base = pick(4) ? (void *)str() : (void *)ptr(16);
            v[i].iov_len = len(8);
        }
    }
    *count = len(pairs * 2);
    return (uint64_t)v;
}

/* ------------------------------------------------------------------ */
/* Targets                                                              */

typedef struct {
    const char *name;
    void (*run)(uint64_t a[6], long *nr);
} target_t;

#define T(nm) static void t_##nm(uint64_t a[6], long *nr)

T(thr_new)   { *nr = SYS_thr_new; a[0] = pick(5) ? make_thr_param() : ptr(64); a[1] = len(sizeof(struct thr_param)); }
T(kevent)    {
    *nr = SYS_kevent;
    uint64_t nc = 4;
    a[0] = fds[0];  /* a kqueue */
    a[1] = pick(5) ? make_kevents(&nc) : ptr(64);
    a[2] = pick(5) ? nc : len(4);
    a[3] = pick(2) ? (uint64_t)slot(32 * sizeof(struct kevent)) : ptr(64);
    a[4] = len(32);
    struct timespec *ts = slot(sizeof(*ts));
    if ((char *)(ts + 1) <= edge) { ts->tv_sec = 0; ts->tv_nsec = (long)pick(3) ? 0 : (long)rnd(); }
    a[5] = pick(5) ? (uint64_t)ts : ptr(16);
}
T(sendmsg)   { *nr = SYS_sendmsg; a[0] = fd(); a[1] = pick(5) ? make_msghdr() : ptr(56); a[2] = MSG_DONTWAIT | (pick(2) ? 0 : (uint32_t)rnd()); }
T(recvmsg)   { *nr = SYS_recvmsg; a[0] = fd(); a[1] = pick(5) ? make_msghdr() : ptr(56); a[2] = MSG_DONTWAIT | (pick(2) ? 0 : (uint32_t)rnd()); }
T(sendto)    { uint64_t l = 16; *nr = SYS_sendto; a[0] = fd(); a[1] = ptr(64); a[2] = len(64); a[3] = MSG_DONTWAIT; a[4] = make_sockaddr(&l); a[5] = l; }
T(recvfrom)  {
    *nr = SYS_recvfrom; a[0] = fd(); a[1] = ptr(64); a[2] = len(64); a[3] = MSG_DONTWAIT;
    a[4] = ptr(128);
    socklen_t *lp = slot(sizeof(*lp));
    if ((char *)(lp + 1) <= edge) *lp = (socklen_t)len(128);
    a[5] = pick(4) ? (uint64_t)lp : ptr(4);
}
T(connect)   { uint64_t l = 16; *nr = SYS_connect; a[0] = fd(); a[1] = pick(6) ? make_sockaddr(&l) : ptr(16); a[2] = pick(6) ? l : len(16); }
T(bind)      { uint64_t l = 16; *nr = SYS_bind; a[0] = fd(); a[1] = pick(6) ? make_sockaddr(&l) : ptr(16); a[2] = pick(6) ? l : len(16); }
T(sockname)  {
    *nr = pick(2) ? SYS_getsockname : (pick(2) ? SYS_getpeername : SYS_accept);
    a[0] = fd(); a[1] = ptr(128);
    socklen_t *lp = slot(sizeof(*lp));
    if ((char *)(lp + 1) <= edge) *lp = (socklen_t)len(128);
    a[2] = pick(4) ? (uint64_t)lp : ptr(4);
}
T(sockopt)   {
    *nr = pick(2) ? SYS_setsockopt : SYS_getsockopt;
    a[0] = fd(); a[1] = pick(3) ? SOL_SOCKET : (pick(2) ? IPPROTO_IP : rnd() & 0xffff);
    a[2] = pick(2) ? pick(0x1100) : rnd(); a[3] = ptr(16);
    if (*nr == SYS_setsockopt) a[4] = len(4);
    else {
        socklen_t *lp = slot(sizeof(*lp));
        if ((char *)(lp + 1) <= edge) *lp = (socklen_t)len(16);
        a[4] = pick(4) ? (uint64_t)lp : ptr(4);
    }
}
T(sigreturn) { *nr = SYS_sigreturn; a[0] = pick(6) ? make_ucontext() : ptr(sizeof(ucontext_t)); }
T(sigaction) { *nr = SYS_sigaction; a[0] = pick(2) ? 1 + pick(64) : rnd(); a[1] = ptr(32); a[2] = ptr(32); }
T(sigmask)   { *nr = SYS_sigprocmask; a[0] = pick(4); a[1] = ptr(16); a[2] = ptr(16); }
T(altstack)  { *nr = SYS_sigaltstack; a[0] = ptr(24); a[1] = ptr(24); }
T(sysctl)    {
    *nr = SYS___sysctl;
    int *mib = slot(24 * sizeof(int));
    for (int i = 0; i < 24 && (char *)(mib + i + 1) <= edge; i++)
        mib[i] = i == 0 ? (int)(pick(4) ? 1 + pick(8) : rnd()) : (int)(pick(3) ? pick(80) : rnd());
    a[0] = pick(6) ? (uint64_t)mib : ptr(8); a[1] = len(pick(6) + 1);
    a[2] = ptr(256);
    size_t *ol = slot(sizeof(*ol));
    if ((char *)(ol + 1) <= edge) *ol = len(256);
    a[3] = pick(4) ? (uint64_t)ol : ptr(8);
    a[4] = pick(3) ? 0 : ptr(16); a[5] = len(8);
}
T(sysctlbyname) {
    *nr = SYS___sysctlbyname;
    static const char *names[] = { "kern.ostype", "kern.osrelease", "hw.ncpu", "kern.proc.pid",
                                   "security.jail.jailed", "vm.overcommit", "kern.hostname", "x" };
    char *n = arena + (pick(ARENA_SIZE - 64) & ~7ull);
    strcpy(n, names[pick(8)]);
    a[0] = pick(4) ? (uint64_t)n : str(); a[1] = pick(3) ? strlen(n) : len(16);
    a[2] = ptr(256);
    size_t *ol = slot(sizeof(*ol));
    if ((char *)(ol + 1) <= edge) *ol = len(256);
    a[3] = pick(4) ? (uint64_t)ol : ptr(8);
    a[4] = pick(3) ? 0 : ptr(16); a[5] = len(8);
}
T(jail)      {
    uint64_t c = 4;
    *nr = pick(2) ? SYS_jail_get : SYS_jail_set;
    a[0] = pick(6) ? make_jail_iovs(&c) : ptr(32); a[1] = c;
    a[2] = pick(2) ? pick(16) : rnd();
}
T(rwv)       {
    uint64_t c = 4;
    static const long nrs[] = { SYS_readv, SYS_writev, SYS_preadv };
    *nr = nrs[pick(3)];
    a[0] = pick(2) ? (uint64_t)fds[1] : fd();   /* fds[1]: /dev/null */
    a[1] = pick(6) ? make_iovs(&c) : ptr(32); a[2] = c; a[3] = pick(64);
}
T(umtx)      {
    *nr = SYS__umtx_op;
    a[0] = ptr(32); a[1] = pick(4) ? pick(30) : rnd(); a[2] = word();
    a[3] = pick(2) ? len(16) : ptr(16);
    struct timespec *ts = slot(sizeof(*ts));
    if ((char *)(ts + 1) <= edge) { ts->tv_sec = 0; ts->tv_nsec = 1000; }
    a[4] = pick(3) ? (uint64_t)ts : ptr(16);
}
T(ioctl)     {
    static const unsigned long cmds[] = { FIONREAD, FIONBIO, FIOASYNC, FIOCLEX, TIOCGWINSZ,
                                          TIOCSWINSZ, TIOCGETA, TIOCSETA, TIOCGPGRP, TIOCSPGRP,
                                          FIODGNAME, FIOGETOWN, 0xc0206911 /* SIOCGIFFLAGS */,
                                          0xc0106924 /* SIOCGIFCONF */ };
    *nr = SYS_ioctl;
    a[0] = fd();
    a[1] = pick(4) ? cmds[pick(sizeof(cmds) / sizeof(cmds[0]))] : (rnd() & 0xffffffff);
    a[2] = ptr(64);
}
T(path)      {
    static const long nrs[] = { SYS_openat, SYS_fstatat, SYS_readlinkat };
    *nr = nrs[pick(3)];
    a[0] = pick(2) ? (uint64_t)-100 /* AT_FDCWD */ : fd(); a[1] = str();
    if (*nr == SYS_openat) { a[2] = pick(2) ? O_RDONLY : rnd() & 0xffffff; a[3] = 0644; }
    else if (*nr == SYS_fstatat) { a[2] = ptr(256); a[3] = pick(2) ? 0 : rnd() & 0xffff; }
    else { a[2] = ptr(256); a[3] = len(256); }
}
T(dirents)   {
    *nr = pick(2) ? SYS_getdirentries : SYS___getcwd;
    if (*nr == SYS_getdirentries) { a[0] = pick(2) ? (uint64_t)fds[2] : fd(); a[1] = ptr(512); a[2] = len(512); a[3] = ptr(8); }
    else { a[0] = ptr(256); a[1] = len(256); }
}
T(fsstat)    {
    static const long nrs[] = { SYS_getfsstat, SYS_fstatfs, SYS_fstat };
    *nr = nrs[pick(3)];
    if (*nr == SYS_getfsstat) { a[0] = ptr(2048); a[1] = len(2048); a[2] = pick(4); }
    else { a[0] = fd(); a[1] = ptr(512); }
}
T(execve)    {
    *nr = SYS_execve;
    static const char *paths[] = { "/usr/bin/true", "/nonexistent", "/bin/sh" };
    char *p = arena + (pick(ARENA_SIZE - 64) & ~7ull);
    strcpy(p, paths[pick(2)]);   /* never /bin/sh: it would wait on input */
    a[0] = pick(4) ? (uint64_t)p : str();
    size_t n = pick(40);
    uint64_t *av = slot((n + 1) * 8);
    for (size_t i = 0; i <= n && (char *)(av + i + 1) <= edge; i++)
        av[i] = i == n && pick(3) ? 0 : str();
    a[1] = pick(5) ? (uint64_t)av : ptr(8);
    a[2] = pick(3) ? 0 : (uint64_t)slot(64);
}
T(poll)      {
    static const long nrs[] = { SYS_poll, SYS_ppoll, SYS_select };
    *nr = nrs[pick(3)];
    struct timespec *ts = slot(sizeof(*ts));
    if ((char *)(ts + 1) <= edge) { ts->tv_sec = 0; ts->tv_nsec = 0; }
    if (*nr == SYS_select) { a[0] = len(64); a[1] = ptr(128); a[2] = ptr(128); a[3] = ptr(128); a[4] = (uint64_t)ts; }
    else { a[0] = ptr(64); a[1] = len(8); a[2] = (uint64_t)ts; a[3] = ptr(16); }
    if (*nr == SYS_poll) a[2] = 0;   /* poll timeout in ms */
}
T(thrmisc)   {
    switch (pick(4)) {
    case 0: *nr = SYS_thr_self; a[0] = ptr(8); break;
    case 1: *nr = SYS_thr_set_name; a[0] = pick(2) ? (uint64_t)-1 : rnd(); a[1] = str(); break;
    case 2: *nr = SYS_rtprio_thread; a[0] = pick(3); a[1] = pick(2) ? 0 : rnd(); a[2] = ptr(4); break;
    default: *nr = SYS_cpuset_getaffinity; a[0] = pick(5); a[1] = pick(5); a[2] = (uint64_t)-1; a[3] = len(16); a[4] = ptr(128); break;
    }
}
T(misc)      {
    switch (pick(5)) {
    case 0: *nr = SYS_clock_gettime; a[0] = pick(2) ? pick(16) : rnd(); a[1] = ptr(16); break;
    case 1: *nr = SYS_getrandom; a[0] = ptr(256); a[1] = len(256); a[2] = pick(4); break;
    case 2: *nr = SYS_wait4; a[0] = (uint64_t)-1; a[1] = ptr(4); a[2] = 1 /* WNOHANG */ | (pick(2) ? 0 : rnd() & 0xff); a[3] = ptr(144); break;
    case 3: *nr = SYS_procctl; a[0] = pick(3); a[1] = pick(2) ? 0 : rnd(); a[2] = pick(2) ? pick(30) : rnd(); a[3] = ptr(64); break;
    default: *nr = SYS_nanosleep; {
        struct timespec *ts = slot(sizeof(*ts));
        if ((char *)(ts + 1) <= edge) { ts->tv_sec = 0; ts->tv_nsec = (long)pick(1000); }
        a[0] = pick(3) ? (uint64_t)ts : ptr(16); a[1] = ptr(16);
    }
    }
}

/* Any syscall but those that would end the run or the program's memory */
static int denied(long n) {
    static const long deny[] = {
        1, SYS_fork, SYS_vfork, SYS_rfork, SYS_pdfork, SYS_execve, SYS_fexecve,
        SYS_kill, SYS_thr_kill, SYS_thr_kill2, SYS_sigqueue, SYS_pdkill, SYS_thr_exit,
        SYS_sigreturn, SYS_mmap, SYS_munmap, SYS_mprotect, SYS_reboot, SYS_abort2,
        SYS_thr_suspend, SYS_sigsuspend, SYS_sigwait, SYS_sigtimedwait, SYS_sigwaitinfo,
        SYS_close, SYS_close_range, 509 /* closefrom (old) */, SYS_dup2, SYS_setrlimit,
        SYS_unlink, SYS_unlinkat, SYS_rmdir, SYS_rename, SYS_renameat, SYS_sigprocmask,
        SYS_sigaction, 203 /* mlock */, 324 /* mlockall */,
    };
    for (size_t i = 0; i < sizeof(deny) / sizeof(deny[0]); i++)
        if (deny[i] == n) return 1;
    return 0;
}

T(random)    {
    long n;
    do n = (long)pick(SYS_MAXSYSCALL); while (denied(n));
    *nr = n;
    for (int i = 0; i < 6; i++) {
        switch (pick(4)) {
        case 0: a[i] = ptr(64); break;
        case 1: a[i] = len(64); break;
        case 2: a[i] = fd(); break;
        default: a[i] = word(); break;
        }
    }
    /* syscall(2) / __syscall(2): the real number is the first argument,
     * from the same allowlist */
    if (n == 0 || n == 198) {
        long m;
        do m = (long)pick(SYS_MAXSYSCALL); while (denied(m) || m == 0 || m == 198);
        a[0] = (uint64_t)m;
    }
}

static const target_t targets[] = {
    { "thr_new", t_thr_new }, { "kevent", t_kevent }, { "sendmsg", t_sendmsg },
    { "recvmsg", t_recvmsg }, { "sendto", t_sendto }, { "recvfrom", t_recvfrom },
    { "connect", t_connect }, { "bind", t_bind }, { "sockname", t_sockname },
    { "sockopt", t_sockopt }, { "sigreturn", t_sigreturn }, { "sigaction", t_sigaction },
    { "sigmask", t_sigmask }, { "altstack", t_altstack }, { "sysctl", t_sysctl },
    { "sysctlbyname", t_sysctlbyname }, { "jail", t_jail }, { "rwv", t_rwv },
    { "umtx", t_umtx }, { "ioctl", t_ioctl }, { "path", t_path }, { "dirents", t_dirents },
    { "fsstat", t_fsstat }, { "execve", t_execve }, { "poll", t_poll },
    { "thrmisc", t_thrmisc }, { "misc", t_misc }, { "random", t_random },
};
#define NTARGETS (sizeof(targets) / sizeof(targets[0]))

/* A signal delivered on a hostile alternate stack: the tracer writes the
 * frame wherever it points */
static void on_sig(int s) { (void)s; }
static void signal_on_hostile_stack(void) {
    stack_t ss;
    memset(&ss, 0, sizeof(ss));
    ss.ss_sp = (void *)(pick(2) ? (uint64_t)(edge - pick(PAGE * 4)) : ptr(PAGE));
    ss.ss_size = (size_t)(pick(2) ? PAGE * 2 : len(PAGE * 2));
    ss.ss_flags = 0;
    if (sc(SYS_sigaltstack, (uint64_t)&ss, 0, 0, 0, 0, 0) != 0) return;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sig;
    sa.sa_flags = SA_ONSTACK | (pick(2) ? SA_NODEFER : 0);
    sigaction(SIGUSR1, &sa, NULL);
    long tid;
    sc(SYS_thr_self, (uint64_t)&tid, 0, 0, 0, 0, 0);
    sc(SYS_thr_kill, (uint64_t)tid, SIGUSR1, 0, 0, 0, 0);
}

static void logf_call(const char *name, long nr, const uint64_t a[6]) {
    char line[256];
    int n = snprintf(line, sizeof(line), "%s %ld %llx %llx %llx %llx %llx %llx\n", name, nr,
                     (unsigned long long)a[0], (unsigned long long)a[1], (unsigned long long)a[2],
                     (unsigned long long)a[3], (unsigned long long)a[4], (unsigned long long)a[5]);
    (void)sc(SYS_write, 2, (uint64_t)line, (uint64_t)n, 0, 0, 0);
}

/* Calls that often end the process making them (a sigreturn that lands
 * on fz_exit_proc, a thread on a bad stack, an exec, a sleep) run in a
 * throwaway child, so the batch goes on */
static int risky(const target_t *t) {
    static const char *names[] = { "sigreturn", "thr_new", "execve", "random", "umtx",
                                   "misc", "sigaction", NULL };
    for (int i = 0; names[i]; i++)
        if (strcmp(t->name, names[i]) == 0) return 1;
    return 0;
}

static void in_child(void (*fn)(void *), void *arg) {
    pid_t c = fork();
    if (c == 0) {
        alarm(2);
        fn(arg);
        _exit(0);
    }
    if (c > 0) {
        int st;
        while (waitpid(c, &st, 0) < 0 && errno == EINTR) {}
    }
}

struct call { long nr; uint64_t a[6]; };
static void do_call(void *p) {
    struct call *c = p;
    (void)sc(c->nr, c->a[0], c->a[1], c->a[2], c->a[3], c->a[4], c->a[5]);
}
static void do_signal(void *p) { (void)p; signal_on_hostile_stack(); }

static void batch(uint64_t seed, int calls) {
    rs = seed * 0x9e3779b97f4a7c15ull + 1;
    alarm(60);
    for (int i = 0; i < calls; i++) {
        churn();
        if (pick(64) == 0) {
            in_child(do_signal, NULL);
            continue;
        }
        const target_t *t = &targets[pick(NTARGETS)];
        struct call c = { 0, { 0, 0, 0, 0, 0, 0 } };
        t->run(c.a, &c.nr);
        if (verbose) logf_call(t->name, c.nr, c.a);
        __atomic_add_fetch(&stats->calls, 1, __ATOMIC_RELAXED);
        __atomic_add_fetch(&stats->by[t - targets], 1, __ATOMIC_RELAXED);
        if (risky(t)) in_child(do_call, &c);
        else do_call(&c);
    }
    _exit(0);
}

static void setup(void) {
    char *m = mmap(NULL, ARENA_SIZE + PAGE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (m == MAP_FAILED) { perror("mmap"); exit(2); }
    if (munmap(m + ARENA_SIZE, PAGE) != 0) { perror("munmap"); exit(2); }
    arena = m;
    edge = m + ARENA_SIZE;
    memset(arena, 0, ARENA_SIZE);
    stats = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
    if (stats == MAP_FAILED) { perror("mmap"); exit(2); }
    memset(stats, 0, sizeof(*stats));

    int sv[2] = { -1, -1 }, sv2[2] = { -1, -1 };
    fds[0] = kqueue();
    fds[1] = open("/dev/null", O_RDWR);
    fds[2] = open("/", O_RDONLY | O_DIRECTORY);
    socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
    fds[3] = sv[0];
    fds[4] = sv[1];
    fds[5] = socket(AF_INET, SOCK_DGRAM, 0);
    fds[6] = socket(AF_INET, SOCK_STREAM, 0);
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv2);
    fds[7] = sv2[0];
    for (int i = 0; i < 8; i++)
        if (fds[i] >= 0) fcntl(fds[i], F_SETFL, fcntl(fds[i], F_GETFL) | O_NONBLOCK);
    if (fds[5] >= 0) {
        struct sockaddr_in in;
        memset(&in, 0, sizeof(in));
        in.sin_len = sizeof(in);
        in.sin_family = AF_INET;
        in.sin_port = htons(40000);
        in.sin_addr.s_addr = htonl(0x7f000001);
        bind(fds[5], (struct sockaddr *)&in, sizeof(in));
    }
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "-v") == 0) {
        if (argc < 4) { fprintf(stderr, "usage: %s -v seed batch\n", argv[0]); return 2; }
        verbose = 1;
        setup();
        uint64_t seed = strtoull(argv[2], NULL, 0), b = strtoull(argv[3], NULL, 0);
        batch(seed ^ (b * 0x100000001b3ull), 100000);
    }
    uint64_t seed = argc > 1 ? strtoull(argv[1], NULL, 0) : (uint64_t)time(NULL);
    int batches = argc > 2 ? atoi(argv[2]) : 200;
    int calls = argc > 3 ? atoi(argv[3]) : 300;
    setup();

    /* Indirect syscalls give what direct ones give */
    long direct = sc(SYS_getpid, 0, 0, 0, 0, 0, 0);
    long ind0 = sc(0, SYS_getpid, 0, 0, 0, 0, 0);
    long ind198 = sc(198, SYS_getpid, 0, 0, 0, 0, 0);
    char wbuf[8] = "abc";
    long wr = sc(0, SYS_write, (uint64_t)fds[1], (uint64_t)wbuf, 3, 0, 0);
    long nested = sc(0, 0, SYS_getpid, 0, 0, 0, 0);
    if (ind0 != direct || ind198 != direct || wr != 3 || nested != -ENOSYS) {
        printf("syscall_fuzz: FAIL indirect syscalls: getpid %ld, via 0 %ld, via 198 %ld, write %ld, nested %ld\n",
               direct, ind0, ind198, wr, nested);
        return 1;
    }

    printf("syscall_fuzz: seed %llu, %d batches of %d calls\n", (unsigned long long)seed, batches, calls);
    fflush(stdout);

    int ok = 0, sig = 0, alarmed = 0, killed = 0, other = 0;
    int bysig[64];
    memset(bysig, 0, sizeof(bysig));
    for (int b = 0; b < batches; b++) {
        pid_t c = fork();
        if (c < 0) { perror("fork"); return 2; }
        if (c == 0) batch(seed ^ ((uint64_t)b * 0x100000001b3ull), calls);
        int st = 0, waited = 0;
        /* The child has an alarm; past that it is killed */
        for (int t = 0; t < 9000; t++) {
            pid_t r = waitpid(c, &st, WNOHANG);
            if (r == c) { waited = 1; break; }
            usleep(10000);
        }
        if (!waited) {
            kill(c, SIGKILL);
            waitpid(c, &st, 0);
            killed++;
            printf("  batch %d: did not end, killed\n", b);
            continue;
        }
        if (WIFEXITED(st) && WEXITSTATUS(st) == 0) ok++;
        else if (WIFSIGNALED(st)) {
            if (WTERMSIG(st) == SIGALRM) alarmed++;
            else sig++;
            if (WTERMSIG(st) < 64) bysig[WTERMSIG(st)]++;
        } else other++;
    }
    printf("syscall_fuzz: %llu calls made:", (unsigned long long)stats->calls);
    for (size_t t = 0; t < NTARGETS; t++)
        printf(" %s %llu", targets[t].name, (unsigned long long)stats->by[t]);
    printf("\n");
    printf("syscall_fuzz: done: %d batches, %d finished, %d died by a signal, %d alarm, %d killed, %d other exit\n",
           batches, ok, sig, alarmed, killed, other);
    for (int s = 1; s < 64; s++)
        if (bysig[s]) printf("  signal %d: %d\n", s, bysig[s]);
    return 0;
}
