/*
 * Unit tests for the signal number and wait4 option translation in
 * src/signal/signal_emul.c
 *
 * Build and run:  make test-signal
 */

#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "bsdulator.h"
#include "bsdulator/signal_emul.h"
#include "bsdulator/msg_emul.h"
#include "bsdulator/syscall.h"

int abi_translate_at_flags(int freebsd_flags);
int abi_at_flags_arg(int freebsd_nr);
long abi_utime_nsec_to_linux(long nsec);

int abi_translate_errno(int linux_errno);
int abi_translate_errno_to_linux(int freebsd_errno);

/* The module reads and writes traced processes; these tests do not. */
int bsd_debug_level = 0;
ssize_t interceptor_read_mem(pid_t pid, void *local, const void *remote, size_t len) {
    (void)pid; (void)local; (void)remote; (void)len;
    return -1;
}
ssize_t interceptor_write_mem(pid_t pid, const void *local, void *remote, size_t len) {
    (void)pid; (void)local; (void)remote; (void)len;
    return -1;
}

static int failures = 0;

#define CHECK(cond, msg) do {                                   \
    if (cond) { printf("  ok   %s\n", msg); }                    \
    else { printf("  FAIL %s\n", msg); failures++; }             \
} while (0)

int main(void) {
    printf("signal number translation\n");
    CHECK(sig_fbsd_to_linux(1) == SIGHUP, "HUP");
    CHECK(sig_fbsd_to_linux(10) == SIGBUS, "BUS 10 -> 7");
    CHECK(sig_fbsd_to_linux(12) == SIGSYS, "SYS 12 -> 31");
    CHECK(sig_fbsd_to_linux(16) == SIGURG, "URG 16 -> 23");
    CHECK(sig_fbsd_to_linux(17) == SIGSTOP, "STOP 17 -> 19");
    CHECK(sig_fbsd_to_linux(18) == SIGTSTP, "TSTP 18 -> 20");
    CHECK(sig_fbsd_to_linux(19) == SIGCONT, "CONT 19 -> 18");
    CHECK(sig_fbsd_to_linux(20) == SIGCHLD, "CHLD 20 -> 17");
    CHECK(sig_fbsd_to_linux(23) == SIGIO, "IO 23 -> 29");
    CHECK(sig_fbsd_to_linux(29) == SIGPWR, "INFO 29 -> PWR");
    CHECK(sig_fbsd_to_linux(30) == SIGUSR1, "USR1 30 -> 10");
    CHECK(sig_fbsd_to_linux(31) == SIGUSR2, "USR2 31 -> 12");
    CHECK(sig_fbsd_to_linux(7) == 0, "EMT has no Linux signal");
    CHECK(sig_fbsd_to_linux(65) == 34, "SIGRTMIN 65 -> 34");
    CHECK(sig_fbsd_to_linux(0) == 0 && sig_fbsd_to_linux(200) == 0, "out of range");

    int roundtrip = 1;
    for (int s = 1; s <= 33; s++) {
        if (s == 7) continue;
        if (sig_linux_to_fbsd(sig_fbsd_to_linux(s)) != s) roundtrip = 0;
    }
    for (int s = 65; s <= 95; s++)
        if (sig_linux_to_fbsd(sig_fbsd_to_linux(s)) != s) roundtrip = 0;
    CHECK(roundtrip, "FreeBSD -> Linux -> FreeBSD round trip");
    CHECK(sig_linux_to_fbsd(16) == 0, "Linux STKFLT has no FreeBSD signal");

    printf("wait4 options\n");
    CHECK(sig_wait_options_to_linux(1) == WNOHANG, "WNOHANG");
    CHECK(sig_wait_options_to_linux(2) == WUNTRACED, "WUNTRACED");
    CHECK(sig_wait_options_to_linux(4) == WCONTINUED, "WCONTINUED 4 -> 8");
    CHECK(sig_wait_options_to_linux(16) == 0, "WEXITED dropped (implied by wait4)");

    printf("errno translation\n");
    CHECK(abi_translate_errno(11) == 35, "EAGAIN 11 -> 35");
    CHECK(abi_translate_errno(35) == 11, "EDEADLK 35 -> 11");
    CHECK(abi_translate_errno(2) == 2, "ENOENT unchanged");
    CHECK(abi_translate_errno(38) == 78, "ENOSYS 38 -> 78");
    CHECK(abi_translate_errno(88) == 38, "ENOTSOCK 88 -> 38");
    CHECK(abi_translate_errno(90) == 40, "EMSGSIZE 90 -> 40");
    CHECK(abi_translate_errno(111) == 61, "ECONNREFUSED 111 -> 61");
    CHECK(abi_translate_errno(115) == 36, "EINPROGRESS 115 -> 36");
    /* Codes that exist on both systems map back to themselves */
    static const int both[] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
        37, 38, 39, 40, 42, 43, 66, 67, 71, 72, 74, 75, 84, 87, 88, 89, 90,
        91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105,
        106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 122, 125,
        130, 131,
    };
    int eround = 1;
    for (size_t i = 0; i < sizeof(both) / sizeof(both[0]); i++)
        if (abi_translate_errno_to_linux(abi_translate_errno(both[i])) != both[i]) eround = 0;
    CHECK(eround, "errno Linux -> FreeBSD -> Linux round trip");

    printf("MSG_* flags\n");
    CHECK(msg_flags_to_linux(0x80) == 0x40, "MSG_DONTWAIT 0x80 -> 0x40");
    CHECK(msg_flags_to_linux(0x20000) == 0x4000, "MSG_NOSIGNAL 0x20000 -> 0x4000");
    CHECK(msg_flags_to_linux(0x2) == 0x2, "MSG_PEEK unchanged");

    printf("*at syscall flags\n");
    CHECK(abi_at_flags_arg(FBSD_SYS_fchownat) == 4, "fchownat flag is arg 4, not the gid");
    CHECK(abi_at_flags_arg(FBSD_SYS_linkat) == 4, "linkat flag is arg 4");
    CHECK(abi_at_flags_arg(FBSD_SYS_unlinkat) == 2, "unlinkat flag is arg 2");
    CHECK(abi_at_flags_arg(FBSD_SYS_fstatat) == 3, "fstatat flag is arg 3");
    CHECK(abi_at_flags_arg(FBSD_SYS_utimensat) == 3, "utimensat flag is arg 3");
    CHECK(abi_at_flags_arg(FBSD_SYS_openat) == -1, "openat has no AT_ flag");
    CHECK(abi_translate_at_flags(0x0200) == 0x0100, "AT_SYMLINK_NOFOLLOW 0x200 -> 0x100");
    CHECK(abi_translate_at_flags(0x0800) == 0x0200, "AT_REMOVEDIR 0x800 -> 0x200");
    CHECK(abi_translate_at_flags(0) == 0, "no flags stay none");
    CHECK(abi_utime_nsec_to_linux(-1) == (1L << 30) - 1, "UTIME_NOW -1 -> Linux");
    CHECK(abi_utime_nsec_to_linux(-2) == (1L << 30) - 2, "UTIME_OMIT -2 -> Linux");
    CHECK(abi_utime_nsec_to_linux(123456789) == 123456789, "real nanoseconds unchanged");

    if (failures) {
        printf("%d test(s) FAILED\n", failures);
        return 1;
    }
    printf("all translation tests PASSED\n");
    return 0;
}
