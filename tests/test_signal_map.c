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

    if (failures) {
        printf("%d test(s) FAILED\n", failures);
        return 1;
    }
    printf("all signal tests PASSED\n");
    return 0;
}
