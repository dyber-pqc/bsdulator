/*
 * Unit tests for the container seccomp filter (src/jail/seccomp.c)
 *
 * Build and run:  make test-seccomp
 *
 * Each check runs in a forked child that installs the filter, so the
 * test process itself stays unfiltered.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "bsdulator/seccomp.h"

static int failures = 0;

#define CHECK(cond, msg) do {                                   \
    if (cond) { printf("  ok   %s\n", msg); }                    \
    else { printf("  FAIL %s\n", msg); failures++; }             \
} while (0)

/* Run fn in a filtered child; returns its exit status (0 = expectation met) */
static int in_child(int (*fn)(void)) {
    pid_t p = fork();
    if (p == 0) {
        if (container_seccomp_install() < 0) _exit(100);
        _exit(fn());
    }
    int st = 0;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 200;
}

static int denied(long nr) {
    errno = 0;
    long r = syscall(nr, 0, 0, 0, 0, 0, 0);
    return (r == -1 && errno == EPERM) ? 0 : 1;
}

static int t_getpid(void) { return syscall(SYS_getpid) > 0 ? 0 : 1; }
static int t_skipped(void) {
    errno = 0;
    long r = syscall(-1);
    return (r == -1 && errno == ENOSYS) ? 0 : 1;   /* reaches the kernel */
}
static int t_fork(void) {
    pid_t c = fork();
    if (c == 0) _exit(0);
    if (c < 0) return 1;
    int st;
    waitpid(c, &st, 0);
    return 0;
}
static int t_unshare(void) { return denied(SYS_unshare); }
static int t_mount(void) { return denied(SYS_mount); }
static int t_ptrace(void) { return denied(SYS_ptrace); }
static int t_clone_userns(void) {
    errno = 0;
    long r = syscall(SYS_clone, CLONE_NEWUSER | SIGCHLD, 0, 0, 0, 0);
    if (r == 0) _exit(0);
    return (r == -1 && errno == EPERM) ? 0 : 1;
}
#ifdef SYS_io_uring_setup
static int t_io_uring(void) { return denied(SYS_io_uring_setup); }
#endif
#ifdef SYS_clone3
static int t_clone3(void) {
    errno = 0;
    long r = syscall(SYS_clone3, 0, 0);
    return (r == -1 && errno == ENOSYS) ? 0 : 1;
}
#endif

int main(void) {
    printf("container seccomp filter\n");
    CHECK(in_child(t_getpid) == 0, "ordinary syscalls allowed");
    CHECK(in_child(t_skipped) == 0, "skipped syscall (-1) passes through");
    CHECK(in_child(t_fork) == 0, "fork allowed");
    CHECK(in_child(t_unshare) == 0, "unshare refused");
    CHECK(in_child(t_clone_userns) == 0, "clone with a new user namespace refused");
    CHECK(in_child(t_mount) == 0, "mount refused");
    CHECK(in_child(t_ptrace) == 0, "ptrace refused");
#ifdef SYS_io_uring_setup
    CHECK(in_child(t_io_uring) == 0, "io_uring refused");
#endif
#ifdef SYS_clone3
    CHECK(in_child(t_clone3) == 0, "clone3 returns ENOSYS");
#endif
    if (failures) {
        printf("%d test(s) FAILED\n", failures);
        return 1;
    }
    printf("all seccomp tests PASSED\n");
    return 0;
}
