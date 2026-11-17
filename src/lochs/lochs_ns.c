/*
 * lochs_ns.c - per-container PID, mount, UTS and IPC namespaces
 *
 * Each running container has a holder process: PID 1 of the container's
 * PID namespace, which also holds its mount, UTS (hostname) and IPC
 * namespaces. Every bsdulator run for the container joins them with
 * "-N <holder pid>", so all of a container's processes share one view and
 * see neither host processes nor other containers'. Stopping the container
 * kills the holder, which ends every process still in the namespace.
 *
 * The holder's host pid is kept in /var/lib/lochs/ns/<name>.pid (the
 * container state file is a raw struct dump, so it gets no new field).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "bsdulator/lochs_ns.h"

#define NS_DIR "/var/lib/lochs/ns"
#define HOLDER_NAME "lochs-init"

static void pid_file(const char *name, char *out, size_t sz) {
    snprintf(out, sz, NS_DIR "/%s.pid", name);
}

static void on_chld(int sig) { (void)sig; }

/* PID 1 of the container: reap orphans until killed */
static void holder_loop(void) {
    prctl(PR_SET_NAME, HOLDER_NAME, 0, 0, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_chld;
    sigaction(SIGCHLD, &sa, NULL);
    for (int fd = 0; fd < 1024; fd++) close(fd);
    for (;;) {
        while (waitpid(-1, NULL, 0) > 0) {}
        pause();
    }
}

/* Is pid a live holder? (pids are reused after a distro restart) */
static int is_holder(pid_t pid) {
    char path[64], comm[64] = "";
    snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    if (!fgets(comm, sizeof(comm), f)) comm[0] = '\0';
    fclose(f);
    comm[strcspn(comm, "\n")] = '\0';
    return strcmp(comm, HOLDER_NAME) == 0;
}

pid_t lochs_ns_pid(const char *name) {
    char path[512];
    pid_file(name, path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    long v = 0;
    if (fscanf(f, "%ld", &v) != 1) v = 0;
    fclose(f);
    return (v > 0 && is_holder((pid_t)v)) ? (pid_t)v : 0;
}

pid_t lochs_ns_start(const char *name) {
    pid_t existing = lochs_ns_pid(name);
    if (existing > 0) return existing;

    mkdir("/var/lib/lochs", 0755);
    mkdir(NS_DIR, 0700);

    int pfd[2];
    if (pipe(pfd) < 0) return -1;
    fflush(stdout);
    fflush(stderr);
    pid_t h = fork();
    if (h < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (h == 0) {
        close(pfd[0]);
        setsid();
        pid_t init = -1;
        if (unshare(CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID) == 0) {
            /* Host mounts made later (volumes) still reach the container;
             * nothing mounted inside leaks back to the host */
            mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL);
            sethostname(name, strlen(name));
            init = fork();
            if (init == 0) holder_loop();
        }
        ssize_t w = write(pfd[1], &init, sizeof(init));
        (void)w;
        _exit(init > 0 ? 0 : 1);
    }
    close(pfd[1]);
    pid_t init = -1;
    ssize_t r = read(pfd[0], &init, sizeof(init));
    close(pfd[0]);
    waitpid(h, NULL, 0);
    if (r != (ssize_t)sizeof(init) || init <= 0) return -1;

    char path[512];
    pid_file(name, path, sizeof(path));
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "%d\n", (int)init);
        fclose(f);
    }
    return init;
}

void lochs_ns_stop(const char *name) {
    pid_t pid = lochs_ns_pid(name);
    if (pid > 0) {
        /* PID 1 exiting ends every process left in the namespace */
        kill(pid, SIGKILL);
        for (int i = 0; i < 50 && is_holder(pid); i++) usleep(20000);
    }
    char path[512];
    pid_file(name, path, sizeof(path));
    unlink(path);
}

int lochs_ns_add_args(const char *name, const char **argv, int *n, char *buf, size_t bufsz) {
    pid_t pid = lochs_ns_pid(name);
    if (pid <= 0) return 0;
    snprintf(buf, bufsz, "%d", (int)pid);
    argv[(*n)++] = "-N";
    argv[(*n)++] = buf;
    return 1;
}
