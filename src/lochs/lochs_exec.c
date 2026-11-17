/*
 * lochs_exec.c - Run external programs without a shell, and validate names
 *
 * Replaces system()/popen() command strings. Arguments go straight to
 * execvp(), so nothing a user controls is ever interpreted by /bin/sh.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define LOCHS_SELF_PATH_MAX 4096

#include "bsdulator/lochs_exec.h"

static int wait_status(pid_t pid) {
    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

static void redirect_to_devnull(int fd) {
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        dup2(devnull, fd);
        if (devnull != fd) close(devnull);
    }
}

int lochs_run(const char *const argv[], int flags) {
    return lochs_run_in_cgroup(argv, NULL, flags);
}

int lochs_run_in_cgroup(const char *const argv[], const char *cgroup_procs,
                        int flags) {
    if (!argv || !argv[0]) return -1;

    fflush(stdout);
    fflush(stderr);

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (flags & LOCHS_RUN_DETACH)
            setsid();
        if (cgroup_procs) {
            int cfd = open(cgroup_procs, O_WRONLY);
            if (cfd < 0) _exit(126);
            char pidbuf[32];
            int n = snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)getpid());
            if (write(cfd, pidbuf, (size_t)n) != n) _exit(126);
            close(cfd);
        }
        if (flags & LOCHS_RUN_QUIET) {
            redirect_to_devnull(STDOUT_FILENO);
            redirect_to_devnull(STDERR_FILENO);
        }
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    if (flags & LOCHS_RUN_NOWAIT) return (int)pid;
    return wait_status(pid);
}

static int capture(const char *const argv[], char *out, size_t outsz,
                   int keep_stderr) {
    if (!argv || !argv[0]) return -1;
    if (out && outsz) out[0] = '\0';

    int fds[2];
    if (pipe(fds) < 0) return -1;

    fflush(stdout);
    fflush(stderr);

    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        if (keep_stderr)
            dup2(fds[1], STDERR_FILENO);
        else
            redirect_to_devnull(STDERR_FILENO);
        close(fds[1]);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }

    close(fds[1]);
    size_t used = 0;
    char buf[4096];
    for (;;) {
        ssize_t n = read(fds[0], buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        if (out && outsz > 1 && used < outsz - 1) {
            size_t room = outsz - 1 - used;
            size_t take = (size_t)n < room ? (size_t)n : room;
            memcpy(out + used, buf, take);
            used += take;
        }
    }
    close(fds[0]);
    if (out && outsz) out[used] = '\0';
    return wait_status(pid);
}

int lochs_run_tee(const char *const argv[], const char *log_path) {
    if (!argv || !argv[0]) return -1;

    int log_fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
    int fds[2];
    if (pipe(fds) < 0) {
        if (log_fd >= 0) close(log_fd);
        return -1;
    }

    fflush(stdout);
    fflush(stderr);

    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        if (log_fd >= 0) close(log_fd);
        return -1;
    }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        dup2(fds[1], STDERR_FILENO);
        close(fds[1]);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }

    close(fds[1]);
    char buf[4096];
    for (;;) {
        ssize_t n = read(fds[0], buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        if (write(STDOUT_FILENO, buf, (size_t)n) < 0) { /* keep logging */ }
        if (log_fd >= 0 && write(log_fd, buf, (size_t)n) < 0) {
            close(log_fd);
            log_fd = -1;
        }
    }
    close(fds[0]);
    if (log_fd >= 0) close(log_fd);
    return wait_status(pid);
}

int lochs_capture(const char *const argv[], char *out, size_t outsz) {
    return capture(argv, out, outsz, 1);
}

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

int lochs_capture_timeout(const char *const argv[], char *out, size_t outsz,
                          int timeout_sec, int *timed_out) {
    if (timed_out) *timed_out = 0;
    if (!argv || !argv[0]) return -1;
    if (out && outsz) out[0] = '\0';

    int fds[2];
    if (pipe(fds) < 0) return -1;

    fflush(stdout);
    fflush(stderr);

    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        dup2(fds[1], STDERR_FILENO);
        close(fds[1]);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }

    close(fds[1]);
    long deadline = timeout_sec > 0 ? now_ms() + timeout_sec * 1000L : 0;
    size_t used = 0;
    char buf[4096];
    for (;;) {
        int wait_ms = -1;
        if (deadline) {
            long left = deadline - now_ms();
            if (left <= 0) {
                kill(pid, SIGKILL);
                if (timed_out) *timed_out = 1;
                break;
            }
            wait_ms = (int)left;
        }
        struct pollfd pfd = { .fd = fds[0], .events = POLLIN };
        int pr = poll(&pfd, 1, wait_ms);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (pr == 0) continue;   /* deadline check at loop top */
        ssize_t n = read(fds[0], buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        if (out && outsz > 1 && used < outsz - 1) {
            size_t room = outsz - 1 - used;
            size_t take = (size_t)n < room ? (size_t)n : room;
            memcpy(out + used, buf, take);
            used += take;
        }
    }
    close(fds[0]);
    if (out && outsz) out[used] = '\0';
    return wait_status(pid);
}

int lochs_capture_stdout(const char *const argv[], char *out, size_t outsz) {
    return capture(argv, out, outsz, 0);
}

static int is_alnum(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9');
}

int lochs_valid_name(const char *s) {
    if (!s || !s[0]) return 0;
    if (!is_alnum(s[0])) return 0;
    size_t len = 0;
    for (const char *p = s; *p; p++, len++) {
        if (len >= 63) return 0;
        if (!is_alnum(*p) && *p != '_' && *p != '.' && *p != '-') return 0;
    }
    if (strstr(s, "..")) return 0;
    return 1;
}

int lochs_valid_image_ref(const char *s) {
    if (!s || !s[0]) return 0;
    if (!is_alnum(s[0])) return 0;
    size_t len = 0;
    for (const char *p = s; *p; p++, len++) {
        if (len >= 255) return 0;
        if (!is_alnum(*p) && *p != '_' && *p != '.' && *p != '-' &&
            *p != ':' && *p != '/' && *p != '@') return 0;
    }
    if (strstr(s, "..")) return 0;
    return 1;
}

int lochs_reject_name(const char *what, const char *value) {
    fprintf(stderr,
            "Error: invalid %s '%s'. Use letters, digits, '.', '_' or '-', "
            "starting with a letter or digit (max 63 characters).\n",
            what, value ? value : "");
    return 0;
}

const char *lochs_self_path(void) {
    static char path[LOCHS_SELF_PATH_MAX];
    if (path[0]) return path;
    ssize_t n = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (n <= 0) {
        path[0] = '\0';
        return "lochs";
    }
    path[n] = '\0';
    return path;
}

const char *lochs_bsdulator_path(void) {
    static char path[LOCHS_SELF_PATH_MAX];
    if (path[0]) return path;

    const char *self = lochs_self_path();
    const char *slash = strrchr(self, '/');
    if (slash) {
        size_t dir_len = (size_t)(slash - self);
        if (dir_len + sizeof("/bsdulator") < sizeof(path)) {
            memcpy(path, self, dir_len);
            memcpy(path + dir_len, "/bsdulator", sizeof("/bsdulator"));
            if (access(path, X_OK) == 0) return path;
        }
    }
    if (access("./bsdulator", X_OK) == 0) {
        snprintf(path, sizeof(path), "./bsdulator");
        return path;
    }
    snprintf(path, sizeof(path), "bsdulator");
    return path;
}

void lochs_fprint_shell_quoted(FILE *f, const char *value) {
    fputc('\'', f);
    for (const char *p = value; *p; p++) {
        if (*p == '\'')
            fputs("'\\''", f);
        else
            fputc(*p, f);
    }
    fputc('\'', f);
}
