/*
 * BSDulator - FreeBSD Compatibility Layer for Linux
 * Main Entry Point
 * 
 * NOTE: This program only works on Linux - it uses ptrace and other
 * Linux-specific APIs that do not exist on Windows or macOS.
 * 
 * Copyright (c) 2024
 * BSD-2-Clause License
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "bsdulator.h"

/* Global state */
int bsd_debug_level = BSD_DEBUG_ERROR;
static char *freebsd_root = NULL;
static char *netns_name = NULL;
static int ns_holder_pid = 0;
static interceptor_state_t *global_state = NULL;

/*
 * bsdulator runs as two processes. The front is what the caller waits for:
 * it exits with the program's exit code as soon as the program exits, like
 * "docker exec". The tracer, its child, traces the program and everything
 * it starts, and keeps going after the program exits while daemons or
 * background jobs it started are still running. Messages from the tracer
 * to the front: { MSG_PID, host pid } then { MSG_EXIT, code }.
 */
enum { MSG_PID = 1, MSG_EXIT = 2 };
static int report_fd = -1;
static volatile sig_atomic_t front_target = 0;

static void report(int type, int value) {
    if (report_fd < 0) return;
    int m[2] = { type, value };
    ssize_t w = write(report_fd, m, sizeof(m));
    (void)w;
}

/* The program has exited: tell the front, then carry on detached */
static void tracer_main_exited(int code) {
    report(MSG_EXIT, code);
    if (report_fd >= 0) close(report_fd);
    report_fd = -1;
    /* Off the caller's terminal and output: a pipe the caller reads to
     * the end must not wait for the daemons */
    setsid();
    int nfd = open("/dev/null", O_RDWR);
    if (nfd >= 0) {
        dup2(nfd, 0);
        dup2(nfd, 1);
        dup2(nfd, 2);
        if (nfd > 2) close(nfd);
    }
}

/* Front: pass on signals sent with kill(); terminal ones (Ctrl-C) already
 * reach the program, which is in the same process group */
static void front_signal(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    if (si && si->si_code > 0) return;
    if (front_target > 0) kill((pid_t)front_target, sig);
}

static void front_wait(pid_t tracer, int fd) {
    front_target = tracer;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = front_signal;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    static const int fwd[] = { SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2, SIGWINCH };
    for (size_t i = 0; i < sizeof(fwd) / sizeof(fwd[0]); i++) sigaction(fwd[i], &sa, NULL);

    int m[2];
    for (;;) {
        ssize_t n = read(fd, m, sizeof(m));
        if (n < 0 && errno == EINTR) continue;
        if (n != (ssize_t)sizeof(m)) break;
        if (m[0] == MSG_PID) front_target = m[1];
        else if (m[0] == MSG_EXIT) _exit(m[1]);
    }
    /* The tracer ended without a report: use its own status */
    int st = 0;
    while (waitpid(tracer, &st, 0) < 0 && errno == EINTR) {}
    if (WIFEXITED(st)) _exit(WEXITSTATUS(st));
    if (WIFSIGNALED(st)) _exit(128 + WTERMSIG(st));
    _exit(1);
}

/* Tracer: the program gets terminal signals itself; SIGTERM ends the
 * tracer, and the kernel then kills every traced process (EXITKILL) */
static void tracer_ignore(int sig) { (void)sig; }

static void print_version(void) {
    printf("BSDulator v%d.%d.%d\n",
           BSDULATOR_VERSION_MAJOR,
           BSDULATOR_VERSION_MINOR,
           BSDULATOR_VERSION_PATCH);
    printf("FreeBSD syscall compatibility layer for Linux\n");
}

static void print_usage(const char *prog) {
    print_version();
    printf("\nUsage: %s [options] <freebsd-binary> [args...]\n", prog);
    printf("\nOptions:\n");
    printf("  -h, --help           Show this help message\n");
    printf("  -V, --version        Show version\n");
    printf("  -v, --verbose        Increase verbosity (can be repeated)\n");
    printf("  -q, --quiet          Quiet mode (errors only)\n");
    printf("  -r, --root <path>    FreeBSD root filesystem path\n");
    printf("  -n, --netns <name>   Run in network namespace\n");
    printf("  -N, --ns <pid>       Join the PID, mount, UTS and IPC namespaces of <pid>\n");
    printf("  -s, --stats          Print syscall statistics on exit\n");
    printf("  -t, --trace          Trace all syscalls (very verbose)\n");
    printf("\nExamples:\n");
    printf("  %s /path/to/freebsd/echo \"Hello World\"\n", prog);
    printf("  %s -v -r ./freebsd-root ./freebsd-root/bin/ls -la\n", prog);
    printf("\nEnvironment:\n");
    printf("  BSDULATOR_ROOT       FreeBSD root filesystem (default: ./freebsd-root)\n");
    printf("  BSDULATOR_DEBUG      Debug level (0-4)\n");
    printf("\nNOTE: This program only runs on Linux.\n");
}

static struct option long_options[] = {
    {"help",    no_argument,       0, 'h'},
    {"version", no_argument,       0, 'V'},
    {"verbose", no_argument,       0, 'v'},
    {"quiet",   no_argument,       0, 'q'},
    {"root",    required_argument, 0, 'r'},
    {"netns",   required_argument, 0, 'n'},
    {"ns",      required_argument, 0, 'N'},
    {"stats",   no_argument,       0, 's'},
    {"trace",   no_argument,       0, 't'},
    {0, 0, 0, 0}
};

/* Initialize BSDulator subsystems */
int bsdulator_init(void) {
    BSD_INFO("Initializing BSDulator v%d.%d.%d",
             BSDULATOR_VERSION_MAJOR,
             BSDULATOR_VERSION_MINOR,
             BSDULATOR_VERSION_PATCH);
    
    /* Initialize syscall translation tables */
    if (syscall_init() != 0) {
        BSD_ERROR("Failed to initialize syscall tables");
        return -1;
    }
    
    /* Initialize interceptor */
    if (interceptor_init() != 0) {
        BSD_ERROR("Failed to initialize interceptor");
        return -1;
    }
    
    /* Handlers, not SIG_IGN: exec resets them for the traced program */
    signal(SIGINT, tracer_ignore);
    signal(SIGQUIT, tracer_ignore);
    signal(SIGHUP, tracer_ignore);
    
    BSD_INFO("Initialization complete");
    return 0;
}

/* Cleanup resources */
void bsdulator_cleanup(void) {
    interceptor_cleanup();
    if (freebsd_root) {
        free(freebsd_root);
        freebsd_root = NULL;
    }
    if (netns_name) {
        free(netns_name);
        netns_name = NULL;
    }
    BSD_INFO("Cleanup complete");
}

/* Set debug level */
void bsdulator_set_debug(int level) {
    bsd_debug_level = level;
}

/* Set FreeBSD root path */
void bsdulator_set_freebsd_root(const char *path) {
    if (freebsd_root) {
        free(freebsd_root);
    }
    if (path) {
        char abs_path[PATH_MAX];
        if (realpath(path, abs_path)) {
            freebsd_root = strdup(abs_path);
        } else {
            freebsd_root = strdup(path);  /* fallback */
        }
    } else {
        freebsd_root = NULL;
    }
}

/* Get FreeBSD root path */
const char *bsdulator_get_freebsd_root(void) {
    if (freebsd_root) {
        return freebsd_root;
    }
    
    /* Check environment */
    const char *env = getenv("BSDULATOR_ROOT");
    if (env) {
        return env;
    }
    
    /* Default */
    return "./freebsd-root";
}

/* Set network namespace name */
void bsdulator_set_netns(const char *name) {
    if (netns_name) {
        free(netns_name);
    }
    netns_name = name ? strdup(name) : NULL;
}

/* Get network namespace name */
const char *bsdulator_get_netns(void) {
    return netns_name;
}

/* Container namespaces to join: those of this host process (0 = none) */
void bsdulator_set_ns_pid(int pid) {
    ns_holder_pid = pid;
}

int bsdulator_get_ns_pid(void) {
    return ns_holder_pid;
}

static int rooted_mode;

void bsdulator_set_rooted(int on) {
    rooted_mode = on;
}

int bsdulator_is_rooted(void) {
    return rooted_mode;
}

/* Run a FreeBSD binary */
int bsdulator_run(const char *binary, char *const argv[], char *const envp[]) {
    binary_info_t info;
    int ret;
    
    BSD_INFO("Preparing to run: %s", binary);
    
    /* Get binary information */
    ret = loader_get_info(binary, &info);
    if (ret != 0) {
        BSD_ERROR("Cannot read binary: %s", binary);
        return 1;
    }
    
    /* Print binary info in verbose mode */
    if (bsd_debug_level >= BSD_DEBUG_INFO) {
        loader_print_info(&info);
    }
    
    /* Check if this is a FreeBSD binary */
    if (info.os_type != BINARY_FREEBSD) {
        BSD_WARN("%s is not a FreeBSD binary (detected: %s)",
                 binary, loader_os_name(info.os_type));
        BSD_WARN("Continuing anyway - syscall translation may fail");
    }
    
    /* Check architecture compatibility */
    if (info.arch != ARCH_X86_64) {
        BSD_ERROR("Only x86_64 binaries are supported (detected: %s)",
                  loader_arch_name(info.arch));
        return 1;
    }
    
    /* Check if dynamic binary */
    if (info.link_type == LINK_DYNAMIC) {
        BSD_WARN("Dynamic binary detected - may need FreeBSD libraries");
        BSD_WARN("Interpreter: %s", info.interp);
    }
    
    /* Split into the front (returns the exit code) and the tracer */
    int rp[2];
    if (pipe2(rp, O_CLOEXEC) < 0) {
        BSD_ERROR("pipe: %s", strerror(errno));
        return 1;
    }
    fflush(stdout);
    fflush(stderr);
    pid_t tracer = fork();
    if (tracer < 0) {
        BSD_ERROR("fork: %s", strerror(errno));
        return 1;
    }
    if (tracer > 0) {
        close(rp[1]);
        front_wait(tracer, rp[0]);
    }
    close(rp[0]);
    report_fd = rp[1];
    interceptor_set_main_exit_hook(tracer_main_exited);

    /* Spawn the process under ptrace */
    pid_t pid = interceptor_spawn(binary, argv, (char *const *)envp);
    if (pid < 0) {
        BSD_ERROR("Failed to spawn process: %s", strerror(errno));
        report(MSG_EXIT, 127);
        return 1;
    }
    report(MSG_PID, (int)pid);
    
    BSD_INFO("Spawned process with PID %d", (int)pid);
    
    /* Set up interceptor state */
    interceptor_state_t state = {
        .pid = pid,
        .running = true,
        .in_syscall = false,
        .syscall_count = 0,
        .translated_count = 0,
        .emulated_count = 0,
        .failed_count = 0
    };
    
    global_state = &state;
    
    /* Run the main interception loop */
    ret = interceptor_run(&state);
    
    global_state = NULL;
    
    /* Return the exit code from the traced process */
    int code = state.last_event == EVENT_EXIT ? state.exit_code : (ret < 0 ? 1 : ret);
    report(MSG_EXIT, code);
    return code;
}

int main(int argc, char *argv[], char *envp[]) {
    int opt;
    int opt_idx = 0;
    int show_stats = 0;
    
    /* Check environment for debug level */
    const char *debug_env = getenv("BSDULATOR_DEBUG");
    if (debug_env) {
        bsd_debug_level = atoi(debug_env);
    }
    
    /* Parse options */
    while ((opt = getopt_long(argc, argv, "+hVvqr:n:N:st", long_options, &opt_idx)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return 0;
                
            case 'V':
                print_version();
                return 0;
                
            case 'v':
                if (bsd_debug_level < BSD_DEBUG_TRACE) {
                    bsd_debug_level++;
                }
                break;
                
            case 'q':
                bsd_debug_level = BSD_DEBUG_ERROR;
                break;
                
            case 'r':
                bsdulator_set_freebsd_root(optarg);
                break;
                
            case 'n':
                bsdulator_set_netns(optarg);
                break;

            case 'N':
                bsdulator_set_ns_pid(atoi(optarg));
                break;
                
            case 's':
                show_stats = 1;
                break;
                
            case 't':
                bsd_debug_level = BSD_DEBUG_TRACE;
                break;
                
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    /* Need at least a binary to run */
    if (optind >= argc) {
        fprintf(stderr, "Error: No binary specified\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    const char *binary = argv[optind];
    char **binary_argv = &argv[optind];
    
    /* Check if binary exists */
    if (access(binary, X_OK) != 0) {
        fprintf(stderr, "Error: Cannot execute '%s': %s\n", binary, strerror(errno));
        return 1;
    }
    
    /* Initialize BSDulator */
    if (bsdulator_init() != 0) {
        fprintf(stderr, "Error: Failed to initialize BSDulator\n");
        return 1;
    }
    
    /* Run the FreeBSD binary */
    int result = bsdulator_run(binary, binary_argv, envp);
    
    /* Print statistics if requested */
    if (show_stats && global_state) {
        interceptor_print_stats(global_state);
    }
    
    /* Cleanup */
    bsdulator_cleanup();
    
    return result;
}
