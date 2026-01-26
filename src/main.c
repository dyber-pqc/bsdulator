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

#include "bsdulator.h"

/* Global state */
int bsd_debug_level = BSD_DEBUG_ERROR;
static char *freebsd_root = NULL;
static interceptor_state_t *global_state = NULL;

/* Signal handler for clean shutdown */
static void signal_handler(int sig) {
    if (global_state && global_state->pid > 0) {
        BSD_INFO("Caught signal %d, terminating traced process", sig);
        kill(global_state->pid, SIGKILL);
    }
    exit(128 + sig);
}

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
    
    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
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
    
    /* Spawn the process under ptrace */
    pid_t pid = interceptor_spawn(binary, argv, (char *const *)envp);
    if (pid < 0) {
        BSD_ERROR("Failed to spawn process: %s", strerror(errno));
        return 1;
    }
    
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
    if (state.last_event == EVENT_EXIT) {
        return state.exit_code;
    }
    
    return ret;
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
    while ((opt = getopt_long(argc, argv, "+hVvqr:st", long_options, &opt_idx)) != -1) {
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
