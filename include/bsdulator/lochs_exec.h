/*
 * lochs_exec.h - Run external programs without a shell, and validate names
 *
 * Every helper here takes an argument vector, never a command string, so
 * container names, paths, image references and user commands are passed to
 * the program as single arguments and are never parsed by /bin/sh.
 */

#ifndef LOCHS_EXEC_H
#define LOCHS_EXEC_H

#include <stddef.h>
#include <stdio.h>

/* Flags for lochs_run() */
#define LOCHS_RUN_QUIET   0x1   /* send stdout and stderr to /dev/null */
#define LOCHS_RUN_NOWAIT  0x2   /* do not wait; return the child's PID */

/*
 * Run argv[0] (looked up in PATH) with the NULL-terminated argv.
 * Returns the exit status (0..255), 128+signal if it was killed,
 * the child PID with LOCHS_RUN_NOWAIT, or -1 if it could not be started.
 */
int lochs_run(const char *const argv[], int flags);

/*
 * Like lochs_run(), but the child first writes its PID to cgroup_procs
 * (e.g. /sys/fs/cgroup/lochs/<name>/cgroup.procs) so it and everything it
 * starts inherit that cgroup's limits. cgroup_procs may be NULL.
 */
int lochs_run_in_cgroup(const char *const argv[], const char *cgroup_procs,
                        int flags);

/*
 * Run argv with stdout and stderr copied both to our stdout and appended
 * to log_path (like "cmd 2>&1 | tee -a log_path"). stdin is inherited.
 * Returns the command's exit status, or -1 if it could not be started.
 */
int lochs_run_tee(const char *const argv[], const char *log_path);

/*
 * Like lochs_run(), but collects stdout and stderr into out (always
 * NUL-terminated; output beyond outsz-1 bytes is read and discarded).
 */
int lochs_capture(const char *const argv[], char *out, size_t outsz);

/*
 * Like lochs_capture(), but kills the command (SIGKILL) if it runs longer
 * than timeout_sec seconds (0 = no limit). *timed_out is set to 1 if so.
 */
int lochs_capture_timeout(const char *const argv[], char *out, size_t outsz,
                          int timeout_sec, int *timed_out);

/*
 * Like lochs_capture(), but only stdout is collected; stderr is discarded.
 */
int lochs_capture_stdout(const char *const argv[], char *out, size_t outsz);

/*
 * Container, network, volume and tag names: 1..63 characters,
 * [A-Za-z0-9][A-Za-z0-9_.-]*, and never "." or "..".
 */
int lochs_valid_name(const char *s);

/*
 * Image references such as "freebsd:15", "nginx:1.26" or
 * "registry.example.com/team/app:1.0": letters, digits and . _ - : / @,
 * starting with a letter or digit, no "..", at most 255 characters.
 */
int lochs_valid_image_ref(const char *s);

/* Print a standard error for a rejected name and return 0. */
int lochs_reject_name(const char *what, const char *value);

/* Path of the running lochs binary (from /proc/self/exe), or "lochs". */
const char *lochs_self_path(void);

/*
 * Path of the bsdulator engine: next to the lochs binary if present,
 * else ./bsdulator if present (development tree), else "bsdulator" (PATH).
 */
const char *lochs_bsdulator_path(void);

/*
 * Write value to f as a single-quoted POSIX shell word, escaping any
 * single quotes, so a FreeBSD /bin/sh reading the file sees it literally.
 */
void lochs_fprint_shell_quoted(FILE *f, const char *value);

#endif /* LOCHS_EXEC_H */
