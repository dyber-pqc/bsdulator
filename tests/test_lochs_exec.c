/*
 * Unit tests for src/lochs/lochs_exec.c
 *
 * Build and run:  make test-exec
 *
 * The injection tests pass hostile strings as arguments and check that they
 * arrive unchanged and that no shell ever interprets them (the canary file
 * must never be created).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "bsdulator/lochs_exec.h"

static int failures = 0;

#define CHECK(cond, msg) do {                                   \
    if (cond) { printf("  ok   %s\n", msg); }                    \
    else { printf("  FAIL %s\n", msg); failures++; }             \
} while (0)

static const char *CANARY = "/tmp/lochs_exec_test_canary";

static int canary_exists(void) {
    struct stat st;
    return stat(CANARY, &st) == 0;
}

static void test_names(void) {
    printf("lochs_valid_name\n");
    CHECK(lochs_valid_name("web"), "accepts web");
    CHECK(lochs_valid_name("my_app-2.prod"), "accepts my_app-2.prod");
    CHECK(!lochs_valid_name(""), "rejects empty");
    CHECK(!lochs_valid_name("-rf"), "rejects leading dash");
    CHECK(!lochs_valid_name(".hidden"), "rejects leading dot");
    CHECK(!lochs_valid_name("a..b"), "rejects ..");
    CHECK(!lochs_valid_name("a/b"), "rejects slash");
    CHECK(!lochs_valid_name("x';touch /tmp/p;'"), "rejects quote and semicolon");
    CHECK(!lochs_valid_name("$(id)"), "rejects command substitution");
    CHECK(!lochs_valid_name("a b"), "rejects space");
    CHECK(!lochs_valid_name("a\nb"), "rejects newline");
    char long_name[80];
    memset(long_name, 'a', sizeof(long_name) - 1);
    long_name[sizeof(long_name) - 1] = '\0';
    CHECK(!lochs_valid_name(long_name), "rejects 79 characters");

    printf("lochs_valid_image_ref\n");
    CHECK(lochs_valid_image_ref("freebsd:15"), "accepts freebsd:15");
    CHECK(lochs_valid_image_ref("ghcr.io/org/app:1.0"), "accepts registry path");
    CHECK(lochs_valid_image_ref("app@sha256:abc123"), "accepts digest");
    CHECK(!lochs_valid_image_ref("x;id"), "rejects semicolon");
    CHECK(!lochs_valid_image_ref("../../etc"), "rejects ..");
    CHECK(!lochs_valid_image_ref("a b"), "rejects space");
}

static void test_run(void) {
    printf("lochs_run / lochs_capture\n");
    unlink(CANARY);

    const char *ok_argv[] = { "true", NULL };
    CHECK(lochs_run(ok_argv, 0) == 0, "true exits 0");

    const char *fail_argv[] = { "sh", "-c", "exit 3", NULL };
    CHECK(lochs_run(fail_argv, 0) == 3, "exit status is passed back");

    const char *missing_argv[] = { "/nonexistent/binary", NULL };
    CHECK(lochs_run(missing_argv, LOCHS_RUN_QUIET) == 127, "missing binary gives 127");

    /* A hostile argument must reach the program unchanged and unexecuted */
    char hostile[256];
    snprintf(hostile, sizeof(hostile), "x'; touch %s; echo '$(touch %s)`touch %s`",
             CANARY, CANARY, CANARY);
    const char *echo_argv[] = { "printf", "%s", hostile, NULL };
    char out[512];
    int r = lochs_capture(echo_argv, out, sizeof(out));
    CHECK(r == 0, "printf ran");
    CHECK(strcmp(out, hostile) == 0, "hostile argument arrives byte for byte");
    CHECK(!canary_exists(), "no shell interpreted the argument");

    /* Output truncation keeps a terminated buffer */
    const char *big_argv[] = { "printf", "0123456789", NULL };
    char small[5];
    lochs_capture(big_argv, small, sizeof(small));
    CHECK(strcmp(small, "0123") == 0, "capture truncates and terminates");

    /* stdout-only capture drops stderr */
    const char *err_argv[] = { "sh", "-c", "echo out; echo err 1>&2", NULL };
    lochs_capture_stdout(err_argv, out, sizeof(out));
    CHECK(strcmp(out, "out\n") == 0, "capture_stdout ignores stderr");
}

static void test_timeout(void) {
    printf("lochs_capture_timeout\n");
    int timed_out = 0;
    char out[64];
    const char *slow_argv[] = { "sleep", "5", NULL };
    int r = lochs_capture_timeout(slow_argv, out, sizeof(out), 1, &timed_out);
    CHECK(timed_out == 1, "slow command times out");
    CHECK(r == 128 + 9, "killed with SIGKILL");

    const char *fast_argv[] = { "echo", "hi", NULL };
    r = lochs_capture_timeout(fast_argv, out, sizeof(out), 5, &timed_out);
    CHECK(r == 0 && timed_out == 0 && strcmp(out, "hi\n") == 0, "fast command completes");
}

static void test_tee(void) {
    printf("lochs_run_tee\n");
    const char *log = "/tmp/lochs_exec_test_tee.log";
    unlink(log);
    const char *argv[] = { "sh", "-c", "echo one; echo two 1>&2; exit 4", NULL };
    int r = lochs_run_tee(argv, log);
    CHECK(r == 4, "tee returns the command's status");

    FILE *f = fopen(log, "r");
    char buf[64] = "";
    size_t n = f ? fread(buf, 1, sizeof(buf) - 1, f) : 0;
    if (f) fclose(f);
    buf[n] = '\0';
    CHECK(strstr(buf, "one") && strstr(buf, "two"), "log holds stdout and stderr");
    unlink(log);
}

static void test_quote(void) {
    printf("lochs_fprint_shell_quoted\n");
    char *buf = NULL;
    size_t len = 0;
    FILE *f = open_memstream(&buf, &len);
    lochs_fprint_shell_quoted(f, "it's $(x)");
    fclose(f);
    CHECK(strcmp(buf, "'it'\\''s $(x)'") == 0, "single quotes are escaped");

    /* Round trip through a real shell */
    char script[256];
    snprintf(script, sizeof(script), "printf %%s %s", buf);
    const char *argv[] = { "sh", "-c", script, NULL };
    char out[64];
    lochs_capture(argv, out, sizeof(out));
    CHECK(strcmp(out, "it's $(x)") == 0, "shell reads the value literally");
    free(buf);
}

int main(void) {
    test_names();
    test_run();
    test_timeout();
    test_tee();
    test_quote();
    unlink(CANARY);
    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
