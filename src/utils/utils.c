/*
 * BSDulator - Utility Functions
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "bsdulator.h"

/* Logging utility */
void bsd_log(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[BSDulator] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

/* Error logging */
void bsd_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[BSDulator ERROR] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

/* Hex dump for debugging */
void bsd_hexdump(const void *data, size_t size) {
    const unsigned char *p = data;
    for (size_t i = 0; i < size; i++) {
        if (i % 16 == 0) {
            fprintf(stderr, "%08zx: ", i);
        }
        fprintf(stderr, "%02x ", p[i]);
        if (i % 16 == 15 || i == size - 1) {
            fprintf(stderr, "\n");
        }
    }
}
