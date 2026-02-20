/*
 * BSDulator - FreeBSD Compatibility Layer for Linux
 * Main Header File
 */

#ifndef BSDULATOR_H
#define BSDULATOR_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <stdio.h>

/* Version */
#define BSDULATOR_VERSION_MAJOR 0
#define BSDULATOR_VERSION_MINOR 1
#define BSDULATOR_VERSION_PATCH 0

/* Configuration */
#define BSD_MAX_SYSCALL 600
#define BSD_MAX_PATH 4096

/* Debug levels */
#define BSD_DEBUG_NONE    0
#define BSD_DEBUG_ERROR   1
#define BSD_DEBUG_WARN    2
#define BSD_DEBUG_INFO    3
#define BSD_DEBUG_TRACE   4

/* Global debug level */
extern int bsd_debug_level;

/* Logging macros */
#define BSD_LOG(level, fmt, ...) do { \
    if (bsd_debug_level >= level) { \
        fprintf(stderr, "[BSD] " fmt "\n", ##__VA_ARGS__); \
    } \
} while(0)

#define BSD_ERROR(fmt, ...) BSD_LOG(BSD_DEBUG_ERROR, "ERROR: " fmt, ##__VA_ARGS__)
#define BSD_WARN(fmt, ...)  BSD_LOG(BSD_DEBUG_WARN, "WARN: " fmt, ##__VA_ARGS__)
#define BSD_INFO(fmt, ...)  BSD_LOG(BSD_DEBUG_INFO, fmt, ##__VA_ARGS__)
#define BSD_TRACE(fmt, ...) BSD_LOG(BSD_DEBUG_TRACE, "TRACE: " fmt, ##__VA_ARGS__)

/* Include component headers */
#include "bsdulator/syscall.h"
#include "bsdulator/interceptor.h"
#include "bsdulator/loader.h"
#include "bsdulator/abi.h"
#include "bsdulator/jail.h"

/* Main entry points */
int bsdulator_init(void);
void bsdulator_cleanup(void);
int bsdulator_run(const char *binary, char *const argv[], char *const envp[]);

/* Configuration */
void bsdulator_set_debug(int level);
void bsdulator_set_freebsd_root(const char *path);
const char *bsdulator_get_freebsd_root(void);
void bsdulator_set_netns(const char *netns_name);
const char *bsdulator_get_netns(void);

#endif /* BSDULATOR_H */
