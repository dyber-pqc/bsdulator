/*
 * lochs - FreeBSD jail management for Linux
 * Part of the Lochs.dev project
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "bsdulator/lochs.h"

typedef struct {
    const char *name;
    const char *description;
    int (*handler)(int argc, char **argv);
} lochs_command_t;

static lochs_command_t commands[] = {
    {"create",  "Create a new jail",                    lochs_cmd_create},
    {"start",   "Start a stopped jail",                 lochs_cmd_start},
    {"stop",    "Stop a running jail",                  lochs_cmd_stop},
    {"rm",      "Remove a jail",                        lochs_cmd_rm},
    {"exec",    "Execute a command in a jail",          lochs_cmd_exec},
    {"logs",    "View container logs",                  lochs_cmd_logs},
    {"ps",      "List jails",                           lochs_cmd_ps},
    {"images",  "List local images",                    lochs_cmd_images},
    {"pull",    "Pull an image from registry",          lochs_cmd_pull},
    {"push",    "Push an image to registry",            NULL},  /* Future */
    {"search",  "Search for images",                    lochs_cmd_search},
    {"rmi",     "Remove an image",                      lochs_cmd_rmi},
    {"build",   "Build image from Lochfile",            lochs_cmd_build},
    {"compose", "Manage multi-jail applications",       lochs_cmd_compose},
    {"version", "Show version information",             lochs_cmd_version},
    {NULL, NULL, NULL}
};

static void print_usage(const char *prog) {
    fprintf(stderr, "\n");
    fprintf(stderr, "  \033[1;31m🏔️  Lochs.dev\033[0m - FreeBSD jails on Linux\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Usage: %s <command> [options]\n", prog);
    fprintf(stderr, "\n\033[1mJail Commands:\033[0m\n");
    fprintf(stderr, "  %-12s %s\n", "create", "Create a new jail");
    fprintf(stderr, "  %-12s %s\n", "start", "Start a stopped jail");
    fprintf(stderr, "  %-12s %s\n", "stop", "Stop a running jail");
    fprintf(stderr, "  %-12s %s\n", "rm", "Remove a jail");
    fprintf(stderr, "  %-12s %s\n", "exec", "Execute a command in a jail");
    fprintf(stderr, "  %-12s %s\n", "logs", "View container logs");
    fprintf(stderr, "  %-12s %s\n", "ps", "List jails");
    
    fprintf(stderr, "\n\033[1mImage Commands:\033[0m\n");
    fprintf(stderr, "  %-12s %s\n", "images", "List local images");
    fprintf(stderr, "  %-12s %s\n", "pull", "Pull an image (e.g., lochs pull freebsd:15)");
    fprintf(stderr, "  %-12s %s\n", "search", "Search for images in registry");
    fprintf(stderr, "  %-12s %s\n", "rmi", "Remove a local image");
    fprintf(stderr, "  %-12s %s\n", "build", "Build image from Lochfile");
    
    fprintf(stderr, "\n\033[1mOrchestration:\033[0m\n");
    fprintf(stderr, "  %-12s %s\n", "compose", "Manage multi-jail applications (lochs.yml)");
    
    fprintf(stderr, "\n\033[1mOther:\033[0m\n");
    fprintf(stderr, "  %-12s %s\n", "version", "Show version information");
    
    fprintf(stderr, "\nRun '%s <command> --help' for more information.\n\n", prog);
}

static void print_banner(void) {
    fprintf(stderr, "\033[1;31m");
    fprintf(stderr, "    __                __       \n");
    fprintf(stderr, "   / /   ____  _____ / /_  ___ \n");
    fprintf(stderr, "  / /   / __ \\/ ___// __ \\/ __/\n");
    fprintf(stderr, " / /___/ /_/ / /__ / / / /\\__ \\\n");
    fprintf(stderr, "/_____/\\____/\\___//_/ /_//___/ \n");
    fprintf(stderr, "\033[0m");
    fprintf(stderr, "         \033[0;37mFreeBSD jails on Linux\033[0m\n\n");
}

int main(int argc, char **argv) {
    /* Need at least a command */
    if (argc < 2) {
        print_banner();
        print_usage(argv[0]);
        return 1;
    }
    
    /* Handle --version and --help at top level */
    if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0) {
        printf("lochs version %s\n", LOCHS_VERSION);
        return 0;
    }
    
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_banner();
        print_usage(argv[0]);
        return 0;
    }
    
    /* Find and execute command */
    for (int i = 0; commands[i].name != NULL; i++) {
        if (strcmp(argv[1], commands[i].name) == 0) {
            if (commands[i].handler == NULL) {
                fprintf(stderr, "Command '%s' is not yet implemented.\n", commands[i].name);
                return 1;
            }
            
            /* Load existing jail state */
            lochs_state_load();
            
            /* Also load image database */
            lochs_images_load();
            
            /* Execute command with remaining args */
            int result = commands[i].handler(argc - 1, argv + 1);
            
            /* Save state after command */
            lochs_state_save();
            
            return result;
        }
    }
    
    fprintf(stderr, "lochs: '%s' is not a lochs command.\n", argv[1]);
    fprintf(stderr, "See 'lochs --help' for available commands.\n");
    return 1;
}
