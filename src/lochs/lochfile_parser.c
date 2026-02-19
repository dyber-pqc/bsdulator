/*
 * Lochfile Parser
 * 
 * Parses Dockerfile-like Lochfile format for building jail images.
 * 
 * Supported directives:
 *   FROM <image>           - Base image (required)
 *   RUN <command>          - Run command in jail during build
 *   COPY <src> <dst>       - Copy files from build context
 *   ENV <key>=<value>      - Set environment variable
 *   WORKDIR <path>         - Set working directory
 *   USER <user>            - Set user
 *   EXPOSE <port>          - Document exposed ports
 *   ENTRYPOINT [...]       - Default entrypoint
 *   CMD [...]              - Default command
 *   LABEL <key>=<value>    - Add metadata label
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>

#include "bsdulator/lochs.h"

/* Safe string copy */
static void safe_strcpy(char *dst, const char *src, size_t dst_size) {
    if (dst_size == 0) return;
    size_t len = strlen(src);
    if (len >= dst_size) len = dst_size - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/* Build context */
typedef struct {
    char base_image[128];
    char tag[128];
    char workdir[256];
    char user[64];
    
    /* Build steps */
    struct {
        char src[512];
        char dst[512];
    } copies[64];
    int copy_count;
    
    char *run_commands[128];
    int run_count;
    
    struct {
        char key[64];
        char value[256];
    } env[64];
    int env_count;
    
    struct {
        char key[64];
        char value[256];
    } labels[32];
    int label_count;
    
    int expose_ports[32];
    int expose_count;
    
    char entrypoint[1024];
    char cmd[1024];
    
    /* Build context directory */
    char context_dir[512];
    
    /* Build directory */
    char build_dir[512];
    
} lochfile_context_t;

/*
 * Trim whitespace from string
 */
static char *trim(char *str) {
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    
    return str;
}

/*
 * Generate short hash for image ID
 */
static void generate_hash(char *out, size_t out_size) {
    unsigned long hash = (unsigned long)time(NULL) ^ (unsigned long)getpid();
    snprintf(out, out_size, "%08lx%04x", hash, (unsigned)(rand() & 0xFFFF));
}

/*
 * Parse a single Lochfile line
 */
static int parse_line(lochfile_context_t *ctx, const char *line, int line_num) {
    char *line_copy = strdup(line);
    char *trimmed = trim(line_copy);
    
    /* Skip empty lines and comments */
    if (trimmed[0] == '\0' || trimmed[0] == '#') {
        free(line_copy);
        return 0;
    }
    
    /* Find directive */
    char directive[32] = {0};
    const char *args = trimmed;
    int i = 0;
    while (*args && !isspace((unsigned char)*args) && i < 31) {
        directive[i++] = (char)toupper((unsigned char)*args);
        args++;
    }
    directive[i] = '\0';
    
    /* Skip whitespace after directive */
    while (*args && isspace((unsigned char)*args)) args++;
    
    /* Process directives */
    if (strcmp(directive, "FROM") == 0) {
        safe_strcpy(ctx->base_image, args, sizeof(ctx->base_image));
    }
    else if (strcmp(directive, "COPY") == 0 || strcmp(directive, "ADD") == 0) {
        if (ctx->copy_count < 64) {
            char src[512] = {0}, dst[512] = {0};
            if (sscanf(args, "%511s %511s", src, dst) >= 1) {
                safe_strcpy(ctx->copies[ctx->copy_count].src, src, sizeof(ctx->copies[0].src));
                /* If no dest, use same as source */
                if (dst[0]) {
                    safe_strcpy(ctx->copies[ctx->copy_count].dst, dst, sizeof(ctx->copies[0].dst));
                } else {
                    safe_strcpy(ctx->copies[ctx->copy_count].dst, src, sizeof(ctx->copies[0].dst));
                }
                ctx->copy_count++;
            } else {
                fprintf(stderr, "Lochfile:%d: Invalid COPY syntax\n", line_num);
            }
        }
    }
    else if (strcmp(directive, "RUN") == 0) {
        if (ctx->run_count < 128) {
            ctx->run_commands[ctx->run_count++] = strdup(args);
        }
    }
    else if (strcmp(directive, "ENV") == 0) {
        if (ctx->env_count < 64) {
            /* Handle both "ENV KEY=value" and "ENV KEY value" */
            char *eq = strchr(args, '=');
            if (eq) {
                size_t key_len = (size_t)(eq - args);
                if (key_len > 63) key_len = 63;
                memcpy(ctx->env[ctx->env_count].key, args, key_len);
                ctx->env[ctx->env_count].key[key_len] = '\0';
                safe_strcpy(ctx->env[ctx->env_count].value, eq + 1, sizeof(ctx->env[0].value));
            } else {
                /* "ENV KEY value" format */
                char key[64], value[256];
                if (sscanf(args, "%63s %255[^\n]", key, value) == 2) {
                    safe_strcpy(ctx->env[ctx->env_count].key, key, sizeof(ctx->env[0].key));
                    safe_strcpy(ctx->env[ctx->env_count].value, value, sizeof(ctx->env[0].value));
                }
            }
            ctx->env_count++;
        }
    }
    else if (strcmp(directive, "LABEL") == 0) {
        if (ctx->label_count < 32) {
            char *eq = strchr(args, '=');
            if (eq) {
                size_t key_len = (size_t)(eq - args);
                if (key_len > 63) key_len = 63;
                memcpy(ctx->labels[ctx->label_count].key, args, key_len);
                ctx->labels[ctx->label_count].key[key_len] = '\0';
                /* Remove quotes from value */
                const char *val = eq + 1;
                if (*val == '"') val++;
                safe_strcpy(ctx->labels[ctx->label_count].value, val, sizeof(ctx->labels[0].value));
                size_t vlen = strlen(ctx->labels[ctx->label_count].value);
                if (vlen > 0 && ctx->labels[ctx->label_count].value[vlen-1] == '"') {
                    ctx->labels[ctx->label_count].value[vlen-1] = '\0';
                }
                ctx->label_count++;
            }
        }
    }
    else if (strcmp(directive, "EXPOSE") == 0) {
        char *port_list = strdup(args);
        char *saveptr;
        char *token = strtok_r(port_list, " \t,", &saveptr);
        while (token && ctx->expose_count < 32) {
            int port = atoi(token);
            if (port > 0 && port < 65536) {
                ctx->expose_ports[ctx->expose_count++] = port;
            }
            token = strtok_r(NULL, " \t,", &saveptr);
        }
        free(port_list);
    }
    else if (strcmp(directive, "WORKDIR") == 0) {
        safe_strcpy(ctx->workdir, args, sizeof(ctx->workdir));
    }
    else if (strcmp(directive, "USER") == 0) {
        safe_strcpy(ctx->user, args, sizeof(ctx->user));
    }
    else if (strcmp(directive, "ENTRYPOINT") == 0) {
        safe_strcpy(ctx->entrypoint, args, sizeof(ctx->entrypoint));
    }
    else if (strcmp(directive, "CMD") == 0) {
        safe_strcpy(ctx->cmd, args, sizeof(ctx->cmd));
    }
    else if (strcmp(directive, "MAINTAINER") == 0) {
        /* Deprecated but supported - convert to label */
        if (ctx->label_count < 32) {
            strcpy(ctx->labels[ctx->label_count].key, "maintainer");
            safe_strcpy(ctx->labels[ctx->label_count].value, args, sizeof(ctx->labels[0].value));
            ctx->label_count++;
        }
    }
    else if (strcmp(directive, "VOLUME") == 0 ||
             strcmp(directive, "ARG") == 0 ||
             strcmp(directive, "SHELL") == 0 ||
             strcmp(directive, "STOPSIGNAL") == 0 ||
             strcmp(directive, "HEALTHCHECK") == 0 ||
             strcmp(directive, "ONBUILD") == 0) {
        /* Recognized but not implemented - just warn */
        fprintf(stderr, "Lochfile:%d: Warning: %s not yet implemented, skipping\n", 
                line_num, directive);
    }
    else {
        fprintf(stderr, "Lochfile:%d: Unknown directive '%s'\n", line_num, directive);
        free(line_copy);
        return -1;
    }
    
    free(line_copy);
    return 0;
}

/*
 * Parse a Lochfile
 */
static int lochfile_parse(const char *path, lochfile_context_t *ctx) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Error: Cannot open Lochfile '%s': %s\n", path, strerror(errno));
        return -1;
    }
    
    memset(ctx, 0, sizeof(*ctx));
    strcpy(ctx->workdir, "/");
    
    char line[4096];
    int line_num = 0;
    int error = 0;
    
    while (fgets(line, sizeof(line), f)) {
        line_num++;
        
        /* Remove trailing newline */
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';
        if (len > 1 && line[len-2] == '\r') line[len-2] = '\0';
        
        /* Handle line continuation */
        len = strlen(line);
        while (len > 0 && line[len-1] == '\\') {
            line[len-1] = ' ';
            if (!fgets(line + len, (int)(sizeof(line) - len), f)) break;
            len = strlen(line);
            if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';
            line_num++;
        }
        
        if (parse_line(ctx, line, line_num) != 0) {
            error = 1;
        }
    }
    
    fclose(f);
    
    /* Validate required fields */
    if (ctx->base_image[0] == '\0') {
        fprintf(stderr, "Error: Lochfile requires FROM directive\n");
        return -1;
    }
    
    return error ? -1 : 0;
}

/*
 * Free lochfile context
 */
static void lochfile_free(lochfile_context_t *ctx) {
    for (int i = 0; i < ctx->run_count; i++) {
        free(ctx->run_commands[i]);
    }
}

/*
 * Execute a command in the build jail using BSDulator
 */
static int run_in_jail(const char *build_dir, const char *command) {
    char cmd[4096];
    
    /* Use BSDulator to run FreeBSD command in the build directory */
    snprintf(cmd, sizeof(cmd),
        "./bsdulator -t %s/libexec/ld-elf.so.1 %s/bin/sh -c '%s'",
        build_dir, build_dir, command);
    
    return system(cmd);
}

/*
 * Build image from Lochfile
 */
int lochs_build_from_lochfile(const char *lochfile_path, const char *context_dir, const char *tag) {
    lochfile_context_t ctx;
    int ret;
    
    printf("\033[1m=== Building image from %s ===\033[0m\n\n", lochfile_path);
    
    /* Parse Lochfile */
    if (lochfile_parse(lochfile_path, &ctx) != 0) {
        return -1;
    }
    
    safe_strcpy(ctx.context_dir, context_dir, sizeof(ctx.context_dir));
    if (tag) {
        safe_strcpy(ctx.tag, tag, sizeof(ctx.tag));
    }
    
    /* Show build plan */
    printf("Build plan:\n");
    printf("  Base image: %s\n", ctx.base_image);
    printf("  COPY steps: %d\n", ctx.copy_count);
    printf("  RUN steps:  %d\n", ctx.run_count);
    printf("  ENV vars:   %d\n", ctx.env_count);
    if (tag) printf("  Tag:        %s\n", tag);
    printf("\n");
    
    /* Step 1: Get base image */
    printf("\033[1mStep 1/6: Resolving base image\033[0m\n");
    
    char *base_path = lochs_image_get_path(ctx.base_image);
    if (!base_path) {
        printf("  Base image not found locally, pulling...\n");
        if (lochs_image_pull(ctx.base_image) != 0) {
            fprintf(stderr, "Error: Failed to pull base image '%s'\n", ctx.base_image);
            lochfile_free(&ctx);
            return -1;
        }
        base_path = lochs_image_get_path(ctx.base_image);
        if (!base_path) {
            fprintf(stderr, "Error: Failed to resolve base image path\n");
            lochfile_free(&ctx);
            return -1;
        }
    }
    printf("  ✓ Using: %s\n\n", base_path);
    
    /* Step 2: Create build directory */
    printf("\033[1mStep 2/6: Creating build environment\033[0m\n");
    
    char image_id[20];
    generate_hash(image_id, sizeof(image_id));
    snprintf(ctx.build_dir, sizeof(ctx.build_dir), "/var/lib/lochs/images/%s", image_id);
    
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", ctx.build_dir);
    if (system(cmd) != 0) {
        fprintf(stderr, "Error: Failed to create build directory\n");
        free(base_path);
        lochfile_free(&ctx);
        return -1;
    }
    
    /* Copy base image */
    printf("  Copying base image...\n");
    snprintf(cmd, sizeof(cmd), "cp -a '%s'/. '%s'/ 2>/dev/null", base_path, ctx.build_dir);
    ret = system(cmd);
    (void)ret;
    free(base_path);
    printf("  ✓ Build directory: %s\n\n", ctx.build_dir);
    
    /* Step 3: Process COPY directives */
    printf("\033[1mStep 3/6: Copying files\033[0m\n");
    if (ctx.copy_count == 0) {
        printf("  (no files to copy)\n");
    }
    for (int i = 0; i < ctx.copy_count; i++) {
        char src_path[1024];
        char dst_path[1024];
        
        /* Resolve source relative to context */
        if (ctx.copies[i].src[0] == '/') {
            safe_strcpy(src_path, ctx.copies[i].src, sizeof(src_path));
        } else {
            snprintf(src_path, sizeof(src_path), "%s/%s", context_dir, ctx.copies[i].src);
        }
        
        /* Resolve destination in build dir */
        if (ctx.copies[i].dst[0] == '/') {
            snprintf(dst_path, sizeof(dst_path), "%s%s", ctx.build_dir, ctx.copies[i].dst);
        } else {
            snprintf(dst_path, sizeof(dst_path), "%s/%s", ctx.build_dir, ctx.copies[i].dst);
        }
        
        printf("  COPY %s -> %s\n", ctx.copies[i].src, ctx.copies[i].dst);
        
        /* Create parent directory */
        char *last_slash = strrchr(dst_path, '/');
        if (last_slash && last_slash != dst_path) {
            *last_slash = '\0';
            snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", dst_path);
            ret = system(cmd);
            (void)ret;
            *last_slash = '/';
        }
        
        /* Check if source exists */
        struct stat st;
        if (stat(src_path, &st) != 0) {
            fprintf(stderr, "  ✗ Source not found: %s\n", src_path);
            continue;
        }
        
        /* Copy file or directory */
        if (S_ISDIR(st.st_mode)) {
            snprintf(cmd, sizeof(cmd), "cp -a '%s'/. '%s'/ 2>/dev/null", src_path, dst_path);
        } else {
            snprintf(cmd, sizeof(cmd), "cp -a '%s' '%s'", src_path, dst_path);
        }
        
        if (system(cmd) == 0) {
            printf("  ✓ Copied\n");
        } else {
            fprintf(stderr, "  ✗ Failed to copy\n");
        }
    }
    printf("\n");
    
    /* Step 4: Process RUN directives */
    printf("\033[1mStep 4/6: Running build commands\033[0m\n");
    if (ctx.run_count == 0) {
        printf("  (no commands to run)\n");
    }
    for (int i = 0; i < ctx.run_count; i++) {
        printf("  RUN %s\n", ctx.run_commands[i]);
        
        /* Run command using BSDulator */
        ret = run_in_jail(ctx.build_dir, ctx.run_commands[i]);
        if (ret == 0) {
            printf("  ✓ Success\n");
        } else {
            printf("  ⚠ Command returned %d (continuing)\n", ret);
        }
    }
    printf("\n");
    
    /* Step 5: Create image metadata */
    printf("\033[1mStep 5/6: Creating image metadata\033[0m\n");
    
    char meta_path[600];
    snprintf(meta_path, sizeof(meta_path), "%s/.lochs_image.conf", ctx.build_dir);
    
    FILE *meta = fopen(meta_path, "w");
    if (meta) {
        fprintf(meta, "# Lochs image configuration\n");
        fprintf(meta, "# Built: %s\n", ctime(&(time_t){time(NULL)}));
        fprintf(meta, "base=%s\n", ctx.base_image);
        
        if (ctx.workdir[0] && strcmp(ctx.workdir, "/") != 0) {
            fprintf(meta, "workdir=%s\n", ctx.workdir);
        }
        if (ctx.user[0]) {
            fprintf(meta, "user=%s\n", ctx.user);
        }
        if (ctx.entrypoint[0]) {
            fprintf(meta, "entrypoint=%s\n", ctx.entrypoint);
        }
        if (ctx.cmd[0]) {
            fprintf(meta, "cmd=%s\n", ctx.cmd);
        }
        
        /* Environment */
        for (int i = 0; i < ctx.env_count; i++) {
            fprintf(meta, "env.%s=%s\n", ctx.env[i].key, ctx.env[i].value);
        }
        
        /* Labels */
        for (int i = 0; i < ctx.label_count; i++) {
            fprintf(meta, "label.%s=%s\n", ctx.labels[i].key, ctx.labels[i].value);
        }
        
        /* Exposed ports */
        if (ctx.expose_count > 0) {
            fprintf(meta, "expose=");
            for (int i = 0; i < ctx.expose_count; i++) {
                fprintf(meta, "%s%d", i > 0 ? "," : "", ctx.expose_ports[i]);
            }
            fprintf(meta, "\n");
        }
        
        fclose(meta);
        printf("  ✓ Created .lochs_image.conf\n");
    }
    printf("\n");
    
    /* Step 6: Register image */
    printf("\033[1mStep 6/6: Registering image\033[0m\n");
    
    /* Determine final image name */
    char image_name[128];
    char image_tag_only[64] = "latest";
    
    if (tag) {
        safe_strcpy(image_name, tag, sizeof(image_name));
        /* Extract tag part */
        char *colon = strchr(image_name, ':');
        if (colon) {
            safe_strcpy(image_tag_only, colon + 1, sizeof(image_tag_only));
        }
    } else {
        snprintf(image_name, sizeof(image_name), "build-%s:latest", image_id);
    }
    
    /* Extract name without tag for registration */
    char name_only[128];
    safe_strcpy(name_only, image_name, sizeof(name_only));
    char *colon = strchr(name_only, ':');
    if (colon) *colon = '\0';
    
    /* Register with image system */
    if (lochs_image_register(name_only, image_tag_only, image_id) == 0) {
        printf("  ✓ Registered as %s\n", image_name);
    } else {
        printf("  ⚠ Image built but registration failed\n");
        printf("    You can still use it with --path %s\n", ctx.build_dir);
    }
    
    printf("\n\033[1;32m=== Successfully built %s ===\033[0m\n", image_name);
    printf("Image ID: %s\n", image_id);
    printf("Path:     %s\n", ctx.build_dir);
    printf("\nTo use: lochs create mycontainer --image %s\n", image_name);
    
    lochfile_free(&ctx);
    return 0;
}
