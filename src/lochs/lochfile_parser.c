/*
 * Lochfile Parser
 * 
 * Parses Dockerfile-like Lochfile format for building jail images.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "bsdulator/lochs.h"

/* Helper to suppress unused result warnings */
#define IGNORE_RESULT(x) do { if (x) {} } while(0)

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
    char base_image[64];
    char name[64];
    char hostname[64];
    char ip[32];
    int vnet;
    char workdir[256];
    char user[32];
    
    /* Build steps */
    char *packages[64];
    int package_count;
    
    struct {
        char src[256];
        char dst[256];
    } copies[32];
    int copy_count;
    
    char *run_commands[64];
    int run_count;
    
    struct {
        char key[64];
        char value[256];
    } env[32];
    int env_count;
    
    int expose_ports[32];
    int expose_count;
    
    char *entrypoint[16];
    int entrypoint_count;
    
    char *cmd[16];
    int cmd_count;
    
    /* Build context directory */
    char context_dir[256];
    
    /* Output image path */
    char output_path[256];
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
 * Parse a JSON-style array: ["arg1", "arg2", ...]
 */
static int parse_json_array(const char *str, char **out, int max_items) {
    int count = 0;
    const char *p = str;
    
    /* Skip to opening bracket */
    while (*p && *p != '[') p++;
    if (*p != '[') return 0;
    p++;
    
    char buffer[1024];
    int in_string = 0;
    int buf_pos = 0;
    
    while (*p && *p != ']' && count < max_items) {
        if (*p == '"') {
            if (in_string) {
                buffer[buf_pos] = '\0';
                out[count++] = strdup(buffer);
                buf_pos = 0;
                in_string = 0;
            } else {
                in_string = 1;
            }
        } else if (in_string) {
            if (*p == '\\' && *(p+1)) {
                p++;
                buffer[buf_pos++] = *p;
            } else {
                buffer[buf_pos++] = *p;
            }
        }
        p++;
    }
    
    return count;
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
    else if (strcmp(directive, "NAME") == 0) {
        safe_strcpy(ctx->name, args, sizeof(ctx->name));
    }
    else if (strcmp(directive, "HOSTNAME") == 0) {
        safe_strcpy(ctx->hostname, args, sizeof(ctx->hostname));
    }
    else if (strcmp(directive, "IP") == 0) {
        safe_strcpy(ctx->ip, args, sizeof(ctx->ip));
    }
    else if (strcmp(directive, "VNET") == 0) {
        ctx->vnet = 1;
    }
    else if (strcmp(directive, "PKG") == 0) {
        char *pkg_list = strdup(args);
        char *saveptr;
        char *token = strtok_r(pkg_list, " \t", &saveptr);
        while (token && ctx->package_count < 64) {
            ctx->packages[ctx->package_count++] = strdup(token);
            token = strtok_r(NULL, " \t", &saveptr);
        }
        free(pkg_list);
    }
    else if (strcmp(directive, "COPY") == 0) {
        if (ctx->copy_count < 32) {
            char src[256] = {0}, dst[256] = {0};
            if (sscanf(args, "%255s %255s", src, dst) == 2) {
                safe_strcpy(ctx->copies[ctx->copy_count].src, src, sizeof(ctx->copies[0].src));
                safe_strcpy(ctx->copies[ctx->copy_count].dst, dst, sizeof(ctx->copies[0].dst));
                ctx->copy_count++;
            } else {
                fprintf(stderr, "Lochfile:%d: Invalid COPY syntax\n", line_num);
            }
        }
    }
    else if (strcmp(directive, "RUN") == 0) {
        if (ctx->run_count < 64) {
            ctx->run_commands[ctx->run_count++] = strdup(args);
        }
    }
    else if (strcmp(directive, "ENV") == 0) {
        if (ctx->env_count < 32) {
            char *eq = strchr(args, '=');
            if (eq) {
                size_t key_len = (size_t)(eq - args);
                if (key_len > 63) key_len = 63;
                memcpy(ctx->env[ctx->env_count].key, args, key_len);
                ctx->env[ctx->env_count].key[key_len] = '\0';
                safe_strcpy(ctx->env[ctx->env_count].value, eq + 1, sizeof(ctx->env[0].value));
                ctx->env_count++;
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
        ctx->entrypoint_count = parse_json_array(args, ctx->entrypoint, 16);
    }
    else if (strcmp(directive, "CMD") == 0) {
        ctx->cmd_count = parse_json_array(args, ctx->cmd, 16);
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
        
        /* Handle line continuation */
        while (len > 1 && line[len-2] == '\\') {
            line[len-2] = ' ';
            if (!fgets(line + len - 1, (int)(sizeof(line) - len + 1), f)) break;
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
    for (int i = 0; i < ctx->package_count; i++) {
        free(ctx->packages[i]);
    }
    for (int i = 0; i < ctx->run_count; i++) {
        free(ctx->run_commands[i]);
    }
    for (int i = 0; i < ctx->entrypoint_count; i++) {
        free(ctx->entrypoint[i]);
    }
    for (int i = 0; i < ctx->cmd_count; i++) {
        free(ctx->cmd[i]);
    }
}

/*
 * Build image from Lochfile
 */
static int lochfile_build(const char *lochfile_path, const char *context_dir, const char *tag) {
    lochfile_context_t ctx;
    
    printf("Building from %s...\n", lochfile_path);
    
    if (lochfile_parse(lochfile_path, &ctx) != 0) {
        return -1;
    }
    
    safe_strcpy(ctx.context_dir, context_dir, sizeof(ctx.context_dir));
    
    printf("\n");
    printf("  FROM:       %s\n", ctx.base_image);
    if (ctx.name[0]) printf("  NAME:       %s\n", ctx.name);
    if (ctx.hostname[0]) printf("  HOSTNAME:   %s\n", ctx.hostname);
    if (ctx.ip[0]) printf("  IP:         %s\n", ctx.ip);
    if (ctx.vnet) printf("  VNET:       enabled\n");
    if (ctx.package_count > 0) {
        printf("  PACKAGES:   ");
        for (int i = 0; i < ctx.package_count; i++) {
            printf("%s ", ctx.packages[i]);
        }
        printf("\n");
    }
    printf("  COPY steps: %d\n", ctx.copy_count);
    printf("  RUN steps:  %d\n", ctx.run_count);
    printf("\n");
    
    /* Step 1: Get base image */
    printf("Step 1: Resolving base image %s\n", ctx.base_image);
    
    char *base_path = lochs_image_get_path(ctx.base_image);
    if (!base_path) {
        printf("  Base image not found locally, pulling...\n");
        if (lochs_image_pull(ctx.base_image) != 0) {
            lochfile_free(&ctx);
            return -1;
        }
        base_path = lochs_image_get_path(ctx.base_image);
        if (!base_path) {
            fprintf(stderr, "Error: Failed to get base image path\n");
            lochfile_free(&ctx);
            return -1;
        }
    }
    printf("  Using base: %s\n", base_path);
    
    /* Step 2: Create build directory - use short names */
    char build_dir[128];
    snprintf(build_dir, sizeof(build_dir), "/var/lib/lochs/build/b%ld", (long)time(NULL));
    
    printf("\nStep 2: Creating build directory %s\n", build_dir);
    
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", build_dir);
    if (system(cmd) != 0) {
        fprintf(stderr, "Error: Failed to create build directory\n");
        free(base_path);
        lochfile_free(&ctx);
        return -1;
    }
    
    /* Copy base image */
    printf("  Copying base image...\n");
    snprintf(cmd, sizeof(cmd), "cp -a '%s'/. '%s'/ 2>/dev/null || true", base_path, build_dir);
    IGNORE_RESULT(system(cmd));
    free(base_path);
    
    /* Step 3: Process COPY directives */
    if (ctx.copy_count > 0) {
        printf("\nStep 3: Copying files\n");
        for (int i = 0; i < ctx.copy_count; i++) {
            char src_path[512];
            char dst_path[512];
            
            /* Resolve source relative to context */
            if (ctx.copies[i].src[0] == '/') {
                safe_strcpy(src_path, ctx.copies[i].src, sizeof(src_path));
            } else {
                snprintf(src_path, sizeof(src_path), "%s/%s", context_dir, ctx.copies[i].src);
            }
            
            snprintf(dst_path, sizeof(dst_path), "%s%s", build_dir, ctx.copies[i].dst);
            
            printf("  COPY %s -> %s\n", ctx.copies[i].src, ctx.copies[i].dst);
            
            /* Create parent directory */
            char *last_slash = strrchr(dst_path, '/');
            if (last_slash) {
                *last_slash = '\0';
                snprintf(cmd, sizeof(cmd), "mkdir -p '%s'", dst_path);
                IGNORE_RESULT(system(cmd));
                *last_slash = '/';
            }
            
            snprintf(cmd, sizeof(cmd), "cp -a '%s' '%s'", src_path, dst_path);
            if (system(cmd) != 0) {
                fprintf(stderr, "  Warning: Failed to copy %s\n", src_path);
            }
        }
    }
    
    /* Step 4: Process RUN directives */
    if (ctx.run_count > 0) {
        printf("\nStep 4: Running build commands\n");
        for (int i = 0; i < ctx.run_count; i++) {
            printf("  RUN %s\n", ctx.run_commands[i]);
            
            /* Run command in chroot */
            snprintf(cmd, sizeof(cmd), 
                "chroot '%s' /bin/sh -c '%s' 2>&1 || echo '  (command may have failed)'",
                build_dir, ctx.run_commands[i]);
            IGNORE_RESULT(system(cmd));
        }
    }
    
    /* Step 5: Create jail metadata */
    printf("\nStep 5: Creating jail configuration\n");
    
    char meta_path[160];
    snprintf(meta_path, sizeof(meta_path), "%s/.lochs.conf", build_dir);
    
    FILE *meta = fopen(meta_path, "w");
    if (meta) {
        fprintf(meta, "# Lochs jail configuration\n");
        fprintf(meta, "# Built from Lochfile\n\n");
        if (ctx.name[0]) fprintf(meta, "name=%s\n", ctx.name);
        if (ctx.hostname[0]) fprintf(meta, "hostname=%s\n", ctx.hostname);
        if (ctx.ip[0]) fprintf(meta, "ip=%s\n", ctx.ip);
        if (ctx.vnet) fprintf(meta, "vnet=1\n");
        if (ctx.workdir[0]) fprintf(meta, "workdir=%s\n", ctx.workdir);
        if (ctx.user[0]) fprintf(meta, "user=%s\n", ctx.user);
        
        if (ctx.entrypoint_count > 0) {
            fprintf(meta, "entrypoint=");
            for (int i = 0; i < ctx.entrypoint_count; i++) {
                fprintf(meta, "%s%s", i > 0 ? " " : "", ctx.entrypoint[i]);
            }
            fprintf(meta, "\n");
        }
        
        if (ctx.expose_count > 0) {
            fprintf(meta, "expose=");
            for (int i = 0; i < ctx.expose_count; i++) {
                fprintf(meta, "%s%d", i > 0 ? "," : "", ctx.expose_ports[i]);
            }
            fprintf(meta, "\n");
        }
        
        fclose(meta);
    }
    
    /* Step 6: Save as image */
    printf("\nStep 6: Saving image\n");
    
    char image_name[128];
    if (tag) {
        safe_strcpy(image_name, tag, sizeof(image_name));
    } else if (ctx.name[0]) {
        snprintf(image_name, sizeof(image_name), "%s:latest", ctx.name);
    } else {
        snprintf(image_name, sizeof(image_name), "build-%ld:latest", (long)time(NULL));
    }
    
    /* Move to images directory */
    char final_path[160];
    const char *build_name = strrchr(build_dir, '/');
    if (build_name) build_name++; else build_name = build_dir;
    snprintf(final_path, sizeof(final_path), "/var/lib/lochs/images/%s", build_name);
    
    snprintf(cmd, sizeof(cmd), "mv '%s' '%s'", build_dir, final_path);
    if (system(cmd) != 0) {
        fprintf(stderr, "Warning: Failed to move to images directory\n");
        safe_strcpy(final_path, build_dir, sizeof(final_path));
    }
    
    printf("\n");
    printf("Successfully built image: %s\n", image_name);
    printf("  Path: %s\n", final_path);
    
    lochfile_free(&ctx);
    return 0;
}

/*
 * External interface for build command
 */
int lochs_build_from_lochfile(const char *lochfile, const char *context, const char *tag) {
    return lochfile_build(lochfile, context, tag);
}
