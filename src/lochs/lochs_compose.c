/*
 * Lochs Compose - Multi-container orchestration
 * 
 * Parses lochs.yml files and manages multi-container deployments.
 * Uses a simple line-by-line YAML parser (no external dependencies).
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <libgen.h>

#include "lochs_compose.h"
#include "bsdulator/lochs.h"

/* Safe string copy that always null-terminates */
static void safe_copy(char *dst, const char *src, size_t dst_size) {
    if (dst_size == 0) return;
    size_t src_len = strlen(src);
    size_t copy_len = (src_len < dst_size - 1) ? src_len : dst_size - 1;
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
}

/* Simple helper to trim whitespace */
static char *trim(char *str) {
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

/* Get indentation level (number of leading spaces) */
static int get_indent(const char *line) {
    int indent = 0;
    while (*line == ' ') {
        indent++;
        line++;
    }
    return indent;
}

/* Parse a "key: value" line */
static int parse_key_value(const char *line, char *key, size_t key_size, 
                           char *value, size_t value_size) {
    const char *colon = strchr(line, ':');
    if (!colon) return -1;
    
    /* Extract key */
    size_t key_len = (size_t)(colon - line);
    if (key_len >= key_size) key_len = key_size - 1;
    memcpy(key, line, key_len);
    key[key_len] = '\0';
    
    /* Trim key */
    char *k = trim(key);
    if (k != key) memmove(key, k, strlen(k) + 1);
    
    /* Extract value (skip colon and whitespace) */
    const char *v = colon + 1;
    while (*v && isspace((unsigned char)*v)) v++;
    
    /* Handle quoted strings */
    if (*v == '"' || *v == '\'') {
        char quote = *v;
        v++;
        const char *end = strchr(v, quote);
        if (end) {
            size_t len = (size_t)(end - v);
            if (len >= value_size) len = value_size - 1;
            memcpy(value, v, len);
            value[len] = '\0';
        } else {
            safe_copy(value, v, value_size);
        }
    } else {
        safe_copy(value, v, value_size);
        /* Trim trailing whitespace and comments */
        char *comment = strchr(value, '#');
        if (comment) *comment = '\0';
        char *end = value + strlen(value) - 1;
        while (end >= value && isspace((unsigned char)*end)) {
            *end = '\0';
            end--;
        }
    }
    
    return 0;
}

/* Parse port mapping like "8080:80" or "8080:80/tcp" */
static int parse_port(const char *str, compose_port_t *port) {
    char buf[64];
    safe_copy(buf, str, sizeof(buf));
    
    /* Remove quotes and dashes */
    char *s = buf;
    while (*s == '-' || *s == ' ' || *s == '"' || *s == '\'') s++;
    
    /* Check for protocol */
    strcpy(port->protocol, "tcp");
    char *slash = strchr(s, '/');
    if (slash) {
        *slash = '\0';
        safe_copy(port->protocol, slash + 1, sizeof(port->protocol));
    }
    
    /* Parse host:container */
    char *colon = strchr(s, ':');
    if (!colon) return -1;
    
    *colon = '\0';
    port->host_port = atoi(s);
    port->container_port = atoi(colon + 1);
    
    return (port->host_port > 0 && port->container_port > 0) ? 0 : -1;
}

/* Parse volume mapping like "/host:/container" or "/host:/container:ro" */
static int parse_volume(const char *str, compose_volume_t *vol) {
    char buf[1024];
    safe_copy(buf, str, sizeof(buf));
    
    /* Remove quotes and dashes */
    char *s = buf;
    while (*s == '-' || *s == ' ' || *s == '"' || *s == '\'') s++;
    
    vol->readonly = 0;
    
    /* Check for :ro suffix */
    char *ro = strstr(s, ":ro");
    if (ro && (ro[3] == '\0' || ro[3] == '"' || ro[3] == '\'')) {
        vol->readonly = 1;
        *ro = '\0';
    }
    
    /* Parse host:container */
    char *colon = strchr(s, ':');
    if (!colon) return -1;
    
    *colon = '\0';
    safe_copy(vol->host_path, s, sizeof(vol->host_path));
    safe_copy(vol->container_path, colon + 1, sizeof(vol->container_path));
    
    return 0;
}

/* Parse environment variable "NAME=value" */
static int parse_env(const char *str, compose_env_t *env) {
    char buf[512];
    safe_copy(buf, str, sizeof(buf));
    
    /* Remove quotes and dashes */
    char *s = buf;
    while (*s == '-' || *s == ' ' || *s == '"' || *s == '\'') s++;
    
    char *eq = strchr(s, '=');
    if (!eq) {
        /* Just a name, value is empty */
        safe_copy(env->name, s, sizeof(env->name));
        env->value[0] = '\0';
        return 0;
    }
    
    *eq = '\0';
    safe_copy(env->name, s, sizeof(env->name));
    safe_copy(env->value, eq + 1, sizeof(env->value));
    
    /* Remove trailing quote */
    size_t len = strlen(env->value);
    if (len > 0 && (env->value[len-1] == '"' || env->value[len-1] == '\'')) {
        env->value[len-1] = '\0';
    }
    
    return 0;
}

/*
 * Parse a lochs.yml file
 */
int compose_parse_file(const char *filename, compose_file_t *compose) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Error: Cannot open '%s'\n", filename);
        return -1;
    }
    
    memset(compose, 0, sizeof(*compose));
    strcpy(compose->version, "1");
    
    /* Extract project name from directory */
    char *fn_copy = strdup(filename);
    char *dir = dirname(fn_copy);
    char *base = basename(dir);
    if (strcmp(base, ".") == 0 || strcmp(base, "/") == 0) {
        char cwd[512];
        if (getcwd(cwd, sizeof(cwd))) {
            base = basename(cwd);
        }
    }
    safe_copy(compose->project_name, base, sizeof(compose->project_name));
    free(fn_copy);
    
    char line[2048];
    int in_services = 0;
    int in_service = 0;
    int in_ports = 0;
    int in_volumes = 0;
    int in_environment = 0;
    int in_depends_on = 0;
    compose_service_t *current_service = NULL;
    int service_indent = 0;
    
    while (fgets(line, sizeof(line), f)) {
        /* Remove newline */
        line[strcspn(line, "\r\n")] = '\0';
        
        /* Skip empty lines and comments */
        char *trimmed = trim(line);
        if (*trimmed == '\0' || *trimmed == '#') continue;
        
        int indent = get_indent(line);
        char key[256], value[1024];
        
        /* Check for top-level keys */
        if (indent == 0) {
            in_services = 0;
            in_service = 0;
            in_ports = 0;
            in_volumes = 0;
            in_environment = 0;
            in_depends_on = 0;
            
            if (parse_key_value(trimmed, key, sizeof(key), value, sizeof(value)) == 0) {
                if (strcmp(key, "version") == 0) {
                    safe_copy(compose->version, value, sizeof(compose->version));
                } else if (strcmp(key, "services") == 0) {
                    in_services = 1;
                }
            }
            continue;
        }
        
        /* Inside services block */
        if (in_services && !in_service) {
            /* This should be a service name */
            if (parse_key_value(trimmed, key, sizeof(key), value, sizeof(value)) == 0) {
                if (compose->service_count < COMPOSE_MAX_SERVICES) {
                    current_service = &compose->services[compose->service_count++];
                    memset(current_service, 0, sizeof(*current_service));
                    safe_copy(current_service->name, key, sizeof(current_service->name));
                    /* Default image */
                    strcpy(current_service->image, "freebsd:15.0-minimal");
                    in_service = 1;
                    service_indent = indent;
                }
            }
            continue;
        }
        
        /* Inside a service definition */
        if (in_service && current_service) {
            /* Check if we've exited the service (less indent) */
            if (indent <= service_indent && !(*trimmed == '-')) {
                /* New service or end of services */
                if (parse_key_value(trimmed, key, sizeof(key), value, sizeof(value)) == 0) {
                    if (compose->service_count < COMPOSE_MAX_SERVICES) {
                        current_service = &compose->services[compose->service_count++];
                        memset(current_service, 0, sizeof(*current_service));
                        safe_copy(current_service->name, key, sizeof(current_service->name));
                        strcpy(current_service->image, "freebsd:15.0-minimal");
                        service_indent = indent;
                        in_ports = 0;
                        in_volumes = 0;
                        in_environment = 0;
                        in_depends_on = 0;
                    }
                }
                continue;
            }
            
            /* Check for list items */
            if (*trimmed == '-') {
                char *item = trimmed + 1;
                while (*item && isspace((unsigned char)*item)) item++;
                
                if (in_ports && current_service->port_count < COMPOSE_MAX_PORTS) {
                    parse_port(item, &current_service->ports[current_service->port_count++]);
                } else if (in_volumes && current_service->volume_count < COMPOSE_MAX_VOLUMES) {
                    parse_volume(item, &current_service->volumes[current_service->volume_count++]);
                } else if (in_environment && current_service->env_count < COMPOSE_MAX_ENV) {
                    parse_env(item, &current_service->env[current_service->env_count++]);
                } else if (in_depends_on && current_service->depends_count < COMPOSE_MAX_DEPENDS) {
                    /* Remove quotes */
                    char *dep = item;
                    if (*dep == '"' || *dep == '\'') dep++;
                    char *end = dep + strlen(dep) - 1;
                    while (end > dep && (*end == '"' || *end == '\'' || isspace((unsigned char)*end))) {
                        *end = '\0';
                        end--;
                    }
                    safe_copy(current_service->depends_on[current_service->depends_count++], 
                              dep, COMPOSE_MAX_NAME);
                }
                continue;
            }
            
            /* Parse service property */
            if (parse_key_value(trimmed, key, sizeof(key), value, sizeof(value)) == 0) {
                in_ports = 0;
                in_volumes = 0;
                in_environment = 0;
                in_depends_on = 0;
                
                if (strcmp(key, "image") == 0) {
                    safe_copy(current_service->image, value, sizeof(current_service->image));
                } else if (strcmp(key, "command") == 0) {
                    safe_copy(current_service->command, value, sizeof(current_service->command));
                } else if (strcmp(key, "hostname") == 0) {
                    safe_copy(current_service->hostname, value, sizeof(current_service->hostname));
                } else if (strcmp(key, "ip4_addr") == 0 || strcmp(key, "ip") == 0) {
                    safe_copy(current_service->ip4_addr, value, sizeof(current_service->ip4_addr));
                } else if (strcmp(key, "vnet") == 0) {
                    current_service->vnet = (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0);
                } else if (strcmp(key, "restart") == 0) {
                    current_service->restart_always = (strcmp(value, "always") == 0);
                } else if (strcmp(key, "ports") == 0) {
                    in_ports = 1;
                } else if (strcmp(key, "volumes") == 0) {
                    in_volumes = 1;
                } else if (strcmp(key, "environment") == 0) {
                    in_environment = 1;
                } else if (strcmp(key, "depends_on") == 0) {
                    in_depends_on = 1;
                }
            }
        }
    }
    
    fclose(f);
    
    if (compose->service_count == 0) {
        fprintf(stderr, "Error: No services defined in '%s'\n", filename);
        return -1;
    }
    
    return 0;
}

/* Find a service by name */
static compose_service_t *find_service(compose_file_t *compose, const char *name) {
    for (int i = 0; i < compose->service_count; i++) {
        if (strcmp(compose->services[i].name, name) == 0) {
            return &compose->services[i];
        }
    }
    return NULL;
}

/* Check if all dependencies are started */
static int deps_satisfied(compose_file_t *compose, compose_service_t *svc) {
    for (int i = 0; i < svc->depends_count; i++) {
        compose_service_t *dep = find_service(compose, svc->depends_on[i]);
        if (!dep || !dep->started) {
            return 0;
        }
    }
    return 1;
}

/* Generate container name from project + service */
static void make_container_name(char *buf, size_t size, 
                                const char *project, const char *service) {
    snprintf(buf, size, "%s_%s", project, service);
}

/*
 * Start all services (lochs compose up)
 */
int compose_up(compose_file_t *compose, int detach) {
    printf("Starting %d service(s) from project '%s'...\n", 
           compose->service_count, compose->project_name);
    
    /* Start services in dependency order */
    int started = 0;
    int max_iterations = compose->service_count * 2;  /* Prevent infinite loops */
    
    while (started < compose->service_count && max_iterations-- > 0) {
        for (int i = 0; i < compose->service_count; i++) {
            compose_service_t *svc = &compose->services[i];
            
            if (svc->started) continue;
            if (!deps_satisfied(compose, svc)) continue;
            
            char container_name[128];
            make_container_name(container_name, sizeof(container_name),
                               compose->project_name, svc->name);
            
            printf("  Starting %s...\n", svc->name);
            
            /* Build create command */
            char cmd[4096];
            int pos = snprintf(cmd, sizeof(cmd), 
                "./lochs create %s --image %s",
                container_name, svc->image);
            
            if (svc->ip4_addr[0]) {
                pos += snprintf(cmd + pos, sizeof(cmd) - (size_t)pos,
                    " --ip %s", svc->ip4_addr);
            }
            
            if (svc->vnet) {
                pos += snprintf(cmd + pos, sizeof(cmd) - (size_t)pos, " --vnet");
            }
            
            /* Create container */
            int ret = system(cmd);
            if (ret != 0) {
                /* Container might already exist, try to continue */
                fprintf(stderr, "  Warning: create returned %d (container may exist)\n", ret);
            }
            
            /* Start container */
            snprintf(cmd, sizeof(cmd), "./lochs start %s", container_name);
            ret = system(cmd);
            if (ret != 0) {
                fprintf(stderr, "  Error: Failed to start %s\n", svc->name);
                continue;
            }
            
            /* Run command if specified */
            if (svc->command[0]) {
                snprintf(cmd, sizeof(cmd), "./lochs exec %s %s %s",
                    container_name, 
                    detach ? "&" : "",
                    svc->command);
                /* For now, just note the command - actual background execution needs more work */
                printf("  Command: %s\n", svc->command);
            }
            
            svc->started = 1;
            started++;
            printf("  ✓ %s started\n", svc->name);
        }
    }
    
    if (started < compose->service_count) {
        fprintf(stderr, "Warning: Only %d of %d services started (dependency issue?)\n",
                started, compose->service_count);
        return -1;
    }
    
    printf("\nAll services started!\n");
    
    /* Reload state so parent process has current state */
    lochs_state_load();
    
    return 0;
}

/*
 * Stop all services (lochs compose down)
 */
int compose_down(compose_file_t *compose) {
    printf("Stopping %d service(s) from project '%s'...\n",
           compose->service_count, compose->project_name);
    
    /* Stop in reverse order (opposite of dependencies) */
    for (int i = compose->service_count - 1; i >= 0; i--) {
        compose_service_t *svc = &compose->services[i];
        
        char container_name[128];
        make_container_name(container_name, sizeof(container_name),
                           compose->project_name, svc->name);
        
        printf("  Stopping %s...\n", svc->name);
        
        char cmd[512];
        int ret;
        
        snprintf(cmd, sizeof(cmd), "./lochs stop %s 2>/dev/null", container_name);
        ret = system(cmd);
        (void)ret;  /* Intentionally ignore - container may not be running */
        
        snprintf(cmd, sizeof(cmd), "./lochs rm %s 2>/dev/null", container_name);
        ret = system(cmd);
        (void)ret;  /* Intentionally ignore - container may not exist */
        
        svc->started = 0;
    }
    
    printf("\nAll services stopped.\n");
    return 0;
}

/*
 * List services (lochs compose ps)
 */
int compose_ps(compose_file_t *compose) {
    /* Load current state to check container status */
    lochs_state_load();
    
    printf("Project: %s\n\n", compose->project_name);
    printf("%-20s %-25s %-15s %s\n", "SERVICE", "CONTAINER", "IMAGE", "STATUS");
    printf("%-20s %-25s %-15s %s\n", "-------", "---------", "-----", "------");
    
    for (int i = 0; i < compose->service_count; i++) {
        compose_service_t *svc = &compose->services[i];
        
        char container_name[128];
        make_container_name(container_name, sizeof(container_name),
                           compose->project_name, svc->name);
        
        /* Check if container exists and is running */
        lochs_jail_t *jail = lochs_jail_find(container_name);
        const char *status = "not created";
        if (jail) {
            switch (jail->state) {
                case JAIL_STATE_CREATED: status = "created"; break;
                case JAIL_STATE_RUNNING: status = "\033[32mrunning\033[0m"; break;
                case JAIL_STATE_STOPPED: status = "stopped"; break;
                default: status = "unknown"; break;
            }
        }
        
        printf("%-20s %-25s %-15s %s\n",
               svc->name, container_name, svc->image, status);
    }
    
    return 0;
}

/*
 * Execute command in service
 */
int compose_exec(compose_file_t *compose, const char *service, int argc, char **argv) {
    compose_service_t *svc = find_service(compose, service);
    if (!svc) {
        fprintf(stderr, "Error: Service '%s' not found\n", service);
        return -1;
    }
    
    char container_name[128];
    make_container_name(container_name, sizeof(container_name),
                       compose->project_name, svc->name);
    
    /* Build exec command */
    char cmd[4096];
    int pos = snprintf(cmd, sizeof(cmd), "./lochs exec %s", container_name);
    
    for (int i = 0; i < argc && pos < (int)sizeof(cmd) - 1; i++) {
        pos += snprintf(cmd + pos, sizeof(cmd) - (size_t)pos, " %s", argv[i]);
    }
    
    return system(cmd);
}

/*
 * View logs (stub for now)
 */
int compose_logs(compose_file_t *compose, const char *service) {
    (void)compose;
    (void)service;
    printf("Logs not yet implemented\n");
    return 0;
}

/*
 * Free compose file resources
 */
void compose_free(compose_file_t *compose) {
    /* Nothing dynamic to free currently */
    (void)compose;
}
