/*
 * Lochs Compose - Multi-container orchestration
 * 
 * Parses lochs.yml files and manages multi-container deployments.
 * Similar to Docker Compose but for FreeBSD jails.
 */

#ifndef LOCHS_COMPOSE_H
#define LOCHS_COMPOSE_H

#define COMPOSE_MAX_SERVICES    32
#define COMPOSE_MAX_NAME        64
#define COMPOSE_MAX_IMAGE       128
#define COMPOSE_MAX_COMMAND     1024
#define COMPOSE_MAX_VOLUMES     16
#define COMPOSE_MAX_PORTS       16
#define COMPOSE_MAX_ENV         32
#define COMPOSE_MAX_DEPENDS     16

/* Port mapping */
typedef struct {
    int host_port;
    int container_port;
    char protocol[8];  /* "tcp" or "udp" */
} compose_port_t;

/* Volume mapping */
typedef struct {
    char host_path[512];
    char container_path[512];
    int readonly;
} compose_volume_t;

/* Environment variable */
typedef struct {
    char name[64];
    char value[256];
} compose_env_t;

/* Service definition */
typedef struct {
    char name[COMPOSE_MAX_NAME];
    char image[COMPOSE_MAX_IMAGE];
    char command[COMPOSE_MAX_COMMAND];
    char hostname[COMPOSE_MAX_NAME];
    char ip4_addr[32];
    int vnet;
    int restart_always;
    
    /* Ports */
    compose_port_t ports[COMPOSE_MAX_PORTS];
    int port_count;
    
    /* Volumes */
    compose_volume_t volumes[COMPOSE_MAX_VOLUMES];
    int volume_count;
    
    /* Environment */
    compose_env_t env[COMPOSE_MAX_ENV];
    int env_count;
    
    /* Dependencies */
    char depends_on[COMPOSE_MAX_DEPENDS][COMPOSE_MAX_NAME];
    int depends_count;
    
    /* Runtime state */
    int started;
    int jid;
} compose_service_t;

/* Compose file */
typedef struct {
    char version[16];
    char project_name[COMPOSE_MAX_NAME];
    compose_service_t services[COMPOSE_MAX_SERVICES];
    int service_count;
} compose_file_t;

/*
 * Parse a lochs.yml file
 * Returns 0 on success, -1 on error
 */
int compose_parse_file(const char *filename, compose_file_t *compose);

/*
 * Start all services (lochs compose up)
 */
int compose_up(compose_file_t *compose, int detach);

/*
 * Stop all services (lochs compose down)
 */
int compose_down(compose_file_t *compose);

/*
 * List services (lochs compose ps)
 */
int compose_ps(compose_file_t *compose);

/*
 * Execute command in service (lochs compose exec)
 */
int compose_exec(compose_file_t *compose, const char *service, int argc, char **argv);

/*
 * View logs (lochs compose logs)
 */
int compose_logs(compose_file_t *compose, const char *service);

/*
 * Free compose file resources
 */
void compose_free(compose_file_t *compose);

#endif /* LOCHS_COMPOSE_H */
