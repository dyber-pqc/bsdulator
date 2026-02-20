#ifndef LOCHS_H
#define LOCHS_H

#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#define LOCHS_VERSION "0.1.0"
#define LOCHS_MAX_NAME 64
#define LOCHS_MAX_PATH 1024
#define LOCHS_MAX_JAILS 64
#define LOCHS_MAX_SERVICES 32
#define LOCHS_MAX_PORTS 16

/* Jail states */
typedef enum {
    JAIL_STATE_CREATED,
    JAIL_STATE_RUNNING,
    JAIL_STATE_STOPPED,
    JAIL_STATE_REMOVED
} jail_state_t;

/* Port mapping */
typedef struct {
    int host_port;
    int container_port;
    char protocol[8];               /* "tcp" or "udp" */
    pid_t forwarder_pid;            /* PID of socat process */
} lochs_port_map_t;

/* Volume mount */
typedef struct {
    char host_path[512];
    char container_path[512];
    int readonly;
} lochs_volume_t;

#define LOCHS_MAX_VOLUMES 16
#define LOCHS_MAX_ENV 32
#define LOCHS_MAX_NETWORKS 16
#define LOCHS_NETWORK_NAME_MAX 64

/* Managed jail entry (extends raw bsd_jail_t) */
typedef struct {
    int jid;
    char name[LOCHS_MAX_NAME];
    char path[LOCHS_MAX_PATH];
    char image[LOCHS_MAX_NAME];
    char ip4_addr[64];
    int vnet;
    jail_state_t state;
    pid_t pid;                      /* Main process PID */
    time_t created_at;
    time_t started_at;
    
    /* Port mappings */
    lochs_port_map_t ports[LOCHS_MAX_PORTS];
    int port_count;
    
    /* Volume mounts */
    lochs_volume_t volumes[LOCHS_MAX_VOLUMES];
    int volume_count;
    
    /* Environment variables */
    char env_keys[LOCHS_MAX_ENV][64];
    char env_values[LOCHS_MAX_ENV][256];
    int env_count;
    
    /* Network */
    char network[LOCHS_NETWORK_NAME_MAX];
    char netns[32];                 /* Network namespace name */
    
    /* Storage - OverlayFS COW */
    char image_path[LOCHS_MAX_PATH];  /* Base image (lowerdir) */
    char diff_path[LOCHS_MAX_PATH];   /* Container changes (upperdir) */
    char work_path[LOCHS_MAX_PATH];   /* OverlayFS work dir */
    char merged_path[LOCHS_MAX_PATH]; /* Merged view (container root) */
    int overlay_mounted;              /* Is overlay currently mounted? */

    /* Auto-start command */
    char cmd[1024];                   /* CMD from Lochfile */
    char entrypoint[1024];            /* ENTRYPOINT from Lochfile */
    char workdir[256];                /* WORKDIR from Lochfile */
} lochs_jail_t;

/* Network definition */
typedef struct {
    char name[LOCHS_NETWORK_NAME_MAX];
    char subnet[64];                /* e.g., "172.20.0.0/16" */
    char gateway[64];               /* e.g., "172.20.0.1" */
    char bridge[20];                /* Linux bridge name, e.g., "lochs0" */
    int next_ip;                    /* Next IP to assign (last octet) */
    int active;
} lochs_network_t;

/* Lochfile parsed representation */
typedef struct {
    char from_image[LOCHS_MAX_NAME];
    char name[LOCHS_MAX_NAME];
    char ip4_addr[64];
    int vnet;
    char *packages[64];             /* PKG directives */
    int package_count;
    char *copy_src[32];             /* COPY sources */
    char *copy_dst[32];             /* COPY destinations */
    int copy_count;
    char *run_commands[64];         /* RUN directives */
    int run_count;
    char *entrypoint[16];           /* ENTRYPOINT args */
    int entrypoint_argc;
    int expose_ports[32];
    int expose_count;
} lochfile_t;

/* lochs.yml service definition */
typedef struct {
    char name[LOCHS_MAX_NAME];
    char image[LOCHS_MAX_NAME];
    char build_path[LOCHS_MAX_PATH];
    char *ports[16];
    int port_count;
    char *volumes[16];
    int volume_count;
    char *depends_on[16];
    int depends_count;
    char network[LOCHS_MAX_NAME];
} lochs_service_t;

/* lochs.yml parsed representation */
typedef struct {
    char version[16];
    lochs_service_t services[LOCHS_MAX_SERVICES];
    int service_count;
} lochs_compose_t;

/* Command handlers */
int lochs_cmd_create(int argc, char **argv);
int lochs_cmd_start(int argc, char **argv);
int lochs_cmd_stop(int argc, char **argv);
int lochs_cmd_rm(int argc, char **argv);
int lochs_cmd_exec(int argc, char **argv);
int lochs_cmd_ps(int argc, char **argv);
int lochs_cmd_images(int argc, char **argv);
int lochs_cmd_pull(int argc, char **argv);
int lochs_cmd_build(int argc, char **argv);
int lochs_cmd_compose(int argc, char **argv);
int lochs_cmd_version(int argc, char **argv);
int lochs_cmd_search(int argc, char **argv);
int lochs_cmd_rmi(int argc, char **argv);
int lochs_cmd_logs(int argc, char **argv);
int lochs_cmd_network(int argc, char **argv);

/* Network management */
int lochs_network_create(const char *name, const char *subnet);
int lochs_network_remove(const char *name);
int lochs_network_list(void);
lochs_network_t *lochs_network_find(const char *name);
char *lochs_network_assign_ip(const char *network_name);
int lochs_network_setup_container(const char *container_name, const char *network_name);
int lochs_network_teardown_container(const char *container_name);
int lochs_networks_load(void);
int lochs_networks_save(void);

/* Compose parser */
int lochs_compose_parse(const char *path, lochs_compose_t *compose);
void lochs_compose_free(lochs_compose_t *compose);

/* Image management (lochs_images.c) */
int lochs_images_load(void);
int lochs_images_save(void);
int lochs_image_pull(const char *image_name);
int lochs_image_list_local(void);
int lochs_image_remove(const char *image_name);
int lochs_image_search(const char *query);
char *lochs_image_get_path(const char *image_name);
int lochs_image_register(const char *name, const char *tag, const char *image_id);

/* Lochfile build (lochfile_parser.c) */
int lochs_build_from_lochfile(const char *lochfile, const char *context, const char *tag);

/* Jail state persistence */
int lochs_state_save(void);
int lochs_state_load(void);
lochs_jail_t *lochs_jail_find(const char *name);
int lochs_jail_add(lochs_jail_t *jail);
int lochs_jail_remove(const char *name);

/* Storage management - OverlayFS COW */
int lochs_storage_init(void);
int lochs_storage_create_container(lochs_jail_t *jail, const char *image_path);
int lochs_storage_mount_container(lochs_jail_t *jail);
int lochs_storage_unmount_container(lochs_jail_t *jail);
int lochs_storage_destroy_container(lochs_jail_t *jail);
int lochs_storage_is_zfs_available(void);
int lochs_storage_is_overlay_available(void);

#endif /* LOCHS_H */
