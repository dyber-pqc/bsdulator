#ifndef LOCHS_H
#define LOCHS_H

#include <stdint.h>
#include <sys/types.h>

#define LOCHS_VERSION "0.1.0"
#define LOCHS_MAX_NAME 64
#define LOCHS_MAX_PATH 1024
#define LOCHS_MAX_SERVICES 32

/* Jail states */
typedef enum {
    JAIL_STATE_CREATED,
    JAIL_STATE_RUNNING,
    JAIL_STATE_STOPPED,
    JAIL_STATE_REMOVED
} jail_state_t;

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
} lochs_jail_t;

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

/* Lochfile parser */
int lochfile_parse(const char *path, lochfile_t *lf);
void lochfile_free(lochfile_t *lf);

/* Compose parser */
int lochs_compose_parse(const char *path, lochs_compose_t *compose);
void lochs_compose_free(lochs_compose_t *compose);

/* Image management */
int lochs_image_list(void);
int lochs_image_pull(const char *image_name);
int lochs_image_exists(const char *image_name);
char *lochs_image_path(const char *image_name);

/* Jail state persistence */
int lochs_state_save(void);
int lochs_state_load(void);
lochs_jail_t *lochs_jail_find(const char *name);
int lochs_jail_add(lochs_jail_t *jail);
int lochs_jail_remove(const char *name);

#endif /* LOCHS_H */