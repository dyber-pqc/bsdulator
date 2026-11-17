/*
 * lochs_ns.c - per-container PID, mount, UTS and IPC namespaces
 *
 * Each running container has a holder process: PID 1 of the container's
 * PID namespace, which also holds its mount, UTS (hostname) and IPC
 * namespaces. Every bsdulator run for the container joins them with
 * "-N <holder pid>", so all of a container's processes share one view and
 * see neither host processes nor other containers'. Stopping the container
 * kills the holder, which ends every process still in the namespace.
 *
 * The holder's host pid is kept in /var/lib/lochs/ns/<name>.pid (the
 * container state file is a raw struct dump, so it gets no new field).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <ftw.h>

#include "bsdulator/lochs.h"
#include "bsdulator/lochs_exec.h"

#include "bsdulator/lochs_ns.h"

#define NS_DIR "/var/lib/lochs/ns"
#define HOLDER_NAME "lochs-init"

static void pid_file(const char *name, char *out, size_t sz) {
    snprintf(out, sz, NS_DIR "/%s.pid", name);
}

static void base_file(const char *name, char *out, size_t sz);

static void on_chld(int sig) { (void)sig; }

/* PID 1 of the container: reap orphans until killed */
static void holder_loop(void) {
    prctl(PR_SET_NAME, HOLDER_NAME, 0, 0, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_chld;
    sigaction(SIGCHLD, &sa, NULL);
    for (int fd = 0; fd < 1024; fd++) close(fd);
    for (;;) {
        while (waitpid(-1, NULL, 0) > 0) {}
        pause();
    }
}

/* Is pid a live holder? (pids are reused after a distro restart) */
static int is_holder(pid_t pid) {
    char path[64], comm[64] = "";
    snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    if (!fgets(comm, sizeof(comm), f)) comm[0] = '\0';
    fclose(f);
    comm[strcspn(comm, "\n")] = '\0';
    return strcmp(comm, HOLDER_NAME) == 0;
}

pid_t lochs_ns_pid(const char *name) {
    char path[512];
    pid_file(name, path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    long v = 0;
    if (fscanf(f, "%ld", &v) != 1) v = 0;
    fclose(f);
    return (v > 0 && is_holder((pid_t)v)) ? (pid_t)v : 0;
}

/*
 * A /proc of the container's own: it lists only the container's processes
 * (the caller is PID 1 of its PID namespace). Like Docker, the parts that
 * reach the kernel as a whole are read-only and a few files are hidden.
 * Needed by /dev/fd, /dev/stdin and friends, which point into /proc/self.
 */
static void private_proc(const char *root) {
    char p[4096], q[4200];
    snprintf(p, sizeof(p), "%s/proc", root);
    mkdir(p, 0555);
    if (mount("proc", p, "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0) {
        fprintf(stderr, "Warning: no private /proc (%s)\n", strerror(errno));
        return;
    }
    static const char *ro[] = { "sys", "sysrq-trigger", "irq", "bus", "fs" };
    for (size_t i = 0; i < sizeof(ro) / sizeof(ro[0]); i++) {
        snprintf(q, sizeof(q), "%s/%s", p, ro[i]);
        if (access(q, F_OK) == 0 && mount(q, q, NULL, MS_BIND | MS_REC, NULL) == 0)
            mount(NULL, q, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
    }
    static const char *hide[] = { "kcore", "keys", "timer_list", "sched_debug", "latency_stats" };
    for (size_t i = 0; i < sizeof(hide) / sizeof(hide[0]); i++) {
        snprintf(q, sizeof(q), "%s/%s", p, hide[i]);
        if (access(q, F_OK) == 0) mount("/dev/null", q, NULL, MS_BIND, NULL);
    }
}

#ifndef SYS_open_tree
#define SYS_open_tree 428
#endif
#ifndef SYS_move_mount
#define SYS_move_mount 429
#endif

/*
 * Make the current directory (the container root) the mount namespace's
 * "/" and detach the host's filesystem from the namespace, so nothing
 * outside the container exists there (with chroot alone it stays
 * reachable). Works from "." only: the paths above the root are not
 * reachable from the container's user namespace (lochs storage is 0700).
 * Returns 0 on success, 1 when it is unavailable and the namespace is
 * unchanged, -1 when it failed half-way and the namespace must not be used.
 */
static int pivot_into(void) {
    /* pivot_root needs a mount point this namespace created itself: a
     * recursive bind of "." attached on top of "." */
    int t = (int)syscall(SYS_open_tree, AT_FDCWD, ".", 1 /* OPEN_TREE_CLONE */ |
                         0x8000 /* AT_RECURSIVE */ | O_CLOEXEC);
    if (t < 0) return 1;
    if (syscall(SYS_move_mount, t, "", AT_FDCWD, ".", 0x4 /* MOVE_MOUNT_F_EMPTY_PATH */) < 0) {
        close(t);
        return 1;
    }
    int r = fchdir(t);   /* into the new mount */
    close(t);
    if (r < 0) return -1;
    /* Old root is stacked on "." and then detached: no directory needed */
    if (syscall(SYS_pivot_root, ".", ".") < 0) return -1;
    if (umount2(".", MNT_DETACH) < 0) return -1;
    if (chdir("/") < 0) return -1;
    return 0;
}

pid_t lochs_ns_start(const char *name, const char *root) {
    pid_t existing = lochs_ns_pid(name);
    if (existing > 0) return existing;

    mkdir("/var/lib/lochs", 0755);
    mkdir(NS_DIR, 0700);

    /*
     * The holder first makes a user namespace; lochs then writes its uid
     * and gid maps (container 0..65535 -> host LOCHS_ID_BASE..), and the
     * holder makes the other namespaces inside it, so container root has
     * privileges only over the container. Kernels without user namespaces
     * fall back to the other namespaces alone.
     */
    int pfd[2], up[2], go[2];
    if (pipe(pfd) < 0) return -1;
    if (pipe(up) < 0 || pipe(go) < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    fflush(stdout);
    fflush(stderr);
    pid_t h = fork();
    if (h < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (h == 0) {
        close(pfd[0]);
        close(up[0]);
        close(go[1]);
        setsid();
        /* Into the container's cgroup (lochs_cgroup_apply_limits), while
         * still host root: everything in the container descends from
         * here, and bsdulator -N joins the same cgroup */
        if (lochs_cgroup_join(name) != 0) _exit(1);
        /* Into the root while still host root: unsharing the mount
         * namespace moves the working directory onto its copy there, and
         * the root is then set up from "." */
        int have_root = root && root[0] && chdir(root) == 0;
        char userns = unshare(CLONE_NEWUSER) == 0;
        ssize_t w = write(up[1], &userns, 1);
        char ok = 0;
        if (read(go[0], &ok, 1) != 1) ok = 0;
        pid_t init = -1;
        if (userns && !ok) _exit(1);
        /* A cgroup namespace too: the container sees its cgroup as "/" */
        int nsflags = CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID;
        int made = unshare(nsflags | CLONE_NEWCGROUP) == 0 || unshare(nsflags) == 0;
        if (made) {
            /* Host mounts made later (volumes) still reach the container;
             * nothing mounted inside leaks back to the host */
            mount(NULL, "/", NULL, MS_REC | MS_SLAVE, NULL);
            sethostname(name, strlen(name));
            /* PID 1 sets up the filesystem: /proc must be mounted from
             * inside the PID namespace to show only its processes */
            int rp[2];
            if (pipe(rp) == 0) {
                init = fork();
                if (init == 0) {
                    close(rp[0]);
                    if (have_root) private_proc(".");
                    int pv = have_root ? pivot_into() : 1;
                    if (pv > 0 && root && root[0])
                        fprintf(stderr, "Warning: pivot_root failed for '%s' (%s); the host filesystem stays in its mount namespace\n",
                                name, strerror(errno));
                    char st = pv < 0 ? 0 : 1;
                    ssize_t rw = write(rp[1], &st, 1);
                    (void)rw;
                    if (pv < 0) _exit(1);
                    holder_loop();
                }
                close(rp[1]);
                char st = 0;
                if (init > 0 && (read(rp[0], &st, 1) != 1 || !st)) {
                    fprintf(stderr, "Error: could not set up the root of '%s'\n", name);
                    kill(init, SIGKILL);
                    init = -1;
                }
                close(rp[0]);
            }
        }
        w = write(pfd[1], &init, sizeof(init));
        (void)w;
        _exit(init > 0 ? 0 : 1);
    }
    close(pfd[1]);
    close(up[1]);
    close(go[0]);
    char userns = 0, ok = 1;
    if (read(up[0], &userns, 1) != 1) userns = 0;
    if (userns) {
        char path[64], map[64];
        snprintf(map, sizeof(map), "0 %u %d\n", (unsigned)lochs_ns_base(name), LOCHS_ID_COUNT);
        const char *files[2] = { "uid_map", "gid_map" };
        for (int i = 0; i < 2 && ok; i++) {
            snprintf(path, sizeof(path), "/proc/%d/%s", (int)h, files[i]);
            int fd = open(path, O_WRONLY);
            if (fd < 0 || write(fd, map, strlen(map)) != (ssize_t)strlen(map)) ok = 0;
            if (fd >= 0) close(fd);
        }
        if (!ok) fprintf(stderr, "Warning: cannot map ids for '%s': %s\n", name, strerror(errno));
    } else {
        fprintf(stderr, "Warning: no user namespaces on this kernel; '%s' runs as host root\n", name);
    }
    ssize_t gw = write(go[1], &ok, 1);
    (void)gw;
    close(up[0]);
    close(go[1]);
    pid_t init = -1;
    ssize_t r = read(pfd[0], &init, sizeof(init));
    close(pfd[0]);
    waitpid(h, NULL, 0);
    if (r != (ssize_t)sizeof(init) || init <= 0) return -1;

    char path[512];
    pid_file(name, path, sizeof(path));
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "%d\n", (int)init);
        fclose(f);
    }
    return init;
}

void lochs_ns_stop(const char *name) {
    pid_t pid = lochs_ns_pid(name);
    if (pid > 0) {
        /* PID 1 exiting ends every process left in the namespace */
        kill(pid, SIGKILL);
        for (int i = 0; i < 50 && is_holder(pid); i++) usleep(20000);
    }
    char path[512];
    pid_file(name, path, sizeof(path));
    unlink(path);
    base_file(name, path, sizeof(path));
    unlink(path);
}

int lochs_ns_add_args(const char *name, const char **argv, int *n, char *buf, size_t bufsz) {
    pid_t pid = lochs_ns_pid(name);
    if (pid <= 0) return 0;
    snprintf(buf, bufsz, "%d", (int)pid);
    argv[(*n)++] = "-N";
    argv[(*n)++] = buf;
    return 1;
}

/* ---------------------------------------------------------------------
 * Container id ranges
 *
 * Container uid/gid N is host <base> + N, and every container has its own
 * base (LOCHS_ID_BASE + k * LOCHS_ID_COUNT, k >= 1), kept in
 * /var/lib/lochs/ids/<name> from its first start until `lochs rm`. Root of
 * one container is then nobody to another container's files and processes.
 *
 * Image and container layers keep container ids on disk (0..65535). At
 * start the image and the container's own layer are mounted idmapped to
 * the container's range, and the overlay is built on those mounts (Linux
 * 5.19+). On older kernels lochs falls back to one shared range,
 * LOCHS_ID_BASE, with the layers chown-shifted into it on disk.
 * ------------------------------------------------------------------- */

#define IDS_DIR "/var/lib/lochs/ids"
#define IDMNT_DIR "/var/lib/lochs/idmnt"

static long read_long(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    long v = -1;
    if (fscanf(f, "%ld", &v) != 1) v = -1;
    fclose(f);
    return v;
}

static int write_long(const char *path, long v) {
    char tmp[600];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return -1;
    fprintf(f, "%ld\n", v);
    if (fclose(f) != 0) return -1;
    return rename(tmp, path);
}

uid_t lochs_ids_alloc(const char *name) {
    char path[512];
    mkdir("/var/lib/lochs", 0755);
    mkdir(IDS_DIR, 0700);
    snprintf(path, sizeof(path), IDS_DIR "/%s", name);
    long v = read_long(path);
    if (v >= (long)LOCHS_ID_BASE + LOCHS_ID_COUNT) return (uid_t)v;

    int lfd = open(IDS_DIR "/.lock", O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lfd >= 0) flock(lfd, LOCK_EX);
    v = read_long(path);
    if (v < (long)LOCHS_ID_BASE + LOCHS_ID_COUNT) {
        /* Lowest slot no other container holds */
        static unsigned char used[8192];
        memset(used, 0, sizeof(used));
        DIR *d = opendir(IDS_DIR);
        struct dirent *e;
        while (d && (e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.' || strchr(e->d_name, '.')) continue;
            char p2[600];
            snprintf(p2, sizeof(p2), IDS_DIR "/%s", e->d_name);
            long b = read_long(p2);
            long k = (b - LOCHS_ID_BASE) / LOCHS_ID_COUNT;
            if (b > LOCHS_ID_BASE && k > 0 && k < (long)sizeof(used)) used[k] = 1;
        }
        if (d) closedir(d);
        long k = 1;
        while (k < (long)sizeof(used) && used[k]) k++;
        v = k < (long)sizeof(used) ? (long)LOCHS_ID_BASE + k * LOCHS_ID_COUNT : -1;
        if (v > 0 && write_long(path, v) < 0) v = -1;
    }
    if (lfd >= 0) close(lfd);   /* releases the lock */
    return v > 0 ? (uid_t)v : (uid_t)LOCHS_ID_BASE;
}

void lochs_ids_free(const char *name) {
    char path[512];
    snprintf(path, sizeof(path), IDS_DIR "/%s", name);
    unlink(path);
}

/* The range of a running container (written at start) */
static void base_file(const char *name, char *out, size_t sz) {
    snprintf(out, sz, NS_DIR "/%s.ids", name);
}

void lochs_ns_set_base(const char *name, uid_t base) {
    char path[512];
    mkdir("/var/lib/lochs", 0755);
    mkdir(NS_DIR, 0700);
    base_file(name, path, sizeof(path));
    write_long(path, (long)base);
}

uid_t lochs_ns_base(const char *name) {
    char path[512];
    base_file(name, path, sizeof(path));
    long v = read_long(path);
    return v >= LOCHS_ID_BASE ? (uid_t)v : (uid_t)LOCHS_ID_BASE;
}

/* --- ownership shifting --------------------------------------------- */

static uid_t shift_from, shift_to;

static int shift_one(const char *path, const struct stat *st, int flag, struct FTW *ftw) {
    (void)flag; (void)ftw;
    /* Never device nodes: /dev entries are bind mounts of the host's */
    if (S_ISCHR(st->st_mode) || S_ISBLK(st->st_mode)) return 0;
    uid_t u = st->st_uid;
    gid_t g = st->st_gid;
    uid_t nu = (u >= shift_from && u - shift_from < (uid_t)LOCHS_ID_COUNT) ? u - shift_from + shift_to : u;
    gid_t ng = (g >= shift_from && g - shift_from < (gid_t)LOCHS_ID_COUNT) ? g - shift_from + shift_to : g;
    if (nu == u && ng == g) return 0;
    if (lchown(path, nu, ng) < 0) return 0;  /* keep going */
    /* chown clears setuid/setgid bits: restore the mode */
    if (!S_ISLNK(st->st_mode) && (st->st_mode & (S_ISUID | S_ISGID)))
        chmod(path, st->st_mode & 07777);
    return 0;
}

int lochs_idshift_tree(const char *dir, uid_t from, uid_t to) {
    if (from == to) return 0;
    struct stat st;
    if (lstat(dir, &st) < 0) return -1;
    shift_from = from;
    shift_to = to;
    return nftw(dir, shift_one, 64, FTW_PHYS | FTW_MOUNT) < 0 ? -1 : 0;
}

/* A tree shared by containers (an image layer, a named volume) keeps its
 * current shift in IDS_DIR/<key>. Older lochs marked a shifted image with
 * a .lochs-idmap-100000 file in its root. */
int lochs_tree_ids(const char *key, const char *path, uid_t want) {
    char state[600], marker[1100];
    mkdir("/var/lib/lochs", 0755);
    mkdir(IDS_DIR, 0700);
    snprintf(state, sizeof(state), IDS_DIR "/%s", key);
    snprintf(marker, sizeof(marker), "%s/.lochs-idmap-%d", path, LOCHS_ID_BASE);
    long cur = read_long(state);
    if (cur < 0) cur = access(marker, F_OK) == 0 ? LOCHS_ID_BASE : 0;
    if ((uid_t)cur != want) {
        printf("  Ids: shifting %s files to %s ids (once)\n", key, want ? "host" : "container");
        if (lochs_idshift_tree(path, (uid_t)cur, want) < 0) return -1;
    }
    unlink(marker);
    return write_long(state, (long)want);
}

void lochs_tree_ids_forget(const char *key) {
    char state[600];
    snprintf(state, sizeof(state), IDS_DIR "/%s", key);
    unlink(state);
}

static void image_key(const char *image_path, char *out, size_t sz) {
    const char *b = strrchr(image_path, '/');
    snprintf(out, sz, "image.%s", b ? b + 1 : image_path);
}

int lochs_image_ids(const char *image_path, uid_t want) {
    char key[300];
    image_key(image_path, key, sizeof(key));
    return lochs_tree_ids(key, image_path, want);
}

int lochs_image_ids_set(const char *image_path, uid_t state) {
    char key[300], path[600];
    image_key(image_path, key, sizeof(key));
    mkdir("/var/lib/lochs", 0755);
    mkdir(IDS_DIR, 0700);
    snprintf(path, sizeof(path), IDS_DIR "/%s", key);
    return write_long(path, (long)state);
}

void lochs_image_ids_forget(const char *image_path) {
    char key[300];
    image_key(image_path, key, sizeof(key));
    lochs_tree_ids_forget(key);
}

/*
 * Lochs storage holds files owned by container ids, on disk host ids 0..
 * (setuid root among them) and container-made files. Host users must not
 * reach them: the directories are root-only. Containers never walk these
 * paths (each is pivoted into its own root, set up from inside it).
 */
void lochs_storage_lockdown(void) {
    static const char *dirs[] = { "/var/lib/lochs/images", "/var/lib/lochs/containers",
                                  "/var/lib/lochs/volumes", IDS_DIR, IDMNT_DIR };
    mkdir("/var/lib/lochs", 0755);
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        mkdir(dirs[i], 0700);
        chmod(dirs[i], 0700);
    }
}

/* --- idmapped layers ------------------------------------------------ */

#ifndef SYS_open_tree
#define SYS_open_tree 428
#endif
#ifndef SYS_move_mount
#define SYS_move_mount 429
#endif
#ifndef SYS_mount_setattr
#define SYS_mount_setattr 442
#endif
#define L_OPEN_TREE_CLONE 1
#define L_OPEN_TREE_CLOEXEC O_CLOEXEC
#define L_MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#define L_MOUNT_ATTR_IDMAP 0x00100000
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
struct l_mount_attr { unsigned long long attr_set, attr_clr, propagation, userns_fd; };

/* A user namespace mapping ids uid_first.. and gid_first.. (count of
 * each) to host ids host.., for idmapped mounts. Its helper process is gone
 * on return; the fd keeps it alive. */
static int userns_map(uid_t uid_first, gid_t gid_first, uid_t host, unsigned count) {
    int p[2];
    if (pipe(p) < 0) return -1;
    pid_t c = fork();
    if (c < 0) { close(p[0]); close(p[1]); return -1; }
    if (c == 0) {
        close(p[0]);
        char ok = unshare(CLONE_NEWUSER) == 0;
        ssize_t w = write(p[1], &ok, 1);
        (void)w;
        pause();
        _exit(0);
    }
    close(p[1]);
    char ok = 0;
    if (read(p[0], &ok, 1) != 1) ok = 0;
    close(p[0]);
    int fd = -1;
    if (ok) {
        char path[64], map[2][64];
        snprintf(map[0], sizeof(map[0]), "%u %u %u\n", (unsigned)uid_first, (unsigned)host, count);
        snprintf(map[1], sizeof(map[1]), "%u %u %u\n", (unsigned)gid_first, (unsigned)host, count);
        const char *files[2] = { "uid_map", "gid_map" };
        int good = 1;
        for (int i = 0; i < 2 && good; i++) {
            const char *m = map[i];
            snprintf(path, sizeof(path), "/proc/%d/%s", (int)c, files[i]);
            int mfd = open(path, O_WRONLY | O_CLOEXEC);
            if (mfd < 0 || write(mfd, m, strlen(m)) != (ssize_t)strlen(m)) good = 0;
            if (mfd >= 0) close(mfd);
        }
        snprintf(path, sizeof(path), "/proc/%d/ns/user", (int)c);
        if (good) fd = open(path, O_RDONLY | O_CLOEXEC);
    }
    kill(c, SIGKILL);
    waitpid(c, NULL, 0);
    return fd;
}

static int userns_for(uid_t base) {
    return userns_map(0, 0, base, LOCHS_ID_COUNT);
}

/* Attach an idmapped copy of src at dst, with MOUNT_ATTR_* attrs too */
static int idmap_mount_attr(const char *src, const char *dst, int ufd, unsigned long long attrs) {
    int t = (int)syscall(SYS_open_tree, AT_FDCWD, src, L_OPEN_TREE_CLONE | L_OPEN_TREE_CLOEXEC);
    if (t < 0) return -1;
    struct l_mount_attr a = { L_MOUNT_ATTR_IDMAP | attrs, 0, 0, (unsigned long long)ufd };
    int r = (int)syscall(SYS_mount_setattr, t, "", AT_EMPTY_PATH, &a, sizeof(a));
    if (r == 0) {
        mkdir(dst, 0700);
        r = (int)syscall(SYS_move_mount, t, "", AT_FDCWD, dst, L_MOVE_MOUNT_F_EMPTY_PATH);
    }
    int e = errno;
    close(t);
    errno = e;
    return r;
}

static int idmap_mount(const char *src, const char *dst, int ufd) {
    return idmap_mount_attr(src, dst, ufd, 0);
}

/*
 * Volumes: bind src at dst idmapped so that on-disk ids uid_first../
 * gid_first.. (count) belong to the container's ids host.. Returns 0, or
 * -1 with errno (the filesystem may not support idmapped mounts).
 */
int lochs_idmap_bind(const char *src, const char *dst, uid_t uid_first, gid_t gid_first,
                     uid_t host, unsigned count, int readonly, int nosuid) {
    int ufd = userns_map(uid_first, gid_first, host, count);
    if (ufd < 0) return -1;
    unsigned long long attrs = 0;
    if (readonly) attrs |= 0x1;              /* MOUNT_ATTR_RDONLY */
    if (nosuid) attrs |= 0x2 | 0x4;          /* MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV */
    int r = idmap_mount_attr(src, dst, ufd, attrs);
    int e = errno;
    close(ufd);
    errno = e;
    return r;
}

static int kernel_at_least(int maj, int min) {
    FILE *f = fopen("/proc/sys/kernel/osrelease", "r");
    if (!f) return 0;
    int a = 0, b = 0;
    int n = fscanf(f, "%d.%d", &a, &b);
    fclose(f);
    return n == 2 && (a > maj || (a == maj && b >= min));
}

int lochs_idmap_supported(void) {
    static int cached = -1;
    if (cached >= 0) return cached;
    cached = 0;
    /* LOCHS_NO_IDMAP=1 forces the shared-range fallback, for testing it.
     * Only with no other container running: it shifts the shared image
     * files, which idmapped containers still use. */
    const char *no = getenv("LOCHS_NO_IDMAP");
    if (no && no[0] == '1') return 0;
    /* Overlay over idmapped layers needs 5.19 */
    if (!kernel_at_least(5, 19)) return 0;
    int ufd = userns_for(LOCHS_ID_BASE);
    if (ufd < 0) return 0;
    mkdir("/var/lib/lochs", 0755);
    int t = (int)syscall(SYS_open_tree, AT_FDCWD, "/var/lib/lochs", L_OPEN_TREE_CLONE | L_OPEN_TREE_CLOEXEC);
    if (t >= 0) {
        struct l_mount_attr a = { L_MOUNT_ATTR_IDMAP, 0, 0, (unsigned long long)ufd };
        cached = syscall(SYS_mount_setattr, t, "", AT_EMPTY_PATH, &a, sizeof(a)) == 0;
        close(t);
    }
    close(ufd);
    return cached;
}

static void idmnt_paths(const char *name, char *dir, char *lower, char *rw, size_t sz) {
    snprintf(dir, sz, IDMNT_DIR "/%s", name);
    snprintf(lower, sz, IDMNT_DIR "/%s/lower", name);
    snprintf(rw, sz, IDMNT_DIR "/%s/rw", name);
}

void lochs_idmap_unmount(const char *name) {
    char dir[512], lower[512], rw[512];
    idmnt_paths(name, dir, lower, rw, sizeof(dir));
    umount2(lower, MNT_DETACH);
    umount2(rw, MNT_DETACH);
    rmdir(lower);
    rmdir(rw);
    rmdir(dir);
}

/*
 * Mount the container's overlay at merged over idmapped views of the image
 * and of the container directory (which holds diff/ and work/). The mount
 * is made with container root's filesystem ids: overlayfs does its own
 * work (work dir, copy-up) with the mounter's, which must have a container
 * id. Returns 0, or -1 with nothing left mounted.
 */
int lochs_idmap_mount_overlay(const char *name, uid_t base, const char *image,
                              const char *cdir, const char *merged) {
    char dir[512], lower[512], rw[512];
    idmnt_paths(name, dir, lower, rw, sizeof(dir));
    lochs_idmap_unmount(name);   /* left over from a crash */
    mkdir(IDMNT_DIR, 0700);
    mkdir(dir, 0700);
    int ufd = userns_for(base);
    if (ufd < 0) return -1;
    int r = idmap_mount(image, lower, ufd);
    if (r == 0) r = idmap_mount(cdir, rw, ufd);
    close(ufd);
    if (r < 0) {
        fprintf(stderr, "Error: idmapped mount failed: %s\n", strerror(errno));
        lochs_idmap_unmount(name);
        return -1;
    }
    char opts[2048];
    snprintf(opts, sizeof(opts), "lowerdir=%s,upperdir=%s/diff,workdir=%s/work", lower, rw, rw);
    lochs_croot_set(base);
    fflush(stdout);
    fflush(stderr);
    pid_t c = fork();
    if (c == 0) {
        lochs_croot_enter();
        _exit(mount("overlay", merged, "overlay", 0, opts) == 0 ? 0 : errno);
    }
    int st = 0;
    waitpid(c, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        fprintf(stderr, "Error: overlay mount failed: %s\n",
                WIFEXITED(st) ? strerror(WEXITSTATUS(st)) : "helper died");
        lochs_idmap_unmount(name);
        return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------------
 * Network: each container gets its own network namespace (owned by the
 * host, so `ip netns` and port forwarding work), a veth pair to the host
 * with a /30 from 10.201.0.0/16, outbound NAT, and low ports allowed for
 * container root inside that namespace only.
 * ------------------------------------------------------------------- */

static int run(const char *const argv[]) {
    return lochs_run(argv, LOCHS_RUN_QUIET);
}

static void net_file(const char *name, char *out, size_t sz) {
    snprintf(out, sz, NS_DIR "/%s.net", name);
}

/* Index of the container's /30, from its .net file; 0 if none */
static int net_index(const char *name) {
    char path[512];
    net_file(name, path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int idx = 0;
    if (fscanf(f, "%d", &idx) != 1) idx = 0;
    fclose(f);
    return idx;
}

/* Lowest index no other container uses */
static int free_index(void) {
    char used[256] = {0};
    DIR *d = opendir(NS_DIR);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            size_t n = strlen(e->d_name);
            if (n < 5 || strcmp(e->d_name + n - 4, ".net") != 0) continue;
            char nm[256];
            snprintf(nm, sizeof(nm), "%.*s", (int)(n - 4), e->d_name);
            int i = net_index(nm);
            if (i > 0 && i < 256) used[i] = 1;
        }
        closedir(d);
    }
    for (int i = 1; i < 255; i++) if (!used[i]) return i;
    return -1;
}

const char *lochs_ns_ip(const char *name) {
    static char ip[32];
    int i = net_index(name);
    if (i <= 0) return NULL;
    /* /30 block i: .4i+1 host side, .4i+2 container */
    snprintf(ip, sizeof(ip), "10.201.%d.%d", (i * 4) / 256, (i * 4) % 256 + 2);
    return ip;
}

int lochs_ns_net_up(const char *name, char *netns, size_t netns_sz) {
    int idx = net_index(name);
    if (idx <= 0) idx = free_index();
    if (idx <= 0) return -1;

    char ns[64], hv[16], cv[16], hip[40], cip[40], gw[32];
    snprintf(ns, sizeof(ns), "lochs-%s", name);
    unsigned h = 5381;
    for (const char *p = name; *p; p++) h = h * 33 + (unsigned char)*p;
    snprintf(hv, sizeof(hv), "lh%06x", h & 0xffffff);
    snprintf(cv, sizeof(cv), "lc%06x", h & 0xffffff);
    int b3 = (idx * 4) / 256, b4 = (idx * 4) % 256;
    snprintf(hip, sizeof(hip), "10.201.%d.%d/30", b3, b4 + 1);
    snprintf(cip, sizeof(cip), "10.201.%d.%d/30", b3, b4 + 2);
    snprintf(gw, sizeof(gw), "10.201.%d.%d", b3, b4 + 1);

    /* Fresh namespace and pair (a stale one from a crash goes first) */
    { const char *a[] = { "ip", "netns", "delete", ns, NULL }; run(a); }
    { const char *a[] = { "ip", "link", "delete", hv, NULL }; run(a); }
    { const char *a[] = { "ip", "netns", "add", ns, NULL }; if (run(a) != 0) return -1; }
    { const char *a[] = { "ip", "link", "add", hv, "type", "veth", "peer", "name", cv, NULL }; if (run(a) != 0) return -1; }
    { const char *a[] = { "ip", "link", "set", cv, "netns", ns, NULL }; if (run(a) != 0) return -1; }
    { const char *a[] = { "ip", "addr", "add", hip, "dev", hv, NULL }; run(a); }
    { const char *a[] = { "ip", "link", "set", hv, "up", NULL }; run(a); }
    { const char *a[] = { "ip", "-n", ns, "link", "set", "lo", "up", NULL }; run(a); }
    { const char *a[] = { "ip", "-n", ns, "addr", "add", cip, "dev", cv, NULL }; run(a); }
    { const char *a[] = { "ip", "-n", ns, "link", "set", cv, "up", NULL }; run(a); }
    { const char *a[] = { "ip", "-n", ns, "route", "add", "default", "via", gw, NULL }; run(a); }
    /* Container root may bind ports below 1024 - in this namespace only */
    { const char *a[] = { "ip", "netns", "exec", ns, "sysctl", "-q", "-w",
                          "net.ipv4.ip_unprivileged_port_start=0", NULL }; run(a); }
    /* Outbound traffic */
    {
        const char *c[] = { "iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "10.201.0.0/16",
                            "!", "-d", "10.201.0.0/16", "-j", "MASQUERADE", NULL };
        if (run(c) != 0) {
            const char *a[] = { "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.201.0.0/16",
                                "!", "-d", "10.201.0.0/16", "-j", "MASQUERADE", NULL };
            run(a);
        }
    }

    char path[512];
    net_file(name, path, sizeof(path));
    FILE *f = fopen(path, "w");
    if (f) { fprintf(f, "%d %s %s\n", idx, hv, ns); fclose(f); }
    snprintf(netns, netns_sz, "%s", ns);
    return 0;
}

void lochs_ns_net_down(const char *name) {
    char ns[64], path[512];
    snprintf(ns, sizeof(ns), "lochs-%s", name);
    /* Deleting the namespace destroys the veth pair */
    { const char *a[] = { "ip", "netns", "delete", ns, NULL }; run(a); }
    net_file(name, path, sizeof(path));
    unlink(path);
}
