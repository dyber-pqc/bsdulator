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
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <ftw.h>

#include "bsdulator/lochs_exec.h"

#include "bsdulator/lochs_ns.h"

#define NS_DIR "/var/lib/lochs/ns"
#define HOLDER_NAME "lochs-init"

static void pid_file(const char *name, char *out, size_t sz) {
    snprintf(out, sz, NS_DIR "/%s.pid", name);
}

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

/*
 * Make root the mount namespace's "/" and detach the host's filesystem
 * from the namespace, so nothing outside the container exists there (with
 * chroot alone it stays reachable). Returns 0 on success,
 * 1 when pivot_root is unavailable and the namespace is unchanged, -1 when
 * it failed half-way and the namespace must not be used.
 */
static int pivot_into(const char *root) {
    if (!root || !root[0]) return 1;
    /* pivot_root needs a mount point this namespace created itself */
    if (mount(root, root, NULL, MS_BIND | MS_REC, NULL) < 0) return 1;
    if (chdir(root) < 0) return 1;
    /* Old root is stacked on "." and then detached: no directory needed */
    if (syscall(SYS_pivot_root, ".", ".") < 0) {
        if (chdir("/") < 0) return -1;
        return 1;
    }
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
        char userns = unshare(CLONE_NEWUSER) == 0;
        ssize_t w = write(up[1], &userns, 1);
        char ok = 0;
        if (read(go[0], &ok, 1) != 1) ok = 0;
        pid_t init = -1;
        if (userns && !ok) _exit(1);
        if (unshare(CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID) == 0) {
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
                    if (root && root[0]) private_proc(root);
                    int pv = pivot_into(root);
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
        snprintf(map, sizeof(map), "0 %d %d\n", LOCHS_ID_BASE, LOCHS_ID_COUNT);
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
 * File ownership in the container's id range
 *
 * Container uid/gid N is host LOCHS_ID_BASE + N. Image and container files
 * are shifted once into that range (Docker's userns-remap does the same).
 * chown clears setuid/setgid bits, so the mode is restored after it.
 * ------------------------------------------------------------------- */

static int shift_one(const char *path, const struct stat *st, int flag, struct FTW *ftw) {
    (void)flag; (void)ftw;
    /* Never device nodes: /dev entries are bind mounts of the host's */
    if (S_ISCHR(st->st_mode) || S_ISBLK(st->st_mode)) return 0;
    uid_t u = st->st_uid;
    gid_t g = st->st_gid;
    if (u >= (uid_t)LOCHS_ID_COUNT && g >= (gid_t)LOCHS_ID_COUNT) return 0;  /* already shifted */
    uid_t nu = u < (uid_t)LOCHS_ID_COUNT ? u + LOCHS_ID_BASE : u;
    gid_t ng = g < (gid_t)LOCHS_ID_COUNT ? g + LOCHS_ID_BASE : g;
    if (lchown(path, nu, ng) < 0) return 0;  /* keep going */
    if (!S_ISLNK(st->st_mode) && (st->st_mode & (S_ISUID | S_ISGID)))
        chmod(path, st->st_mode & 07777);
    return 0;
}

int lochs_idshift_tree(const char *dir, int use_marker) {
    char marker[1024];
    snprintf(marker, sizeof(marker), "%s/.lochs-idmap-%d", dir, LOCHS_ID_BASE);
    if (use_marker && access(marker, F_OK) == 0) return 0;
    struct stat st;
    if (lstat(dir, &st) < 0) return -1;
    if (nftw(dir, shift_one, 64, FTW_PHYS | FTW_MOUNT) < 0) return -1;
    if (use_marker) {
        int fd = open(marker, O_WRONLY | O_CREAT | O_CLOEXEC, 0444);
        if (fd >= 0) {
            if (fchown(fd, LOCHS_ID_BASE, LOCHS_ID_BASE) < 0) { /* not fatal */ }
            close(fd);
        }
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
