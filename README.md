<div align="center">

<img src="lochs-logo.png" alt="Lochs" width="280">

# Lochs

**FreeBSD containers, everywhere.**

Run FreeBSD jails on Linux with Docker-like simplicity.

[![License](https://img.shields.io/badge/license-Source%20Available-blue?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20WSL2-38bdf8?style=flat-square)]()
[![FreeBSD](https://img.shields.io/badge/FreeBSD-15.0-AB2B28?style=flat-square&logo=freebsd&logoColor=white)]()
[![Website](https://img.shields.io/badge/lochs.dev-visit-red?style=flat-square)](https://lochs.dev)
[![Discord](https://img.shields.io/badge/Discord-join-5865F2?style=flat-square&logo=discord&logoColor=white)](https://discord.gg/km3VGfUW)

</div>

---

## Install

```bash
curl -fsSL https://lochs.dev/install.sh | sudo bash
```

This installs Lochs, the bsdulator engine, and fetches the FreeBSD 15.0-RELEASE base system.

## Quick Start

```bash
# Pull the base image, then create and start a jail
$ lochs pull freebsd:15
$ lochs create webserver -i freebsd:15 --vnet -p 8080:80
$ lochs start webserver

# Execute into the jail
$ lochs exec webserver /bin/sh
root@webserver:/ # pkg install nginx

# List running jails
$ lochs ps
JID  NAME        IP           STATUS
1    webserver   10.0.0.10    running

# Stop and remove
$ lochs stop webserver
$ lochs rm webserver
```

## What Is This?

**Lochs** (pronounced "locks", like the Scottish lakes) is a Docker-like container management CLI for FreeBSD jails on Linux. It provides familiar commands (`create`, `start`, `exec`, `ps`, `stop`) and brings FreeBSD's jail isolation system — the original container technology (2000, 13 years before Docker) — to any Linux host.

Under the hood, Lochs uses the **bsdulator** engine, a FreeBSD binary compatibility layer that intercepts system calls via ptrace and translates them to Linux equivalents in real time, with no VM. Think Wine for FreeBSD, or the inverse of FreeBSD's Linuxulator. ptrace stops on every system call, so expect noticeably slower syscall-heavy workloads than native FreeBSD.

> **Status: alpha.** FreeBSD base utilities and `/bin/sh` work. Multi-threaded programs and software that relies on `kqueue` (including nginx's default configuration) do not work reliably yet; see [Known limitations](#known-limitations).

## Features

### Engine (bsdulator)
- **224 FreeBSD syscalls mapped**: 175 translated directly, 49 emulated, several of them partially ([full matrix](docs/syscalls.md))
- **Static and dynamic** FreeBSD binary support
- **FreeBSD jail syscalls** — `jail`, `jail_get`, `jail_set`, `jail_attach`, `jail_remove`
- **VNET** — full network stack isolation via Linux network namespaces
- **Bridge networking** — automatic inter-jail and host-to-jail communication
- **ABI translation** — flags, structures, errno, signals, sockaddr
- **TLS emulation** — full Thread Local Storage for FreeBSD binaries
- **Path translation** — FreeBSD system paths redirected to local root

### Lochs CLI
- **Docker-like commands** — `pull`, `create`, `start`, `exec`, `stop`, `rm`, `ps`
- **Lochfile** — Dockerfile equivalent for building custom jail images
- **lochs.yml** — Compose files for multi-service deployments
- **Image registry** — Pull from FreeBSD mirrors or custom registries
- **Port forwarding** — `-p 8080:80` maps host ports to jail ports
- **Network management** — `lochs network create/rm/ls`

### Network Architecture

```
Host System
+---------------------------------------------------------+
|                                                         |
|   bsdjail0 (bridge)                                     |
|   10.0.0.1/24                                           |
|      |                                                  |
|      +-- veth0_j1 <------> eth0 (jail1 netns)           |
|      |                      10.0.0.10/24                |
|      |                                                  |
|      +-- veth0_j2 <------> eth0 (jail2 netns)           |
|                             10.0.0.20/24                |
|                                                         |
+---------------------------------------------------------+
```

## Building from Source

```bash
git clone https://github.com/dyber-pqc/bsdulator.git
cd bsdulator

# Install dependencies (Ubuntu/Debian)
sudo apt-get install -y build-essential iproute2 wget

# Build
make

# Download FreeBSD base system (~180 MB)
./scripts/setup_freebsd_root.sh

# Verify
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/echo "Hello from FreeBSD!"
```

See [docs/INSTALL.md](docs/INSTALL.md) for platform-specific instructions (Fedora, Arch, Alpine, WSL2, Docker).

## Engine Direct Usage

For low-level access using the bsdulator engine directly:

```bash
# Static binaries
./bsdulator ./freebsd-root/rescue/echo "Hello"
./bsdulator ./freebsd-root/rescue/ls /

# Dynamic binaries (via FreeBSD dynamic linker)
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/sh

# Create a jail directly
sudo ./bsdulator ./freebsd-root/libexec/ld-elf.so.1 \
    ./freebsd-root/usr/sbin/jail -c name=test path=./freebsd-root ip4.addr=10.0.0.10 vnet persist

# List jails
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jls jid name ip4.addr path

# Execute in jail
sudo ./bsdulator ./freebsd-root/libexec/ld-elf.so.1 \
    ./freebsd-root/usr/sbin/jexec 1 /bin/sh -c "whoami; pwd; ls /"

# Remove jail
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jail -r 1
```

```
Usage: bsdulator [options] <freebsd-binary> [args...]

Options:
  -h, --help           Show help message
  -V, --version        Show version
  -v, --verbose        Increase verbosity (can be repeated)
  -q, --quiet          Quiet mode (errors only)
  -r, --root <path>    FreeBSD root filesystem path
  -s, --stats          Print syscall statistics on exit
  -t, --trace          Trace all syscalls (very verbose)

Environment:
  BSDULATOR_ROOT       FreeBSD root filesystem (default: ./freebsd-root)
  BSDULATOR_DEBUG      Debug level (0-4)
```

## Syscall Support

| Category | Examples | Status |
|----------|----------|--------|
| Process | fork, exec, wait, exit, kill, getpid | Full |
| File I/O | open, read, write, close, stat, fstat | Full |
| Memory | mmap, mprotect, munmap, brk | Full |
| Network | socket, bind, connect, send, recv | Full |
| Time | gettimeofday, clock_gettime, nanosleep | Full |
| Signals | sigaction, sigprocmask, sigfastblock | Full |
| IPC | semget, msgget, shmget | Full |
| *at syscalls | openat, fstatat, unlinkat | Full |
| Threading | thr_self, thr_exit, thr_kill, _umtx_op | Partial: `thr_new` missing, `_umtx_op` returns without waiting or locking |
| sysctl | __sysctl, __sysctlbyname | Emulated |
| Jail | jail, jail_get, jail_set, jail_attach, jail_remove | Full |
| kqueue | kqueue, kevent | Not working: the backing epoll fd is created in the tracer, not the jailed process |
| Capsicum | cap_enter, cap_getmode | Stub |

224 syscalls mapped (175 translated, 49 emulated, 12 more explicitly unsupported). See [docs/syscalls.md](docs/syscalls.md) for the complete matrix.

## Known Limitations

- **Isolation: partial, not reviewed.** Containers started by `lochs` get their own user, PID, mount, UTS (hostname), IPC and network namespaces, run with Docker's default capability set, `no_new_privs` and a seccomp filter (no mounting, modules, kexec, ptrace, io_uring, BPF, keyrings, clock setting or new namespaces; non-x86-64 syscalls kill the process). Their mount namespace is switched to the container root with `pivot_root`, so the host's filesystem is not in it at all, and `/proc` is not mounted inside, as in a FreeBSD jail. Each container has its own range of 65536 host uids/gids (the first container 165536+N, the next 231072+N, ...), so container root is not root on the host and is nobody to other containers. Image and container layers keep container ids on disk and are mounted idmapped into the container's range (Linux 5.19+); on older kernels all containers share 100000+N and the layers are chown-shifted into it. The tracer (bsdulator) does not stay host root: it moves into the container's namespaces and runs as container root, with Docker's capabilities only permitted plus `CAP_SYS_PTRACE` (all inside the container's user namespace), `no_new_privs`, not dumpable and its own seccomp filter, so a fault in it gives no more than container root; `lochs stop` no longer runs any container program as host root. `lochs build` RUN steps run the same way, in a temporary container of their own (id range, namespaces, network, the tracer inside), and COPY gives files to container root. Not yet: an outside review. Named volumes (`-v name:/path`) are mounted idmapped like the layers, so containers sharing one each see it as their own. A host directory (`-v /dir:/path`) is mapped to its owner: that host user is container root there (nosuid, nodev), so the container gets no more than the owner's rights; a directory owned by host root, or on a filesystem without idmapped mounts, keeps host ids and looks like `nobody` inside. Lochs storage under `/var/lib/lochs` is root-only (0700). Only run software you trust until the isolation work in the Lochs Build Plan is done.
- **Threads: libthr works.** `thr_new` is a Linux thread (`clone`), and `_umtx_op` maps FreeBSD's mutexes, condition variables, read/write locks, semaphores and waits onto futexes on the same memory, so pthreads behave as on FreeBSD (tested: contended mutexes, condvars, rwlocks, semaphores, barriers, TLS, `pthread_kill`, 64 threads; `xz -T`, `zstd -T`, and FreeBSD's own `cc`/`ld.lld`). Signal handlers are per process and masks per thread. Not yet: process-shared sync objects (`UMTX_OP_SHM`), robust-mutex recovery, priority-protect ceilings, `thr_suspend`/`thr_wake`. Programs with their own runtime (Go) are untested.
- **kqueue: `EVFILT_READ`, `EVFILT_WRITE` and `EVFILT_USER` only.** A kqueue is an epoll instance in the traced process, and `kevent()` runs as `epoll_ctl`/`epoll_wait` in that process, so it blocks only the caller. FreeBSD's nginx package (kqueue only) starts, serves, reloads on `HUP` and stops on `QUIT`. Not yet: `EVFILT_TIMER`, `EVFILT_SIGNAL`, `EVFILT_VNODE`, `EVFILT_PROC`; the `data` byte count of read/write events is an estimate.
- **Signals: mostly FreeBSD semantics.** The tracer keeps each process's handlers, mask, pending set and alternate stack, and runs handlers with a FreeBSD signal frame (`siginfo_t`, `ucontext_t`, `sigreturn`), honoring `SA_RESTART`, `SA_SIGINFO`, `SA_NODEFER`, `SA_RESETHAND` and `sigfastblock`. Not yet: `sigqueue` values, `SIGCHLD` set to `SIG_IGN` does not auto-reap children, job-control stops are ignored, and AVX register state is not saved across a handler.
- **No Capsicum.** Programs that use casper fail, for example `wc: Unable to initialize casper`.
- **Outside a jail, some paths are the host's.** Without a jail the FreeBSD root is only reached by translating system paths (`/bin/`, `/lib/`, `/etc/`, ...), so `ls /` lists the host's root. Inside a jail everything is the container's.
- **Speed.** ptrace adds two context switches per system call.
- **Dashboard.** `lochs dashboard` listens on 127.0.0.1 by default and requires a bearer token; `--listen 0.0.0.0` exposes it, and anyone with the token can run commands in containers.

These are the first items on the engine roadmap.

## System Requirements

| Requirement | Details |
|-------------|---------|
| **OS** | Linux (kernel 3.8+) |
| **Architecture** | x86_64 only |
| **Privileges** | Root/sudo for jail and networking features |
| **Packages** | `iproute2` (for networking) |
| **Tested On** | Ubuntu 24.04, WSL2, Debian 12, Fedora 39 |

## Project Structure

```
bsdulator/
+-- src/
|   +-- main.c                 # Entry point and CLI
|   +-- interceptor/           # ptrace syscall interception, TLS setup
|   +-- syscall/               # FreeBSD -> Linux syscall mapping
|   +-- loader/                # FreeBSD ELF detection
|   +-- abi/                   # Flags/struct translation
|   +-- runtime/               # FreeBSD runtime environment, sysctl
|   +-- jail/                  # Jail syscalls, VNET, namespaces
|   +-- lochs/                 # Lochs CLI implementation
+-- include/bsdulator/         # Headers
+-- scripts/                   # Setup and compatibility scripts
+-- examples/                  # Lochfile, lochs.yml, test files
+-- docs/                      # Documentation
+-- Makefile
+-- Dockerfile
```

## Roadmap

### Completed
- [x] 224 FreeBSD syscalls mapped (see Known Limitations for partial ones)
- [x] Static and dynamic binary support
- [x] FreeBSD shell with pipes and redirects
- [x] Full jail lifecycle (create, list, exec, remove)
- [x] VNET with bridge networking
- [x] Lochs CLI with Lochfile and compose support
- [x] Web dashboard (`lochs dashboard`)

### In Progress
- [ ] NAT/masquerade for external jail connectivity
- [ ] Resource limit enforcement (CPU, memory via rctl)
- [ ] Lochs image registry
- [ ] `lochs.dev/install.sh` one-line installer

### Planned
- [ ] Threads (`thr_new`, real `_umtx_op`) and working kqueue
- [ ] PID, mount and user namespaces plus seccomp for real isolation
- [ ] macOS support via Hypervisor.framework VM
- [ ] Windows native support via Hyper-V
- [ ] GPU passthrough for ML workloads

## Documentation

| Document | Description |
|----------|-------------|
| [Quick Start](docs/quickstart.md) | 5-minute getting started guide |
| [Installation](docs/INSTALL.md) | Platform-specific install instructions |
| [Syscall Matrix](docs/syscalls.md) | Complete syscall support reference |
| [Architecture](docs/architecture.md) | How Lochs works under the hood |
| [Lochs Guide](LOCHS.md) | Full CLI documentation |
| [Contributing](CONTRIBUTING.md) | How to contribute |
| [Changelog](CHANGELOG.md) | Release history |

## Community

- **Website**: [lochs.dev](https://lochs.dev)
- **Discord**: [Join the server](https://discord.gg/km3VGfUW)
- **Community Hub**: [dyber.org/community](https://www.dyber.org/community)
- **GitHub Discussions**: [Ask questions](https://github.com/dyber-pqc/bsdulator/discussions)
- **Commercial Support**: support@dyber.org

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Priority areas:
1. NAT/masquerade for external jail connectivity
2. Resource limit enforcement
3. Additional syscall translations
4. Test coverage

## License

Source Available License - See [LICENSE](LICENSE) for details.

Source code is available for viewing, modification, and non-commercial use. Commercial use requires a separate license. Contact support@dyber.org.

## Acknowledgments

- FreeBSD Project for jail architecture and documentation
- Linux kernel developers for ptrace and namespace infrastructure
- The Wine project for inspiration on compatibility layers

---

<div align="center">

Built by [Dyber](https://github.com/dyber-pqc) | [lochs.dev](https://lochs.dev)

</div>
