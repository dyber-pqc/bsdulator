# Changelog

All notable changes to BSDulator and Lochs will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.3] - 2026-02-20

### Added
- **Full network namespace isolation** for containers
  - Each container gets its own Linux network namespace (`lochs_<name>`)
  - Isolated eth0 interface with assigned IP from subnet pool
  - veth pair connects container netns to host bridge
  - Gateway connectivity with proper routing
- **BSDulator `--netns` flag** for network namespace entry
  - Child process enters netns after ptrace setup, before execve
  - Avoids ptrace conflicts that caused segfaults with `ip netns exec`
- Network namespace cleanup on container stop/remove

### Fixed
- Segfault when running BSDulator inside `ip netns exec` wrapper
- veth pair creation order (move to netns before bridge attachment)
- eth0 interface configuration inside network namespace

### Technical Details
- `interceptor_spawn()` now calls `setns()` in child process after `PTRACE_TRACEME`
- Added `bsdulator_set_netns()` / `bsdulator_get_netns()` API
- `lochs_jail_t` structure extended with `netns[32]` field
- `lochs_cmd_start()` and `lochs_cmd_exec()` pass `--netns` to bsdulator

## [0.3.2] - 2026-02-20

### Added
- **Container networking** with `lochs network create/rm/ls`
  - Linux bridge creation per network (`lochs_<name>`)
  - Automatic IP assignment from subnet pool (172.20.0.0/24, etc.)
  - `--network` flag for `lochs create`
  - veth pair creation for container connectivity
  - `/etc/hosts` injection for container name resolution
  - NAT via iptables MASQUERADE for external access
  - Network teardown on container stop
- **RUN directive** in Lochfile
  - Execute FreeBSD commands during image build via BSDulator
  - Direct binary execution for simple commands (no shell overhead)
  - Shell fallback for complex commands (pipes, redirects, etc.)
  - Proper path resolution in build directory

### Files Changed
- `src/lochs/lochs_network.c` (new)
- `src/lochs/lochfile_parser.c` (RUN implementation)
- `src/lochs/lochs_commands.c` (`--network` flag)
- `include/bsdulator/lochs.h` (network types)

## [0.3.1] - 2026-02-19

### Added
- **Volume mounts** with `-v /host:/container[:ro]`
  - Bind mount support with read-only option
  - Auto-unmount on container stop
- **Environment variables** with `-e KEY=value`
  - Written to `/.lochs_env` in container
- **Container logs** with `lochs logs [-f] [-n N] <container>`
  - Follow mode (`-f`) for streaming
  - Tail option (`-n`) for last N lines
  - Logs captured via tee to `/var/lib/lochs/logs/`

## [0.3.0] - 2026-02-18

### Added
- **Lochfile build system**
  - Directives: `FROM`, `COPY`, `RUN`, `ENV`, `LABEL`, `EXPOSE`, `CMD`, `WORKDIR`
  - `lochs build -f Lochfile -t name:tag .`
  - Image registration for built images
- **lochs.yml compose** for multi-container orchestration
  - Commands: `up`, `down`, `ps`, `exec`, `logs`
  - YAML parser (no external dependencies)
  - Dependency resolution with `depends_on`
  - Network and port forwarding support
- **Port forwarding** with `-p host:container`
  - TCP/UDP support via socat
  - Multiple port mappings per container

### Fixed
- JID tracking sync between Lochs and BSDulator state files
- Structure alignment for jail state file reading (simplified vs actual structs)
- State file persistence in compose (parent process reloads after child saves)

## [0.2.0] - 2026-01-15

### Added
- Basic jail lifecycle: `create`, `start`, `stop`, `rm`
- Image management: `pull`, `images`, `search`, `rmi`
- Container execution: `exec` into running containers
- Static IP assignment with `--ip` flag
- VNET support via Linux network namespaces
- `lochs ps` container listing with JID sync
- State persistence in `/var/lib/lochs/jails.dat`

### BSDulator Features
- 200+ FreeBSD syscall translations
- FreeBSD TLS (Thread Local Storage) setup
- Jail syscall emulation (`jail`, `jail_get`, `jail_set`, `jail_attach`, `jail_remove`)
- Path translation for FreeBSD binaries
- Multi-process support (fork, clone, vfork)
- Signal translation
- Structure translation (stat, dirent, statfs)

## [0.1.0] - 2026-01-01

### Added
- Initial BSDulator implementation
- ptrace-based syscall interception
- Basic syscall translation table
- FreeBSD ELF binary detection
- Simple syscall logging

---

## Version History Summary

| Version | Date | Highlights |
|---------|------|------------|
| 0.3.3 | 2026-02-20 | Network namespace isolation |
| 0.3.2 | 2026-02-20 | Container networking, RUN directive |
| 0.3.1 | 2026-02-19 | Volumes, env vars, logs |
| 0.3.0 | 2026-02-18 | Lochfile build, compose, port forwarding |
| 0.2.0 | 2026-01-15 | Jail lifecycle, image pull, exec |
| 0.1.0 | 2026-01-01 | Initial release |
