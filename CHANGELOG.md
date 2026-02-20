# Changelog

All notable changes to BSDulator and Lochs will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.6] - 2026-02-20

### Added
- **Auto-start CMD support** for containers
  - CMD from Lochfile is stored in `.lochs_image.conf` during build
  - CMD is loaded into jail structure when creating container
  - CMD automatically executed in background when container starts
- **DNS configuration** for containers
  - `/etc/resolv.conf` copied from host into container at network setup
  - Fallback to Google DNS (8.8.8.8, 8.8.4.4) if host resolv.conf unavailable
- **External network access (NAT)** now fully functional
  - iptables MASQUERADE rules applied when creating networks
  - Containers can reach external IPs (verified: 8.8.8.8, 1.1.1.1)
  - Requires `iptables` package and `net.ipv4.ip_forward=1`

### Fixed
- Image metadata (CMD, ENTRYPOINT, WORKDIR) now properly passed from build to container

### Technical Details
- `load_image_metadata()` function reads `.lochs_image.conf` at container creation
- `lochs_jail_t` extended with `cmd[1024]`, `entrypoint[1024]`, `workdir[256]` fields
- Network setup creates `/etc/resolv.conf` alongside `/etc/hosts`
- NAT rules: `iptables -t nat -A POSTROUTING -s <subnet> -j MASQUERADE`

### Known Limitations
- DNS hostname resolution (e.g., `ping google.com`) requires getaddrinfo syscall emulation (not yet implemented)
- External access works with IP addresses only

## [0.3.5] - 2026-02-20

### Added
- **Socket option translation** for FreeBSD→Linux setsockopt/getsockopt
  - SO_TIMESTAMP (0x400 → 29) - enables packet timestamps for ping
  - SO_SNDBUF, SO_RCVBUF, SO_SNDLOWAT, SO_RCVLOWAT translation
  - SO_SNDTIMEO, SO_RCVTIMEO, SO_ERROR, SO_TYPE translation
  - SO_DEBUG, SO_REUSEADDR, SO_KEEPALIVE, SO_BROADCAST, etc.
  - SOL_SOCKET level translation (FreeBSD 0xffff → Linux 1)
- **jail_attach syscall mapping** in interceptor for chroot execution
- FreeBSD `/rescue/ping` now fully functional in containers

### Fixed
- `setsockopt SO_TIMESTAMP: Protocol not available` error
  - Root cause: FreeBSD SO_TIMESTAMP=0x400, Linux SO_TIMESTAMP=29
  - Root cause: FreeBSD SOL_SOCKET=0xffff, Linux SOL_SOCKET=1
- `No Linux syscall mapping for emulated FreeBSD syscall 436` error
  - jail_attach (436) now properly maps to chroot (161) in interceptor
- Socket option translation now works regardless of level parameter

### Technical Details
- New `translate_sockopt_to_linux()` function in syscall_table.c
- `emul_setsockopt()` and `emul_getsockopt()` handlers with level+optname translation
- SO_TS_CLOCK (0x1017) gracefully ignored (FreeBSD-specific, no Linux equivalent)
- SO_NOSIGPIPE gracefully ignored (FreeBSD-specific)
- Interceptor switch statement extended with FBSD_SYS_jail_attach → 161 mapping

## [0.3.4] - 2026-02-20

### Added
- **OverlayFS Copy-on-Write (COW) filesystem** for per-container isolation
  - Each container gets isolated storage via Linux OverlayFS
  - Base image shared read-only (lowerdir), changes written to container-specific diff (upperdir)
  - Merged view provides unified filesystem for jail
  - Storage automatically cleaned up on container removal
- Unique MAC addresses per container (02:00:00:00:00:XX based on IP)
- Container-to-container networking verified working

### Fixed
- `/etc/hosts` duplication issue - now writes clean per-container hosts files
- Duplicate MAC addresses causing container communication failure

### Technical Details
- New `lochs_storage.c` module with `lochs_storage_create_container()`, `mount()`, `unmount()`, `destroy()`
- `lochs_jail_t` extended with `image_path`, `diff_path`, `work_path`, `merged_path`, `overlay_mounted`
- Storage paths: `/var/lib/lochs/containers/<name>/{diff,work,merged}`
- ZFS support detection for future native ZFS COW on supported systems

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
- **Duplicate MAC addresses** causing container-to-container communication failure
  - Now assigns unique locally-administered MACs based on IP (02:00:00:00:00:XX)
- Container-to-container networking verified working (ping by IP)

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
| 0.3.6 | 2026-02-20 | Auto-start CMD, DNS config, NAT working |
| 0.3.5 | 2026-02-20 | Socket option translation, ping working |
| 0.3.4 | 2026-02-20 | OverlayFS COW filesystem |
| 0.3.3 | 2026-02-20 | Network namespace isolation |
| 0.3.2 | 2026-02-20 | Container networking, RUN directive |
| 0.3.1 | 2026-02-19 | Volumes, env vars, logs |
| 0.3.0 | 2026-02-18 | Lochfile build, compose, port forwarding |
| 0.2.0 | 2026-01-15 | Jail lifecycle, image pull, exec |
| 0.1.0 | 2026-01-01 | Initial release |
