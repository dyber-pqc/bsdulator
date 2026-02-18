# BSDulator Development Roadmap

## Vision

Create a complete FreeBSD compatibility layer for Linux, enabling FreeBSD applications and jails to run seamlessly on Linux systems without virtualization.

---

## Phase 1: Core Foundation ✓ (Current)

**Goal**: Get a static FreeBSD binary (echo) running on Linux

### Completed
- [x] Project structure and build system
- [x] ptrace-based syscall interception
- [x] FreeBSD ELF binary detection
- [x] Basic syscall translation table (200+ syscalls)
- [x] ABI translation for common flags/constants
- [x] Command-line interface
- [x] Test framework

### Testing
```bash
# Verify Linux binary compatibility
./bsdulator /bin/echo "Hello"

# Download FreeBSD base system
make freebsd-root

# Test FreeBSD static binary
./bsdulator ./freebsd-root/rescue/echo "Hello from FreeBSD"
```

---

## Phase 2: Expanded Syscall Coverage

**Goal**: Support common FreeBSD utilities

### Tasks
- [ ] Complete file syscall family
  - [ ] fstatat structure translation
  - [ ] getdirentries → getdents64 translation
  - [ ] Extended attributes (extattr_*)
  
- [ ] Process management
  - [ ] rfork → clone translation
  - [ ] wait6 implementation
  - [ ] procctl emulation
  
- [ ] Signal handling
  - [ ] Complete signal number translation
  - [ ] sigaction structure translation
  - [ ] SIGINFO handling (no Linux equivalent)
  
- [ ] Memory management
  - [ ] minherit emulation
  - [ ] Complete mmap flag translation

### Testing
```bash
./bsdulator ./freebsd-root/rescue/ls -la
./bsdulator ./freebsd-root/rescue/cat /etc/passwd
./bsdulator ./freebsd-root/rescue/cp file1 file2
```

---

## Phase 3: FreeBSD-Specific Features

**Goal**: Support FreeBSD-unique functionality

### kqueue → epoll Translation
- [ ] Create epoll fd for kqueue fd
- [ ] Translate EVFILT_* to epoll events
- [ ] Handle kevent structure conversion
- [ ] Support common filters:
  - [ ] EVFILT_READ
  - [ ] EVFILT_WRITE
  - [ ] EVFILT_VNODE
  - [ ] EVFILT_PROC
  - [ ] EVFILT_SIGNAL
  - [ ] EVFILT_TIMER

### sysctl Emulation
- [ ] Parse FreeBSD sysctl MIB names
- [ ] Map to Linux /proc and /sys
- [ ] Common sysctls:
  - [ ] kern.hostname
  - [ ] kern.ostype
  - [ ] kern.osrelease
  - [ ] hw.ncpu
  - [ ] hw.physmem

### Jail Support (Critical for Jailhouse)
- [ ] jail() syscall using Linux namespaces
  - [ ] PID namespace
  - [ ] Mount namespace
  - [ ] Network namespace
  - [ ] UTS namespace
- [ ] jail_attach() implementation
- [ ] jail_get/set/remove
- [ ] Resource limits via cgroups

### Capsicum (Capability Mode)
- [ ] cap_enter() → seccomp-bpf
- [ ] cap_rights_limit
- [ ] cap_getmode

---

## Phase 4: Dynamic Binary Support

**Goal**: Run dynamically linked FreeBSD binaries

### Challenges
1. FreeBSD uses `/libexec/ld-elf.so.1` as dynamic linker
2. FreeBSD libc (`libc.so.7`) differs from glibc
3. Library search paths differ

### Approaches

#### Option A: FreeBSD Libraries in chroot
```bash
# Set up FreeBSD library environment
export BSDULATOR_ROOT=./freebsd-root
./bsdulator ./freebsd-root/bin/ls
```
- Intercept file operations to redirect /lib → $BSDULATOR_ROOT/lib
- Simple but requires full FreeBSD base

#### Option B: Library Interception
- Intercept dlopen/dlsym
- Redirect FreeBSD library loads to wrapper libraries
- More complex but smaller footprint

#### Option C: Custom Dynamic Linker
- Load FreeBSD ld-elf.so.1 in memory
- Handle its syscalls specially
- Most complete solution

### Tasks
- [ ] Implement library path translation
- [ ] Handle FreeBSD ld-elf.so.1
- [ ] Test with common dynamic binaries
  - [ ] /bin/sh
  - [ ] /bin/ls
  - [ ] /usr/bin/env

---

## Phase 5: Jailhouse Integration

**Goal**: Connect BSDulator with Jailhouse container manager

### Components
```
┌─────────────────────────────────────────────┐
│              Jailhouse CLI                   │
│     jailhouse create/start/stop/attach      │
├─────────────────────────────────────────────┤
│            Container Manager                 │
│   Image management, networking, storage     │
├─────────────────────────────────────────────┤
│              BSDulator                       │
│        Syscall translation layer            │
├─────────────────────────────────────────────┤
│              Linux Kernel                    │
│    Namespaces, cgroups, networking          │
└─────────────────────────────────────────────┘
```

### Tasks
- [ ] Create libbsdulator for integration
- [ ] Implement jail management API
- [ ] Resource limits (CPU, memory, I/O)
- [ ] Network virtualization
- [ ] Storage management (ZFS-like features?)
- [ ] Jailhouse configuration format (jail-housing.yml)

### API Design
```c
// libbsdulator API
bsd_jail_t *bsd_jail_create(const char *name, const char *root);
int bsd_jail_start(bsd_jail_t *jail);
int bsd_jail_stop(bsd_jail_t *jail);
int bsd_jail_attach(bsd_jail_t *jail);
int bsd_jail_exec(bsd_jail_t *jail, const char *cmd, ...);
```

---

## Phase 6: Performance Optimization

**Goal**: Minimize syscall translation overhead

### Approaches

#### eBPF-based Fast Path
- Use eBPF to intercept syscalls in kernel
- Direct number translation without context switch
- Requires kernel 5.0+

#### Syscall Patching
- Rewrite syscall instructions in binary
- Replace with call to translation stub
- Fastest but most invasive

#### Caching
- Cache translated syscall numbers
- Memoize structure translations
- Reduce repeated work

### Benchmarks
- [ ] Create benchmark suite
- [ ] Compare against native FreeBSD
- [ ] Compare against QEMU user-mode
- [ ] Profile hotspots

---

## Phase 7: Multi-Platform Support

**Goal**: Support additional architectures and host OSes

### Architectures
- [x] x86_64 (amd64)
- [ ] i386 (32-bit x86)
- [ ] aarch64 (ARM64)
- [ ] armv7 (32-bit ARM)

### Host Operating Systems
- [x] Linux
- [ ] macOS (via Hypervisor.framework)
- [ ] Windows (via WSL2)

### Tasks
- [ ] Abstract ptrace interface
- [ ] Add platform-specific backends
- [ ] Cross-compilation support

---

## Future Ideas

### Package Manager Integration
- Install FreeBSD packages on Linux
- Translate `pkg` commands
- Dependency resolution

### Networking Stack
- FreeBSD pf → iptables/nftables
- FreeBSD ifconfig → ip commands
- VNET jail support

### ZFS Support
- Use Linux ZFS module
- Jail dataset management
- Snapshots and clones

### GUI Applications
- X11 compatibility (mostly works)
- Wayland support
- FreeBSD-specific graphics ioctls

---

## Timeline (Estimated)

| Phase | Duration | Status |
|-------|----------|--------|
| Phase 1: Core | 2 weeks | ✓ Complete |
| Phase 2: Syscalls | 4 weeks | In Progress |
| Phase 3: FreeBSD Features | 6 weeks | Planned |
| Phase 4: Dynamic Binaries | 4 weeks | Planned |
| Phase 5: Jailhouse | 8 weeks | Planned |
| Phase 6: Optimization | 4 weeks | Future |
| Phase 7: Multi-Platform | 8 weeks | Future |

---

## Contributing

Priority areas for contributions:

1. **Syscall implementations** - Add missing syscalls to translation table
2. **Testing** - Test with real FreeBSD applications, report issues
3. **Documentation** - Improve docs, add examples
4. **kqueue emulation** - Critical for many FreeBSD apps
5. **Performance** - Profile and optimize hot paths

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.
