# BSDulator

**FreeBSD Binary Compatibility Layer for Linux**

BSDulator enables running unmodified FreeBSD binaries on Linux by intercepting and translating FreeBSD system calls to their Linux equivalents. Similar to how Wine runs Windows applications on Linux, or how FreeBSD's Linuxulator runs Linux binaries on FreeBSD—but in reverse.

## 🎉 Current Status: FreeBSD Jails Fully Functional on Linux!

BSDulator now provides **complete FreeBSD jail support**, bringing FreeBSD's powerful jail containerization to Linux. This is the first implementation of FreeBSD jails outside of FreeBSD itself.

### What Works

| Feature | Examples | Status |
|---------|----------|--------|
| Static binaries | `/rescue/echo`, `/rescue/ls`, `/rescue/cat`, `/rescue/sh` | ✅ **Working** |
| Dynamic binaries | `/bin/echo`, `/bin/ls`, `/bin/cat`, `/bin/sh` | ✅ **Working** |
| FreeBSD Shell | `/bin/sh` with pipes, redirects | ✅ **Working** |
| Shared libraries | `libc.so.7`, `ld-elf.so.1` | ✅ **Loading** |
| **Jail creation** | `jail -c name=test path=./freebsd-root ip4.addr=10.0.0.1 persist` | ✅ **Working** |
| **Jail listing** | `jls`, `jls -v`, `jls jid name ip4.addr path` | ✅ **Working** |
| **Jail execution** | `jexec 1 /bin/sh -c "echo hello"` | ✅ **Working** |
| **Jail exec flags** | `jexec -l`, `jexec -U root`, `jexec -u root` | ✅ **Working** |
| **Jail removal** | `jail -r 1` | ✅ **Working** |
| **Jail IP assignment** | `ip4.addr=192.168.1.10` parameter | ✅ **Working** |
| **Multiple jails** | Create, manage, and remove multiple concurrent jails | ✅ **Working** |

```bash
# Run FreeBSD binaries
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/echo "Hello from FreeBSD!"
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/ls -la /
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/sh -c 'pwd; echo test'

# Create and manage FreeBSD jails on Linux!
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jail -c name=myjail path=./freebsd-root ip4.addr=10.0.0.1 persist
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jls
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jls jid name ip4.addr path
sudo ./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jexec 1 /bin/sh -c "echo Hello from inside the jail!"
sudo ./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jexec -U root 1 /bin/sh -c "id"
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jail -r 1
```

## Features

- **Full Syscall Translation**: 200+ FreeBSD syscalls translated to Linux equivalents
- **Complete FreeBSD Jail Support**: Create, list, execute, and remove jails with IP assignment
- **Jail IP Assignment**: Assign IPv4 addresses to jails via `ip4.addr` parameter
- **Jail Execution Flags**: Full support for `jexec -l`, `-U`, and `-u` flags
- **Dynamic Binary Support**: Loads FreeBSD shared libraries and dynamic linker
- **Path Translation**: Automatically redirects FreeBSD system paths to local root
- **ABI Translation**: Handles differences in flags, structures, errno values, and signals
- **TLS Emulation**: Full Thread Local Storage setup for FreeBSD binaries
- **Persistent Jails**: Jail state persists across BSDulator invocations
- **Verbose Tracing**: Detailed syscall tracing for debugging

## Building

```bash
# Clone or download the source
cd bsdulator

# Build optimized release
make

# Or build with debug symbols
make debug

# Clean and rebuild
make clean && make
```

## Quick Start

```bash
# 1. Build BSDulator
make

# 2. Download FreeBSD base system (~180MB)
./scripts/setup_freebsd_root.sh

# 3. Run FreeBSD binaries!
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/echo "Hello from FreeBSD!"

# 4. Create a jail with IP address!
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jail -c name=test path=./freebsd-root ip4.addr=10.0.0.1 persist

# 5. List jails (with IP addresses)
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jls jid name ip4.addr path

# 6. Execute commands in jail (requires sudo for chroot)
sudo ./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jexec 1 /bin/sh -c "whoami; pwd; ls /"

# 7. Execute with user flag
sudo ./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jexec -U root 1 /bin/sh -c "id"

# 8. Remove jail
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jail -r 1
```

## Usage

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

## How It Works

1. **Binary Detection**: Examines ELF OS/ABI field and FreeBSD notes to identify FreeBSD binaries.

2. **Dynamic Linker Setup**: For dynamic binaries, the FreeBSD dynamic linker (`ld-elf.so.1`) loads shared libraries from the FreeBSD root.

3. **Path Translation**: Intercepts file-related syscalls and redirects FreeBSD system paths (`/lib`, `/usr/lib`, `/etc`, etc.) to the local FreeBSD root filesystem.

4. **Syscall Interception**: Uses ptrace to intercept every syscall:
   - **Entry**: Translates FreeBSD syscall numbers and arguments to Linux equivalents
   - **Exit**: Translates return values, structures (like stat), and errno values

5. **Jail Emulation**: Implements FreeBSD jail syscalls using:
   - Persistent jail registry in `/tmp/bsdulator_jails.dat`
   - Linux `chroot()` for filesystem isolation
   - Process tracking for jail attachment
   - IP address assignment and retrieval
   - Dynamic linker rewriting for jailed binary execution

6. **TLS Setup**: Creates FreeBSD-compatible Thread Local Storage structures including TCB, DTV, and pthread structures.

## Syscall Support

| Category | Examples | Status |
|----------|----------|--------|
| Process | fork, exec, wait, exit, kill, getpid | ✅ Full |
| File I/O | open, read, write, close, stat, fstat | ✅ Full |
| Memory | mmap, mprotect, munmap, brk | ✅ Full |
| Network | socket, bind, connect, send, recv | ✅ Full |
| Time | gettimeofday, clock_gettime, nanosleep | ✅ Full |
| Signals | sigaction, sigprocmask, sigfastblock | ✅ Full |
| IPC | semget, msgget, shmget | ✅ Full |
| *at syscalls | openat, fstatat, unlinkat, etc. | ✅ Full |
| Threading | thr_self, thr_exit, thr_kill | ✅ Emulated |
| sysctl | __sysctl, __sysctlbyname | ✅ Emulated |
| **Jail** | jail, jail_get, jail_set, jail_attach, jail_remove | ✅ **Full** |
| **Credentials** | setgroups, credsync | ✅ Emulated |
| kqueue | kqueue, kevent | ✅ Basic |
| Capsicum | cap_enter, cap_getmode | ⚠️ Stub |

## Jail Implementation Details

BSDulator implements FreeBSD jail syscalls to provide container-like isolation:

| Syscall | Number | Description | Implementation |
|---------|--------|-------------|----------------|
| `jail` | 338 | Create/modify jail | Allocates JID, stores config |
| `jail_get` | 506 | Query jail parameters | Returns jail info via iovec |
| `jail_set` | 507 | Set jail parameters | Updates jail config, IP addresses |
| `jail_attach` | 436 | Attach process to jail | Linux chroot() + process tracking |
| `jail_remove` | 508 | Remove a jail | Removes from registry |

**Jail Features:**
- Persistent storage across BSDulator invocations
- Multiple concurrent jails with unique JIDs
- IPv4 address assignment (`ip4.addr` parameter)
- Multiple IPs per jail (comma-separated)
- Both static (`/rescue/*`) and dynamic (`/bin/*`) binaries work inside jails
- Process isolation via chroot
- Full `jexec` flag support (`-l`, `-U`, `-u`)
- Verbose jail listing (`jls -v`)
- Proper FreeBSD environment setup (TLS, auxv) for jailed processes

**Supported Jail Parameters:**
- `name` - Jail name/hostname
- `path` - Root filesystem path
- `host.hostname` - Hostname
- `ip4.addr` - IPv4 address(es), comma-separated
- `persist` - Keep jail alive without processes
- `jid` - Jail ID (for queries)
- `cpuset.id` - CPU set ID
- `osreldate`, `osrelease` - OS version info

## Known Limitations

- **Jail networking**: IP addresses are stored but not enforced (no network namespace yet)
- **Jail resource limits**: CPU/memory limits not enforced
- **32-bit binaries**: Not supported (x86_64 only)
- **Performance**: ptrace interception adds overhead (~10-30%)
- **Some vi features**: Editor has minor issues with temp files

## Project Structure

```
bsdulator/
├── src/
│   ├── main.c                 # Entry point and CLI
│   ├── interceptor/
│   │   └── interceptor.c      # ptrace syscall interception, TLS setup
│   ├── syscall/
│   │   └── syscall_table.c    # FreeBSD→Linux syscall mapping
│   ├── loader/
│   │   └── elf_loader.c       # FreeBSD ELF detection
│   ├── abi/
│   │   └── abi_translate.c    # Flags/struct translation
│   ├── runtime/
│   │   └── freebsd_runtime.c  # FreeBSD runtime environment, auxv
│   └── jail/
│       └── jail.c             # Jail syscall emulation
├── include/
│   └── bsdulator/
│       ├── bsdulator.h        # Main header
│       ├── interceptor.h
│       ├── syscall.h
│       ├── loader.h
│       ├── abi.h
│       └── jail.h             # Jail structures and functions
├── scripts/
│   └── setup_freebsd_root.sh  # Download FreeBSD base
├── freebsd-root/              # FreeBSD filesystem (after setup)
├── Makefile
├── LICENSE
└── README.md
```

## Roadmap

### Phase 1: Core Compatibility ✅ Complete
- [x] Basic syscall translation
- [x] Static binary support
- [x] Dynamic binary support
- [x] Path translation
- [x] Stat structure translation
- [x] Shell support
- [x] TLS emulation

### Phase 2: Jail Support ✅ Complete
- [x] jail syscall (create jails)
- [x] jail_get (query jail info)
- [x] jail_set (configure jails)
- [x] jail_attach (attach process to jail)
- [x] jail_remove (destroy jails)
- [x] jls command working
- [x] jexec command working
- [x] Multiple concurrent jails
- [x] Persistent jail storage

### Phase 3: Networking & Advanced Jails ✅ Complete
- [x] Jail IP assignment (`ip4.addr` parameter)
- [x] IP address display in `jls`
- [x] `jexec -l` (login shell)
- [x] `jexec -U` / `-u` (user flags)
- [x] `jls -v` (verbose listing)
- [x] FreeBSD 15 syscall support (`credsync`, `__realpathat`)
- [ ] Virtual network stack (Linux network namespaces) - Future

### Phase 4: Jailhouse.io Integration (Planned)
- [ ] CLI wrapper (`jailhouse create/start/exec/stop`)
- [ ] YAML configuration files
- [ ] Web dashboard
- [ ] Windows/macOS support via VM

## Related Projects

- **[Jailhouse.io](https://jailhouse.io)**: Docker-like container management for FreeBSD jails (uses BSDulator as the compatibility engine)
- **FreeBSD Linuxulator**: Runs Linux binaries on FreeBSD (the inverse of BSDulator)
- **Wine**: Runs Windows applications on Linux (similar concept)

## Contributing

Contributions welcome! Priority areas:

1. Linux network namespace integration for jail isolation
2. Resource limit enforcement
3. Additional syscall translations
4. Test coverage
5. Documentation

## License

Source Available License - See [LICENSE](LICENSE) for details.

Core BSDulator source code is available for viewing, modification, and non-commercial use. Commercial use requires a separate license agreement.

## Acknowledgments

- FreeBSD Project for the excellent documentation and jail implementation
- Linux kernel developers for ptrace infrastructure
- The Wine project for inspiration on compatibility layers
