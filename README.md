# BSDulator

**FreeBSD Binary Compatibility Layer for Linux**

BSDulator enables running unmodified FreeBSD binaries on Linux by intercepting and translating FreeBSD system calls to their Linux equivalents. Similar to how Wine runs Windows applications on Linux, or how FreeBSD's Linuxulator runs Linux binaries on FreeBSD—but in reverse.

## 🎉 Current Status: Fully Functional

BSDulator now supports both **static and dynamic FreeBSD binaries**, including the FreeBSD shell!

### What Works

| Binary Type | Examples | Status |
|-------------|----------|--------|
| Static binaries | `/rescue/echo`, `/rescue/ls`, `/rescue/cat` | ✅ **Working** |
| Dynamic binaries | `/bin/echo`, `/bin/ls`, `/bin/cat` | ✅ **Working** |
| FreeBSD Shell | `/bin/sh` | ✅ **Working** |
| Shared libraries | `libc.so.7`, `ld-elf.so.1` | ✅ **Loading** |

```bash
# These all work!
./bsdulator -r ./freebsd-root ./freebsd-root/bin/echo "Hello from FreeBSD!"
./bsdulator -r ./freebsd-root ./freebsd-root/bin/ls -la ./freebsd-root/
./bsdulator -r ./freebsd-root ./freebsd-root/bin/cat ./freebsd-root/COPYRIGHT
./bsdulator -r ./freebsd-root ./freebsd-root/bin/sh -c 'pwd; echo test; echo done'
```

## Features

- **Full Syscall Translation**: 200+ FreeBSD syscalls translated to Linux equivalents
- **Dynamic Binary Support**: Loads FreeBSD shared libraries and dynamic linker
- **Path Translation**: Automatically redirects FreeBSD system paths to local root
- **ABI Translation**: Handles differences in flags, structures, errno values, and signals
- **Stat Structure Translation**: Converts between FreeBSD and Linux stat formats
- **mmap Flag Translation**: Handles FreeBSD-specific mmap flags including MAP_ALIGNED
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

# 3. Create symlink for dynamic linker (one-time setup)
sudo mkdir -p /libexec
sudo ln -sf $(pwd)/freebsd-root/libexec/ld-elf.so.1 /libexec/ld-elf.so.1

# 4. Run FreeBSD binaries!
./bsdulator -r ./freebsd-root ./freebsd-root/bin/echo "Hello from FreeBSD!"
./bsdulator -r ./freebsd-root ./freebsd-root/bin/ls -la ./freebsd-root/
./bsdulator -r ./freebsd-root ./freebsd-root/bin/sh -c 'echo Running FreeBSD shell!'
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

2. **Dynamic Linker Setup**: For dynamic binaries, ensures the FreeBSD dynamic linker (`ld-elf.so.1`) can find and load shared libraries.

3. **Path Translation**: Intercepts file-related syscalls and redirects FreeBSD system paths (`/lib`, `/usr/lib`, `/etc`, etc.) to the local FreeBSD root filesystem.

4. **Syscall Interception**: Uses ptrace to intercept every syscall:
   - **Entry**: Translates FreeBSD syscall numbers and arguments to Linux equivalents
   - **Exit**: Translates return values, structures (like stat), and errno values

5. **ABI Translation**: Handles differences between FreeBSD and Linux:
   - Open flags (O_CREAT, O_APPEND, etc.)
   - mmap flags (MAP_ANONYMOUS, MAP_ALIGNED)
   - Signal numbers and structures
   - Stat structures (different field layouts and sizes)
   - Directory entry formats

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
| kqueue | kqueue, kevent | 🚧 Planned |
| jail | jail, jail_attach, jail_get | 🚧 Planned |
| Capsicum | cap_enter, cap_getmode | ⚠️ Stub |

## Known Limitations

- **Shell pipes**: Commands using `|` may hang (fork tracking needs work)
- **Extended attributes**: `extattr_*` syscalls return "Function not implemented"
- **32-bit binaries**: Not supported (x86_64 only)
- **Performance**: ptrace interception adds overhead (~10-30%)
- **kqueue**: Not yet implemented (use poll/select based programs)

## Project Structure

```
bsdulator/
├── src/
│   ├── main.c                 # Entry point and CLI
│   ├── interceptor/
│   │   └── interceptor.c      # ptrace syscall interception
│   ├── syscall/
│   │   └── syscall_table.c    # FreeBSD→Linux syscall mapping
│   ├── loader/
│   │   └── elf_loader.c       # FreeBSD ELF detection
│   ├── abi/
│   │   └── abi_translate.c    # Flags/struct translation
│   └── runtime/
│       └── freebsd_runtime.c  # FreeBSD runtime environment
├── include/
│   └── bsdulator/
│       ├── bsdulator.h        # Main header
│       ├── interceptor.h
│       ├── syscall.h
│       ├── loader.h
│       └── abi.h
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

### Phase 2: Enhanced Features (In Progress)
- [ ] kqueue → epoll translation
- [ ] Fix shell pipe support
- [ ] Implement extattr syscalls
- [ ] Improve fork/clone tracking

### Phase 3: Jail Support (Planned)
- [ ] jail syscall using Linux namespaces
- [ ] jail_attach, jail_get, jail_set, jail_remove
- [ ] Integration with Jailhouse.io

### Phase 4: Production Ready
- [ ] Performance optimization
- [ ] Comprehensive test suite
- [ ] arm64 architecture support
- [ ] Documentation and tutorials

## Related Projects

- **[Jailhouse.io](https://jailhouse.io)**: Docker-like container management for FreeBSD jails (uses BSDulator as the compatibility engine)
- **FreeBSD Linuxulator**: Runs Linux binaries on FreeBSD (the inverse of BSDulator)
- **Wine**: Runs Windows applications on Linux (similar concept)

## Contributing

Contributions welcome! Priority areas:

1. kqueue → epoll emulation
2. Shell pipe support (fork tracking)
3. jail syscall implementation
4. Additional syscall translations
5. Test coverage

## License

Source Available License - See [LICENSE](LICENSE) for details.

Core BSDulator source code is available for viewing, modification, and non-commercial use. Commercial use requires a separate license agreement.

## Acknowledgments

- FreeBSD Project for the excellent documentation
- Linux kernel developers for ptrace infrastructure
- The Wine project for inspiration on compatibility layers