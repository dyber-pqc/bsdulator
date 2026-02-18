# BSDulator Architecture

## Overview

BSDulator is a FreeBSD binary compatibility layer for Linux. It allows FreeBSD executables to run on Linux by intercepting system calls and translating them to their Linux equivalents.

## Execution Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         User Command                            │
│              ./bsdulator /path/to/freebsd/binary                │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      ELF Loader (loader.c)                      │
│  1. Read ELF header                                             │
│  2. Check EI_OSABI == ELFOSABI_FREEBSD (9)                     │
│  3. Detect static vs dynamic linking                            │
│  4. Extract binary metadata                                     │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Interceptor (interceptor.c)                   │
│  1. fork() child process                                        │
│  2. Child: ptrace(TRACEME) + execve(binary)                    │
│  3. Parent: ptrace(SETOPTIONS) with TRACESYSGOOD               │
│  4. Parent: Main interception loop                              │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Main Interception Loop                       │
│                                                                 │
│  while (process running) {                                      │
│      waitpid() → get event                                      │
│                                                                 │
│      if (SYSCALL_ENTER) {                                       │
│          freebsd_nr = regs.orig_rax                            │
│          linux_nr = syscall_translate(freebsd_nr)              │
│          args = translate_args(args)                            │
│          regs.orig_rax = linux_nr                              │
│      }                                                          │
│                                                                 │
│      if (SYSCALL_EXIT) {                                        │
│          retval = translate_return(retval)                      │
│      }                                                          │
│                                                                 │
│      ptrace(SYSCALL) → continue to next syscall                │
│  }                                                              │
└─────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. ELF Loader (`src/loader/elf_loader.c`)

Responsible for:
- Detecting FreeBSD binaries via ELF OS/ABI byte
- Checking for FreeBSD notes in section headers
- Determining static vs dynamic linking
- Extracting interpreter path for dynamic binaries

```c
// ELF OS/ABI byte location
elf_header[EI_OSABI] == ELFOSABI_FREEBSD (9)
```

### 2. Syscall Interceptor (`src/interceptor/interceptor.c`)

Uses Linux ptrace to:
- Spawn processes under trace control
- Intercept every syscall at entry and exit
- Read/modify registers (syscall number, arguments, return value)
- Read/write process memory (for string arguments)

Key ptrace operations:
- `PTRACE_TRACEME` - Child requests to be traced
- `PTRACE_SETOPTIONS` - Set `PTRACE_O_TRACESYSGOOD` for clean syscall detection
- `PTRACE_SYSCALL` - Continue to next syscall entry/exit
- `PTRACE_GETREGS/SETREGS` - Read/modify registers

### 3. Syscall Translation (`src/syscall/syscall_table.c`)

Contains mapping table from FreeBSD syscall numbers to Linux:

```c
typedef struct {
    int freebsd_nr;      // FreeBSD syscall number
    int linux_nr;        // Linux syscall number
    const char *name;    // Syscall name for debugging
    syscall_result_t type; // TRANSLATED, EMULATED, UNSUPPORTED
    syscall_handler_t handler; // Emulation function (if needed)
} syscall_entry_t;
```

Translation types:
- **TRANSLATED**: Direct 1:1 mapping (most syscalls)
- **EMULATED**: Requires userspace implementation (jail, kqueue)
- **UNSUPPORTED**: No equivalent, returns ENOSYS

### 4. ABI Translation (`src/abi/abi_translate.c`)

Handles differences in:
- Open flags (`O_CREAT`, `O_DIRECT`, etc.)
- mmap flags (`MAP_ANONYMOUS`, `MAP_STACK`)
- Signal numbers (FreeBSD/Linux differ after signal 10)
- fcntl commands
- struct stat layout
- errno values

## x86_64 Syscall ABI

Both FreeBSD and Linux use the same register convention for syscalls:

| Purpose | Register |
|---------|----------|
| Syscall number | rax |
| Argument 1 | rdi |
| Argument 2 | rsi |
| Argument 3 | rdx |
| Argument 4 | r10 |
| Argument 5 | r8 |
| Argument 6 | r9 |
| Return value | rax |

The `orig_rax` field in ptrace contains the original syscall number even after return.

## Challenges

### 1. Static vs Dynamic Binaries

**Static binaries** (like those in `/rescue/`) work directly because all code is self-contained.

**Dynamic binaries** require:
- FreeBSD's dynamic linker (`/libexec/ld-elf.so.1`)
- FreeBSD shared libraries (`libc.so.7`, etc.)
- Proper `LD_LIBRARY_PATH` setup

### 2. FreeBSD-Specific Syscalls

Some syscalls have no Linux equivalent:
- `jail()`, `jail_attach()` - FreeBSD jails
- `kqueue()`, `kevent()` - Event notification (Linux uses epoll)
- `__sysctl()` - System configuration
- `cap_enter()` - Capsicum sandboxing

These require userspace emulation.

### 3. Structure Layout Differences

FreeBSD and Linux have different layouts for:
- `struct stat` - Different field order and sizes
- `struct dirent` - Different format
- Signal structures

These require translation when reading/writing process memory.

### 4. Performance

ptrace interception adds significant overhead because:
- Every syscall requires 4 context switches (entry trap, exit trap)
- Register read/write for each syscall
- Memory operations use `process_vm_readv/writev`

Future optimization: Use seccomp-bpf for syscalls that don't need translation.

## Memory Layout

```
┌────────────────────────────────────────┐ High addresses
│              Stack                      │
│         (grows downward)                │
├────────────────────────────────────────┤
│                                        │
│         (unmapped space)               │
│                                        │
├────────────────────────────────────────┤
│              Heap                       │
│          (grows upward)                 │
├────────────────────────────────────────┤
│              BSS                        │
│       (uninitialized data)             │
├────────────────────────────────────────┤
│              Data                       │
│        (initialized data)              │
├────────────────────────────────────────┤
│              Text                       │
│         (program code)                  │
├────────────────────────────────────────┤
│     Dynamic Linker (if dynamic)        │
└────────────────────────────────────────┘ Low addresses
```

## Future Architecture

### Phase 2: eBPF Acceleration

Use seccomp-bpf to filter syscalls:
- Allow known-identical syscalls to pass through
- Only trap syscalls needing translation

### Phase 3: Jail Emulation

Map FreeBSD jails to Linux namespaces:
- PID namespace → jail process isolation
- Network namespace → jail vnet
- Mount namespace → jail filesystem
- cgroups → jail resource limits

### Phase 4: kqueue Emulation

Translate kqueue/kevent to epoll:
- kqueue fd → epoll fd
- kevent filters → epoll events
- Maintain state mapping between APIs
