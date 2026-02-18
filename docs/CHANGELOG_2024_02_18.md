# BSDulator Changelog - February 18, 2025

## File Redirection Fix

### Problem
Shell file redirection (`echo foo > /tmp/file.txt`) was failing with "Bad address" error.

### Root Cause
FreeBSD's `F_DUPFD_CLOEXEC` fcntl command uses value **17**, but Linux uses **1030** (F_LINUX_SPECIFIC_BASE + 6). The shell uses this command when setting up file redirections.

### Fix
Added translation in `src/abi/abi_translate.c`:
```c
case FBSD_F_DUPFD_CLOEXEC:
    /* FreeBSD F_DUPFD_CLOEXEC = 17, Linux = 1030 (F_LINUX_SPECIFIC_BASE + 6) */
    return 1030;
```

### Result
- Output redirection (`>`) ✅
- Append redirection (`>>`) ✅
- Input redirection with builtins (`read < file`) ✅

---

## sigaction Structure Translation

### Problem
`tar --help` was failing with "sigaction(SIGINFO) failed" and later "sigaction(SIGUSR1) failed: Operation not permitted".

### Root Causes

1. **SIGINFO (29)** - FreeBSD-only signal with no Linux equivalent
2. **sigaction structure mismatch** - FreeBSD and Linux have different layouts:
   - FreeBSD: `{ handler(8), flags(4), mask(16) }` = 28 bytes
   - Linux: `{ handler(8), flags(8), restorer(8), mask(128) }` = 152 bytes
3. **sigset size parameter** - Linux `rt_sigaction` expects 8 bytes, not 128

### Fix
Updated `emul_sigaction()` in `src/syscall/syscall_table.c`:

1. Stub SIGINFO (29), SIGTHR (32), and SIGEMT (7) - signals without Linux equivalents
2. Read FreeBSD sigaction structure from child's memory using `process_vm_readv()`
3. Convert to Linux sigaction structure
4. Call `rt_sigaction` with correct sigset size (8 bytes)
5. Write back converted oldact to child's memory using `process_vm_writev()`

### Result
- `tar --help` ✅
- `tar -tvf archive.tar` ✅
- Signal handling for standard signals works

---

## Testing Summary

### Working Commands
```bash
# Basic commands
./bsdulator freebsd-root/rescue/echo "Hello World"
./bsdulator freebsd-root/rescue/ls /
./bsdulator freebsd-root/rescue/cat /etc/passwd
./bsdulator freebsd-root/rescue/pwd

# Pipes
./bsdulator freebsd-root/rescue/sh -c "echo hello | cat"

# File redirection
./bsdulator freebsd-root/rescue/sh -c "echo foo > /tmp/test.txt"
./bsdulator freebsd-root/rescue/sh -c "echo bar >> /tmp/test.txt"

# tar (read operations)
./bsdulator freebsd-root/rescue/tar --help
./bsdulator freebsd-root/rescue/tar -tvf /tmp/archive.tar
```

### Known Issues
1. **tar -cvf** - Fails with "statvfs failed: Bad file descriptor"
   - Cause: fstatfs structure needs translation (FreeBSD/Linux differ)
   - Priority: Medium

2. **Input redirection with external commands** - argv[0] corruption
   - Example: `sh -c "cat < /tmp/file"` shows garbage in argv[0]
   - Cause: Stack/memory issue during fork+redirect
   - Priority: Medium

3. **vi** - Terminal ioctl issues
   - Needs TIOCGETA/TIOCSETA translation to TCGETS/TCSETS
   - Priority: Low

---

## Technical Details

### fcntl Command Values
| Command | FreeBSD | Linux |
|---------|---------|-------|
| F_DUPFD | 0 | 0 |
| F_GETFD | 1 | 1 |
| F_SETFD | 2 | 2 |
| F_GETFL | 3 | 3 |
| F_SETFL | 4 | 4 |
| F_DUPFD_CLOEXEC | 17 | 1030 |

### Signal Numbers Requiring Special Handling
| Signal | FreeBSD | Linux | Action |
|--------|---------|-------|--------|
| SIGEMT | 7 | N/A | Stub (return 0) |
| SIGINFO | 29 | N/A | Stub (return 0) |
| SIGTHR | 32 | N/A | Stub (return 0) |
| SIGUSR1 | 30 | 10 | Translate |
| SIGUSR2 | 31 | 12 | Translate |
