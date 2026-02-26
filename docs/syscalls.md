# Syscall Support Matrix

BSDulator translates FreeBSD system calls to Linux equivalents. Each syscall falls into one of four categories:

| Type | Description |
|------|-------------|
| **Translated** | FreeBSD syscall number mapped directly to a Linux syscall number. Arguments may be translated (flags, structures) before the Linux kernel executes the call. |
| **Emulated** | No direct Linux equivalent. BSDulator implements the behavior in userspace via a custom handler function. |
| **Stub** | Returns a hardcoded success value without real functionality. Prevents crashes in programs that call it. |
| **Unsupported** | Returns `ENOSYS`. No translation or emulation exists yet. |

---

## Process Control

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `syscall` | 0 | Emulated | — | Indirect syscall; dispatches to real syscall with shifted args |
| `exit` | 1 | Translated | `exit` | |
| `fork` | 2 | Translated | `fork` | |
| `vfork` | 66 | Translated | `vfork` | |
| `execve` | 59 | Translated | `execve` | |
| `wait4` | 7 | Translated | `wait4` | |
| `kill` | 37 | Translated | `kill` | Signal numbers translated |
| `getpid` | 20 | Translated | `getpid` | |
| `getppid` | 39 | Translated | `getppid` | |
| `getpgrp` | 81 | Translated | `getpgrp` | |
| `setpgid` | 82 | Translated | `setpgid` | |
| `setsid` | 147 | Translated | `setsid` | |
| `getsid` | 310 | Translated | `getsid` | |
| `getpgid` | 207 | Translated | `getpgid` | |
| `rfork` | 251 | Emulated | `fork` | Falls back to `fork()`; flag translation not yet implemented |

## File I/O

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `read` | 3 | Translated | `read` | |
| `write` | 4 | Translated | `write` | |
| `open` | 5 | Translated | `open` | Open flags translated via `abi_translate_open_flags` |
| `close` | 6 | Translated | `close` | |
| `link` | 9 | Translated | `link` | |
| `unlink` | 10 | Translated | `unlink` | |
| `chdir` | 12 | Translated | `chdir` | |
| `fchdir` | 13 | Translated | `fchdir` | |
| `chmod` | 15 | Translated | `chmod` | |
| `chown` | 16 | Translated | `chown` | |
| `lchown` | 254 | Translated | `lchown` | |
| `fchown` | 123 | Translated | `fchown` | |
| `fchmod` | 124 | Translated | `fchmod` | |
| `access` | 33 | Translated | `access` | |
| `symlink` | 57 | Translated | `symlink` | |
| `readlink` | 58 | Translated | `readlink` | |
| `umask` | 60 | Translated | `umask` | |
| `chroot` | 61 | Translated | `chroot` | |
| `rename` | 128 | Translated | `rename` | |
| `mkdir` | 136 | Translated | `mkdir` | |
| `rmdir` | 137 | Translated | `rmdir` | |
| `mkfifo` | 132 | Emulated | `mknod` | Translated to `mknod` with `S_IFIFO` |
| `dup` | 41 | Translated | `dup` | |
| `dup2` | 90 | Translated | `dup2` | |
| `fcntl` | 92 | Translated | `fcntl` | Command values translated via `abi_translate_fcntl_cmd` |
| `flock` | 131 | Translated | `flock` | |
| `fsync` | 95 | Translated | `fsync` | |
| `fdatasync` | 550 | Translated | `fdatasync` | |
| `sync` | 36 | Translated | `sync` | |
| `readv` | 120 | Translated | `readv` | |
| `writev` | 121 | Translated | `writev` | |
| `pread` | 475 | Translated | `pread64` | |
| `pwrite` | 476 | Translated | `pwrite64` | |
| `preadv` | 289 | Translated | `preadv` | |
| `pwritev` | 290 | Translated | `pwritev` | |
| `lseek` | 478 | Translated | `lseek` | |
| `truncate` | 479 | Translated | `truncate` | |
| `ftruncate` | 480 | Translated | `ftruncate` | |
| `ioctl` | 54 | Emulated | — | Translates terminal ioctl commands (TIOCGETA, etc.) |
| `select` | 93 | Translated | `select` | |
| `pselect` | 522 | Translated | `pselect6` | |
| `poll` | 209 | Translated | `poll` | |
| `ppoll` | 545 | Translated | `ppoll` | |
| `pipe2` | 542 | Translated | `pipe2` | |

## *at Syscalls

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `openat` | 499 | Translated | `openat` | Flags translated |
| `faccessat` | 489 | Translated | `faccessat` | AT_ flags translated |
| `fchmodat` | 490 | Translated | `fchmodat` | AT_ flags translated |
| `fchownat` | 491 | Translated | `fchownat` | AT_ flags translated |
| `linkat` | 495 | Translated | `linkat` | |
| `mkdirat` | 496 | Translated | `mkdirat` | |
| `mknodat` | 559 | Translated | `mknodat` | |
| `readlinkat` | 500 | Translated | `readlinkat` | |
| `renameat` | 501 | Translated | `renameat` | |
| `symlinkat` | 502 | Translated | `symlinkat` | |
| `unlinkat` | 503 | Translated | `unlinkat` | AT_ flags translated |
| `futimesat` | 494 | Translated | `futimesat` | |
| `utimensat` | 547 | Translated | `utimensat` | |

## Stat Family

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `fstat` | 551 | Translated | `fstat` | Structure differences handled by ABI layer |
| `fstatat` | 552 | Translated | `newfstatat` | AT_ flags translated |
| `statfs` | 555 | Translated | `statfs` | |
| `fstatfs` | 556 | Emulated | — | Returns success with minimal data |
| `getdirentries` | 554 | Translated | `getdents64` | Directory entry format translated |

## User/Group IDs

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `getuid` | 24 | Translated | `getuid` | |
| `geteuid` | 25 | Translated | `geteuid` | |
| `getgid` | 47 | Translated | `getgid` | |
| `getegid` | 43 | Translated | `getegid` | |
| `setuid` | 23 | Translated | `setuid` | |
| `setgid` | 181 | Translated | `setgid` | |
| `seteuid` | 183 | Emulated | `setresuid` | Implemented via `setresuid(-1, euid, -1)` |
| `setegid` | 182 | Emulated | `setresgid` | Implemented via `setresgid(-1, egid, -1)` |
| `setreuid` | 126 | Translated | `setreuid` | |
| `setregid` | 127 | Translated | `setregid` | |
| `setresuid` | 311 | Translated | `setresuid` | |
| `setresgid` | 312 | Translated | `setresgid` | |
| `getresuid` | 360 | Translated | `getresuid` | |
| `getresgid` | 361 | Translated | `getresgid` | |
| `getgroups` | 79 | Translated | `getgroups` | |
| `setgroups` | 80 | Translated | `setgroups` | |
| `issetugid` | 253 | Emulated | — | Checks if running setuid/setgid |

## Memory Management

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `mmap` | 477 | Translated | `mmap` | Prot and flags translated via ABI layer |
| `munmap` | 73 | Translated | `munmap` | |
| `mprotect` | 74 | Translated | `mprotect` | |
| `madvise` | 75 | Translated | `madvise` | |
| `msync` | 65 | Translated | `msync` | |
| `mlock` | 203 | Translated | `mlock` | |
| `munlock` | 204 | Translated | `munlock` | |
| `mlockall` | 324 | Translated | `mlockall` | |
| `munlockall` | 325 | Translated | `munlockall` | |
| `mincore` | 78 | Translated | `mincore` | |
| `break` | 17 | Translated | `brk` | |
| `minherit` | 250 | Emulated | — | Returns success (no Linux equivalent) |

## Networking

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `socket` | 97 | Emulated | — | Socket type flags translated (e.g., `SOCK_CLOEXEC`) |
| `bind` | 104 | Emulated | — | `sockaddr` translated (FreeBSD has `sin_len` field) |
| `listen` | 106 | Translated | `listen` | |
| `accept` | 30 | Translated | `accept` | |
| `accept4` | 541 | Translated | `accept4` | |
| `connect` | 98 | Emulated | — | `sockaddr` translated |
| `shutdown` | 134 | Translated | `shutdown` | |
| `socketpair` | 135 | Translated | `socketpair` | |
| `sendto` | 133 | Emulated | — | `sockaddr` translated |
| `recvfrom` | 29 | Translated | `recvfrom` | |
| `sendmsg` | 28 | Translated | `sendmsg` | |
| `recvmsg` | 27 | Translated | `recvmsg` | |
| `getsockopt` | 118 | Emulated | — | Socket option constants translated |
| `setsockopt` | 105 | Emulated | — | Socket option constants translated |
| `getsockname` | 32 | Translated | `getsockname` | |
| `getpeername` | 31 | Translated | `getpeername` | |
| `sendfile` | 393 | Translated | `sendfile` | |

## Signals

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `sigaction` | 416 | Emulated | — | `sigset_t` size differs: FreeBSD 16 bytes vs Linux 8 bytes |
| `sigprocmask` | 340 | Emulated | — | `sigset_t` size translation |
| `sigpending` | 343 | Translated | `rt_sigpending` | |
| `sigsuspend` | 341 | Translated | `rt_sigsuspend` | |
| `sigaltstack` | 53 | Translated | `sigaltstack` | |
| `sigwait` | 429 | Translated | `rt_sigtimedwait` | |
| `sigtimedwait` | 345 | Translated | `rt_sigtimedwait` | |
| `sigwaitinfo` | 346 | Translated | `rt_sigtimedwait` | |
| `sigqueue` | 456 | Translated | `rt_sigqueueinfo` | |
| `sigfastblock` | 573 | Emulated | — | FreeBSD-specific; returns success |

## Time

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `gettimeofday` | 116 | Translated | `gettimeofday` | |
| `settimeofday` | 122 | Translated | `settimeofday` | |
| `clock_gettime` | 232 | Emulated | — | Clock ID translation (FreeBSD clock IDs differ) |
| `clock_settime` | 233 | Translated | `clock_settime` | |
| `clock_getres` | 234 | Translated | `clock_getres` | |
| `clock_nanosleep` | 244 | Translated | `clock_nanosleep` | |
| `nanosleep` | 240 | Translated | `nanosleep` | |
| `getitimer` | 86 | Translated | `getitimer` | |
| `setitimer` | 83 | Translated | `setitimer` | |
| `utimes` | 138 | Translated | `utimes` | |
| `futimes` | 206 | Translated | `futimesat` | |
| `futimens` | 546 | Translated | `utimensat` | |

## Timers

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `ktimer_create` | 235 | Translated | `timer_create` | |
| `ktimer_delete` | 236 | Translated | `timer_delete` | |
| `ktimer_settime` | 237 | Translated | `timer_settime` | |
| `ktimer_gettime` | 238 | Translated | `timer_gettime` | |
| `ktimer_getoverrun` | 239 | Translated | `timer_getoverrun` | |
| `timerfd_create` | 585 | Translated | `timerfd_create` | |
| `timerfd_gettime` | 586 | Translated | `timerfd_gettime` | |
| `timerfd_settime` | 587 | Translated | `timerfd_settime` | |

## Resource Limits

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `getrlimit` | 194 | Translated | `getrlimit` | |
| `setrlimit` | 195 | Translated | `setrlimit` | |
| `getrusage` | 117 | Translated | `getrusage` | |
| `setpriority` | 96 | Translated | `setpriority` | |
| `getpriority` | 100 | Translated | `getpriority` | |

## Scheduler

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `sched_setparam` | 327 | Translated | `sched_setparam` | |
| `sched_getparam` | 328 | Translated | `sched_getparam` | |
| `sched_setscheduler` | 329 | Translated | `sched_setscheduler` | |
| `sched_getscheduler` | 330 | Translated | `sched_getscheduler` | |
| `sched_yield` | 331 | Translated | `sched_yield` | |
| `sched_get_priority_max` | 332 | Translated | `sched_get_priority_max` | |
| `sched_get_priority_min` | 333 | Translated | `sched_get_priority_min` | |
| `sched_rr_get_interval` | 334 | Translated | `sched_rr_get_interval` | |
| `sched_getcpu` | 581 | Translated | `getcpu` | |

## IPC (Inter-Process Communication)

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `semget` | 221 | Translated | `semget` | |
| `semop` | 222 | Translated | `semop` | |
| `semctl` | 510 | Translated | `semctl` | |
| `msgget` | 225 | Translated | `msgget` | |
| `msgsnd` | 226 | Translated | `msgsnd` | |
| `msgrcv` | 227 | Translated | `msgrcv` | |
| `msgctl` | 511 | Translated | `msgctl` | |
| `shmget` | 231 | Translated | `shmget` | |
| `shmat` | 228 | Translated | `shmat` | |
| `shmdt` | 230 | Translated | `shmdt` | |
| `shmctl` | 512 | Translated | `shmctl` | |

## Threading

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `thr_self` | 432 | Emulated | — | Returns Linux `gettid()` |
| `thr_exit` | 431 | Emulated | — | Calls Linux `exit()` |
| `thr_kill` | 433 | Emulated | — | Calls Linux `tgkill()` |
| `thr_wake` | 443 | Emulated | — | Uses `futex(FUTEX_WAKE)` |
| `rtprio_thread` | 466 | Emulated | — | Returns success (stub) |
| `_umtx_op` | 454 | Emulated | — | Userspace mutex operations via futex |

## CPU Affinity

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `cpuset_getaffinity` | 487 | Emulated | — | Uses Linux `sched_getaffinity` |

## Context

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `getcontext` | 421 | Emulated | — | Returns success (minimal implementation) |

## Jail (FreeBSD Container Isolation)

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `jail` | 338 | Emulated | — | Creates jail; allocates JID, stores config, optional VNET setup |
| `jail_attach` | 436 | Emulated | — | Attaches process via `chroot()` + Linux namespaces |
| `jail_get` | 506 | Emulated | — | Returns jail parameters via iovec |
| `jail_set` | 507 | Emulated | — | Updates jail config, IP addresses, VNET |
| `jail_remove` | 508 | Emulated | — | Removes jail, cleans up networking and namespaces |

## kqueue / kevent

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `kqueue` | 362 | Emulated | — | Creates epoll fd (basic translation) |
| `kevent` | 560 | Emulated | — | Translates to epoll operations (basic) |

## Capsicum (Capability Mode)

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `cap_enter` | 516 | Stub | — | Returns success; no actual sandboxing |
| `cap_getmode` | 517 | Stub | — | Returns "not in capability mode" |
| `cap_rights_limit` | 533 | Stub | — | Returns success |
| `cap_ioctls_limit` | 534 | Stub | — | Returns success |
| `cap_fcntls_limit` | 536 | Stub | — | Returns success |

## sysctl

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `__sysctl` | 202 | Emulated | — | Full sysctl emulation via `freebsd_runtime` |
| `__sysctlbyname` | 570 | Emulated | — | Name-based sysctl lookup |

## Path Configuration

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `pathconf` | 191 | Emulated | — | Returns FreeBSD-compatible path config values |
| `fpathconf` | 192 | Emulated | — | File descriptor variant |
| `lpathconf` | 513 | Emulated | — | Symlink-aware variant |

## Architecture-Specific

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `sysarch` | 165 | Emulated | — | Handles `AMD64_SET_FSBASE` / `AMD64_GET_FSBASE` via `arch_prctl` |

## Miscellaneous

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `__getcwd` | 326 | Translated | `getcwd` | |
| `acct` | 51 | Translated | `acct` | |
| `mount` | 21 | Translated | `mount` | |
| `unmount` | 22 | Translated | `umount2` | |
| `swapon` | 85 | Translated | `swapon` | |
| `swapoff` | 582 | Translated | `swapoff` | |
| `reboot` | 55 | Translated | `reboot` | |
| `quotactl` | 148 | Translated | `quotactl` | |
| `ptrace` | 26 | Translated | `ptrace` | |
| `getrandom` | 563 | Translated | `getrandom` | |
| `copy_file_range` | 569 | Translated | `copy_file_range` | |
| `close_range` | 575 | Translated | `close_range` | |
| `membarrier` | 584 | Translated | `membarrier` | |
| `kcmp` | 588 | Translated | `kcmp` | |
| `posix_fallocate` | 530 | Translated | `fallocate` | |
| `posix_fadvise` | 531 | Translated | `fadvise64` | |
| `getdtablesize` | 89 | Emulated | — | Returns `RLIMIT_NOFILE` current value |
| `yield` | 321 | Emulated | — | Calls `sched_yield()` |

## FreeBSD 15 Additions

| FreeBSD Syscall | Number | Type | Linux Equivalent | Notes |
|-----------------|--------|------|------------------|-------|
| `__realpathat` | 574 | Emulated | — | Resolves real path relative to directory fd |
| `credsync` | 596 | Emulated | — | Returns success (credential synchronization) |

## Explicitly Unsupported

These FreeBSD-specific syscalls have no Linux equivalent and return `ENOSYS`:

| FreeBSD Syscall | Number | Reason |
|-----------------|--------|--------|
| `chflags` | 34 | No Linux equivalent for file flags |
| `fchflags` | 35 | No Linux equivalent |
| `lchflags` | 391 | No Linux equivalent |
| `revoke` | 56 | No Linux equivalent |
| `ktrace` | 45 | FreeBSD-specific tracing (BSDulator uses ptrace) |
| `getlogin` | 49 | FreeBSD login session tracking |
| `setlogin` | 50 | FreeBSD login session tracking |
| `profil` | 44 | Deprecated profiling interface |
| `rtprio` | 166 | FreeBSD real-time priority (use `rtprio_thread` instead) |
| `ntp_adjtime` | 176 | NTP kernel interface |
| `ntp_gettime` | 248 | NTP kernel interface |
| `undelete` | 205 | UFS-specific file undelete |

---

## Summary

| Category | Translated | Emulated | Stub | Unsupported | Total |
|----------|-----------|----------|------|-------------|-------|
| Process Control | 13 | 2 | — | — | 15 |
| File I/O | 35 | 2 | — | — | 37 |
| *at Syscalls | 13 | — | — | — | 13 |
| Stat | 3 | 1 | — | — | 4 |
| User/Group IDs | 14 | 3 | — | — | 17 |
| Memory | 10 | 1 | — | — | 11 |
| Networking | 9 | 7 | — | — | 16 |
| Signals | 7 | 3 | — | — | 10 |
| Time | 9 | 1 | — | — | 10 |
| Timers | 8 | — | — | — | 8 |
| Resource Limits | 5 | — | — | — | 5 |
| Scheduler | 9 | — | — | — | 9 |
| IPC | 11 | — | — | — | 11 |
| Threading | — | 6 | — | — | 6 |
| CPU Affinity | — | 1 | — | — | 1 |
| Context | — | 1 | — | — | 1 |
| Jail | — | 5 | — | — | 5 |
| kqueue/kevent | — | 2 | — | — | 2 |
| Capsicum | — | — | 5 | — | 5 |
| sysctl | — | 2 | — | — | 2 |
| Path Config | — | 3 | — | — | 3 |
| Architecture | — | 1 | — | — | 1 |
| Misc | 14 | 2 | — | — | 16 |
| FreeBSD 15 | — | 2 | — | — | 2 |
| Unsupported | — | — | — | 12 | 12 |
| **Total** | **160** | **45** | **5** | **12** | **222** |

## ABI Translation Notes

Several translated syscalls require argument or return value translation beyond simple number mapping:

- **Open flags**: `O_CREAT`, `O_EXCL`, `O_APPEND`, etc. have different bit values on FreeBSD vs Linux
- **mmap flags/prot**: `MAP_SHARED`, `MAP_PRIVATE`, `PROT_READ`, etc. are translated
- **AT_ flags**: `AT_SYMLINK_NOFOLLOW`, `AT_REMOVEDIR`, etc. differ between systems
- **fcntl commands**: `F_GETFD`, `F_SETFL`, etc. are translated
- **Signal numbers**: FreeBSD and Linux use different signal numbering
- **sockaddr structures**: FreeBSD includes a `sin_len` field that Linux lacks
- **errno values**: Error codes are mapped between FreeBSD and Linux conventions
- **stat structures**: Field layout differences handled in the ABI translation layer
- **sigset_t size**: FreeBSD uses 128-bit signal sets, Linux uses 64-bit
- **Clock IDs**: FreeBSD and Linux clock constants differ for `clock_gettime`
