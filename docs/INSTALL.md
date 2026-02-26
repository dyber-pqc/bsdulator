# Installation Guide

## System Requirements

| Requirement | Details |
|-------------|---------|
| **OS** | Linux (kernel 3.8+) |
| **Architecture** | x86_64 only |
| **Compiler** | GCC or Clang with C11 support |
| **Privileges** | Root/sudo for jail and networking features |
| **Disk Space** | ~10 MB (binaries) + ~180 MB (FreeBSD root filesystem) |

### Supported Platforms

| Platform | Status | Notes |
|----------|--------|-------|
| Ubuntu 20.04+ | Fully supported | Primary development platform |
| Debian 11+ | Fully supported | |
| Fedora 35+ | Fully supported | |
| WSL2 | Fully supported | Requires WSL2 (not WSL1) |
| Arch Linux | Supported | |
| Alpine Linux | Supported | Use `musl`-compatible build |

## Quick Install

```bash
git clone https://github.com/dyber-pqc/bsdulator.git
cd bsdulator
./scripts/check_compat.sh
make
./scripts/setup_freebsd_root.sh
```

## Platform-Specific Instructions

### Ubuntu / Debian

```bash
# Install build dependencies
sudo apt-get update
sudo apt-get install -y build-essential iproute2 wget ca-certificates

# Clone and build
git clone https://github.com/dyber-pqc/bsdulator.git
cd bsdulator
make

# Download FreeBSD base system (~180 MB)
./scripts/setup_freebsd_root.sh

# Verify installation
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/echo "Hello from FreeBSD!"
```

### Fedora / RHEL / CentOS

```bash
# Install build dependencies
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y iproute wget ca-certificates

# Clone and build
git clone https://github.com/dyber-pqc/bsdulator.git
cd bsdulator
make

# Download FreeBSD base system
./scripts/setup_freebsd_root.sh
```

### Arch Linux

```bash
# Install build dependencies
sudo pacman -S base-devel iproute2 wget

# Clone and build
git clone https://github.com/dyber-pqc/bsdulator.git
cd bsdulator
make

# Download FreeBSD base system
./scripts/setup_freebsd_root.sh
```

### Alpine Linux

```bash
# Install build dependencies
apk add build-base iproute2 wget ca-certificates

# Clone and build
git clone https://github.com/dyber-pqc/bsdulator.git
cd bsdulator
make

# Download FreeBSD base system
./scripts/setup_freebsd_root.sh
```

### WSL2 (Windows Subsystem for Linux)

BSDulator requires WSL2. WSL1 does not support the Linux namespaces needed for jail features.

```bash
# Verify you are on WSL2
wsl.exe -l -v

# Then follow the Ubuntu/Debian instructions above
sudo apt-get update
sudo apt-get install -y build-essential iproute2 wget ca-certificates

git clone https://github.com/dyber-pqc/bsdulator.git
cd bsdulator
make
./scripts/setup_freebsd_root.sh
```

**WSL2 notes:**
- Networking features (VNET, bridge) work fully under WSL2
- If `ptrace_scope` is restricted, run: `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`

## Building from Source

### Standard Build

```bash
make
```

Produces optimized (`-O2`) `bsdulator` and `lochs` binaries in the project root.

### Debug Build

```bash
make debug
```

Enables AddressSanitizer, UndefinedBehaviorSanitizer, debug symbols (`-g3`), and disables optimization (`-O0`). Use this for development and bug reporting.

### Verbose Build

```bash
make verbose
```

Enables all logging output (`-DBSD_VERBOSE`). Useful for tracing syscall translation behavior.

### Install System-Wide

```bash
sudo make install
```

Installs `bsdulator` and `lochs` to `/usr/local/bin/`.

To remove:

```bash
sudo make uninstall
```

## Docker

```bash
# Build the image
docker build -t bsdulator .

# Run with a FreeBSD root filesystem
docker run --privileged -v /path/to/freebsd-root:/opt/bsdulator/freebsd-root bsdulator \
    ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/echo "Hello"
```

**Note:** Jail and VNET features require `--privileged` for namespace access.

## FreeBSD Root Filesystem

BSDulator needs a FreeBSD base system to provide the libraries and binaries it runs.

### Automatic Setup

```bash
./scripts/setup_freebsd_root.sh
```

This downloads and extracts the FreeBSD 14 base system (~180 MB) into `./freebsd-root/`.

### Manual Setup

If you prefer to set it up manually:

1. Download the FreeBSD base tarball from https://download.freebsd.org/
2. Extract to a directory:
   ```bash
   mkdir -p freebsd-root
   tar -xf base.txz -C freebsd-root
   ```
3. Point BSDulator at it:
   ```bash
   ./bsdulator -r /path/to/freebsd-root ./freebsd-root/bin/echo "Hello"
   # Or use the environment variable
   export BSDULATOR_ROOT=/path/to/freebsd-root
   ```

## Verifying Your Installation

### Compatibility Check

```bash
./scripts/check_compat.sh
```

This checks your kernel version, architecture, namespace support, ptrace scope, required commands, and networking capabilities.

### Basic Functionality Test

```bash
# Static binary
./bsdulator ./freebsd-root/rescue/echo "Hello from FreeBSD (static)"

# Dynamic binary
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/echo "Hello from FreeBSD (dynamic)"

# Shell
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/sh -c "echo working | cat"
```

### Jail Functionality Test (requires sudo)

```bash
# Create a jail
sudo ./bsdulator ./freebsd-root/libexec/ld-elf.so.1 \
    ./freebsd-root/usr/sbin/jail -c name=test path=./freebsd-root ip4.addr=10.0.0.1 persist

# List jails
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jls

# Clean up
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jail -r 1
```

### Full Test Suite

```bash
make test
```

## Troubleshooting

### ptrace permission denied

```
Error: PTRACE_TRACEME failed
```

Your system may restrict ptrace. Fix with:

```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

To make it permanent, add `kernel.yama.ptrace_scope = 0` to `/etc/sysctl.d/99-bsdulator.conf`.

### Namespace operations fail

Jail and VNET features require root privileges and kernel namespace support. Ensure:

- You are running with `sudo`
- Your kernel has `CONFIG_NAMESPACES` enabled (all major distros do)
- You are on WSL2 if using Windows (WSL1 lacks namespace support)

### FreeBSD binary segfaults

Try running with verbose output to diagnose:

```bash
./bsdulator -vvv ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/failing-binary
```

Common causes:
- Missing FreeBSD shared libraries — re-run `./scripts/setup_freebsd_root.sh`
- Unimplemented syscall — check output for "unhandled syscall" messages and file an issue

### Build errors

Ensure you have a C11-compatible compiler:

```bash
gcc --version   # Need GCC 4.7+
clang --version # Need Clang 3.1+
```
