# Quick Start Guide

Get BSDulator running in 5 minutes.

## 1. Install Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y build-essential iproute2 wget

# Fedora
sudo dnf groupinstall -y "Development Tools" && sudo dnf install -y iproute wget
```

## 2. Build

```bash
git clone https://github.com/dyber-pqc/bsdulator.git
cd bsdulator
make
```

## 3. Download FreeBSD Base System

```bash
./scripts/setup_freebsd_root.sh
```

This downloads ~180 MB of FreeBSD libraries and binaries into `./freebsd-root/`.

## 4. Run FreeBSD Binaries

### Static binaries (no dynamic linker needed)

```bash
./bsdulator ./freebsd-root/rescue/echo "Hello from FreeBSD!"
./bsdulator ./freebsd-root/rescue/ls /
./bsdulator ./freebsd-root/rescue/cat /etc/os-release
```

### Dynamic binaries (use the FreeBSD dynamic linker)

```bash
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/echo "Hello from FreeBSD!"
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/ls -la /
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/sh -c "echo pipes work | cat"
```

## 5. Create a FreeBSD Jail

```bash
# Create a jail with an IP address
sudo ./bsdulator ./freebsd-root/libexec/ld-elf.so.1 \
    ./freebsd-root/usr/sbin/jail -c name=myjail path=./freebsd-root ip4.addr=10.0.0.10 persist

# List running jails
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jls

# Run a command inside the jail
sudo ./bsdulator ./freebsd-root/libexec/ld-elf.so.1 \
    ./freebsd-root/usr/sbin/jexec 1 /bin/sh -c "echo Hello from inside the jail!"

# Remove the jail when done
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jail -r 1
```

## 6. Create a Jail with Virtual Networking

```bash
# Create two networked jails
sudo ./bsdulator ./freebsd-root/libexec/ld-elf.so.1 \
    ./freebsd-root/usr/sbin/jail -c name=web path=./freebsd-root ip4.addr=10.0.0.10 vnet persist

sudo ./bsdulator ./freebsd-root/libexec/ld-elf.so.1 \
    ./freebsd-root/usr/sbin/jail -c name=db path=./freebsd-root ip4.addr=10.0.0.20 vnet persist

# Test connectivity
ping -c 1 10.0.0.10                          # Host -> web jail
ping -c 1 10.0.0.20                          # Host -> db jail
ip netns exec bsdjail_1 ping -c 1 10.0.0.20  # web -> db jail

# List jails with details
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jls jid name ip4.addr path

# Clean up
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jail -r 1
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jail -r 2
```

## Useful Flags

```bash
# Verbose output (see what syscalls are being translated)
./bsdulator -v ./freebsd-root/rescue/ls

# Maximum verbosity (full syscall trace)
./bsdulator -vvv ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/ls

# Print syscall statistics on exit
./bsdulator -s ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/echo test

# Specify a custom FreeBSD root path
./bsdulator -r /path/to/freebsd-root ./freebsd-root/rescue/echo hello
```

## Next Steps

- Read the full [Installation Guide](INSTALL.md) for platform-specific details
- See [architecture.md](architecture.md) for how BSDulator works under the hood
- Check the [roadmap](roadmap.md) for upcoming features
- See [CONTRIBUTING.md](../CONTRIBUTING.md) to get involved
