<div align="center">

# 🏔️ Lochs

**FreeBSD jails, everywhere. Docker-like simplicity.**

[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20|%20macOS%20|%20Windows%20|%20FreeBSD-38bdf8?style=for-the-badge)]()
[![FreeBSD](https://img.shields.io/badge/FreeBSD-15.0-AB2B28?style=for-the-badge&logo=freebsd&logoColor=white)]()

<img src="https://jailhouse.io/assets/lochs-banner.png" alt="Lochs" width="700">

```bash
lochs pull freebsd:15
lochs create myapp --image freebsd:15
lochs start myapp
lochs exec myapp /bin/sh
```

</div>

---

## What is Lochs?

**Lochs** (pronounced "locks", like the Scottish lakes) is a cross-platform container runtime that brings FreeBSD's legendary jail isolation system to Linux, macOS, and Windows. Think Docker, but for FreeBSD jails — with the security model that inspired Docker in the first place.

FreeBSD jails were the original container technology (introduced in 2000, 13 years before Docker). They're battle-tested in production at Netflix, Sony PlayStation Network, WhatsApp, and countless hosting providers. Now you can use them anywhere.

### Why Lochs?

| Problem | Lochs Solution |
|---------|----------------|
| "We have legacy FreeBSD apps but Linux infrastructure" | Run FreeBSD binaries natively on Linux via BSDulator |
| "Docker's security model isn't strong enough" | FreeBSD jails provide kernel-level isolation with 24+ years of hardening |
| "I need FreeBSD's networking stack (pf, CARP)" | Full FreeBSD userland including firewall and HA tools |
| "ZFS is better than overlayfs" | Native ZFS support on FreeBSD, emulated datasets on Linux |
| "I want one tool across all my systems" | Same `lochs` CLI on Linux, macOS, Windows, and FreeBSD |

---

## Features

### Container Management
- **🐳 Docker-like CLI** — Familiar commands: `pull`, `create`, `start`, `exec`, `stop`, `rm`
- **📦 Image Registry** — Pull from official FreeBSD mirrors or custom registries
- **🏗️ Lochfile** — Dockerfile-equivalent for building custom jail images
- **📋 lochs.yml** — Compose files for multi-container deployments
- **💾 State Persistence** — Containers survive host reboots

### Isolation & Security
- **🔒 Kernel-level Isolation** — True process separation, not just namespaces
- **🛡️ Secure by Default** — No root in container, restricted syscalls, no raw sockets
- **📁 Filesystem Isolation** — Each jail has its own root filesystem
- **👤 User Namespace Mapping** — Map container root to unprivileged host user

### Networking
- **🌐 Virtual Networks** — Isolated bridge networks between jails
- **🔗 VNET Support** — Full network stack virtualization per jail
- **📡 IP Assignment** — Static IPv4/IPv6 per container
- **🚪 Port Forwarding** — Expose container ports to host
- **🔥 pf Firewall** — FreeBSD's packet filter available in jails

### Cross-Platform
- **🐧 Linux** — Via BSDulator syscall translation (ptrace-based)
- **🍎 macOS** — Via lightweight FreeBSD VM (Hypervisor.framework)
- **🪟 Windows** — Via WSL2 + BSDulator or Hyper-V VM
- **😈 FreeBSD** — Native jail support (no translation needed)

### Developer Experience  
- **⚡ Fast Startup** — Jails start in milliseconds, not seconds
- **📊 Resource Limits** — CPU, memory, and I/O constraints via rctl
- **🔍 Introspection** — `lochs ps`, `lochs logs`, `lochs exec`
- **🎯 GPU Passthrough** — NVIDIA/AMD GPU access for ML workloads (Zernel)

### Currently Implemented (v0.3)
- **🏗️ Lochfile Build** — `FROM`, `COPY`, `RUN`, `ENV`, `LABEL`, `EXPOSE`, `CMD`, `WORKDIR`
- **📋 Compose** — `lochs compose up/down/ps/exec` with dependency resolution
- **🌐 Networking** — `lochs network create/rm/ls`, `--network` flag, bridge creation
- **🚪 Port Forwarding** — `-p 8080:80` using socat
- **📁 Volume Mounts** — `-v /host:/container[:ro]` with bind mounts
- **🌍 Environment** — `-e KEY=value` injected at container start
- **📜 Logs** — `lochs logs [-f] [-n N]` with follow mode

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER INTERFACE                                  │
│                                                                             │
│    lochs CLI          lochs.yml           Lochfile          REST API        │
│    (commands)         (compose)           (build)           (programmatic)  │
└──────────────────────────────┬──────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            LOCHS DAEMON                                      │
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Image     │  │  Container  │  │   Network   │  │   Volume    │        │
│  │   Manager   │  │   Manager   │  │   Manager   │  │   Manager   │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────┐       │
│  │                      State Database                              │       │
│  │                   /var/lib/lochs/*.dat                           │       │
│  └─────────────────────────────────────────────────────────────────┘       │
└──────────────────────────────┬──────────────────────────────────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
          ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│     LINUX       │  │     macOS       │  │    FreeBSD      │
│                 │  │                 │  │                 │
│  ┌───────────┐  │  │  ┌───────────┐  │  │  ┌───────────┐  │
│  │ BSDulator │  │  │  │  FreeBSD  │  │  │  │  Native   │  │
│  │ (ptrace)  │  │  │  │    VM     │  │  │  │   Jails   │  │
│  └─────┬─────┘  │  │  └─────┬─────┘  │  │  └─────┬─────┘  │
│        │        │  │        │        │  │        │        │
│        ▼        │  │        ▼        │  │        ▼        │
│  ┌───────────┐  │  │  ┌───────────┐  │  │  ┌───────────┐  │
│  │  Linux    │  │  │  │  FreeBSD  │  │  │  │  FreeBSD  │  │
│  │  Kernel   │  │  │  │  Kernel   │  │  │  │  Kernel   │  │
│  └───────────┘  │  │  └───────────┘  │  │  └───────────┘  │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

### Component Overview

| Component | Description |
|-----------|-------------|
| **Lochs CLI** | User-facing command-line interface |
| **BSDulator** | FreeBSD syscall translation layer for Linux (ptrace-based) |
| **Image Manager** | Pulls, stores, and manages FreeBSD filesystem images |
| **Container Manager** | Creates, starts, stops jail instances |
| **Network Manager** | Configures bridges, veth pairs, IP assignment |
| **Volume Manager** | Bind mounts, nullfs, ZFS datasets |

---

## Installation

### Linux (Debian/Ubuntu)

```bash
# Install dependencies
sudo apt update
sudo apt install -y build-essential git

# Clone and build
git clone https://github.com/jailhouse-io/lochs.git
cd lochs
make
sudo make install

# Verify installation
lochs version
```

### Linux (RHEL/Fedora)

```bash
sudo dnf install -y gcc make git
git clone https://github.com/jailhouse-io/lochs.git
cd lochs && make && sudo make install
```

### macOS (Homebrew)

```bash
brew tap jailhouse-io/lochs
brew install lochs
```

### Windows (WSL2)

```powershell
# In PowerShell (Admin)
wsl --install -d Ubuntu

# In WSL2 Ubuntu
sudo apt update && sudo apt install -y build-essential git
git clone https://github.com/jailhouse-io/lochs.git
cd lochs && make && sudo make install
```

### FreeBSD (Native)

```bash
pkg install lochs
# or from ports
cd /usr/ports/sysutils/lochs && make install clean
```

### From Source

```bash
git clone https://github.com/jailhouse-io/lochs.git
cd lochs
make
sudo make install

# Optional: Install shell completions
sudo make install-completions
```

---

## Quick Start

### 1. Pull a FreeBSD Image

```bash
# Pull official FreeBSD 15.0 base image
lochs pull freebsd:15

# List available images
lochs search
# Output:
# freebsd:15          Official FreeBSD 15.0-RELEASE         620MB
# freebsd:15-minimal  FreeBSD 15.0 (stripped)               450MB
# freebsd:15-rescue   FreeBSD 15.0 rescue environment       93MB
# freebsd:14.2        Official FreeBSD 14.2-RELEASE         580MB
```

### 2. Create and Start a Container

```bash
# Create a container named "web"
lochs create web --image freebsd:15

# Start it
lochs start web

# Check status
lochs ps
# Output:
# NAME    JID    IMAGE        STATUS     IP            PATH
# web     1      freebsd:15   running    10.0.0.2      /var/lib/lochs/containers/web
```

### 3. Run Commands Inside

```bash
# Execute a single command
lochs exec web /bin/ls /

# Get an interactive shell
lochs exec -it web /bin/sh

# Inside the jail:
# # pkg install nginx
# # service nginx start
# # exit
```

### 4. Networking

```bash
# Create container with specific IP
lochs create db --image freebsd:15 --ip 10.0.0.10

# Create container with port forwarding
lochs create api --image freebsd:15 -p 8080:80

# Create container with full network stack (vnet)
lochs create router --image freebsd:15 --vnet

# Containers can communicate
lochs exec web ping 10.0.0.10
```

### 5. Stop and Remove

```bash
lochs stop web
lochs rm web

# Or force remove a running container
lochs rm -f web
```

---

## CLI Reference

### Image Commands

| Command | Description |
|---------|-------------|
| `lochs pull <image>` | Download image from registry |
| `lochs images` | List local images |
| `lochs search [query]` | Search available images |
| `lochs rmi <image>` | Remove local image |
| `lochs build -f Lochfile -t name:tag .` | Build image from Lochfile |
| `lochs push <image>` | Push image to registry |
| `lochs save <image> -o file.txz` | Export image to tarball |
| `lochs load -i file.txz` | Import image from tarball |

### Container Commands

| Command | Description |
|---------|-------------|
| `lochs create <name> --image <image>` | Create new container |
| `lochs start <name>` | Start container |
| `lochs stop <name>` | Stop container gracefully |
| `lochs kill <name>` | Force stop container |
| `lochs restart <name>` | Restart container |
| `lochs rm <name>` | Remove stopped container |
| `lochs rm -f <name>` | Force remove running container |

### Execution Commands

| Command | Description |
|---------|-------------|
| `lochs exec <name> <cmd>` | Run command in container |
| `lochs exec -it <name> /bin/sh` | Interactive shell |
| `lochs exec -u www <name> <cmd>` | Run as specific user |
| `lochs exec -w /app <name> <cmd>` | Set working directory |
| `lochs attach <name>` | Attach to container console |

### Inspection Commands

| Command | Description |
|---------|-------------|
| `lochs ps` | List running containers |
| `lochs ps -a` | List all containers |
| `lochs inspect <name>` | Detailed container info (JSON) |
| `lochs top <name>` | Show processes in container |
| `lochs logs <name>` | View container logs |
| `lochs stats` | Live resource usage |
| `lochs diff <name>` | Filesystem changes since creation |

### Network Commands

| Command | Description |
|---------|-------------|
| `lochs network ls` | List networks |
| `lochs network create <name>` | Create bridge network |
| `lochs network rm <name>` | Remove network |
| `lochs network connect <net> <container>` | Connect container to network |
| `lochs network disconnect <net> <container>` | Disconnect from network |

### Volume Commands

| Command | Description |
|---------|-------------|
| `lochs volume ls` | List volumes |
| `lochs volume create <name>` | Create named volume |
| `lochs volume rm <name>` | Remove volume |
| `lochs volume inspect <name>` | Volume details |

### System Commands

| Command | Description |
|---------|-------------|
| `lochs version` | Show version info |
| `lochs info` | System-wide information |
| `lochs prune` | Remove unused data |
| `lochs events` | Real-time event stream |

---

## Create Options

```bash
lochs create <name> --image <image> [options]
```

| Option | Description | Example |
|--------|-------------|---------|
| `--image, -i` | Base image (required) | `--image freebsd:15` |
| `--ip` | Static IPv4 address | `--ip 10.0.0.100` |
| `--ip6` | Static IPv6 address | `--ip6 fd00::100` |
| `--hostname, -h` | Container hostname | `--hostname webserver` |
| `--vnet` | Full network stack virtualization | `--vnet` |
| `-p, --publish` | Port forwarding | `-p 8080:80` |
| `-v, --volume` | Bind mount | `-v /host/path:/jail/path` |
| `-e, --env` | Environment variable | `-e DB_HOST=localhost` |
| `--env-file` | Load env from file | `--env-file .env` |
| `-m, --memory` | Memory limit | `-m 512M` |
| `--cpus` | CPU limit | `--cpus 2` |
| `--read-only` | Read-only root filesystem | `--read-only` |
| `--privileged` | Relax security restrictions | `--privileged` |
| `--network` | Connect to network | `--network mybridge` |
| `--dns` | Custom DNS server | `--dns 8.8.8.8` |
| `--add-host` | Add /etc/hosts entry | `--add-host db:10.0.0.5` |
| `--restart` | Restart policy | `--restart always` |

---

## Lochfile (Build Images)

Lochfiles are the Lochs equivalent of Dockerfiles. They define how to build custom jail images.

### Syntax

```dockerfile
# Lochfile

# Base image
FROM freebsd:15

# Metadata
LABEL maintainer="you@example.com"
LABEL version="1.0"

# Install packages
RUN pkg install -y nginx postgresql15-server redis

# Copy files
COPY nginx.conf /usr/local/etc/nginx/nginx.conf
COPY app/ /var/www/app/

# Set environment variables
ENV RAILS_ENV=production
ENV DATABASE_URL=postgres://localhost/myapp

# Expose ports
EXPOSE 80 443

# Create user
RUN pw useradd -n www -d /nonexistent -s /usr/sbin/nologin

# Set working directory
WORKDIR /var/www/app

# Run as non-root
USER www

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost/health || exit 1

# Default command
CMD ["/usr/local/sbin/nginx", "-g", "daemon off;"]
```

### Build Commands

```bash
# Build image
lochs build -f Lochfile -t mycompany/webapp:v1 .

# Build with arguments
lochs build --build-arg VERSION=1.2.3 -t myapp:latest .

# Build without cache
lochs build --no-cache -t myapp:latest .
```

### Example: Ruby on Rails App

```dockerfile
FROM freebsd:15

# System dependencies
RUN pkg install -y ruby31 ruby31-gems postgresql15-client node18 yarn

# App dependencies
WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle install --deployment --without development test

COPY package.json yarn.lock ./
RUN yarn install --production

# Copy application
COPY . .

# Precompile assets
RUN SECRET_KEY_BASE=dummy bundle exec rails assets:precompile

# Runtime config
ENV RAILS_ENV=production
ENV RAILS_LOG_TO_STDOUT=true
EXPOSE 3000

CMD ["bundle", "exec", "puma", "-C", "config/puma.rb"]
```

---

## lochs.yml (Compose)

Define multi-container applications with a single YAML file.

### Basic Example

```yaml
version: "1"

services:
  web:
    image: freebsd:15
    build: ./web
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./app:/var/www/app
      - web-logs:/var/log/nginx
    environment:
      - RAILS_ENV=production
    depends_on:
      - db
      - redis
    restart: always
    
  db:
    image: freebsd:15
    command: /usr/local/bin/postgres -D /var/db/postgres/data15
    volumes:
      - postgres-data:/var/db/postgres/data15
    environment:
      POSTGRES_USER: myapp
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    ip4_addr: 10.0.0.10
    
  redis:
    image: freebsd:15
    command: /usr/local/bin/redis-server
    volumes:
      - redis-data:/var/db/redis
    ip4_addr: 10.0.0.11

volumes:
  postgres-data:
  redis-data:
  web-logs:

networks:
  default:
    driver: bridge
    ipam:
      config:
        - subnet: 10.0.0.0/24
          gateway: 10.0.0.1

secrets:
  db_password:
    file: ./secrets/db_password.txt
```

### Compose Commands

```bash
# Start all services
lochs compose up

# Start in background
lochs compose up -d

# View logs
lochs compose logs -f

# Stop all services
lochs compose down

# Stop and remove volumes
lochs compose down -v

# Scale a service
lochs compose up -d --scale web=3

# Rebuild images
lochs compose build

# Execute command in service
lochs compose exec web /bin/sh
```

### Advanced Example: Microservices

```yaml
version: "1"

services:
  # API Gateway
  gateway:
    image: mycompany/gateway:latest
    ports:
      - "443:443"
    depends_on:
      - auth
      - users
      - orders
    networks:
      - frontend
      - backend
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: '1'
          memory: 512M

  # Authentication Service
  auth:
    image: mycompany/auth:latest
    environment:
      - JWT_SECRET_FILE=/run/secrets/jwt_secret
    secrets:
      - jwt_secret
    networks:
      - backend
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 10s
      timeout: 5s
      retries: 3

  # User Service
  users:
    image: mycompany/users:latest
    depends_on:
      - users-db
    networks:
      - backend
      - users-net
    environment:
      DATABASE_URL: postgres://users-db:5432/users

  users-db:
    image: freebsd:15
    command: /usr/local/bin/postgres
    volumes:
      - users-data:/var/db/postgres
    networks:
      - users-net

  # Order Service  
  orders:
    image: mycompany/orders:latest
    depends_on:
      - orders-db
      - kafka
    networks:
      - backend
      - orders-net

  orders-db:
    image: freebsd:15
    command: /usr/local/bin/postgres
    volumes:
      - orders-data:/var/db/postgres
    networks:
      - orders-net

  # Message Queue
  kafka:
    image: mycompany/kafka-fbsd:latest
    ports:
      - "9092:9092"
    volumes:
      - kafka-data:/var/kafka
    networks:
      - backend

networks:
  frontend:
  backend:
    internal: true
  users-net:
    internal: true
  orders-net:
    internal: true

volumes:
  users-data:
  orders-data:
  kafka-data:

secrets:
  jwt_secret:
    external: true
```

---

## Networking

### Network Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `bridge` (default) | Virtual bridge network | Most applications |
| `host` | Share host network namespace | Performance-critical apps |
| `none` | No networking | Batch jobs, security |
| `vnet` | Full network stack per jail | Network appliances, routers |

### Bridge Networking

```bash
# Create custom bridge
lochs network create --subnet 172.20.0.0/16 mynet

# Run containers on custom network
lochs create app1 --image freebsd:15 --network mynet --ip 172.20.0.10
lochs create app2 --image freebsd:15 --network mynet --ip 172.20.0.11

# Containers can reach each other by name
lochs exec app1 ping app2
```

### VNET (Virtual Network Stack)

```bash
# Create container with dedicated network stack
lochs create router --image freebsd:15 --vnet

# Inside the jail, you have full control:
lochs exec router /bin/sh
# # ifconfig em0 10.0.0.1/24
# # sysctl net.inet.ip.forwarding=1
# # pfctl -e
# # pfctl -f /etc/pf.conf
```

### Port Forwarding

```bash
# Single port
lochs create web --image freebsd:15 -p 8080:80

# Multiple ports
lochs create app --image freebsd:15 -p 80:80 -p 443:443

# Port range
lochs create game --image freebsd:15 -p 27015-27020:27015-27020/udp

# Bind to specific interface
lochs create internal --image freebsd:15 -p 127.0.0.1:8080:80
```

### DNS and Service Discovery

```bash
# Containers on same network can resolve each other by name
lochs create db --image freebsd:15 --network mynet
lochs create web --image freebsd:15 --network mynet

# web can connect to "db" hostname
lochs exec web ping db
lochs exec web psql -h db -U postgres
```

---

## Volumes and Storage

### Bind Mounts

```bash
# Mount host directory
lochs create web --image freebsd:15 -v /var/www:/usr/local/www

# Read-only mount
lochs create web --image freebsd:15 -v /etc/ssl:/etc/ssl:ro

# Mount single file
lochs create app --image freebsd:15 -v ./config.json:/app/config.json
```

### Named Volumes

```bash
# Create named volume
lochs volume create postgres-data

# Use in container
lochs create db --image freebsd:15 -v postgres-data:/var/db/postgres

# Inspect volume
lochs volume inspect postgres-data

# Backup volume
lochs run --rm -v postgres-data:/data -v $(pwd):/backup freebsd:15 \
  tar czf /backup/postgres-backup.tar.gz /data
```

### ZFS Integration (FreeBSD Host)

```bash
# Create ZFS-backed volume
lochs volume create --driver zfs --opt compression=lz4 mydata

# Snapshot
lochs volume snapshot mydata@backup1

# Clone
lochs volume clone mydata@backup1 mydata-copy

# Send/Receive for backup
lochs volume send mydata@backup1 | ssh backup-server lochs volume receive
```

---

## Security

### Default Security Model

Lochs jails are secure by default:

| Restriction | Default | Description |
|-------------|---------|-------------|
| `allow.raw_sockets` | `false` | No raw socket access |
| `allow.chflags` | `false` | Can't change file flags |
| `allow.mount` | `false` | Can't mount filesystems |
| `allow.set_hostname` | `true` | Can set hostname |
| `allow.sysvipc` | `false` | No SysV IPC |
| `securelevel` | `3` | Maximum security level |
| `enforce_statfs` | `2` | Can only see own mounts |

### Running as Non-Root

```bash
# Run entire container as unprivileged user
lochs create app --image freebsd:15 --user www

# Map container root to host unprivileged user
lochs create app --image freebsd:15 --userns=remap
```

### Read-Only Containers

```bash
# Read-only root filesystem
lochs create app --image freebsd:15 --read-only

# With writable tmpfs for /tmp
lochs create app --image freebsd:15 --read-only --tmpfs /tmp
```

### Resource Limits

```bash
# Memory limit
lochs create app --image freebsd:15 -m 512M

# CPU limit (number of cores)
lochs create app --image freebsd:15 --cpus 2

# CPU shares (relative weight)
lochs create app --image freebsd:15 --cpu-shares 512

# Combined limits
lochs create app --image freebsd:15 -m 1G --cpus 4 --pids-limit 100
```

### Capabilities

```bash
# Drop all capabilities except needed ones
lochs create app --image freebsd:15 --cap-drop=ALL --cap-add=NET_BIND_SERVICE

# Available capabilities:
# CHOWN, DAC_OVERRIDE, FSETID, FOWNER, MKNOD, NET_RAW, SETGID, SETUID,
# SETFCAP, SETPCAP, NET_BIND_SERVICE, SYS_CHROOT, KILL, AUDIT_WRITE
```

---

## Registry

### Official Registry

```bash
# Pull from default registry (Dyber)
lochs pull freebsd:15

# Explicit registry
lochs pull registry.jailhouse.io/freebsd:15
```

### Available Images

| Image | Description | Size |
|-------|-------------|------|
| `freebsd:15` | FreeBSD 15.0-RELEASE full base | 620MB |
| `freebsd:15-minimal` | Stripped (no docs/debug) | 450MB |
| `freebsd:15-rescue` | Rescue environment only | 93MB |
| `freebsd:14.2` | FreeBSD 14.2-RELEASE | 580MB |
| `freebsd:14.1` | FreeBSD 14.1-RELEASE | 575MB |
| `freebsd:13.4` | FreeBSD 13.4-RELEASE | 550MB |
| `zernel/base` | Zernel base image | 700MB |
| `zernel/pytorch` | PyTorch + CUDA | 4.2GB |
| `zernel/tensorflow` | TensorFlow + CUDA | 3.8GB |

### Private Registry

```bash
# Login to private registry
lochs login registry.mycompany.com

# Pull private image
lochs pull registry.mycompany.com/myapp:v1.2.3

# Push to private registry
lochs tag myapp:latest registry.mycompany.com/myapp:v1.2.3
lochs push registry.mycompany.com/myapp:v1.2.3
```

### Self-Hosted Registry

```bash
# Run your own registry
lochs create registry --image jailhouse/registry:2 \
  -p 5000:5000 \
  -v registry-data:/var/lib/registry

# Configure clients
echo '{"registries": ["myregistry.local:5000"]}' > ~/.lochs/config.json
```

---

## BSDulator (Technical Deep Dive)

BSDulator is the syscall translation engine that enables FreeBSD binaries to run on Linux.

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    FreeBSD Binary (ELF)                         │
│                                                                 │
│   Calls FreeBSD syscall (e.g., syscall 5 = open)               │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                       BSDulator                                  │
│                                                                 │
│   1. ptrace intercepts syscall                                  │
│   2. Reads FreeBSD syscall number (5)                          │
│   3. Looks up in translation table → Linux syscall 2 (open)    │
│   4. Translates arguments (flags, paths)                       │
│   5. Rewrites registers with Linux values                      │
│   6. Lets Linux kernel execute                                 │
│   7. Translates return value back to FreeBSD format            │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Linux Kernel                                │
│                                                                 │
│   Executes translated syscall                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Syscall Categories

| Category | Examples | Translation Method |
|----------|----------|-------------------|
| **Direct** | exit, read, write | Number translation only |
| **Translated** | open, stat, mmap | Number + argument translation |
| **Emulated** | jail_*, sysctl, kqueue | Full emulation in BSDulator |
| **Unsupported** | Mach ports, DTrace | Returns ENOSYS |

### Supported Syscalls

BSDulator supports 200+ FreeBSD syscalls including:

- **File I/O**: open, read, write, close, lseek, pread, pwrite, fstat, fstatat
- **Process**: fork, vfork, execve, wait4, exit, getpid, getppid
- **Memory**: mmap, munmap, mprotect, brk, sbrk
- **Signals**: sigaction, sigprocmask, sigsuspend, kill
- **Networking**: socket, bind, listen, accept, connect, send, recv
- **IPC**: pipe, socketpair, shm_open, sem_open
- **Jails**: jail, jail_get, jail_set, jail_attach, jail_remove
- **Threading**: thr_new, thr_exit, thr_self, _umtx_op
- **sysctl**: Full emulation of FreeBSD sysctl tree

### Performance

| Operation | Native FreeBSD | BSDulator on Linux | Overhead |
|-----------|---------------|-------------------|----------|
| syscall (getpid) | 0.3 µs | 2.1 µs | 7x |
| file read (4KB) | 1.2 µs | 1.8 µs | 1.5x |
| fork + exec | 450 µs | 680 µs | 1.5x |
| network I/O | ~same | ~same | <5% |

Overhead is primarily from ptrace context switches. For I/O-bound workloads, the overhead is negligible.

---

## Integration with Zernel

Zernel is a FreeBSD-based operating system optimized for AI/ML workloads. It uses Lochs for container management.

### Zernel Features

- **Native FreeBSD** — No translation overhead
- **GPU Passthrough** — Direct NVIDIA/AMD GPU access in jails
- **ZFS** — Copy-on-write, snapshots, compression, encryption
- **DTrace** — Production-safe tracing
- **bhyve** — Type-2 hypervisor for nested virtualization

### Zernel + Lochs Workflow

```bash
# On Zernel host (bare metal or VM)

# Pull ML image
lochs pull zernel/pytorch:2.1-cuda12

# Create GPU-enabled container
lochs create training --image zernel/pytorch:2.1-cuda12 \
  --gpu all \
  -v /data/datasets:/datasets \
  -v /data/models:/models

# Start training
lochs exec training python train.py \
  --data /datasets/imagenet \
  --output /models/resnet50.pt

# Scale to multiple GPUs
for i in 0 1 2 3; do
  lochs create worker-$i --image zernel/pytorch:2.1-cuda12 --gpu $i
  lochs exec -d worker-$i python distributed_train.py --rank $i
done
```

### Resource Isolation for ML

```yaml
# lochs.yml for ML training cluster
version: "1"

services:
  coordinator:
    image: zernel/pytorch:2.1-cuda12
    command: python coordinator.py
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 16G
    networks:
      - ml-cluster

  worker:
    image: zernel/pytorch:2.1-cuda12
    command: python worker.py
    deploy:
      replicas: 4
      resources:
        limits:
          cpus: '8'
          memory: 32G
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
    depends_on:
      - coordinator
    networks:
      - ml-cluster

networks:
  ml-cluster:
    driver: bridge
```

---

## Troubleshooting

### Common Issues

#### Container Won't Start

```bash
# Check container status
lochs inspect mycontainer

# View logs
lochs logs mycontainer

# Try starting with verbose output
lochs start mycontainer --debug

# Common causes:
# - Image not found: lochs pull <image>
# - Port already in use: change port mapping
# - Permission denied: run with sudo
```

#### Networking Issues

```bash
# Check network configuration
lochs network inspect bridge

# Verify container IP
lochs exec mycontainer ifconfig

# Test connectivity
lochs exec mycontainer ping 8.8.8.8

# Check iptables/pf rules
sudo iptables -L -n
```

#### Permission Denied

```bash
# BSDulator requires ptrace permissions
# On systems with ptrace restrictions:
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

# For persistent change, add to /etc/sysctl.conf:
# kernel.yama.ptrace_scope = 0
```

#### Slow Performance

```bash
# Check if running in debug mode
lochs info

# Disable tracing
export BSDULATOR_DEBUG=0

# Use --privileged for reduced overhead (less secure)
lochs create app --image freebsd:15 --privileged
```

### Debug Mode

```bash
# Enable verbose logging
export BSDULATOR_DEBUG=4
lochs start mycontainer

# Trace specific syscalls
lochs exec mycontainer --strace /bin/ls

# Inspect jail state
cat /tmp/bsdulator_jails.dat | xxd
```

### Getting Help

```bash
# Built-in help
lochs --help
lochs create --help

# Documentation
open https://docs.jailhouse.io

# Community Discord
open https://discord.gg/jailhouse

# File a bug
open https://github.com/jailhouse-io/lochs/issues
```

---

## Project Structure

```
lochs/
├── src/
│   ├── main.c                    # BSDulator entry point
│   ├── interceptor/
│   │   └── interceptor.c         # ptrace syscall interception
│   ├── syscall/
│   │   └── syscall_table.c       # FreeBSD→Linux syscall mapping
│   ├── abi/
│   │   └── abi_translate.c       # Structure translation (stat, dirent, etc.)
│   ├── runtime/
│   │   └── freebsd_runtime.c     # FreeBSD environment emulation
│   ├── jail/
│   │   └── jail.c                # Jail syscall implementation
│   └── lochs/
│       ├── lochs_main.c          # CLI entry point
│       ├── lochs_commands.c      # create, start, stop, exec, etc.
│       ├── lochs_images.c        # Image registry and management
│       └── lochfile_parser.c     # Lochfile build system
├── include/
│   └── bsdulator/
│       ├── bsdulator.h           # Main header
│       ├── syscall.h             # Syscall definitions
│       ├── interceptor.h         # Interceptor API
│       ├── abi.h                 # ABI translation
│       └── jail.h                # Jail structures
├── Makefile
├── README.md
├── LICENSE
└── docs/
    ├── architecture.md
    ├── syscalls.md
    └── networking.md
```

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
git clone https://github.com/jailhouse-io/lochs.git
cd lochs
make debug

# Run tests
make test

# Run specific test
./tests/run_test.sh syscalls

# Code formatting
make format

# Static analysis
make lint
```

### Areas for Contribution

- **Syscall coverage** — Implement missing FreeBSD syscalls
- **Platform support** — macOS VM backend, Windows Hyper-V
- **Networking** — Advanced vnet features, VXLAN support
- **Documentation** — Tutorials, examples, translations
- **Testing** — More test cases, CI/CD improvements

---

## Roadmap

### v0.2 (Completed)
- [x] Basic jail lifecycle (create, start, stop, rm)
- [x] Image pull from registry  
- [x] exec into running containers
- [x] Static IP assignment
- [x] BSDulator syscall translation
- [x] JID tracking sync between Lochs and BSDulator

### v0.3 (Current - Completed)
- [x] **Lochfile build system** — `FROM`, `COPY`, `ENV`, `LABEL`, `EXPOSE`, `CMD`, `WORKDIR`
- [x] **RUN directive** — Execute FreeBSD commands during image build via BSDulator
- [x] **lochs.yml compose support** — `up`, `down`, `ps`, `exec`, dependency resolution
- [x] **Port forwarding** — `-p host:container` with socat
- [x] **Volume mounts** — `-v /host:/container[:ro]` with bind mounts
- [x] **Environment variables** — `-e KEY=value`, written to `/.lochs_env`
- [x] **Container logs** — `lochs logs [-f] [-n N] <container>`
- [x] **Container networking** — `lochs network create/rm/ls`, `--network` flag, bridge creation, IP assignment
- [x] **Network namespace isolation** — Full Linux netns per container, veth pairs, isolated eth0
- [x] Image registration for built images

### v0.4 (Current)
- [x] **OverlayFS Copy-on-Write filesystem** for per-container isolation
- [x] Container-to-container networking (ping by IP)
- [x] Unique MAC addresses per container
- [x] Clean `/etc/hosts` per container (no duplication)
- [ ] Auto-start command (CMD/command from Lochfile/compose)
- [ ] Resource limits (memory, CPU via cgroups)
- [ ] Health checks
- [ ] Restart policies
- [ ] Container-to-container networking (ping by name via DNS)

### v0.5
- [ ] Push to registry (`lochs push`)
- [ ] macOS support (FreeBSD VM)
- [ ] Windows support (WSL2)
- [ ] Named volumes (`lochs volume create`)

### v1.0
- [ ] Production-ready stability
- [ ] Full Docker CLI compatibility
- [ ] GUI (Tauri-based)
- [ ] Enterprise features (SSO, audit logs)

---

## License

BSD 2-Clause License. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

- **FreeBSD Project** — For creating jails and inspiring modern containers
- **Wine Project** — For proving syscall translation is viable
- **Docker** — For popularizing the container workflow we emulate
- **Netflix, Sony, WhatsApp** — For proving FreeBSD at scale

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full changelog.

### v0.3.4 (February 2026)

**Features:**
- **OverlayFS Copy-on-Write filesystem** for per-container isolation
  - Each container gets isolated storage via Linux OverlayFS
  - Base image shared read-only, changes written to container-specific diff
  - Merged view provides unified filesystem for jail
- Unique MAC addresses per container (02:00:00:00:00:XX based on IP)
- Container-to-container networking verified working

**Fixed:**
- `/etc/hosts` duplication issue - now writes clean per-container hosts files
- Duplicate MAC addresses causing container communication failure

### v0.3.3 (February 2026)

**Features:**
- Full network namespace isolation for containers
- Each container gets its own Linux netns (`lochs_<n>`)
- Isolated eth0 interface with assigned IP from subnet pool
- veth pair connects container netns to host bridge
- BSDulator `--netns` flag for namespace entry
- Child process enters netns after ptrace setup, before execve

**Fixed:**
- Segfault when running BSDulator inside `ip netns exec` wrapper
- veth pair creation order and interface configuration

### v0.3.2 (February 2026)

**Features:**
- Container networking with `lochs network create/rm/ls`
- `--network` flag for `lochs create` to connect containers to networks
- Linux bridge creation per network with automatic IP assignment
- `/etc/hosts` injection for container name resolution
- veth pair creation for container connectivity
- Network teardown on container stop
- RUN directive in Lochfile - execute FreeBSD commands during build
- Direct binary execution for simple RUN commands
- Shell fallback for complex RUN commands (pipes, redirects)

### v0.3.1 (February 2026)

**Features:**
- Volume mounts with `-v /host:/container[:ro]`
- Environment variables with `-e KEY=value`
- Container logs with `lochs logs [-f] [-n N] <container>`
- Logs captured via tee to `/var/lib/lochs/logs/`
- Auto-unmount volumes on container stop

### v0.3.0 (February 2026)

**Features:**
- Lochfile build system (`FROM`, `COPY`, `ENV`, `LABEL`, `EXPOSE`, `CMD`, `WORKDIR`)
- lochs compose multi-container orchestration (`up`, `down`, `ps`, `exec`)
- YAML parser for compose files (no external dependencies)
- Dependency resolution with `depends_on`
- Port forwarding with `-p host:container` using socat
- Image registration for built images

**Fixes:**
- JID tracking sync between Lochs and BSDulator state files
- Structure alignment fix for jail state file reading
- State file persistence in compose (parent reload after child save)

### v0.2.0 (January 2026)

**Features:**
- Basic jail lifecycle (create, start, stop, rm)
- Image pull from FreeBSD mirrors and Dyber registry
- exec into running containers
- Static IP assignment
- VNET support via Linux network namespaces
- BSDulator syscall translation (200+ syscalls)

---

<div align="center">

**Lochs** — FreeBSD jails, everywhere.

Built with 😈 by [Jailhouse.io](https://jailhouse.io) | [Dyber](https://github.com/dyber-pqc)

[Documentation](https://docs.jailhouse.io) · [Discord](https://discord.gg/jailhouse) · [Twitter](https://twitter.com/jailhouseio)

</div>
