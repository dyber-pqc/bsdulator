# Lochs Dashboard REST API

The Lochs dashboard exposes a REST API on port 8420 (default).
All responses are JSON. Mutations use `POST` or `DELETE`.

## Authentication

When the dashboard starts, it generates a bearer token and prints it
to the console (also saved to `/var/lib/lochs/dashboard.token`).
Include it in every request:

```
Authorization: Bearer <token>
```

### POST /api/auth

Validate a token (login).

```bash
curl -X POST http://localhost:8420/api/auth \
  -H 'Content-Type: application/json' \
  -d '{"token":"<token>"}'
```

**Response:** `{"ok":true}` on success, `401` on failure.

---

## System

### GET /api/system

```bash
curl http://localhost:8420/api/system -H "Authorization: Bearer $TOKEN"
```

```json
{
  "version": "0.5.0",
  "containers_total": 3,
  "containers_running": 1,
  "containers_stopped": 1,
  "containers_created": 1,
  "images_total": 2,
  "networks_total": 1,
  "volumes_total": 0
}
```

---

## Containers

### GET /api/containers

List all containers.

```bash
curl http://localhost:8420/api/containers -H "Authorization: Bearer $TOKEN"
```

### GET /api/containers/\<name\>

Get a single container's details.

```bash
curl http://localhost:8420/api/containers/myapp -H "Authorization: Bearer $TOKEN"
```

### POST /api/containers

Create a new container.

```bash
curl -X POST http://localhost:8420/api/containers \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"web","image":"freebsd-base:14","ports":"8080:80","memory":"256m","start":"true"}'
```

| Field    | Required | Description                          |
|----------|----------|--------------------------------------|
| name     | yes      | Container name                       |
| image    | yes      | Image name                           |
| ports    | no       | Comma-separated `host:container`     |
| memory   | no       | Memory limit (e.g. `256m`, `1g`)     |
| cpus     | no       | CPU millicores                       |
| pids     | no       | PID limit                            |
| env      | no       | Comma-separated `KEY=value` pairs    |
| start    | no       | `"true"` to auto-start after create  |

### POST /api/containers/\<name\>/start

```bash
curl -X POST http://localhost:8420/api/containers/web/start \
  -H "Authorization: Bearer $TOKEN"
```

### POST /api/containers/\<name\>/stop

```bash
curl -X POST http://localhost:8420/api/containers/web/stop \
  -H "Authorization: Bearer $TOKEN"
```

### POST /api/containers/\<name\>/restart

```bash
curl -X POST http://localhost:8420/api/containers/web/restart \
  -H "Authorization: Bearer $TOKEN"
```

### POST /api/containers/\<name\>/rm

```bash
curl -X POST http://localhost:8420/api/containers/web/rm \
  -H "Authorization: Bearer $TOKEN"
```

### POST /api/containers/\<name\>/exec

Execute a command inside a running container.

```bash
curl -X POST http://localhost:8420/api/containers/web/exec \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"cmd":"uname -a"}'
```

**Response:** `{"ok":true,"output":"FreeBSD 14.0 ..."}`

---

## Images

### GET /api/images

List all local images.

```bash
curl http://localhost:8420/api/images -H "Authorization: Bearer $TOKEN"
```

### POST /api/images/pull

Pull an image from the registry.

```bash
curl -X POST http://localhost:8420/api/images/pull \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"image":"freebsd-base:14"}'
```

### DELETE /api/images/\<repo:tag\>

Remove a local image.

```bash
curl -X DELETE http://localhost:8420/api/images/freebsd-base:14 \
  -H "Authorization: Bearer $TOKEN"
```

---

## Networks

### GET /api/networks

List all networks.

```bash
curl http://localhost:8420/api/networks -H "Authorization: Bearer $TOKEN"
```

### POST /api/networks

Create a network.

```bash
curl -X POST http://localhost:8420/api/networks \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"mynet","subnet":"10.99.0.0/24"}'
```

### DELETE /api/networks/\<name\>

Remove a network.

```bash
curl -X DELETE http://localhost:8420/api/networks/mynet \
  -H "Authorization: Bearer $TOKEN"
```

---

## Volumes

### GET /api/volumes

List all named volumes.

```bash
curl http://localhost:8420/api/volumes -H "Authorization: Bearer $TOKEN"
```

### POST /api/volumes

Create a volume.

```bash
curl -X POST http://localhost:8420/api/volumes \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"data"}'
```

### DELETE /api/volumes/\<name\>

Remove a volume.

```bash
curl -X DELETE http://localhost:8420/api/volumes/data \
  -H "Authorization: Bearer $TOKEN"
```

---

## Logs

### GET /api/logs/\<name\>

Get the last 200 log lines for a container.

```bash
curl http://localhost:8420/api/logs/web -H "Authorization: Bearer $TOKEN"
```

```json
{
  "container": "web",
  "lines": ["2024-01-15 Starting...", "..."],
  "total_lines": 42
}
```

### GET /api/logs/\<name\>/download

Download the full log file as plain text.

```bash
curl -O http://localhost:8420/api/logs/web/download \
  -H "Authorization: Bearer $TOKEN"
```

---

## Stats

### GET /api/stats/\<name\>

Get current resource usage (cgroup-based).

```bash
curl http://localhost:8420/api/stats/web -H "Authorization: Bearer $TOKEN"
```

```json
{
  "container": "web",
  "cpu_usage_usec": 12345678,
  "memory_bytes": 67108864,
  "memory_limit_bytes": 268435456,
  "swap_bytes": 0,
  "pids": 5,
  "pids_limit": 100
}
```

### GET /api/stats/\<name\>/history

Get time-series resource history (ring buffer, ~6 min at 3s polling).

```bash
curl http://localhost:8420/api/stats/web/history -H "Authorization: Bearer $TOKEN"
```

```json
{
  "container": "web",
  "points": [
    {"t":1705000000,"cpu":123456,"mem":67108864,"pids":5},
    {"t":1705000003,"cpu":234567,"mem":67108864,"pids":5}
  ],
  "count": 120
}
```

---

## Build

### POST /api/build

Build an image from Lochfile content.

```bash
curl -X POST http://localhost:8420/api/build \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"content":"FROM freebsd-base:14\nRUN pkg install -y nginx","tag":"my-nginx:latest"}'
```

**Response:** `{"ok":true,"output":"Step 1/2: FROM freebsd-base:14\n..."}`
