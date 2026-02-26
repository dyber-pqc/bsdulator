# Examples

This directory contains example files for BSDulator and Lochs.

## Files

- **`Lochfile`** — Example Lochfile (Dockerfile equivalent) for building a custom FreeBSD jail image
- **`TestLochfile`** — Minimal Lochfile used for testing the build system
- **`lochs.yml`** — Example compose file for multi-service deployments
- **`hello.sh`** — Simple test script used by the example Lochfile
- **`minimal`** — Pre-compiled minimal FreeBSD ELF binary for testing BSDulator

## Usage

### Run the example Lochfile

```bash
lochs build -f examples/Lochfile -t myapp:latest
lochs run --name myapp myapp:latest
```

### Run the compose example

```bash
lochs compose -f examples/lochs.yml up
```

### Test with the minimal binary

```bash
./bsdulator examples/minimal
```
