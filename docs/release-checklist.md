# Release Checklist

Use this checklist when preparing a new BSDulator/Lochs release.

## Pre-Release

### 1. Verify Tests Pass

```bash
# Build clean
make clean && make

# Run test suite
make test

# Run with verbose tracing to spot regressions
./bsdulator -vvv ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/echo "smoke test"
./bsdulator -vvv ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/ls -la /
./bsdulator -vvv ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/sh -c "echo pipes | cat"
```

### 2. Test Jail Functionality (requires sudo)

```bash
# Create jail
sudo ./bsdulator ./freebsd-root/libexec/ld-elf.so.1 \
    ./freebsd-root/usr/sbin/jail -c name=release-test path=./freebsd-root ip4.addr=10.0.0.50 vnet persist

# List and verify
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jls jid name ip4.addr path

# Execute in jail
sudo ./bsdulator ./freebsd-root/libexec/ld-elf.so.1 \
    ./freebsd-root/usr/sbin/jexec 1 /bin/sh -c "echo jail works"

# Network connectivity
ping -c 1 10.0.0.50

# Clean up
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/sbin/jail -r 1
```

### 3. Test Lochs CLI

```bash
./lochs version
./lochs images
./lochs ps
```

### 4. Test Debug Build

```bash
make clean && make debug
./bsdulator ./freebsd-root/rescue/echo "debug build works"
make clean && make
```

### 5. Verify Docker Build

```bash
docker build -t bsdulator:test .
```

## Version Bump

### 6. Determine Version Number

Refer to [versioning.md](versioning.md) for bump rules:

- Bug fix: bump PATCH (0.3.6 -> 0.3.7)
- New feature: bump MINOR (0.3.6 -> 0.4.0)
- Breaking change: bump MAJOR (0.3.6 -> 1.0.0)

### 7. Update VERSION File

```bash
echo "0.X.Y" > VERSION
```

### 8. Update Source Version Constants

In `include/bsdulator.h`:
```c
#define BSDULATOR_VERSION_MAJOR 0
#define BSDULATOR_VERSION_MINOR X
#define BSDULATOR_VERSION_PATCH Y
```

In `include/bsdulator/lochs.h`:
```c
#define LOCHS_VERSION "0.X.Y"
```

### 9. Update CHANGELOG.md

Move items from `[Unreleased]` into a new version section:

```markdown
## [Unreleased]

## [0.X.Y] - YYYY-MM-DD

### Added
- New feature description

### Changed
- Changed behavior description

### Fixed
- Bug fix description
```

Follow [Keep a Changelog](https://keepachangelog.com/) format. Categories:
- **Added** — new features
- **Changed** — changes to existing functionality
- **Deprecated** — soon-to-be removed features
- **Removed** — removed features
- **Fixed** — bug fixes
- **Security** — vulnerability fixes

Also update the version summary table at the bottom of CHANGELOG.md.

## Release

### 10. Commit

```bash
git add VERSION include/bsdulator.h include/bsdulator/lochs.h CHANGELOG.md
git commit -m "release: v0.X.Y"
```

### 11. Tag

```bash
git tag v0.X.Y
```

For pre-releases:
```bash
git tag v0.X.Y-alpha.1
git tag v0.X.Y-beta.1
git tag v0.X.Y-rc.1
```

### 12. Push

```bash
git push origin main --tags
```

This triggers `.github/workflows/release.yml` which:
- Builds release binaries (`bsdulator`, `lochs`)
- Strips binaries
- Creates a tarball: `bsdulator-v0.X.Y-linux-amd64.tar.gz`
- Generates SHA256 checksum
- Extracts changelog for release notes
- Creates a GitHub Release
- Builds and pushes Docker image to `ghcr.io` (non-alpha only)

## Post-Release

### 13. Verify GitHub Release

- [ ] Release appears at https://github.com/dyber-pqc/bsdulator/releases
- [ ] Tarball and checksum are attached
- [ ] Release notes match CHANGELOG entry
- [ ] Docker image is pushed (check `ghcr.io/dyber-pqc/bsdulator:0.X.Y`)

### 14. Update lochs.dev Install Script (if needed)

If the install script references a hardcoded version, update and redeploy:

```bash
# Edit scripts/install.sh if version is pinned
# Redeploy to Cloudflare Pages
wrangler pages deploy /path/to/site --project-name lochs-dev --branch production
```

### 15. Announce

- [ ] Post to GitHub Discussions
- [ ] Notify Discord server
- [ ] Update dyber.org/community if major release
