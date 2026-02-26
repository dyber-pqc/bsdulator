# Versioning Strategy

BSDulator and Lochs follow [Semantic Versioning](https://semver.org/) (SemVer).

## Format

```
MAJOR.MINOR.PATCH
```

- **MAJOR** — Breaking changes to the syscall translation layer, CLI interface, or jail behavior
- **MINOR** — New features (syscalls, Lochs commands, jail capabilities) that are backwards-compatible
- **PATCH** — Bug fixes, documentation updates, and minor improvements

## Current Version

The canonical version is in the `VERSION` file at the repository root. This is the single source of truth.

Version constants in source code should match:

| File | Constant |
|------|----------|
| `VERSION` | Canonical version (plain text) |
| `include/bsdulator.h` | `BSDULATOR_VERSION_MAJOR`, `_MINOR`, `_PATCH` |
| `include/bsdulator/lochs.h` | `LOCHS_VERSION` |
| `CHANGELOG.md` | Latest `## [x.y.z]` entry |

## Pre-1.0

While BSDulator is pre-1.0:

- The API and CLI are not guaranteed stable
- Minor versions may include breaking changes
- Patch versions are strictly non-breaking

## Git Tags

Tags follow the format `v{MAJOR}.{MINOR}.{PATCH}`:

```
v0.3.6
v0.4.0
v1.0.0
```

Pre-release tags use suffixes:

```
v0.4.0-alpha.1
v0.4.0-beta.1
v0.4.0-rc.1
```

## Release Process

1. Update `VERSION` file with the new version
2. Update version constants in `include/bsdulator.h` and `include/bsdulator/lochs.h`
3. Add a changelog entry to `CHANGELOG.md` under `## [x.y.z] - YYYY-MM-DD`
4. Commit: `git commit -m "release: v0.x.y"`
5. Tag: `git tag v0.x.y`
6. Push: `git push origin main --tags`
7. The `release.yml` workflow automatically:
   - Builds release binaries
   - Creates a GitHub Release with changelog notes
   - Builds and pushes a Docker image to `ghcr.io` (non-alpha only)

## Version Bumping Guide

| Change | Bump | Example |
|--------|------|---------|
| New syscall translation | PATCH | 0.3.5 -> 0.3.6 |
| New Lochs CLI command | MINOR | 0.3.6 -> 0.4.0 |
| New jail feature (VNET, etc.) | MINOR | 0.3.6 -> 0.4.0 |
| Bug fix | PATCH | 0.3.6 -> 0.3.7 |
| Breaking CLI change | MAJOR (post-1.0) | 1.0.0 -> 2.0.0 |
| Breaking syscall behavior | MAJOR (post-1.0) | 1.0.0 -> 2.0.0 |
