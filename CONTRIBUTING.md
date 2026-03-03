# Contributing to Lochs

First off, thank you for considering contributing to Lochs! It's people like you that make Lochs such a great tool for the FreeBSD and Linux communities.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Adding Syscall Support](#adding-syscall-support)
- [Testing](#testing)
- [Documentation](#documentation)
- [Community](#community)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- Linux system (Ubuntu 20.04+, Debian 11+, Fedora 35+, or similar)
- GCC or Clang compiler
- Make
- Git
- Root/sudo access (for jail and networking features)

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/dyber-pqc/bsdulator.git
cd bsdulator

# Check system compatibility
./scripts/check_compat.sh

# Build
make

# Download FreeBSD base system for testing
./scripts/setup_freebsd_root.sh

# Run tests
./tests/run_tests.sh
```

## Development Setup

### Debug Build

For development, use the debug build which includes sanitizers:

```bash
make debug
```

This enables:
- Address sanitizer (ASan)
- Undefined behavior sanitizer (UBSan)
- Debug symbols (`-g3`)
- No optimization (`-O0`)

### Verbose Build

For detailed syscall logging:

```bash
make verbose
```

### Running with Verbose Output

```bash
# Single verbose flag
./bsdulator -v ./freebsd-root/rescue/ls

# Maximum verbosity (syscall trace)
./bsdulator -vvv ./freebsd-root/rescue/ls

# With syscall statistics
./bsdulator -s ./freebsd-root/rescue/ls
```

## Project Structure

```
bsdulator/
├── src/
│   ├── main.c                    # Entry point, CLI parsing
│   ├── interceptor/
│   │   └── interceptor.c         # ptrace syscall interception
│   ├── syscall/
│   │   ├── syscall_table.c       # FreeBSD→Linux syscall mapping
│   │   └── netlink_emul.c        # Netlink socket emulation
│   ├── loader/
│   │   └── elf_loader.c          # FreeBSD ELF detection
│   ├── abi/
│   │   └── abi_translate.c       # ABI structure translation
│   ├── runtime/
│   │   └── freebsd_runtime.c     # sysctl emulation, runtime env
│   ├── jail/
│   │   └── jail.c                # Jail syscalls, VNET, namespaces
│   └── lochs/
│       ├── lochs_main.c          # Lochs CLI entry point
│       ├── lochs_commands.c      # CLI command implementations
│       ├── lochs_images.c        # Image management
│       ├── lochs_compose.c       # lochs.yml compose
│       ├── lochfile_parser.c     # Lochfile parsing
│       ├── lochs_network.c       # Container networking
│       └── lochs_storage.c       # OverlayFS storage
├── include/
│   └── bsdulator/
│       ├── bsdulator.h           # Main header, logging macros
│       ├── syscall.h             # Syscall definitions
│       ├── jail.h                # Jail structures
│       ├── lochs.h               # Lochs CLI structures
│       └── ...
├── scripts/
│   ├── setup_freebsd_root.sh     # Download FreeBSD base
│   └── check_compat.sh           # System compatibility check
├── tests/
│   └── run_tests.sh              # Test suite
└── docs/
    └── *.md                      # Documentation
```

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.yml)
3. Include:
   - Clear description of the issue
   - Steps to reproduce
   - Expected vs actual behavior
   - System information
   - Verbose output (`-vvv` flag)

### Suggesting Features

1. Use the [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.yml)
2. Describe the use case
3. Explain why this would benefit other users

### Requesting Syscall Support

1. Use the [Syscall Request template](.github/ISSUE_TEMPLATE/syscall_request.yml)
2. Identify which FreeBSD application needs it
3. Link to FreeBSD documentation

### Contributing Code

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`./tests/run_tests.sh`)
5. Commit with a descriptive message
6. Push to your fork
7. Open a Pull Request

## Coding Standards

### C Style Guide

- Use C11 standard
- 4 spaces for indentation (no tabs)
- Opening braces on the same line
- Descriptive variable names
- Comment complex logic

```c
// Good
int translate_syscall(int fbsd_syscall, struct syscall_args *args) {
    if (fbsd_syscall < 0 || fbsd_syscall >= FBSD_SYS_MAXSYSCALL) {
        LOG_ERROR("Invalid syscall number: %d", fbsd_syscall);
        return -ENOSYS;
    }
    
    // Translate FreeBSD syscall to Linux equivalent
    int linux_syscall = syscall_table[fbsd_syscall];
    ...
}
```

### Logging

Use the provided logging macros:

```c
LOG_ERROR("Critical error: %s", strerror(errno));
LOG_WARN("Warning: feature not fully implemented");
LOG_INFO("Processing syscall %d", syscall_num);
LOG_DEBUG("Detailed debug info: ptr=%p", ptr);
LOG_TRACE("Very detailed trace info");
```

### Error Handling

- Always check return values
- Use errno appropriately
- Clean up resources on error paths

```c
int fd = open(path, O_RDONLY);
if (fd < 0) {
    LOG_ERROR("Failed to open %s: %s", path, strerror(errno));
    return -errno;
}
```

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style (formatting, etc.)
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `perf`: Performance improvement
- `test`: Adding tests
- `chore`: Maintenance tasks

Examples:
```
feat(syscall): add support for kqueue/kevent emulation
fix(jail): resolve VNET cleanup on jail removal
docs(readme): update installation instructions
```

## Pull Request Process

1. Ensure all tests pass
2. Update documentation if needed
3. Update CHANGELOG.md with your changes
4. Request review from maintainers
5. Address review feedback
6. Squash commits if requested

## Adding Syscall Support

### 1. Find the Syscall Numbers

```c
// FreeBSD: /usr/include/sys/syscall.h
#define SYS_kqueue  362

// Linux: /usr/include/asm/unistd_64.h
#define __NR_epoll_create  213
```

### 2. Add to Syscall Table

In `src/syscall/syscall_table.c`:

```c
// Add translation entry
[FBSD_SYS_kqueue] = {
    .linux_syscall = __NR_epoll_create,
    .handler = emul_kqueue,
    .name = "kqueue",
    .needs_translation = true,
},
```

### 3. Implement Handler (if needed)

```c
static long emul_kqueue(struct syscall_args *args) {
    // Translate FreeBSD kqueue to Linux epoll
    int epfd = syscall(__NR_epoll_create1, 0);
    if (epfd < 0) {
        return -errno;
    }
    
    // Store mapping for later kevent translation
    kqueue_map_add(epfd);
    
    return epfd;
}
```

### 4. Add Tests

```bash
# Test that the new syscall works
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/usr/bin/some_app
```

## Testing

### Running Tests

```bash
# Full test suite
./tests/run_tests.sh

# Quick functionality check
./bsdulator ./freebsd-root/rescue/echo "Hello"
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/ls -la
```

### Adding New Tests

Add test cases to `tests/run_tests.sh`:

```bash
# Test: New feature
echo "Test N: Description"
if ./bsdulator <test_command> 2>&1 | grep -q "expected_output"; then
    pass "Test description"
else
    fail "Test description"
fi
```

## Documentation

- Update README.md for user-facing changes
- Update docs/ for detailed documentation
- Add inline comments for complex code
- Update CHANGELOG.md for all notable changes

## Community

- **GitHub Discussions**: Ask questions and share ideas
- **Issues**: Report bugs and request features
- **Email**: zkleckner@dyber.org for commercial inquiries

## Recognition

Contributors will be recognized in:
- CHANGELOG.md (for each release)
- README.md (Contributors section)
- Release notes

## License

By contributing, you agree that your contributions will be licensed under the project's [Source Available License](LICENSE).

---

Thank you for contributing to Lochs! 🎉
