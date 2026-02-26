## Description

<!-- Describe your changes in detail -->

## Related Issue

<!-- Link to the issue this PR addresses -->
Fixes #

## Type of Change

<!-- Mark relevant options with [x] -->

- [ ] 🐛 Bug fix (non-breaking change that fixes an issue)
- [ ] ✨ New feature (non-breaking change that adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to change)
- [ ] 📚 Documentation update
- [ ] 🔧 Refactoring (no functional changes)
- [ ] 🧪 Tests (adding or updating tests)
- [ ] 🏗️ Infrastructure (CI/CD, build system)

## Component Affected

<!-- Mark relevant options with [x] -->

- [ ] BSDulator core (syscall translation)
- [ ] Lochs CLI
- [ ] Jail management
- [ ] Networking (VNET)
- [ ] Storage (OverlayFS)
- [ ] Lochfile parser
- [ ] lochs.yml compose
- [ ] Documentation
- [ ] Tests
- [ ] CI/CD

## Testing

<!-- Describe the tests you ran -->

- [ ] I have run `./tests/run_tests.sh` and all tests pass
- [ ] I have run `./scripts/check_compat.sh` on my system
- [ ] I have tested the changes manually with FreeBSD binaries

### Test commands used:

```bash
# Add the commands you used to test
./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/echo "test"
```

### Test environment:

- **OS**: 
- **Kernel**: 
- **Compiler**: 

## Checklist

- [ ] My code follows the project's coding style
- [ ] I have added comments for complex code sections
- [ ] I have updated the documentation (if applicable)
- [ ] I have added entries to CHANGELOG.md (if applicable)
- [ ] My changes don't generate new compiler warnings
- [ ] New syscall translations include proper error handling

## Screenshots / Logs

<!-- If applicable, add screenshots or log output -->

## Additional Notes

<!-- Any additional information -->
