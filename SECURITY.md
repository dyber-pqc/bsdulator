# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in BSDulator or Lochs, **please do not open a public issue.** Instead, report it responsibly via email:

**security@dyber.org**

Please include:

- Description of the vulnerability
- Steps to reproduce the issue
- Affected component(s) and version(s)
- Potential impact assessment
- Any suggested fixes (optional but appreciated)

### Response Timeline

| Action | Timeframe |
|--------|-----------|
| Acknowledgment of report | 48 hours |
| Initial assessment | 5 business days |
| Status update to reporter | 10 business days |
| Fix release (critical) | 30 days |
| Fix release (non-critical) | Next scheduled release |

## Scope

The following components are in scope for security reports:

### In Scope

- **Syscall translation layer** — Incorrect or unsafe translation of FreeBSD syscalls to Linux equivalents
- **ptrace interception** — Vulnerabilities in the process tracing and interception logic
- **ELF loader** — Malicious ELF binary handling, buffer overflows, or memory corruption
- **Jail isolation** — Escapes from jail confinement, namespace breakouts, or privilege escalation
- **VNET networking** — Network namespace isolation failures, unauthorized cross-jail communication
- **Lochs container management** — Image handling, OverlayFS storage, or compose file parsing vulnerabilities
- **ABI translation** — Structure translation errors that could lead to memory corruption
- **Path translation** — Directory traversal or path escape vulnerabilities

### Out of Scope

- Vulnerabilities in FreeBSD binaries themselves (report to [FreeBSD Security](https://www.freebsd.org/security/))
- Vulnerabilities in the Linux kernel (report to the appropriate kernel security contact)
- Issues requiring physical access to the machine
- Social engineering attacks
- Denial of service through resource exhaustion when running as root (this is a known requirement)

## Security Considerations

BSDulator has inherent security characteristics that users should be aware of:

### Privileged Operations

- Jail and VNET features require **root/sudo** access
- ptrace usage requires appropriate permissions
- Network namespace management requires CAP_NET_ADMIN
- Users should run unprivileged features without root whenever possible

### Architecture

- BSDulator intercepts syscalls via ptrace — the traced process runs with the caller's privileges
- Jail isolation relies on Linux namespaces (mount, PID, network, UTS) for containment
- Path translation confines FreeBSD binary file access to the specified root directory
- No sandboxing is applied beyond Linux namespace isolation for jail features

### Recommendations

- Run BSDulator with the minimum privileges required for your use case
- Use jail features only in trusted environments
- Keep your Linux kernel updated for namespace security fixes
- Do not run untrusted FreeBSD binaries without reviewing them first
- Use VNET isolation when running multiple jails that should not communicate

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest on `main` | Yes |
| Older commits | Best effort |

As BSDulator is pre-1.0, security fixes are applied to the `main` branch only.

## Credit

We are happy to credit security researchers who responsibly disclose vulnerabilities (unless you prefer to remain anonymous). Let us know your preference when reporting.

## PGP Key

If you need to encrypt your report, request our PGP key by emailing security@dyber.org with the subject line "PGP Key Request".
