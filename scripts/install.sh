#!/bin/bash
#
# Lochs Installer
# https://lochs.dev/install.sh
#
# Usage: curl -fsSL https://lochs.dev/install.sh | sudo bash
#

set -euo pipefail

# Configuration
REPO="dyber-pqc/bsdulator"
INSTALL_DIR="/usr/local/bin"
FREEBSD_ROOT="/opt/lochs/freebsd-root"
FREEBSD_VERSION="14.2"
FREEBSD_ARCH="amd64"
BASE_URL="https://download.freebsd.org/releases/${FREEBSD_ARCH}/${FREEBSD_VERSION}-RELEASE"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${BLUE}==>${NC} ${BOLD}$1${NC}"; }
ok()    { echo -e "${GREEN}  ✓${NC} $1"; }
warn()  { echo -e "${YELLOW}  ⚠${NC} $1"; }
error() { echo -e "${RED}  ✗${NC} $1"; exit 1; }

# Detect OS and architecture
detect_system() {
    OS=$(uname -s)
    ARCH=$(uname -m)

    if [ "$OS" != "Linux" ]; then
        error "Lochs requires Linux. Detected: $OS"
    fi

    if [ "$ARCH" != "x86_64" ]; then
        error "Lochs requires x86_64. Detected: $ARCH"
    fi

    if [ "$(id -u)" -ne 0 ]; then
        error "This installer must be run as root (use sudo)"
    fi

    # Detect package manager
    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
    elif command -v pacman &>/dev/null; then
        PKG_MGR="pacman"
    elif command -v apk &>/dev/null; then
        PKG_MGR="apk"
    else
        PKG_MGR="unknown"
    fi
}

# Install system dependencies
install_deps() {
    info "Installing dependencies..."

    case "$PKG_MGR" in
        apt)
            apt-get update -qq
            apt-get install -y -qq build-essential iproute2 wget ca-certificates >/dev/null 2>&1
            ;;
        dnf)
            dnf install -y -q gcc make iproute wget ca-certificates >/dev/null 2>&1
            ;;
        pacman)
            pacman -Sy --noconfirm --quiet base-devel iproute2 wget >/dev/null 2>&1
            ;;
        apk)
            apk add --quiet build-base iproute2 wget ca-certificates >/dev/null 2>&1
            ;;
        *)
            warn "Unknown package manager. Please ensure gcc, make, iproute2, and wget are installed."
            ;;
    esac

    ok "Dependencies installed"
}

# Download and build BSDulator + Lochs from latest release or source
install_binaries() {
    info "Installing BSDulator engine and Lochs CLI..."

    # Try to download pre-built release first
    LATEST_TAG=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/' || echo "")

    if [ -n "$LATEST_TAG" ]; then
        TARBALL_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/bsdulator-${LATEST_TAG}-linux-amd64.tar.gz"
        TMPDIR=$(mktemp -d)

        if wget -qO "${TMPDIR}/release.tar.gz" "$TARBALL_URL" 2>/dev/null; then
            tar -xzf "${TMPDIR}/release.tar.gz" -C "$TMPDIR"
            install -m 755 "${TMPDIR}"/bsdulator-*/bsdulator "$INSTALL_DIR/bsdulator"
            install -m 755 "${TMPDIR}"/bsdulator-*/lochs "$INSTALL_DIR/lochs"
            rm -rf "$TMPDIR"
            ok "BSDulator engine installed (${LATEST_TAG})"
            ok "Lochs CLI installed"
            return
        fi

        rm -rf "$TMPDIR"
    fi

    # Fall back to building from source
    warn "No pre-built release found, building from source..."

    TMPDIR=$(mktemp -d)
    cd "$TMPDIR"
    wget -qO source.tar.gz "https://github.com/${REPO}/archive/refs/heads/main.tar.gz"
    tar -xzf source.tar.gz
    cd bsdulator-main
    make -j"$(nproc)" >/dev/null 2>&1
    strip bsdulator lochs 2>/dev/null || true
    install -m 755 bsdulator "$INSTALL_DIR/bsdulator"
    install -m 755 lochs "$INSTALL_DIR/lochs"
    cd /
    rm -rf "$TMPDIR"

    ok "BSDulator engine installed (built from source)"
    ok "Lochs CLI installed"
}

# Download FreeBSD base system
fetch_freebsd_base() {
    info "Fetching FreeBSD ${FREEBSD_VERSION}-RELEASE base system..."

    if [ -d "$FREEBSD_ROOT" ] && [ -f "$FREEBSD_ROOT/libexec/ld-elf.so.1" ]; then
        ok "FreeBSD base already present at $FREEBSD_ROOT"
        return
    fi

    mkdir -p "$FREEBSD_ROOT"

    TMPDIR=$(mktemp -d)
    wget -qO "${TMPDIR}/base.txz" "${BASE_URL}/base.txz" || error "Failed to download FreeBSD base"
    tar -xf "${TMPDIR}/base.txz" -C "$FREEBSD_ROOT"
    rm -rf "$TMPDIR"

    ok "FreeBSD ${FREEBSD_VERSION}-RELEASE base fetched"
}

# Configure environment
configure() {
    info "Configuring..."

    # Set default BSDULATOR_ROOT
    mkdir -p /etc/lochs
    cat > /etc/lochs/lochs.conf <<EOF
# Lochs configuration
BSDULATOR_ROOT=${FREEBSD_ROOT}
FREEBSD_VERSION=${FREEBSD_VERSION}
EOF

    # Create profile.d entry for environment
    cat > /etc/profile.d/lochs.sh <<'EOF'
export BSDULATOR_ROOT=/opt/lochs/freebsd-root
EOF

    ok "Configuration written to /etc/lochs/lochs.conf"
}

# Verify installation
verify() {
    info "Verifying installation..."

    if command -v bsdulator &>/dev/null; then
        ok "bsdulator is in PATH"
    else
        warn "bsdulator not found in PATH (installed to $INSTALL_DIR)"
    fi

    if command -v lochs &>/dev/null; then
        ok "lochs is in PATH"
    else
        warn "lochs not found in PATH (installed to $INSTALL_DIR)"
    fi

    if [ -f "$FREEBSD_ROOT/libexec/ld-elf.so.1" ]; then
        ok "FreeBSD base system present"
    else
        warn "FreeBSD base system not found at $FREEBSD_ROOT"
    fi
}

# Print summary
summary() {
    echo ""
    echo -e "${GREEN}${BOLD}Lochs installed successfully!${NC}"
    echo ""
    echo "  Get started:"
    echo ""
    echo "    lochs run --name myapp freebsd:15"
    echo "    lochs exec myapp /bin/sh"
    echo ""
    echo "  Documentation:  https://lochs.dev"
    echo "  Discord:        https://discord.gg/km3VGfUW"
    echo "  Community:      https://www.dyber.org/community"
    echo ""
}

# Main
main() {
    echo ""
    echo -e "${BOLD}Lochs Installer${NC}"
    echo -e "FreeBSD containers for Linux — ${BLUE}https://lochs.dev${NC}"
    echo ""

    detect_system
    install_deps
    install_binaries
    fetch_freebsd_base
    configure
    verify
    summary
}

main "$@"
