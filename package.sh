#!/bin/bash
#
# Lochs packaging script
#
# Builds .deb (Debian/Ubuntu) or .rpm (RHEL/Fedora) packages.
#
# Usage:
#   ./package.sh deb          Build .deb package
#   ./package.sh rpm          Build .rpm package
#   ./package.sh              Auto-detect distro and build
#   ./package.sh install      Build + install for current distro
#

set -e

VERSION="0.3.6"
PKG_NAME="lochs"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}==>${NC} $1"; }
ok()    { echo -e "${GREEN}==>${NC} $1"; }
err()   { echo -e "${RED}Error:${NC} $1" >&2; exit 1; }

# Detect distro family
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian|linuxmint|pop) echo "deb" ;;
            fedora|rhel|centos|rocky|alma) echo "rpm" ;;
            *) echo "unknown" ;;
        esac
    elif [ -f /etc/debian_version ]; then
        echo "deb"
    elif [ -f /etc/redhat-release ]; then
        echo "rpm"
    else
        echo "unknown"
    fi
}

build_deb() {
    info "Building .deb package..."

    # Check for dpkg-buildpackage
    if command -v dpkg-buildpackage >/dev/null 2>&1; then
        info "Using dpkg-buildpackage"
        cd "$SCRIPT_DIR"
        dpkg-buildpackage -us -uc -b
        ok "Package built: ../${PKG_NAME}_${VERSION}-1_amd64.deb"
        echo ""
        echo "  Install with:"
        echo "    sudo dpkg -i ../${PKG_NAME}_${VERSION}-1_amd64.deb"
        echo "    sudo apt-get install -f   # fix any missing deps"
        return
    fi

    # Fallback: build manually with fpm
    if command -v fpm >/dev/null 2>&1; then
        info "Using fpm (dpkg-buildpackage not found)"
        cd "$SCRIPT_DIR"
        make clean && make

        fpm -s dir -t deb \
            -n "$PKG_NAME" \
            -v "$VERSION" \
            --description "FreeBSD jail management for Linux" \
            --url "https://lochs.dev" \
            --license "MIT" \
            --maintainer "Zachary Kleckner <zach@lochs.dev>" \
            --depends "libc6" \
            --recommends "socat" \
            --after-install debian/postinst \
            --deb-systemd lochs-dashboard.service \
            bsdulator=/usr/bin/bsdulator \
            lochs=/usr/bin/lochs \
            lochs-dashboard.service=/lib/systemd/system/lochs-dashboard.service \
            docs/api.md=/usr/share/doc/lochs/api.md \
            docs/quickstart.md=/usr/share/doc/lochs/quickstart.md

        ok "Package built: ${PKG_NAME}_${VERSION}_amd64.deb"
        return
    fi

    # Last resort: checkinstall
    if command -v checkinstall >/dev/null 2>&1; then
        info "Using checkinstall (dpkg-buildpackage and fpm not found)"
        cd "$SCRIPT_DIR"
        make clean && make
        sudo checkinstall --pkgname="$PKG_NAME" --pkgversion="$VERSION" \
            --maintainer="zach@lochs.dev" --pkglicense="MIT" \
            --requires="libc6" --nodoc -y make install install-service
        return
    fi

    err "No .deb build tool found. Install one of:
    sudo apt-get install dpkg-dev debhelper    # recommended
    sudo apt-get install checkinstall          # easy alternative
    gem install fpm                            # ruby-based"
}

build_rpm() {
    info "Building .rpm package..."

    if ! command -v rpmbuild >/dev/null 2>&1; then
        # Try fpm
        if command -v fpm >/dev/null 2>&1; then
            info "Using fpm (rpmbuild not found)"
            cd "$SCRIPT_DIR"
            make clean && make

            fpm -s dir -t rpm \
                -n "$PKG_NAME" \
                -v "$VERSION" \
                --description "FreeBSD jail management for Linux" \
                --url "https://lochs.dev" \
                --license "MIT" \
                --maintainer "Zachary Kleckner <zach@lochs.dev>" \
                --depends "glibc" \
                bsdulator=/usr/bin/bsdulator \
                lochs=/usr/bin/lochs \
                lochs-dashboard.service=/lib/systemd/system/lochs-dashboard.service \
                docs/api.md=/usr/share/doc/lochs/api.md

            ok "Package built: ${PKG_NAME}-${VERSION}-1.x86_64.rpm"
            return
        fi

        err "rpmbuild not found. Install with:
    sudo dnf install rpm-build         # Fedora/RHEL
    gem install fpm                    # alternative"
    fi

    info "Using rpmbuild"
    cd "$SCRIPT_DIR"

    # Create rpmbuild tree
    RPMBUILD="$HOME/rpmbuild"
    mkdir -p "$RPMBUILD"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

    # Create source tarball
    TARDIR="${PKG_NAME}-${VERSION}"
    mkdir -p "/tmp/$TARDIR"
    cp -r "$SCRIPT_DIR"/* "/tmp/$TARDIR/"
    tar -czf "$RPMBUILD/SOURCES/${PKG_NAME}-${VERSION}.tar.gz" -C /tmp "$TARDIR"
    rm -rf "/tmp/$TARDIR"

    # Copy spec
    cp "$SCRIPT_DIR/lochs.spec" "$RPMBUILD/SPECS/"

    # Build
    rpmbuild -bb "$RPMBUILD/SPECS/lochs.spec"

    ok "Package built in $RPMBUILD/RPMS/"
    echo ""
    echo "  Install with:"
    echo "    sudo dnf install $RPMBUILD/RPMS/x86_64/${PKG_NAME}-${VERSION}-1*.rpm"
}

do_install() {
    local distro
    distro=$(detect_distro)

    case "$distro" in
        deb)
            build_deb
            info "Installing .deb package..."
            sudo dpkg -i "${SCRIPT_DIR}/../${PKG_NAME}_${VERSION}-1_amd64.deb" 2>/dev/null || \
            sudo dpkg -i "${SCRIPT_DIR}/${PKG_NAME}_${VERSION}_amd64.deb" 2>/dev/null || \
            { info "Falling back to make install"; sudo make -C "$SCRIPT_DIR" install install-service; }
            ;;
        rpm)
            build_rpm
            ;;
        *)
            info "Unknown distro — using make install"
            cd "$SCRIPT_DIR"
            make clean && make
            sudo make install install-service
            ok "Installed to /usr/bin/ via make install"
            ;;
    esac
}

# --- Main ---

case "${1:-auto}" in
    deb)     build_deb ;;
    rpm)     build_rpm ;;
    install) do_install ;;
    auto)
        distro=$(detect_distro)
        case "$distro" in
            deb) build_deb ;;
            rpm) build_rpm ;;
            *)   err "Cannot auto-detect distro. Use: $0 deb|rpm|install" ;;
        esac
        ;;
    *)
        echo "Usage: $0 [deb|rpm|install]"
        echo ""
        echo "  deb      Build .deb package (Debian/Ubuntu)"
        echo "  rpm      Build .rpm package (RHEL/Fedora)"
        echo "  install  Auto-detect, build, and install"
        echo "  (none)   Auto-detect distro and build"
        exit 1
        ;;
esac
