#!/bin/bash
#
# BSDulator - Setup FreeBSD Root Filesystem
# Downloads and extracts FreeBSD base system for testing
#

set -e

FREEBSD_VERSION="14.3"
FREEBSD_ARCH="amd64"
BASE_FILE="base.txz"

# Try multiple mirrors
MIRRORS=(
    "https://download.freebsd.org/ftp/releases/${FREEBSD_ARCH}/${FREEBSD_VERSION}-RELEASE"
    "https://ftp.freebsd.org/pub/FreeBSD/releases/${FREEBSD_ARCH}/${FREEBSD_VERSION}-RELEASE"
    "https://ftp1.us.freebsd.org/pub/FreeBSD/releases/${FREEBSD_ARCH}/${FREEBSD_VERSION}-RELEASE"
)

# Directory for FreeBSD root
FREEBSD_ROOT="${1:-./freebsd-root}"

echo "================================================"
echo "BSDulator - FreeBSD Root Filesystem Setup"
echo "================================================"
echo ""
echo "FreeBSD Version: ${FREEBSD_VERSION}"
echo "Architecture:    ${FREEBSD_ARCH}"
echo "Target:          ${FREEBSD_ROOT}"
echo ""

# Check if already exists
if [ -d "${FREEBSD_ROOT}/bin" ]; then
    echo "FreeBSD root already exists at ${FREEBSD_ROOT}"
    echo "Remove it first if you want to re-download."
    exit 0
fi

# Create directory
mkdir -p "${FREEBSD_ROOT}"
cd "${FREEBSD_ROOT}"

# Download base.txz if not present or too small
if [ ! -f "${BASE_FILE}" ] || [ $(stat -c%s "${BASE_FILE}" 2>/dev/null || echo 0) -lt 1000000 ]; then
    rm -f "${BASE_FILE}" 2>/dev/null || true
    
    echo "Downloading FreeBSD ${FREEBSD_VERSION} base system (~180MB)..."
    echo ""
    
    DOWNLOAD_SUCCESS=0
    for MIRROR in "${MIRRORS[@]}"; do
        echo "Trying mirror: ${MIRROR}/${BASE_FILE}"
        
        if command -v curl &> /dev/null; then
            if curl -L -f -# -o "${BASE_FILE}" "${MIRROR}/${BASE_FILE}"; then
                # Check file size (should be > 100MB)
                SIZE=$(stat -c%s "${BASE_FILE}" 2>/dev/null || echo 0)
                if [ "$SIZE" -gt 100000000 ]; then
                    echo "Download successful (${SIZE} bytes)"
                    DOWNLOAD_SUCCESS=1
                    break
                else
                    echo "Downloaded file too small, trying next mirror..."
                    rm -f "${BASE_FILE}"
                fi
            fi
        elif command -v wget &> /dev/null; then
            if wget -q --show-progress -O "${BASE_FILE}" "${MIRROR}/${BASE_FILE}"; then
                SIZE=$(stat -c%s "${BASE_FILE}" 2>/dev/null || echo 0)
                if [ "$SIZE" -gt 100000000 ]; then
                    echo "Download successful (${SIZE} bytes)"
                    DOWNLOAD_SUCCESS=1
                    break
                else
                    echo "Downloaded file too small, trying next mirror..."
                    rm -f "${BASE_FILE}"
                fi
            fi
        fi
    done
    
    if [ "$DOWNLOAD_SUCCESS" -eq 0 ]; then
        echo ""
        echo "ERROR: Failed to download from all mirrors."
        echo ""
        echo "You can manually download base.txz from:"
        echo "  https://download.freebsd.org/releases/amd64/"
        echo ""
        echo "Look for the latest version (e.g., 14.0-RELEASE, 14.1-RELEASE)"
        echo "and download base.txz to: ${FREEBSD_ROOT}/"
        echo ""
        echo "Then run this script again."
        exit 1
    fi
fi

# Verify file before extraction
echo ""
echo "Verifying download..."
if ! file "${BASE_FILE}" | grep -q "XZ compressed"; then
    echo "ERROR: Downloaded file is not a valid XZ archive."
    echo "File type: $(file ${BASE_FILE})"
    echo ""
    echo "The file may be an error page. Contents:"
    head -c 500 "${BASE_FILE}"
    echo ""
    rm -f "${BASE_FILE}"
    exit 1
fi

# Extract
echo ""
echo "Extracting base system (this may take a few minutes)..."
tar -xJf "${BASE_FILE}"

echo ""
echo "================================================"
echo "FreeBSD root filesystem ready at: $(pwd)"
echo ""
echo "Contents:"
ls -la

echo ""
echo "Static binaries for testing:"
echo "  ./freebsd-root/rescue/echo"
echo "  ./freebsd-root/rescue/ls"
echo "  ./freebsd-root/rescue/cat"
echo "  ./freebsd-root/rescue/sh"
echo ""
echo "The /rescue directory contains statically linked binaries"
echo "that don't require FreeBSD dynamic libraries."
echo ""
echo "Test with:"
echo "  ./bsdulator ./freebsd-root/rescue/echo Hello World"
echo "================================================"
