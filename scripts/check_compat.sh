#!/bin/bash
#
# BSDulator Compatibility Check Script
# Verifies system requirements for running BSDulator with full jail support
#
# Usage: ./scripts/check_compat.sh
#

set +e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASS=0
FAIL=0
WARN=0

print_header() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          BSDulator Compatibility Check                       ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

check_pass() {
    echo -e "  ${GREEN}✓${NC} $1"
    ((PASS++))
}

check_fail() {
    echo -e "  ${RED}✗${NC} $1"
    ((FAIL++))
}

check_warn() {
    echo -e "  ${YELLOW}⚠${NC} $1"
    ((WARN++))
}

check_info() {
    echo -e "  ${BLUE}ℹ${NC} $1"
}

# ============================================================================
# System Checks
# ============================================================================

check_os() {
    echo -e "${BLUE}[System]${NC}"
    
    # Check if Linux
    if [[ "$(uname -s)" != "Linux" ]]; then
        check_fail "Not running Linux (found: $(uname -s))"
        echo "       BSDulator requires Linux for ptrace and namespace support"
        return 1
    fi
    check_pass "Running Linux"
    
    # Check architecture
    ARCH=$(uname -m)
    if [[ "$ARCH" != "x86_64" ]]; then
        check_fail "Architecture not supported: $ARCH (need x86_64)"
        return 1
    fi
    check_pass "Architecture: x86_64"
    
    # Check kernel version
    KERNEL=$(uname -r)
    KERNEL_MAJOR=$(echo "$KERNEL" | cut -d. -f1)
    KERNEL_MINOR=$(echo "$KERNEL" | cut -d. -f2)
    
    if [[ "$KERNEL_MAJOR" -lt 3 ]] || [[ "$KERNEL_MAJOR" -eq 3 && "$KERNEL_MINOR" -lt 8 ]]; then
        check_fail "Kernel version too old: $KERNEL (need 3.8+)"
        return 1
    fi
    check_pass "Kernel version: $KERNEL (3.8+ required)"
    
    # Check for WSL
    if grep -qi microsoft /proc/version 2>/dev/null; then
        if grep -qi "WSL2" /proc/version 2>/dev/null || [[ -d /run/WSL ]]; then
            check_pass "WSL2 detected (full support)"
        else
            check_warn "WSL1 detected - namespaces may not work"
        fi
    fi
    
    # Show distro info
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        check_info "Distribution: $PRETTY_NAME"
    fi
    
    return 0
}

check_privileges() {
    echo ""
    echo -e "${BLUE}[Privileges]${NC}"
    
    if [[ $EUID -eq 0 ]]; then
        check_pass "Running as root"
    else
        check_warn "Not running as root - jail features require sudo"
        check_info "Run with: sudo ./bsdulator ..."
    fi
    
    # Check if user can use sudo
    if command -v sudo &> /dev/null; then
        if sudo -n true 2>/dev/null; then
            check_pass "Passwordless sudo available"
        else
            check_info "sudo available (may prompt for password)"
        fi
    fi
}

check_kernel_features() {
    echo ""
    echo -e "${BLUE}[Kernel Features]${NC}"
    
    # Check for namespace support
    if [[ -d /proc/self/ns ]]; then
        check_pass "Namespace support available"
        
        # Check specific namespaces
        for ns in net mnt uts pid user; do
            if [[ -e /proc/self/ns/$ns ]]; then
                check_pass "  ${ns} namespace: available"
            else
                check_fail "  ${ns} namespace: not available"
            fi
        done
    else
        check_fail "Namespace support not available"
    fi
    
    # Check for ptrace
    if [[ -e /proc/sys/kernel/yama/ptrace_scope ]]; then
        PTRACE_SCOPE=$(cat /proc/sys/kernel/yama/ptrace_scope)
        case $PTRACE_SCOPE in
            0)
                check_pass "ptrace scope: 0 (unrestricted)"
                ;;
            1)
                check_pass "ptrace scope: 1 (restricted to children - OK for BSDulator)"
                ;;
            2|3)
                check_warn "ptrace scope: $PTRACE_SCOPE (restricted - may need CAP_SYS_PTRACE)"
                check_info "To fix: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope"
                ;;
        esac
    else
        check_pass "ptrace: no YAMA restrictions"
    fi
}

check_commands() {
    echo ""
    echo -e "${BLUE}[Required Commands]${NC}"
    
    # Essential commands
    local essential_cmds=("ip" "mount" "chroot")
    for cmd in "${essential_cmds[@]}"; do
        if command -v "$cmd" &> /dev/null; then
            check_pass "$cmd: $(command -v $cmd)"
        else
            check_fail "$cmd: not found (required)"
        fi
    done
    
    # Optional but recommended
    echo ""
    echo -e "${BLUE}[Optional Commands]${NC}"
    
    local optional_cmds=("brctl" "ping" "tar" "xz")
    for cmd in "${optional_cmds[@]}"; do
        if command -v "$cmd" &> /dev/null; then
            check_pass "$cmd: $(command -v $cmd)"
        else
            check_warn "$cmd: not found (optional)"
        fi
    done
}

check_networking() {
    echo ""
    echo -e "${BLUE}[Network Features]${NC}"
    
    # Check if we can create network namespaces
    if [[ $EUID -eq 0 ]]; then
        # Try to create a test namespace
        TEST_NS="bsdulator_test_$$"
        if ip netns add "$TEST_NS" 2>/dev/null; then
            check_pass "Can create network namespaces"
            ip netns delete "$TEST_NS" 2>/dev/null
        else
            check_fail "Cannot create network namespaces"
        fi
        
        # Check if we can create bridges
        TEST_BR="bsdtest$$"
        if ip link add "$TEST_BR" type bridge 2>/dev/null; then
            check_pass "Can create bridge interfaces"
            ip link delete "$TEST_BR" 2>/dev/null
        else
            check_warn "Cannot create bridge interfaces"
        fi
        
        # Check if we can create veth pairs
        TEST_VETH="bsdveth$$"
        if ip link add "${TEST_VETH}a" type veth peer name "${TEST_VETH}b" 2>/dev/null; then
            check_pass "Can create veth pairs"
            ip link delete "${TEST_VETH}a" 2>/dev/null
        else
            check_warn "Cannot create veth pairs"
        fi
    else
        check_info "Skipping network tests (requires root)"
    fi
    
    # Check IP forwarding
    if [[ -f /proc/sys/net/ipv4/ip_forward ]]; then
        IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
        if [[ "$IP_FORWARD" == "1" ]]; then
            check_pass "IP forwarding: enabled"
        else
            check_info "IP forwarding: disabled (enable for external jail connectivity)"
            check_info "To enable: echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward"
        fi
    fi
}

check_freebsd_root() {
    echo ""
    echo -e "${BLUE}[FreeBSD Root Filesystem]${NC}"
    
    # Check common locations
    local locations=("./freebsd-root" "../freebsd-root" "/opt/freebsd-root")
    local found=0
    
    for loc in "${locations[@]}"; do
        if [[ -d "$loc" && -f "$loc/libexec/ld-elf.so.1" ]]; then
            check_pass "FreeBSD root found: $loc"
            found=1
            
            # Check key files
            if [[ -x "$loc/bin/sh" ]]; then
                check_pass "  /bin/sh: present"
            else
                check_warn "  /bin/sh: missing"
            fi
            
            if [[ -d "$loc/usr/sbin" ]]; then
                if [[ -x "$loc/usr/sbin/jail" ]]; then
                    check_pass "  /usr/sbin/jail: present"
                else
                    check_warn "  /usr/sbin/jail: missing"
                fi
            fi
            
            break
        fi
    done
    
    if [[ $found -eq 0 ]]; then
        check_warn "FreeBSD root not found"
        check_info "Run: ./scripts/setup_freebsd_root.sh"
    fi
}

check_bsdulator() {
    echo ""
    echo -e "${BLUE}[BSDulator Binary]${NC}"
    
    if [[ -x "./bsdulator" ]]; then
        check_pass "bsdulator binary: ./bsdulator"
        
        # Try to get version or basic info
        if ./bsdulator --version 2>/dev/null; then
            :
        elif ./bsdulator -V 2>/dev/null; then
            :
        fi
    else
        check_warn "bsdulator binary not found"
        check_info "Run: make"
    fi
}

print_summary() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                         Summary                              ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${GREEN}Passed:${NC}   $PASS"
    echo -e "  ${YELLOW}Warnings:${NC} $WARN"
    echo -e "  ${RED}Failed:${NC}   $FAIL"
    echo ""
    
    if [[ $FAIL -eq 0 ]]; then
        if [[ $WARN -eq 0 ]]; then
            echo -e "  ${GREEN}✓ System is fully compatible with BSDulator${NC}"
        else
            echo -e "  ${GREEN}✓ System is compatible with BSDulator${NC}"
            echo -e "  ${YELLOW}  (some optional features may be limited)${NC}"
        fi
        echo ""
        echo "  Quick start:"
        echo "    make"
        echo "    ./scripts/setup_freebsd_root.sh"
        echo "    sudo ./bsdulator ./freebsd-root/libexec/ld-elf.so.1 ./freebsd-root/bin/echo Hello"
        echo ""
        return 0
    else
        echo -e "  ${RED}✗ System has compatibility issues${NC}"
        echo "    Please address the failed checks above."
        echo ""
        return 1
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    print_header
    
    check_os || true
    check_privileges
    check_kernel_features
    check_commands
    check_networking
    check_freebsd_root
    check_bsdulator
    
    print_summary
}

main "$@"
