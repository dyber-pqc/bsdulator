#!/bin/bash
#
# BSDulator Test Suite
#

BSDULATOR="./bsdulator"
FREEBSD_ROOT="./freebsd-root"
PASSED=0
FAILED=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED++))
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED++))
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo "================================================"
echo "BSDulator Test Suite"
echo "================================================"
echo ""

# Check if bsdulator exists
if [ ! -x "${BSDULATOR}" ]; then
    echo "Error: ${BSDULATOR} not found or not executable"
    echo "Run 'make' first to build BSDulator"
    exit 1
fi

# Test 1: Version output
echo "Test 1: Version output"
if ${BSDULATOR} --version 2>&1 | grep -q "BSDulator"; then
    pass "Version command works"
else
    fail "Version command failed"
fi

# Test 2: Help output
echo "Test 2: Help output"
if ${BSDULATOR} --help 2>&1 | grep -q "Usage:"; then
    pass "Help command works"
else
    fail "Help command failed"
fi

# Test 3: Error on missing binary
echo "Test 3: Error on missing binary"
if ${BSDULATOR} /nonexistent/binary 2>&1 | grep -qi "error\|cannot"; then
    pass "Properly reports missing binary"
else
    fail "Should report error for missing binary"
fi

# Test 4: Check FreeBSD root exists
echo "Test 4: FreeBSD root filesystem"
if [ -d "${FREEBSD_ROOT}/rescue" ]; then
    pass "FreeBSD root exists at ${FREEBSD_ROOT}"
else
    warn "FreeBSD root not found - run './scripts/setup_freebsd_root.sh'"
    echo "  Skipping binary execution tests"
fi

# Test 5: Detect FreeBSD binary (if available)
if [ -f "${FREEBSD_ROOT}/rescue/echo" ]; then
    echo "Test 5: FreeBSD binary detection"
    if ${BSDULATOR} -v "${FREEBSD_ROOT}/rescue/echo" test 2>&1 | grep -qi "freebsd"; then
        pass "Correctly identifies FreeBSD binary"
    else
        fail "Failed to identify FreeBSD binary"
    fi
    
    # Test 6: Run FreeBSD echo
    echo "Test 6: Execute FreeBSD echo"
    OUTPUT=$(${BSDULATOR} "${FREEBSD_ROOT}/rescue/echo" "Hello from FreeBSD" 2>/dev/null)
    if [ "$OUTPUT" = "Hello from FreeBSD" ]; then
        pass "FreeBSD echo executed correctly"
    else
        fail "FreeBSD echo output mismatch: got '$OUTPUT'"
    fi
    
    # Test 7: Run with verbose flag
    echo "Test 7: Verbose execution"
    if ${BSDULATOR} -v "${FREEBSD_ROOT}/rescue/echo" test 2>&1 | grep -q "syscall"; then
        pass "Verbose mode shows syscall info"
    else
        # May not show syscalls if verbose level too low
        warn "Verbose output may need -vv for syscall trace"
    fi
    
    # Test 8: Statistics output
    echo "Test 8: Statistics output"
    if ${BSDULATOR} -s "${FREEBSD_ROOT}/rescue/echo" test 2>&1 | grep -qi "statistic\|total.*syscall"; then
        pass "Statistics output works"
    else
        warn "Statistics output not detected (may vary by execution)"
    fi
fi

# Test with Linux binary (should still work or warn)
echo "Test 9: Linux binary handling"
if ${BSDULATOR} /bin/echo "Linux echo" 2>&1 | grep -qE "Linux|not.*FreeBSD|warning"; then
    pass "Handles Linux binary appropriately"
else
    # It might just work anyway
    warn "Linux binary handling unclear"
fi

echo ""
echo "================================================"
echo "Test Results: ${PASSED} passed, ${FAILED} failed"
echo "================================================"

if [ ${FAILED} -gt 0 ]; then
    exit 1
fi
exit 0
