#!/bin/sh
#
# Fuzz the tracer: tests/freebsd/syscall_fuzz.c sends hostile arguments to
# the syscalls bsdulator parses, from inside a throwaway container, under
# the sanitizer build of bsdulator (make fuzz-build). Run as root on a
# lochs host with the freebsd:15 image (it has FreeBSD's cc).
#
#   tests/fuzz_tracer.sh <dir with the fuzz bsdulator> [seed] [runs] [batches] [calls]
#
# lochs runs the bsdulator next to it, so the installed lochs is copied
# into that directory.
#
# A run passes when the fuzzer prints its "done" line within the time
# limit and the sanitizers report nothing. The tracer's memory is the
# container's (its cgroup); its peak is shown.

set -u
BIN=${1:?usage: $0 <fuzz-bin-dir> [seed] [runs] [batches] [calls]}
SEED=${2:-$(date +%s)}
RUNS=${3:-5}
BATCHES=${4:-200}
CALLS=${5:-300}
LOCHS=$BIN/lochs
SRC=$(cd "$(dirname "$0")" && pwd)/freebsd/syscall_fuzz.c
NAME=fuzzbox
LOGDIR=${FUZZ_LOGDIR:-/tmp/lochs-fuzz}
mkdir -p "$LOGDIR"

[ -x "$BIN/bsdulator" ] || { echo "no $BIN/bsdulator (make fuzz-build)"; exit 2; }
cp "$(command -v lochs)" "$LOCHS.new" && mv -f "$LOCHS.new" "$LOCHS" || exit 2
# lochs with the fuzz bsdulator; setarch -R: see the fuzz run below
fl() { setarch x86_64 -R "$LOCHS" "$@"; }

fl rm -f "$NAME" >/dev/null 2>&1
fl create "$NAME" -i freebsd:15 --memory 2g >/dev/null || exit 2
fl start "$NAME" >"$LOGDIR/start.log" 2>&1 || { cat "$LOGDIR/start.log"; exit 2; }
cleanup() {
    fl stop "$NAME" >/dev/null 2>&1
    fl rm -f "$NAME" >/dev/null 2>&1
}
trap cleanup EXIT

fl cp "$SRC" "$NAME:/root/syscall_fuzz.c" >/dev/null || exit 2
# Built with the normal tracer: setup, not what is tested
lochs exec "$NAME" /usr/bin/cc -O1 -Wall -o /root/syscall_fuzz /root/syscall_fuzz.c \
    >"$LOGDIR/cc.log" 2>&1 || { cat "$LOGDIR/cc.log"; exit 2; }

fail=0
i=0
while [ $i -lt "$RUNS" ]; do
    s=$((SEED + i))
    log="$LOGDIR/run-$s.log"
    # setarch -R: GCC's AddressSanitizer crashes at startup now and then
    # on kernels with 32-bit mmap randomization (vm.mmap_rnd_bits); the
    # fuzz run (and the programs it traces) go without address
    # randomization instead
    BSDULATOR_KEEP_STDERR=1 timeout 900 setarch x86_64 -R "$LOCHS" exec "$NAME" /root/syscall_fuzz "$s" "$BATCHES" "$CALLS" >"$log" 2>&1
    rc=$?
    peak=$(cat /sys/fs/cgroup/lochs/$NAME/memory.peak 2>/dev/null)
    if grep -qE "AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:" "$log"; then
        echo "FAIL seed $s: sanitizer report ($log)"
        grep -m 5 -E "ERROR|runtime error|SUMMARY" "$log"
        fail=1
    elif [ $rc -eq 124 ]; then
        echo "FAIL seed $s: no end within 900 s ($log)"
        fail=1
    elif ! grep -q "syscall_fuzz: done" "$log"; then
        echo "FAIL seed $s: the run ended early, exit $rc ($log)"
        tail -5 "$log"
        fail=1
    else
        echo "ok   seed $s: $(grep "syscall_fuzz: done" "$log" | sed 's/syscall_fuzz: done: //'), memory peak ${peak:-?}"
        grep "calls made" "$log" | sed 's/^syscall_fuzz: /     /'
    fi
    i=$((i + 1))
done
[ $fail -eq 0 ] && echo "PASS: $RUNS runs from seed $SEED" || echo "FAILED"
exit $fail
