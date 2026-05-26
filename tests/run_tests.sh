#!/bin/sh
#
# AHT test orchestrator: builds the library + test binaries, brings
# up tests/server/server.py on 127.0.0.1:8764, runs every binary in
# tests/bin/, and tears the server down on exit.
#
# Self-contained tests (test_url, test_url_encoding, test_headers,
# test_log, test_tcp, test_http_io, test_http_wire, test_http_client)
# don't touch the Python server but cost nothing to leave it
# running, so the script doesn't bother partitioning them.

set -eu

cd "$(dirname "$0")/.."

LOG=$(mktemp -t aht-server.XXXXXX.log)
SERVER_PID=

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -f "$LOG"
}
trap cleanup EXIT INT TERM

echo "==> building library"
alr build

echo "==> building tests"
alr exec -- gprbuild -P tests/tests.gpr

echo "==> starting HTTP fixture (port 8764)"
python3 tests/server/server.py >"$LOG" 2>&1 &
SERVER_PID=$!

# Wait for the server's READY line (printed once it's listening).
# 5 s should be plenty; bail out loudly if it never appears so a
# crashed server doesn't masquerade as test failures.
for _ in $(seq 1 50); do
    if grep -q '^READY ' "$LOG" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if ! grep -q '^READY ' "$LOG" 2>/dev/null; then
    echo "FATAL: HTTP fixture did not become ready in 5s; log follows:"
    cat "$LOG"
    exit 2
fi

echo "==> running tests"
# Source the list of mains from tests.gpr so a rename or removal in
# the project file is automatically reflected here — discovering by
# `tests/bin/*` would silently run stale binaries left behind by
# the previous build and mask the change.
NAMES=$(grep -oE '"test_[a-z0-9_]+\.adb"' tests/tests.gpr \
        | tr -d '"' | sed 's/\.adb$//')
if [ -z "$NAMES" ]; then
    echo "FATAL: could not parse any test mains from tests/tests.gpr"
    exit 2
fi

FAILED=0
TOTAL=0
for name in $NAMES; do
    bin="tests/bin/$name"
    TOTAL=$((TOTAL + 1))
    if [ ! -x "$bin" ]; then
        echo "  MISSING $name (not built)"
        FAILED=$((FAILED + 1))
        continue
    fi
    if "$bin"; then
        :
    else
        echo "  FAIL $name"
        FAILED=$((FAILED + 1))
    fi
done

if [ "$FAILED" -gt 0 ]; then
    echo "==> $FAILED of $TOTAL test(s) failed"
    exit 1
fi
echo "==> $TOTAL test(s) passed"
