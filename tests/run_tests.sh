#!/bin/sh
#
# AHT test orchestrator: builds the library + test binaries, brings
# up the three Python fixtures (HTTP on 8764, WebSocket on 8765, HTTPS
# on 8766), runs every test main listed in tests/tests.gpr, and tears
# the fixtures down on exit.
#
# Self-contained tests (test_url, test_url_encoding, test_headers,
# test_log, test_tcp, test_http_io, test_http_wire, test_http_client,
# test_ws_frames) don't touch any fixture but cost nothing to leave
# them running, so the script doesn't bother partitioning.

set -eu

cd "$(dirname "$0")/.."

VENV=tests/.venv
LOG=$(mktemp -t aht-server.XXXXXX.log)
HTTP_PID=
WS_PID=
TLS_PID=

cleanup() {
    if [ -n "$HTTP_PID" ]; then
        kill "$HTTP_PID" 2>/dev/null || true
        wait "$HTTP_PID" 2>/dev/null || true
    fi
    if [ -n "$WS_PID" ]; then
        kill "$WS_PID" 2>/dev/null || true
        wait "$WS_PID" 2>/dev/null || true
    fi
    if [ -n "$TLS_PID" ]; then
        kill "$TLS_PID" 2>/dev/null || true
        wait "$TLS_PID" 2>/dev/null || true
    fi
    rm -f "$LOG"
}
trap cleanup EXIT INT TERM

echo "==> building library"
alr build

echo "==> building tests"
alr exec -- gprbuild -P tests/tests.gpr

echo "==> preparing venv (tests/.venv)"
if [ ! -d "$VENV" ]; then
    python3 -m venv "$VENV"
fi
# -q so a fully-cached install doesn't spam the log. Always run so
# a fresh requirements.txt entry gets picked up without the
# developer having to delete the venv.
"$VENV"/bin/pip install -q -r tests/server/requirements.txt
PY="$VENV"/bin/python3

echo "==> generating self-signed test cert"
sh scripts/generate_cert.sh

echo "==> starting HTTP (8764) + WS (8765) + TLS (8766) fixtures"
"$PY" tests/server/server.py     >>"$LOG" 2>&1 &
HTTP_PID=$!
"$PY" tests/server/server_ws.py  >>"$LOG" 2>&1 &
WS_PID=$!
"$PY" tests/server/server_tls.py >>"$LOG" 2>&1 &
TLS_PID=$!

# Wait for every fixture's READY line (printed once it is listening).
# 5 s should be plenty; bail out loudly if any never appears so a
# crashed fixture doesn't masquerade as test failures.
for _ in $(seq 1 50); do
    HAS_HTTP=$(grep -c '^READY http ' "$LOG" 2>/dev/null || true)
    HAS_WS=$(grep -c   '^READY ws '   "$LOG" 2>/dev/null || true)
    HAS_TLS=$(grep -c  '^READY tls '  "$LOG" 2>/dev/null || true)
    if [ "$HAS_HTTP" -ge 1 ] && [ "$HAS_WS" -ge 1 ] \
       && [ "$HAS_TLS" -ge 1 ]; then
        break
    fi
    sleep 0.1
done
HAS_HTTP=$(grep -c '^READY http ' "$LOG" 2>/dev/null || echo 0)
HAS_WS=$(grep -c   '^READY ws '   "$LOG" 2>/dev/null || echo 0)
HAS_TLS=$(grep -c  '^READY tls '  "$LOG" 2>/dev/null || echo 0)
if [ "$HAS_HTTP" -lt 1 ] || [ "$HAS_WS" -lt 1 ] || [ "$HAS_TLS" -lt 1 ]
then
    echo "FATAL: fixtures did not become ready in 5s (http=$HAS_HTTP "
    echo "ws=$HAS_WS tls=$HAS_TLS); log follows:"
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
