#!/bin/sh
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
#
# Builds the library and the example programs, starts the fixtures the
# examples dial (HTTP 8764, WS 8765, HTTPS 8766, stall 8767, wss 8768),
# runs every main listed in examples/examples.gpr in order, and kills
# the fixtures on exit.
#
# Inputs:  BUILD_MODE (debug|release, default debug) and
#          AHT_TLS_BACKEND (default openssl, kept in step with aht.gpr).
# Outputs: each example's stdout; fixture output goes to a temp log,
#          printed only when a fixture fails to come up.
# Exit:    0 when every example ran, 1 when any failed or was not
#          built, 2 when a fixture did not become ready or no mains
#          were found in examples.gpr.

set -eu

cd "$(dirname "$0")/.."

# Exported so the gpr externals pick them up and Exec_Dir
# (examples/bin/$BUILD_MODE-$AHT_TLS_BACKEND) resolves to the binaries
# just built.
BUILD_MODE=${BUILD_MODE:-debug}
export BUILD_MODE
AHT_TLS_BACKEND=${AHT_TLS_BACKEND:-openssl}
export AHT_TLS_BACKEND

VENV=tests/.venv
LOG=$(mktemp "${TMPDIR:-/tmp}/aht-examples.XXXXXX")
HTTP_PID=
WS_PID=
TLS_PID=
STALL_PID=
WSS_PID=

cleanup() {
    for pid in "$HTTP_PID" "$WS_PID" "$TLS_PID" "$STALL_PID" "$WSS_PID"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -f "$LOG"
}
trap cleanup EXIT INT TERM

echo "==> building library"
alr build

echo "==> building examples"
alr exec -- gprbuild -p -P examples/examples.gpr

echo "==> preparing venv (tests/.venv)"
if [ ! -d "$VENV" ]; then
    python3 -m venv "$VENV"
fi
# -q so a fully-cached install does not spam the log.
"$VENV"/bin/pip install -q -r tests/server/requirements.txt
PY="$VENV"/bin/python3

echo "==> generating self-signed cert (for the https + wss examples)"
sh scripts/generate_cert.sh

echo "==> starting HTTP (8764) + WS (8765) + HTTPS (8766) + stall (8767) + wss (8768) fixtures"
"$PY" tests/server/server.py        >>"$LOG" 2>&1 &
HTTP_PID=$!
"$PY" tests/server/server_ws.py     >>"$LOG" 2>&1 &
WS_PID=$!
"$PY" tests/server/server_tls.py    >>"$LOG" 2>&1 &
TLS_PID=$!
"$PY" tests/server/server_stall.py  >>"$LOG" 2>&1 &
STALL_PID=$!
"$PY" tests/server/server_ws_tls.py >>"$LOG" 2>&1 &
WSS_PID=$!

# Wait for every fixture's READY line; a fixture that never prints it
# fails here, not as an example bug.
for _ in $(seq 1 50); do
    HAS_HTTP=$(grep -c  '^READY http '  "$LOG" 2>/dev/null || true)
    HAS_WS=$(grep -c    '^READY ws '    "$LOG" 2>/dev/null || true)
    HAS_TLS=$(grep -c   '^READY tls '   "$LOG" 2>/dev/null || true)
    HAS_STALL=$(grep -c '^READY stall ' "$LOG" 2>/dev/null || true)
    HAS_WSS=$(grep -c   '^READY wss '   "$LOG" 2>/dev/null || true)
    if [ "$HAS_HTTP" -ge 1 ] && [ "$HAS_WS" -ge 1 ] \
       && [ "$HAS_TLS" -ge 1 ] && [ "$HAS_STALL" -ge 1 ] \
       && [ "$HAS_WSS" -ge 1 ]; then
        break
    fi
    sleep 0.1
done
if [ "$HAS_HTTP" -lt 1 ] || [ "$HAS_WS" -lt 1 ] || [ "$HAS_TLS" -lt 1 ] \
   || [ "$HAS_STALL" -lt 1 ] || [ "$HAS_WSS" -lt 1 ]
then
    echo "FATAL: fixtures did not become ready in 5s (http=$HAS_HTTP"
    echo "ws=$HAS_WS tls=$HAS_TLS stall=$HAS_STALL wss=$HAS_WSS); log follows:"
    cat "$LOG"
    exit 2
fi

echo "==> running examples"
# Source the ordered main list from examples.gpr so a rename or reorder
# in the project file is reflected here automatically.
NAMES=$(grep -oE '"ex_[a-z0-9_]+\.adb"' examples/examples.gpr \
        | tr -d '"' | sed 's/\.adb$//')
if [ -z "$NAMES" ]; then
    echo "FATAL: could not parse any example mains from examples/examples.gpr"
    exit 2
fi

FAILED=0
TOTAL=0
for name in $NAMES; do
    bin="examples/bin/$BUILD_MODE-$AHT_TLS_BACKEND/$name"
    TOTAL=$((TOTAL + 1))
    echo "----- $name -----"
    if [ ! -x "$bin" ]; then
        echo "  MISSING $name (not built)"
        FAILED=$((FAILED + 1))
        continue
    fi
    if "$bin"; then
        :
    else
        rc=$?
        echo "  FAIL $name (exit $rc)"
        FAILED=$((FAILED + 1))
    fi
done

if [ "$FAILED" -gt 0 ]; then
    echo "==> $FAILED of $TOTAL example(s) failed"
    exit 1
fi
echo "==> all $TOTAL example(s) ran"
