#!/bin/sh
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
#
# AHT test orchestrator: builds the library and the test binaries,
# starts the Python fixtures, runs every main listed in
# tests/tests.gpr under a per-test timeout, and tears the fixtures
# down on exit.
#
# Inputs: BUILD_MODE (debug|release), AHT_TLS_BACKEND
# (openssl|mbedtls), AHT_OS (posix|windows), AHT_CROSS_TARGET,
# AHT_TRACEBACK, AHT_TEST_LAUNCHER, TEST_TIMEOUT (seconds, 300),
# WINEDEBUG. Output: one line per test; fixture output goes to a
# temporary log shown only when a fixture fails to come up. Exit 0
# when every test passes, 1 when any fails or times out, 2 on a
# setup error.
#
# Fixtures, by port: 8764 HTTP, 8765 WebSocket echo, 8766 HTTPS,
# 8767 stall, 8768 wss echo, 8769 deaf TLS, 8771 abrupt close, 8773
# corrupted record, 8774/8775 invalid or dribbled handshake, 8776
# concurrent corruption, 8777 hostile WebSocket peer, 8778 close
# watcher, 8770 go-httpbin (optional; test_httpbin SKIPs without it).

set -eu

cd "$(dirname "$0")/.."

# Exported so the gpr external and the per-mode Exec_Dir see it.
BUILD_MODE=${BUILD_MODE:-debug}
export BUILD_MODE

# Exported so the gpr external and the Alire pre-build action
# (scripts/fetch_mbedtls.sh) see the same choice. Keep the default in
# lockstep with aht.gpr.
AHT_TLS_BACKEND=${AHT_TLS_BACKEND:-openssl}
export AHT_TLS_BACKEND

# Exported for the same two readers; keep the default in lockstep
# with aht.gpr. AHT_OS=windows cross-builds with mingw-w64 and runs
# the .exe under wine against the same native fixtures, so a
# difference is attributable to the port. Not a substitute for
# Windows: wine implements the API AHT calls, not the one Windows
# has; docs/tls.md says what has to be checked on the real thing.
AHT_OS=${AHT_OS:-posix}
export AHT_OS

case "$AHT_OS" in
    posix)
        VARIANT=$BUILD_MODE-$AHT_TLS_BACKEND
        EXE=
        LAUNCH=
        ;;
    windows)
        # One triplet drives gprbuild --target, the cross C toolchain
        # in scripts/fetch_mbedtls.sh and the directory names. Keep
        # the default in lockstep with aht.gpr and that script, which
        # checks it against the compiler's -dumpmachine.
        AHT_CROSS_TARGET=${AHT_CROSS_TARGET:-x86_64-w64-mingw32}
        export AHT_CROSS_TARGET
        # A stored traceback faults on raise on 32-bit x86; see
        # Traceback_Kind in aht.gpr.
        case "$AHT_CROSS_TARGET" in
            i?86-*) AHT_TRACEBACK=${AHT_TRACEBACK:-none} ;;
            *)      AHT_TRACEBACK=${AHT_TRACEBACK:-stored} ;;
        esac
        export AHT_TRACEBACK
        # Must match the Variant in aht.gpr.
        VARIANT=$BUILD_MODE-$AHT_TLS_BACKEND-$AHT_CROSS_TARGET
        EXE=.exe
        LAUNCH=${AHT_TEST_LAUNCHER:-wine}
        if ! command -v "${LAUNCH%% *}" >/dev/null 2>&1; then
            echo "FATAL: AHT_OS=windows needs '$LAUNCH' to run the" \
                 "cross-built binaries; set AHT_TEST_LAUNCHER or" \
                 "install wine."
            exit 2
        fi
        # wine chatters on stderr about unimplemented stubs, which
        # would drown the tests' own output.
        WINEDEBUG=${WINEDEBUG:--all}
        export WINEDEBUG
        ;;
    *)
        echo "FATAL: AHT_OS=$AHT_OS is not one of posix, windows"
        exit 2
        ;;
esac

VENV=tests/.venv
LOG=$(mktemp "${TMPDIR:-/tmp}/aht-server.XXXXXX")
HTTP_PID=
WS_PID=
TLS_PID=
STALL_PID=
WSS_PID=
TLSDEAF_PID=
TLSABRUPT_PID=
TLSCLOSEWATCH_PID=
TLSCORRUPT_PID=
TLSBADHS_PID=
TLSCONC_PID=
WSHOSTILE_PID=
HTTPBIN_PID=

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
    if [ -n "$STALL_PID" ]; then
        kill "$STALL_PID" 2>/dev/null || true
        wait "$STALL_PID" 2>/dev/null || true
    fi
    if [ -n "$WSS_PID" ]; then
        kill "$WSS_PID" 2>/dev/null || true
        wait "$WSS_PID" 2>/dev/null || true
    fi
    if [ -n "$TLSDEAF_PID" ]; then
        kill "$TLSDEAF_PID" 2>/dev/null || true
        wait "$TLSDEAF_PID" 2>/dev/null || true
    fi
    if [ -n "$TLSABRUPT_PID" ]; then
        kill "$TLSABRUPT_PID" 2>/dev/null || true
        wait "$TLSABRUPT_PID" 2>/dev/null || true
    fi
    if [ -n "$TLSCLOSEWATCH_PID" ]; then
        kill "$TLSCLOSEWATCH_PID" 2>/dev/null || true
        wait "$TLSCLOSEWATCH_PID" 2>/dev/null || true
    fi
    if [ -n "$TLSCORRUPT_PID" ]; then
        kill "$TLSCORRUPT_PID" 2>/dev/null || true
        wait "$TLSCORRUPT_PID" 2>/dev/null || true
    fi
    if [ -n "$TLSBADHS_PID" ]; then
        kill "$TLSBADHS_PID" 2>/dev/null || true
        wait "$TLSBADHS_PID" 2>/dev/null || true
    fi
    if [ -n "$TLSCONC_PID" ]; then
        kill "$TLSCONC_PID" 2>/dev/null || true
        wait "$TLSCONC_PID" 2>/dev/null || true
    fi
    if [ -n "$WSHOSTILE_PID" ]; then
        kill "$WSHOSTILE_PID" 2>/dev/null || true
        wait "$WSHOSTILE_PID" 2>/dev/null || true
    fi
    if [ -n "$HTTPBIN_PID" ]; then
        kill "$HTTPBIN_PID" 2>/dev/null || true
        wait "$HTTPBIN_PID" 2>/dev/null || true
    fi
    rm -f "$LOG"
}
trap cleanup EXIT INT TERM

echo "==> building library ($VARIANT)"
if [ "$AHT_OS" = "posix" ]; then
    alr build
    echo "==> building tests"
    alr exec -- gprbuild -P tests/tests.gpr
else
    # Alire drives the native toolchain, so the cross build goes
    # straight to gprbuild and runs the pre-build action by hand; it
    # picks the per-target mbedTLS tree from AHT_OS.
    sh scripts/fetch_mbedtls.sh
    gprbuild --target="$AHT_CROSS_TARGET" -P aht.gpr
    echo "==> building tests"
    gprbuild --target="$AHT_CROSS_TARGET" -P tests/tests.gpr

    # XP loadability applies to 32-bit x86 only; checked against the
    # built images, since what matters is what the linker named.
    case "$AHT_CROSS_TARGET" in
        i?86-*)
            echo "==> checking XP-loadable imports"
            sh scripts/check_xp_imports.sh \
               "$AHT_CROSS_TARGET-objdump" "tests/bin/$VARIANT"/*.exe
            ;;
    esac
fi

echo "==> preparing venv (tests/.venv)"
if [ ! -d "$VENV" ]; then
    python3 -m venv "$VENV"
fi
# Always run, so a new requirements.txt entry is picked up.
"$VENV"/bin/pip install -q -r tests/server/requirements.txt
PY="$VENV"/bin/python3

echo "==> generating self-signed test cert"
sh scripts/generate_cert.sh

echo "==> starting HTTP (8764) + WS (8765) + TLS (8766) + stall (8767) + wss (8768) + tlsdeaf (8769) + tlsabrupt (8771) + tlscorrupt (8773) + tlsbadhandshake (8774+8775) + tlsconcurrent (8776) + wshostile (8777) + tlsclosewatch (8778) fixtures"
"$PY" tests/server/server.py          >>"$LOG" 2>&1 &
HTTP_PID=$!
"$PY" tests/server/server_ws.py       >>"$LOG" 2>&1 &
WS_PID=$!
"$PY" tests/server/server_tls.py      >>"$LOG" 2>&1 &
TLS_PID=$!
"$PY" tests/server/server_stall.py    >>"$LOG" 2>&1 &
STALL_PID=$!
"$PY" tests/server/server_ws_tls.py   >>"$LOG" 2>&1 &
WSS_PID=$!
"$PY" tests/server/server_tls_deaf.py >>"$LOG" 2>&1 &
TLSDEAF_PID=$!
"$PY" tests/server/server_tls_abrupt.py >>"$LOG" 2>&1 &
TLSABRUPT_PID=$!
"$PY" tests/server/server_tls_closewatch.py >>"$LOG" 2>&1 &
TLSCLOSEWATCH_PID=$!
"$PY" tests/server/server_tls_corrupt.py >>"$LOG" 2>&1 &
TLSCORRUPT_PID=$!
"$PY" tests/server/server_tls_badhandshake.py >>"$LOG" 2>&1 &
TLSBADHS_PID=$!
"$PY" tests/server/server_tls_concurrent.py >>"$LOG" 2>&1 &
TLSCONC_PID=$!
"$PY" tests/server/server_ws_hostile.py >>"$LOG" 2>&1 &
WSHOSTILE_PID=$!

# Wait up to 5 s for every fixture's READY line, printed once it is
# listening, so a crashed fixture does not masquerade as test failures.
for _ in $(seq 1 50); do
    HAS_HTTP=$(grep -c    '^READY http '    "$LOG" 2>/dev/null || true)
    HAS_WS=$(grep -c      '^READY ws '      "$LOG" 2>/dev/null || true)
    HAS_TLS=$(grep -c     '^READY tls '     "$LOG" 2>/dev/null || true)
    HAS_STALL=$(grep -c   '^READY stall '   "$LOG" 2>/dev/null || true)
    HAS_WSS=$(grep -c     '^READY wss '     "$LOG" 2>/dev/null || true)
    HAS_TLSDEAF=$(grep -c '^READY tlsdeaf ' "$LOG" 2>/dev/null || true)
    HAS_TLSABRUPT=$(grep -c '^READY tlsabrupt ' "$LOG" 2>/dev/null || true)
    HAS_TLSCLOSEWATCH=$(grep -c '^READY tlsclosewatch ' "$LOG" 2>/dev/null || true)
    HAS_TLSCORRUPT=$(grep -c '^READY tlscorrupt ' "$LOG" 2>/dev/null || true)
    HAS_TLSBADHS=$(grep -c '^READY tlsbadhandshake ' "$LOG" 2>/dev/null || true)
    HAS_TLSCONC=$(grep -c '^READY tlsconcurrent ' "$LOG" 2>/dev/null || true)
    HAS_WSHOSTILE=$(grep -c '^READY wshostile ' "$LOG" 2>/dev/null || true)
    if [ "$HAS_HTTP" -ge 1 ] && [ "$HAS_WS" -ge 1 ] \
       && [ "$HAS_TLS" -ge 1 ] && [ "$HAS_STALL" -ge 1 ] \
       && [ "$HAS_WSS" -ge 1 ] && [ "$HAS_TLSDEAF" -ge 1 ] \
       && [ "$HAS_TLSABRUPT" -ge 1 ] && [ "$HAS_TLSCORRUPT" -ge 1 ] \
       && [ "$HAS_TLSCLOSEWATCH" -ge 1 ] \
       && [ "$HAS_TLSBADHS" -ge 1 ] && [ "$HAS_TLSCONC" -ge 1 ] \
       && [ "$HAS_WSHOSTILE" -ge 1 ]; then
        break
    fi
    sleep 0.1
done
# Re-read for the verdict. `|| true`, not `|| echo 0`: grep -c prints
# 0 itself and only exits non-zero, so an echo would make the value
# two lines.
HAS_HTTP=$(grep -c    '^READY http '    "$LOG" 2>/dev/null || true)
HAS_WS=$(grep -c      '^READY ws '      "$LOG" 2>/dev/null || true)
HAS_TLS=$(grep -c     '^READY tls '     "$LOG" 2>/dev/null || true)
HAS_STALL=$(grep -c   '^READY stall '   "$LOG" 2>/dev/null || true)
HAS_WSS=$(grep -c     '^READY wss '     "$LOG" 2>/dev/null || true)
HAS_TLSDEAF=$(grep -c '^READY tlsdeaf ' "$LOG" 2>/dev/null || true)
HAS_TLSABRUPT=$(grep -c '^READY tlsabrupt ' "$LOG" 2>/dev/null || true)
HAS_TLSCLOSEWATCH=$(grep -c '^READY tlsclosewatch ' "$LOG" 2>/dev/null || true)
HAS_TLSCORRUPT=$(grep -c '^READY tlscorrupt ' "$LOG" 2>/dev/null || true)
HAS_TLSBADHS=$(grep -c '^READY tlsbadhandshake ' "$LOG" 2>/dev/null || true)
HAS_TLSCONC=$(grep -c '^READY tlsconcurrent ' "$LOG" 2>/dev/null || true)
HAS_WSHOSTILE=$(grep -c '^READY wshostile ' "$LOG" 2>/dev/null || true)
if [ "$HAS_HTTP" -lt 1 ] || [ "$HAS_WS" -lt 1 ] \
   || [ "$HAS_TLS" -lt 1 ] || [ "$HAS_STALL" -lt 1 ] \
   || [ "$HAS_WSS" -lt 1 ] || [ "$HAS_TLSDEAF" -lt 1 ] \
   || [ "$HAS_TLSABRUPT" -lt 1 ] || [ "$HAS_TLSCORRUPT" -lt 1 ] \
   || [ "$HAS_TLSCLOSEWATCH" -lt 1 ] \
   || [ "$HAS_TLSBADHS" -lt 1 ] || [ "$HAS_TLSCONC" -lt 1 ] \
   || [ "$HAS_WSHOSTILE" -lt 1 ]
then
    echo "FATAL: fixtures did not become ready in 5s (http=$HAS_HTTP "
    echo "ws=$HAS_WS tls=$HAS_TLS stall=$HAS_STALL wss=$HAS_WSS"
    echo "tlsdeaf=$HAS_TLSDEAF tlsabrupt=$HAS_TLSABRUPT tlsclosewatch=$HAS_TLSCLOSEWATCH"
    echo "tlscorrupt=$HAS_TLSCORRUPT tlsbadhs=$HAS_TLSBADHS"
    echo "tlsconc=$HAS_TLSCONC wshostile=$HAS_WSHOSTILE); log follows:"
    cat "$LOG"
    exit 2
fi

# Optional: go-httpbin (mccutchen/go-httpbin), a third-party HTTP/1.1
# server, only when a Go toolchain can produce the binary (the helper
# works offline once cached). Otherwise AHT_HTTPBIN_URL stays unset
# and test_httpbin SKIPs; never fatal.
echo "==> ensuring go-httpbin fixture (optional)"
if HTTPBIN_BIN=$(sh tests/httpbin/get_httpbin.sh 2>>"$LOG"); then
    "$HTTPBIN_BIN" -host 127.0.0.1 -port 8770 >>"$LOG" 2>&1 &
    HTTPBIN_PID=$!
    for _ in $(seq 1 50); do
        if grep -q 'go-httpbin listening' "$LOG" 2>/dev/null; then
            break
        fi
        sleep 0.1
    done
    if grep -q 'go-httpbin listening' "$LOG" 2>/dev/null; then
        AHT_HTTPBIN_URL=http://127.0.0.1:8770
        export AHT_HTTPBIN_URL
        echo "==> go-httpbin listening on 8770 (test_httpbin enabled)"
    else
        echo "==> go-httpbin did not become ready; test_httpbin will SKIP"
        kill "$HTTPBIN_PID" 2>/dev/null || true
        HTTPBIN_PID=
    fi
else
    echo "==> go-httpbin unavailable (no Go toolchain?); test_httpbin will SKIP"
fi

echo "==> running tests"
# The list of mains comes from tests.gpr; `tests/bin/*` would run
# stale binaries left behind by a previous build.
NAMES=$(grep -oE '"test_[a-z0-9_]+\.adb"' tests/tests.gpr \
        | tr -d '"' | sed 's/\.adb$//')
if [ -z "$NAMES" ]; then
    echo "FATAL: could not parse any test mains from tests/tests.gpr"
    exit 2
fi

# Per-test wall-clock cap: a deadlocked test would hide every test
# after it, and Ada waits for dependent tasks at scope exit, so a
# test that has reported a stuck task still cannot exit. Enforced by
# tests/run_one.py: coreutils timeout is absent on the macOS runner
# and without -k only sends SIGTERM; the wrapper escalates to SIGKILL
# on the whole process group.
TEST_TIMEOUT=${TEST_TIMEOUT:-300}
CAP="$PY tests/run_one.py $TEST_TIMEOUT"

FAILED=0
TOTAL=0
for name in $NAMES; do
    bin="tests/bin/$VARIANT/$name$EXE"
    TOTAL=$((TOTAL + 1))
    if [ ! -x "$bin" ]; then
        echo "  MISSING $name (not built)"
        FAILED=$((FAILED + 1))
        continue
    fi
    # $LAUNCH is empty for a native run and drops out of the command.
    if $CAP $LAUNCH "$bin"; then
        :
    else
        status=$?
        if [ "$status" -eq 124 ]; then
            echo "  TIMEOUT $name (exceeded ${TEST_TIMEOUT}s)"
        else
            echo "  FAIL $name"
        fi
        FAILED=$((FAILED + 1))
    fi
done

if [ "$FAILED" -gt 0 ]; then
    echo "==> $FAILED of $TOTAL test(s) failed"
    exit 1
fi
echo "==> $TOTAL test(s) passed"
