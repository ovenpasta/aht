#!/bin/sh
#
# AHT test orchestrator: builds the library + test binaries, brings up
# the Python fixtures, runs every test main listed in tests/tests.gpr,
# and tears the fixtures down on exit.
#
# Fixtures, by port:
#   8764  HTTP
#   8765  WebSocket echo
#   8766  HTTPS
#   8767  stall — accepts, then silence (handshake-timeout test)
#   8768  wss echo
#   8769  deaf TLS — handshakes, never reads (write-poison test)
#   8771  abrupt close — no close_notify (truncation policy)
#   8773  corrupted record (integrity failure)
#   8774  invalid handshake record / 8775 dribbled header
#   8776  mid-session corruption under concurrency
#   8777  WebSocket peer that misbehaves (overruns, floods, goes deaf)
#   8770  go-httpbin, optional — only when a Go toolchain can build it
#         (see tests/httpbin/get_httpbin.sh); test_httpbin SKIPs otherwise.
#
# Self-contained tests (test_url, test_url_encoding, test_headers,
# test_log, test_tcp, test_http_io, test_http_wire, test_http_client,
# test_ws_frames) don't touch any fixture but cost nothing to leave
# them running, so the script doesn't bother partitioning.

set -eu

cd "$(dirname "$0")/.."

# Build profile (debug|release). Exported so the gpr `external("BUILD_MODE")`
# picks it up for both `alr build` and the tests build, and so the per-mode
# Exec_Dir (tests/bin/$BUILD_MODE) resolves to the binaries we just built.
BUILD_MODE=${BUILD_MODE:-debug}
export BUILD_MODE

# TLS backend (openssl|mbedtls). Exported so the gpr
# `external("AHT_TLS_BACKEND")` AND the Alire pre-build action
# (scripts/fetch_mbedtls.sh gates on it) both see the same choice.
# Keep the default in lockstep with aht.gpr's.
AHT_TLS_BACKEND=${AHT_TLS_BACKEND:-openssl}
export AHT_TLS_BACKEND

# Target OS family (posix|windows). Exported for the same two readers
# as above; keep the default in lockstep with aht.gpr's AHT_OS.
#
# AHT_OS=windows cross-builds with a mingw-w64 toolchain and runs the
# resulting .exe under wine, against these same Python fixtures on
# these same ports. The fixtures are native either way -- only the
# testee crosses over, which is the point: the client is what is being
# ported, and pointing it at an unchanged server is what makes a
# difference attributable to the port.
#
# This is not a substitute for running on Windows. wine implements the
# API AHT calls, not the one Windows has; it is the fast loop, and
# docs/tls.md says what still has to be checked on the real thing.
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
        # in scripts/fetch_mbedtls.sh, and the directory names all
        # three meet in. Keep the default in lockstep with aht.gpr and
        # that script; the script checks it against the compiler's own
        # -dumpmachine, so a mismatch is reported rather than built.
        AHT_CROSS_TARGET=${AHT_CROSS_TARGET:-x86_64-w64-mingw32}
        export AHT_CROSS_TARGET
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
LOG=$(mktemp -t aht-server.XXXXXX.log)
HTTP_PID=
WS_PID=
TLS_PID=
STALL_PID=
WSS_PID=
TLSDEAF_PID=
TLSABRUPT_PID=
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
    # straight to gprbuild -- which means the pre-build action Alire
    # would have run has to be invoked by hand. Same script, same
    # gating on AHT_TLS_BACKEND; it picks the per-target mbedTLS tree
    # from AHT_OS, exported above.
    sh scripts/fetch_mbedtls.sh
    gprbuild --target="$AHT_CROSS_TARGET" -P aht.gpr
    echo "==> building tests"
    gprbuild --target="$AHT_CROSS_TARGET" -P tests/tests.gpr
fi

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

echo "==> starting HTTP (8764) + WS (8765) + TLS (8766) + stall (8767) + wss (8768) + tlsdeaf (8769) + tlsabrupt (8771) + tlscorrupt (8773) + tlsbadhandshake (8774+8775) + tlsconcurrent (8776) + wshostile (8777) fixtures"
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
"$PY" tests/server/server_tls_corrupt.py >>"$LOG" 2>&1 &
TLSCORRUPT_PID=$!
"$PY" tests/server/server_tls_badhandshake.py >>"$LOG" 2>&1 &
TLSBADHS_PID=$!
"$PY" tests/server/server_tls_concurrent.py >>"$LOG" 2>&1 &
TLSCONC_PID=$!
"$PY" tests/server/server_ws_hostile.py >>"$LOG" 2>&1 &
WSHOSTILE_PID=$!

# Wait for every fixture's READY line (printed once it is listening).
# 5 s should be plenty; bail out loudly if any never appears so a
# crashed fixture doesn't masquerade as test failures.
for _ in $(seq 1 50); do
    HAS_HTTP=$(grep -c    '^READY http '    "$LOG" 2>/dev/null || true)
    HAS_WS=$(grep -c      '^READY ws '      "$LOG" 2>/dev/null || true)
    HAS_TLS=$(grep -c     '^READY tls '     "$LOG" 2>/dev/null || true)
    HAS_STALL=$(grep -c   '^READY stall '   "$LOG" 2>/dev/null || true)
    HAS_WSS=$(grep -c     '^READY wss '     "$LOG" 2>/dev/null || true)
    HAS_TLSDEAF=$(grep -c '^READY tlsdeaf ' "$LOG" 2>/dev/null || true)
    HAS_TLSABRUPT=$(grep -c '^READY tlsabrupt ' "$LOG" 2>/dev/null || true)
    HAS_TLSCORRUPT=$(grep -c '^READY tlscorrupt ' "$LOG" 2>/dev/null || true)
    HAS_TLSBADHS=$(grep -c '^READY tlsbadhandshake ' "$LOG" 2>/dev/null || true)
    HAS_TLSCONC=$(grep -c '^READY tlsconcurrent ' "$LOG" 2>/dev/null || true)
    HAS_WSHOSTILE=$(grep -c '^READY wshostile ' "$LOG" 2>/dev/null || true)
    if [ "$HAS_HTTP" -ge 1 ] && [ "$HAS_WS" -ge 1 ] \
       && [ "$HAS_TLS" -ge 1 ] && [ "$HAS_STALL" -ge 1 ] \
       && [ "$HAS_WSS" -ge 1 ] && [ "$HAS_TLSDEAF" -ge 1 ] \
       && [ "$HAS_TLSABRUPT" -ge 1 ] && [ "$HAS_TLSCORRUPT" -ge 1 ] \
       && [ "$HAS_TLSBADHS" -ge 1 ] && [ "$HAS_TLSCONC" -ge 1 ] \
       && [ "$HAS_WSHOSTILE" -ge 1 ]; then
        break
    fi
    sleep 0.1
done
# Re-read for the verdict. `|| true` and NOT `|| echo 0`: grep -c
# already prints 0 when nothing matched, it just exits non-zero, so
# adding an echo produced a two-line "0\n0". Every numeric test below
# then failed with "integer expected" -- and because they sit inside
# an `if` condition, set -e does not see it, so the runner sailed past
# its own fixture check and ran the suite against whatever happened to
# be listening on those ports. A stale fixture from an earlier run
# would have been used silently. The polling loop above always had
# this right; only the verdict did not.
HAS_HTTP=$(grep -c    '^READY http '    "$LOG" 2>/dev/null || true)
HAS_WS=$(grep -c      '^READY ws '      "$LOG" 2>/dev/null || true)
HAS_TLS=$(grep -c     '^READY tls '     "$LOG" 2>/dev/null || true)
HAS_STALL=$(grep -c   '^READY stall '   "$LOG" 2>/dev/null || true)
HAS_WSS=$(grep -c     '^READY wss '     "$LOG" 2>/dev/null || true)
HAS_TLSDEAF=$(grep -c '^READY tlsdeaf ' "$LOG" 2>/dev/null || true)
HAS_TLSABRUPT=$(grep -c '^READY tlsabrupt ' "$LOG" 2>/dev/null || true)
HAS_TLSCORRUPT=$(grep -c '^READY tlscorrupt ' "$LOG" 2>/dev/null || true)
HAS_TLSBADHS=$(grep -c '^READY tlsbadhandshake ' "$LOG" 2>/dev/null || true)
HAS_TLSCONC=$(grep -c '^READY tlsconcurrent ' "$LOG" 2>/dev/null || true)
HAS_WSHOSTILE=$(grep -c '^READY wshostile ' "$LOG" 2>/dev/null || true)
if [ "$HAS_HTTP" -lt 1 ] || [ "$HAS_WS" -lt 1 ] \
   || [ "$HAS_TLS" -lt 1 ] || [ "$HAS_STALL" -lt 1 ] \
   || [ "$HAS_WSS" -lt 1 ] || [ "$HAS_TLSDEAF" -lt 1 ] \
   || [ "$HAS_TLSABRUPT" -lt 1 ] || [ "$HAS_TLSCORRUPT" -lt 1 ] \
   || [ "$HAS_TLSBADHS" -lt 1 ] || [ "$HAS_TLSCONC" -lt 1 ] \
   || [ "$HAS_WSHOSTILE" -lt 1 ]
then
    echo "FATAL: fixtures did not become ready in 5s (http=$HAS_HTTP "
    echo "ws=$HAS_WS tls=$HAS_TLS stall=$HAS_STALL wss=$HAS_WSS"
    echo "tlsdeaf=$HAS_TLSDEAF tlsabrupt=$HAS_TLSABRUPT"
    echo "tlscorrupt=$HAS_TLSCORRUPT tlsbadhs=$HAS_TLSBADHS"
    echo "tlsconc=$HAS_TLSCONC wshostile=$HAS_WSHOSTILE); log follows:"
    cat "$LOG"
    exit 2
fi

# Optional fixture: go-httpbin (mccutchen/go-httpbin), a real
# third-party HTTP/1.1 server. Enabled only when a Go toolchain can
# produce the binary (the helper installs it from the module cache and
# works offline once cached); otherwise the test_httpbin main SKIPs
# because AHT_HTTPBIN_URL stays unset. Never fatal — third-party interop
# is a bonus, not a gate on machines without Go.
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

# Per-test wall-clock cap. Without one, a test that deadlocks stalls
# the run and hides every test after it — and a deadlock is exactly
# what several of these tests exist to catch, so the failure mode and
# the detector would cancel out. A test may also be unable to unwind
# itself: Ada waits for dependent tasks at scope exit, so a test that
# has already reported a stuck task still cannot exit. This is the
# backstop for that.
#
# Enforced by tests/run_one.py rather than timeout(1): coreutils is
# absent on the macOS runner, so there the cap would not exist at all,
# and GNU timeout without -k only sends SIGTERM. The wrapper escalates
# to SIGKILL and signals the child's whole process group. Python is
# already required here — every fixture is one.
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
