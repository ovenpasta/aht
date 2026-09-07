#!/bin/sh
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
#
# Autobahn|Testsuite conformance run for the AHT WebSocket client:
# starts the crossbario/autobahn-testsuite fuzzingserver in Docker,
# waits for its port, runs the testee tests/autobahn/bin/aht_autobahn
# (~500 RFC 6455 cases, echoing every data message), removes the
# container on exit and prints where the reports landed.
#
# The testee is not built here; build it first with
#     alr exec -- gprbuild -P tests/autobahn/autobahn.gpr
#
# Inputs: BUILD_MODE, AHT_TLS_BACKEND (select the testee binary);
# AUTOBAHN_URL (ws://127.0.0.1:9001; its port also drives the server
# listen port, -p publish and readiness probe); AUTOBAHN_AGENT (AHT);
# AUTOBAHN_NO_DOCKER (use a server already up at AUTOBAHN_URL);
# AUTOBAHN_IMAGE; AUTOBAHN_NET (host, or bridge for Docker Desktop);
# AUTOBAHN_WEBPORT (8642). Output: reports/index.html and index.json.
# Exit 2 when the testee is missing or the server never opens its
# port; otherwise the testee's status.

set -eu

cd "$(dirname "$0")"
HERE=$(pwd)

# Mode and backend select the per-variant Exec_Dir.
BUILD_MODE=${BUILD_MODE:-debug}
AHT_TLS_BACKEND=${AHT_TLS_BACKEND:-openssl}
BIN="bin/$BUILD_MODE-$AHT_TLS_BACKEND/aht_autobahn"

URL=${AUTOBAHN_URL:-ws://127.0.0.1:9001}
AGENT=${AUTOBAHN_AGENT:-AHT}
IMAGE=${AUTOBAHN_IMAGE:-crossbario/autobahn-testsuite}
NET=${AUTOBAHN_NET:-host}

# host:port for the probe and the server listen port. The server
# binds 0.0.0.0 inside the container; HOST is where the client dials.
HOSTPORT=${URL#*://}
HOSTPORT=${HOSTPORT%%/*}
case "$HOSTPORT" in
    *:*) HOST=${HOSTPORT%:*}; PORT=${HOSTPORT##*:} ;;
    *)   HOST=$HOSTPORT;      PORT=9001 ;;
esac
# The embedded web UI (default :8080) is moved to a free high port so
# host networking does not collide with the host's :8080; it is unused.
WEBPORT=${AUTOBAHN_WEBPORT:-8642}
CONTAINER=aht-fuzzingserver

CID=
SPEC_DIR=

cleanup() {
    if [ -n "$CID" ]; then
        docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    fi
    if [ -n "$SPEC_DIR" ]; then
        rm -rf "$SPEC_DIR"
    fi
}
trap cleanup EXIT INT TERM

if [ ! -x "$BIN" ]; then
    echo "FATAL: $BIN not built. Build it first:"
    echo "    alr exec -- gprbuild -P tests/autobahn/autobahn.gpr"
    exit 2
fi

if [ -z "${AUTOBAHN_NO_DOCKER:-}" ]; then
    echo "==> starting fuzzingserver ($IMAGE) on :$PORT"
    mkdir -p "$HERE/reports"
    # Remove a stale container from an aborted previous run, if any.
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    # config/fuzzingserver.json is a template; the requested port is
    # substituted into a per-run copy mounted as /config.
    SPEC_DIR=$(mktemp -d)
    chmod 755 "$SPEC_DIR"
    sed -E "s#(\"url\": \"ws://0\.0\.0\.0:)[0-9]+#\1$PORT#" \
        config/fuzzingserver.json > "$SPEC_DIR/fuzzingserver.json"
    chmod 644 "$SPEC_DIR/fuzzingserver.json"
    if [ "$NET" = "host" ]; then
        NETARGS="--network host"
    else
        NETARGS="-p $PORT:$PORT"
    fi
    # No --rm: a server that crashes on boot must keep its logs for
    # the diagnostic below; the trap removes it on exit.
    CID=$(docker run -d \
        -v "$SPEC_DIR:/config" \
        -v "$HERE/reports:/reports" \
        $NETARGS --name "$CONTAINER" \
        "$IMAGE" \
        wstest -m fuzzingserver -s /config/fuzzingserver.json \
        --webport "$WEBPORT")

    echo "==> waiting for $URL"
    # Poll the host-side HOST:PORT the client will dial. python3, not
    # the container's sh, whose /dev/tcp may be dash without network
    # redirection. HOST/PORT are argv, not interpolated into the text.
    ready=
    for _ in $(seq 1 100); do
        if python3 -c 'import socket,sys; s=socket.socket(); s.settimeout(1); sys.exit(s.connect_ex((sys.argv[1], int(sys.argv[2]))))' "$HOST" "$PORT" >/dev/null 2>&1; then
            ready=1
            break
        fi
        # Bail out early if the container has already exited.
        if [ -z "$(docker ps -q -f name="$CONTAINER")" ]; then
            break
        fi
        sleep 0.2
    done
    if [ -z "$ready" ]; then
        echo "FATAL: fuzzingserver did not open $HOST:$PORT; container logs follow:"
        docker logs "$CONTAINER" 2>&1 || true
        exit 2
    fi
else
    echo "==> AUTOBAHN_NO_DOCKER set; using existing server at $URL"
fi

echo "==> running cases (agent $AGENT)"
"$BIN" "$URL" "$AGENT"

echo "==> reports in $HERE/reports (open index.html / index.json)"
