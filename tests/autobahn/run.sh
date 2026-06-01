#!/bin/sh
#
# Autobahn|Testsuite conformance run for the AHT WebSocket client.
#
# The Autobahn "fuzzingserver" throws ~500 RFC 6455 protocol-conformance
# cases at a *client*. We run the server from the upstream Docker image
# (the autobahntestsuite Python package is Python-2-only and abandoned)
# and drive it with our own testee, tests/autobahn/bin/aht_autobahn,
# which echoes every data message back until the server closes the case.
#
# Lifecycle:
#   1. start crossbario/autobahn-testsuite listening on AUTOBAHN_URL's
#      port (default :9001),
#   2. wait for the port, run the testee (agent "AHT"),
#   3. tear the container down,
#   4. print where the HTML/JSON reports landed.
#
# The container is always removed on exit (trap), so a failed run does
# not leave the port occupied.
#
# The testee is NOT built here: building needs the Alire toolchain (alr),
# which is on the developer's PATH but not root's, and this script is
# typically run under sudo for docker access. Build it once, as yourself:
#
#     alr exec -- gprbuild -P tests/autobahn/autobahn.gpr
#
# then run this script.
#
# Env knobs:
#   AUTOBAHN_URL       ws:// base URL the client dials
#                      (default ws://127.0.0.1:9001). In docker mode its
#                      port also drives the server's listen port, the -p
#                      publish (bridge), and the readiness probe, so
#                      overriding it moves the entire run as a unit.
#   AUTOBAHN_AGENT     agent name reported to the suite (default AHT).
#   AUTOBAHN_NO_DOCKER if set, assume a fuzzingserver is already up at
#                      AUTOBAHN_URL and only build + run the testee
#                      (skips all docker orchestration).
#   AUTOBAHN_IMAGE     override the docker image
#                      (default crossbario/autobahn-testsuite).
#   AUTOBAHN_NET       container network mode: "host" (default) or "bridge".
#                      Host mode is the default because publishing a port
#                      with -p fails on this host: runc tries to lower the
#                      net.ipv4.ip_unprivileged_port_start sysctl in the
#                      container netns and the write is denied. Host
#                      networking shares the host netns, so :9001 inside is
#                      :9001 on the host and no port-mapping sysctl is set.
#                      The server binds 0.0.0.0 (see config/), so bridge
#                      mode does work on hosts where -p is permitted — the
#                      published port reaches the in-container listener.

set -eu

cd "$(dirname "$0")"
HERE=$(pwd)

URL=${AUTOBAHN_URL:-ws://127.0.0.1:9001}
AGENT=${AUTOBAHN_AGENT:-AHT}
IMAGE=${AUTOBAHN_IMAGE:-crossbario/autobahn-testsuite}
NET=${AUTOBAHN_NET:-host}

# Split the client URL into the host:port the probe and (in docker mode)
# the server listen on. The server always binds 0.0.0.0 inside the
# container regardless of HOST so the published port is reachable in
# bridge mode; HOST is only where the client/probe connect.
HOSTPORT=${URL#*://}
HOSTPORT=${HOSTPORT%%/*}
case "$HOSTPORT" in
    *:*) HOST=${HOSTPORT%:*}; PORT=${HOSTPORT##*:} ;;
    *)   HOST=$HOSTPORT;      PORT=9001 ;;
esac
# The fuzzingserver also starts an embedded web UI (default :8080). Under
# host networking that collides with whatever already owns the host's
# :8080, so move it to a free high port. We never use the UI — results are
# read from the mounted reports/ dir — so any free port works.
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

if [ ! -x bin/aht_autobahn ]; then
    echo "FATAL: bin/aht_autobahn not built. Build it first, as yourself:"
    echo "    alr exec -- gprbuild -P tests/autobahn/autobahn.gpr"
    exit 2
fi

if [ -z "${AUTOBAHN_NO_DOCKER:-}" ]; then
    echo "==> starting fuzzingserver ($IMAGE) on :$PORT"
    mkdir -p "$HERE/reports"
    # Remove a stale container from an aborted previous run, if any.
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    # config/fuzzingserver.json is a template; substitute the requested
    # port into a per-run copy so the server listens where the client
    # dials. Mounted as /config so the wstest invocation is unchanged.
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
    # No --rm: if the server crashes on boot we want its logs to survive
    # for the diagnostic below. The trap removes it on exit either way.
    CID=$(docker run -d \
        -v "$SPEC_DIR:/config" \
        -v "$HERE/reports:/reports" \
        $NETARGS --name "$CONTAINER" \
        "$IMAGE" \
        wstest -m fuzzingserver -s /config/fuzzingserver.json \
        --webport "$WEBPORT")

    echo "==> waiting for $URL"
    # Poll the host-side HOST:PORT the client will dial (both host and
    # bridge networking land the port there). Probe with python3 rather
    # than the container's sh, whose /dev/tcp may be dash without bash's
    # network redirection. HOST/PORT are passed as argv, not interpolated
    # into the program text.
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
bin/aht_autobahn "$URL" "$AGENT"

echo "==> reports in $HERE/reports (open index.html / index.json)"
