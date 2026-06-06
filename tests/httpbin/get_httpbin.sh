#!/bin/sh
#
# Ensures a go-httpbin binary is available for the suite's optional
# real-third-party-server fixture (mccutchen/go-httpbin). Strategy:
#
#   1. if tests/httpbin/bin/go-httpbin already exists, reuse it (cached);
#   2. else if a `go` toolchain is on PATH, `go install` the pinned
#      version into that dir (works offline once the module is in the
#      Go module cache);
#   3. else give up.
#
# On success: prints the absolute binary path to stdout and exits 0.
# On failure (no Go / install failed, e.g. offline first run): prints a
# diagnostic to stderr and exits 1, so the orchestrator can skip the
# fixture instead of failing the whole suite. stdout carries *only* the
# path so callers can `BIN=$(get_httpbin.sh)`.

set -eu

VERSION=v2.23.0
PKG="github.com/mccutchen/go-httpbin/v2/cmd/go-httpbin@${VERSION}"

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN_DIR="$HERE/bin"
BIN="$BIN_DIR/go-httpbin"

if [ -x "$BIN" ]; then
    echo "$BIN"
    exit 0
fi

if ! command -v go >/dev/null 2>&1; then
    echo "get_httpbin: no 'go' toolchain on PATH; skipping go-httpbin" >&2
    exit 1
fi

mkdir -p "$BIN_DIR"
echo "get_httpbin: installing $PKG -> $BIN" >&2
# GOBIN forces the binary into our local dir regardless of the user's
# GOPATH/GOBIN. The command directory is cmd/go-httpbin, so the produced
# binary is named go-httpbin.
if GOBIN="$BIN_DIR" go install "$PKG" >&2 && [ -x "$BIN" ]; then
    echo "$BIN"
    exit 0
fi

echo "get_httpbin: 'go install' failed (offline first run?); skipping" >&2
exit 1
