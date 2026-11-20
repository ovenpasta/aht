#!/bin/sh
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
#
# Generate a self-signed cert + key for the HTTPS/WSS test fixtures,
# with SANs for both "localhost" and 127.0.0.1 so verification passes
# by name or by literal address, and a second, unrelated self-signed
# cert for tests that need trust anchors not covering the fixtures.
#
# Output: tests/server/certs/server.crt, server.key and other.crt
# (git-ignored). Regenerates unconditionally on every run. Exit status
# is openssl's.

set -eu

cd "$(dirname "$0")/.."

OUT=tests/server/certs
mkdir -p "$OUT"

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$OUT/server.key" \
    -out "$OUT/server.crt" \
    -days 3650 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    >/dev/null 2>&1

# The key is not needed: nothing serves this certificate.
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$OUT/other.key" \
    -out "$OUT/other.crt" \
    -days 3650 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    >/dev/null 2>&1
rm -f "$OUT/other.key"

echo "==> wrote $OUT/server.crt, $OUT/server.key and $OUT/other.crt"
