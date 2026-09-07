#!/bin/sh
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
#
# Generate a self-signed cert + key for the HTTPS/WSS test fixtures,
# with SANs for both "localhost" and 127.0.0.1 so verification passes
# by name or by literal address.
#
# Output: tests/server/certs/server.crt and server.key (git-ignored).
# Regenerates unconditionally on every run. Exit status is openssl's.

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

echo "==> wrote $OUT/server.crt and $OUT/server.key"
