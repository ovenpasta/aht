#!/bin/sh
#
# Generate a self-signed cert + key for the HTTPS/WSS test fixtures.
# The cert carries SANs for both "localhost" and 127.0.0.1 so mbedTLS
# hostname verification passes whether a test connects by name or by
# literal address.
#
# Output: tests/server/certs/server.crt, tests/server/certs/server.key
# (git-ignored — regenerated on every test run).
#
# Regenerates unconditionally: a stale cert outliving an SAN/expiry
# change is a worse failure mode than the ~50 ms openssl costs.

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
