#!/bin/sh
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
#
# scripts/regen_mbedtls_bindings.sh - generate Ada specs for the
# mbedTLS surface AHT.Transport.TLS uses, into scratch/gen_bindings/,
# for the maintainer to curate into src/tls/mbedtls/aht-mbedtls-*
# when bumping the pinned version or extending the surface. Not part
# of `alr build`.
#
# Input: the posix tree built by scripts/fetch_mbedtls.sh. Output:
# one .ads per header in scratch/gen_bindings/, plus gen_<h>.log.
# Exit 1 when the tree is absent or a header produces no spec.

set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)

# The pinned version and the tree name are scripts/fetch_mbedtls.sh's;
# this reads the posix tree that script builds.
VERSION=$(sed -n 's/^VERSION=//p' "${ROOT}/scripts/fetch_mbedtls.sh")
MBED=${ROOT}/third_party/mbedtls-${VERSION:-3.6.7}

if [ ! -d "${MBED}/include/mbedtls" ]; then
    echo "regen_mbedtls_bindings: FATAL - mbedTLS source not present;" \
         "run AHT_TLS_BACKEND=mbedtls sh scripts/fetch_mbedtls.sh first" >&2
    exit 1
fi

OUT=${ROOT}/scratch/gen_bindings
rm -rf "$OUT"
mkdir -p "$OUT"

# Headers backing the curated surface. More can be added as new
# surface is bound; the curation step decides what lands in src/.
HEADERS="
    version.h
    error.h
    ssl.h
    net_sockets.h
    x509_crt.h
    ctr_drbg.h
    entropy.h
"

(
    cd "$OUT"
    for H in $HEADERS; do
        # Some gcc versions exit non-zero from -fdump-ada-spec on a
        # bare header yet still write the .ads, so the expected spec
        # landing is the signal, not the exit status. gcc's output is
        # shown only on failure.
        base=${H%.h}
        expected="aht-mbedtls-mbedtls_${base}_h.ads"
        gcc -c -fdump-ada-spec -C \
            -fada-spec-parent=AHT.Mbedtls \
            -I "${MBED}/include" \
            "${MBED}/include/mbedtls/${H}" >"gen_${base}.log" 2>&1 || true
        if [ ! -f "$expected" ]; then
            echo "regen_mbedtls_bindings: FATAL - generating ${H} produced" \
                 "no ${expected}; gcc reported:" >&2
            cat "gen_${base}.log" >&2
            exit 1
        fi
    done
)

# Count what was produced so the operator has a quick sanity reading.
SPECS=$(ls "$OUT"/*.ads 2>/dev/null | wc -l | tr -d ' ')
echo "==> regen_mbedtls_bindings: ${SPECS} .ads file(s) in" \
     "${OUT#"$ROOT"/}"
echo "    Curate into src/tls/mbedtls/aht-mbedtls-*.ads: drop the _h suffix,"
echo "    drop unused symbols, simplify chars_ptr parameters to"
echo "    System.Address where appropriate, and re-pragma each"
echo "    Import with a clear Convention => C."
