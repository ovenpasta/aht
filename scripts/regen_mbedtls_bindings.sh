#!/bin/sh
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
#
# scripts/regen_mbedtls_bindings.sh — generate Ada specs for the
# mbedTLS surface AHT.Transport.TLS uses, into scratch/gen_bindings/.
# The operator then copies a *curated* subset into src/aht-mbedtls-*.
#
# This script does NOT run as part of `alr build`. It's a one-shot
# the maintainer invokes when bumping the pinned mbedTLS version
# (or extending the API surface): regenerate, diff against the
# previous curation, edit src/aht-mbedtls-*.ads to match.
#
# Why not auto-emit src/aht-mbedtls-*.ads on every build?
#   * The generator's output carries _h suffixes, baggage comments
#     and helper packages we don't want in tree.
#   * The curated specs trim each header's surface to just the
#     symbols Transport.TLS actually imports, so it's easy to see
#     what is and isn't depended on.
#   * Generation requires gcc to read the mbedTLS headers; that
#     would mean every build invokes gcc twice (once for Ada,
#     once for the headers) for no day-to-day benefit.

set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
MBED=${ROOT}/third_party/mbedtls-2.28.9

if [ ! -d "${MBED}/include/mbedtls" ]; then
    echo "regen_mbedtls_bindings: FATAL — mbedTLS source not present;" \
         "run scripts/fetch_mbedtls.sh first" >&2
    exit 1
fi

OUT=${ROOT}/scratch/gen_bindings
rm -rf "$OUT"
mkdir -p "$OUT"

# Headers we care about, in the order Transport.TLS will need them.
# More can be added as new surface is bound; the curation step is
# what decides what actually lands in src/.
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
        # Some gcc versions exit non-zero here: -fdump-ada-spec
        # declines to emit an object file for a bare header, yet still
        # writes the .ads. So the exit status is not a reliable signal
        # of success — instead we verify the expected top-level spec
        # landed. gcc's output is kept per-header and surfaced only if
        # generation genuinely failed (e.g. a missing include).
        base=${H%.h}
        expected="aht-mbedtls-mbedtls_${base}_h.ads"
        gcc -c -fdump-ada-spec -C \
            -fada-spec-parent=AHT.Mbedtls \
            -I "${MBED}/include" \
            "${MBED}/include/mbedtls/${H}" >"gen_${base}.log" 2>&1 || true
        if [ ! -f "$expected" ]; then
            echo "regen_mbedtls_bindings: FATAL — generating ${H} produced" \
                 "no ${expected}; gcc reported:" >&2
            cat "gen_${base}.log" >&2
            exit 1
        fi
    done
)

# Count what we produced so the operator has a quick sanity reading.
SPECS=$(ls "$OUT"/*.ads 2>/dev/null | wc -l | tr -d ' ')
echo "==> regen_mbedtls_bindings: ${SPECS} .ads file(s) in" \
     "${OUT#"$ROOT"/}"
echo "    Curate into src/aht-mbedtls-*.ads — drop the _h suffix,"
echo "    drop unused symbols, simplify chars_ptr parameters to"
echo "    System.Address where appropriate, and re-pragma each"
echo "    Import with a clear Convention => C."
