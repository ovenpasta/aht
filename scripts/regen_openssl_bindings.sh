#!/bin/sh
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
#
# scripts/regen_openssl_bindings.sh - generate Ada specs for the
# OpenSSL surface AHT.Transport.TLS uses, into
# scratch/gen_bindings_openssl/, for the maintainer to curate into
# src/tls/openssl/aht-openssl-* when moving to a new OpenSSL major or
# extending the surface. Not part of `alr build`.
#
# Input: AHT_OPENSSL_DIR (default /usr), the same variable the build
# uses. Output: one .ads per header plus its transitive includes
# (ssl.h cascades into many), and gen_<h>.log. Exit 1 when ssl.h is
# missing or a header produces no spec.

set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
INC=${AHT_OPENSSL_DIR:-/usr}/include

if [ ! -f "${INC}/openssl/ssl.h" ]; then
    echo "regen_openssl_bindings: FATAL - no openssl/ssl.h under ${INC};" \
         "install the OpenSSL 3 headers or set AHT_OPENSSL_DIR" >&2
    exit 1
fi

OUT=${ROOT}/scratch/gen_bindings_openssl
rm -rf "$OUT"
mkdir -p "$OUT"

# Headers backing the curated surface: ssl.h (SSL_CTX/SSL/verify),
# bio.h (memory BIOs), err.h (error queue), crypto.h (version),
# x509_vfy.h (X509_VERIFY_PARAM).
HEADERS="
    ssl.h
    bio.h
    err.h
    crypto.h
    x509_vfy.h
"

(
    cd "$OUT"
    for H in $HEADERS; do
        # Some gcc versions exit non-zero from -fdump-ada-spec on a
        # bare header yet still write the .ads, so the expected spec
        # landing is the signal, not the exit status.
        base=${H%.h}
        expected="aht-openssl-openssl_${base}_h.ads"
        gcc -c -fdump-ada-spec -C \
            -fada-spec-parent=AHT.Openssl \
            -I "${INC}" \
            "${INC}/openssl/${H}" >"gen_${base}.log" 2>&1 || true
        if [ ! -f "$expected" ]; then
            echo "regen_openssl_bindings: FATAL - generating ${H} produced" \
                 "no ${expected}; gcc reported:" >&2
            cat "gen_${base}.log" >&2
            exit 1
        fi
    done
)

SPECS=$(ls "$OUT"/*.ads 2>/dev/null | wc -l | tr -d ' ')
echo "==> regen_openssl_bindings: ${SPECS} .ads file(s) in" \
     "${OUT#"$ROOT"/}"
echo "    Curate into src/tls/openssl/aht-openssl-*.ads: drop the _h"
echo "    suffix, drop unused symbols, simplify chars_ptr parameters"
echo "    to System.Address where appropriate, and re-pragma each"
echo "    Import with a clear Convention => C."
