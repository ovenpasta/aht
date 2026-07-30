#!/bin/sh
#
# scripts/regen_openssl_bindings.sh — generate Ada specs for the
# OpenSSL surface AHT.Transport.TLS uses, into
# scratch/gen_bindings_openssl/. The operator then reconciles a
# *curated* subset into src/tls/openssl/aht-openssl-*.
#
# This script does NOT run as part of `alr build`. It's a one-shot the
# maintainer invokes when moving to a new OpenSSL major (or extending
# the API surface): regenerate, diff against the previous curation,
# edit src/tls/openssl/aht-openssl-*.ads to match.
#
# Note: dumping ssl.h cascades into MANY transitive spec files (the
# OpenSSL headers pull each other in); only the curated subset ever
# lands in src/. Point AHT_OPENSSL_DIR at a non-system OpenSSL to
# generate against it (same variable the build uses).

set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
INC=${AHT_OPENSSL_DIR:-/usr}/include

if [ ! -f "${INC}/openssl/ssl.h" ]; then
    echo "regen_openssl_bindings: FATAL — no openssl/ssl.h under ${INC};" \
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
        # Some gcc versions exit non-zero here: -fdump-ada-spec
        # declines to emit an object file for a bare header, yet still
        # writes the .ads. So the exit status is not a reliable signal
        # of success — instead we verify the expected top-level spec
        # landed.
        base=${H%.h}
        expected="aht-openssl-openssl_${base}_h.ads"
        gcc -c -fdump-ada-spec -C \
            -fada-spec-parent=AHT.Openssl \
            -I "${INC}" \
            "${INC}/openssl/${H}" >"gen_${base}.log" 2>&1 || true
        if [ ! -f "$expected" ]; then
            echo "regen_openssl_bindings: FATAL — generating ${H} produced" \
                 "no ${expected}; gcc reported:" >&2
            cat "gen_${base}.log" >&2
            exit 1
        fi
    done
)

SPECS=$(ls "$OUT"/*.ads 2>/dev/null | wc -l | tr -d ' ')
echo "==> regen_openssl_bindings: ${SPECS} .ads file(s) in" \
     "${OUT#"$ROOT"/}"
echo "    Curate into src/tls/openssl/aht-openssl-*.ads — drop the _h"
echo "    suffix, drop unused symbols, simplify chars_ptr parameters"
echo "    to System.Address where appropriate, and re-pragma each"
echo "    Import with a clear Convention => C."
