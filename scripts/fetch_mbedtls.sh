#!/bin/sh
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
#
# scripts/fetch_mbedtls.sh - download and build mbedTLS 3.6.7 into
# third_party/mbedtls-<version>[-<triplet>]. Runs as the Alire
# pre-build action; exits 0 without network or make once the tree's
# stamp matches this invocation. The tarball is the official release
# asset, pinned by the SHA-256 upstream publishes.
#
# Inputs: AHT_TLS_BACKEND (no-op unless mbedtls), AHT_OS (posix |
# windows), AHT_CROSS_TARGET (toolchain triplet, windows only), CC,
# AR, AHT_WIN32_WINNT. Outputs: library/libmbed{tls,x509,crypto}.a,
# the edited include/mbedtls/mbedtls_config.h and .aht-build-stamp
# under the tree. Exit 0 on success or no-op, 1 on a missing hash
# tool, 2 on a toolchain, download, hash, lock or tree error, 3 on a
# config edit or build failure.
#
# The config is edited into mbedtls_config.h, not passed as -D:
# MBEDTLS_THREADING_C changes the sizeof of context structs, and the
# glue must read the header the archive was built from; the stamp
# fingerprints the post-edit header. Trees are keyed by toolchain
# triplet, composed the same way in aht.gpr from AHT_OS and
# AHT_CROSS_TARGET.
#
# Threading, per target:
#   posix    MBEDTLS_THREADING_C + MBEDTLS_THREADING_PTHREAD;
#            AHT.Transport.TLS is called from several Ada tasks.
#   windows  threadless: mbedTLS ships no Windows mutex, and every
#            mutex it would take guards state this client keeps per
#            session or never reaches (docs/mbedtls.md lists them).
#
# The windows build needs PSA Crypto unreached: its process-global
# state is guarded only under MBEDTLS_THREADING_C. The probe asserts
# both macros that reach it are off:
#   MBEDTLS_USE_PSA_CRYPTO    routes X.509 and TLS through PSA.
#   MBEDTLS_SSL_PROTO_TLS1_3  TLS 1.3 code always uses PSA, and a
#                             1.3-capable client reaches it in every
#                             ClientHello.
# A compiled probe, not a grep: a macro can also arrive via
# MBEDTLS_CONFIG_FILE or a user config header.

set -eu

# No-op under any other AHT_TLS_BACKEND. Keep the default in lockstep
# with aht.gpr. The env var is the supported selection route because
# it reaches this action; a -X selection does not.
if [ "${AHT_TLS_BACKEND:-openssl}" != "mbedtls" ]; then
    exit 0
fi

VERSION=3.6.7
SHA256=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6

# The official release asset (tag mbedtls-<version>, bzip2). GitHub's
# auto-generated tag snapshots omit the framework/ submodule and do
# not build.
URL=https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${VERSION}/mbedtls-${VERSION}.tar.bz2

# Bumped whenever this script changes how a tree is produced or
# checked; the stamp carries it, so an older tree is rebuilt.
SCHEMA=6

# Target OS family. Keep the default in lockstep with AHT_OS in
# aht.gpr, which points at the tree this script produces.
TARGET=${AHT_OS:-posix}

case "$TARGET" in
    posix)
        TRIPLET=
        ;;
    windows)
        TRIPLET=${AHT_CROSS_TARGET:-x86_64-w64-mingw32}
        ;;
    *)
        echo "fetch_mbedtls: FATAL - AHT_OS=$TARGET is not one of" \
             "posix, windows" >&2
        exit 2
        ;;
esac

# tests/run_tests.sh passes this same triplet to gprbuild --target.
# CC and AR may be overridden, but the compiler's own target is
# checked against the triplet below.
if [ -n "$TRIPLET" ]; then
    SUFFIX=-${TRIPLET}
    CC=${CC:-${TRIPLET}-gcc}
    AR=${AR:-${TRIPLET}-ar}
else
    SUFFIX=
    CC=${CC:-cc}
    AR=${AR:-ar}
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
THIRD=${ROOT}/third_party
DEST=${THIRD}/mbedtls-${VERSION}${SUFFIX}
# The edits, the stamp fingerprint and aht.gpr's -I all read this path.
CFG=${DEST}/include/mbedtls/mbedtls_config.h
STAMP=${DEST}/.aht-build-stamp
ARCHIVE=${THIRD}/mbedtls-${VERSION}.tar.bz2

# AHT.Mbedtls links all three; an interrupted build leaves some present.
LIB_TLS=${DEST}/library/libmbedtls.a
LIB_X509=${DEST}/library/libmbedx509.a
LIB_CRYPTO=${DEST}/library/libmbedcrypto.a

if ! command -v "$CC" >/dev/null 2>&1; then
    echo "fetch_mbedtls: FATAL - C compiler '$CC' not found on PATH." >&2
    echo "  Set AHT_CROSS_TARGET (e.g. i686-w64-mingw32) or CC/AR to" \
         "name the toolchain for AHT_OS=$TARGET." >&2
    exit 2
fi

# `-dumpmachine` is understood by gcc and clang alike.
MACHINE=$("$CC" -dumpmachine)
CCVER=$("$CC" -dumpversion)

if [ -n "$TRIPLET" ]; then
    if [ "$MACHINE" != "$TRIPLET" ]; then
        echo "fetch_mbedtls: FATAL - AHT_CROSS_TARGET is $TRIPLET but" \
             "'$CC' targets $MACHINE" >&2
        echo "  The triplet names the tree, the object directories and" \
             "gprbuild --target, so these have to be the same string." >&2
        exit 2
    fi
else
    case "$MACHINE" in
        *mingw*|*cygwin*)
            echo "fetch_mbedtls: FATAL - AHT_OS=posix but '$CC' targets" \
                 "$MACHINE" >&2
            exit 2
            ;;
    esac
fi

# SHA-256 via sha256sum (GNU), shasum -a 256 (BSD, macOS) or openssl
# dgst, normalised to a bare hex string.
compute_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    else
        echo "fetch_mbedtls: FATAL - need sha256sum, shasum, or" \
             "openssl on PATH to verify the mbedTLS archive" >&2
        return 1
    fi
}

# Everything that determines the bytes in the archives. A tree whose
# stamp does not match is re-extracted: the config edits are one-way.
stamp_line() {
    echo "schema=$SCHEMA mbedtls=$VERSION os=$TARGET triplet=${TRIPLET:-none}" \
         "machine=$MACHINE cc=$CC ccver=$CCVER ar=$AR config=$1"
}

# Ask the preprocessor what the glue will see: the stamp says the
# header has not moved since the build, this says it means what the
# build assumed.
check_config() {
    # mktemp: a posix and a windows build may run in parallel. No .c
    # suffix (mktemp templates end in X's); -x c names the language.
    probe=$(mktemp "${THIRD}/.aht-config-probe.XXXXXX")
    cat > "$probe" <<'EOF'
#include <mbedtls/ssl.h>
#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY)
#error "MBEDTLS_NO_PLATFORM_ENTROPY is not set, so entropy_poll.c registers itself alongside AHT's source. Its windows branch calls BCryptGenRandom, which imports bcrypt.dll and leaves the image unloadable on the XP target. AHT supplies the pool from AHT.Random via aht_mbedtls_entropy_new"
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#error "MBEDTLS_SSL_PROTO_TLS1_3 is enabled. TLS 1.3 always uses PSA Crypto, whose process-global entropy context nothing here seeds and whose global state the threadless windows build assumes is unreached. Every handshake fails at ClientHello. See the header of scripts/fetch_mbedtls.sh"
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#error "MBEDTLS_USE_PSA_CRYPTO is enabled. PSA keeps process-global state; AHT's engine lock is per session (AHT.TLS_Sync.Lock_Type is a protected TYPE, one instance per Backend_State), so two sessions in two tasks are inside the library at once by design. PSA's globals are guarded only under MBEDTLS_THREADING_C, which the windows target does not have. See the header of scripts/fetch_mbedtls.sh"
#endif
EOF
    case "$TARGET" in
        posix)
            cat >> "$probe" <<'EOF'
#if !defined(MBEDTLS_THREADING_C) || !defined(MBEDTLS_THREADING_PTHREAD)
#error "expected a threaded posix build; mbedtls_config.h does not enable MBEDTLS_THREADING_C + MBEDTLS_THREADING_PTHREAD"
#endif
EOF
            ;;
        windows)
            cat >> "$probe" <<'EOF'
#if defined(MBEDTLS_THREADING_C)
#error "expected a threadless windows build; mbedtls_config.h enables MBEDTLS_THREADING_C, for which mbedTLS ships no Windows implementation -- pthread or a caller-supplied THREADING_ALT, and nothing else"
#endif
EOF
            ;;
    esac
    if ! "$CC" -x c -I"${DEST}/include" -fsyntax-only "$probe" 2>&1; then
        rm -f "$probe"
        echo "fetch_mbedtls: FATAL - mbedTLS configuration check failed" \
             "for $DEST" >&2
        return 1
    fi
    rm -f "$probe"
}

# All three archives present, built for this target by this toolchain,
# from an mbedtls_config.h that has not changed since. Asked before and after
# waiting for the build lock.
tree_is_current() {
    [ -s "$LIB_TLS" ] && [ -s "$LIB_X509" ] && [ -s "$LIB_CRYPTO" ] \
        && [ -f "$STAMP" ] && [ -f "$CFG" ] \
        && [ "$(cat "$STAMP")" = "$(stamp_line "$(compute_sha256 "$CFG")")" ]
}

# Fast path.
if tree_is_current; then
    check_config
    exit 0
fi

mkdir -p "$THIRD"

# From here on the tree is rewritten; two runs of the same target
# would interleave into one broken tree. mkdir is the lock: atomic on
# every POSIX filesystem, and macOS ships no flock. Per DEST, so
# different targets still build in parallel.
LOCK=${DEST}.lock
HELD_LOCK=

# HELD_LOCK tells the handler whether there is anything to release;
# another process's lock directory looks the same from here.
cleanup_lock() {
    if [ -n "$HELD_LOCK" ]; then
        rmdir "$LOCK" 2>/dev/null || true
        HELD_LOCK=
    fi
}
trap cleanup_lock EXIT

# sh runs a trap between statements, so a signal between the mkdir
# and the HELD_LOCK assignment would leave a lock nobody releases.
# Signals are held off (dropped, not queued) across that pair and
# armed everywhere else. HUP is included for builds whose terminal or
# ssh session goes away.
hold_signals() { trap '' INT TERM HUP; }
arm_signals() {
    trap 'cleanup_lock; exit 130' INT
    trap 'cleanup_lock; exit 143' TERM
    trap 'cleanup_lock; exit 129' HUP
}
arm_signals

LOCK_WAIT=0
while :; do
    hold_signals
    if mkdir "$LOCK" 2>/dev/null; then
        HELD_LOCK=1
        arm_signals
        break
    fi
    arm_signals

    if [ "$LOCK_WAIT" -ge 600 ]; then
        echo "fetch_mbedtls: FATAL - waited 600s for $LOCK" >&2
        echo "  Another build of this target is either still running" \
             "or was killed without releasing it. If nothing is" \
             "building, remove that directory and re-run." >&2
        exit 2
    fi
    if [ "$LOCK_WAIT" = 0 ]; then
        echo "==> fetch_mbedtls: waiting for a concurrent build of" \
             "$TARGET"
    fi
    sleep 1
    LOCK_WAIT=$((LOCK_WAIT + 1))
done

# Recheck under the lock: the loser of the race has nothing to do.
if tree_is_current; then
    check_config
    exit 0
fi

# Download to a unique name, then rename. The archive is shared
# between targets and the lock is per target, so two cold builds can
# be here at once; rename within one directory is atomic, and the
# tarball is hash-checked afterwards.
if [ ! -s "$ARCHIVE" ]; then
    echo "==> fetch_mbedtls: downloading ${VERSION}"
    part=$(mktemp "${ARCHIVE}.XXXXXX")
    if ! curl --fail --silent --show-error --location -o "$part" "$URL"
    then
        rm -f "$part"
        echo "fetch_mbedtls: FATAL - download failed" >&2
        exit 2
    fi
    mv "$part" "$ARCHIVE"
fi

# Pinned-hash verification; the fixed-string config edits below rely
# on the header's exact bytes being known.
GOT_SHA=$(compute_sha256 "$ARCHIVE")
if [ "$GOT_SHA" != "$SHA256" ]; then
    echo "fetch_mbedtls: FATAL - SHA-256 mismatch for $ARCHIVE" >&2
    echo "  expected: $SHA256" >&2
    echo "  got:      $GOT_SHA" >&2
    echo "  delete the file and re-run, or update the pin in" \
         "scripts/fetch_mbedtls.sh after independently verifying" \
         "the new hash." >&2
    exit 2
fi

# Discard any existing tree: the stamp is absent, stale or contradicts
# the header's hash, and the config edits are not undone by `make
# clean`. Guarded on a file only an extracted mbedTLS has, because the
# path is composed from environment variables and this is an `rm -rf`.
if [ -d "$DEST" ]; then
    if [ ! -f "$DEST/library/Makefile" ]; then
        echo "fetch_mbedtls: FATAL - $DEST exists but does not look" \
             "like an mbedTLS source tree; refusing to remove it." >&2
        exit 2
    fi
    echo "==> fetch_mbedtls: discarding stale tree $DEST"
    rm -rf "$DEST"
fi

# Unpacked into a staging directory first: the tarball contains
# mbedtls-<version>/, which would land on the posix tree when building
# for windows. mktemp -d, unique per invocation, not only per target.
echo "==> fetch_mbedtls: extracting ($TARGET, $MACHINE)"
STAGE=$(mktemp -d "${THIRD}/.unpack.XXXXXX")
tar xjf "$ARCHIVE" -C "$STAGE"
mv "${STAGE}/mbedtls-${VERSION}" "$DEST"
rmdir "$STAGE"

# Turn a macro on in the config header, then prove it took. The
# substitution is a fixed string against a hash-pinned file, so a
# miss means the pin moved; this check names the expected line.
enable_macro() {
    macro=$1
    # No `sed -i`: it needs an argument on BSD/macOS and none on GNU.
    sed "s|^//#define ${macro}\$|#define ${macro}|" "$CFG" > "${CFG}.new"
    mv "${CFG}.new" "$CFG"
    if ! grep -q "^#define ${macro}\$" "$CFG"; then
        echo "fetch_mbedtls: FATAL - could not enable ${macro} in" \
             "$CFG" >&2
        echo "  The expected '//#define ${macro}' line was not there." \
             "Has the pinned version changed?" >&2
        exit 3
    fi
}

# The inverse, for macros the pinned release ships enabled. A miss
# means the pin moved, not that the macro was already off.
disable_macro() {
    macro=$1
    sed "s|^#define ${macro}\$|//#define ${macro}|" "$CFG" > "${CFG}.new"
    mv "${CFG}.new" "$CFG"
    if ! grep -q "^//#define ${macro}\$" "$CFG"; then
        echo "fetch_mbedtls: FATAL - could not disable ${macro} in" \
             "$CFG" >&2
        echo "  The expected '#define ${macro}' line was not there." \
             "Has the pinned version changed?" >&2
        exit 3
    fi
}

# Both targets. mbedTLS draws through AHT.Random instead of its own
# entropy_poll.c (src/tls/mbedtls/aht-mbedtls-entropy.ads), whose
# Windows branch imports bcrypt.dll and leaves the image unloadable on
# XP. On posix too, so the whole suite runs through the callback.
enable_macro MBEDTLS_NO_PLATFORM_ENTROPY

# TLS 1.3 always uses PSA Crypto (upstream docs/use-psa-crypto.md),
# reached in every ClientHello via the key_share; PSA's own entropy
# context is left sourceless by MBEDTLS_NO_PLATFORM_ENTROPY, so every
# handshake would fail. The TLS1_3 key-exchange-mode macros stay as
# shipped: their prerequisites are PSA_WANT_*, so they pass
# check_config.h unused.
disable_macro MBEDTLS_SSL_PROTO_TLS1_3

case "$TARGET" in
    posix)
        enable_macro MBEDTLS_THREADING_C
        enable_macro MBEDTLS_THREADING_PTHREAD
        THREADING="pthread"
        EXTRA_CFLAGS=""
        ;;
    windows)
        THREADING="none"
        # Below 0x0600 x509_crt.c uses its own inet_pton; ws2_32
        # exports one only from Vista, and eager import resolution
        # would leave the image unloadable on XP. Keep in lockstep
        # with Win32_Winnt in aht.gpr, which the glue is compiled with.
        EXTRA_CFLAGS=" -D_WIN32_WINNT=${AHT_WIN32_WINNT:-0x0501}"
        ;;
esac

check_config

# Threading macros are in the header, which the glue reads too. CFLAGS
# is set, not appended: the Makefile's default is a bare -O2.
echo "==> fetch_mbedtls: building (threading: $THREADING)"
make -C "$DEST" CC="$CC" AR="$AR" CFLAGS="-O2$EXTRA_CFLAGS" lib >/dev/null

for lib in "$LIB_TLS" "$LIB_X509" "$LIB_CRYPTO"; do
    if [ ! -s "$lib" ]; then
        echo "fetch_mbedtls: FATAL - build did not produce $lib" >&2
        exit 3
    fi
done

# Written last, so an interrupted build leaves no stamp.
stamp_line "$(compute_sha256 "$CFG")" > "$STAMP"

echo "==> fetch_mbedtls: mbedTLS ${VERSION} built for ${TARGET}" \
     "${TRIPLET:+($TRIPLET) }($(du -h "$LIB_TLS" | cut -f1) libmbedtls.a," \
     "threading: $THREADING)"
