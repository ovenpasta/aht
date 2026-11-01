#!/bin/sh
# Copyright (C) 2026 Zack Boll
# SPDX-License-Identifier: Apache-2.0
set -eu
cd "$(dirname "$0")/../.."
test "$(uname -s)" = Linux || { echo 'Linux pressure fixture required' >&2; exit 2; }
export AHT_TLS_BACKEND=${AHT_TLS_BACKEND:-openssl}
export BUILD_MODE=${BUILD_MODE:-debug}
gprbuild -p -j4 -P tests/nonblocking/nonblocking.gpr
scratch=$(mktemp -d /tmp/aht-nonblocking-XXXXXX)
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
python3 tests/nonblocking/reproduce.py \
  --probe "$(pwd)/tests/bin/nonblocking-$BUILD_MODE-$AHT_TLS_BACKEND/tls_probe" \
  --aht "$(pwd)" --backend "$AHT_TLS_BACKEND" --scratch "$scratch/results"