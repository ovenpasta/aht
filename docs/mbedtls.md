# mbedTLS Integration

Status: fetch + build chain done; bindings not yet generated.

The library targets **mbedTLS v2.28.9** (LTS). The version is pinned
for reproducibility; upgrading requires rerunning the binding
regeneration and curating any diffs.

## Fetch & build

`scripts/fetch_mbedtls.sh` does the following on first run:

1. Download the v2.28.9 source tarball from
   `https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v2.28.9.tar.gz`.
   The download is resumable (writes to `.part` then renames on
   success).
2. Verify SHA-256 against the pinned constant
   `e4dbcf86a4fb31506482888560f02b161e0ecfb82fee0643abcfc86abee5817e`
   — mismatch aborts the build loudly.
3. Extract into `third_party/mbedtls-2.28.9/`.
4. `make lib` with
   `CFLAGS="-O2 -DMBEDTLS_THREADING_C -DMBEDTLS_THREADING_PTHREAD"`
   so the library's internal mutex usage is task-safe (the WS
   receiver task and HTTP send path both touch the same SSL
   context).
5. Leave the static archives at
   `third_party/mbedtls-2.28.9/library/{libmbedtls,libmbedx509,libmbedcrypto}.a`.

The script is **idempotent**: once `libmbedtls.a` exists and is
non-empty it exits 0 without touching the network or invoking make,
so the second-run latency is a few milliseconds.

`alire.toml` runs the script as the `pre-build` action, so
`alr build` is one step (cold ~20 s on a modern box; warm
~instant).

`aht.gpr` will gain `-L third_party/mbedtls-2.28.9/library` and the
three `-l` flags once `AHT.Transport.TLS` lands — until then no
Ada code references mbedTLS symbols, so the libs build but don't
get linked.

## Bindings: generated, not hand-written

This is a firm convention, not a preference:

1. `scripts/regen_mbedtls_bindings.sh` (to be completed) creates a
   throwaway `scratch/gen_bindings/`.
2. Invokes:
   ```sh
   gcc -c -fdump-ada-spec -C \
       -fada-spec-parent=AHT.Mbedtls \
       -I third_party/mbedtls-2.28.9/include \
       third_party/mbedtls-2.28.9/include/mbedtls/ssl.h \
       third_party/mbedtls-2.28.9/include/mbedtls/net_sockets.h \
       third_party/mbedtls-2.28.9/include/mbedtls/x509_crt.h \
       third_party/mbedtls-2.28.9/include/mbedtls/ctr_drbg.h \
       third_party/mbedtls-2.28.9/include/mbedtls/entropy.h \
       third_party/mbedtls-2.28.9/include/mbedtls/error.h
   ```
3. The operator reads the generated `.ads` files and copies only the
   identifiers actually used by `AHT.Transport.TLS` into
   `src/aht-mbedtls-*.ads`. Unused symbols are dropped.
4. A hand-written `aht-mbedtls.adb` helper maps non-zero mbedTLS
   `int` returns to `AHT.Transport.TLS.TLS_Error` with the human
   message from `mbedtls_strerror`.

**Do not** hand-write `pragma Import` lines for mbedTLS. Doing so
invites struct-layout / signature drift between C headers and Ada
specs. The generator keeps the binding honest.

## Surface actually used

Scoped to the minimum that `AHT.Transport.TLS` needs:

- `mbedtls_{ssl,ssl_config,entropy,ctr_drbg,x509_crt,net}_init`/`_free`
- `mbedtls_ssl_config_defaults`
- `mbedtls_ssl_conf_authmode`, `_ca_chain`, `_rng`
- `mbedtls_ssl_setup`, `mbedtls_ssl_set_hostname`, `mbedtls_ssl_set_bio`
- `mbedtls_ssl_handshake`, `mbedtls_ssl_read`, `mbedtls_ssl_write`
- `mbedtls_ssl_close_notify`
- `mbedtls_net_connect`
- `mbedtls_x509_crt_parse_file` / `_parse_path`
- `mbedtls_ctr_drbg_seed`, `mbedtls_entropy_func`
- `mbedtls_strerror`

Everything else from the generated specs is dropped on curation.
