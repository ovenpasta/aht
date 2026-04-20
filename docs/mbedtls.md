# mbedTLS Integration

Status: fetch script is a placeholder; binding not yet generated.

The library targets **mbedTLS v2.28.9** (LTS). The version is pinned
for reproducibility; upgrading requires rerunning the binding
regeneration and curating any diffs.

## Fetch & build

`scripts/fetch_mbedtls.sh` (to be completed) does:

1. Download `mbedtls-2.28.9.tar.bz2` from the upstream GitHub release.
2. Verify SHA-256 against a pinned constant in the script.
3. Extract into `third_party/mbedtls-2.28.9/`.
4. `make lib` with
   `CFLAGS="-DMBEDTLS_THREADING_C -DMBEDTLS_THREADING_PTHREAD"` so
   the library is safe under Ada tasking.
5. Leave the static archives at
   `third_party/mbedtls-2.28.9/library/{libmbedtls,libmbedx509,libmbedcrypto}.a`.

`alire.toml` runs the script as a `pre-build` action, so `alr build`
is one step.

`aht.gpr` exposes `-L third_party/mbedtls-2.28.9/library` through
`package Linker`; the binding unit carries a `pragma Linker_Options`
for the three `-l` flags so any executable transitively pulls them in.

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
