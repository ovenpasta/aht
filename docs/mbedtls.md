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

The link wiring is `pragma Linker_Options` in
`src/aht-mbedtls.ads` rather than a project-level switch:

```ada
pragma Linker_Options ("-Lthird_party/mbedtls-2.28.9/library");
pragma Linker_Options ("-lmbedtls");
pragma Linker_Options ("-lmbedx509");
pragma Linker_Options ("-lmbedcrypto");
pragma Linker_Options ("-lpthread");
```

The pragmas only fire when a binary transitively `with`s
`AHT.Mbedtls.*`, so test binaries that don't touch mbedTLS skip
the extra link step entirely. Relative paths resolve against the
linker's CWD, which `gprbuild` sets to the project root.

## Bindings: generated, not hand-written

This is a firm convention, not a preference:

1. `scripts/regen_mbedtls_bindings.sh` creates a throwaway
   `scratch/gen_bindings/` and invokes
   `gcc -c -fdump-ada-spec -C -fada-spec-parent=AHT.Mbedtls`
   against the per-module headers
   (`version.h`, `error.h`, `ssl.h`, `net_sockets.h`,
   `x509_crt.h`, `ctr_drbg.h`, `entropy.h`).
2. The operator reads the generated `.ads` files and copies a
   *curated* subset — only the identifiers actually used by
   `AHT.Transport.TLS` — into `src/aht-mbedtls-*.ads`. The
   curation step typically:
   * drops the `_h` suffix on the package name
     (`aht-mbedtls-mbedtls_version_h.ads` →
     `aht-mbedtls-version.ads`);
   * drops unused symbols (the generator emits ~50 .ads files of
     transitive glibc/stdc baggage; we keep one per mbedTLS
     module);
   * simplifies buffer parameters from
     `Interfaces.C.Strings.chars_ptr` (heap-allocated) to
     `System.Address` where callers want to pass a stack
     `char_array` via `'Address`;
   * adds an Ada-side wrapper that returns a `String` instead
     of leaving the caller to manage NUL termination.
3. A hand-written body (`aht-mbedtls.adb`, when TLS lands) will
   map non-zero mbedTLS `int` returns to `AHT.Transport.TLS_Error`
   with the human message from `mbedtls_strerror`.

**Do not** hand-write `pragma Import` lines for mbedTLS without
running the generator first. Doing so invites struct-layout /
signature drift between C headers and Ada specs. The current
small surface — `AHT.Mbedtls.Version` only, for the bind/link
smoke test — was curated from the regenerated output, not
hand-typed.

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
