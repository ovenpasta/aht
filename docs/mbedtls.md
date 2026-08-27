# mbedTLS Integration

This is the **mbedtls TLS backend** (`AHT_TLS_BACKEND=mbedtls`; the
default backend is the system OpenSSL 3 — see [`tls.md`](tls.md) for
backend selection and the per-backend behavioral differences).

`AHT.Transport.TLS`'s mbedtls body sits on top of the TCP transport
via custom BIO callbacks; the transport-level test
(`tests/src/test_tls.adb`) covers verify, insecure, and
untrusted-chain rejection.

This backend targets **mbedTLS 3.6.7**, the current long-term-support
line, which upstream supports with security fixes until at least
March 2027. The default backend is still the system OpenSSL 3.

Changing the version means rerunning the binding regeneration and
curating any diffs, and it means updating three things that name the
version independently: `VERSION` and the pinned SHA-256 in
`scripts/fetch_mbedtls.sh`, `Mbedtls_Tree` in `aht.gpr`, and the
constants in `AHT.Mbedtls.Version`. Nothing in the build reconciles
them. What catches a disagreement is `test_tls_version`, which asks
the linked library for its own version string and compares it against
a hardcoded expectation — the only kind that can disagree with the
binary. A `Mbedtls_Tree` left pointing at a tree the fetch script no
longer builds compiles and links perfectly well, and that test is what
reports it.

## Fetch & build

`scripts/fetch_mbedtls.sh` does the following on first run:

1. Download the official release tarball from
   `https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2`.
   The download is resumable (writes to `.part` then renames on
   success). It is the uploaded release asset and not GitHub's
   auto-generated tag snapshot: the snapshots omit the `framework/`
   submodule and do not build.
2. Verify SHA-256 against the pinned constant
   `a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6`
   — mismatch aborts the build loudly.
3. Extract into `third_party/mbedtls-3.6.7/`.
4. Edit the tree's own `include/mbedtls/mbedtls_config.h`, then
   `make lib` with `CFLAGS="-O2"`. The configuration lives in that
   header rather than in `-D` flags so the archive and the C glue
   cannot disagree about a macro that changes a struct's size; the
   script's header explains what that would cost.
5. Leave the static archives at
   `third_party/mbedtls-3.6.7/library/{libmbedtls,libmbedx509,libmbedcrypto}.a`.

The script is **idempotent**: once `libmbedtls.a` exists and is
non-empty it exits 0 without touching the network or invoking make,
so the second-run latency is a few milliseconds.

`alire.toml` runs the script as the `pre-build` action, so
`alr build` is one step (cold ~20 s on a modern box; warm
~instant).

The link wiring is `pragma Linker_Options` in
`src/aht-mbedtls.ads` rather than a project-level switch:

```ada
pragma Linker_Options ("-Lthird_party/mbedtls-3.6.7/library");
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
3. `AHT.Mbedtls.Error.Strerror` wraps `mbedtls_strerror` to turn a
   non-zero `int` return into an Ada `String`; `AHT.Transport.TLS`
   maps those into `TLS_Error` (or, for a BIO-callback failure, the
   matching `Timeout_Error` / `Aborted_Error` / `Transport_Error`).

**Do not** hand-write `pragma Import` lines for mbedTLS without
running the generator first. Doing so invites struct-layout /
signature drift between C headers and Ada specs. The current
small surface — `AHT.Mbedtls.Version` only, for the bind/link
smoke test — was curated from the regenerated output, not
hand-typed.

## Contexts are opaque: the C glue owns sizeof

Ada binds mbedTLS **functions** (ABI-stable signatures) but never
models a context struct. The structs' layout and size depend on the
target ABI *and* the build configuration — `MBEDTLS_THREADING_C` adds a
mutex member, for instance — so any size baked into Ada (a hardcoded
`sizeof`, or a hand-modelled record) is wrong the moment the target or
config differs from the box the binding was written on.

Instead, every context is an opaque `System.Address`, allocated and
freed by a tiny C translation unit, `csrc/aht_mbedtls_glue.c`:

- `aht_mbedtls_{ssl,config,ctr_drbg,entropy,x509_crt}_new` —
  `malloc(sizeof *c)` + the matching `_init`, returning `void *`. The
  *target's* C compiler computes `sizeof`, so it is always correct.
- the matching `_free` — `_free` + `free`.
- `aht_mbedtls_ctr_drbg_seed` / `aht_mbedtls_conf_rng` — the two calls
  that pass mbedTLS's own function pointers (`mbedtls_entropy_func`,
  `mbedtls_ctr_drbg_random`), which is naturally C's job.

`src/aht-mbedtls-glue.ads` is the thin Ada side: each entry is a
`System.Address`-in / `System.Address`-out import.

> **Config macros must match the library.** The glue is a separate
> translation unit from the `.a`, so it must be compiled with the
> *same* `mbedtls_config` view — specifically `MBEDTLS_THREADING_C`
> and `MBEDTLS_THREADING_PTHREAD`. If the library has the mutex member
> but the glue's headers don't, `*_new` under-allocates and the
> library's `*_init` writes past the block (heap corruption). The C
> switches in `aht.gpr` carry these defines and must stay in lockstep
> with the CFLAGS in `scripts/fetch_mbedtls.sh`.

## Byte I/O stays on the TCP transport (custom BIO)

mbedTLS does crypto only. `mbedtls_ssl_set_bio` installs send/recv
callbacks that bridge to the existing `AHT.Transport.TCP`, so HTTPS/WSS
inherit its DNS multi-candidate fallback, compound read deadline, and
`Abort_Pending` unchanged — there is no second socket stack and
`mbedtls_net_*` is not used. Because an Ada exception must never cross
the C callback frame, each callback catches it, records the kind in the
BIO context, and returns a negative `MBEDTLS_ERR_NET_*` code; the Ada
side re-raises the right exception after the mbedTLS call returns.

## Surface actually used

Scoped to the minimum that `AHT.Transport.TLS` needs:

- context lifecycle via the C glue (see above), not direct
  `_init`/`_free` from Ada
- `mbedtls_ssl_config_defaults`
- `mbedtls_ssl_conf_authmode`, `_ca_chain`, `_rng`
- `mbedtls_ssl_setup`, `mbedtls_ssl_set_hostname`, `mbedtls_ssl_set_bio`
- `mbedtls_ssl_handshake`, `mbedtls_ssl_read`, `mbedtls_ssl_write`
- `mbedtls_ssl_close_notify`
- `mbedtls_x509_crt_parse_file` / `_parse_path`
- `mbedtls_ctr_drbg_seed`, `mbedtls_entropy_func`
- `mbedtls_strerror`

Byte I/O is the TCP transport's job (custom BIO), so `mbedtls_net_*`
is deliberately absent. Everything else from the generated specs is
dropped on curation.
