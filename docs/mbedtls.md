<!--
SPDX-FileCopyrightText: 2026 Aldo Nicolas Bruno
SPDX-License-Identifier: Apache-2.0
-->

# mbedTLS Integration

This is the **mbedtls TLS backend** (`AHT_TLS_BACKEND=mbedtls`). The
default backend is the system OpenSSL 3; [`tls.md`](tls.md) covers
backend selection, the per-backend behavioural differences, and the
engine design both backends share. This file covers what is specific
to mbedTLS: fetching and building the vendored library, linking it,
the C glue, and the binding surface.

The backend targets **mbedTLS 3.6.7**, the current long-term-support
line, which upstream supports with security fixes until at least
March 2027.

## Fetch and build

`scripts/fetch_mbedtls.sh` runs as the Alire `pre-build` action, so
`alr build` is one step (about 20 s cold, a few milliseconds warm).
Under any backend other than mbedtls it exits immediately. Otherwise
it:

1. Downloads the official release asset
   `https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2`,
   resumably (a `.part` file renamed on success). GitHub's
   auto-generated tag snapshots omit the `framework/` submodule and
   do not build.
2. Verifies the SHA-256 against the pinned constant
   `a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6`;
   a mismatch fails the build.
3. Extracts into `third_party/mbedtls-3.6.7/` for POSIX, or
   `third_party/mbedtls-3.6.7-<triplet>/` for `AHT_OS=windows`
   (`AHT_CROSS_TARGET`, checked against the compiler's
   `-dumpmachine`). mbedTLS builds in-tree, and the targets are not
   configured alike.
4. Edits the tree's own `include/mbedtls/mbedtls_config.h`:
   `MBEDTLS_NO_PLATFORM_ENTROPY` on, `MBEDTLS_SSL_PROTO_TLS1_3` off,
   and on POSIX `MBEDTLS_THREADING_C` and
   `MBEDTLS_THREADING_PTHREAD` on. Windows is built threadless. A
   compiled probe then asks the preprocessor that the edits took and
   that neither `MBEDTLS_USE_PSA_CRYPTO` nor
   `MBEDTLS_SSL_PROTO_TLS1_3` is reachable by any route.
5. Runs `make lib` with `CFLAGS="-O2"`. The Windows targets add
   `-D_WIN32_WINNT=0x0501` (`AHT_WIN32_WINNT`), which is not an
   mbedTLS macro and changes no struct: `x509_crt.c` calls the
   platform `inet_pton` at `0x0600` and above and its own software
   one below, and `ws2_32` exports `inet_pton` only from Vista, so
   the higher value leaves an image that verifies an IP SAN
   unloadable on XP. `aht.gpr` passes the same value (`Win32_Winnt`)
   to the glue; `scripts/check_xp_imports.sh` catches the two
   disagreeing.
6. Leaves the static archives at
   `<tree>/library/{libmbedtls,libmbedx509,libmbedcrypto}.a` and
   writes a build stamp recording the script schema, the version,
   the target, the compiler, and the hash of the edited config
   header.

The script is idempotent: when the stamp matches what the invocation
wants, it exits 0 without touching the network or invoking make. A
tree whose stamp does not match is re-extracted rather than repaired,
because the header edits are one-way and `make clean` does not undo
them.

Configuration lives in the header rather than in `-D` flags so that
the archive and the C glue read the same bytes. `aht.gpr` carries no
mbedTLS macros, only `-I` at the tree's `include/`. See
*Configuration of the vendored library* in [`tls.md`](tls.md).

## Linking

Three places contribute to the link line:

- `aht.gpr` puts `-L<tree>/library` (`Mbedtls_Lib_Dir`, absolute via
  `Aht'Project_Dir`) in `Linker'Linker_Options`, so it also resolves
  when AHT is consumed as a dependency.
- `AHT.Mbedtls` (`src/tls/mbedtls/aht-mbedtls.ads`) names the three
  archives with `pragma Linker_Options`: `-lmbedtls`, `-lmbedx509`,
  `-lmbedcrypto`. The pragmas fire only when a binary transitively
  `with`s `AHT.Mbedtls.*`, so binaries that do not touch TLS skip
  them.
- `AHT.Mbedtls.Link` carries the OS-dependent part. The POSIX spec
  (`src/tls/mbedtls/os/posix/`) adds `-lpthread`, which the threaded
  archive needs; the Windows spec (`src/tls/mbedtls/os/windows/`) is
  empty, because that archive is threadless. `aht.gpr` puts exactly
  one of the two directories on `Source_Dirs`.

## Contexts are opaque: the C glue owns `sizeof`

Ada binds mbedTLS functions, whose signatures are ABI-stable, and
never models a context struct. The structs' layout and size depend on
the target ABI and on the build configuration (`MBEDTLS_THREADING_C`
adds a mutex member), so any size baked into Ada would be wrong the
moment either differed from the box the binding was written on.

Every context is an opaque `System.Address`, allocated and freed by
`csrc/mbedtls/aht_mbedtls_glue.c`:

- `aht_mbedtls_{ssl,config,ctr_drbg,entropy,x509_crt}_new`:
  `malloc(sizeof *c)` plus the matching `_init`, returning `void *`
  (NULL on allocation failure). The target's C compiler computes
  `sizeof`.
- the matching `_free`: the library's `_free` plus `free`.
- `aht_mbedtls_entropy_new` also registers
  `aht_mbedtls_entropy_poll` (`AHT.Mbedtls.Entropy.Poll`) with
  `mbedtls_entropy_add_source` as the pool's only source, marked
  strong, with `MBEDTLS_ENTROPY_BLOCK_SIZE` as the threshold. A
  failed registration is reported as allocation failure.
- `aht_mbedtls_ctr_drbg_seed` and `aht_mbedtls_conf_rng`, the two
  calls that pass mbedTLS's own function pointers
  (`mbedtls_entropy_func`, `mbedtls_ctr_drbg_random`).

`src/tls/mbedtls/aht-mbedtls-glue.ads` is the Ada side: each entry is
a `System.Address` import. The glue is a separate translation unit
from the archive and must see the same configuration; it does,
because both read the tree's `mbedtls_config.h`.

## Byte I/O

mbedTLS does crypto only. `mbedtls_ssl_set_bio` installs the send and
recv callbacks (`Send_CB`, `Recv_CB` in
`src/tls/mbedtls/aht-transport-tls.adb`), and they move bytes to and
from two in-memory queues; they never call the TCP transport, and
`mbedtls_net_*` is not used. The engine loop around each
`mbedtls_ssl_*` call drains the outbound queue to the socket and
feeds the inbound queue from it, so `Timeout_Error`, `Aborted_Error`
and `Transport_Error` propagate from the engine's own
`TCP.Read`/`TCP.Write` calls and no exception crosses the C frame.
The only failure a callback reports is an allocation failure while
growing a queue, returned as `MBEDTLS_ERR_NET_*`; the callbacks
record no error kind. Fatal mbedTLS codes become `TLS_Error` carrying
the `mbedtls_strerror` message (`AHT.Mbedtls.Error.Strerror`). The
engine, its locks and its coordinator are described once, in
[`tls.md`](tls.md).

## Binding surface

The packages under `src/tls/mbedtls/`:

- `AHT.Mbedtls`: the root; the archive link pragmas.
- `AHT.Mbedtls.SSL`: `mbedtls_ssl_config_defaults`,
  `mbedtls_ssl_conf_authmode`, `mbedtls_ssl_conf_ca_chain`,
  `mbedtls_ssl_setup`, `mbedtls_ssl_set_hostname`,
  `mbedtls_ssl_set_bio`, `mbedtls_ssl_handshake`,
  `mbedtls_ssl_read`, `mbedtls_ssl_write`,
  `mbedtls_ssl_close_notify`, the callback profiles, and the
  protocol and error constants the body branches on.
- `AHT.Mbedtls.X509`: `mbedtls_x509_crt_parse_file`,
  `mbedtls_x509_crt_parse_path`, and `mbedtls_x509_crt_parse` for
  `CA_PEM`.
- `AHT.Mbedtls.Glue`: the C glue above.
- `AHT.Mbedtls.Entropy`: `Poll`, exported to C as
  `aht_mbedtls_entropy_poll`; fills from `AHT.Random` and returns
  `MBEDTLS_ERR_ENTROPY_SOURCE_FAILED` on any failure, never
  propagating an exception.
- `AHT.Mbedtls.Error`: `Strerror`, wrapping `mbedtls_strerror`.
- `AHT.Mbedtls.Link`: the OS-dependent link line, one spec per OS
  directory.
- `AHT.Mbedtls.Version`: the pinned `Major`, `Minor` and `Patch`,
  and `Version_String`/`Full_Version_String` wrapping
  `mbedtls_version_get_string` and `mbedtls_version_get_string_full`.

Through the glue, `mbedtls_entropy_add_source`,
`mbedtls_ctr_drbg_seed`, `mbedtls_entropy_func`,
`mbedtls_ssl_conf_rng` and `mbedtls_ctr_drbg_random` are reached as
well. Everything else in the generated specs is dropped at curation.

## Maintaining the backend

### Regenerating the bindings

The bindings are generated and curated, never hand-typed. Do not add
`pragma Import` lines for mbedTLS without running the generator
first; hand-typed imports invite signature drift between the C
headers and the Ada specs.

1. `scripts/regen_mbedtls_bindings.sh` creates a throwaway
   `scratch/gen_bindings/` and runs
   `gcc -c -fdump-ada-spec -C -fada-spec-parent=AHT.Mbedtls` against
   `version.h`, `error.h`, `ssl.h`, `net_sockets.h`, `x509_crt.h`,
   `ctr_drbg.h` and `entropy.h` in the vendored tree. It does not
   run as part of `alr build`.
2. Copy a curated subset, only the identifiers `AHT.Transport.TLS`
   uses, into `src/tls/mbedtls/aht-mbedtls-*.ads`. Curation drops
   the `_h` suffix on the package name
   (`aht-mbedtls-mbedtls_version_h.ads` becomes
   `aht-mbedtls-version.ads`), drops unused symbols (the generator
   emits around 50 files of transitive libc baggage), simplifies
   buffer parameters from `Interfaces.C.Strings.chars_ptr` to
   `System.Address` so that callers can pass a stack `char_array` by
   `'Address`, and adds Ada wrappers returning `String` where the C
   side fills a NUL-terminated buffer.

### Bumping the version

Four places name the version independently, and nothing in the build
reconciles them:

- `VERSION` and `SHA256` in `scripts/fetch_mbedtls.sh`;
- `Mbedtls_Tree` in `aht.gpr`;
- `Major`, `Minor` and `Patch` in `AHT.Mbedtls.Version`;
- the tree path in `scripts/regen_mbedtls_bindings.sh`.

`test_tls_version` asks the linked library for its version string and
compares it against literals spelled out in the test, which is what
reports a `Mbedtls_Tree` left pointing at a tree the fetch script no
longer builds; update those literals too. After a bump, rerun the
binding generator and curate any diffs. Bump `SCHEMA` in the fetch
script whenever the script changes how a tree is produced or checked,
so that existing trees are rebuilt.

### The threadless Windows build

The Windows archive has no `MBEDTLS_THREADING_C`. The argument that
this is sound, per mutex the library would otherwise take:

- `entropy.c`, `ctr_drbg.c`: both contexts are per transport object
  (`Backend_State`), never shared between sessions or tasks.
- `rsa.c`: the context is per session. `mbedtls_rsa_public` takes
  the mutex during certificate verification, which happens in the
  single-tasked handshake.
- `ssl_cache.c`, `ssl_ticket.c`, `ssl_cookie.c`: server-side state.
- `hmac_drbg.c`: unused; the RNG is CTR_DRBG.
- `memory_buffer_alloc.c`: `MBEDTLS_MEMORY_BUFFER_ALLOC_C` is off.
- `x509_crt.c`: the `readdir` mutex guards the POSIX branch of
  `mbedtls_x509_crt_parse_path`; the `_WIN32` branch uses
  `FindFirstFileW` with a per-call handle.
- `platform_util.c`: the `gmtime` mutex guards the
  `PLATFORM_UTIL_USE_GMTIME` fallback; `_WIN32` uses the thread-safe
  `gmtime_s`.

The argument holds only while PSA Crypto stays unreached, since PSA
keeps process-global state that no per-session lock covers. The
fetch script's compiled probe fails the build if
`MBEDTLS_USE_PSA_CRYPTO` or `MBEDTLS_SSL_PROTO_TLS1_3` is on, for
both targets; the header of `scripts/fetch_mbedtls.sh` states why.
Making the entropy source or the DRBG a library-level singleton would
invalidate the first row, and the comment on `Backend_State` in the
backend body says so.
