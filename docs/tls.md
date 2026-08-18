# TLS Backends

`AHT.Transport.TLS` is one spec with two interchangeable bodies. The
backend is chosen at build time and exactly one backend's sources and
libraries are compiled/linked:

- **openssl** (default) — the system OpenSSL 3 (`libssl`/`libcrypto`),
  TLS 1.2/1.3. Bindings: `AHT.Openssl.*` under `src/tls/openssl/`.
- **mbedtls** — vendored mbedTLS 2.28 (TLS 1.2), downloaded and
  compiled on first build by `scripts/fetch_mbedtls.sh`. Bindings:
  `AHT.Mbedtls.*` under `src/tls/mbedtls/`; see
  [`mbedtls.md`](mbedtls.md).

## Selecting a backend

```sh
alr build                                   # openssl (default)
AHT_TLS_BACKEND=mbedtls alr build           # mbedtls
```

`AHT_TLS_BACKEND` is a gpr external read from the environment (or
`-XAHT_TLS_BACKEND=...`). **The environment variable is the supported
route**: it also reaches the Alire pre-build action, which is how
`scripts/fetch_mbedtls.sh` knows whether to fetch — a consumer that
selects mbedtls only through `[gpr-set-externals]` must additionally
export the variable (or run the fetch script once by hand), because
gpr externals do not reach action environments.

Every build combination gets its own output tree
(`obj/<mode>-<backend>`, `lib/<mode>-<backend>`, test/example `bin/`
dirs likewise), so switching never clobbers artifacts. `AHT_OS=windows`
appends the cross toolchain's **target triplet** to that variant
(`obj/debug-mbedtls-x86_64-w64-mingw32`) and gets its own mbedTLS tree
(`third_party/mbedtls-2.28.9-x86_64-w64-mingw32`), because mbedTLS
builds in-tree and the targets are not configured alike. The triplet
rather than the word "windows": an i686 and an x86-64 mingw build are
as incompatible as a Linux one, and a shared directory would let each
overwrite the other. `AHT_CROSS_TARGET` selects it, and
`scripts/fetch_mbedtls.sh` checks it against the compiler's own
`-dumpmachine`. POSIX keeps the unsuffixed names, so existing
checkouts are undisturbed.

mbedtls is the backend for `AHT_OS=windows`: the openssl backend wants
a system OpenSSL 3, and the vendored tree is what makes a cross build
self-contained. Windows is **not a supported configuration** — see
`AHT_OS` in `aht.gpr` and the note in `CLAUDE.md` for what has been
measured and what has not.

`AHT_OPENSSL_DIR` (default `/usr`) points at the OpenSSL installation
prefix. Linux distributions with `libssl-dev` need nothing; macOS
ships no OpenSSL headers, so:

```sh
brew install openssl@3
export AHT_OPENSSL_DIR=$(brew --prefix openssl@3)
```

The openssl backend requires OpenSSL **3** — the bindings import
3.0-only symbols (link-time failure on LibreSSL/1.1) and `Connect`
double-checks `OPENSSL_version_major >= 3` at runtime.

## Behavioral differences

The public contract (`aht-transport-tls.ads`) is shared; two policies
deliberately differ per backend:

| | openssl | mbedtls |
|---|---|---|
| `CA_PEM` supplied | envelope validated by `AHT.PEM` first, always — including under `Insecure`, where OpenSSL then loads nothing because verification is off while mbedTLS still parses the chain. Validation is the normalised behaviour; loading is not. Mutually exclusive with `CA_Path`. | same validation; the chain is parsed even under `Insecure` |
| `CA_Path = ""`, verifying | platform trust store (`SSL_CTX_set_default_verify_paths`; honours `SSL_CERT_FILE`/`SSL_CERT_DIR`) — public `https://` endpoints work out of the box | no default trust — the handshake rejects; pass a CA bundle or set `Insecure` |
| CA **directory** semantics | c_rehash hashed-name lookup | loads every file in the directory |
| IP-literal host, verifying | verified against the cert's IP SANs (`X509_VERIFY_PARAM_set1_ip_asc`), no SNI sent | rejected — mbedTLS 2.28 matches dNSName SANs/CN only |
| Abrupt TCP EOF (no close_notify) | **`TLS_Error`** — truncation must fail, because HTTP supports EOF-framed bodies and a silent truncation would be a data-integrity hole (`SSL_OP_IGNORE_UNEXPECTED_EOF` is never set) | clean EOF (`Last = 0`) — long-standing backend behavior, pinned by test_tls_truncation |
| Protocol versions | TLS 1.2 minimum, TLS 1.3 active; renegotiation disabled | TLS 1.2 (mbedTLS 2.28 maximum) |

Both backends: DNS-name hosts get SNI + hostname verification;
`Insecure => True` skips certificate verification entirely (SNI still
sent for DNS names); a failed `Connect` leaves the object retryable
while a successful session makes it single-use.

## The openssl engine (memory BIOs)

OpenSSL 3 does not permit two tasks inside `SSL_read`/`SSL_write` on
one `SSL*` — TLS 1.3 KeyUpdates and session tickets processed inside a
read mutate connection-shared state — but the WebSocket client runs a
receiver task in `Read` concurrently with senders in `Write`. The
engine therefore never lets OpenSSL touch the socket:

- `SSL_set_bio` installs two `BIO_s_mem` BIOs (RBIO inbound ciphertext,
  WBIO outbound). Every `SSL_*` call is **non-blocking** and runs
  under `SSL_Lock` with a fixed discipline: `ERR_clear_error` → one
  call → `SSL_get_error` immediately → capture the error queue on a
  fatal result (latching `Engine_Dead` before the lock is released —
  OpenSSL forbids further I/O after `SSL_ERROR_SSL`/`SSL_ERROR_SYSCALL`)
  → sample WBIO's pending count → release.
- **Drain (wire output)**: under `Drain_Lock` (strict order: Drain
  outer, SSL inner), WBIO ciphertext is extracted and written to the
  TCP transport; extraction under the drain lock keeps wire order. A
  drain failure is fail-closed: ciphertext may be half-sent, so the
  engine dies and the session is poisoned.
- **Feed (wire input)**: a protected coordinator arbitrates the single
  `TCP.Read` via an atomic feeder claim; the non-owner parks on a
  single-waiter armed latch (claim-failure and arming are one
  protected action — no lost wakeups) and is woken by feed, feeder
  release, EOF, fatal, or abort, then re-evaluates and retries. Sound
  because the transport contract allows at most one reader + one
  writer task. `SSL_write → WANT_READ` (a post-handshake message
  mid-stream) self-feeds when the claim is free, else waits — bounded
  by the WRITE deadline either way.
- **Deadlines**: both `Set_*_Deadline` budgets are mirrored as
  absolute instants computed once at the setter call; every blocking
  step — lock seize (timed entry call), latch wait, feed `TCP.Read`,
  drain `TCP.Write` (deadline-explicit TCP overloads) — is bounded by
  the deadline of the operation performing it, and re-checks a modular
  abort epoch bumped by `Abort_Pending` (which wakes both selector
  waiters and the latch waiter; non-sticky by epoch snapshot).
- **EOF**: RBIO starts "empty is retryable" (`BIO_set_mem_eof_return
  -1`, → WANT_READ) and flips to hard EOF (0) when `TCP.Read` reports
  the stream ended, so the next engine call classifies it: a real
  close_notify reads as clean EOF (`ZERO_RETURN` → `Last = 0`),
  anything else is the truncation `TLS_Error`.
- **Close** never skips cleanup: `SSL_shutdown` (its own result
  protocol — a 0 return means close_notify queued and `SSL_get_error`
  must NOT be consulted; skipped entirely after fatal errors) and
  `TCP.Close` run in separate best-effort blocks, then the frees
  (`SSL_free` reclaims both BIOs, then `SSL_CTX_free`) run
  unconditionally.

The coordinator and locks live in `AHT.TLS_Sync` (shared by both
engines), and `test_tls_keyupdate` drives them white-box on either
backend via `TLS_Sync_Cases` (claim/arm atomicity,
abort-wakes-parked-waiter, deadline-expiry-while-parked,
wake-then-claim) — plus, on openssl, an end-to-end `openssl s_server`
KeyUpdate exchange including a phase with a writer task running
concurrently with the reader across rekeys. The CLI for that
test is trusted only at `${AHT_OPENSSL_DIR:-/usr}/bin/openssl` and
only if `version` reports OpenSSL 3 — a bare `openssl` on PATH may be
LibreSSL.

## The mbedtls engine

The mbedtls backend is built the same way, and for the same reason.
An `mbedtls_ssl_context` is **not** safe for two tasks at once: the
library's own mutexes, in a build that has any, guard its shared
internals and never one session's state, and `mbedtls_ssl_read` may
itself write (alerts). Since the WebSocket client runs a receiver task
in `Read` while senders call `Write`, a blocking-BIO design would put
two tasks inside one context.

So the BIO callbacks never touch the socket either: they move bytes to
and from two in-memory queues (`Engine_IO`), making every
`mbedtls_ssl_*` call return promptly — `MBEDTLS_ERR_SSL_WANT_READ`
when the inbound queue is dry — with the same Phase A / drain / feed
structure, the same `SSL_Lock` + `Drain_Lock` ordering, the same
`AHT.TLS_Sync` coordinator, and the same per-operation deadline and
abort-epoch bounds as above. Network exceptions propagate natively
from the engine's own `TCP.Read`/`TCP.Write` calls, so nothing has to
smuggle an Ada exception across a C frame any more.

### How the vendored library is configured

`scripts/fetch_mbedtls.sh` builds one tree per target and writes the
configuration into that tree's own `include/mbedtls/config.h` rather
than passing `-D` flags. `aht.gpr` points the glue's `-I` at the same
header, so the archive and `csrc/mbedtls/aht_mbedtls_glue.c` read
identical bytes.

That is not tidiness. `MBEDTLS_THREADING_C` adds a mutex member to
several context structs, so a glue translation unit that disagrees
with the archive computes a different `sizeof`, under-allocates in its
`*_new`, and `mbedtls_*_init` writes past the block. Nothing reports
it. Stating the macros in two files and keeping them in step by
comment is exactly the arrangement that produces that bug.

POSIX enables `MBEDTLS_THREADING_C` and `MBEDTLS_THREADING_PTHREAD`.

**Windows is built threadless**, because mbedTLS 2.28 offers pthread
or a caller-supplied `THREADING_ALT` and nothing else. That is sound
rather than convenient — but not because the mutexes are all
unreachable. Some are; the rest guard state that only ever has one
task in it, for reasons this client enforces itself.

| Mutex in 2.28 | Why it cannot matter here |
|---|---|
| `entropy.c`, `ctr_drbg.c` | Both contexts are per transport object (`Backend_State`), never shared between sessions or tasks |
| `rsa.c` | The context is per session and every engine call on it is serialized (see below) |
| `ssl_cache.c`, `ssl_ticket.c`, `ssl_cookie.c` | Server-side state |
| `hmac_drbg.c` | Unused — the RNG is CTR_DRBG |
| `memory_buffer_alloc.c` | `MBEDTLS_MEMORY_BUFFER_ALLOC_C` is off |
| `x509_crt.c` | The `readdir` mutex guards the POSIX branch of `mbedtls_x509_crt_parse_path`; the `_WIN32` branch uses `FindFirstFileW` with a per-call handle |
| `platform_util.c` | The `gmtime` mutex guards the `PLATFORM_UTIL_USE_GMTIME` fallback; `_WIN32` uses the thread-safe `gmtime_s` |

The argument holds only while `MBEDTLS_USE_PSA_CRYPTO` is off: PSA in
2.28 keeps process-global state, and its threading arrived in 3.6. The
fetch script checks that macro and fails the build if it is ever
enabled, for both targets.

The RSA row needs spelling out, because two plausible readings of it
are both wrong.

"This client has no private key" is true and beside the point:
`mbedtls_rsa_private` is not the only holder of that mutex,
`mbedtls_rsa_public` takes it too, and certificate verification goes
straight through `mbedtls_rsa_public`.

"Every engine call is serialized under `SSL_Lock`" is also not it. The
handshake — which is exactly when certificates are verified — runs
*unlocked*, deliberately: see the pump in the mbedtls backend, which
says so in as many words. It can, because at that point the session is
single-tasked and not yet published, so there is no second task to
exclude.

The argument that does hold has three parts, and needs all three:

1. Every context is per session, the CA chain and peer certificate
   included — they hang off `Backend_State`, not off anything shared.
2. **Handshake**: single-tasked and the session is unpublished, so no
   lock is needed and none is taken. This is where certificates are
   verified, so it is where the RSA mutex would otherwise matter.
3. **Published**: a second task can reach the session, so every
   `mbedtls_ssl_*` call goes through `SSL_Lock`.
4. **Teardown**: `Close` calls `mbedtls_ssl_close_notify` unlocked, and
   that is not an omission. `Close` is documented single-threaded and
   runs after admission has stopped and every borrower has drained, so
   it is exclusive by the same argument the handshake is — one task,
   no one else able to reach the session.

Two tasks therefore never enter one context in any of the three
phases, and the two unlocked phases are unlocked for the same reason
rather than by oversight.

The load-bearing row is still the first one. Making the entropy source
or the DRBG a library-level singleton — tempting, since seeding is the
expensive part of connecting — would invalidate the argument silently,
and the comment on `Backend_State` says so where someone would be
about to do it.

Two differences from the openssl engine, both from mbedTLS semantics:
the peer's stream simply ending (`MBEDTLS_ERR_SSL_CONN_EOF`, what a
recv callback returning 0 becomes) is treated as a clean EOF rather
than a truncation error, and there is no KeyUpdate to handle because
TLS 1.2 has none. See [`transport.md`](transport.md) for the
handshake walkthrough and [`mbedtls.md`](mbedtls.md) for the
fetch/build/binding pipeline.

## Bindings

Both binding trees are generated with `gcc -fdump-ada-spec` and
hand-curated — never hand-written:

- `scripts/regen_openssl_bindings.sh` (against
  `$AHT_OPENSSL_DIR/include`),
- `scripts/regen_mbedtls_bindings.sh` (against the vendored tree).

C glue exists only where unavoidable: mbedTLS needs allocation glue
because its context structs have config-dependent sizes
(`csrc/mbedtls/`); OpenSSL handles are already opaque pointers, so its
glue (`csrc/openssl/`) only wraps the few macro-defined entry points
(SNI, min-proto, `BIO_set_mem_eof_return`) so their ctrl numbers come
from the installed headers.
