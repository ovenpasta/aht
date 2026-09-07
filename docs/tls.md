<!--
SPDX-FileCopyrightText: 2026 Aldo Nicolas Bruno
SPDX-License-Identifier: Apache-2.0
-->

# TLS Backends

`AHT.Transport.TLS` is one spec with two interchangeable bodies. The
backend is chosen at build time, and exactly one backend's sources
and libraries are compiled and linked:

- **openssl** (default): the system OpenSSL 3 (`libssl`/`libcrypto`),
  TLS 1.2 and 1.3. Bindings `AHT.Openssl.*` under `src/tls/openssl/`.
- **mbedtls**: vendored mbedTLS 3.6 (TLS 1.2), downloaded and built
  on first build by `scripts/fetch_mbedtls.sh`. Bindings
  `AHT.Mbedtls.*` under `src/tls/mbedtls/`; see
  [`mbedtls.md`](mbedtls.md).

## Selecting a backend

```sh
alr build                                   # openssl (default)
AHT_TLS_BACKEND=mbedtls alr build           # mbedtls
```

`AHT_TLS_BACKEND` is a gpr external read from the environment (or
`-XAHT_TLS_BACKEND=...`). The environment variable is the supported
route: it also reaches the Alire pre-build action, which is how
`scripts/fetch_mbedtls.sh` knows whether to fetch. A consumer that
selects mbedtls only through `[gpr-set-externals]` must also export
the variable, or run the fetch script once by hand, because gpr
externals do not reach action environments.

Every build combination has its own output tree
(`obj/<mode>-<backend>`, `lib/<mode>-<backend>`, and the test and
example `bin/` directories likewise), so switching never clobbers
artifacts. `AHT_OS=windows` appends the cross toolchain's target
triplet to the variant (`obj/debug-mbedtls-x86_64-w64-mingw32`) and
uses its own mbedTLS tree
(`third_party/mbedtls-3.6.7-x86_64-w64-mingw32`), because mbedTLS
builds in-tree and the targets are not configured alike. The key is
the triplet rather than the word "windows" because an i686 and an
x86-64 mingw build are as incompatible as a Linux one.
`AHT_CROSS_TARGET` selects the triplet, and `scripts/fetch_mbedtls.sh`
checks it against the compiler's own `-dumpmachine`. POSIX keeps the
unsuffixed names.

mbedtls is the backend for `AHT_OS=windows`: the openssl backend
needs a system OpenSSL 3, and the vendored tree makes a cross build
self-contained. Windows is not a supported configuration; see
`AHT_OS` in `aht.gpr` and `CONTRIBUTING.md` for what has been measured.

`AHT_OPENSSL_DIR` (default `/usr`) is the OpenSSL installation
prefix. Linux distributions with `libssl-dev` need nothing; macOS
ships no OpenSSL headers, so:

```sh
brew install openssl@3
export AHT_OPENSSL_DIR=$(brew --prefix openssl@3)
```

The openssl backend requires OpenSSL 3: the bindings import 3.0-only
symbols (a link-time failure on LibreSSL or 1.1), and `Connect`
checks `OPENSSL_version_major >= 3` at runtime.

## Behavioral differences

The public contract (`aht-transport-tls.ads`) is shared. The two
backends differ in these policies:

- **`CA_PEM` supplied.** Both backends validate the envelope with
  `AHT.PEM` first, always, including under `Insecure`. OpenSSL then
  loads nothing under `Insecure`, because verification is off;
  mbedTLS parses the chain regardless. `CA_PEM` and `CA_Path` are
  mutually exclusive on both.
- **`CA_Path = ""`, verifying.** openssl uses the platform trust
  store (`SSL_CTX_set_default_verify_paths`, honouring
  `SSL_CERT_FILE` and `SSL_CERT_DIR`), so public `https://` endpoints
  work out of the box. mbedtls configures no default trust, so the
  handshake rejects; pass a CA bundle or set `Insecure`.
- **CA directory semantics.** openssl expects c_rehash hashed names;
  mbedtls loads every file in the directory.
- **IP-literal host, verifying.** openssl verifies against the
  certificate's IP SANs (`X509_VERIFY_PARAM_set1_ip_asc`) and sends
  no SNI. mbedtls verifies against the iPAddress SANs as well.
- **Abrupt TCP EOF (no close_notify).** openssl raises `TLS_Error`:
  HTTP supports EOF-framed bodies, so a silent truncation would be a
  data-integrity hole (`SSL_OP_IGNORE_UNEXPECTED_EOF` is never set).
  mbedtls reports a clean EOF (`Last = 0`).
- **Protocol versions.** openssl: TLS 1.2 minimum, TLS 1.3 active,
  renegotiation disabled. mbedtls: TLS 1.2 only;
  `MBEDTLS_SSL_PROTO_TLS1_3` is compiled out (see *Configuration of
  the vendored library*).

On both backends a DNS-name host gets SNI and hostname verification;
`Insecure => True` skips certificate verification (SNI is still sent
for DNS names); a failed `Connect` leaves the object retryable, and a
successful session makes it single-use.

## Allocation and abort

Each backend's `Connect` allocates twice: `Self.State := new
Backend_State`, and later `Self.State.TCP := new
AHT.Transport.TCP.TCP_Transport`. Both go through `AHT.Guarded_New`
(`src/aht-guarded_new.ads`), which performs the `new` inside a
protected action so that an abort cannot leave the object attached to
its collection uninitialized; that unit's spec states the GNAT
behaviour and the argument. Each backend body instantiates it once
per site at library level (`New_State`, `New_TCP`), so each `Gate` is
elaborated once for the life of the program. The two sites differ in
what a stranded object costs. `Backend_State` holds protected objects
with entries, and finalizing a zero-filled one hangs on the i686
Windows build, where a zeroed `CRITICAL_SECTION` reads as contended;
that was measured with a zero-filled object of this shape, not by
aborting inside this particular `new`. A stranded `TCP_Transport`
would be a leak plus a fault swallowed by `Transport_Type.Finalize`,
reasoned from the code rather than observed.

## The engine

Neither library allows two tasks inside one connection object.
OpenSSL 3 forbids two tasks in `SSL_read`/`SSL_write` on one `SSL*`
(TLS 1.3 KeyUpdates and session tickets processed inside a read
mutate connection-shared state). An `mbedtls_ssl_context` is not safe
for two tasks either: the library's mutexes, in a build that has any,
guard its shared internals and never one session's state, and
`mbedtls_ssl_read` may itself write (alerts). The WebSocket client
runs a receiver task in `Read` while senders call `Write`, so a
blocking-BIO design would put two tasks inside one session.

Both backends therefore keep the library away from the socket. The
bytes travel over an `AHT.Transport.TCP` instance held inside
`Backend_State`, allocated per `Connect` attempt; there is no second
socket stack, so `https://` and `wss://` inherit the TCP transport's
DNS multi-candidate fallback, deadlines and `Abort_Pending`. The
library reads and writes in-memory queues, every library call returns
promptly, and all network waiting happens in Ada outside the library:

- **Engine call.** Every library call runs under `SSL_Lock` and is
  non-blocking. On openssl the discipline is `ERR_clear_error`, one
  call, `SSL_get_error` immediately, capture the error queue on a
  fatal result, sample the WBIO's pending count, release. On mbedtls
  a negative return other than `WANT_READ`, `WANT_WRITE`,
  `PEER_CLOSE_NOTIFY` and `CONN_EOF` is fatal. A fatal result latches
  `Engine_Dead` before the lock is released, with the reason, so the
  operations rejected afterwards report what killed the session.
- **Drain (wire output).** Under `Drain_Lock` (strict order: Drain
  outer, SSL inner), queued ciphertext is extracted and written to
  the TCP transport; extraction under the drain lock keeps wire
  order. A drain failure is fail-closed: ciphertext may be half-sent,
  so the engine dies and the inner TCP is poisoned.
- **Feed (wire input).** A protected coordinator arbitrates the
  single `TCP.Read` through an atomic feeder claim. The non-owner
  parks on a single-waiter armed latch (claim failure and arming are
  one protected action, so no wakeup is lost) and is woken by feed,
  feeder release, EOF, fatal, or abort, then re-evaluates and
  retries. This is sound because the transport contract allows at
  most one reader and one writer task. A write that needs a record
  from the peer (`WANT_READ` mid-write) feeds itself when the claim
  is free and otherwise waits, bounded by the write deadline.
- **Deadlines.** Both `Set_*_Deadline` budgets are mirrored as
  absolute instants computed once at the setter call. Every blocking
  step (lock seize as a timed entry call, latch wait, feed
  `TCP.Read`, drain `TCP.Write`, through the deadline-explicit TCP
  overloads) is bounded by the deadline of the operation performing
  it, and re-checks a modular abort epoch that `Abort_Pending` bumps.
  `Abort_Pending` wakes both TCP selector waiters and the latch
  waiter; it is not sticky, because operations snapshot the epoch at
  entry.
- **Close** never skips cleanup: the close_notify and its drain
  (skipped after a fatal error) and `TCP.Close` run in separate
  best-effort blocks, then every context is freed unconditionally.
  `Close` is idempotent, and a failed `Connect` has already released
  everything.

The locks and coordinator live in `AHT.TLS_Sync`, shared by both
bodies and kept separate so that a test can drive the claim, arm,
wake and abort protocol directly.

### openssl specifics

`SSL_set_bio` installs two `BIO_s_mem` BIOs, RBIO for inbound
ciphertext and WBIO for outbound. OpenSSL forbids further I/O after
`SSL_ERROR_SSL` or `SSL_ERROR_SYSCALL`, which is what `Engine_Dead`
enforces. The RBIO starts as "empty is retryable"
(`BIO_set_mem_eof_return -1`, reported as `WANT_READ`) and flips to
hard EOF (0) when `TCP.Read` reports the stream ended, so the next
engine call classifies it: a real close_notify reads as clean EOF
(`SSL_ERROR_ZERO_RETURN`, `Last = 0`), anything else is the
truncation `TLS_Error`. `SSL_shutdown` has its own result protocol: a
0 return means close_notify was queued and `SSL_get_error` must not
be consulted; it is skipped entirely after a fatal error. `SSL_free`
reclaims both BIOs, then `SSL_CTX_free`.

### mbedtls specifics

The BIO callbacks (`Send_CB`, `Recv_CB` in
`src/tls/mbedtls/aht-transport-tls.adb`) move bytes to and from the
two queues in `Engine_IO` and never touch the socket. `Recv_CB`
returns `MBEDTLS_ERR_SSL_WANT_READ` when the inbound queue is dry and
0 once the stream has ended. The only failure a callback can report
is an allocation failure while growing a queue, returned as
`MBEDTLS_ERR_NET_*`; no Ada exception crosses the C frame, and the
callbacks record no error kind for the Ada side to re-raise. Network
exceptions (`Timeout_Error`, `Aborted_Error`, `Transport_Error`)
propagate from the engine's own `TCP.Read`/`TCP.Write` calls, so a
deadline or cancel during a TLS read is the same exception a plain
TCP read raises. mbedTLS-internal failures surface as `TLS_Error`
carrying the `mbedtls_strerror` message.

`Connect` runs in this order:

1. `AHT.Transport.TCP.Connect (Host, Port, Connect_Timeout,
   Resolve_Timeout)`.
2. Allocate the `ssl`, `ssl_config`, `ctr_drbg` and `entropy`
   contexts (and `x509_crt` when trust anchors are supplied) through
   the C glue, and seed the DRBG.
3. `mbedtls_ssl_config_defaults` (client, stream, default preset)
   and `mbedtls_ssl_conf_authmode`: `VERIFY_REQUIRED`, or
   `VERIFY_NONE` under `Insecure`.
4. Trust anchors. `CA_Path` is loaded with
   `mbedtls_x509_crt_parse_path` when it names a directory
   (`Ada.Directories.Kind`) and `mbedtls_x509_crt_parse_file`
   otherwise; `CA_PEM` with `mbedtls_x509_crt_parse`, passing the
   NUL inside the counted length. Only a return of 0 is accepted; a
   positive count of certificates that failed to parse rejects the
   bundle whole.
5. `mbedtls_ssl_setup`, then `mbedtls_ssl_set_hostname (Host)` for
   SNI and certificate-name verification. mbedTLS matches dNSName
   SANs, the CN and iPAddress SANs.
6. `mbedtls_ssl_set_bio` with the two callbacks. No recv-timeout
   callback is installed; deadlines live on the engine's TCP calls.
7. The handshake pump: `mbedtls_ssl_handshake`, push what it queued,
   pull what it asks for, bounded by `Handshake_Deadline`. This runs
   on the connecting task with no locks taken; the session is not
   yet reachable by any other task.
8. The application deadlines mirrored before `Connect` are installed
   on the fresh TCP transport as remaining budgets.

Which calls are locked follows the session's life. The handshake runs
single-tasked before the session is published, so it takes no lock;
a published session serializes every `mbedtls_ssl_*` call under
`SSL_Lock`; and `Close` calls `mbedtls_ssl_close_notify` unlocked,
under its precondition that no other task is inside any operation on
the transport. Every mbedTLS context, the CA chain and the peer
certificate included, hangs off `Backend_State`, so two tasks can
only meet in one context by being in the same session at once.

Two behaviours follow from mbedTLS semantics rather than from this
design: the peer's stream ending (`MBEDTLS_ERR_SSL_CONN_EOF`, what a
recv callback returning 0 becomes) is a clean EOF, and there is no
KeyUpdate to handle because TLS 1.2 has none.

## Configuration of the vendored library

`scripts/fetch_mbedtls.sh` builds one tree per target and writes the
configuration into that tree's own
`include/mbedtls/mbedtls_config.h` rather than passing `-D` flags.
`aht.gpr` points the glue's `-I` at the same header, so the archive
and `csrc/mbedtls/aht_mbedtls_glue.c` read identical bytes.
`MBEDTLS_THREADING_C` adds a mutex member to several context structs,
so a glue translation unit that disagreed with the archive would
compute a different `sizeof`, under-allocate in its `*_new`, and let
`mbedtls_*_init` write past the block, with nothing to report it. The
build stamp carries the hash of the edited header, so a tree whose
header changed after the build is rebuilt rather than linked.

Both targets set `MBEDTLS_NO_PLATFORM_ENTROPY` and compile out
`MBEDTLS_SSL_PROTO_TLS1_3`. POSIX enables `MBEDTLS_THREADING_C` and
`MBEDTLS_THREADING_PTHREAD`, and `AHT.Mbedtls.Link`
(`src/tls/mbedtls/os/posix/`) adds `-lpthread` to the link line.

Windows is built threadless, because mbedTLS offers pthread or a
caller-supplied `THREADING_ALT` and nothing else. That is sound
because every mutex the library would take guards either a context
this backend keeps per session or a code path this client does not
reach, and it holds only while PSA Crypto stays unreached, since PSA
keeps process-global state that no per-session lock covers. Two
macros reach PSA, `MBEDTLS_USE_PSA_CRYPTO` and
`MBEDTLS_SSL_PROTO_TLS1_3` (the TLS 1.3 code always uses PSA, and a
1.3-capable client reaches it while building every ClientHello), and
the fetch script's compiled probe fails the build on either, for both
targets. The header of `scripts/fetch_mbedtls.sh` states the
argument; the per-mutex enumeration is in [`mbedtls.md`](mbedtls.md)
under *Maintaining the backend*. Making the entropy source or the
DRBG a library-level singleton would invalidate it, and the comment
on `Backend_State` says so.

## The `Close` precondition

`Close` on either backend nulls and frees the backend state, and
`Is_Connected`, the deadline setters and `Abort_Pending` all
dereference it, so the precondition in `aht-transport-tls.ads` covers
every operation, not only `Read` and `Write`: no other task may be
inside any operation on the transport while `Close` runs, and the
transport cannot enforce it. The HTTP client is synchronous, so it
has no second task. `AHT.Websocket.Client` closes a published session
from its receiver task after every borrow has been returned, and an
attempt that never published from the connecting task, which is then
the session's only owner. A direct user of `AHT.Transport.TLS` has to
quiesce its own tasks before calling `Close`. For a fatal write while
a reader is parked, the inner TCP is poisoned (reader-safe) and
`Close` deferred until the reader has exited.

## Entropy on mbedtls

Both targets are built `MBEDTLS_NO_PLATFORM_ENTROPY`, so
`entropy_poll.c` contributes nothing and `mbedtls_entropy_init`
leaves the pool with no sources. `aht_mbedtls_entropy_new` (the C
glue) registers `AHT.Mbedtls.Entropy.Poll` as the only source; it
fills from `AHT.Random`, which the client also draws frame masks and
handshake nonces from. One source keeps the platform entropy decision
in one place: `entropy_poll.c`'s Windows branch calls
`BCryptGenRandom`, which puts `bcrypt.dll` in the import table and
leaves the image unloadable before Vista. `src/os/README.md`
describes the import-table check. There is no quiet failure mode:
with no source and no working callback, `mbedtls_ctr_drbg_seed`
fails and no handshake happens.

## Bindings

Both binding trees are generated with `gcc -fdump-ada-spec` and
hand-curated, never hand-written:

- `scripts/regen_openssl_bindings.sh`, against
  `$AHT_OPENSSL_DIR/include`;
- `scripts/regen_mbedtls_bindings.sh`, against the vendored tree.

C glue exists only where unavoidable. mbedTLS needs allocation glue
because its context structs have configuration-dependent sizes
(`csrc/mbedtls/aht_mbedtls_glue.c`). OpenSSL handles are already
opaque pointers, so its glue (`csrc/openssl/aht_openssl_glue.c`) only
wraps the macro-defined entry points (SNI, minimum protocol version,
`BIO_set_mem_eof_return`) so that their ctrl numbers come from the
installed headers.
