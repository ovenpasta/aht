<!--
SPDX-FileCopyrightText: 2026 Aldo Nicolas Bruno
SPDX-License-Identifier: Apache-2.0
-->

# TLS Backends

`AHT.Transport.TLS` is one spec with two interchangeable bodies. The
backend is chosen at build time and exactly one backend's sources and
libraries are compiled/linked:

- **openssl** (default) — the system OpenSSL 3 (`libssl`/`libcrypto`),
  TLS 1.2/1.3. Bindings: `AHT.Openssl.*` under `src/tls/openssl/`.
- **mbedtls** — vendored mbedTLS 3.6 (TLS 1.2), downloaded and
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
(`third_party/mbedtls-3.6.7-x86_64-w64-mingw32`), because mbedTLS
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
| IP-literal host, verifying | verified against the cert's IP SANs (`X509_VERIFY_PARAM_set1_ip_asc`), no SNI sent | verified against the cert's iPAddress SANs — the backends agree here, and `test_tls_ip_host` asserts the same property from both sources |
| Abrupt TCP EOF (no close_notify) | **`TLS_Error`** — truncation must fail, because HTTP supports EOF-framed bodies and a silent truncation would be a data-integrity hole (`SSL_OP_IGNORE_UNEXPECTED_EOF` is never set) | clean EOF (`Last = 0`) — long-standing backend behavior, pinned by test_tls_truncation |
| Protocol versions | TLS 1.2 minimum, TLS 1.3 active; renegotiation disabled | TLS 1.2 — `MBEDTLS_SSL_PROTO_TLS1_3` is compiled out, for the PSA reasons below |

Both backends: DNS-name hosts get SNI + hostname verification;
`Insecure => True` skips certificate verification entirely (SNI still
sent for DNS names); a failed `Connect` leaves the object retryable
while a successful session makes it single-use.

## Allocation and abort

Each backend's `Connect` has two allocation sites: `Self.State := new
Backend_State` and, a little further in, `Self.State.TCP := new
AHT.Transport.TCP.TCP_Transport`. Both go through `AHT.Guarded_New`
(`src/aht-guarded_new.ads`), a generic that wraps one `new` in a
protected procedure taking its destination as an `access` parameter.
The reason is the same one behind
`AHT.Websocket.Client.Lifecycle_Controller.Create_Session` — see
*Abort safety is structural* in `docs/websocket.md` for the full
argument — restated here only to the depth this layer needs: GNAT
attaches a heap object to its access type's collection, under the
runtime's global task lock, before the object is initialized, and
releasing that lock is an abort completion point
(`Allocate_Any_Controlled`, `s-stposu.adb`). An abort inside a bare
`new` can therefore leave the object attached, uninitialized, and
unreachable — the allocating statement never completed, so nothing
holds a pointer to it — and library finalization runs on it anyway. A
protected action is abort-deferred for its whole duration, so
performing the `new` inside one closes the window, and the destination
is passed by `access` rather than `out` because an `out` parameter's
copy-back happens after the action ends, exactly where the abort
lands.

`AHT.Guarded_New` is a **private** child of `AHT`, not of `AHT.TLS_Sync`
— it guards a general property of `new`, unrelated to TLS
synchronisation, and it is not part of the published API; a private
child is visible only to bodies of `AHT`'s own descendants (RM
10.1.2(8)), which is exactly what both backend bodies are. It is
generic because the two sites do not share a type: `Backend_State` is
completed differently by each backend body (it is the Taft-amended
type behind `Backend_State_Access` in `aht-transport-tls.ads`), so the
allocator for it has to live in that body regardless.
`AHT.Transport.TCP.TCP_Transport` is the same type in both backends,
but each body pairs it with its own `TCP_Access`, so each instantiates
the generic separately for it too. Every instantiation is a
library-level declaration in the backend body, so its `Gate` is
elaborated once for the life of the program rather than once per
`Connect`.

The two sites strand differently. `Backend_State` carries two
`Lock_Type` and a `Coordinator_Type` (`AHT.TLS_Sync`) — protected types
with entries — and a zero-filled one is not inert: finalizing it enters
a zero-filled `CRITICAL_SECTION`, whose `LockCount` of 0 reads as
contended where an initialized, unheld one is -1, and finalization
hangs. That mechanism is measured, on the i686 Windows build, by the
`Create_Session` fix this one mirrors and by a standalone zero-fill
probe — not, separately, by tearing an abort inside this specific
`new`. `TCP_Transport` strands more cheaply: it holds no
`CRITICAL_SECTION`, and `Transport_Type.Finalize`
(`src/aht-transport.adb`) dispatches on the object's tag before doing
anything else, so on zero-filled memory — a null tag — the dispatch
faults and Finalize's own blanket `when others => null` swallows it. A
stranded `TCP_Transport` is a leak and a swallowed fault, not a hang —
reasoned from that code, not measured — and it is guarded by the same
construct because doing so costs nothing, not because it was observed
to hang anything.

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

**Windows is built threadless**, because mbedTLS offers pthread
or a caller-supplied `THREADING_ALT` and nothing else. That is sound
rather than convenient — but not because the mutexes are all
unreachable. Some are; the rest guard state that only ever has one
task in it, for reasons this client enforces itself.

| Mutex | Why it cannot matter here |
|---|---|
| `entropy.c`, `ctr_drbg.c` | Both contexts are per transport object (`Backend_State`), never shared between sessions or tasks |
| `rsa.c` | The context is per session and every engine call on it is serialized (see below) |
| `ssl_cache.c`, `ssl_ticket.c`, `ssl_cookie.c` | Server-side state |
| `hmac_drbg.c` | Unused — the RNG is CTR_DRBG |
| `memory_buffer_alloc.c` | `MBEDTLS_MEMORY_BUFFER_ALLOC_C` is off |
| `x509_crt.c` | The `readdir` mutex guards the POSIX branch of `mbedtls_x509_crt_parse_path`; the `_WIN32` branch uses `FindFirstFileW` with a per-call handle |
| `platform_util.c` | The `gmtime` mutex guards the `PLATFORM_UTIL_USE_GMTIME` fallback; `_WIN32` uses the thread-safe `gmtime_s` |

The argument holds only while PSA Crypto stays unreached. PSA keeps
process-global state, which no per-session lock covers and which the
threadless build has nothing to guard with. Two macros reach it, and
the fetch script's compiled probe fails the build on either, for both
targets:

- `MBEDTLS_USE_PSA_CRYPTO`, which routes X.509 and TLS through PSA.
- `MBEDTLS_SSL_PROTO_TLS1_3`. The TLS 1.3 code always uses PSA
  whatever the first macro says, and a 1.3-capable client reaches it
  while assembling its ClientHello — so on every handshake, not only
  the ones that negotiate 1.3. That is why this backend is TLS 1.2:
  the protocol is compiled out, not merely left unnegotiated.

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

The argument that does hold is one invariant over the session's whole
life, plus what makes it true in each phase of that life.

**The invariant.** Every context is per session, the CA chain and peer
certificate included — they hang off `Backend_State`, not off anything
shared. So the only way two tasks meet in one context is by both being
in the same session at once.

**The phases**, which is where that is ruled out:

| Phase | Why no two tasks |
|---|---|
| Handshake | Single-tasked and the session is not yet published, so no lock is needed and none is taken. This is where certificates are verified, so it is where the RSA mutex would otherwise matter. |
| Published | A second task can reach the session, so every `mbedtls_ssl_*` call goes through `SSL_Lock`. |
| Teardown | `Close` calls `mbedtls_ssl_close_notify` unlocked, and that is not an omission: `Close` carries a precondition that no other task is inside *any* operation on the transport, so it is exclusive by the same argument as the handshake — one task, nobody else able to reach the session. |

The two unlocked phases are unlocked for the same reason rather than
by oversight, and it is the reason that matters: a lock is absent
where exclusivity comes from the lifecycle instead.

Teardown differs from the other two in *who* guarantees it. The
handshake is exclusive by construction — no reference to the session
has escaped yet, so nothing else can reach it. Teardown is exclusive
only because `Close`'s precondition says so, and that precondition is
the caller's to keep; `aht-transport-tls.ads` states it and notes it
is not enforceable there.

It covers every operation, not just `Read` and `Write`. `Close` nulls
and frees the backend state, and `Is_Connected`, the deadline setters
and `Abort_Pending` all dereference it, so any of them racing `Close`
is a use-after-free rather than a stale answer.

Each client meets that contract its own way, and those ways are not
the contract. The HTTP client is synchronous, so there is never a
second task. `Websocket.Client` has two ways, split by whether the
session ever became reachable by a second task:

- **Published sessions** are closed by the receiver, in `Reclaim`,
  after `Stop_Admission` has shut the door and `Wait_No_Borrowers` has
  seen the last borrow returned. Exclusivity comes from the borrow
  lifecycle.
- **An attempt that never published** — a failed or aborted `Connect`
  — is closed by `Attempt_Owner.Finalize`, on the connecting task
  itself. The receiver task still exists — it is a component of the
  client, not of a connection, so it outlives any one of them — and it
  may even have accepted the `Start` rendezvous, since `Cur_Sess` is
  assigned inside the accept body and `Publish` can raise after that.
  What makes this exclusive is not that acceptance never happened but
  that *ownership never completed*: the rendezvous handler drops the
  pointer, so the receiver retains no path to the session and the
  connecting task is its only owner. The owner checks
  `Attempt_Handed_Off` first and does nothing if it fired, which is
  what keeps the two routes from both firing on one session.

`Wait_Closed` is easy to mistake for that point and is not it.
`Reclaim` publishes `Closed` — which opens that entry — *before* it
drains borrowers, and `Websocket.Client.Close` waits there while still
holding its own teardown borrow. An entry that meant "reclaimed" would
therefore deadlock against the drain it is part of. What a caller
waits on for the transport to be closed and the session freed is
`Wait_Generation_Done`, reached only after the pin's scope ends and
that borrow goes back.

A direct user of `AHT.Transport.TLS` has neither mechanism and has to
quiesce its own tasks. One that calls `Close` with a reader still
running breaks the threading argument along with everything else the
precondition protects.

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

### Where the entropy comes from

Both targets are built `MBEDTLS_NO_PLATFORM_ENTROPY`, so
`entropy_poll.c` contributes nothing and `mbedtls_entropy_init` leaves
the pool with no sources at all. `aht_mbedtls_entropy_new` registers
`AHT.Mbedtls.Entropy.Poll` in its place, which fills from
`AHT.Random` — the same source the client draws frame masks and
handshake nonces from.

One source rather than two, because the platform entropy call is
precisely where a platform-incompatible dependency hides:
`entropy_poll.c`'s Windows branch calls `BCryptGenRandom`, which puts
`bcrypt.dll` in the import table and leaves the image unloadable
before Vista. Compiling it out leaves exactly one place that decision
is made, and `src/os/README.md` describes the import-table assertion
that guards it.

There is no quiet failure mode. With no platform source and no working
callback, `mbedtls_ctr_drbg_seed` fails and no handshake happens at
all — so any passing TLS test has already established that the
callback delivered. `test_tls_entropy` also asserts it directly: a
connect must move `AHT.Random`'s counters. The openssl source of that
test asserts the same connect leaves them untouched, and that control
is what makes the mbedtls half mean anything.

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
