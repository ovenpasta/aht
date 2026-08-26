# Transport

Packages:

- `AHT.Transport` — the abstract transport interface.
- `AHT.Transport.TCP` — plain TCP, used for `http://` / `ws://`.
- `AHT.Transport.TLS` — TLS over the TCP transport, selected by the
  clients for `https://` / `wss://`.
- `AHT.Transport.Waits` — the one piece of `Check_Selector`'s timeout
  contract that is easy to get wrong. Supported surface, so that
  `test_waits` can drive it directly; see the unit for why
  `GNAT.Sockets.Forever` is a sentinel rather than a duration.

## Abstraction

```ada
type Transport_Type is abstract tagged limited null record;

procedure Write (Self, Data : Byte_Array) is abstract;
procedure Read  (Self; Data : out Byte_Array; Last : out Natural) is abstract;
procedure Close (Self) is abstract;
function  Is_Connected (Self) return Boolean is abstract;

procedure Set_Read_Deadline
  (Self : in out Transport_Type; Deadline : Duration) is null;
procedure Abort_Pending (Self : in out Transport_Type) is null;
```

### Read semantics

`Read` fills `Data` up to its bound, blocking until either:

- some bytes arrive (sets `Last` to the last filled index), or
- the peer closes cleanly (sets `Last := 0`).

It does **not** guarantee filling the entire slice — callers that need
exact byte counts (e.g. `AHT.HTTP.IO.Read_N`) loop until `Last = 0`
(error) or the expected total is reached.

### Deadline and cancel

Two optional read-side hooks share a single mechanism — the TCP
transport wires both to a persistent `GNAT.Sockets.Selector_Type`
created on `Connect` and destroyed on `Close`:

- **`Set_Read_Deadline (Duration)`** — wall-clock budget, measured
  from the call, that every subsequent `Read` collectively must
  finish within. The deadline is **compound**: each `Read` consults
  the time remaining, not the original `Duration`, so a slow-drip
  peer that returns one byte every *(Deadline / N)* seconds still
  trips `Timeout_Error` on call *N+1* instead of refreshing the
  budget every entry. Pass `Duration'Last` to clear the deadline.
  The TCP implementation stores the deadline as an `Ada.Real_Time`
  instant (monotonic, so wall-clock jumps don't corrupt it) and
  passes the remaining slice as `Timeout` to `Check_Selector`
  before every `Receive_Socket`; an already-elapsed deadline short-
  circuits the park and raises immediately.
- **`Abort_Pending`** — cross-task kill-switch. Calls
  `Abort_Selector`, causing any `Check_Selector` currently parked on
  the same selector to return `Aborted`; `Read` translates that to
  `Aborted_Error`. Safe to call when no read is pending; idempotent.

The default bodies (`is null`) are no-ops, so implementations that
don't support interruptible reads are silently ignored by cancel-
aware callers and their reads block indefinitely.

### Shared exceptions

- `Transport_Error` — OS-level I/O failures or protocol-level socket
  errors (connect refused, write to closed peer, …).
- `Timeout_Error` — `Set_Read_Deadline` expired.
- `Aborted_Error` — `Abort_Pending` fired while a `Read` was parked.

TLS adds `AHT.Transport.TLS.TLS_Error` for mbedTLS-specific failures
(invalid cert chain, handshake failure, bad record, …).

## `AHT.Transport.TCP`

Thin wrapper over `GNAT.Sockets`. `Connect (Host, Port)`:

1. Tries `Inet_Addr (Host)` — succeeds for IPv4 and IPv6 literals. If
   the parse succeeds, only that single address is tried: a literal
   that doesn't answer is a hard failure, not a prompt to start
   resolving DNS for it.
2. Otherwise calls `Get_Host_By_Name`, builds an `Endpoint_List` of
   every resolved address paired with `Port`, and delegates to
   `Connect_Candidates`, which iterates **all** candidates in order,
   closing the half-open socket from any failed attempt before trying
   the next. The first `Connect_Socket` that succeeds wins.
3. Each attempt opens a `Socket_Stream` socket of the family that
   matches the resolved address, so `Connect` works for `127.0.0.1`,
   `::1`, and dual-stacked DNS names alike.
4. If every address fails, raises `Transport_Error` carrying the
   **last** OS error message (typically `Connection refused`).

`Connect_Candidates (Self, Endpoints)` is exposed publicly: it takes an
explicit list of `(Host, Port)` pairs where each `Host` must already be
a numeric IP literal. It is the same iteration `Connect` uses
internally after DNS, and exists in the public spec so tests can drive
the multi-address fallback deterministically with a known-bad +
known-good candidate pair (see `tests/src/test_tcp.adb` case 3).

No heap-allocated stream is held: `Write` and `Read` call
`Send_Socket` / `Receive_Socket` directly on the underlying
`Socket_Type`. This avoids the `GNAT.Sockets.Stream` / `Free` pairing
and keeps `TCP_Transport` leak-free across repeated connect/close
cycles.

Interaction with `AHT.URL`: `Connect` takes a plain string host, not a
`URL_Type`. The caller passes `URL.Host` (already IPv6-bracketless)
and `URL.Port`. IPv6 literals don't need any bracket handling at the
socket layer — `GNAT.Sockets` accepts the raw address.

`Write` loops around `Send_Socket` until the whole slice is flushed;
short sends re-enter with the remaining tail. `Read` parks in
`Check_Selector` on the transport's persistent selector first (so it
honours `Set_Read_Deadline` and stays interruptible by
`Abort_Pending`), then a single `Receive_Socket` — `Last := 0`
whenever the peer has closed cleanly, matching the abstract contract.

A fatal `Write` **poisons** the transport rather than closing it,
because a reader may be parked inside `Check_Selector` and `GNAT`
forbids `Close_Selector` while it is. `Poison` marks the transport
disconnected, shuts the socket down, and wakes the reader through
`Abort_Selector`; reclaiming the socket and the selectors is left to
the single-threaded `Close`.

The wake goes through the selector rather than through the shutdown
on purpose. Shutting a socket down makes it readable on POSIX, so the
parked `select` returns and `Receive_Socket` reports 0 — but Winsock
signals nothing to a `select` already waiting for a locally initiated
shutdown, so on Windows that reader would sit there until its own
deadline. The selector's signalling channel is explicit and behaves
the same on both.

A reader woken this way raises `Transport_Error`, and does **not**
report `Last := 0`. That distinction is deliberate: the connection was
torn down under the reader by a failing write, which is not the same
event as the peer closing, and reporting it as EOF would tell the
caller the wrong thing. It is also what makes the outcome one value
rather than a race between the two wake mechanisms — the decision is
made on the transport's own state, not on which `Selector_Status`
happened to arrive.

`Close` is idempotent: repeated calls after the first are no-ops, and
`Socket_Error` from `Shutdown_Socket` / `Close_Socket` is swallowed
because the connection is going away regardless. It also tears down
the persistent selector and clears any outstanding read deadline so
a fresh `Connect` on the same object starts from a clean state.

Any `Socket_Error` or `Host_Error` during `Connect`, `Write`, or
`Read` is re-raised as `AHT.Transport.Transport_Error` with the
underlying OS message appended, so callers never have to know about
`GNAT.Sockets` directly.

### Covered by `tests/bin/test_tcp`

An in-process Ada echo-server task type binds `127.0.0.1:0`
(OS-assigned port) and exposes two entries:

- `Get_Port` hands the port back along with any setup error as an
  `Unbounded_String`, so bind/listen denial surfaces as a `Fail (...)`
  line rather than a `TASKING_ERROR` at rendezvous.
- `Wait_Done` returns a runtime-error `Unbounded_String` captured
  after `Get_Port`, so a failure on the server side (accept timeout,
  receive/send error) contributes to the test's `Failures` counter
  instead of only printing a line.

The server uses `Check_Selector` with a 2-second timeout before
`Accept_Socket` so it never hangs if a client-side failure means
nobody ever connects.

Seven cases, each with its own server task (except case 4, which
doesn't need one). All client operations are wrapped in exception
handlers and followed by an unconditional idempotent `Close`, so
assertion-style early returns inside `Drive_Echo` never leak the
client socket.

1. **literal** — `Connect ("127.0.0.1", Port)`: `Inet_Addr` parses,
   single-candidate path.
2. **DNS** — `Connect ("localhost", Port)`: `Inet_Addr` fails, so the
   name goes to `AHT.DNS` and the literals it returns become the
   candidate list. On dual-stack boxes this also exercises the
   IPv4/IPv6 fallback — `getaddrinfo` is asked for both families,
   which `Get_Host_By_Name` could not do.
3. **multi-addr [bad, good]** — drives `Connect_Candidates` directly
   with `[(127.0.0.1, bad_port), (127.0.0.1, good_port)]`, where
   `bad_port` is reserved by a bound-but-not-listening socket so
   connects to it are refused by the kernel. Proves the
   first-fails-second-succeeds path plus the per-attempt socket
   cleanup, independent of DNS state on the host.
4. **multi-addr [bad, bad]** — two bound-but-not-listening ports so
   every candidate is refused. Asserts `Connect_Candidates` raises
   `Transport_Error` *and* that the message contains the last
   candidate's port, not the first — proving the "last error wins"
   aggregation contract from `Connect_Candidates`.
5. **abort** — a `Silent_Server` task type accepts one client and
   then holds the socket without sending. The client calls `Read`
   on a 64-byte buffer; a sibling `Aborter` task delays 100 ms and
   calls `Abort_Pending`. Asserts `Aborted_Error` surfaces within
   1 s of the abort call.
6. **timeout** — same silent peer. Client calls
   `Set_Read_Deadline (0.1)` then `Read`. Asserts `Timeout_Error`
   fires between 0.05 s and 1 s (not early, not runaway).
7. **compound timeout** — same silent peer. Client calls
   `Set_Read_Deadline (0.1)`, then `delay 0.25` (burning the whole
   budget *before* `Read`), then `Read`. Asserts the raise happens
   within 0.05 s of the `Read` call, not after another 0.1 s —
   proves the deadline is a wall-clock budget from the `Set_`
   call, not a fresh allowance per `Read`.

## `AHT.Transport.TLS`

One backend-neutral spec, two bodies selected at build time by the
`AHT_TLS_BACKEND` gpr external — **openssl** (default, system OpenSSL
3) or **mbedtls** (vendored 2.28). Backend selection, the deliberate
per-backend policy differences (trust-store default, abrupt-EOF
handling, IP-SAN verification) and the OpenSSL memory-BIO engine are
documented in [`tls.md`](tls.md); this section covers the shared
contract and the mbedtls walkthrough.

Shared shape: the bytes always travel over a real
`AHT.Transport.TCP` instance held *inside* the backend state (freshly
allocated per `Connect` attempt, so a FAILED `Connect` releases it
and the object stays retryable; a successful session latches the
transport single-use). There is no second socket stack, so `https://`
and `wss://` inherit the TCP transport's DNS multi-candidate
fallback, deadlines and `Abort_Pending`. Like every transport, a TLS
transport supports at most ONE concurrent reader task and ONE
concurrent writer task.

### mbedTLS backend walkthrough

`Connect (Host, Port, Insecure, CA_Path, ..., CA_PEM)` lifecycle:

1. **TCP connect first** — `AHT.Transport.TCP.Connect (Host, Port)`, so
   all of the deadline/abort/fallback machinery above is reused. The
   inner TCP transport's address is then stored in the BIO context for
   the callbacks.
2. Allocate the `ssl`, `ssl_config`, `ctr_drbg`, `entropy` (and, if a
   CA is supplied, `x509_crt`) contexts via the C glue, which owns
   `sizeof` (never modelled in Ada).
3. Seed the DRBG (`mbedtls_ctr_drbg_seed`).
4. `mbedtls_ssl_config_defaults` — client / stream / default preset.
5. `mbedtls_ssl_conf_authmode`:
   - `MBEDTLS_SSL_VERIFY_REQUIRED` by default;
   - `MBEDTLS_SSL_VERIFY_NONE` when `Insecure => True` (self-signed
     test certs).
6. **CA loading is explicit, no platform default.** If `CA_Path` is
   non-empty it is loaded with `mbedtls_x509_crt_parse_path` when it
   names a directory and `mbedtls_x509_crt_parse_file` otherwise
   (chosen via `Ada.Directories.Kind`), and a non-clean parse is a hard
   `TLS_Error`. With `CA_Path = ""` **no** trust anchors are configured
   here (there is no `/etc/ssl/certs` fallback), so unless `Insecure`
   is set the handshake will reject the peer — callers must pass a CA
   bundle or opt into `Insecure`. (The openssl backend differs: it
   falls back to the platform trust store — see `tls.md`.)

6b. **In-memory anchors.** `CA_PEM` carries one or more concatenated
   PEM certificates instead of a path, for anchors compiled into the
   binary. Supplying both it and `CA_Path` raises `TLS_Error` before
   anything is dialled — no precedence, and the refusal stands under
   `Insecure`.

   Its envelope is validated by `AHT.PEM` before either backend sees
   it, and unconditionally, because neither backend can answer "was
   the input wholly what I supplied?". OpenSSL's `PEM_R_NO_START_LINE`
   means "no further header found", which trailing garbage produces
   too; mbedTLS returns the count of certificates that *failed*, which
   for trailing garbage is zero. Both accepted a valid certificate
   followed by junk until the shared check was added.

7. `mbedtls_ssl_setup`, then `mbedtls_ssl_set_hostname (Host)` for SNI
   *and* cert-name verification.
8. `mbedtls_ssl_set_bio` wires the send/recv callbacks. They are
   **memory-only**: they move bytes to and from two in-process queues
   rather than the socket, so no `mbedtls_ssl_*` call ever blocks (an
   empty inbound queue yields `WANT_READ`). No recv-timeout callback
   is installed — deadlines live on the engine's own TCP calls.
9. Loop `mbedtls_ssl_handshake`, pushing whatever it queued to the
   wire and pulling what it asks for, all bounded by
   `Handshake_Deadline`; any other negative code fails.
10. `Read` / `Write` run the engine loop: one `mbedtls_ssl_read` /
    `_write` under the engine lock, drain the outbound queue to the
    socket, feed the inbound queue on `WANT_READ` (see
    [`tls.md`](tls.md) for the locking and coordinator design). A
    clean close (`PEER_CLOSE_NOTIFY`, or the peer's stream ending as
    `CONN_EOF`) maps to `Last := 0`, matching the abstract contract.
11. `Close` is best-effort `mbedtls_ssl_close_notify` plus a final
    drain (skipped for a session that died fatally), then `TCP.Close`,
    then unconditionally frees every context. Idempotent; a failed
    `Connect` has already freed and closed, so a follow-up `Close` is
    a no-op.

**Network errors keep their identity.** Because the socket I/O
happens in Ada — in the engine's own `TCP.Read`/`TCP.Write` calls, not
inside a BIO callback — `Timeout_Error` (deadline), `Aborted_Error`
(`Abort_Pending`) and `Transport_Error` propagate natively, so a
deadline or cancel during a TLS read surfaces as the *same* exception
a plain TCP read would raise. Nothing has to smuggle an Ada exception
across a C frame. mbedTLS-internal failures (bad cert chain, handshake
failure, bad record) surface as `TLS_Error` with the
`mbedtls_strerror` message.

Concurrency: each transport instance owns its own state, so tasks
using separate `TLS_Transport` objects never interfere. On ONE
instance the contract is one reader + one writer task (the WSS
receiver-plus-sender shape), and **both** backends meet it the same
way — by serializing every library call under an engine lock and
doing all waiting outside it, never by letting two tasks into one
session object. `MBEDTLS_THREADING_C + MBEDTLS_THREADING_PTHREAD` is
still enabled, but it protects mbedTLS's *shared* internals (the RNG
and friends), not a single `mbedtls_ssl_context` — which is precisely
why the engine, not the library's threading support, is what makes
the reader/writer pair safe. See [`tls.md`](tls.md).

Covered by `tests/bin/test_tls` (transport level): against the HTTPS
fixture `tests/server/server_tls.py` it verifies a good chain
(`CA_Path` → handshake succeeds, `/hello` echoes back), `Insecure`
bypass, and that a `VERIFY_REQUIRED` connect with no CA rejects the
self-signed chain with `TLS_Error`.
