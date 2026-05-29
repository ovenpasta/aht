# Transport

Packages:

| Unit | Status |
|---|---|
| `AHT.Transport` (abstract) | spec implemented |
| `AHT.Transport.TCP` | implemented |
| `AHT.Transport.TLS` | implemented (transport level; `https://`/`wss://` client wiring pending) |

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

## `AHT.Transport.TCP` — implemented

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
2. **DNS** — `Connect ("localhost", Port)`: `Inet_Addr` fails,
   `Get_Host_By_Name` iterates. On dual-stack boxes this also
   exercises the IPv4/IPv6 fallback.
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

## `AHT.Transport.TLS` — implemented

mbedTLS does the crypto; the bytes still travel over a real
`AHT.Transport.TCP` instance held *inside* the `TLS_Transport`. There
is no second socket stack and `mbedtls_net_*` is **not** used — see
[`mbedtls.md`](mbedtls.md) for the opaque-context / custom-BIO
rationale. The upshot: `https://` and `wss://` inherit the TCP
transport's DNS multi-candidate fallback, compound read deadline, and
`Abort_Pending` unchanged, because `Set_Read_Deadline` and
`Abort_Pending` on the TLS transport just forward to the inner TCP one.

`Connect (Host, Port, Insecure, CA_Path)` lifecycle:

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
   bundle or opt into `Insecure`.
7. `mbedtls_ssl_setup`, then `mbedtls_ssl_set_hostname (Host)` for SNI
   *and* cert-name verification.
8. `mbedtls_ssl_set_bio` wires the send/recv callbacks (blocking; no
   recv-timeout callback — the deadline lives in the TCP transport).
9. Loop `mbedtls_ssl_handshake`, re-entering on
   `WANT_READ` / `WANT_WRITE`, failing on any other negative code.
10. `Read` / `Write` delegate to `mbedtls_ssl_read` / `_write`,
    re-entering on `WANT_READ` / `WANT_WRITE`; a clean close
    (`PEER_CLOSE_NOTIFY`, or the BIO recv reporting EOF) maps to
    `Last := 0`, matching the abstract contract.
11. `Close` is best-effort `mbedtls_ssl_close_notify`, then
    `TCP.Close`, then frees every context. Idempotent; a failed
    `Connect` has already freed and closed, so a follow-up `Close` is a
    no-op.

**Exceptions never cross the C frame.** The BIO send/recv callbacks
call into the inner TCP transport, which may raise `Timeout_Error`
(deadline), `Aborted_Error` (`Abort_Pending`), or `Transport_Error`.
Each callback catches it, records the kind in the BIO context, and
returns a negative `MBEDTLS_ERR_NET_{SEND,RECV}_FAILED`; the Ada side
inspects that record after the mbedTLS call returns and re-raises the
matching exception, so a deadline or cancel during a TLS read surfaces
as the *same* `Timeout_Error` / `Aborted_Error` a plain TCP read would
raise. mbedTLS-internal failures (bad cert chain, handshake failure,
bad record) surface as `TLS_Error` with the `mbedtls_strerror` message.

Concurrency: each transport instance owns its own mbedTLS state, so
two tasks using separate `TLS_Transport` objects do not interfere.
mbedTLS itself is compiled with `MBEDTLS_THREADING_C +
MBEDTLS_THREADING_PTHREAD` so its internal shared structures are safe
under parallel use.

Covered by `tests/bin/test_tls` (transport level): against the HTTPS
fixture `tests/server/server_tls.py` it verifies a good chain
(`CA_Path` → handshake succeeds, `/hello` echoes back), `Insecure`
bypass, and that a `VERIFY_REQUIRED` connect with no CA rejects the
self-signed chain with `TLS_Error`.
