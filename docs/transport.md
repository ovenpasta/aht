# Transport

Packages:

| Unit | Status |
|---|---|
| `AHT.Transport` (abstract) | spec implemented |
| `AHT.Transport.TCP` | implemented |
| `AHT.Transport.TLS` | stubbed |

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

- **`Set_Read_Deadline (Duration)`** — max time the next `Read` (and
  subsequent reads, until reset) may block before raising
  `Timeout_Error`. `Duration'Last` means no deadline. Applied by
  passing the stored value as `Timeout` to `Check_Selector` before
  every `Receive_Socket`.
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
the persistent selector and resets `Read_Deadline` to
`Duration'Last` so a fresh `Connect` on the same object starts from
a clean state.

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

Four cases, each with its own server task (except case 4, which
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

## `AHT.Transport.TLS` — to be implemented

Wraps a TCP transport with an mbedTLS SSL context. Lifecycle per
connection:

1. Initialise `mbedtls_{ssl, ssl_config, x509_crt, ctr_drbg, entropy,
   net}` contexts.
2. Seed the DRBG (`mbedtls_ctr_drbg_seed`).
3. Load CA chain — `CA_Path` if supplied, else `/etc/ssl/certs` — via
   `mbedtls_x509_crt_parse_file` / `_path`.
4. `mbedtls_ssl_config_defaults` with client preset, TLS 1.2+
   profile.
5. `mbedtls_ssl_conf_authmode`:
   - `MBEDTLS_SSL_VERIFY_REQUIRED` by default;
   - `MBEDTLS_SSL_VERIFY_NONE` when `Insecure => True` (for self-
     signed test certs).
6. `mbedtls_net_connect` + `mbedtls_ssl_set_bio` binding.
7. `mbedtls_ssl_set_hostname` for SNI.
8. Loop `mbedtls_ssl_handshake` until it returns 0 or an error.
9. `Read` / `Write` delegate to `mbedtls_ssl_read` / `_write`,
   re-entering on `MBEDTLS_ERR_SSL_WANT_READ` / `_WANT_WRITE`.
10. `Close` calls `mbedtls_ssl_close_notify` then frees every context.

Concurrency: each transport instance owns its own mbedTLS state, so
two tasks using separate `TLS_Transport` objects do not interfere.
mbedTLS itself is compiled with `MBEDTLS_THREADING_C +
MBEDTLS_THREADING_PTHREAD` so its internal shared structures are safe
under parallel use.
