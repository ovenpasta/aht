<!--
SPDX-FileCopyrightText: 2026 Aldo Nicolas Bruno
SPDX-License-Identifier: Apache-2.0
-->

# Transport

Packages:

- `AHT.Transport`: the abstract transport interface.
- `AHT.Transport.TCP`: plain TCP, used for `http://` and `ws://`.
- `AHT.Transport.TLS`: TLS over the TCP transport, used for
  `https://` and `wss://`. One spec, one body per backend; see
  [`tls.md`](tls.md).
- `AHT.Transport.Waits`: the clamp that keeps a finite wait from
  becoming `GNAT.Sockets.Forever`. Public so that a test can drive
  it without a socket.

## Abstraction

```ada
type Transport_Type is
  abstract new Ada.Finalization.Limited_Controlled with null record;

procedure Write (Self : in out Transport_Type;
                 Data : Byte_Array) is abstract;
procedure Read  (Self : in out Transport_Type;
                 Data : out Byte_Array;
                 Last : out Natural) is abstract;
procedure Close (Self : in out Transport_Type) is abstract;
function  Is_Connected (Self : Transport_Type) return Boolean
  is abstract;

procedure Set_Read_Deadline
  (Self : in out Transport_Type; Deadline : Duration) is null
  with Pre'Class => Deadline >= 0.0;
procedure Set_Write_Deadline
  (Self : in out Transport_Type; Deadline : Duration) is null
  with Pre'Class => Deadline >= 0.0;
procedure Abort_Pending (Self : in out Transport_Type) is null;

overriding procedure Finalize (Self : in out Transport_Type);
```

### Read and Write semantics

`Read` fills `Data` up to its bound, blocking until some bytes arrive
(`Last` is the last filled index) or the peer closes cleanly
(`Last := 0`). It does not guarantee filling the slice; callers that
need exact counts (`AHT.HTTP.IO.Read_N`) loop.

`Write` sends every byte of `Data` or raises. A `Timeout_Error`,
`Aborted_Error` or `Transport_Error` can be raised after some bytes
have reached the peer, so a failed write is not all-or-nothing on the
wire and is retry-unsafe for anything non-idempotent. An
implementation that can desynchronise the stream this way must fail
closed and mark the connection dead (see *Poison* below); the caller
owns the decision to retry.

Concurrency contract, all implementations: at most one task in
`Read` and one task in `Write` at a time, the receiver-task-plus-
sender shape the WebSocket client uses. Two concurrent readers or
two concurrent writers are not supported.

### Deadlines and cancel

`Set_Read_Deadline` and `Set_Write_Deadline` each set a wall-clock
budget, measured from the call, for every subsequent `Read` (or
`Write`) until reset. The budget is compound: each operation consults
the time remaining, not the original `Duration`, so a slow-drip peer
that returns one byte every `Deadline / N` seconds still trips
`Timeout_Error` on call `N+1`. `Duration'Last` clears the deadline
and is the initial state. Both setters carry
`Pre'Class => Deadline >= 0.0`.

`Abort_Pending` unblocks a `Read` or `Write` in progress, typically
from another task, by making it raise `Aborted_Error`. It is
idempotent and safe to call when nothing is pending.

The default bodies are no-ops, so an implementation that cannot
enforce them leaves `Read` and `Write` blocking.

### Finalize

`Finalize` dispatches to the concrete `Close`, so a transport that
goes out of scope without an explicit `Close` still drops its socket
and TLS contexts. It never raises: any exception from `Close` is
swallowed, because a propagating exception during unwinding becomes
`Program_Error`. It relies on every `Close` being idempotent, since
component or parent finalization can drive a second `Close` after an
explicit one, and it inherits `Close`'s single-threaded precondition:
no other task may be inside any operation on the transport while it
runs. Standalone transports (the HTTP client's per-request one) are
used on one task. The WebSocket client's transport lives in a
heap-allocated session that its receiver task owns and closes after
quiescing every borrower, so `Finalize` there runs on an already
closed transport.

### Exceptions

- `Transport_Error`: OS-level I/O failures or socket errors (connect
  refused, write to a closed peer, a connection torn down under a
  parked operation by `Poison`).
- `Timeout_Error`: a budget expired (`Set_Read_Deadline`,
  `Set_Write_Deadline`, `Connect_Timeout`, `Resolve_Timeout`,
  `Handshake_Deadline`).
- `Aborted_Error`: `Abort_Pending` fired while an operation was
  parked.
- `AHT.Transport.TLS.TLS_Error`: backend-neutral; a TLS-level failure
  on either backend (untrusted chain, handshake failure, bad record,
  the truncation case on openssl).

## `AHT.Transport.TCP`

A wrapper over `GNAT.Sockets`.

`Connect (Host, Port, Connect_Timeout, Resolve_Timeout)`:

1. Tries `Inet_Addr (Host)`, which succeeds for IPv4 and IPv6
   literals. If it parses, only that address is tried; a literal
   that does not answer is a hard failure.
2. Otherwise calls `AHT.DNS.Resolve` (through `getaddrinfo`, both
   families), bounded by `Resolve_Timeout`, builds an
   `Endpoint_List` of every returned literal paired with `Port`, and
   delegates to `Connect_Candidates`.
3. `Connect_Candidates (Endpoints, Connect_Timeout)` tries every
   candidate in the resolver's order, closing the half-open socket
   from a failed attempt before the next; the first `Connect_Socket`
   that succeeds wins. Each attempt opens a stream socket of the
   address's family, so `127.0.0.1`, `::1` and dual-stacked names
   all work. `Connect_Timeout` is one total budget across all
   candidates, not per candidate; exhaustion raises `Timeout_Error`.
   If every candidate fails for another reason, `Transport_Error`
   carries the last OS error message.

`Resolve_Timeout` exhaustion raises `Timeout_Error`, distinct from
the `Transport_Error` of a lookup that answered with no usable
address. It is not consulted when `Host` is a literal.
`Duration'Last` (the default) leaves either budget unbounded.

`Connect_Candidates` is public so that tests can drive the fallback
with an explicit list; each `Host` must already be a numeric literal.

`Connect` takes a plain string host, not a `URL_Type`: the caller
passes `URL.Host` (already bracketless) and `URL.Port`.
`GNAT.Sockets` accepts a raw IPv6 address.

A transport is permanently single-use. `Used` latches at the first
successful `Connect` and is never cleared, not even by `Close`, so a
later `Connect` raises `Transport_Error`; a reader parked on the old
session could otherwise wake after a new descriptor was swapped in
and read the wrong connection. A `Connect` that fails leaves the
object usable for a retry. To open another connection, use a fresh
object.

### Reading and writing

No stream object is held: `Write` and `Read` call `Send_Socket` and
`Receive_Socket` directly on the socket, so there is no
`GNAT.Sockets.Stream`/`Free` pairing to leak.

`Connect` creates two persistent `Selector_Type`s, `Selector` for the
read path and `Write_Selector` for the write path, and `Close`
destroys them. A single selector does not support two simultaneous
`Check_Selector` waiters, so each direction parks on its own; that is
what limits the transport to one reader and one writer.

`Read` parks in `Check_Selector` on the read selector with the time
remaining on the read deadline as `Timeout`, then does a single
`Receive_Socket`; `Last := 0` when the peer has closed cleanly. An
already-elapsed deadline raises without parking. The deadline is
stored as an `Ada.Real_Time` instant, so wall-clock jumps do not
affect it.

`Write` loops around `Send_Socket` until the whole slice is flushed,
parking on the write selector until the socket is writable and
checking the write deadline on each pass.

`Read` and `Write` also have deadline-explicit overloads taking an
absolute `Ada.Real_Time.Time`. They bound that one call by that
instant and ignore the compound deadlines; everything else, including
`Abort_Pending` and the poison rules, is the same. The TLS backends
use them to bound a wait performed on behalf of the other direction's
operation by that operation's deadline.

`Abort_Pending` calls `Abort_Selector` on both selectors, so a `Read`
or `Write` parked in `Check_Selector` returns `Aborted` and raises
`Aborted_Error`.

`Waits.Bounded` clamps every finite timeout handed to
`Check_Selector`. `GNAT.Sockets.Forever` is a sentinel mapped to a
null `timeval`, not a duration: on Windows `select` takes a 32-bit
millisecond timeout, so `Forever` is about 49.7 days and
`Duration'Last` does not fit in `Selector_Duration`. `Bounded` never
returns the sentinel; a budget above `Longest_Finite` is served in
chunks, with the caller re-checking its absolute deadline between
parks.

### Poison

A fatal `Write` poisons the transport rather than closing it, because
a reader may be parked inside `Check_Selector` and GNAT forbids
`Close_Selector` while it is. `Poison` marks the transport
disconnected, shuts the socket down, and aborts both selectors; it
does not close the socket or the selectors, which is left to the
single-threaded `Close`. `Poison` is safe to call while another task
is parked on the same transport. The TLS backends' `Drop_Connection`
takes it from read-side fatal paths too, so the caller is not
necessarily the writer; both selectors are aborted for that reason.

The wake goes through the selector rather than relying on the
shutdown. Shutting a socket down makes it readable on POSIX, so a
parked `select` returns and `Receive_Socket` reports 0; Winsock
signals nothing to a `select` already waiting for a locally initiated
shutdown.

A `Read` or `Write` woken this way raises `Transport_Error`, not
`Aborted_Error` and not an EOF: the connection was torn down under
the operation, which is neither a caller-requested abort nor the peer
closing. The outcome is decided on the transport's `Connected` flag
(`Atomic`, because `Poison` writes it from another task) rather than
on which `Selector_Status` arrived. Its message says "poisoned after
its entry check", distinct from the message an operation that finds
the transport already dead at that check gets; neither message says
whether the operation was blocked, since `Abort_Selector` queues an
event that the next `Check_Selector` consumes.

### Close

`Close` is idempotent: repeated calls are no-ops, and `Socket_Error`
from `Shutdown_Socket`/`Close_Socket` is swallowed. It closes the
socket and both selectors and clears the deadlines. Its
precondition, which the caller keeps and the transport cannot
enforce, is that no other task is inside any operation on the
transport: `Close` reclaims the socket, both selectors and the
deadline state, and a `Close` racing a parked reader is a contract
violation (GNAT forbids `Close_Selector` while another task waits on
it). For the concurrent fatal-write case, `Poison` and defer `Close`
until the reader has exited.

Any `Socket_Error` or `Host_Error` during `Connect`, `Write` or
`Read` is re-raised as `Transport_Error` with the OS message
appended, so callers never see `GNAT.Sockets` exceptions.

## `AHT.Transport.TLS`

One backend-neutral spec (`src/aht-transport-tls.ads`) with two
bodies, `src/tls/openssl/` and `src/tls/mbedtls/`, selected by the
`AHT_TLS_BACKEND` gpr external. Backend selection, the per-backend
policy differences, the memory-BIO engine both backends share, the
mbedtls `Connect` sequence and the vendored-library configuration are
all in [`tls.md`](tls.md).

The bytes always travel over an `AHT.Transport.TCP` instance held
inside the backend state, allocated per `Connect` attempt, so a
failed `Connect` releases it and the object stays retryable, while a
successful session latches the transport single-use. There is no
second socket stack, so `https://` and `wss://` inherit the TCP
transport's DNS fallback, deadlines and `Abort_Pending`. The
concurrency contract is the same: one reader task and one writer
task.

`Connect (Host, Port, Insecure, CA_Path, Connect_Timeout,
Handshake_Deadline, CA_PEM, Resolve_Timeout)`:

- `Connect_Timeout` and `Resolve_Timeout` are forwarded to the TCP
  connect. Resolving here rather than in the caller keeps `Host` as
  the name, so SNI and certificate verification are unaffected.
- `Handshake_Deadline` bounds the TLS handshake only: not DNS or the
  TCP connect (they run before it is armed), and not later
  `Read`/`Write` (the `Set_*_Deadline` budgets govern those and are
  installed after the handshake succeeds).
- `CA_Path` names a PEM bundle file or a directory; `CA_PEM` is the
  same material in memory, for anchors compiled into the binary.
  Supplying both raises `TLS_Error` before anything is dialled, even
  under `Insecure`. `CA_PEM`'s envelope is validated by `AHT.PEM`
  before either backend sees it, unconditionally, because neither
  backend reports trailing garbage after a valid certificate:
  OpenSSL's `PEM_R_NO_START_LINE` also means "no further header",
  and mbedTLS returns the count of certificates that failed, which
  is zero for trailing junk. Parsing is all-or-nothing.
- `Insecure => True` skips certificate verification.

`Close` is a best-effort close_notify (skipped when the session died
of a fatal error), then `TCP.Close`, then unconditional freeing of
the backend contexts; idempotent. Its precondition is the TCP one
extended to the whole object: `Close` frees the state that
`Is_Connected`, the deadline setters and `Abort_Pending` dereference,
so no other task may be inside any operation while it runs. See
*The `Close` precondition* in [`tls.md`](tls.md).

`Is_Connected` is true after a successful `Connect` until `Close`,
except that a session poisoned by a fatal `Read`/`Write` reports
false through a task-safe latch. `Set_Read_Deadline` and
`Set_Write_Deadline` are mirrored as absolute times computed once and
forwarded to the inner TCP; they may be called before `Connect`, in
which case they apply to the future connection's `Read`/`Write`, not
to the handshake.

## Tests

The transport tests are listed in `tests/tests.gpr`. The built
binaries are under `tests/bin/<variant>/`, where the variant is
`<mode>-<backend>`, with the cross target appended for
`AHT_OS=windows`.
