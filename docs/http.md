# HTTP Stack

Packages under `AHT.HTTP`:

| Unit | Status |
|---|---|
| `AHT.HTTP` (root exceptions) | implemented |
| `AHT.HTTP.Methods` | implemented |
| `AHT.HTTP.Status` | implemented |
| `AHT.HTTP.Headers` | implemented |
| `AHT.HTTP.Request` | implemented (wire write) |
| `AHT.HTTP.Response` | implemented (wire read) |
| `AHT.HTTP.IO` | implemented (chunked decoder has streaming + buffered overloads) |
| `AHT.HTTP.Client` | implemented (HTTP, sync + streaming + async, with cancel); HTTPS pending TLS |

Common exceptions (in `AHT.HTTP`): `HTTP_Error`, `Protocol_Error`,
`Handshake_Error`.

## `AHT.HTTP.Methods`

`type Method_Type is (GET, POST, PUT, DELETE, HEAD, PATCH, OPTIONS);`
with `function Image (M) return String`.

## `AHT.HTTP.Status`

```ada
subtype Status_Code is Integer
  with Static_Predicate => Status_Code in 100 .. 599;
function Reason_Phrase (Code : Status_Code) return String;
```

`Reason_Phrase` returns the standard reason for the common codes
(100/101/200/201/202/204, 3xx, 4xx, 5xx) and `""` for codes without a
defined phrase. The subtype predicate catches nonsensical values at
runtime when contracts are enabled.

## `AHT.HTTP.Headers`

Case-insensitive multimap. Names are normalized to lowercase on
storage; lookup is case-insensitive.

### Type invariant

`Type_Invariant => Invariant_Ok (Map.Entries)` — every stored name is
non-empty and already lowercase. The invariant is checked after every
public call that may mutate the map.

### Operations

- `Set (Self, Name, Value)` — `Pre => Name'Length > 0`. Removes any
  existing entries for `Name`, then stores the new one.
  **Post** `Self.Contains (Name)`.
- `Append (Self, Name, Value)` — `Pre => Name'Length > 0`. Preserves
  existing entries. **Post** `Self.Contains (Name)`. Use for
  repeatable headers (including `Set-Cookie`).
- `Remove (Self, Name)` — **Post** `not Self.Contains (Name)`.
- `Contains (Self, Name) return Boolean`.
- `Get (Self, Name) return String` — first value or `""`.
- `Values (Self, Name) return Value_List` — every value in insertion
  order. **Does not** combine with `", "`, because `Set-Cookie`
  (RFC 6265 §3) is not comma-combinable. The caller decides.
- `Count (Self) return Natural` — total entries (not unique names).
- `Iterate (Self, Process)` — yields each stored entry; names arrive
  lowercase.

## `AHT.HTTP.Request`

```ada
type Request_Type is tagged record
   Method  : AHT.HTTP.Methods.Method_Type := AHT.HTTP.Methods.GET;
   Target  : AHT.URL.URL_Type;
   Headers : AHT.HTTP.Headers.Map;
   Body_B  : AHT.Bytes.Byte_Vector;
end record;

procedure Write
  (Self : Request_Type;
   T    : in out AHT.Transport.Transport_Type'Class);
```

`Write` emits the HTTP/1.1 wire form — request line
(`METHOD SP request-target SP HTTP/1.1 CRLF`), stored headers in
insertion order, blank line, body. Header names are written in
their stored lowercase form (RFC 7230 §3.2 allows it; case is
insensitive on the wire).

If `Body_B` is non-empty and the caller did not set `Content-Length`,
`Write` synthesises a `Content-Length` so the request is always
framed. It does **not** invent `Host`, `User-Agent`, `Connection`,
or `Authorization`: routing and policy headers stay the caller's job
(the `Client` layer above is the one that merges them in).

If the caller sets `Transfer-Encoding`, `Write` raises
`Protocol_Error`. v1 does not do chunked request bodies — `Write`
transcribes `Body_B` verbatim, and emitting a TE-chunked header
with raw body bytes would produce malformed wire that the peer
would reject (or worse, misparse). Streaming upload is a separate
API still to land.

## `AHT.HTTP.Response`

```ada
type Response_Type is tagged record
   Status  : AHT.HTTP.Status.Status_Code := 200;
   Reason  : Ada.Strings.Unbounded.Unbounded_String;
   Headers : AHT.HTTP.Headers.Map;
   Body_B  : AHT.Bytes.Byte_Vector;
end record;

procedure Read
  (Self   : out Response_Type;
   T      : in out AHT.Transport.Transport_Type'Class;
   Method : AHT.HTTP.Methods.Method_Type := AHT.HTTP.Methods.GET);
```

`Read` parses a status line (`HTTP/1.x SP status SP [reason]`),
header lines until a blank line, then picks body framing:

0. `Method = HEAD`, or `Status` in 1xx / 204 / 205 / 304 → no body.
   The message ends at the empty line; any `Content-Length` or
   `Transfer-Encoding` the peer sent is ignored per RFC 7230 §3.3.3
   (and RFC 9110 §15.3.6 for 205). This is load-bearing for:
   - **HEAD** — the peer usually advertises the GET-equivalent
     `Content-Length`; the codec can't infer the request method,
     so the caller passes it. Reading the announced bytes would
     block forever (no body is coming).
   - **101 Switching Protocols** — bytes after CRLFCRLF belong to
     the upgraded protocol, e.g. a WebSocket frame; reading them
     as body would consume the first frame.
   - 204 / 205 / 304 on `Connection: close` — the EOF fallback
     would otherwise block until the peer closes even though the
     message is already complete.
1. `Transfer-Encoding: chunked` → `AHT.HTTP.IO.Read_Chunked_Body`.
2. `Content-Length: N` → `Read_N` for exactly *N* bytes.
3. otherwise → read until the peer closes (for
   `Connection: close` responses).

Only `chunked` is understood in v1 — any other
`Transfer-Encoding` (gzip, compress, chunked+gzip, …) raises
`Protocol_Error` rather than hand back decoded bytes for a codec
we don't have. A `Status` outside `100..599`, a missing colon on
a header line, or a non-numeric `Content-Length` also raise
`Protocol_Error`. The status line with an empty reason phrase
(`HTTP/1.1 204 CRLF`) is legal and leaves `Reason` empty.

## `AHT.HTTP.IO`

Transport-level helpers over `AHT.Transport.Transport_Type'Class`.
All four operations delegate to `Transport.Read` / `Transport.Write`
and, crucially, do **not** track their own deadlines. Deadlines and
cancel live on the transport (`Set_Read_Deadline` / `Abort_Pending`);
because the deadline is compound (a wall-clock budget from the
`Set_` call that is not refreshed per `Read` — see
`docs/transport.md`), the byte-by-byte `Read_Line` and the looped
`Read_N` below honour it for the whole logical operation, not for
each underlying `Read`. A slow-drip peer that dribbles one byte per
(deadline / N) seconds trips `Timeout_Error` instead of tying up the
reader forever.

- `Write_All (T, Data)` — the transport's `Write` contract is
  already all-or-raise, so this is a thin named entry point plus a
  `Log.Trace` on the `"http.io"` subsystem. Empty slice is a no-op.
- `Read_Line (T, Max_Length => 8_192) return String` — reads
  byte-by-byte until CRLF, returns the line **without** the CRLF.
  Byte-by-byte lets the caller transition from line-mode (status +
  headers) to body-mode without a buffered-reader abstraction: the
  transport is positioned exactly at the byte after CRLF with no
  overshoot. Raises `Protocol_Error` on peer close before CRLF or
  when `Max_Length` bytes have been consumed without finding one.
- `Read_N (T, Data)` — fills every slot in `Data` by looping around
  `Transport.Read`. Raises `Protocol_Error` if the peer closes
  before `Data'Length` bytes have been received. Zero-length slice
  is a no-op.
- `Read_Chunked_Body (T) return Byte_Vector` — RFC 7230 §4.1
  decoder. Each iteration reads a chunk-size line (hex digits,
  case-insensitive; `chunk-ext` after a `;` is ignored), reads the
  chunk-data with `Read_N`, then consumes the mandatory bare CRLF.
  The zero-size chunk terminates the body; a trailer section
  follows (read and discarded — trailers are not surfaced in v1)
  until a bare CRLF ends the message. Raises `Protocol_Error` on
  non-hex size, size overflow past `Natural'Last`, or chunk-data
  not followed by bare CRLF.

## `AHT.HTTP.Client`

```ada
type Client_Type is tagged record
   User_Agent      : Unbounded_String := "AHT/0.1";
   Default_Headers : AHT.HTTP.Headers.Map;
   CA_Path         : Unbounded_String;
   Insecure        : Boolean := False;
   Timeout_Seconds : Natural := 30;
end record;

procedure Send (Self, Req, Resp);
function  Get  (Self, URL) return Response_Type;
```

### Behaviour

- **Synchronous, one request per call.** Each `Send` owns a fresh
  transport for the duration of the call, so multiple tasks can share
  one `Client_Type` without extra synchronization. `Connection: close`
  in v1 — no keep-alive, no HTTP/2.

- **Scheme dispatch** on `Req.Target.Scheme`:
  - `http://` → `AHT.Transport.TCP`.
  - `https://` → not yet wired; raises `HTTP_Error` until mbedTLS
    integration lands (planned `AHT.Transport.TLS` with `CA_Path` /
    `Insecure`).
  - `ws://` / `wss://` → raises `HTTP_Error`; route those through
    `AHT.Websocket.Client`.

- **Header merging.** `Send` builds a working copy of `Req` and fills
  in three classes of headers, *only where not already present*, so
  the order of precedence is `Req` > `Default_Headers` > auto:
  1. Each entry of `Self.Default_Headers` whose name is absent from
     `Req.Headers` is appended (preserving multi-valued defaults
     like repeated `Accept`).
  2. `Host` from the URL (`host[:port]`, omitting the default port).
  3. `User-Agent` from `Self.User_Agent`.
  4. `Connection: close`.

- **Interim 1xx loop.** `Send` reads responses in a loop and only
  exits when the status is not 1xx. `101 Switching Protocols` is
  the one **terminal** 1xx — it returns as-is with the post-header
  bytes still buffered on the transport for a WebSocket layer to
  consume. `100 Continue`, `103 Early Hints`, and friends are read
  and discarded.

- **HEAD bodies.** `Req.Method` is threaded into `Response.Read` so
  HEAD responses skip body framing even when the peer sends a
  Content-Length (which it commonly does, advertising the
  GET-equivalent size).

- **Deadline.** When `Timeout_Seconds > 0`, `Send` calls
  `Set_Read_Deadline` on the transport before writing. The deadline
  is the wall-clock budget for the whole response (status line +
  headers + body), not per-`Read`.

- **Body framing.** Inherited from `Response.Read` — chunked >
  Content-Length > read-until-EOF for `Connection: close`.

- **Errors.** Non-2xx status is **not** an exception — `Resp.Status`
  carries it. Exceptions are reserved for malformed wire or
  transport failure: `HTTP_Error`, `Protocol_Error`,
  `Transport_Error`, `Timeout_Error`, `Aborted_Error`. The transport
  is closed in every exit path (success or exception).

- **`Get (URL)`** — convenience: parses `URL`, builds a GET with no
  body, calls `Send`. Raises `AHT.URL.Parse_Error` on malformed URL.

### Streaming — `Send_Streaming`

```ada
procedure Send_Streaming
  (Self : in out Client_Type;
   Req  : Request_Type;
   Resp : out Response_Type;
   Sink : not null access procedure (Chunk : AHT.Bytes.Byte_Array));
procedure Send_Streaming
  (Self, Req, Resp, Sink, Cancel : ...);  -- + Cancel_Handle
```

Same semantics as `Send` for status line / headers / 1xx looping
/ 101 carve-out / HEAD suppression / scheme dispatch, but body
bytes are delivered to `Sink` as they arrive instead of being
accumulated in `Resp.Body_B`. After the call, `Resp.Status`,
`Resp.Reason`, and `Resp.Headers` are populated; `Resp.Body_B`
is empty.

The buffered `Send`s and `Send_Streaming` share a single internal
core (`Run_Request` takes a sink; the buffered overloads supply a
sink that appends to `Resp.Body_B`), so every behaviour
documented for `Send` — header merging, deadline, cancel — also
applies here.

Chunk granularity (treat as hints, not contract):

- `Transfer-Encoding: chunked` → one `Sink` call per decoded
  chunk; the zero-size terminator is consumed but not delivered.
- `Content-Length: N` → `Sink` is called with up to 4 KiB chunks
  (one call when `N` ≤ 4 KiB).
- neither header (`Connection: close`) → `Sink` is called with
  whatever the transport returns per `Read` (typically up to one
  TCP segment).

`Sink` may raise; the exception propagates out of `Send_Streaming`
and the transport is closed on that path. `Sink` must not invoke
`Send` recursively against the same `Client_Type` (the transport
is in mid-call).

`Sink` is **not called for 1xx responses** (no body) and **not
called for 101 Switching Protocols** (post-header bytes are left
on the wire for the WebSocket layer).

### Cancellation — `Cancel_Handle`

The 4-argument `Send` takes a `Cancel_Handle` for cross-task abort:

```ada
type Cancel_Handle is limited private;
procedure Cancel        (Self : in out Cancel_Handle);
function  Is_Cancelled  (Self : Cancel_Handle) return Boolean;

procedure Send
  (Self   : in out Client_Type;
   Req    : Request_Type;
   Resp   : out Response_Type;
   Cancel : in out Cancel_Handle);
```

Internally the handle wraps a protected object holding the
currently-bound transport and a sticky `Cancelled` flag. `Send`
binds the transport after `Connect` and unbinds before `Close`;
`Cancel` from any task sets the flag and dispatches
`Transport.Abort_Pending` on the bound transport, which is what
unblocks a parked `Read` (the same mechanism `test_tcp` exercises
at the transport layer).

Lifecycle:

- **Cancel during the request** → `Send` raises
  `AHT.Transport.Aborted_Error` from inside the response `Read`.
  The transport is closed on the abort path.
- **Cancel before Send** → handle is armed; the next `Send` raises
  immediately *before* dialing. Without this, a pre-cancelled
  handle would still cost a TCP connect.
- **Cancel after Send returns** → handle's `Bound` is null;
  `Cancel` is a quiet no-op (the flag still flips so
  `Is_Cancelled` reports the call happened).
- **Bind race** — if `Cancel` lands between `Connect` returning
  and `Bind` running, the `Bind` body re-checks `Cancelled` under
  the protected lock and fires `Abort_Pending` on the
  freshly-bound transport. The very first `Read` then raises.

Caveats:

- **Single-use.** Once `Cancel` has been called, every subsequent
  `Send` with this handle aborts immediately. Declare a fresh
  handle per cancellable operation.
- **No connect cancellation in v1.** `Abort_Pending` is a Read-
  side hook; `Cancel` can't interrupt a `Connect` in flight. A
  hung connect waits for the OS connect timeout (the client has
  no connect-side timeout of its own — `Timeout_Seconds` only
  feeds `Set_Read_Deadline`, which runs after `Connect` returns).
  The cancel then takes effect on the first Read.
- **Don't share a handle across concurrent `Send`s.** The
  protected `Bound` slot is overwritten by whichever Send binds
  last; `Cancel` will only abort that one. Use one handle per
  call.

### Async — `Send_Async` / `Await`

```ada
type Async_Handle is limited private;
procedure Send_Async  (Self : in out Client_Type;
                       Req  : Request_Type;
                       Async : in out Async_Handle);
procedure Await       (Self : in out Async_Handle;
                       Resp : out Response_Type);
procedure Cancel      (Self : in out Async_Handle);
function  Is_Done     (Self : Async_Handle) return Boolean;
function  Is_Cancelled (Self : Async_Handle) return Boolean;
```

`Async_Handle` wraps a worker task plus a `Cancel_State`. The
worker auto-starts when the handle is elaborated and blocks at an
internal `accept Start or terminate`. `Send_Async` snapshots
`Self` and `Req` into the worker, kicks off the request, and
returns immediately. The worker runs the same `Run_Request` core
as the sync surface, stashes the response (or the exception via
`Ada.Exceptions.Save_Occurrence`) in the shared `Cancel_State`,
flips `Done_Flag`, and **terminates**. `Await` waits on the
`Done_Flag` barrier and reads the stored result; multiple Awaits
all read the same state. `Cancel` is the same Cancel_State
mechanism as the sync handle.

Lifecycle:

- **One Send per handle.** A second `Send_Async` on a started
  handle raises `HTTP_Error`. Declare a fresh handle per request.
- **`Await` before `Send_Async` raises.** A fresh handle's worker
  is parked at its `Start` rendezvous and `Wait_Until_Done` would
  block forever, so `Await` checks `Started` first and raises
  `HTTP_Error` rather than deadlocking.
- **`Await` is replayable.** Subsequent Awaits on a Done handle
  re-read the cached response (or re-raise the cached
  exception); no second rendezvous, no block.
- **Snapshot at Start.** `Self` and `Req` are copied into the
  worker by the entry call; mutating them in the caller after
  `Send_Async` has no effect on the in-flight request.
- **Cancel before, during, or after.** Same Cancel_State rules:
  pre-cancel before `Send_Async` arms the next Send; cancel
  during `Run_Request` aborts the bound transport; cancel after
  `Await` (the worker is past Done) is a sticky no-op that just
  flips `Is_Cancelled`.
- **Drop without `Await`.** The worker terminates as soon as it
  finishes `Run_Request` and stashes the result, so the
  enclosing master only waits for `Run_Request` itself — no
  trailing rendezvous. A hung connect or read still blocks the
  scope exit, so `Cancel` + `Await` if you might want to abandon
  before the request finishes.

Streaming async (`Send_Streaming_Async`) is **not** in v1. If
you want streaming + async, spawn your own task that calls
`Send_Streaming` directly.
