# HTTP Stack

Packages under `AHT.HTTP`:

- `AHT.HTTP` — root package: the common exceptions.
- `AHT.HTTP.Methods` — the method enumeration.
- `AHT.HTTP.Status` — status codes and classification.
- `AHT.HTTP.Headers` — case-insensitive header map.
- `AHT.HTTP.Request` — request record, buffered + streaming wire write.
- `AHT.HTTP.Response` — response record, wire read.
- `AHT.HTTP.IO` — line/body readers; chunked decoder with streaming +
  buffered overloads.
- `AHT.HTTP.Client` — the client: HTTP + HTTPS, sync + streaming +
  async, with cancel.

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
   Body_B  : AHT.Bytes.Buffer;
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

### Anti-smuggling framing checks

`Write` (and `Write_Streaming` below) reject framing that RFC 7230
§3.3.3 calls out as a request-smuggling hazard, each raising
`Protocol_Error` before any wire byte is written:

- **`Transfer-Encoding` from the caller is rejected.** The buffered
  `Write` transcribes `Body_B` verbatim, so a TE-chunked header over
  raw bytes is malformed wire; the chunked encoder is `Write_Streaming`'s
  job and it owns that header. Use `Write_Streaming` (without a
  `Content-Length`) for chunked upload.
- **A duplicate `Content-Length` is rejected.** The header map allows
  repeated names, and intermediaries can disagree on which value wins.
- **A single caller `Content-Length` must match the body.** For
  buffered `Write` it must equal `Body_B.Length`; a declared-vs-actual
  mismatch (e.g. `Content-Length: 1` over a 4-byte body) would truncate
  the upload or hang the peer.

### Streaming upload — `Write_Streaming`

```ada
type Body_Source is limited interface;
procedure Read_Chunk
  (Self : in out Body_Source;
   Buf  : out AHT.Bytes.Byte_Array;
   Last : out Natural) is abstract;

subtype Byte_Count is Interfaces.Integer_64 range 0 .. Interfaces.Integer_64'Last;
procedure Set_Content_Length (Self : in out Request_Type; N : Byte_Count);

procedure Write_Streaming
  (Self        : Request_Type;
   T           : in out AHT.Transport.Transport_Type'Class;
   Source      : in out Body_Source'Class;
   Abort_Check : access function return Boolean := null);
```

`Write_Streaming` pumps a request body from a pull-style `Source`
straight to the wire, never buffering it — so a multi-GB upload runs in
O(1) memory. The caller derives a concrete type from `Body_Source` and
implements `Read_Chunk`, which fills the library-provided window
`Buf (Buf'First .. Last)` with the next bytes and signals end-of-stream
with `Last < Buf'First` (canonically `Last = 0`). Upload state (a file
handle, a generator cursor) lives in that derived type, so no closure or
`'Unrestricted_Access` is needed; the source is passed by reference and
the whole upload completes before the call returns.

The head is built exactly like `Write` (same request line, same
lowercase headers, same anti-smuggling checks). Framing is header-driven:

- **Fixed** — a single `Content-Length` (set it with `Set_Content_Length`,
  which takes a 64-bit `Byte_Count` so multi-GB sizes are expressible)
  streams exactly N raw bytes. A source that signals EOF early
  (under-run) or hands over more than N (over-run) raises
  `Protocol_Error`; the stream stops at exactly N.
- **Chunked** — with no `Content-Length`, the encoder emits
  `Transfer-Encoding: chunked` and frames each window as
  `{hex-size}CRLF {bytes} CRLF`, closing with `0 CRLF CRLF`
  (lowercase hex chunk size, no leading zeros — RFC 7230 §4.1). An empty
  body is just the terminator.

`Abort_Check`, when non-null, is polled between windows; a `True` result
raises `AHT.Transport.Aborted_Error` mid-body. It is a cheap secondary
fast-exit — the real bound on a stuck send is the transport's
non-blocking write deadline / `Abort_Pending`. A `Timeout_Error` /
`Aborted_Error` can fire after some body bytes have reached the peer, so
a failed streaming upload is retry-unsafe for a non-idempotent request.

### Ready-made body sources — `AHT.HTTP.Request.Sources`

You rarely need to hand-roll a `Body_Source`. The child package
`AHT.HTTP.Request.Sources` ships a `Stream_Source` over any Ada stream
(`Ada.Streams.Root_Stream_Type'Class`) — which subsumes files (via
`Ada.Streams.Stream_IO.Stream`), sockets, in-memory streams, and
generators in one type:

```ada
type Stream_Source is new Body_Source with private;
function Create
  (Stream : not null access Ada.Streams.Root_Stream_Type'Class)
   return Stream_Source;
```

```ada
--  Stream a file straight to the wire, no buffering, no Read_Chunk.
F : Ada.Streams.Stream_IO.File_Type;
Ada.Streams.Stream_IO.Open (F, Ada.Streams.Stream_IO.In_File, Path);
declare
   Src : Request.Sources.Stream_Source :=
           Request.Sources.Create (Ada.Streams.Stream_IO.Stream (F));
begin
   Req.Set_Content_Length (Byte_Count (Ada.Directories.Size (Path)));  --  fixed
   Client.Send_Streaming_Body (C, Req, Resp, Src);
end;
Ada.Streams.Stream_IO.Close (F);
```

- **Borrows, never owns.** `Stream_Source` holds an access to the stream;
  it has no finalizer and never opens or closes anything. The caller owns
  the file/socket lifetime. This is sound because the upload is
  synchronous — the source and the stream it points at outlive the whole
  `Send_Streaming_Body` / `Write_Streaming` call by construction.
- **Framing stays header-driven.** A generic stream has no length, so for
  fixed framing set the `Content-Length` yourself
  (`Set_Content_Length (Byte_Count (Ada.Directories.Size (Path)))` for a
  file); omit it for chunked. The source never touches framing.
- **In-memory bodies** don't need a source at all — use `Set_Body`
  (buffered). `Stream_Source` is for the streaming / from-disk /
  from-socket case.

## `AHT.HTTP.Response`

```ada
type Response_Type is tagged record
   Status  : AHT.HTTP.Status.Status_Code := 200;
   Reason  : Ada.Strings.Unbounded.Unbounded_String;
   Headers : AHT.HTTP.Headers.Map;
   Body_B  : AHT.Bytes.Buffer;
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

Only `chunked` is understood — any other
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
- `Read_Chunked_Body (T) return Buffer` — RFC 7230 §4.1
  decoder. Each iteration reads a chunk-size line (hex digits,
  case-insensitive; `chunk-ext` after a `;` is ignored), reads the
  chunk-data with `Read_N`, then consumes the mandatory bare CRLF.
  The zero-size chunk terminates the body; a trailer section
  follows (read and discarded — trailers are not surfaced)
  until a bare CRLF ends the message. Raises `Protocol_Error` on
  non-hex size, size overflow past `Natural'Last`, or chunk-data
  not followed by bare CRLF.

## `AHT.HTTP.Client`

```ada
type Client_Type is tagged record
   User_Agent      : Unbounded_String := "AHT/0.1";
   Default_Headers : AHT.HTTP.Headers.Map;
   CA_Path         : Unbounded_String;
   CA_PEM          : Unbounded_String;
   Insecure        : Boolean := False;
   Timeout_Seconds : Natural := 30;

   Resolve_Timeout    : Phase_Bound := Inherit;
   Connect_Timeout    : Phase_Bound := Inherit;
   Handshake_Deadline : Phase_Bound := Inherit;
   Write_Deadline     : Phase_Bound := Inherit;
   Read_Deadline      : Phase_Bound := Inherit;
end record;

type Phase_Bound is private;
Inherit   : constant Phase_Bound;   --  use Timeout_Seconds
Unbounded : constant Phase_Bound;   --  no bound at all
function Seconds (S : Duration) return Phase_Bound;

procedure Send (Self, Req, Resp);
function  Get  (Self, URL) return Response_Type;
```

`CA_PEM` holds trust anchors as PEM data rather than a path, for
anchors compiled into the binary. Setting both it and `CA_Path` raises
`TLS_Error` — but on the **request that consumes them**, not when the
field is set, and not at all on a plain `http://` request. These are
persistent TLS configuration on the client record rather than
arguments to a call, so a plain request simply does not read them,
exactly as it already ignores `CA_Path`.

### Behaviour

- **Synchronous, one request per call.** Each `Send` owns a fresh
  transport for the duration of the call, so multiple tasks can share
  one `Client_Type` without extra synchronization. `Connection: close`
  on every request — no keep-alive, no HTTP/2.

- **Scheme dispatch** on `Req.Target.Scheme`:
  - `http://` → `AHT.Transport.TCP`.
  - `https://` → `AHT.Transport.TLS` (custom BIO over the TCP
    transport). `Send` constructs a `TLS_Transport`, threading
    `Client_Type.CA_Path` / `.CA_PEM` / `.Insecure` into the
    handshake, then runs
    the same wire round-trip polymorphically.
  - `ws://` / `wss://` → raises `HTTP_Error`; route those through
    `AHT.Websocket.Client`.

- **`Timeout_Seconds` is a per-phase budget, not one end-to-end
  deadline.** A request walks five phases, and `Timeout_Seconds` (when
  non-zero) bounds each independently — each phase gets the full value
  as its own budget, so the wall clock a request may occupy is a
  multiple of it, not equal to it. `Timeout_Seconds = 0` disables all
  of them. The phases are the same for `http://` and `https://` (the
  TLS handshake phase is simply absent for plain HTTP):
  1. *DNS resolution* — **bounded** via `Connect`'s `Resolve_Timeout`,
     which resolves through `AHT.DNS` rather than a blocking
     `getaddrinfo` the caller cannot leave. The bound is on the
     *caller*: on expiry `Timeout_Error` is raised and the lookup
     itself carries on, because nothing can cancel it. A lookup that
     answers with no usable address is `Transport_Error` instead —
     a slow resolver and a bad name are different problems.
     Multi-candidate fallback (every A/AAAA record) happens here, in
     the TCP transport.
  2. *TCP connect* — **bounded** as a single total budget shared across
     every resolved candidate (not per-candidate), forwarded as
     `Connect`'s `Connect_Timeout`. If the budget runs out before any
     candidate connects, `Timeout_Error` is raised; non-timeout failures
     (all candidates refused) still raise `Transport_Error`.
  3. *TLS handshake* (`https://` only) — **bounded** via `Connect`'s
     `Handshake_Deadline`, so a peer that completes the TCP connect but
     stalls mid-handshake raises `Timeout_Error` instead of hanging. The
     deadline is cleared once the handshake completes.
  4. *request write* (`Send_Streaming_Body` only) — **bounded** by
     `Set_Write_Deadline`, which bounds a peer that stops reading
     mid-upload. The buffered overloads arm none: their body is
     already in RAM and drains in one shot.
  5. *response read* — **bounded** by `Set_Read_Deadline`, armed fresh
     in `Wire_Round_Trip` as a compound deadline over the whole
     response.

  `Cancel_Handle` binds after `Connect` returns, so cancel takes effect
  during the response read — not during DNS, connect, or handshake
  (same for both schemes).

- **Each phase can be bounded on its own.** One number spent five
  times couples bounds that have nothing to do with each other: the
  only way to allow a long download is to raise `Timeout_Seconds`, and
  that hands the same patience to a peer stalling mid-handshake. The
  five `Phase_Bound` fields split the knob, one per phase, each
  defaulting to `Inherit` — so a client that sets none of them behaves
  exactly as it did before the fields existed.

  ```ada
  C.Timeout_Seconds    := 0;                --  no bound on the body
  C.Connect_Timeout    := Client.Seconds (5.0);
  C.Handshake_Deadline := Client.Seconds (5.0);
  ```

  A field is one of three things: `Inherit` (take `Timeout_Seconds`),
  `Unbounded` (no bound, whatever `Timeout_Seconds` says), or
  `Seconds (S)`. The third state is why `Phase_Bound` is not just a
  `Duration` — `Inherit` has to be the default, or adding the fields
  would silently change what every existing client does.

  `Seconds (0.0)` is a **zero** budget, expiring at once; it is *not*
  a synonym for no bound, which is what `Timeout_Seconds => 0` means.
  The two knobs disagree deliberately, because the failure modes are
  not symmetric: reading `Seconds (0.0)` as "no bound" would hang,
  while reading it as zero gives an immediate `Timeout_Error`. Spell
  no bound as `Unbounded`.

  Exhaustion of any of them raises `Timeout_Error`, exactly as
  `Timeout_Seconds` does. The fields change which wait is bounded and
  by how much, never what a breach looks like.

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

- **Deadline.** When the resolved read bound is not `Duration'Last`,
  `Send` arms `Set_Read_Deadline` on the transport *after* the request
  body is on the wire — so a slow or large upload can't burn the response budget —
  as one wall-clock budget for the whole response (status line +
  headers + body), not per-`Read`. (The streaming-upload path
  additionally arms a write deadline; see
  [Streaming upload](#streaming-upload--send_streaming_body).)

- **Body framing.** Inherited from `Response.Read` — chunked >
  Content-Length > read-until-EOF for `Connection: close`.

- **Errors.** Non-2xx status is **not** an exception — `Resp.Status`
  carries it. Exceptions are reserved for malformed wire or
  transport failure: `HTTP_Error`, `Protocol_Error`,
  `Transport_Error`, `Timeout_Error`, `Aborted_Error`, plus
  `AHT.Transport.TLS.TLS_Error` for `https://` (e.g. an
  untrusted/invalid certificate chain). The transport is closed in
  every exit path (success or exception).

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

#### Download straight to an Ada stream

Two further `Send_Streaming` overloads write the response body to any
Ada stream instead of pushing it through a `Sink` — the download mirror
of the [`Stream_Source`](#ready-made-body-sources--ahthttprequestsources)
upload, so "save this response to a file/socket" needs no hand-rolled
callback:

```ada
procedure Send_Streaming
  (Self   : in out Client_Type;
   Req    : Request_Type;
   Resp   : out Response_Type;
   Target : not null access Ada.Streams.Root_Stream_Type'Class);
procedure Send_Streaming
  (Self, Req, Resp, Target, Cancel : ...);  -- + Cancel_Handle
```

```ada
--  Download a body straight to a file, no callback, no buffering.
F : Ada.Streams.Stream_IO.File_Type;
Ada.Streams.Stream_IO.Create (F, Ada.Streams.Stream_IO.Out_File, Path);
Client.Send_Streaming (C, Req, Resp, Target => Stream_IO.Stream (F));
Ada.Streams.Stream_IO.Close (F);
```

These resolve against the `Sink` overloads by the fourth parameter —
pass `Sink => ...` for the callback, `Target => ...` for the stream.
Behaviour is otherwise identical to the `Sink` form: `Resp.Status` /
`Resp.Reason` / `Resp.Headers` are populated, `Resp.Body_B` is empty
(the bytes went to the stream), the same chunk granularity applies, and
a stream `Write` that raises propagates out with the transport closed,
exactly like a raising `Sink`. Like `Stream_Source`, `Target` is
*borrowed* — the synchronous call outlives it, so the caller owns its
open/close lifetime.

### Streaming upload — `Send_Streaming_Body`

```ada
procedure Send_Streaming_Body
  (Self   : in out Client_Type;
   Req    : Request_Type;
   Resp   : out Response_Type;
   Source : in out Request.Body_Source'Class);
procedure Send_Streaming_Body
  (Self, Req, Resp, Source, Cancel : ...);  -- + Cancel_Handle
```

The mirror of `Send_Streaming`: where that streams the *download*
to a `Sink`, this streams the *upload* from a pull-style
`Source`, so a multi-GB body never has to be materialised in RAM.
The body is pulled via `Source.Read_Chunk` and framed on the wire
by `Request.Write_Streaming` — see
[`AHT.HTTP.Request` → Streaming upload](#streaming-upload--write_streaming)
for the `Body_Source` interface, `Set_Content_Length`, and the
fixed-vs-chunked framing rules. The **response is buffered** into
`Resp.Body_B` exactly like the plain `Send` — only the upload
streams.

Everything else matches `Send`: header merging, scheme dispatch,
the 1xx loop, and HEAD suppression are identical (it threads the
same `Run_Request` core, passing the `Source` instead of a
buffered body). Framing is header-driven:

- a single `Content-Length` on `Req` (set it with
  `Request.Set_Content_Length`) → fixed framing of exactly that
  many bytes; an under- or over-run raises `Protocol_Error`;
- otherwise → `Transfer-Encoding: chunked`.

The call is **synchronous** — it runs the whole upload and reads
the response before returning — so `Source` need only outlive the
call (there is no cross-task lifetime question). `Source.Read_Chunk`
runs on the caller's task and **must not block indefinitely**: on the
streaming-upload path `Write_Deadline` — or `Timeout_Seconds`, where
it is left at `Inherit` — arms a write deadline (in
addition to the usual read deadline), but it only bounds a stalled
*transmit* — a peer that stops reading — because it bites only once
control is inside the transport write. It does **not** interrupt a
`Read_Chunk` that is itself blocked, so a source that can stall must
enforce its own timeout. (Buffered `Send`/`Get`/`Send_Streaming` are
unchanged: they arm no write deadline, since their body is already in
RAM and drains in one shot.)

The write deadline is what makes a stalled send bounded: the
transport's non-blocking write loop re-parks on its selector and
raises `Timeout_Error` at the deadline instead of hanging forever.

The cancellable overload takes a `Cancel_Handle` with the same
semantics as the other cancellable surfaces. Cancel during an upload
bites at two points: the in-flight write is broken via `Abort_Pending`
(the parked non-blocking send wakes with `Aborted_Error`), and the
pump polls the handle **between source windows** before each
`Read_Chunk`. So a long upload or a peer that stalls the send is
interruptible — but a `Read_Chunk` already in progress is not
interrupted (cancel is observed before the next window, not during a
blocked read).

Same retry-safety caveat as `Send`: a `Timeout_Error` /
`Aborted_Error` can be raised mid-upload with some bytes already
on the wire, so a failed streaming upload of a non-idempotent
request is retry-unsafe.

Streaming upload is not offered on the **async** surface
(`Send_Async` stays buffered).

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
- **No connect cancellation.** `Abort_Pending` is a Read-
  side hook; `Cancel` can't interrupt a `Connect` in flight. A
  hung connect is bounded only by a deadline — `Connect_Timeout`
  and `Handshake_Deadline`, or `Timeout_Seconds` where those are
  left at `Inherit` (see the per-phase breakdown above) — never by
  `Cancel`, so it ends in `Timeout_Error` rather than on the
  `Cancel`. A caller who sets `Timeout_Seconds` to 0 to allow an
  unbounded body should set those two explicitly, or nothing
  bounds the dial at all. A pending `Cancel` then takes effect on the first
  Read once `Connect` returns.
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

Streaming async (`Send_Streaming_Async`) is not offered. If
you want streaming + async, spawn your own task that calls
`Send_Streaming` directly.
