<!--
SPDX-FileCopyrightText: 2026 Aldo Nicolas Bruno
SPDX-License-Identifier: Apache-2.0
-->

# HTTP Stack

Packages under `AHT.HTTP`:

- `AHT.HTTP`: root package, the common exceptions.
- `AHT.HTTP.Methods`: the method enumeration.
- `AHT.HTTP.Status`: status codes and reason phrases.
- `AHT.HTTP.Headers`: case-insensitive header map.
- `AHT.HTTP.Request`: request record, buffered and streaming wire
  write.
- `AHT.HTTP.Response`: response record, buffered and streaming wire
  read.
- `AHT.HTTP.IO`: line and body readers; chunked decoder with
  streaming and buffered overloads.
- `AHT.HTTP.Client`: the client. HTTP and HTTPS; synchronous,
  streaming and async surfaces, with cancel.

Common exceptions (in `AHT.HTTP`): `HTTP_Error`, `Protocol_Error`.

## Usage

A GET, then a POST with a body:

```ada
with Ada.Text_IO;
with AHT.HTTP.Client;
with AHT.HTTP.Methods;
with AHT.HTTP.Request;
with AHT.HTTP.Response;
with AHT.URL;

procedure Example is
   C    : AHT.HTTP.Client.Client_Type;
   Resp : AHT.HTTP.Response.Response_Type;
begin
   Resp := C.Get ("https://example.com/");
   Ada.Text_IO.Put_Line (Resp.Status'Image & " " & Resp.Body_Text);

   declare
      Req : AHT.HTTP.Request.Request_Type;
   begin
      Req.Method := AHT.HTTP.Methods.POST;
      Req.Target := AHT.URL.Parse ("https://example.com/submit");
      Req.Headers.Set ("Content-Type", "application/json");
      Req.Set_Body ("{""hello"":""world""}");
      C.Send (Req, Resp);
      Ada.Text_IO.Put_Line
        (Resp.Status'Image & " " & Resp.Headers.Get ("Content-Type"));
   end;
end Example;
```

`Send` fills in `Host`, `User-Agent`, `Connection: close` and, for a
non-empty body, `Content-Length`. A non-2xx status is returned in
`Resp.Status`, not raised.

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
defined phrase. The subtype predicate catches out-of-range values at
runtime when contracts are enabled.

## `AHT.HTTP.Headers`

Case-insensitive multimap. Names are normalized to lowercase on
storage; lookup is case-insensitive.

`Type_Invariant => Invariant_Ok (Map.Entries)`: every stored name is
non-empty and lowercase. The invariant is checked after every public
call that may mutate the map.

- `Set (Self, Name, Value)`: `Pre => Name'Length > 0`. Removes any
  existing entries for `Name`, then stores the new one.
  `Post => Self.Contains (Name)`.
- `Append (Self, Name, Value)`: `Pre => Name'Length > 0`. Preserves
  existing entries. `Post => Self.Contains (Name)`. For repeatable
  headers, including `Set-Cookie`.
- `Remove (Self, Name)`: `Post => not Self.Contains (Name)`.
- `Contains (Self, Name) return Boolean`.
- `Get (Self, Name) return String`: first value, or `""`.
- `Values (Self, Name) return Value_List`: every value in insertion
  order. Values are not joined with `", "`, because `Set-Cookie`
  (RFC 6265 §3) is not comma-combinable.
- `Count (Self) return Natural`: total entries, not unique names.
- `Iterate (Self, Process)`: yields each stored entry; names arrive
  lowercase.

## `AHT.HTTP.Request`

```ada
type Request_Type is tagged record
   Method  : AHT.HTTP.Methods.Method_Type := AHT.HTTP.Methods.GET;
   Target  : AHT.URL.URL_Type;
   Headers : AHT.HTTP.Headers.Map;
   Body_B  : AHT.Bytes.Buffer;
end record;

procedure Set_Body (Self : in out Request_Type; Text : String);

procedure Write
  (Self : Request_Type;
   T    : in out AHT.Transport.Transport_Type'Class);
```

`Set_Body` replaces the body with the bytes of `Text`, one octet per
`Character` (no charset encoding); it is the inverse of
`Response.Body_Text`.

`Write` emits the HTTP/1.1 wire form: request line
(`METHOD SP request-target SP HTTP/1.1 CRLF`), stored headers in
insertion order, blank line, body. Header names are written in their
stored lowercase form (RFC 7230 §3.2; case is insensitive on the
wire).

If `Body_B` is non-empty and the caller did not set `Content-Length`,
`Write` synthesises one so the request is always framed. It does not
invent `Host`, `User-Agent`, `Connection` or `Authorization`; routing
and policy headers are the caller's (or the `Client`'s) job.

### Framing checks

`Write` and `Write_Streaming` reject the framing that RFC 7230 §3.3.3
identifies as a request-smuggling hazard, raising `Protocol_Error`
before any wire byte is written:

- A caller-supplied `Transfer-Encoding` is rejected. The buffered
  `Write` transcribes `Body_B` verbatim, so a chunked header over raw
  bytes would be malformed wire; `Write_Streaming` owns that header.
- A duplicate `Content-Length` is rejected. The header map allows
  repeated names, and intermediaries can disagree on which value
  wins.
- A single caller `Content-Length` must match the body. For the
  buffered `Write` it must equal `Body_B.Length`; a mismatch would
  truncate the upload or hang the peer.

### Streaming upload: `Write_Streaming`

```ada
type Body_Source is limited interface;
procedure Read_Chunk
  (Self : in out Body_Source;
   Buf  : out AHT.Bytes.Byte_Array;
   Last : out Natural) is abstract;

subtype Byte_Count is
  Interfaces.Integer_64 range 0 .. Interfaces.Integer_64'Last;
procedure Set_Content_Length (Self : in out Request_Type; N : Byte_Count);

procedure Write_Streaming
  (Self        : Request_Type;
   T           : in out AHT.Transport.Transport_Type'Class;
   Source      : in out Body_Source'Class;
   Abort_Check : access function return Boolean := null);
```

`Write_Streaming` pumps a request body from a pull-style `Source`
to the wire without buffering it, so a multi-GB upload runs in O(1)
memory. The caller derives a concrete type from `Body_Source` and
implements `Read_Chunk`, which fills the library-provided window
`Buf (Buf'First .. Last)` with the next bytes and signals
end-of-stream with `Last < Buf'First` (canonically `Last = 0`).
Upload state (a file handle, a generator cursor) lives in the derived
type; the source is passed by reference and the whole upload
completes before the call returns.

The head is built as by `Write` (same request line, same lowercase
headers, same framing checks). Body framing is header-driven:

- Fixed: a single `Content-Length` (set it with
  `Set_Content_Length`, whose 64-bit `Byte_Count` expresses multi-GB
  sizes) streams exactly N raw bytes. A source that signals EOF early
  (under-run) or hands over more than N (over-run) raises
  `Protocol_Error`; the stream stops at exactly N.
- Chunked: with no `Content-Length`, the encoder emits
  `Transfer-Encoding: chunked` and frames each window as
  `{hex-size}CRLF {bytes} CRLF`, closing with `0 CRLF CRLF`
  (lowercase hex, no leading zeros; RFC 7230 §4.1). An empty body is
  just the terminator.

`Abort_Check`, when non-null, is polled between windows; a `True`
result raises `AHT.Transport.Aborted_Error` mid-body. It is a
secondary fast exit; the bound on a stuck send is the transport's
write deadline and `Abort_Pending`. A `Timeout_Error` or
`Aborted_Error` can fire after some body bytes have reached the peer,
so a failed streaming upload is retry-unsafe for a non-idempotent
request.

### Ready-made body sources: `AHT.HTTP.Request.Sources`

`AHT.HTTP.Request.Sources` ships a `Stream_Source` over any Ada
stream (`Ada.Streams.Root_Stream_Type'Class`), which covers files
(via `Ada.Streams.Stream_IO.Stream`), sockets, in-memory streams and
generators:

```ada
type Stream_Source is new Body_Source with private;
function Create
  (Stream : not null access Ada.Streams.Root_Stream_Type'Class)
   return Stream_Source;
```

```ada
--  Stream a file to the wire with fixed framing.
F : Ada.Streams.Stream_IO.File_Type;
Ada.Streams.Stream_IO.Open (F, Ada.Streams.Stream_IO.In_File, Path);
declare
   Src : Request.Sources.Stream_Source :=
           Request.Sources.Create (Ada.Streams.Stream_IO.Stream (F));
begin
   Req.Set_Content_Length (Byte_Count (Ada.Directories.Size (Path)));
   Client.Send_Streaming_Body (C, Req, Resp, Src);
end;
Ada.Streams.Stream_IO.Close (F);
```

- `Stream_Source` borrows the stream: it holds an access to it, has
  no finalizer, and never opens or closes anything. The caller owns
  the stream's lifetime, which outlives the synchronous upload call.
- Framing stays header-driven. A generic stream has no length, so for
  fixed framing set the `Content-Length` yourself; omit it for
  chunked.
- In-memory bodies need no source: use `Set_Body`.

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

procedure Read_Streaming
  (Self   : out Response_Type;
   T      : in out AHT.Transport.Transport_Type'Class;
   Sink   : not null access procedure (Chunk : AHT.Bytes.Byte_Array);
   Method : AHT.HTTP.Methods.Method_Type := AHT.HTTP.Methods.GET);

function Body_Text (Self : Response_Type) return String;
```

`Read` parses a status line (`HTTP/1.x SP status SP [reason]`),
header lines until a blank line, then picks body framing:

0. `Method = HEAD`, or `Status` in 1xx / 204 / 205 / 304: no body.
   The message ends at the empty line; any `Content-Length` or
   `Transfer-Encoding` the peer sent is ignored (RFC 7230 §3.3.3, and
   RFC 9110 §15.3.6 for 205). This covers:
   - HEAD, where the peer usually advertises the GET-equivalent
     `Content-Length`. The codec cannot infer the request method, so
     the caller passes it.
   - 101 Switching Protocols, where the bytes after CRLFCRLF belong
     to the upgraded protocol (for example a WebSocket frame).
   - 204 / 205 / 304 on `Connection: close`, where the EOF fallback
     would otherwise block until the peer closes.
1. `Transfer-Encoding: chunked`: `AHT.HTTP.IO.Read_Chunked_Body`.
2. `Content-Length: N`: `Read_N` for exactly N bytes.
3. Otherwise: read until the peer closes.

Only `chunked` is understood; any other `Transfer-Encoding` (gzip,
compress, chunked+gzip) raises `Protocol_Error`. A `Status` outside
`100..599`, a missing colon on a header line, or a non-numeric
`Content-Length` also raise `Protocol_Error`. A status line with an
empty reason phrase (`HTTP/1.1 204 CRLF`) is legal and leaves
`Reason` empty.

`Read_Streaming` parses the status line and headers, applies the same
no-body suppression, and delivers the body to `Sink` as it is decoded
instead of accumulating it in `Body_B`, which stays empty. Delivery
granularity (a hint, not a contract):

- `Transfer-Encoding: chunked`: windows of up to 4 KiB. A wire chunk
  larger than the window is delivered as several calls, so chunk
  boundaries are not preserved; `Sink` is never called with an empty
  slice, and the zero-size terminator is consumed but not delivered.
- `Content-Length: N`: slices of up to 4 KiB, each fully populated
  before delivery (one call when N is at most 4 KiB).
- Neither header (`Connection: close`): one call per underlying
  transport `Read` until peer EOF.

Same `Protocol_Error` conditions as `Read`.

`Body_Text` returns the body one `Character` per byte (raw octets, no
charset decoding), for printing or comparing. It is empty when there
is no body: after a HEAD, or after a streaming read that drained the
body into a `Sink`.

## `AHT.HTTP.IO`

Transport-level helpers over `AHT.Transport.Transport_Type'Class`.
All five operations delegate to `Transport.Read` / `Transport.Write`
and track no deadlines of their own. Deadlines and cancel live on the
transport (`Set_Read_Deadline` / `Abort_Pending`). A read deadline is
a wall-clock budget measured from the `Set_` call, not refreshed per
`Read` (see `docs/transport.md`), so the byte-by-byte `Read_Line` and
the looped `Read_N` honour it for the whole logical operation. A peer
that dribbles one byte per (deadline / N) seconds trips
`Timeout_Error`.

- `Write_All (T, Data)`: the transport's `Write` is already
  all-or-raise, so this is a named entry point plus a `Log.Trace` on
  the `"http.io"` subsystem. An empty slice is a no-op.
- `Read_Line (T, Max_Length => 8_192) return String`: reads
  byte-by-byte until CRLF and returns the line without the CRLF.
  Byte-by-byte reading leaves the transport positioned exactly at the
  byte after CRLF, so the caller moves from line mode (status and
  headers) to body mode with no buffered-reader layer. Raises
  `Protocol_Error` on peer close before CRLF or when `Max_Length`
  bytes have been consumed without finding one.
- `Read_N (T, Data)`: fills every slot in `Data` by looping around
  `Transport.Read`. Raises `Protocol_Error` if the peer closes before
  `Data'Length` bytes have arrived. A zero-length slice is a no-op.
- `Read_Chunked_Body (T, Sink)`: streaming RFC 7230 §4.1 decoder.
  Each iteration reads a chunk-size line (hex digits,
  case-insensitive; a `chunk-ext` after `;` is ignored), reads the
  chunk data in bounded windows delivered to `Sink` as non-empty
  slices, then consumes the mandatory bare CRLF. Chunk boundaries are
  not preserved: a large wire chunk arrives as several windows, so
  the decoder's footprint is O(1) in the chunk size. The zero-size
  chunk terminates the body; the trailer section that follows is read
  and discarded (trailers are not surfaced) until a bare CRLF ends the
  message. Raises `Protocol_Error` on a non-hex size, a size past
  `Natural'Last`, or chunk data not followed by a bare CRLF.
- `Read_Chunked_Body (T) return Buffer`: buffered overload; wraps the
  streaming decoder with a sink that appends to one buffer.

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
function Seconds (S : Duration) return Phase_Bound
  with Pre => S >= 0.0;

procedure Send (Self, Req, Resp);
function  Get  (Self, URL) return Response_Type;
```

`CA_PEM` holds trust anchors as PEM data rather than a path, for
anchors compiled into the binary. Setting both it and `CA_Path`
raises `TLS_Error` on the next `https://` request, before anything is
dialled; there is no precedence rule, and the refusal stands under
`Insecure`. A plain `http://` request does not read either field.

### Behaviour

- Synchronous, one request per call. Each `Send` owns a fresh
  transport for the duration of the call, so multiple tasks can share
  one `Client_Type` without extra synchronization. `Connection:
  close` on every request; no keep-alive, no HTTP/2.

- Scheme dispatch on `Req.Target.Scheme`:
  - `http://`: `AHT.Transport.TCP`.
  - `https://`: `AHT.Transport.TLS`. Both TLS engines run over
    memory BIOs (OpenSSL) or in-memory queues (mbedTLS) that the Ada
    side feeds from the TCP transport; the engine never touches the
    socket. `Send` threads `CA_Path` / `CA_PEM` / `Insecure` into the
    handshake and then runs the same round trip polymorphically.
  - `ws://` / `wss://`: raises `HTTP_Error`; use
    `AHT.Websocket.Client`.

- Header merging. `Send` builds a working copy of `Req` and fills in
  headers only where not already present, so precedence is `Req` >
  `Default_Headers` > auto:
  1. Each entry of `Self.Default_Headers` whose name is absent from
     `Req.Headers` is appended (multi-valued defaults are added in
     full or not at all).
  2. `Host` from the URL (`host[:port]`, omitting the default port).
  3. `User-Agent` from `Self.User_Agent`.
  4. `Connection: close`.

- Interim 1xx loop. `Send` reads responses until the status is not
  1xx. `101 Switching Protocols` is the one terminal 1xx: it returns
  as-is with the post-header bytes still buffered on the transport
  for a WebSocket layer to consume. `100 Continue`, `103 Early Hints`
  and the rest are read and discarded.

- HEAD bodies. `Req.Method` is passed to `Response.Read`, so HEAD
  responses skip body framing even when the peer sends a
  `Content-Length`.

- Body framing is `Response.Read`'s: chunked, then `Content-Length`,
  then read-until-EOF.

- Errors. A non-2xx status is not an exception; `Resp.Status`
  carries it. Exceptions are for malformed wire or transport failure:
  `HTTP_Error`, `Protocol_Error`, `Transport_Error`, `Timeout_Error`,
  `Aborted_Error`, plus `AHT.Transport.TLS.TLS_Error` for `https://`
  (for example an untrusted or invalid certificate chain). The
  transport is closed on every exit path.

- Retry safety. A `Timeout_Error` or `Aborted_Error` can be raised
  with request bytes already on the wire, and the library cannot tell
  "never sent" from "partially sent". Such a failure is retry-unsafe
  for a non-idempotent request; the per-request transport is closed,
  so the partially written connection is never reused.

- `Get (URL)`: parses `URL`, builds a GET with no body, calls
  `Send`. Raises `AHT.URL.Parse_Error` on a malformed URL.

### Timeouts

A request walks five phases: DNS resolution, TCP connect, TLS
handshake (`https://` only), request write, response read. Each
phase has its own budget; there is no end-to-end deadline, so the
wall clock a request may occupy is a multiple of the budget, not
equal to it.

`Timeout_Seconds` is the coarse bound, applied to every phase whose
field is left at `Inherit`. `0` means no bound.

The five `Phase_Bound` fields override it per phase. Each is one of
`Inherit` (take `Timeout_Seconds`), `Unbounded` (no bound, whatever
`Timeout_Seconds` says) or `Seconds (S)`. `Seconds (0.0)` is a zero
budget that expires at once; spell "no bound" as `Unbounded`.

| Field | Bounds |
|---|---|
| `Resolve_Timeout` | the DNS lookup, through `AHT.DNS`. The bound is on the caller: on expiry `Timeout_Error` is raised and the lookup itself continues, since nothing can cancel it. A lookup that answers with no usable address is `Transport_Error`. Nothing to bound when the URL carries an IP literal. |
| `Connect_Timeout` | the TCP connect, as one total budget across every address DNS resolved to, not per candidate. Exhaustion before any candidate connects is `Timeout_Error`; every candidate refused is `Transport_Error`. |
| `Handshake_Deadline` | the TLS handshake alone, so only on `https://`; an `http://` request ignores it. Cleared once the handshake completes. |
| `Write_Deadline` | the request write, only on the streaming-upload path (`Send_Streaming_Body`). The buffered overloads arm no write deadline and ignore it. |
| `Read_Deadline` | the response read, armed once the request is fully on the wire, as one compound budget over status line, headers and body together. |

Exhaustion of any of them raises `Timeout_Error`. A `Cancel_Handle`
binds after connect, so cancel takes effect during the response read
and not during DNS, connect or handshake.

```ada
C.Timeout_Seconds    := 0;                --  no bound on the body
C.Connect_Timeout    := Client.Seconds (5.0);
C.Handshake_Deadline := Client.Seconds (5.0);
```

### Streaming download: `Send_Streaming`

```ada
procedure Send_Streaming
  (Self : in out Client_Type;
   Req  : Request_Type;
   Resp : out Response_Type;
   Sink : not null access procedure (Chunk : AHT.Bytes.Byte_Array));
procedure Send_Streaming
  (Self, Req, Resp, Sink, Cancel : ...);  -- + Cancel_Handle
```

Same semantics as `Send` for status line, headers, the 1xx loop, the
101 carve-out, HEAD suppression and scheme dispatch, but body bytes
go to `Sink` as they arrive instead of accumulating in
`Resp.Body_B`. After the call, `Resp.Status`, `Resp.Reason` and
`Resp.Headers` are populated; `Resp.Body_B` is empty. Header
merging, deadlines and cancel apply as for `Send`.

Delivery granularity is `Response.Read_Streaming`'s (see above):
windows of up to 4 KiB for chunked and `Content-Length` bodies, one
call per transport `Read` for `Connection: close` bodies. Treat it as
a hint, not a contract.

`Sink` may raise; the exception propagates out of `Send_Streaming`
and the transport is closed on that path. `Sink` must not invoke
`Send` recursively against the same `Client_Type` while the
transport is mid-call. `Sink` is not called for 1xx responses, and
not for 101 Switching Protocols (post-header bytes are left on the
wire for the WebSocket layer).

#### Download to an Ada stream

Two further `Send_Streaming` overloads write the response body to an
Ada stream, the download mirror of `Stream_Source`:

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
--  Download a body straight to a file.
F : Ada.Streams.Stream_IO.File_Type;
Ada.Streams.Stream_IO.Create (F, Ada.Streams.Stream_IO.Out_File, Path);
Client.Send_Streaming (C, Req, Resp, Target => Stream_IO.Stream (F));
Ada.Streams.Stream_IO.Close (F);
```

These resolve against the `Sink` overloads by the fourth parameter:
pass `Sink => ...` for the callback, `Target => ...` for the stream.
Behaviour is otherwise that of the `Sink` form, and a stream `Write`
that raises propagates out with the transport closed. `Target` is
borrowed: the caller owns its open/close lifetime, which outlives
the synchronous call.

### Streaming upload: `Send_Streaming_Body`

```ada
procedure Send_Streaming_Body
  (Self   : in out Client_Type;
   Req    : Request_Type;
   Resp   : out Response_Type;
   Source : in out Request.Body_Source'Class);
procedure Send_Streaming_Body
  (Self, Req, Resp, Source, Cancel : ...);  -- + Cancel_Handle
```

The upload mirror of `Send_Streaming`: the body is pulled from
`Source.Read_Chunk` and framed on the wire by
`Request.Write_Streaming` (see that section for `Body_Source`,
`Set_Content_Length` and the fixed-vs-chunked rules). The response is
buffered into `Resp.Body_B` as for `Send`; only the upload streams.
Header merging, scheme dispatch, the 1xx loop and HEAD suppression
are as for `Send`. Framing:

- a single `Content-Length` on `Req` (set with
  `Request.Set_Content_Length`): fixed framing of exactly that many
  bytes; an under- or over-run raises `Protocol_Error`;
- otherwise: `Transfer-Encoding: chunked`.

The call is synchronous; it runs the whole upload and reads the
response before returning, so `Source` need only outlive the call.
`Source.Read_Chunk` runs on the caller's task and must not block
indefinitely. This path arms a write deadline (`Write_Deadline`, or
`Timeout_Seconds` where that is `Inherit`) that bounds a stalled
transmit, a peer that stops reading, by re-parking the transport's
non-blocking write loop on its selector and raising `Timeout_Error`
at the deadline. It does not interrupt a `Read_Chunk` that is itself
blocked; a source that can stall must enforce its own timeout.

The cancellable overload takes a `Cancel_Handle` with the same
semantics as the other cancellable surfaces. Cancel during an upload
bites at two points: the in-flight write is broken via
`Abort_Pending`, and the pump polls the handle between source
windows, before each `Read_Chunk`. A `Read_Chunk` already in
progress is not interrupted.

Same retry-safety caveat as `Send`. Streaming upload is not offered
on the async surface; `Send_Async` stays buffered.

### Cancellation: `Cancel_Handle`

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

`Cancel` from any task aborts the `Send` running with this handle by
dispatching `Transport.Abort_Pending` on the transport it is using,
which unblocks a parked `Read`.

- Cancel during the request: `Send` raises
  `AHT.Transport.Aborted_Error` from inside the response read. The
  transport is closed on the abort path.
- Cancel before `Send`: the handle is armed; the next `Send` raises
  immediately, before dialing.
- Cancel after `Send` returns: a no-op, except that `Is_Cancelled`
  reports the call happened.
- Cancel between connect returning and the handle taking effect: the
  first `Read` raises. There is no window in which a cancel is lost.

Caveats:

- Single-use. Once `Cancel` has been called, every subsequent `Send`
  with this handle aborts immediately. Declare a fresh handle per
  cancellable operation.
- No connect cancellation. `Abort_Pending` is a read-side hook;
  `Cancel` cannot interrupt a connect in flight, and for `https://`
  that covers the TLS handshake too. A hung connect is bounded only
  by `Connect_Timeout` and `Handshake_Deadline` (or
  `Timeout_Seconds` where those are `Inherit`) and ends in
  `Timeout_Error`. A caller who sets `Timeout_Seconds` to 0 to allow
  an unbounded body should set those two explicitly, or nothing
  bounds the dial. A `Cancel` arriving during connect takes effect on
  the first `Read` once connect returns.
- One handle per concurrent `Send`. A handle shared across two
  concurrent `Send`s tracks whichever bound last; `Cancel` aborts
  only that one.

### Async: `Send_Async` / `Await`

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

`Send_Async` snapshots `Self` and `Req` into a worker task owned by
the handle, starts the request, and returns immediately. The worker
runs the same buffered round trip as `Send` (header merging, 1xx
loop, HEAD suppression, scheme dispatch), stores the response or the
exception in the handle, and terminates. `Await` blocks until the
worker is done and returns the response or re-raises the worker's
exception with its original identity. `Cancel` has the same
semantics as `Cancel_Handle.Cancel`.

- One `Send_Async` per handle. A second call on a started handle
  raises `HTTP_Error`. Declare a fresh handle per request.
- `Await` before `Send_Async` raises `HTTP_Error` rather than
  blocking on a request that was never started.
- `Await` is replayable. Subsequent calls on a done handle re-read
  the stored response (or re-raise the stored exception) without
  blocking.
- Snapshot at start. `Self` and `Req` are copied into the worker;
  mutating them in the caller after `Send_Async` has no effect on the
  in-flight request.
- Cancel before, during or after follows the `Cancel_Handle` rules:
  pre-cancel arms the next start; cancel during the request aborts
  the transport; cancel after `Await` only flips `Is_Cancelled`.
- Drop without `Await`. The worker terminates as soon as it has
  stored its result, so a handle going out of scope waits only for
  the request itself. A hung connect or read still blocks the scope
  exit; `Cancel` then `Await` to abandon a request without blocking
  on it.

Streaming async is not offered. For streaming plus async, spawn a
task that calls `Send_Streaming`.

## Implementation notes

The buffered, streaming, cancellable and async surfaces share one
internal core (`Run_Request`), which owns the transport for the call:
resolve, connect, bind the cancel state, run the wire round trip,
unbind, close. The buffered overloads supply a sink that appends to
`Resp.Body_B`. The write and read deadlines are armed inside the
round trip: the write deadline before the streaming upload, the read
deadline once the request is on the wire.

`Cancel_Handle` and `Async_Handle` both wrap a protected
`Cancel_State` holding the currently bound transport and a sticky
`Cancelled` flag. `Bind` re-checks the flag under the lock and fires
`Abort_Pending` on the freshly bound transport if a `Cancel` landed
between connect returning and the bind, which is what closes the
bind race. The async worker stores its result in the same protected
state and flips a done flag; `Await` waits on that barrier.
