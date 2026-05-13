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
| `AHT.HTTP.IO` | implemented |
| `AHT.HTTP.Client` | stubbed |

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
  (Self : out Response_Type;
   T    : in out AHT.Transport.Transport_Type'Class);
```

`Read` parses a status line (`HTTP/1.x SP status SP [reason]`),
header lines until a blank line, then picks body framing:

0. `Status` in 1xx / 204 / 205 / 304 → no body. The message ends
   at the empty line; any `Content-Length` or `Transfer-Encoding`
   the peer sent is ignored per RFC 7230 §3.3.3 (and RFC 9110
   §15.3.6 for 205). This is load-bearing for **101 Switching
   Protocols** (bytes after CRLFCRLF belong to the upgraded
   protocol, e.g. a WebSocket frame — reading them as body would
   consume the first frame) and for 204/205/304 on
   `Connection: close` streams (otherwise the EOF fallback would
   block until the peer closes even though the message is already
   complete).
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

## `AHT.HTTP.Client` — to be implemented

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
  one `Client_Type` without extra synchronization.
- **Scheme dispatch**: `http://` → `AHT.Transport.TCP`; `https://` →
  `AHT.Transport.TLS` with `CA_Path` / `Insecure`.
- **Wire**: `Connection: close` in v1. No keep-alive, no HTTP/2.
- **Body**: reads via `Content-Length` *or* chunked transfer encoding.
- **Errors**: non-2xx status is **not** an exception — the `Response`
  carries the status. `HTTP_Error` / `Protocol_Error` are for
  malformed wire data or transport failures.
