# HTTP Stack

Packages under `AHT.HTTP`:

| Unit | Status |
|---|---|
| `AHT.HTTP` (root exceptions) | implemented |
| `AHT.HTTP.Methods` | implemented |
| `AHT.HTTP.Status` | implemented |
| `AHT.HTTP.Headers` | implemented |
| `AHT.HTTP.Request` | type defined (body serialization pending) |
| `AHT.HTTP.Response` | type defined (parsing pending) |
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

## `AHT.HTTP.Request` / `AHT.HTTP.Response` — types

Record types carrying `Method`/`Target`/`Headers`/`Body_B` and
`Status`/`Reason`/`Headers`/`Body_B`. Serialization and parsing of
those records belongs to `AHT.HTTP.IO` and `AHT.HTTP.Client`, not to
these packages.

## `AHT.HTTP.IO`

Transport-level helpers over `AHT.Transport.Transport_Type'Class`.
All four operations delegate to `Transport.Read` / `Transport.Write`;
the transport itself owns deadlines and cancel (`Set_Read_Deadline`
/ `Abort_Pending`), so a slow or cancelled HTTP call surfaces as
`Timeout_Error` / `Aborted_Error` through these helpers unchanged.

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
