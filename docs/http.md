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
| `AHT.HTTP.IO` | stubbed |
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

## `AHT.HTTP.IO` — to be implemented

Transport-level helpers over `AHT.Transport.Transport_Type'Class`:

- `Write_All` — loop around `Write` until the whole byte slice is
  sent.
- `Read_Line (T, Max_Length)` — reads a CRLF-terminated line; raises
  `Protocol_Error` if the terminator is not found within
  `Max_Length`. Used for the status line and each header line.
- `Read_N` — read exactly `Data'Length` bytes (for `Content-Length`
  bodies).
- `Read_Chunked_Body` — RFC 7230 §4.1 chunked-transfer decoder,
  returning the reassembled body as a `Byte_Vector`.

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
