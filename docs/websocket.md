# WebSocket

Packages under `AHT.Websocket`:

| Unit | Status |
|---|---|
| `AHT.Websocket` (shared types) | implemented |
| `AHT.Websocket.Frames` | stubbed |
| `AHT.Websocket.Client` | stubbed |

Common exception: `AHT.Websocket.Handshake_Error` — raised by
`Client.Connect` when the HTTP upgrade does not yield `101 Switching
Protocols` (e.g. `401`, `403`, `404`) or when the `Sec-WebSocket-Accept`
header is missing or wrong.

## `AHT.Websocket` — shared types

### Opcodes

```ada
type Opcode is
  (Continuation, Text, Binary,
   Reserved_3, Reserved_4, Reserved_5, Reserved_6, Reserved_7,
   Close, Ping, Pong,
   Reserved_B, Reserved_C, Reserved_D, Reserved_E, Reserved_F);
for Opcode use
  (Continuation => 16#0#, Text => 16#1#, Binary => 16#2#,
   Reserved_3 => 16#3#, Reserved_4 => 16#4#, Reserved_5 => 16#5#,
   Reserved_6 => 16#6#, Reserved_7 => 16#7#,
   Close => 16#8#, Ping => 16#9#, Pong => 16#A#,
   Reserved_B => 16#B#, Reserved_C => 16#C#, Reserved_D => 16#D#,
   Reserved_E => 16#E#, Reserved_F => 16#F#);
```

### Message kind (application view)

```ada
type Message_Kind is (Text_Message, Binary_Message);
```

Fragmented frames are reassembled by the receiver before reaching the
application, so the application never sees `Continuation`.

### Close codes — split subtypes

Received close frames may legitimately carry codes that **must not** be
sent. Rather than one permissive subtype, we split:

```ada
subtype Any_Close_Code is Natural
  with Dynamic_Predicate =>
         Any_Close_Code in 1000 .. 1015
      or else Any_Close_Code in 3000 .. 4999;

subtype Valid_Close_Code is Any_Close_Code
  with Dynamic_Predicate =>
            Valid_Close_Code /= 1005  -- "no status received"
    and then Valid_Close_Code /= 1006  -- "abnormal closure"
    and then Valid_Close_Code /= 1015; -- "TLS handshake failure"
```

`Client.Close` takes `Valid_Close_Code := 1000`; the compiler therefore
rejects `Client.Close (1006, ...)` at call sites that use a literal, and
the dynamic check catches variables at runtime.

### No-code close

A peer may legally send a Close frame with **zero payload bytes**
(RFC 6455 §5.5.1). To represent that distinctly from "code 1005
received", the close callback uses a discriminated record:

```ada
type Close_Info (Has_Code : Boolean := False) is record
   case Has_Code is
      when True  => Code : Any_Close_Code;
      when False => null;
   end case;
end record;
```

`Reason : String` is passed alongside — empty when no reason was sent.

## `AHT.Websocket.Frames`

Pure codec — no socket I/O, so unit-testable in isolation.

### Frame structure (RFC 6455 §5.2)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
```

### Operations

```ada
function Encode
  (Hdr     : Frame_Header;
   Payload : Byte_Array) return Byte_Array;
procedure Decode
  (Input   : Byte_Array;
   Hdr     : out Frame_Header;
   Payload : out Byte_Vector;
   Last    : out Natural);
```

The codec is **direction-neutral** on masking: `Encode` honours
`Hdr.Masked` / `Hdr.Mask_Key` as given, and `Decode` parses
whatever's on the wire (unmasking when MASK is set). The
"client MUST mask outgoing" rule (RFC §5.3) and the "client
MUST reject masked incoming" rule (RFC §5.1) live one layer
up in `AHT.Websocket.Client`, which sets `Hdr.Masked := True`
with a fresh `Random_Mask` on every send and treats a masked
inbound frame as a `Protocol_Error`. Keeping direction enforcement
out of the codec lets the round-trip tests build either side of
the wire without bouncing through a real peer.

`Decode` reports the index of the last consumed byte through
`Last`; `Last = 0` is the sentinel for "buffer holds a valid
prefix but is incomplete — feed me more bytes and call again".

### Protocol-level validation (direction-agnostic)

These checks live in the codec and raise
`AHT.Websocket.Protocol_Error` on violation:

- Reserved opcodes (RFC §5.2 reserved ranges 0x3..0x7 and
  0xB..0xF) are rejected on Decode.
- `RSV1`/`RSV2`/`RSV3` set without negotiated extension — v1
  negotiates none, so any RSV bit is an error.
- Control frame (`Close`/`Ping`/`Pong`) with `FIN = 0` or
  payload > 125 bytes (RFC §5.5). Enforced by both Encode (so
  callers can't accidentally emit a malformed control frame)
  and Decode.
- `Close` payload of exactly 1 byte — illegal per RFC §5.5.1.
  Allowed: 0 bytes (no code, no reason) or ≥ 2 bytes (2-byte
  status code + optional UTF-8 reason).
- `Close` code outside the valid wire range:
  - Encode requires `Valid_Close_Code` (1000..1015 ∪ 3000..4999
    excluding the synthetic 1005 / 1006 / 1015 that must never
    appear on the wire).
  - Decode requires `Any_Close_Code` (the full range including
    1005 / 1006 / 1015, since a peer might wrongly send them
    and we want the Client layer to see them rather than
    silently coerce).
- Non-minimal length encoding — 16-bit ext used for a value
  that fits in 7 bits, 64-bit ext used for a value that fits
  in 16 bits (RFC §5.2). Decode only; Encode picks the minimal
  encoding by construction.
- 64-bit ext length with the top bit set (RFC §5.2) or
  overflowing `Natural`.

A `Random_Mask : Byte_Array (1 .. 4)` helper backed by
`Ada.Numerics.Discrete_Random` is exposed on the Client layer
(not the codec — the codec is happy to take any caller-supplied
mask); the mask isn't cryptographic and the RFC doesn't require
it to be.

## `AHT.Websocket.Client` — to be implemented

### Shape

```ada
type Client_Type is tagged limited private;

procedure Connect
  (Self          : in out Client_Type;
   URL           : String;
   Extra_Headers : AHT.HTTP.Headers.Map := AHT.HTTP.Headers.Empty;
   CA_Path       : String := "";
   Insecure      : Boolean := False);

procedure Send_Text   (Self; Payload : String);
procedure Send_Binary (Self; Payload : Byte_Array);
procedure Send_Ping   (Self; Payload : Byte_Array := []);

procedure Receive
  (Self     : in out Client_Type;
   Msg      : out Message_Type;
   Timeout  : Duration := Duration'Last);

procedure Close
  (Self   : in out Client_Type;
   Code   : Valid_Close_Code := 1000;
   Reason : String := "");

function Is_Open (Self : Client_Type) return Boolean;
```

Callback registration (push-mode receive):

```ada
procedure On_Message (Self; Callback : On_Message_Callback);
procedure On_Close   (Self; Callback : On_Close_Callback);
procedure On_Error   (Self; Callback : On_Error_Callback);
```

Callbacks fire from the receiver task. Use `Receive` instead if the
caller prefers a pull model; both are supported simultaneously — every
inbound message is delivered to the callback (if set) and enqueued into
`Inbox` (if `Receive` is active).

### HTTP upgrade flow

`Connect` reuses `AHT.HTTP.*` for the wire:

1. `AHT.URL.Parse (URL)` — rewrite `ws` → `http`, `wss` → `https` for
   transport selection; preserve the WS scheme on `Client_Type` for
   status reporting.
2. Open a transport via the same scheme dispatch as `AHT.HTTP.Client`
   (TCP for `ws`, TLS for `wss`).
3. Build a `GET` request with the upgrade headers:
   - `Host: <authority>`
   - `Upgrade: websocket`
   - `Connection: Upgrade`
   - `Sec-WebSocket-Version: 13`
   - `Sec-WebSocket-Key: <base64 of 16 random bytes>`
   - plus `Extra_Headers` (e.g. `Authorization`, `Origin`,
     `Sec-WebSocket-Protocol`).
4. `AHT.HTTP.IO.Write_All` the request.
5. Read status line + headers via `AHT.HTTP.IO.Read_Line`.
6. Validate:
   - Status = `101 Switching Protocols`. Any other status raises
     `Handshake_Error` carrying the status and reason — callers
     distinguish `401`/`403` (auth) from `404` (no endpoint) from
     protocol mismatches.
   - `Upgrade: websocket` (case-insensitive token match).
   - `Connection: Upgrade` (case-insensitive token match — the header
     may list additional tokens).
   - `Sec-WebSocket-Accept` equals
     `base64(SHA1(Key & "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`.
7. Hand the open transport to the receiver task and `Send_Guard`; set
   `State := Open`.

### Concurrency model

Three protected objects and one task per connection.

#### `Receiver_Task`

Owns the read side of the transport. Loop:

1. `Frames.Decode` a frame from the transport.
2. If control frame: handle in place.
   - `Ping` → enqueue a `Pong` through `Send_Guard`.
   - `Pong` → drop (no-op; app doesn't see unsolicited pongs).
   - `Close` → send echoing close through `Send_Guard` (if we haven't
     yet), set `State := Closing` → `Closed`, fire `On_Close`, exit.
3. If data frame: buffer into a reassembly `Byte_Vector` until
   `FIN = 1`. On completion, fire `On_Message` (if set) **and** enqueue
   into `Inbox` (if someone is blocked in `Receive` or will be later).
4. On `Transport_Error` or malformed frame: fire `On_Error`, set
   `State := Closed`, exit.

Receiver termination is observed by `Client.Close` via the `State` PO —
`Close` blocks until `State = Closed`, guaranteeing no stray callbacks
after return.

#### `Send_Guard` (protected object)

Serializes writes. WebSocket clients MUST generate a fresh 32-bit mask
per frame (RFC 6455 §5.3), and a single frame's bytes must be written
contiguously. Interleaved writes from two tasks would corrupt the
stream. `Send_Guard.Write_Frame (Frame)` is the only path to the
transport's write side.

#### `Inbox` (protected object)

Bounded FIFO of `Message_Type`. Entry:

```ada
entry Receive (Msg : out Message_Type) when Count > 0;
```

`Receive (..., Timeout)` at the client level is a `select...then delay`
around that entry. Bound is configurable at `Connect` time; default is
modest (e.g. 64) so a slow consumer back-pressures by making the
receiver task block in `Inbox.Put` rather than accumulating unbounded
memory.

#### `State` (protected object)

```ada
type Connection_State is (Connecting, Open, Closing, Closed);
```

Close is **idempotent**: `Client.Close` on a `Closed` client is a
no-op. Transitions always go forward (`Connecting` → `Open` → `Closing`
→ `Closed`); going backwards is impossible. This is enforced by the
PO entries, which rendezvous on valid transitions only.

### Why this shape

- A dedicated receiver task is the natural fit for asynchronous frame
  arrival — pings, server-initiated close, and unsolicited data all
  arrive without application polling.
- Protected objects (instead of `Ada.Synchronous_Task_Control` or
  semaphores) give us the entry-barrier primitive for free, which is
  what `Inbox.Receive` and the `State` transitions want.
- Splitting `Send_Guard` from `State` keeps the write mutex out of the
  critical path of state queries like `Is_Open`.

## Tests — to be implemented

All against `tests/server/server.py` (plain WS on `:8765`) and
`server_tls.py` (WSS on `:8766`):

| Test | Scenario |
|---|---|
| `test_ws_echo` | 1 KiB text + 1 KiB binary echoed |
| `test_ws_fragmentation` | 1 MiB binary split into 64 KiB frames, reassembled, SHA-256 matches |
| `test_ws_close` | client-initiated and server-initiated close paths, both clean |
| `test_ws_tls` | echo over `wss://127.0.0.1:8766` |
| `test_ws_upgrade_headers` | custom `Authorization` passes `/require-auth`; missing header raises `Handshake_Error` with status 401 |

Frame codec also gets a pure unit test (`test_ws_frames`, not listed in
the plan yet) exercising encode/decode round trips for short, medium
(126), and extended (127) lengths plus control-frame validation.
