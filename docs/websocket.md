# WebSocket

Packages under `AHT.Websocket`:

- `AHT.Websocket` — shared types.
- `AHT.Websocket.Frames` — the frame codec.
- `AHT.Websocket.Client` — the client, `ws://` and `wss://`.

Common exception: `AHT.Websocket.Handshake_Error` — raised by
`Client.Connect` when the HTTP upgrade does not yield `101 Switching
Protocols` (e.g. `401`, `403`, `404`) or when the `Sec-WebSocket-Accept`
header is missing or wrong.

## `AHT.Websocket` — shared types

### Opcodes

```ada
type Opcode is
  (Continuation,  -- 0x0
   Text,          -- 0x1
   Binary,        -- 0x2
   Close_Op,      -- 0x8
   Ping_Op,       -- 0x9
   Pong_Op);      -- 0xA
```

Only the six opcodes RFC 6455 defines exist in the enumeration (with a
representation clause pinning the wire values); a frame carrying any
reserved opcode fails decoding with `Protocol_Error`.

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
            Valid_Close_Code /= 1004  -- reserved, no defined meaning
    and then Valid_Close_Code /= 1005  -- "no status received"
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
   Payload : out Buffer;
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
- `RSV1`/`RSV2`/`RSV3` set without negotiated extension — the client
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

## `AHT.Websocket.Client`

### Shape

```ada
type Client_Type is tagged limited private;

--  Full form — Extra_Headers plus optional subprotocols / origin.
procedure Connect
  (Self          : in out Client_Type;
   URL           : String;
   Extra_Headers : AHT.HTTP.Headers.Map;
   Subprotocols  : String := "";
   Origin        : String := "";
   Insecure      : Boolean := False;
   CA_Path       : String := "");

--  Convenience form — no extra headers.
procedure Connect
  (Self     : in out Client_Type;
   URL      : String;
   Insecure : Boolean := False;
   CA_Path  : String := "");

procedure Send_Text   (Self : in out Client_Type; Text : String)
  with Pre => Is_Open (Self);
procedure Send_Binary (Self : in out Client_Type; Data : Byte_Array)
  with Pre => Is_Open (Self);
procedure Send_Ping   (Self : in out Client_Type; Payload : Byte_Array := [])
  with Pre => Is_Open (Self);

procedure Receive
  (Self    : in out Client_Type;
   Msg     : out Message_Type;
   Timeout : Duration := Duration'Last);

procedure Close
  (Self    : in out Client_Type;
   Code    : Valid_Close_Code := 1000;
   Reason  : String := "";
   Timeout : Duration := 5.0);

function Is_Open (Self : Client_Type) return Boolean;
function Selected_Subprotocol (Self : Client_Type) return String;
```

`ws://` runs on the plain TCP transport, `wss://` on the TLS transport;
`Insecure` / `CA_Path` apply to `wss://` only (ignored for `ws://`). A
`Client_Type` is single-use — after `Close`, a second `Connect` raises
`Handshake_Error`. `Receive` blocks up to `Timeout` and raises
`AHT.Websocket.Closed_Error` once the connection has closed; `Close`
runs the §1.4 handshake bounded by `Timeout` (see the `.ads` for the
0.0 / `Duration'Last` knobs).

Callback registration (push-mode receive):

```ada
procedure Set_On_Message (Self : in out Client_Type; CB : On_Message_Callback);
procedure Set_On_Close   (Self : in out Client_Type; CB : On_Close_Callback);
procedure Set_On_Error   (Self : in out Client_Type; CB : On_Error_Callback);
```

Callbacks fire from the receiver task. Use `Receive` instead if the
caller prefers a pull model; both are supported simultaneously — every
inbound message is delivered to the callback (if set) and enqueued into
`Inbox` (so a later `Receive` still sees it). Callbacks must be
task-safe and non-blocking, and an exception raised inside one is
swallowed by the receiver so it can keep draining the wire.

### HTTP upgrade flow

`Connect` reuses `AHT.HTTP.*` for the wire:

1. `AHT.URL.Parse (URL)` yields a `ws` / `wss` scheme directly (no
   rewrite to `http` / `https`); the scheme drives transport selection.
   Non-`ws`/`wss` URLs are rejected upfront with `Handshake_Error`.
2. Dial one transport for the scheme — TCP for `ws://`, TLS for
   `wss://` (threading `Insecure` / `CA_Path` into the TLS handshake) —
   and point `Active` at it.
3. Build a `GET` request with the upgrade headers:
   - `Host: <authority>`
   - `Upgrade: websocket`
   - `Connection: Upgrade`
   - `Sec-WebSocket-Version: 13`
   - `Sec-WebSocket-Key: <base64 of 16 random bytes>`
   - `Sec-WebSocket-Protocol` / `Origin` when `Subprotocols` / `Origin`
     are supplied, plus any `Extra_Headers`. `Extra_Headers` entries
     named `Host`, `Upgrade`, `Connection`, `Sec-WebSocket-Version`, or
     `Sec-WebSocket-Key` are dropped so they can't override the
     generated values; other names (including `Origin` and
     `Sec-WebSocket-Protocol`) are appended as-is, so don't also pass
     those via `Extra_Headers` if you're using the dedicated parameters
     or you'll emit duplicate header lines.
4. `AHT.HTTP.Request.Write` the request over `Active`.
5. `AHT.HTTP.Response.Read` the status line + headers over `Active`.
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
   - At most one `Sec-WebSocket-Protocol`, and any value returned must
     be one the client offered; the accepted value is stored and
     reported by `Selected_Subprotocol`.
7. Hand the open transport to the receiver task; set `State := Open`.

A TLS dial failure (step 2) propagates `AHT.Transport.TLS.TLS_Error`
unwrapped; failures from step 4 onward are wrapped in `Handshake_Error`.

### Concurrency model

Three protected objects and one task per connection.

#### `Receiver_Task`

Owns the read side of the transport. Loop:

1. `Frames.Decode` a frame from the transport.
2. If control frame: handle in place.
   - `Ping` → enqueue a `Pong` through `Send_Guard`.
   - `Pong` → drop (no-op; app doesn't see unsolicited pongs).
   - `Close` → send echoing close through `Send_Guard` (if we haven't
     yet), fire `On_Close`, set `State := Closed` directly, exit.
3. If data frame: buffer into a reassembly `Buffer` until
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
stream. Senders bracket each write with `Acquire` / `Release` and draw
the per-frame mask from `Random_Mask` (under the lock so concurrent
senders can't share generator state). The socket write runs *between*
`Acquire` and `Release`, i.e. outside the protected object's own lock —
so a slow write doesn't block `Release` or `Random_Mask` or state
queries — but the `Acquire` mutex is still held across it, so other
senders serialize behind a slow write. Both the user's `Send_*` calls
and the receiver's Pong / Close echoes go through this guard.

#### `Inbox` (protected object)

FIFO of `Message_Type`. The receiver `Push`es completed messages; the
user's `Receive` pulls. Entry barrier:

```ada
entry Receive (Msg : out Message_Type) when Closed_F or else not Q.Is_Empty;
```

`Receive (..., Timeout)` at the client level is a `select ... or delay`
around that entry. The barrier opens both when a message is available
*and* when `Mark_Closed` has been called, so a `Receive` parked on an
empty queue wakes when the connection goes away and raises
`Closed_Error` instead of blocking forever.

#### `State` (protected object)

```ada
type State_Kind is (Connecting, Open, Closing, Closed);
```

Transitions only ever move forward toward `Closed`. The intermediate
`Closing` is visited only on the user-initiated `Close` path (which
sets `Closing` while it waits for the peer's echo); a peer-initiated
close handled in the receiver sets `Closed` directly, so `Open →
Closed` is observable without ever passing through `Closing`. `Close`
is effectively **idempotent**: on a still-`Connecting` client it's a
no-op, and on an already-`Closed` one it just makes sure the transport
is down. The PO also exposes `Wait_Closed` (an entry that
blocks until `Closed`, used by `Close` to wait for the receiver to
observe the peer's echo) and `Try_Mark_Local_Close`, which atomically
arbitrates whether the user-`Close` path or the receiver's echo path is
the one that emits our Close frame.

### Why this shape

- A dedicated receiver task is the natural fit for asynchronous frame
  arrival — pings, server-initiated close, and unsolicited data all
  arrive without application polling.
- Protected objects (instead of `Ada.Synchronous_Task_Control` or
  semaphores) give us the entry-barrier primitive for free, which is
  what `Inbox.Receive` and the `State` transitions want.
- Splitting `Send_Guard` from `State` keeps the write mutex out of the
  critical path of state queries like `Is_Open`.

## Tests

The WebSocket layer is covered by four test mains:

| Test | Scope | Fixture |
|---|---|---|
| `test_ws_frames` | pure codec — encode/decode round trips for 7/16/64-bit lengths, masking, and control-frame validation | none (in-process) |
| `test_ws_handshake` | the HTTP upgrade: base64 vectors, 101 / Upgrade / Connection / Accept validation, subprotocol checks, single-use lifecycle, `Close` timeout | `server_ws.py` (`ws://127.0.0.1:8765`) + an in-process fake-handshake server |
| `test_ws_echo` | plain-WS frame I/O: text / binary round-trips, `Receive` timeout, post-close `Closed_Error`, ordering, push callbacks | `server_ws.py` (`ws://127.0.0.1:8765`) |
| `test_ws_tls` | the `wss://` sibling: verify / insecure / untrusted, text + binary round-trips over TLS | `server_ws_tls.py` (`wss://127.0.0.1:8768`) |
