<!--
SPDX-FileCopyrightText: 2026 Aldo Nicolas Bruno
SPDX-License-Identifier: Apache-2.0
-->

# WebSocket

Packages under `AHT.Websocket`:

- `AHT.Websocket`, shared types and exceptions.
- `AHT.Websocket.Frames`, the frame codec.
- `AHT.Websocket.Client`, the client, `ws://` and `wss://`.
- `AHT.Websocket.Send_Guards`, the per-connection write latch and its
  scope guard.
- `AHT.Websocket.Handoffs`, the record of a session changing hands
  between the connecting task and the receiver.
- `AHT.Websocket.UTF8`, text validation (RFC 6455 §8.1).
- `AHT.Websocket.Budgets`, the close-budget arithmetic.

`Send_Guards`, `Handoffs` and `Budgets` are separate units so that a
test can drive the production type directly rather than a replica of
it.

`AHT.Random` sits outside the WebSocket tree. It supplies
cryptographically secure bytes from the OS pool for masking keys and
the handshake nonce. Its one non-portable part, the system call
itself, is `AHT.Random.Source`, with a body per OS under `src/os`
(`/dev/urandom`, `RtlGenRandom`) selected by the `AHT_OS` scenario
variable. That unit builds and runs on Windows; the transports and
the test harness are POSIX-verified only.

Exceptions, all declared in `AHT.Websocket`:

| Exception | Means |
|---|---|
| `Handshake_Error` | the HTTP upgrade did not yield `101` (e.g. `401`, `403`, `404`), `Sec-WebSocket-Accept` was missing or wrong, or the call was refused in the client's current state |
| `Protocol_Error` | the peer put something malformed on the wire. The receiver fires `On_Error` and tears the connection down without sending a close frame (see *Failure codes*) |
| `Closed_Error` | there is no connection to act on, or the one being waited on went away |
| `Message_Too_Big` | the peer declared more than the configured ceiling allows. Not a protocol fault: nothing malformed happened. Closes with 1009 |
| `Mode_Error` | the operation is not available in this configuration: `Receive` under `Callback_Only`, connecting `Callback_Only` with no callback, clearing that callback while such a connection is live, or reconfiguring limits once a session exists |
| `Reentrant_Error` | an operation that waits for the receiver was called from the receiver, i.e. from inside a callback |

`AHT.Transport.Timeout_Error` and `AHT.Transport.Aborted_Error` also
surface here. `Timeout_Error` comes from six bounds: the four dial
bounds `Resolve_Timeout`, `Connect_Timeout`, `Handshake_Deadline` and
`Upgrade_Deadline` on `Connect` / `Reconnect`; `Receive`'s own
`Timeout`; and `Drain_Timeout` on `Close` / `Reconnect`. The close
handshake's `Timeout` is the one bound that expires without raising;
see *Bounds on a teardown*. `Aborted_Error` means I/O was cancelled by
a teardown.

`AHT.Random.Entropy_Error` is raised if the OS entropy source cannot
be read. There is no fallback to a weaker source.

## `AHT.Websocket`: shared types

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

Only the six opcodes RFC 6455 defines exist in the enumeration, with
a representation clause pinning the wire values. A frame carrying any
reserved opcode fails decoding with `Protocol_Error`.

### Message kind

```ada
type Message_Kind is (Text_Message, Binary_Message);
```

Fragmented frames are reassembled by the receiver before reaching the
application, so the application never sees `Continuation`.

### Close codes

Received close frames may legitimately carry codes that must not be
sent, so there are two subtypes:

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

`Client.Close` takes `Valid_Close_Code := 1000`. Both subtypes use
`Dynamic_Predicate`, so the check is at run time: `Client.Close
(1006, ...)` raises rather than failing to compile, though GNAT warns
on a literal it can see through.

### No-code close

A peer may legally send a Close frame with zero payload bytes
(RFC 6455 §5.5.1). The close callback distinguishes that from "code
1005 received" with a discriminated record:

```ada
type Close_Info (Has_Code : Boolean := False) is record
   case Has_Code is
      when True  => Code : Any_Close_Code;
      when False => null;
   end case;
end record;
```

`Reason : String` is passed alongside, empty when no reason was sent.

## `AHT.Websocket.Frames`

A pure codec with no socket I/O, unit-testable in isolation.

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

type Fragment_State is (Unchecked, No_Message, In_Message);

procedure Decode
  (Input     : Byte_Array;
   Hdr       : out Frame_Header;
   Payload   : out Buffer;
   Last      : out Natural;
   Allowance : Natural        := Natural'Last;
   Fragment  : Fragment_State := Unchecked);
```

`Allowance` is the size ceiling, checked at header-parse time.
`Decode` reports "incomplete" until the whole declared payload is
buffered, so a limit applied to a returned frame would first have to
accumulate the bytes it exists to refuse; a peer that declares a
gigabyte and then sends nothing would never be answered. Checking the
length field rejects it after ten bytes (four for the 16-bit form).
Exceeding the allowance raises `AHT.Websocket.Message_Too_Big`, which
is distinct from `Protocol_Error` because nothing malformed happened.
The client closes with 1009 on this path. For a fragmented message
the receiver passes the allowance remaining for the whole message, so
the ceiling bounds the message rather than each frame.

`Fragment` lets `Decode` apply the §5.4 opcode sequencing rules at
header-parse time: a `Continuation` under `No_Message`, or a `Text` /
`Binary` under `In_Message`, is a `Protocol_Error`. Control frames
interleave legally and are exempt. `Unchecked` is the default because
`Decode`'s contract is to handle any single frame in isolation, and
callers holding no message state (the codec tests among them) decode
a standalone `Continuation` and expect it to work. A receiver that
tracks the sequence passes the real state. Sequencing is checked
before size, so a frame that is both out of order and oversized
reports the protocol fault.

The codec is direction-neutral on masking: `Encode` honours
`Hdr.Masked` / `Hdr.Mask_Key` as given, and `Decode` parses whatever
is on the wire, unmasking when MASK is set. The "client MUST mask
outgoing" rule (§5.3) and the "client MUST reject masked incoming"
rule (§5.1) live in `AHT.Websocket.Client`, which sets `Hdr.Masked :=
True` with a fresh random mask on every send and treats a masked
inbound frame as a `Protocol_Error`. Keeping direction enforcement
out of the codec lets the round-trip tests build either side of the
wire without a real peer.

`Decode` reports the index of the last consumed byte through `Last`;
`Last = 0` means the buffer holds a valid but incomplete prefix and
more bytes are needed. Both are normal returns. When `Decode` raises,
none of the out parameters is meaningful; callers distinguish
"incomplete" from "rejected" by the exception, never by inspecting
`Last`.

### Protocol-level validation

These checks live in the codec and raise
`AHT.Websocket.Protocol_Error`:

- Reserved opcodes (0x3..0x7 and 0xB..0xF) on Decode.
- `RSV1`/`RSV2`/`RSV3` set. The client negotiates no extension, so
  any RSV bit is an error.
- Control frame (`Close`/`Ping`/`Pong`) with `FIN = 0` or payload
  > 125 bytes (§5.5). Enforced by both Encode and Decode, so a caller
  cannot emit a malformed control frame.
- `Close` payload of exactly 1 byte (§5.5.1). Allowed: 0 bytes, or
  2 or more (status code plus optional UTF-8 reason).
- `Close` code outside the valid wire range. Encode requires
  `Valid_Close_Code`; Decode requires `Any_Close_Code`, the full range
  including 1005 / 1006 / 1015, so that a peer sending one of those
  reaches the client layer rather than being silently coerced.
- Non-minimal length encoding: 16-bit extended length for a value
  that fits in 7 bits, 64-bit for one that fits in 16 (§5.2). Decode
  only; Encode picks the minimal encoding by construction.
- 64-bit extended length with the top bit set (§5.2) or overflowing
  `Natural`.

The codec also exposes `Frame_Header`, and `Classify_Inbound_Close` /
`Inbound_Close_Status` for interpreting a received Close payload:
`Reserved_Code` (1004, 1005, 1006 or 1015; the client answers 1002),
`Bad_Reason` (the reason text is not valid UTF-8; the client answers
1007, per §8.1) or `Accept_Close`.

Masking keys are not generated here; the codec takes any
caller-supplied mask. The client draws them from `AHT.Random`, which
reads the OS entropy pool. RFC §5.3 requires the key to come from a
strong source of entropy and requires one frame's key not to make the
next one guessable. Masking exists so that a client cannot be coerced
into putting bytes on the wire that an intermediary would parse as a
second, attacker-chosen HTTP request; a predictable mask removes that
defence. `Sec-WebSocket-Key` has the matching requirement in §4.1, a
nonce selected randomly per connection.

## `AHT.Websocket.Client`

### Shape

```ada
type Client_Type is tagged limited private;

--  Full form: Extra_Headers plus optional subprotocols / origin.
procedure Connect
  (Self               : in out Client_Type;
   URL                : String;
   Extra_Headers      : AHT.HTTP.Headers.Map;
   Subprotocols       : String := "";
   Origin             : String := "";
   Insecure           : Boolean := False;
   CA_Path            : String := "";
   CA_PEM             : String := "";
   Connect_Timeout    : Duration := Duration'Last;
   Handshake_Deadline : Duration := Duration'Last;
   Upgrade_Deadline   : Duration := Duration'Last;
   Resolve_Timeout    : Duration := Duration'Last);

--  Convenience form: no extra headers.
procedure Connect
  (Self               : in out Client_Type;
   URL                : String;
   Insecure           : Boolean := False;
   CA_Path            : String := "";
   CA_PEM             : String := "";
   Connect_Timeout    : Duration := Duration'Last;
   Handshake_Deadline : Duration := Duration'Last;
   Upgrade_Deadline   : Duration := Duration'Last;
   Resolve_Timeout    : Duration := Duration'Last);

procedure Reconnect
  (Self               : in out Client_Type;
   Timeout            : Duration := 5.0;
   Drain_Timeout      : Duration := Default_Drain_Timeout;
   Connect_Timeout    : Duration := Duration'Last;
   Handshake_Deadline : Duration := Duration'Last;
   Upgrade_Deadline   : Duration := Duration'Last;
   Resolve_Timeout    : Duration := Duration'Last);

procedure Send_Text   (Self : in out Client_Type; Text : String);
procedure Send_Binary (Self : in out Client_Type; Data : Byte_Array);
procedure Send_Ping   (Self : in out Client_Type; Payload : Byte_Array := []);

procedure Receive
  (Self    : in out Client_Type;
   Msg     : out Message_Type;
   Timeout : Duration := Duration'Last);

procedure Close
  (Self          : in out Client_Type;
   Code          : Valid_Close_Code := 1000;
   Reason        : String := "";
   Timeout       : Duration := 5.0;
   Drain_Timeout : Duration := Default_Drain_Timeout);

procedure Configure (Self : in out Client_Type; L : Limits);

function Is_Open              (Self : Client_Type) return Boolean;
function Selected_Subprotocol (Self : Client_Type) return String;
function Generation           (Self : Client_Type) return Natural;
```

`ws://` runs on the plain TCP transport, `wss://` on the TLS
transport. `Insecure`, `CA_Path` and `CA_PEM` configure the TLS
handshake and are not used on a `ws://` dial, but they are still
checked: supplying both `CA_Path` and `CA_PEM` is rejected on either
scheme.

`CA_PEM` is the same trust material as `CA_Path`, held in memory
rather than on disk: one or more concatenated PEM certificates, for
anchors compiled into the binary. Two rules:

- Supplying both raises, before anything is dialled and before
  admission reserves a generation. There is no precedence, and the
  refusal stands under `Insecure`: a caller who passed two sets of
  anchors is wrong about which is in force, and honouring one
  silently would leave that belief intact. On a `ws://` dial the
  client's own check is the only one, since no TLS transport is
  built.
- Parsing is all-or-nothing. A bundle whose tail is truncated or
  corrupt is rejected whole rather than installing the certificates
  that parsed before the damage.

`CA_PEM` is deep-copied into the saved parameters like every other
argument, so `Reconnect` replays it without the caller keeping the
PEM alive.

The `Send_*` operations carry no `Is_Open` precondition. The receiver
task can tear a connection down concurrently (the peer may close
between the application pulling a message and echoing it), so no
caller can guarantee such a precondition across the call. The check
is a runtime guard raising a catchable `Closed_Error`, expressed as a
borrow: a sender that cannot borrow the current session raises rather
than touching one it does not hold.

### Lifecycle: a client outlives its connections

A `Client_Type` is reusable. Each connection is a heap-allocated
`Session_Type` owned for the length of one generation, and the client
is a durable handle that outlives them.

There are two state machines:

```ada
--  Per CONNECTION (RFC 6455 §1.4), inside a session.
type State_Kind is (Connecting, Open, Closing, Closed);

--  Per CLIENT, spanning connections.
type Client_State is (Idle, Connecting, Open, Closing, Disconnected);
```

`Idle` means no connection has ever been successfully published; a
failed first attempt returns the client to `Idle`. `Disconnected`
means a generation was established and has since been fully
reclaimed. Both are dialable.

| Call | `Idle` | `Disconnected` | `Connecting` | `Open` / `Closing` |
|---|---|---|---|---|
| `Connect` | admitted | admitted | `Handshake_Error` | `Handshake_Error` |
| `Reconnect` | `Handshake_Error` | redials saved params | `Handshake_Error` | drains, then redials |
| `Configure` | accepted | accepted | `Mode_Error` | `Mode_Error` |

`Idle` and `Disconnected` differ for exactly one call. `Reconnect`
repeats the last connect that succeeded, and parameters are saved
only on publication, so from `Idle` there is nothing to repeat and it
raises `Handshake_Error`. A failed attempt in between does not become
the thing that gets repeated.

`Connect` never displaces a live connection. `Reconnect` does, and
explicitly.

`Generation` counts connections that were successfully established:
0 before the first, one more on each. Reserved numbers are not
counted, so a failed attempt does not advance it, and the value
answers "am I still looking at the connection I was?" across a
reconnect.

`Selected_Subprotocol` belongs to the connection, not to the client.
It stops answering once that connection is reclaimed rather than
lingering until a later one overwrites it.

### Delivery modes and limits

```ada
type Delivery_Mode is (Pull_Only, Callback_Only, Both);

type Limits is record
   Max_Message_Bytes  : Natural := 32 * 1024 * 1024;
   Max_Inbox_Messages : Count_Type := 1_024;
   Max_Inbox_Bytes    : Natural := 64 * 1024 * 1024;
   Delivery           : Delivery_Mode := Both;
end record;
```

`Callback_Only` does not enqueue at all, and is the only mode that
removes the inbox as a growth path. It therefore requires an
`On_Message` callback: with none there is no consumer, and `Connect`
raises `Mode_Error` rather than dropping every message. Under `Both`,
a message the inbox refuses is not passed to the callback either, so
pull and push consumers observe the same accepted set.

`Configure` is legal only while fully disconnected. Every limit
becomes an immutable property of a session at the moment it is
allocated, so a running connection cannot have its ceilings moved
underneath it and the receiver never re-reads a limit.

### Failure codes

- Exceeding `Max_Message_Bytes`, in one frame or accumulated across a
  fragment sequence, closes with 1009 Message Too Big, fires
  `On_Error`, and tears down through normal reclamation.
- Overrunning an inbox bound closes with 1008 Policy Violation. The
  peer is outrunning the application, not misbehaving; dropping
  silently would corrupt stream semantics the caller cannot detect.
- Invalid UTF-8, in a text message or in a Close reason, closes with
  1007 Invalid Payload Data (§8.1).
- A peer close carrying a reserved code is answered with 1002
  Protocol Error.

A `Protocol_Error` from the codec (a malformed frame) is handled
differently from all of these: the receiver fires `On_Error` and
tears the connection down without sending a close frame. The
connection is already unusable, and a peer that produced a malformed
frame cannot be relied on to read a reply. So a 1002 this client
generates means "your close code was reserved", not "you sent
something malformed". A caller may still pass `Close (Code => 1002)`
explicitly.

The defaults are policy, not minimums. 32 MiB covers the Autobahn §9
cases (up to 16 MiB), exceeds the 13 MB the echo test needs, and
matches what `server_ws.py` accepts. They are also a compatibility
surface: under a lower `Max_Message_Bytes`, a message the previous
ceiling accepted becomes a 1009 close, and a default below 16 MiB
fails the Autobahn §9 cases. See `tests/autobahn/BASELINE.md`.

### Callbacks

```ada
procedure Set_On_Message (Self : in out Client_Type; CB : On_Message_Callback);
procedure Set_On_Close   (Self : in out Client_Type; CB : On_Close_Callback);
procedure Set_On_Error   (Self : in out Client_Type; CB : On_Error_Callback);
```

Callbacks live in the client, not in a connection, so one
installation serves every generation, and they are read afresh for
each event rather than captured once.

Callbacks must not block. They run on the receiver task, and the
receiver cannot reclaim a connection while it is inside user code. A
callback that never returns stalls `Close`, which is bounded, so the
caller gets `Timeout_Error` and the teardown continues in the
background. An exception raised inside a callback is swallowed so the
receiver can keep draining the wire.

`Close`, `Reconnect` and `Receive` raise `Reentrant_Error` when
called from inside a callback. Each would otherwise wait on the task
making the call: the first two for a teardown only the receiver can
complete, the third for a message only the receiver can deliver.
`Send_*` stay legal; they wait for nothing the receiver owes them, so
echoing from `On_Message` works.

A teardown the caller asked for is not reported as an error. `Close`
and `Reconnect` stop a parked receiver by aborting its transport I/O,
so the receiver sees `Aborted_Error` on the way out; that is not
passed to `On_Error`. A peer-driven abort still reaches the callback.

### Bounds on a teardown

```ada
Default_Drain_Timeout : constant Duration := 5.0;
```

`Close` and `Reconnect` bound the teardown with two clocks, which
measure different things; only one of them can raise. `Reconnect`
carries four more, which belong to the dial that follows (see *Bounds
on a dial*).

`Timeout` is a compound budget for getting our Close frame out and
hearing the answer. It covers acquiring the send guard, writing the
Close frame, and waiting for the peer's echo. Bounding only the wait
for the peer would leave the first two unbounded, which is the hole a
peer that stops reading walks through. When it expires the teardown
calls `Abort_Pending` and carries on; it does not raise. Running out
of patience with a peer is a normal outcome, not an error.

`Drain_Timeout` bounds how long to wait for our own receiver to
finish reclaiming the session afterwards. This is the one that raises
`Timeout_Error`.

One exception to the compound budget: `Timeout => 0.0` still grants
the Close-frame write a fixed 0.25 s grace
(`Budgets.Close_Frame_Grace`), because a transport handed a zero
deadline reads it as "fail rather than park", and a literal zero
would mean no goodbye was ever attempted. Every positive budget gets
what is left of itself and no more.

A single knob would make `Timeout => 0.0` mean "and fail if
reclamation is not already finished", which is not what a caller
asking for it wants.

Nothing is abandoned on expiry. The client stays `Closing`,
reclamation continues in the background, and a later call joins the
same completion rather than starting a second one. A `Reconnect` that
cannot finish the drain does not redial; dialing over a session a
teardown still owns is never done.

The usual cause of a drain timeout is a callback that has not
returned, which no receiver-side mechanism can detect:
`Abort_Pending` cancels transport I/O, not user code.

`Receive` has its own unrelated `Timeout`, which raises
`Timeout_Error`; it bounds a wait for a message, not a teardown.

The caller's bound is a liveness knob, not a safety one. Setting it
too low produces spurious `Timeout_Error`s and nothing worse:
teardown continues, nothing is freed early, and a later call joins
the same completion. The safety property lives in
`Wait_No_Borrowers`, which no caller can shorten.

### Bounds on a dial

A dial has four stages that can block, and one knob each.
`Resolve_Timeout` bounds the DNS lookup; `Connect_Timeout` bounds the
TCP connect as a single total budget across every address the lookup
returned; `Handshake_Deadline` bounds the TLS handshake, and does
nothing on `ws://`; `Upgrade_Deadline` bounds the HTTP exchange that
follows. All four default to `Duration'Last`. A caller who sets all
four is bounded end to end.

They are four knobs rather than one because they are four different
waits with different plausible budgets: a caller happy to sit through
a slow handshake on a congested link may still refuse to wait on a
peer that has stopped answering. The two middle ones are implemented
by the transports (`AHT.Transport.TCP.Connect`,
`AHT.Transport.TLS.Connect`); the client forwards them.

`Upgrade_Deadline` is armed on both directions before the request
goes out. A peer that completes the connect and then stops draining
blocks the `Request.Write` exactly as a peer that never answers
blocks the `Response.Read`, and a read deadline would bound only the
second.

It is disarmed before the session is published. `Set_Read_Deadline`
and `Set_Write_Deadline` are compound budgets measured from the
setter call, so a deadline left armed would expire under the receiver
partway through a healthy session and surface as a `Timeout_Error` on
a connection that was never in trouble. The disarm sits after the
response has been validated; validation is all header inspection and
touches the transport nowhere, so the budget covers every byte of the
exchange and nothing after it. `test_ws_connect_bounds` connects with
a one-second upgrade budget, idles past it, and requires a full round
trip afterwards.

Expiry raises `Timeout_Error`, not `Handshake_Error`, for all four,
including the upgrade, whose failure originates inside the block that
otherwise wraps everything in `Handshake_Error`. `Handshake_Error`
means the peer answered and the answer was wrong; `Timeout_Error`
means it did not answer in time; a caller deciding whether to retry
should not have to parse a message to tell them apart. A timed-out
attempt releases its admission and closes its half-built session like
any other failure, so the retry is legal.

`Resolve_Timeout` bounds the caller, not the lookup. `getaddrinfo`
takes no deadline and cannot be cancelled on either platform, so a
resolve that expires has stopped waiting; the lookup carries on in
the worker that `AHT.DNS` abandoned, until the platform resolver
gives up by itself.

The name is resolved inside the library rather than by the
application, so `Host` stays the name all the way through and SNI and
certificate verification are unaffected. An application resolving on
its own and putting the literal in the URL would send no SNI and be
verified against IP SANs, which typical certificates do not carry. A
URL that already carries a literal skips the resolver entirely, and
`Resolve_Timeout` has nothing to bound.

On Windows a task parked in `Connect` cannot be aborted at all (see
*The guarantee is narrower on Windows*), so "dial on a task and
abandon it" is not available there and these bounds are the only way
to bound a dial.

### HTTP upgrade flow

`Connect` reuses `AHT.HTTP.*` for the wire:

1. `AHT.URL.Parse (URL)` yields a `ws` / `wss` scheme directly (no
   rewrite to `http` / `https`); the scheme drives transport
   selection. This runs in the declarative part, before admission, so
   a scheme the URL parser does not know at all (`ftp://`) raises
   `AHT.URL.Parse_Error`, not `Handshake_Error`. A parseable but
   wrong scheme (`http://`, `https://`) is rejected with
   `Handshake_Error`, after admission has reserved a generation, so
   the attempt owner releases it.
2. Build a `GET` request with the upgrade headers:
   - `Host: <authority>`
   - `Upgrade: websocket`
   - `Connection: Upgrade`
   - `Sec-WebSocket-Version: 13`
   - `Sec-WebSocket-Key: <base64 of 16 random bytes>`
   - `Sec-WebSocket-Protocol` / `Origin` when `Subprotocols` /
     `Origin` are supplied, plus any `Extra_Headers`. `Extra_Headers`
     entries named `Host`, `Upgrade`, `Connection`,
     `Sec-WebSocket-Version` or `Sec-WebSocket-Key` are dropped so
     they cannot override the generated values; other names,
     including `Origin` and `Sec-WebSocket-Protocol`, are appended
     as-is. Passing those two both ways emits duplicate header lines.
3. Dial one transport for the scheme, TCP for `ws://` and TLS for
   `wss://`, threading `Insecure` / `CA_Path` / `CA_PEM` into the TLS
   handshake and `Resolve_Timeout` / `Connect_Timeout` /
   `Handshake_Deadline` into the waits. The name is resolved here,
   through `AHT.DNS`, and stays the name for SNI and verification.
   The request is built before the dial, not after.
4. Arm `Upgrade_Deadline` on both directions, then
   `AHT.HTTP.Request.Write` the request over the new transport.
5. `AHT.HTTP.Response.Read` the status line and headers.
6. Validate:
   - Status is `101 Switching Protocols`. Any other status raises
     `Handshake_Error` carrying the status and reason, so callers can
     distinguish `401`/`403` (auth) from `404` (no endpoint) from
     protocol mismatches.
   - `Upgrade: websocket`, a case-insensitive equality rather than a
     token match, so `Upgrade: websocket, foo` is rejected.
   - `Connection: Upgrade`, a case-insensitive token match; the
     header may list additional tokens.
   - `Sec-WebSocket-Accept` equals
     `base64(SHA1(Key & "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`.
   - At most one `Sec-WebSocket-Protocol`, and any value returned
     must be one the client offered.
7. Disarm `Upgrade_Deadline`, then publish the session to the
   persistent receiver and advance the generation.

A TLS dial failure (step 3) propagates `AHT.Transport.TLS.TLS_Error`
unwrapped; failures from step 4 onward are wrapped in
`Handshake_Error`, with one exception. A `Timeout_Error` from steps 4
or 5 is the upgrade budget expiring, and it propagates unwrapped so
it reads the same as the bounds that fire in step 3. Nothing else in
that stretch arms a deadline and the transport is fresh, so the
exception can only be that.

A failed attempt is retryable because the session is per-generation:
the retry builds fresh transports rather than re-dialing one whose
single-use latch is already set.

## Ownership

The hard part of a reusable client is answering "who frees this
session, and when" such that the answer survives an exception or an
abort at any point.

### Sessions are borrowed, never referenced

`Send_*` and `Receive` do not hold a session pointer. They borrow one
from the lifecycle controller for the duration of the call, and a
borrow is refused once teardown has begun. Reclamation waits for the
borrow count to reach zero before freeing anything:

```
1. Stop admission          no new borrows
2. Wake parked borrowers   state Closed, inbox Mark_Closed
3. Abort pending I/O       release anyone parked in Read/Write
4. Wait_No_Borrowers       unbounded
5. Close the transport
6. Drop the published pointer
7. Free the session
8. Signal_Generation_Done  release the waiters, client -> Disconnected
```

Step 4 is the memory-safety gate and has no timeout. A bound there
would mean freeing a session while a task might still be inside it.

The caller's `Drain_Timeout` does not shorten step 4; receiver-side
reclamation stays unbounded end to end. It bounds the caller's
external wait on step 8: a caller that gives up stops waiting, while
the reclamation it was waiting for carries on and completes on its
own. That is what lets a later `Close` or `Reconnect` join the same
completion instead of starting a second teardown.

Waking parked borrowers (step 2) is done twice, by the receiver's own
reclamation and again by the caller's teardown pin. The wake is
idempotent, and a borrower nobody wakes is a drain that never
completes.

### Abort safety is structural

Four GNAT behaviours each rule out an approach that looks correct:

- An `in out` entry parameter's copy-back is not delivered when the
  caller is aborted during the rendezvous. So an ownership transfer
  cannot be recorded by having the accepting task clear the caller's
  pointer; it is recorded in a protected action, which is
  abort-deferred.
- A blocking entry call made from a controlled `Initialize` is
  unabortable, because `Initialize` is abort-deferred, while the same
  call made directly can be cancelled by an asynchronous select. So a
  scope guard may release in `Finalize`, but must not acquire in
  `Initialize`.
- A pending abort takes effect at the end of a protected action,
  before whatever statement follows it. So a guard cannot record "I
  hold this" in its own state after the acquiring call returns; the
  acquiring protected action records the owner itself.
- A heap object is attached to its access type's collection before
  it is initialized, from inside the runtime's global task lock, and
  releasing that lock is an abort completion point
  (`Allocate_Any_Controlled`, steps 2 to 4 of `s-stposu.adb`). An
  abort landing anywhere inside a `new` is delivered with the object
  attached, wholly uninitialized, and unreachable: `new` never
  returned, so no pointer to it exists and no `Free` can be aimed at
  it. Library finalization then finalizes it as though it were real.
  So a session is allocated inside a protected action, which is
  abort-deferred, and the same action hands the pointer to the
  attempt owner.

  This is a property of `new`, not of sessions: the TLS transport's
  two allocation sites have the same window and are closed the same
  way, generically, in `AHT.Guarded_New` (see docs/tls.md).

The third rule shapes two places. `Send_Guard.Acquire` takes the
owner's identity in and records it inside the same action that takes
the latch, so a cancelled acquisition records nothing and its release
is a no-op. Admission works the same way: the `Attempt_Owner` exists
before `Begin_Connect` is called, and `Begin_Connect` records the
generation into it from inside the protected action. An owner created
after admission returned would leave an instant in which the client
was `Connecting` and nothing was responsible for taking it back out;
an abort landing there would strand the client permanently, refusing
every later `Connect`.

Ownership is carried by controlled types, so cleanup runs on every
exit path including an abort: `Attempt_Owner` for an in-flight
connect, `Teardown_Pin` for whoever wins a teardown.

Building a session is one protected action.
`Lifecycle_Controller.Create_Session` allocates the session and
stores the pointer into the attempt owner inside a single action, so
the fourth rule has no window: either nothing was allocated, or the
owner holds a complete session and is already the thing that frees
it. The destination goes in as an `access Session_Access`, as
`Begin_Connect` takes `Owner_Gen`, because an `out` parameter's
copy-back happens after the action has ended, which is where the
abort lands.

What a bare `new` would cost there depends on the target. A zeroed
`pthread_mutex_t` is a valid unlocked mutex, so Linux finalizes the
uninitialized session and carries on. A zeroed `CRITICAL_SECTION` is
not (an initialized, unheld one has `LockCount` -1, and 0 reads as
contended), so on Windows an uninitialized session stranded by an
abort inside `new` hangs library finalization in the `Send_Guard`'s
`Protection_Entries.Finalize`. Only the Windows cross build can catch
that regression.

**What the suite can and cannot pin.** These windows are a few
instructions wide and cannot be steered into from the public API, so
the suite guards their consequences rather than the races themselves.
`test_ws_send_guard` covers what follows from the guard's ownership
protocol: pairing, that a cancelled acquisition releases nothing,
that an aborted acquirer never leaves the latch held. Each is
validated by backing the corresponding line out. Whether an abort
lands inside the interval between the protected action ending and
the next statement is a scheduling race the suite cannot force.
`test_ws_abort` case 5 notices a client left admitted-but-unowned,
because every later `Connect` is then refused, but it does not catch
the record being moved out of the protected action. The design rests
on the structural argument that there is no interval, and the suite
guards what would follow if there were.

**The guarantee is narrower on Windows.** Everything above holds
wherever an abort can reach the aborted task at all, which is a
platform property. GNAT on Linux interrupts a blocking syscall with a
signal, so a task parked in `GNAT.Sockets.Check_Selector` unwinds
when aborted. On Windows an abort cannot interrupt a task parked in a
socket call; it is deferred until the call returns on its own, which
for a `Forever` wait is never.

What this costs:

- The client's own teardown paths are unaffected. Every one of them
  fires `Abort_Pending` first, which wakes the selector through its
  explicit signalling channel rather than relying on the abort.
  `Close`, the forced teardown and the reclamation gate all work.
- A caller who aborts a task sitting inside a call that is parked in
  a socket operation, by `abort T` or by an asynchronous `select ...
  then abort`, hangs, because the transfer of control cannot land
  until that operation returns. On Linux the same code unwinds.
  `Connect` is the clearest case (parked reading the upgrade
  response), `Send` the next (parked filling a socket buffer), and
  `Reconnect` inherits it while redialling.
- `Receive` is not in that list. It waits on the session's protected
  inbox, which the receiver task fills; the socket read belongs to
  that task, not to the caller. A protected entry wait is ordinary
  Ada and is abortable everywhere. Whether aborting a WebSocket
  operation hangs on Windows depends on whether the aborted task is
  the one holding the socket.

`test_ws_abort` skips the two cases that depend on this (2 and 4) on
Windows and says so in its output; the other cases abort tasks
sitting in ordinary Ada waits and run everywhere.

Making the guarantee uniform would mean the client never parking
without a bound, or exposing a wake that a caller can use before
aborting. Neither is done, and Windows is not a supported
configuration.

### `Close` before scope exit is required

`Client_Type` is not controlled, and finalization does not tear a
connection down. It cannot: RM 9.3(5) makes waiting for dependent
tasks the first step of finalizing a master, and object finalization
happens only afterwards. A receiver parked in `Read` therefore
prevents `Finalize` from ever running, so `Finalize` can never be the
thing that unparks it.

The receiver's `terminate` alternative covers the safe cases, never
connected and idle after a completed reclamation, but an open
connection must be closed explicitly. Any automatic shutdown has to
be initiated before master finalization: an explicit `Shutdown`, or a
supervisor owning the client. Never `Finalize`.

### Paths

| Path | Behaviour |
|---|---|
| Failed upgrade before handoff | Session never published; `Connect` closes and frees it directly and admission is released. Object immediately reusable. |
| Dial failure | The same shape one step earlier; admission is still released. |
| Peer failure | The receiver's read raises, the loop exits, full reclamation runs, `On_Error` fires. |
| Graceful close | `Close` wins the teardown, runs the §1.4 handshake on the pinned session, releases its borrow, waits (bounded) for reclamation. |
| Forced reconnect, receiver parked in `Read` | `Reconnect` wins, marks the inbox closed, aborts I/O, drops its borrow, waits. The receiver wakes with `Aborted_Error`, suppresses `On_Error` because the caller asked for this, reclaims. Only then is the new generation dialed. |
| Concurrent `Close` and `Reconnect` | One wins and drives it; the other joins, touches nothing, and waits for the same completion. A later call can likewise join a teardown still running after an earlier caller timed out. |
| Send concurrent with teardown | The borrow is refused (`Closed_Error`), or granted and reclamation waits for it. It cannot park forever, because pending I/O is aborted before the wait. |
| Receiver echo racing a forced teardown | The echo re-checks the forced-drain state after acquiring the guard and bails without latching or writing. |
| Blocked user callback | The receiver never reaches reclamation; the caller's bounded wait raises `Timeout_Error` and the client stays `Closing`. |
| Exception during cleanup | The gate steps propagate; the best-effort steps are handled locally. |

### `Send_Guard`

One latch per connection serialises frame writes; the application's
`Send_*` and the receiver's Pong and Close echoes all go through it.
A WebSocket client must generate a fresh mask per frame (§5.3) and a
frame's bytes must be written contiguously, so interleaved writes
from two tasks would corrupt the stream. The socket write happens
outside the protected object's own lock, so a slow write does not
block state queries, but other senders serialize behind it.

Acquisition is bounded in exactly one place: the teardown's attempt
to send its Close frame, which uses `Try_Take`. Application sends and
the receiver's Pong and Close echoes use the blocking `Take` and
queue normally; bounding those would fail a send because someone else
was slow.

The teardown is the exception because it is the one acquisition that
can deadlock the caller's own bound. A WebSocket write carries no
deadline of its own, so a peer that stops reading parks the
application writer holding the latch, and a teardown that waited
unconditionally for that latch would never reach the `Timeout` meant
to bound it. On expiry it skips the graceful Close frame and aborts
instead: a writer interrupted mid-frame may already have left a
partial message on the wire, and §5.5.1 admits nothing after a Close.

`Close_Frame_Sent` is latched under the guard, so a `Send_*` that
loses the race to a concurrent close observes it and raises instead
of writing a data frame behind our Close.

### The receiver

One persistent task per client, running one generation at a time. It
waits for a session to be handed to it, runs that connection to
completion, reclaims it, and goes back to waiting. Per-connection
state (the decode buffer, the reassembly accumulator) is local to
that run, so a reconnect starts clean rather than inheriting the
previous connection's half-received message.

A rendezvous body that raises leaves the session with the connecting
task, so the receiver drops it and waits for the next handoff rather
than letting one bad handoff end the task and take the client with
it.

## Why this shape

- A dedicated receiver task fits asynchronous frame arrival: pings,
  server-initiated close and unsolicited data all arrive without
  application polling.
- Protected objects give the entry-barrier primitive the inbox and
  the state transitions want, and they are abort-deferred, which the
  ownership records need.
- Splitting the send guard from the state keeps the write latch out
  of the critical path of state queries like `Is_Open`.
- Per-generation heap sessions are what make the client reusable.
  Resetting inline components in place is not done because it cannot
  be made safe against a borrower that is still inside the old
  connection.

## Not provided

Automatic reconnect (retry policy, backoff, attempt limits,
retryable-closure classification, reconnecting/reconnected callbacks)
is not provided. `Reconnect` is the mechanism; policy belongs in a
managed-client layer above it, driven by its own supervisor task.

It must never be driven from `On_Error`, which runs on the receiver:
a callback that tried to reconnect would be asking the receiver to
wait for a teardown only the receiver can perform, which is what
`Reentrant_Error` refuses. Authentication failures and
caller-initiated closes should not retry by default.

## Tests

The WebSocket layer is covered by twenty-five test mains.
`test_ws_send_guard` runs first: what it checks (an aborted acquirer
never leaves the latch held) shows up everywhere else as a hang, so
nothing may sit ahead of it that could hang and stop it running.

| Test | Scope | Fixture |
|---|---|---|
| `test_ws_send_guard` | the guard's ownership protocol in isolation: pairing, cancelled acquisition, aborted acquirer | none (in-process) |
| `test_ws_budgets` | the close-budget arithmetic | none (in-process) |
| `test_ws_masking` | the masking / nonce entropy source: no repeats, not constant, full byte range | none (in-process) |
| `test_ws_frames` | pure codec: length forms, masking, control-frame validation, the `Allowance` and `Fragment` cases | none (in-process) |
| `test_ws_utf8` | text validation | none (in-process) |
| `test_ws_handshake` | the HTTP upgrade: base64 vectors, 101 / Upgrade / Connection / Accept, subprotocol checks | `server_ws.py`, `server.py`, `server_tls.py` + in-process fake |
| `test_ws_connect_bounds` | the four dial bounds: each fires, the upgrade wait tracks the value rather than a fixed bound, the budget does not outlive the upgrade, a timed-out attempt is retryable, an IP literal skips the resolver | `server_stall.py`, `server_ws.py` + the resolver seam |
| `test_dns` | bounded resolution: the caller returns on time, and the abandoned lookup is observed completing afterwards | none (in-process, resolver seam) |
| `test_ws_echo` | frame I/O: text / binary round-trips, `Receive` timeout, ordering, push callbacks | `server_ws.py` |
| `test_ws_ping` | ping / pong echo | `server_ws.py` |
| `test_ws_send_closed` | sending on a closed connection | `server_ws.py` |
| `test_ws_limits` | ceilings and delivery modes, including a huge-length header with no body, which a post-hoc check would hang on instead of rejecting | `server_ws_hostile.py`, `server_ws.py` |
| `test_ws_handoff` | the handover record's contract: one call is the whole record, monotone, calls released together all recorded | none (in-process) |
| `test_ws_reconnect` | reconnect after receiver teardown, failed upgrade, dial failure, across transport kinds; saved-parameter replay; reentrancy refusal | `server_ws.py`, `server_ws_tls.py`, `server_ws_hostile.py`, `server.py` |
| `test_ws_reconnect_fragment` | no reassembly state survives a generation boundary | `server_ws_hostile.py`, `server_ws.py` |
| `test_ws_reconnect_isolation` | what must and must not cross the boundary: parked `Receive`, unread backlog, callbacks, no `On_Error` | `server_ws.py`, `server_ws_hostile.py` |
| `test_ws_reconnect_concurrency` | senders racing a forced teardown, with narrow per-scenario exception sets | `server_ws.py`, `server_ws_hostile.py` |
| `test_ws_reconnect_echo_race` | teardown while the write latch is contended, in three shapes | `server_ws_hostile.py` |
| `test_ws_reconnect_blocked_callback` | a callback that blocks past the bound; the teardown continues and a later call joins it | `server_ws.py` |
| `test_ws_reconnect_leak` | 50 redial cycles, fd and thread counts from `/proc` | `server_ws.py` |
| `test_ws_teardown` | close paths and their bounds, including a writer stuck against a deaf peer | `server_ws_hostile.py`, `server_ws.py` |
| `test_ws_abort` | asynchronous transfer of control across every ownership handoff | `server_ws.py`, `server_stall.py` + in-process fake |
| `test_ws_tls` | the `wss://` sibling: verify / insecure / untrusted, round-trips over TLS | `server_ws_tls.py` |
| `test_pem` | the envelope validator in isolation: bundle rules, plus index arithmetic for shifted and near-Positive'Last bounds | none (in-process) |
| `test_tls_ca_pem` | in-memory trust anchors: same chain as the file, both-supplied refused, partial bundles refused, replayed by `Reconnect` | `server_tls.py`, `server_ws_tls.py`, `server_ws.py` |

### Conformance

The suite above is the project's own tests against its own fixtures.
The external check is the Autobahn|Testsuite, about 500 RFC 6455
cases; `tests/autobahn/BASELINE.md` records the counts, the suite
version and image digest, and the reasoning for every case that is
not `OK`.

The standing is zero hard failures, not "full conformance": 216
cases are `UNIMPLEMENTED` (`permessage-deflate`, which this client
does not negotiate) and four to eleven are `NON-STRICT`. Four of
those (6.4.1 to 6.4.4) are stable; the rest move between `OK` and
`NON-STRICT` from run to run, all of them the
message-queued-then-connection-failed shape the delivery contract
describes. The baseline lists which.

Tests that assert a bound are validated by backing the corresponding
guard out and confirming the test fails, and, where the test depends
on a race having happened, by making that race not happen and
confirming it fails differently. A test whose premise is established
by a delay rather than an observed fact can pass while checking
nothing.

`test_ws_handoff` pins the contract of `AHT.Websocket.Handoffs`, the
type production uses to record that a generation's session changed
hands, with no fixture and no timing-based coordination: one call is
the whole record, a caller that never reaches the call records
nothing, the record is monotone, and calls released together are all
recorded. Every wait there is for an observed fact, a counter the
type maintains or a task's `'Terminated`. Timing remains only as the
liveness backstop: the polls sleep between attempts and give up after
a bound, so a broken build reports instead of hanging.

What that does not cover: an abort arriving during the call. Reaching
that window needs the abort to land in the few instructions between
the protected action ending and the next statement, and no test in
the suite can steer it there. The placement of the record inside the
protected action, and of `Publish` inside the `Start` rendezvous,
rests on the structural argument that abort is deferred there and no
interval exists, as `Send_Guard` recording its owner inside the
acquiring action does.
