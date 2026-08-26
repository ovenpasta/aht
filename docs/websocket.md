# WebSocket

Packages under `AHT.Websocket`:

- `AHT.Websocket` — shared types.
- `AHT.Websocket.Frames` — the frame codec.
- `AHT.Websocket.Client` — the client, `ws://` and `wss://`.
- `AHT.Websocket.Send_Guards` — the per-connection write latch and its
  scope guard. Separate because its correctness argument is about
  abort, and an abort-safety claim tested against a hand-written
  replica is not tested at all.
- `AHT.Websocket.UTF8` — text validation (RFC §8.1).
- `AHT.Websocket.Budgets` — the close-budget arithmetic, extracted so
  it can be checked without a socket.

`AHT.Random` sits outside the WebSocket tree: it supplies
cryptographically secure bytes from the OS pool for masking keys and
the handshake nonce. Its one non-portable part — the system call
itself — is `AHT.Random.Source`, with a body per OS under `src/os`
(`/dev/urandom`, `BCryptGenRandom`) selected by the `AHT_OS` scenario
variable. That unit builds and runs on Windows; the transports and the
test harness are POSIX-verified only.

Exceptions, all declared in `AHT.Websocket`:

| Exception | Means |
|---|---|
| `Handshake_Error` | the HTTP upgrade did not yield `101` (e.g. `401`, `403`, `404`), `Sec-WebSocket-Accept` was missing or wrong, or the call was refused in the client's current state |
| `Protocol_Error` | the peer put something malformed on the wire. The receiver fires `On_Error` and tears the connection down; it does **not** send a close frame on this path (see *Failure codes*) |
| `Closed_Error` | there is no connection to act on, or the one being waited on went away |
| `Message_Too_Big` | the peer declared more than the configured ceiling allows. Not a protocol fault: nothing malformed happened, the peer just asked for more than this endpoint will hold — closes with 1009 |
| `Mode_Error` | the operation is not available in this configuration — `Receive` under `Callback_Only`, connecting `Callback_Only` with no callback, clearing that callback while such a connection is live, or reconfiguring limits once a session exists |
| `Reentrant_Error` | an operation that waits for the receiver was called *from* the receiver, i.e. from inside a callback |

`AHT.Transport.Timeout_Error` and `AHT.Transport.Aborted_Error` also
surface here. `Timeout_Error` comes from six bounds — the four dial
bounds `Resolve_Timeout`, `Connect_Timeout`, `Handshake_Deadline` and
`Upgrade_Deadline` on `Connect` / `Reconnect`; `Receive`'s own
`Timeout`; and
`Drain_Timeout` on `Close` / `Reconnect`. The close handshake's
`Timeout` is the one bound that expires *without* raising; see
*Bounds*. `Aborted_Error` means I/O was cancelled by a teardown.

`AHT.Random.Entropy_Error` is raised if the OS entropy source cannot
be read, rather than falling back to anything weaker.

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

`Client.Close` takes `Valid_Close_Code := 1000`. Both subtypes use
`Dynamic_Predicate`, so this is a **runtime** check, not a compile-time
one: `Client.Close (1006, ...)` raises rather than failing to compile,
though GNAT will warn on a literal it can see through.

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

type Fragment_State is (Unchecked, No_Message, In_Message);

procedure Decode
  (Input     : Byte_Array;
   Hdr       : out Frame_Header;
   Payload   : out Buffer;
   Last      : out Natural;
   Allowance : Natural        := Natural'Last;
   Fragment  : Fragment_State := Unchecked);
```

`Allowance` is the size ceiling, and it lives here rather than one
layer up for a reason that decides the design: `Decode` reports
"incomplete" until the whole declared payload is buffered, so a limit
applied to a *returned* frame would first have to accumulate the very
bytes it exists to refuse. A peer that declares a gigabyte and then
sends nothing would be answered only after the gigabyte arrived —
which it never does. Checking at header-parse time rejects it after
ten bytes. Exceeding it raises `AHT.Websocket.Message_Too_Big`, which
is distinct from `Protocol_Error` because nothing malformed happened:
the peer asked for more than this endpoint will hold. The client
closes with 1009 on this path.

`Fragment` lets `Decode` apply the §5.4 opcode sequencing rules at
header-parse time. `Unchecked` is the default and has to be — the
contract is that `Decode` handles any single frame in isolation, and
callers holding no message state (the codec tests among them) decode a
standalone `Continuation` and expect it to work. A receiver that does
track the sequence passes the real state. Sequencing is checked
*before* size, so a frame that is both out of order and oversized
reports the protocol fault.

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
    excluding 1004, which is reserved with no defined meaning, and
    the synthetic 1005 / 1006 / 1015 that must never appear on the
    wire).
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

The codec also exposes `Frame_Header`, and
`Classify_Inbound_Close` / `Inbound_Close_Status` for interpreting a
received Close payload — which is where the 1007 cases come from: a
Close whose reason is not valid UTF-8 is answered with **1007**, per
§8.1, rather than 1002.

Masking keys are *not* generated here — the codec takes any
caller-supplied mask. The client draws them from `AHT.Random`, which
reads the OS entropy pool.

**They must be unpredictable.** RFC §5.3 requires the key to come from
a strong source of entropy, and requires one frame's key not to make
the next one guessable. This is not about confidentiality: masking
exists so that a client cannot be coerced into putting bytes on the
wire that an intermediary would parse as a second, attacker-chosen
HTTP request. A mask an observer can predict does not weaken that
defence, it removes it. `Sec-WebSocket-Key` has a matching
requirement in §4.1 — a nonce selected randomly per connection.

## `AHT.Websocket.Client`

### Shape

```ada
type Client_Type is tagged limited private;

--  Full form — Extra_Headers plus optional subprotocols / origin.
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

--  Convenience form — no extra headers.
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
handshake, so on a `ws://` dial none of them is *used*.

Not used is not the same as not checked. Supplying both `CA_Path` and
`CA_PEM` is still rejected on `ws://`, because it is a contradiction
in what the caller asked for rather than a setting this dial happens
not to need — and the client checks it itself precisely because no
TLS transport is built there to notice.

`CA_PEM` is the same trust material as `CA_Path`, held in memory
rather than on disk — one or more concatenated PEM certificates, for
anchors compiled into the binary. Two rules:

- **Supplying both raises**, before anything is dialled and before
  admission reserves a generation. There is no precedence, and the
  refusal stands even under `Insecure`: a caller who passed two sets
  of anchors is wrong about which is in force, and honouring one
  silently leaves that belief intact. On a `ws://` dial the client's
  own check is the only thing that catches it, since no TLS transport
  is ever built.
- **Parsing is all-or-nothing.** A bundle whose tail is truncated or
  corrupt is rejected whole rather than installing the certificates
  that parsed before the damage. Trusting a prefix of what the caller
  meant to trust is worse than trusting nothing, because nobody finds
  out.

It is deep-copied into the saved parameters like every other
argument, so `Reconnect` replays it without the caller keeping the
PEM alive.

The `Send_*` operations deliberately carry **no** `Is_Open`
precondition. The receiver task can tear a connection down
concurrently — the peer may close between the application pulling a
message and echoing it — so no caller can guarantee such a
precondition across the call. The check is a runtime guard raising a
catchable `Closed_Error`, and it is expressed as a *borrow*: a sender
that cannot borrow the current session raises rather than touching one
it does not hold.

### Lifecycle: a client outlives its connections

A `Client_Type` is **reusable**. This is the central change from the
original design, in which the receiver was a one-shot task and every
per-connection resource was an inline component, so a second `Connect`
had to be refused. Now each connection is a heap-allocated
`Session_Type` owned for the length of one generation, and the client
is a durable handle that outlives them.

Two state machines, and they are not the same thing:

```ada
--  Per CONNECTION (RFC 6455 §1.4), inside a session.
type State_Kind is (Connecting, Open, Closing, Closed);

--  Per CLIENT, spanning connections.
type Client_State is (Idle, Connecting, Open, Closing, Disconnected);
```

`Idle` means no connection has ever been *successfully published* —
not merely that nothing has been dialed, since a failed first attempt
returns the client to `Idle`. `Disconnected` means a generation was
established and has since been fully reclaimed. Both are dialable, and keeping
them distinct is what lets `Reconnect` know whether there are saved
parameters worth replaying.

| Call | `Idle` | `Disconnected` | `Connecting` | `Open` / `Closing` |
|---|---|---|---|---|
| `Connect` | admitted | admitted | `Handshake_Error` | `Handshake_Error` |
| `Reconnect` | `Handshake_Error` | redials saved params | `Handshake_Error` | drains, then redials |
| `Configure` | accepted | accepted | `Mode_Error` | `Mode_Error` |

`Idle` and `Disconnected` differ for exactly one call. `Reconnect`
repeats the last connect that *succeeded*, and parameters are saved
only on publication — so from `Idle` there is nothing to repeat and it
raises `Handshake_Error`. That is the whole reason the two states are
not collapsed: they are equally dialable, but only one of them has a
past.

`Connect` never displaces a live connection silently — that is the one
thing `Reconnect` exists to do, and it does it explicitly. `Reconnect`
replays the parameters of the last connect that actually **worked**,
not the last one attempted, so a failed attempt in between does not
become the thing that gets repeated.

`Generation` counts connections that were successfully established: 0
before the first, one more on each. Reserved numbers are not counted,
so a failed attempt does not advance it. That is what makes it usable
as "am I still looking at the connection I was?" across a reconnect.

`Selected_Subprotocol` belongs to the connection, not to the client.
It stops answering once that connection is reclaimed rather than
lingering until some later one overwrites it — "gone with the
connection" rather than "replaced eventually".

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
removes the inbox as a growth path outright. It therefore requires an
`On_Message` callback: with none there is no consumer, and `Connect`
raises `Mode_Error` rather than dropping every message in silence.
Under `Both`, a message the inbox refuses is not passed to the
callback either — pull and push consumers observe exactly the same
accepted set.

`Configure` is legal only while fully disconnected. Every limit
becomes an immutable property of a session at the moment it is
allocated, so a running connection cannot have its ceilings moved
underneath it and the receiver never re-reads a limit that might have
changed since it last looked.

The failure codes are deliberately distinct, because the failures are:

- **Exceeding `Max_Message_Bytes`** — in one frame or accumulated
  across a fragment sequence — closes with **1009 Message Too Big**,
  fires `On_Error`, and tears down through normal reclamation.
- **Overrunning an inbox bound** closes with **1008 Policy Violation**.
  This is a different failure: the peer is outrunning the application,
  not misbehaving. Silently dropping would corrupt stream semantics the
  caller has no way to detect.
- **Invalid UTF-8** — in a text message or in a Close reason — closes
  with **1007 Invalid Payload Data** (§8.1).
- **A peer close carrying a reserved code** is answered with **1002
  Protocol Error**.

A `Protocol_Error` from the codec — a malformed frame — is handled
differently from all of these: the receiver fires `On_Error` and tears
the connection down **without sending a close frame at all**. The
connection is already unusable, and there is no reason to believe a
peer that produced a malformed frame will read a reply. So a 1002 this client *generates* means specifically "your close code
was reserved", not "you sent something malformed". A caller may of
course pass `Close (Code => 1002)` explicitly, which is unaffected by
any of this.

The defaults are policy, not minimums. 32 MiB covers the Autobahn §9
cases (~16 MiB) with room to spare, exceeds the 13 MB the echo test
needs, and matches what `server_ws.py` itself accepts.

They are also a **compatibility surface**, and the one part of this
that can break a working application silently: a message that used to
arrive now closes the connection with 1009. A default below the 16 MiB
§9 cases would fail an Autobahn run, which is the intended tripwire —
and it holds: §9 is 54/54 `OK` at the current defaults. See
`tests/autobahn/BASELINE.md`.

### Callbacks

```ada
procedure Set_On_Message (Self : in out Client_Type; CB : On_Message_Callback);
procedure Set_On_Close   (Self : in out Client_Type; CB : On_Close_Callback);
procedure Set_On_Error   (Self : in out Client_Type; CB : On_Error_Callback);
```

Callbacks live in the **client**, not in a connection, so one
installation serves every generation and they are read afresh for each
event rather than captured once.

**Callbacks must not block.** This is now load-bearing rather than
advisory: callbacks run on the receiver task, and the receiver cannot
reclaim a connection while it is inside user code. A callback that
never returns stalls `Close` — which is bounded, so the caller gets
`Timeout_Error` and the teardown continues in the background. An
exception raised inside a callback is swallowed so the receiver can
keep draining the wire.

`Close`, `Reconnect` and `Receive` raise **`Reentrant_Error`** when
called from inside a callback. Each would otherwise wait on the very
task making the call: the first two for a teardown only the receiver
can complete, the third for a message only the receiver can deliver.
Refusing is strictly better than the deadlock it replaces. `Send_*`
stay legal — they wait for nothing the receiver owes them, which is
what keeps echo-from-`On_Message` working.

A teardown the caller asked for is **not** reported as an error.
`Close` and `Reconnect` stop a parked receiver by aborting its
transport I/O, so the receiver sees `Aborted_Error` on the way out;
passing that to `On_Error` would tell the application its connection
had failed every time it deliberately closed one. A peer-driven abort
still reaches the callback.

### Bounds: two clocks, not one

```ada
Default_Drain_Timeout : constant Duration := 5.0;
```

`Close` and `Reconnect` bound the teardown with two clocks, because
they measure different things and only one of them can raise.
(`Reconnect` carries four more, but they belong to the dial that
follows and are covered in *Bounds on a dial* below. The split is at
the drain/redial seam: two for the teardown, four for the redial.)

**`Timeout` is a compound budget for getting our Close frame out and
hearing the answer.** It covers all three of: acquiring the send
guard, writing the Close frame, and waiting for the peer's echo. It is
not "how long to wait for the peer" — that would leave the first two
unbounded, which is exactly the hole a peer that stops reading walks
through. When it expires, the teardown calls `Abort_Pending` and
carries on; **it does not raise**. Running out of patience with a peer
is a normal outcome, not an error.

**`Drain_Timeout` bounds us** — how long to wait for our own receiver
to finish reclaiming the session afterwards. This is the one that
raises `Timeout_Error`.

There is one deliberate exception to the compound budget.
`Timeout => 0.0` still grants the Close-frame write a fixed 0.25 s
grace, because a transport handed a zero deadline reads it as "fail
rather than park" — so a literal zero would mean no goodbye was ever
attempted, which is not what "don't wait for the peer" asks for. Every
positive budget gets what is left of itself and no more.

A single knob would also make `Timeout => 0.0` mean "and fail if
reclamation is not already finished", which is not what anyone asking
for it wants.

Nothing is abandoned on expiry. The client stays `Closing`,
reclamation continues in the background, and a later call **joins**
the same completion rather than starting a second one. A `Reconnect`
that cannot finish the drain does **not** redial — dialing over a
session a teardown still owns is the one thing it must never do.

The usual cause of a drain timeout is a callback that has not
returned, which no receiver-side mechanism can detect: `Abort_Pending`
cancels transport I/O, not user code.

`Receive` has its own, unrelated `Timeout`, and that one does raise
`Timeout_Error` — it bounds a wait for a message, not a teardown.

**The caller's bound is a liveness knob, not a safety one.** Setting
it too low produces spurious `Timeout_Error`s and nothing worse:
teardown continues, nothing is freed early, and a later call joins the
same completion. The safety property lives in `Wait_No_Borrowers`,
which no caller can shorten.

### Bounds on a dial

A dial has four stages that can block, and one knob each.
`Resolve_Timeout` bounds the DNS lookup; `Connect_Timeout` bounds the
TCP connect as a single total budget across every address that lookup
returned; `Handshake_Deadline` bounds the TLS handshake, and so does
nothing on `ws://`, which runs none; `Upgrade_Deadline` bounds the
HTTP exchange that follows. All four default to `Duration'Last`, so a
caller who sets none gets exactly the behaviour that predates them,
and a caller who sets all four is bounded end to end.

They are four knobs and not one because they are four different waits
with different plausible budgets — a caller happy to sit through a
slow handshake on a congested link may still refuse to wait on a peer
that has stopped answering. The transports already implemented the
two middle ones (`AHT.Transport.TCP.Connect`,
`AHT.Transport.TLS.Connect`); the client's job is to forward them.

`Upgrade_Deadline` is armed on **both** directions before the request
goes out, not on the read alone. A peer that completes the connect and
then stops draining blocks the `Request.Write` exactly as a peer that
never answers blocks the `Response.Read`, and a read deadline would
bound only the second.

It is then **disarmed** before the session is published. This is not
tidiness. `Set_Read_Deadline` and `Set_Write_Deadline` are compound
budgets measured from the setter call, so a deadline left armed does
not go on bounding the upgrade — the upgrade is over — it expires
under the receiver partway through a healthy session and surfaces as a
`Timeout_Error` on a connection that was never in trouble. The disarm
sits after the response has been validated, not immediately after it
was read — but validation is all header inspection and touches the
transport nowhere, so the budget covers every byte of the exchange and
nothing after it. `test_ws_connect_bounds` connects
with a one-second upgrade budget, idles past it, and requires a full
round trip afterwards; backed out, it fails there.

**Expiry raises `Timeout_Error`, not `Handshake_Error`**, for all
four — including the upgrade, whose failure originates inside the
block that otherwise wraps everything. The distinction is the point:
`Handshake_Error` means the peer answered and the answer was wrong,
`Timeout_Error` means it did not answer in time, and a caller deciding
whether to retry should not have to parse a message to tell them
apart. A timed-out attempt releases its admission and closes its
half-built session like any other failure, so the retry is legal.

**`Resolve_Timeout` bounds the caller, not the lookup**, and the
distinction is the contract rather than a caveat. `getaddrinfo` takes
no deadline and cannot be cancelled on either platform, so a resolve
that expires has stopped waiting; the lookup carries on in the worker
that `AHT.DNS` abandoned, until the platform resolver gives up by
itself. What the caller gets back is control, on time.

Resolving inside the library rather than telling applications to do it
is what keeps the fix from costing anything: `Host` stays the name all
the way through, so SNI and certificate verification are untouched. An
application resolving on its own and putting the literal in the URL
would send no SNI and be verified against IP SANs, which typical
certificates do not carry — it would trade a hang for a quietly weaker
`wss://`. There is nothing to bound when the URL already carries a
literal, and that path skips the resolver entirely.

The bounds matter most where `abort` cannot substitute for them. On
Windows a task parked in `Connect` cannot be aborted at all (see *The
guarantee is narrower on Windows*), so "dial on a task and abandon it"
is not available and an application has no way to impose a bound from
outside.

### HTTP upgrade flow

`Connect` reuses `AHT.HTTP.*` for the wire:

1. `AHT.URL.Parse (URL)` yields a `ws` / `wss` scheme directly (no
   rewrite to `http` / `https`); the scheme drives transport
   selection. This runs in the declarative part, *before* admission,
   so a scheme the URL parser does not know at all — `ftp://` — raises
   `AHT.URL.Parse_Error`, not `Handshake_Error`. A parseable but wrong
   scheme (`http://`, `https://`) is rejected with `Handshake_Error`
   — and that check happens **after** admission has already reserved a
   generation, so the attempt owner is what releases it.
2. Build a `GET` request with the upgrade headers:
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
     those via `Extra_Headers` if you're using the dedicated
     parameters or you'll emit duplicate header lines.
3. Dial one transport for the scheme — TCP for `ws://`, TLS for
   `wss://` (threading `Insecure` / `CA_Path` / `CA_PEM` into the TLS
   handshake, and `Resolve_Timeout` / `Connect_Timeout` /
   `Handshake_Deadline` into the waits). The name is resolved here,
   through `AHT.DNS`, and stays the name for SNI and verification.
   The request is built before the dial, not after.
4. Arm `Upgrade_Deadline` on both directions, then
   `AHT.HTTP.Request.Write` the request over the new transport.
5. `AHT.HTTP.Response.Read` the status line + headers.
6. Validate:
   - Status = `101 Switching Protocols`. Any other status raises
     `Handshake_Error` carrying the status and reason — callers
     distinguish `401`/`403` (auth) from `404` (no endpoint) from
     protocol mismatches.
   - `Upgrade: websocket` — a case-insensitive *equality*, not a
     token match, so `Upgrade: websocket, foo` is rejected.
   - `Connection: Upgrade` (case-insensitive token match — the header
     may list additional tokens).
   - `Sec-WebSocket-Accept` equals
     `base64(SHA1(Key & "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`.
   - At most one `Sec-WebSocket-Protocol`, and any value returned must
     be one the client offered.
7. Disarm `Upgrade_Deadline`, then publish the session to the
   persistent receiver and advance the generation.

A TLS dial failure (step 3) propagates `AHT.Transport.TLS.TLS_Error`
unwrapped; failures from step 4 onward are wrapped in
`Handshake_Error` — with one exception. A `Timeout_Error` from steps 4
or 5 is the upgrade budget expiring, and it propagates unwrapped so it
reads the same as the two bounds that fire earlier, in steps 3 and
before. Nothing else in that stretch arms a deadline and the transport
is fresh, so the exception can only be that.

A failed attempt is genuinely retryable, and that is a property of the
session being per-generation: the retry builds fresh transports rather
than re-dialing one whose single-use latch is already set. That
failure — dial succeeds, upgrade rejected, object now unusable — is
the bug this whole design started from.

## Ownership

The hard part of a reusable client is not reconnecting. It is
answering "who frees this session, and when", such that the answer
survives an exception or an abort at any point.

### Sessions are borrowed, never referenced

`Send_*` and `Receive` do not hold a session pointer. They **borrow**
one from the lifecycle controller for the duration of the call, and a
borrow is refused once teardown has begun. Reclamation then waits for
the borrow count to reach zero before freeing anything:

```
1. Stop admission          — no new borrows
2. Wake parked borrowers   — state Closed, inbox Mark_Closed
3. Abort pending I/O       — release anyone parked in Read/Write
4. Wait_No_Borrowers       — UNBOUNDED, deliberately
5. Close the transport
6. Drop the published pointer
7. Free the session
8. Signal_Generation_Done  — release the waiters, client → Disconnected
```

Step 4 is the memory-safety gate and it has no timeout by design. A
bound there would mean freeing a session while a task might still be
inside it.

Note what the caller's `Drain_Timeout` does and does not bound. It
does **not** shorten step 4 — receiver-side reclamation stays
unbounded from end to end. It bounds the caller's *external* wait on
step 8, which is a different thing: a caller that gives up stops
waiting, while the reclamation it was waiting for carries on and
completes on its own. That is why a later `Close` or `Reconnect` can
join the very same completion instead of starting a second teardown.

Waking parked borrowers (step 2) is done twice — by the receiver's own
reclamation and again by the caller's teardown pin — deliberately and
idempotently, because a borrower nobody wakes is a drain that never
completes.

### Abort safety is structural, not defensive

Three GNAT behaviours were measured, not assumed, and each one rules
out an approach that looks correct:

- **An `in out` entry parameter's copy-back is not delivered when the
  caller is aborted during the rendezvous.** So an ownership transfer
  cannot be recorded by having the accepting task clear the caller's
  pointer; it has to be recorded in a protected action, which *is*
  abort-deferred.
- **A blocking entry call made from a controlled `Initialize` is
  unabortable**, because `Initialize` is abort-deferred — while the
  same call made directly can be cancelled by an asynchronous select.
  So a scope guard may release in `Finalize`, but must not acquire in
  `Initialize`.
- **A pending abort takes effect at the end of a protected action**,
  before whatever statement follows it. So a guard cannot record "I
  hold this" in its own state after the acquiring call returns — the
  acquiring protected action has to record the owner itself.

That last rule shapes two places. `Send_Guard.Acquire` takes the
owner's identity *in* and records it inside the same action that takes
the latch, so a cancelled acquisition records nothing and its release
is a no-op. And admission works the same way: the `Attempt_Owner`
exists **before** `Begin_Connect` is called, and `Begin_Connect`
records the generation into it from inside the protected action. An
owner created after admission returned would leave an instant in which
the client was `Connecting` and nothing was responsible for taking it
back out — and an abort landing there stranded the client permanently,
refusing every later `Connect`.

Ownership is carried by controlled types, so cleanup runs on every
exit path including an abort: `Attempt_Owner` for an in-flight connect,
`Teardown_Pin` for whoever wins a teardown.

**What the suite can and cannot pin.** These windows are a few
instructions wide and cannot be steered into from the public API, so
for the most part the suite guards their *consequences* rather than
the races themselves. `test_ws_send_guard` covers what follows from
the guard's ownership protocol — pairing, that a cancelled acquisition
releases nothing, that an aborted acquirer never leaves the latch held
— and each is validated by backing the corresponding line out. The
flag *shape* is not caught by it: whether the abort lands inside that
interval is a scheduling race and the victim usually wins. It was
falsified out of tree instead, by a probe that made the release and
the abort adjacent in one task — 200/200 leaks that way, 0/200 with
the owner recorded inside the protected action.

Admission is the same split, for the same reason: `test_ws_abort`
case 5 notices a client left admitted-but-unowned, because every later
`Connect` is then refused forever, but it does not catch the record
being moved out of the protected action. So the design rests on the
structural argument — there is no interval — and the suite guards what
would follow if there were.

**The guarantee is narrower on Windows.** Everything above holds
wherever an abort can reach the aborted task at all, and that is a
platform property rather than a property of this design. GNAT on Linux
interrupts a blocking syscall with a signal, so a task parked in
`GNAT.Sockets.Check_Selector` unwinds when aborted. Windows has no
equivalent mechanism, so the abort is deferred until the call returns
on its own — which, for a `Forever` wait, is never. Measured with a
standalone probe: park a task in `Check_Selector`, abort it, ask
`'Terminated`. Linux terminates; Windows does not.

What this costs, precisely:

- The client's **own** teardown paths are unaffected. Every one of them
  fires `Abort_Pending` first, which wakes the selector through its
  explicit signalling channel rather than relying on the abort to
  interrupt anything. `Close`, the forced teardown and the reclamation
  gate all work.
- A **caller** who aborts a task sitting inside a call that is parked
  in a socket operation — by `abort T` or by an asynchronous
  `select ... then abort` — will hang, because the transfer of control
  cannot land until that operation returns. On Linux the same code
  unwinds. `Connect` is the clearest case (parked reading the upgrade
  response), `Send` the next (parked filling a socket buffer), and
  `Reconnect` inherits it while redialling.
- `Receive` is **not** in that list. It waits on the session's
  protected inbox, which the receiver task fills; the socket read
  belongs to that task, not to the caller. A protected entry wait is
  ordinary Ada and is abortable everywhere. The distinction is worth
  keeping straight, because "aborting a WebSocket operation hangs on
  Windows" is not true as a blanket statement — it depends on whether
  the aborted task is the one holding the socket.

`test_ws_abort` skips exactly the two cases that depend on it (2 and
4) on Windows and says so in its output; the other cases abort tasks
sitting in ordinary Ada waits and run everywhere. Which two was
established by running it, not by reading them.

Making the guarantee uniform would mean the client never parking
without a bound, or exposing a wake that a caller can use before
aborting. Neither is done today, and Windows is not a supported
configuration.

### `Close` before scope exit is required

`Client_Type` is **not** controlled, and finalization deliberately does
not tear a connection down. It cannot: RM 9.3(5) makes *waiting for
dependent tasks* the first step of finalizing a master, and object
finalization happens only afterwards. A receiver parked in `Read`
therefore prevents `Finalize` from ever running, so `Finalize` can
never be the thing that unparks it.

The receiver's `terminate` alternative covers the safe cases — never
connected, and idle after a completed reclamation — but an open
connection must be closed explicitly. Any future automatic shutdown
has to be initiated *before* master finalization: an explicit
`Shutdown`, or a supervisor owning the client. Never `Finalize`.

### Paths

| Path | Behaviour |
|---|---|
| Failed upgrade before handoff | Session never published; `Connect` closes and frees it directly and admission is released. Object immediately reusable — the bug this design started from. |
| Dial failure | The same shape one step earlier; admission is still released. |
| Peer failure | The receiver's read raises, the loop exits, full reclamation runs, `On_Error` fires. |
| Graceful close | `Close` wins the teardown, runs the §1.4 handshake on the pinned session, releases its borrow, waits (bounded) for reclamation. |
| Forced reconnect, receiver parked in `Read` | `Reconnect` wins, marks the inbox closed, aborts I/O, drops its borrow, waits. The receiver wakes with `Aborted_Error`, suppresses `On_Error` because the caller asked for this, reclaims — and only then is the new generation dialed. |
| Concurrent `Close` and `Reconnect` | One wins and drives it; the other joins, touches nothing, and waits for the same completion. A later call can likewise join a teardown still running after an earlier caller timed out. |
| Send concurrent with teardown | The borrow is refused (`Closed_Error`), or granted and reclamation waits for it. It cannot park forever, because pending I/O is aborted before the wait. |
| Receiver echo racing a forced teardown | The echo re-checks the forced-drain state *after* acquiring the guard and bails without latching or writing. |
| Blocked user callback | The receiver never reaches reclamation; the caller's bounded wait raises `Timeout_Error` and the client stays `Closing`. |
| Exception during cleanup | The gate steps propagate; the best-effort steps are handled locally. |

### `Send_Guard`

One latch per connection serialises frame writes — the application's
`Send_*` and the receiver's Pong and Close echoes both go through it.
A WebSocket client must generate a fresh mask per frame (§5.3) and a
frame's bytes must be written contiguously, so interleaved writes from
two tasks would corrupt the stream. The socket write happens *outside*
the protected object's own lock, so a slow write doesn't block state
queries, but other senders still serialize behind it.

Acquisition is bounded in exactly **one** place: the teardown's
attempt to send its Close frame, which uses `Try_Take`. Application
sends and the receiver's Pong and Close echoes all use the blocking
`Take` and queue normally — bounding those would mean failing a send
because someone else was slow, which is not the caller's problem to
absorb.

The teardown is the exception because it is the one acquisition that
can deadlock the caller's own bound. A WebSocket write carries no
deadline of its own, so a peer that simply stops reading parks the
application writer holding the latch — and a teardown that waited
unconditionally for that latch in order to send its Close frame would
never reach the `Timeout` supposed to bound it. On expiry it **skips
the graceful Close frame** and aborts instead: a writer interrupted
mid-frame may already have left a partial message on the wire, and
§5.5.1 admits nothing after a Close.

`Close_Frame_Sent` is latched under the guard, so a `Send_*` that
loses the race to a concurrent close observes it and raises instead of
writing a data frame behind our Close.

### The receiver

One persistent task per client, running one generation at a time. It
waits for a session to be handed to it, runs that connection to
completion, reclaims it, and goes back to waiting. Per-connection
state — the decode buffer, the reassembly accumulator — is local to
that run, which is what makes a reconnect start clean rather than
inheriting the previous connection's half-received message.

A rendezvous body that raises leaves the session with the connecting
task, so the receiver drops it and waits for the next handoff rather
than letting one bad handoff end the task and take the client with it.

## Why this shape

- A dedicated receiver task is the natural fit for asynchronous frame
  arrival — pings, server-initiated close, and unsolicited data all
  arrive without application polling.
- Protected objects give the entry-barrier primitive for free, which
  is what the inbox and the state transitions want, and they are
  abort-deferred, which is what the ownership records need.
- Splitting the send guard from the state keeps the write latch out of
  the critical path of state queries like `Is_Open`.
- Per-generation heap sessions are what make the client reusable at
  all: the alternative — resetting inline components in place — cannot
  be made safe against a borrower that is still inside the old
  connection.

## Not provided

**Automatic reconnect** — retry policy, backoff, attempt limits,
retryable-closure classification, reconnecting/reconnected callbacks —
is deliberately absent. `Reconnect` is the mechanism; policy belongs
in a managed-client layer above it, driven by its own supervisor task.

It must never be driven from `On_Error`, which runs on the receiver:
a callback that tried to reconnect would be asking the receiver to
wait for a teardown only the receiver can perform, which is precisely
what `Reentrant_Error` refuses. Authentication failures and
caller-initiated closes should not retry by default.

## Tests

The WebSocket layer is covered by twenty-five test mains. `test_ws_send_guard`
runs **first** by construction: what it checks shows up everywhere else
as a hang, so nothing may sit ahead of it that could hang and stop it
running at all.

| Test | Scope | Fixture |
|---|---|---|
| `test_ws_send_guard` | the guard's ownership protocol in isolation — pairing, cancelled acquisition, aborted acquirer | none (in-process) |
| `test_ws_budgets` | the close-budget arithmetic, extracted so it can be checked directly | none (in-process) |
| `test_ws_masking` | the masking / nonce entropy source: no repeats, not constant, full byte range | none (in-process) |
| `test_ws_frames` | pure codec — length forms, masking, control-frame validation, the `Allowance` and `Fragment` cases | none (in-process) |
| `test_ws_utf8` | text validation | none (in-process) |
| `test_ws_handshake` | the HTTP upgrade: base64 vectors, 101 / Upgrade / Connection / Accept, subprotocol checks | `server_ws.py`, `server.py`, `server_tls.py` + in-process fake |
| `test_ws_connect_bounds` | the four dial bounds: each fires, the upgrade wait tracks the value rather than some fixed bound, the budget does not outlive the upgrade, a timed-out attempt is retryable, an IP literal skips the resolver | `server_stall.py`, `server_ws.py` + the resolver seam |
| `test_dns` | bounded resolution: the caller returns on time, and the abandoned lookup is observed completing afterwards rather than assumed to have | none (in-process, resolver seam) |
| `test_ws_echo` | frame I/O: text / binary round-trips, `Receive` timeout, ordering, push callbacks | `server_ws.py` |
| `test_ws_ping` | ping / pong echo | `server_ws.py` |
| `test_ws_send_closed` | sending on a closed connection | `server_ws.py` |
| `test_ws_limits` | ceilings and delivery modes; the decisive case is a huge-length header with no body, where a post-hoc check would hang instead of rejecting | `server_ws_hostile.py`, `server_ws.py` |
| `test_ws_handoff` | the handover record's contract: one call is the whole record, monotone, calls released together all recorded | none (in-process) |
| `test_ws_reconnect` | reconnect after receiver teardown, failed upgrade, dial failure, across transport kinds; saved-parameter replay; reentrancy refusal | `server_ws.py`, `server_ws_tls.py`, `server_ws_hostile.py`, `server.py` |
| `test_ws_reconnect_fragment` | no reassembly state survives a generation boundary | `server_ws_hostile.py`, `server_ws.py` |
| `test_ws_reconnect_isolation` | what must and must not cross the boundary: parked `Receive`, unread backlog, callbacks, no `On_Error` | `server_ws.py`, `server_ws_hostile.py` |
| `test_ws_reconnect_concurrency` | senders racing a forced teardown, with deliberately narrow per-scenario exception sets | `server_ws.py`, `server_ws_hostile.py` |
| `test_ws_reconnect_echo_race` | teardown while the write latch is contended, in three shapes | `server_ws_hostile.py` |
| `test_ws_reconnect_blocked_callback` | a callback that blocks past the bound; the teardown continues and a later call joins it | `server_ws.py` |
| `test_ws_reconnect_leak` | 50 redial cycles, fd and thread counts from `/proc` | `server_ws.py` |
| `test_ws_teardown` | close paths and their bounds, including a writer stuck against a deaf peer | `server_ws_hostile.py`, `server_ws.py` |
| `test_ws_abort` | asynchronous transfer of control across every ownership handoff | `server_ws.py`, `server_stall.py` + in-process fake |
| `test_ws_tls` | the `wss://` sibling: verify / insecure / untrusted, round-trips over TLS | `server_ws_tls.py` |
| `test_pem` | the envelope validator in isolation: bundle rules, plus index arithmetic for shifted and near-Positive'Last bounds | none (in-process) |
| `test_tls_ca_pem` | in-memory trust anchors: same chain as the file, both-supplied refused, partial bundles refused, replayed by `Reconnect` | `server_tls.py`, `server_ws_tls.py`, `server_ws.py` |

### Conformance

The suite above is all our own tests against our own fixtures. The
external check is the Autobahn|Testsuite, which throws ~500 RFC 6455
cases at the client; `tests/autobahn/BASELINE.md` records the counts,
the suite version and image digest, and the reasoning for every case
that is not `OK`.

The current standing is **zero hard failures** — deliberately not
"full conformance", since 216 cases are `UNIMPLEMENTED`
(`permessage-deflate`, which this client does not negotiate) and five
or six are `NON-STRICT`. That count moves: four cases flap between
`OK` and `NON-STRICT` from run to run, all of them the
message-queued-then-connection-failed shape the delivery contract
describes. The baseline says which, and why the zero is the number to
read.

Tests that assert a bound are validated by backing the corresponding
guard out and confirming the test fails — and, where the test depends
on a race having happened, by making that race *not* happen and
confirming it fails differently. A test whose premise is established
by a delay rather than an observed fact can pass while checking
nothing, which several of these did before they were corrected.

Every main in the table now meets that standard. The one that did not
was `test_ws_abort`'s handoff sweep, which swept an abort deadline
across a calibrated handshake and needed both outcomes — some samples
torn, some surviving — in one run. That is a statistical property of a
duration varying several-fold under load, so it flaked in both
directions, and re-tuning the span only moved which direction.

It is gone. What it was reaching for — the record that a generation's
session changed hands — is now `AHT.Websocket.Handoffs`, a type
production uses directly, and `test_ws_handoff` pins its *contract*
with no fixture and no timing-based coordination: one call is the
whole record, a caller that never reaches the call records nothing,
the record is monotone, and calls released together are all recorded. Every wait there is for an observed fact —
a counter the type maintains, or a task's `'Terminated`. Timing
remains only as the liveness backstop: the polls sleep between
attempts and give up after a bound, so a broken build reports instead
of hanging.

**What that does not cover, stated plainly:** an abort arriving
*during* the call. Reaching that window needs the abort to land in the
couple of instructions between the protected action ending and the
next statement, and a probe built for it — an asynchronous select
fired while the victim was in the abortable part, 200 rounds, counting
conclusive ones — found around thirty conclusive rounds per run and
**zero** with the abort inside the window. It was removed rather than
left looking like coverage. So the placement of the record inside the
protected action, and of `Publish` inside the `Start` rendezvous,
rests on the structural argument that abort is deferred there and no
interval exists — the same standing as the `Send_Guard` flag shape.

Same move as `Send_Guards`, and for the same reason — an abort-safety
claim tested against a replica is not tested at all.
