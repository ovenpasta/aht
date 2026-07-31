# WebSocket Reconnect — Design

**Status: temporary implementation artifact, not part of the permanent
documentation set.** Once the work lands, the durable lifecycle and API
rules fold into [`websocket.md`](websocket.md) and this file is
deleted. It is deliberately absent from the README documentation index.

## Why

`Client_Type` is single-use. Every per-connection resource is an inline
component — the `Plain`/`Secure` transports, `State`, `Inbox`, `Guard`,
`Selected_Protocol` — and `Receiver_Task` is a one-shot task that runs
one connection and terminates. `Connect` enforces this with
`if Self.State.Get /= Connecting then raise`.

Two consequences:

1. **No reconnect.** A dropped connection means building a new client
   and reinstalling callbacks.
2. **A live bug.** `Connect` documents that *"A failed Connect leaves
   State = Connecting, so retries on a fresh URL still work"*, and its
   guard permits the retry — but on an HTTP-upgrade failure
   (`Resp.Status /= 101`, or a bad `Upgrade` / `Connection` /
   `Sec-WebSocket-Accept` header) the dial has already succeeded, so
   the inline transport's single-use latch is set. The retry then dies
   inside the transport with `TLS_Error "already connected"` (wss) or
   `Transport_Error` (ws), wrapped into a misleading `Handshake_Error`.
   The documented retry path cannot work.

Both are fixed by making per-connection state per-*generation* and
heap-owned, so every attempt gets fresh transports.

**The constraint that shapes the design:** the receiver task stays an
inline component. `Self'Unchecked_Access` in `Connect` is sound only
because RM 9.3 makes the enclosing master await that task before
finalizing its sibling components. A heap-owned session containing the
task would delete that language guarantee and replace it with
hand-written bookkeeping. So the task stays inline and persistent,
looping over generations; only the passive state moves to the heap.

## Shape

```
Client_Type (all inline, persistent)
├─ Receiver : Receiver_Task        -- persistent, loops over generations
├─ Ctl      : Lifecycle_Controller -- protected: client state, current
│                                     session, borrows, generations,
│                                     callback registry, teardown cause
└─ saved connect parameters (deep copies, last SUCCESSFUL connect)

Session_Type (heap, one per generation, NO task)
├─ State  : State_PO           -- RFC close bookkeeping for THIS connection
├─ Inbox  : Inbox_PO           -- bounded (see Bounds below)
├─ Guard  : Send_Guard
├─ Selected_Protocol
├─ Generation : Positive       -- reserved by Begin_Connect
└─ variant: Plain XOR Secure   -- only the transport actually used
```

```ada
type Transport_Kind is (Plain_Transport, Secure_Transport);

type Session_Type
  (Kind              : Transport_Kind;
   Inbox_Capacity    : Ada.Containers.Count_Type;
   Max_Message_Bytes : Natural;
   Max_Inbox_Bytes   : Natural;
   Delivery          : Delivery_Mode) is limited
record
   State             : State_PO;
   Inbox             : Inbox_PO (Inbox_Capacity, Max_Inbox_Bytes);
   Guard             : Send_Guard;
   Selected_Protocol : Unbounded_String;
   Generation        : Positive;

   case Kind is
      when Plain_Transport =>
         Plain  : aliased AHT.Transport.TCP.TCP_Transport;
      when Secure_Transport =>
         Secure : aliased AHT.Transport.TLS.TLS_Transport;
   end case;
end record;
```

The variant constructs only the transport actually needed, instead of
today's "one of each, always". `limited` makes a session containing
protected and controlled components impossible to copy.

**Every limit is a discriminant, not just the inbox capacity.** All
four are discrete types, so they are legal discriminants and therefore
**immutable for the session's lifetime** — which is exactly the
property needed: `Configure` cannot change a running generation
underneath the receiver, because the running generation holds its own
frozen copy taken at allocation.

`Active : Transport_Access` moves out of the session: with the variant
in place, a small `Active (S)` accessor returning
`Transport_Access` per `Kind` replaces the stored pointer, so there is
no field that can be left dangling or stale across generations.

`State_PO`, `Inbox_PO` and `Send_Guard` move verbatim into
`Session_Type`; their internals and races (`Begin_Closing` /
`Already_Closed`, `Try_Mark_Local_Close`, `Close_Frame_Sent`) are
per-connection concerns and do not change. The *client*-level lifecycle
lives in the controller and must not be conflated with the RFC close
state machine inside a session.

## Ownership phases

A session passes through three phases. Leases govern **borrowers only**
— the owner never takes one.

| Phase | Owner | Who else may touch it | Freed by |
|---|---|---|---|
| **Unpublished** | the connecting task, exclusively | nobody — not reachable from the controller | the connecting task, on failure |
| **Published** | the receiver | public operations, by borrowing a lease | — |
| **Draining** | the receiver, still exclusively | existing borrowers only; no new leases | the receiver, after borrows reach zero |

**Invariants**

- **I1.** A task that does not own the session must hold a lease to
  touch *any* of its components, including its protected objects.
  `Acquire` fails unless `Admitting and Cur /= null`.
- **I2.** `Leases = 0` proves only that **no borrowers remain**. It
  says nothing about the owner, which is by then the receiver
  performing reclamation. Because every borrower holds a lease while
  queued on `Inbox.Receive`, `Guard.Acquire` or `State.Wait_Closed`,
  `Leases = 0` does guarantee no task is queued on a session protected
  object — which is what makes `Free` safe.
- **I3.** Only the receiver closes the transport and frees a
  *published* session. An unpublished session is freed by the
  connecting task.
- **I4.** `Publish` happens inside the `Start` rendezvous, so a
  receiver that hits instant EOF cannot begin reclaiming a session the
  controller has not yet published.
- **I5.** No potentially-blocking operation inside the controller.
  `Abort_Pending` and `Close` on a transport are called by tasks, never
  from a protected body — and neither is a user callback.
- **I6.** Only the task that **wins** teardown is handed a pinned
  session. Losers join without touching it.
- **I7. Forced draining forbids *new* receiver-side transport
  operations.** `Abort_Pending` is explicitly non-sticky: it wakes the
  waiters that exist when it fires and nothing more. Without I7 this
  interleaving hangs the caller:

  ```
  application writer holds Send_Guard, blocked in Write
  receiver takes a Ping, queues on Send_Guard
  Reconnect calls Abort_Pending          -- wakes only the writer
  writer wakes, releases guard and lease
  receiver acquires the guard, starts a NEW Pong write
  that write never saw the abort -> parks
  borrowers never reach zero
  ```

  So every receiver-side send (Pong echo, Close echo) must, **after
  acquiring `Send_Guard` and before latching anything or writing**,
  re-check `Ctl.Draining_Forced` and bail out if set. The order
  matters: the check must precede `Try_Mark_Local_Close`, or the echo
  path consumes the "someone will send the Close" token and then
  declines to send it.

  ```ada
  --  receiver-side echo, corrected order
  Guard.Acquire;
  if Ctl.Draining_Forced then Guard.Release; return; end if;
  State.Try_Mark_Local_Close (Should_Send);   --  latch only after the check
  ...
  ```

Leases are taken and released through a `Limited_Controlled` guard
object, so every exit path — exceptions and the `Receive` timeout
branch included — releases exactly once. This mirrors the feeder
scope-guard in the TLS engines (see [`tls.md`](tls.md)).

## Data structures

We compile with `-gnat2022` on GNAT 15.2.1, so controlled and bounded
structures carry the ownership wherever they genuinely can:

| Purpose | Structure |
|---|---|
| Saved connection settings | inline record of `Unbounded_String` + `AHT.HTTP.Headers.Map` — both finalize themselves |
| Lifecycle state | protected object: enums, counters, callbacks, one **non-owning** session pointer |
| Session | `limited` discriminated record, transport chosen by variant |
| Message inbox | protected FIFO over `Ada.Containers.Bounded_Doubly_Linked_Lists` |
| Message payloads | existing controlled `AHT.Bytes.Buffer` |
| Receive accumulator | `Limited_Controlled` holder freeing its byte array in `Finalize` |
| Borrow lease | `Limited_Controlled` scope guard, releases exactly once |
| Transport ownership | inline in the session; transports already derive from `Limited_Controlled` |
| Session pointer | private access type, allocation/deallocation confined to two paths |

**Why one raw access value survives.** Ada 2022 has no standard
owning pointer (`Box` / `unique_ptr`), and the container `Holders` do
not apply: `Session_Type` is limited and its ownership *crosses tasks*.
Reference counting would be actively misleading here — a count reaching
zero says nothing about whether a task is still executing inside the
transport, which is exactly the property the lease protocol exists to
establish. So the session keeps one private access value, freed in
exactly two auditable places:

- the connecting task frees an **unpublished** failed attempt;
- the receiver frees a **published** session after `Wait_No_Borrowers`.

Every nested resource — transports, protected objects, buffers,
unbounded strings — then finalizes automatically at that single `Free`.
The manual part is deciding *when* deallocation is safe, not freeing
each component.

**Rejected alternative: no heap session at all.** Dialing and the HTTP
upgrade could move into the receiver task, with `Session_Type` declared
in its per-generation block, giving automatic block finalization. That
would need a connect-result rendezvous and would push substantial
synchronous handshake logic into the task. Not worth it to remove one
tightly controlled allocation.

Automatic finalization prevents leaks; it cannot prove cross-task
lifetime safety. The lease/quiescence protocol stays.

## Lifecycle controller

```ada
type Client_State is (Idle, Connecting, Open, Closing, Disconnected);
type Teardown_Result is (Won_Teardown, Join_Teardown, No_Session);

type Callbacks is record
   On_Message : On_Message_Callback := null;
   On_Close   : On_Close_Callback   := null;
   On_Error   : On_Error_Callback   := null;
end record;

protected type Lifecycle_Controller is
   --  Admission. ONE protected action must do all of it, or Configure
   --  races Begin_Connect and callback validation races
   --  Set_On_Message (null). Begin_Connect atomically: checks the
   --  state, transitions to Connecting, RESERVES a generation number
   --  (so the connecting task can stamp it into the session and
   --  Publish never invents one), snapshots the pending limits, and
   --  verifies that Callback_Only has a callback installed. Gen is
   --  Natural, not Positive: it must hold a defined value (0) when
   --  admission is refused.
   type Admission is (Admitted, Wrong_State, No_Callback);
   procedure Begin_Connect
     (Gen    : out Natural;
      L      : out Limits;      --  the snapshot the session is built from
      Result : out Admission);  --  Wrong_State -> Handshake_Error
                                --  No_Callback -> Mode_Error
   --  ONLY Admitted has effects. On Wrong_State and No_Callback every
   --  field is left exactly as it was — in particular St, Next_Gen and
   --  Active_Mode — and Gen comes back 0. A refused admission must not
   --  burn a generation number, move the state machine, or commit a
   --  delivery mode, or a rejected Connect would perturb the very
   --  session it failed to create.
   procedure Set_Pending_Limits (L : Limits; OK : out Boolean);
   --  Public Configure. OK = False unless Idle/Disconnected.
   procedure Abandon_Connect;      --  MUST run on every failure after
                                   --  a successful Begin_Connect
   procedure Publish (S : Session_Access);
   --  Called from INSIDE the handoff rendezvous (I4). Sets
   --  Published_Gen := S.Generation and clears Forced.

   --  Borrowing (public operations)
   procedure Acquire (S : out Session_Access; OK : out Boolean);
   procedure Release;

   --  Teardown (I6). Sets Forced := By_Caller on a win; that single
   --  flag drives BOTH I7's echo gate and the suppression of
   --  Aborted_Error in On_Error.
   procedure Begin_Teardown
     (S         : out Session_Access;
      Result    : out Teardown_Result;
      By_Caller : Boolean);
   --  Won_Teardown  : admission was still open; caller gets a PINNED
   --                  session (lease granted in the same protected
   --                  action that stopped admission) and drives
   --                  steps 3-4 of reclamation.
   --  Join_Teardown : teardown already under way — possibly already
   --                  past Wait_No_Borrowers. S is null; the caller
   --                  MUST NOT touch the session and only waits on
   --                  Wait_Generation_Done.
   --  No_Session    : nothing published.

   procedure Stop_Admission;               --  receiver-side, idempotent
   function  Draining_Forced return Boolean;   --  I7
   entry     Wait_No_Borrowers;                --  barrier: Leases = 0
   procedure Clear_Published;
   procedure Signal_Generation_Done;
   entry     Wait_Generation_Done;

   --  Callback registry (RM 9.10: never plain unsynchronized fields).
   --  Set_On_Message (null) is refused — in the same protected action
   --  that reads the state — while a Callback_Only delivery is in
   --  force: during Connecting, Open AND Closing. Connecting, because
   --  the window between admission and publication is exactly when a
   --  race could strip the only consumer from a session already
   --  committed to callback delivery. Closing, because a message may
   --  already be decoded and waiting to be dispatched when teardown
   --  flips the state, and clearing the callback there would discard
   --  it silently.
   procedure Set_On_Message (CB : On_Message_Callback; OK : out Boolean);
   procedure Set_On_Close   (CB : On_Close_Callback);
   procedure Set_On_Error   (CB : On_Error_Callback);
   function  Current_Callbacks return Callbacks;

   --  Queries / bookkeeping
   function  Is_Open return Boolean;
   function  State return Client_State;
   function  Generation return Natural;   --  = Published_Gen
   procedure Set_Receiver_Id (Id : Task_Id);
   function  Receiver_Id return Task_Id;
private
   Cur           : Session_Access := null;
   St            : Client_State   := Idle;
   Leases        : Natural := 0;
   Admitting     : Boolean := False;
   Next_Gen      : Natural := 0;   --  reserved counter
   Published_Gen : Natural := 0;   --  last successfully published
   Done          : Boolean := True;
   Forced        : Boolean := False;   --  I7 + On_Error suppression
   CBs           : Callbacks;
   Pending       : Limits;             --  what the NEXT session gets
   Active_Mode   : Delivery_Mode := Both;
   --  Snapshotted by Begin_Connect (Admitted only) and held until
   --  Signal_Generation_Done or Abandon_Connect — so it still answers
   --  during Connecting, before any session exists, and through
   --  Closing, while the receiver may still be dispatching.
   Rx            : Task_Id := Null_Task_Id;
end Lifecycle_Controller;
```

**Two generation counters, deliberately.** `Begin_Connect` bumps and
returns `Next_Gen`; `Publish` sets `Published_Gen`. A failed attempt
consumes a reserved number without publishing it, so **reserved numbers
have gaps** while the public `Generation` — which reports
`Published_Gen` — advances only on success. Collapsing them into one
field would make either "increments on Publish" or "stamped before
Publish" false.

**Callbacks live here, not in `Client_Type`.** Plain access-value
fields written by `Set_On_*` and read by the receiver are an
unsynchronized conflicting access (RM 9.10) — tolerable in a
short-lived single-connection object, not in one living across
reconnects. The receiver snapshots them with one `Current_Callbacks`
call **per event, not per generation**, so a setter called at runtime
takes effect from the next event onward; the snapshot exists only to
avoid holding the lock across user code (I5).

## Receiver: persistent, one generation at a time

```ada
task type Receiver_Task is
   entry Start (Owner : Client_Access; Sess : Session_Access);
end Receiver_Task;
```

```ada
loop
   select
      accept Start (Owner, Sess) do
         Conn := Owner; S := Sess;
         Conn.Ctl.Set_Receiver_Id (Current_Task);
         Conn.Ctl.Publish (S);                    --  I4
      end Start;
   or
      terminate;                                  --  RM 9.3
   end select;

   begin
      Run_Session (S);
   exception
      when others => null;   --  never kill the task
   end;

   Reclaim (S);
end loop;
```

**All per-connection receiver state becomes local to `Run_Session`** —
`Stop_Loop`, the receive accumulator and the fragmentation / reassembly
state. Otherwise generation two inherits generation one's terminal
`Stop_Loop` and any half-assembled fragment.

**The accumulator must free itself on exceptional exit.** Today `Buf`
holds a raw `Buf.Data` access freed by an explicit `Free` on the normal
path; moving `Buf` inside `Run_Session` does *not* make that automatic.
Wrap it in a `Limited_Controlled` holder whose `Finalize` deallocates,
so any exit — normal, protocol error, abort, or unexpected exception —
reclaims it.

Because there is exactly one receiver for the client's whole life,
**callbacks are strictly serialized across generations** — an old
session's `On_Close` cannot interleave with a new session's
`On_Message`. That isolation is structural, not a counter check.

### Reclamation — receiver only, unbounded

```
1. exit the receive loop (EOF / protocol error / abort / close echo)
2. Ctl.Stop_Admission                  -- GATE: no new borrows
3. S.State.Set (Closed); S.Inbox.Mark_Closed   -- GATE: wake borrowers
4. S.Active.Abort_Pending              -- best effort
5. Ctl.Wait_No_Borrowers               -- INDEFINITE (see below)
6. S.Active.Close                      -- best effort
7. Ctl.Clear_Published                 -- GATE: before the free
8. Free (S)                            -- best effort
9. Ctl.Signal_Generation_Done
```

Admission stops **before** the inbox and state are marked closed;
reversing them leaves a window in which a fresh lease is granted
against a session whose teardown has begun. Steps 2–4 may already have
been done by a `Won_Teardown` initiator; all three are idempotent. Step
4 is required even on receiver-initiated reclamation (peer failure): a
`Send` parked in `Write` on a dead socket holds a lease, and without it
step 5 waits out the write deadline.

**Step 5 is unbounded, and must be.** It is the memory-safety gate: the
receiver must not close or free the session until borrowers reach zero.
Putting a timer here would force a choice between freeing a session
that a borrower is still inside, or deliberately leaking a live
transport — and it would convert temporary scheduler delay into
permanent failure. Neither is acceptable. Liveness is bounded at the
*caller* instead (below).

**Not every step may swallow exceptions.** Steps 2, 3 and 7 are hard
safety gates and must succeed before reclamation advances: if
`Stop_Admission` silently failed, a new borrower could enter after the
zero-borrower check; if `Clear_Published` silently failed and `Free`
proceeded anyway, `Cur` would dangle. They are plain protected
procedure calls with no failure mode of their own, and they are written
without local handlers so that any surprise propagates rather than
being masked. Only the genuinely best-effort operations — step 4's
`Abort_Pending`, step 6's transport `Close`, and step 8's `Free` — carry
local handlers.

**Caller-initiated aborts are not errors.** When `Forced` is set (the
teardown came from the application), the receiver suppresses
`On_Error` for the resulting `Aborted_Error`. Peer-initiated failures
still fire `On_Error` as today.

### Caller-side completion bound

```
Close / Reconnect:
   Begin_Teardown -> Won_Teardown | Join_Teardown | No_Session
   Won:  mark state/inbox closed, Abort_Pending, release the lease
   both: timed Wait_Generation_Done
         - completes -> (Reconnect) redial
         - expires   -> raise Timeout_Error; client stays Closing;
                        teardown continues in the background
```

The bound belongs here, not in the receiver: expiring it is a
*liveness* report, not a safety decision. Nothing is freed early and
nothing leaks — reclamation simply continues, and a later `Close` or
`Reconnect` gets `Join_Teardown` and waits for the same completion.

The bound is **independent of transport deadlines**: after
`Abort_Pending` those are irrelevant, and the remaining delay is
scheduler latency, `Send_Guard` drainage, or user callback execution.
It is a `Reconnect` parameter with a documented default; `Close` reuses
its existing `Timeout` for this phase as well as for the RFC close
handshake.

## Bounds and backpressure

Two unbounded growth paths exist today and should be closed while the
inbox is being moved into the session anyway:

- The inbox is an unbounded `Doubly_Linked_Lists` and retains **every**
  message even when the application only uses callbacks. It is
  reclaimed eventually, but grows without bound during a long
  connection — and a reconnectable client is meant to hold long ones.
- Frame payload and fragmented-message reassembly have **no size
  ceiling** at all.

```ada
type Delivery_Mode is (Pull_Only, Callback_Only, Both);

type Limits is record
   Max_Message_Bytes  : Natural    := 32 * 1024 * 1024;
   Max_Inbox_Messages : Count_Type := 1_024;
   Max_Inbox_Bytes    : Natural    := 64 * 1024 * 1024;
   Delivery           : Delivery_Mode := Both;
end record;

procedure Configure (Self : in out Client_Type; L : Limits);
```

All four are snapshotted into the session as discriminants at
allocation. `Configure` is legal only while **fully disconnected**
(`Idle` or `Disconnected`) — not during `Connecting` or `Closing`,
where an attempt is already in flight — and raises otherwise.

**Admission is one protected action, not a sequence.** A public
"check the state, then write the limits" would let `Configure` race
`Begin_Connect`, and a separate callback validation would race
`Set_On_Message (null)`. So the pending `Limits` live in the
controller, and `Begin_Connect` does the state check, the transition to
`Connecting`, the generation reservation, the limits snapshot and the
`Callback_Only`-has-a-callback check **in a single protected action**,
returning `Wrong_State` or `No_Callback` so `Connect` can raise
`Handshake_Error` or `Mode_Error` accordingly. That check therefore
lands with the controller in step 2, even though the bounded inbox
itself arrives in step 1b.

### The ceiling must live in the decoder

`Frames.Decode` currently signals "incomplete" (`Last = 0`) until the
**entire declared payload** is buffered
(`src/aht-websocket-frames.adb:366`). So a peer that declares a 4 GB
length makes the receiver accumulate 4 GB before `Decode` ever returns
a frame — and any `Max_Message_Bytes` check applied *after* `Decode`
returns is far too late to bound anything.

The check must therefore happen inside the decoder, at header-parse
time, before waiting for the body:

```ada
type Fragment_State is (Unchecked, No_Message, In_Message);

procedure Decode
  (Input     : Byte_Array;
   Hdr       : out Frame_Header;
   Payload   : out Buffer;
   Last      : out Natural;
   Allowance : Natural        := Natural'Last;
   Fragment  : Fragment_State := Unchecked);
```

**`Unchecked` is the default, and it must be.** Defaulting to
`No_Message` would not preserve existing behavior: `test_ws_frames`
decodes a `Continuation` frame standalone with default parameters and
asserts it succeeds (`tests/src/test_ws_frames.adb:288`), which the
sequencing rule below would turn into `Protocol_Error`. `Unchecked`
skips sequencing validation entirely; the receiver always passes a real
state, so the codec keeps its "decode any single frame in isolation"
contract for tests and other callers.

`Len` is already computed and control frames are already structurally
validated immediately afterwards
(`aht-websocket-frames.adb:334-352`), so the insertion point exists.
Both new defaults reproduce today's behavior exactly, leaving every
existing caller and the codec tests unaffected.

For a fragmented message the receiver passes
`Max_Message_Bytes - accumulated_length`, so the ceiling applies to the
**logical message**, not to each frame independently.

**Checks are ordered: sequencing before size.** Suppose 31 MiB has been
accumulated and a 2 MiB **Text** frame arrives where a `Continuation`
was required. Applying the 1 MiB remaining allowance first yields 1009
and hides the sequencing violation, which is a 1002. So `Fragment` is
passed in and opcode sequencing is validated at header time *first*:

1. `Fragment = In_Message` with a `Text`/`Binary` opcode, or
   `Fragment = No_Message` with `Continuation` → `Protocol_Error`
   (1002). `Fragment = Unchecked` skips this step.
2. only then, the allowance → `Message_Too_Big` (1009).

Control frames are exempt from both — they interleave legally and are
already capped at 125 bytes. The receiver's existing sequencing checks
in `Handle_Frame` stay as defence in depth; the point of moving the
check to header time is precedence plus prompt rejection with no body
buffered.

**Lengths above `Natural'Last` need care.** Today
`aht-websocket-frames.adb:321` raises `Protocol_Error` for a 64-bit
length that cannot be represented, before `Len` exists at all. With a
finite allowance such a frame is really a size-policy failure, so it
should be 1009 — but only when a finite policy is actually in force,
or the default path silently changes meaning:

```ada
if V > Unsigned_64 (Natural'Last) then
   if not Is_Control (Hdr.Op) and then Allowance < Natural'Last then
      raise Message_Too_Big;   --  a finite policy is in force
   else
      raise Protocol_Error;    --  unchanged default behaviour
   end if;
elsif not Is_Control (Hdr.Op) and then Natural (V) > Allowance then
   raise Message_Too_Big;
end if;
```

Note the guard `Allowance < Natural'Last` in the first branch. Checking
the allowance before the representability test — the obvious
ordering — would make a `Natural'Last + 1` length raise
`Message_Too_Big` even at the default allowance, since the comparison
is true there too, quietly changing today's `Protocol_Error`.

Note what the limit does and does not promise: it bounds the logical
payload the library will accumulate. It is not a peak-RSS guarantee —
framing overhead and copies remain on top.

### Inbox

- `Max_Inbox_Messages` becomes the bounded list's capacity;
  `Max_Inbox_Bytes` needs an **explicit queued-byte counter**, since a
  bounded list bounds the count, not the payload bytes.
- Insertion is a **non-raising `Try_Push (Msg; Accepted : out Boolean)`**
  — a full inbox is a policy outcome to act on, not an exception to
  unwind through the receiver.
- Byte-limit checks use **subtraction**
  (`Queued_Bytes > Max_Inbox_Bytes - Msg_Len`) rather than addition, so
  a huge payload cannot overflow the comparison it is meant to fail.
- The queued-byte counter is updated **only after** a successful
  insertion, and decremented in `Receive`, both under the same
  protected action as the list operation.

### Delivery modes

- **`Callback_Only` does not enqueue at all**, removing the growth path
  entirely for push-style applications. `Receive` in that mode raises
  `Mode_Error` (new, alongside `Reentrant_Error`) rather than blocking
  forever on an inbox nothing will fill.
- **`Callback_Only` requires a callback.** With `On_Message` null there
  is no consumer at all, and every message would be silently lost.
  `Begin_Connect` returns `No_Callback` — atomically, in the same
  protected action as the admission check — so `Connect`/`Reconnect`
  raise `Mode_Error`; and `Set_On_Message (null)` is refused while a
  `Callback_Only` delivery is in force, meaning throughout
  **`Connecting`, `Open` and `Closing`**. Both ends matter:
  `Connecting` is the gap between admission and publication, where a
  race could strip the only consumer from a session already committed
  to callback delivery; `Closing` is where a message may already be
  decoded and awaiting dispatch, and clearing the callback would
  discard it silently.
- **`Both` enqueues first, then invokes the callback** — and if
  `Try_Push` is refused, the callback is *not* invoked for that
  message. Pull and push consumers therefore observe exactly the same
  accepted message set. (Today's order, `Inbox.Push` then
  `Fire_On_Message`, is already right; what is new is that a refused
  push suppresses the callback.)

### Failure codes

- **Exceeding `Max_Message_Bytes`** — single frame or accumulated
  across a fragment sequence — closes with **1009 Message Too Big**,
  fires `On_Error`, and tears the session down through normal
  reclamation.
- **Exceeding an inbox bound** is a different failure: the peer is
  outrunning the application. Close with **1008 Policy Violation**.
  Silently dropping messages is not an option — it would corrupt stream
  semantics the caller cannot detect.

**On the defaults.** 32 MiB is a *policy* choice, not a test-imposed
minimum: the current suite only requires 13 MB (`test_ws_echo`), and
Autobahn §9 motivates roughly 16 MiB. It happens to match
`server_ws.py`'s own `max_size=32*1024*1024`, which is a reasonable
place to sit. The values above are starting points to confirm against a
full run plus an Autobahn pass, not to assume.

## Public API

```ada
procedure Connect (...);                          --  both existing overloads

procedure Reconnect
  (Self    : in out Client_Type;
   Timeout : Duration := Default_Teardown_Timeout);

function Generation (Self : Client_Type) return Natural;
```

| | `Connect` | `Reconnect` |
|---|---|---|
| `Idle` | dials | raises (never connected) |
| `Disconnected` | dials | redials saved parameters |
| `Connecting` | raises | raises |
| `Open` / `Closing` | raises — never silently closes a live connection | **drains** the current generation, waits (bounded) for completion, then redials |

- `Generation` returns `Published_Gen`: 0 before the first successful
  connect, advancing on each `Publish`.
- `Send_*` acquire a lease; a refused lease raises `Closed_Error`.
- `Receive` acquires a lease and blocks on **that** session's inbox.
  On reclamation `Mark_Closed` wakes it and it raises `Closed_Error`;
  it can never observe the replacement session's messages.
- `Selected_Subprotocol` **borrows the session for the duration of the
  copy** — reading the value without a lease races reclamation. With no
  published session it returns `""` and never raises.
- `Is_Open` is answered from the controller without a lease.
- `Configure` sets the limits for the **next** session and is legal
  only while fully disconnected (`Idle`/`Disconnected`); it raises
  during `Connecting`, `Open` or `Closing`, since every limit becomes
  an immutable session discriminant at allocation.
- Unread messages die with the old session's inbox. Nothing is
  replayed, and nothing can be: WebSocket offers no exactly-once
  redelivery.

**Failure handling in `Connect`.** Every failure after a successful
`Begin_Connect` — session allocation, the dial, the HTTP upgrade, or
the handoff — must run `Abandon_Connect` and free the (unpublished,
caller-owned) session, or the client is stranded in `Connecting`.

**Saved parameters** come from the last **successful** connect, so
`Reconnect` always means "re-establish the connection I had"; it raises
before any successful connect. URL, extra headers, subprotocols,
origin, `Insecure` and `CA_Path` are deep copies, so a caller mutating
its own buffers cannot change what a later `Reconnect` dials.

### Callback reentrancy

`Close`, `Reconnect` and `Receive` compare
`Ada.Task_Identification.Current_Task` against `Ctl.Receiver_Id` and
raise `Reentrant_Error` when they match: the first two would wait on
`Wait_Generation_Done`, which only the receiver can signal, and
`Receive` would wait for a message only the blocked receiver could
deliver. `Send_*` stay legal from callbacks.

**A callback that never returns stalls teardown.** `Abort_Pending`
cancels transport I/O; it cannot cancel user code. A blocked
`On_Message` keeps the receiver from ever reaching `Reclaim`, so no
receiver-side mechanism can detect it — the **caller-side
`Wait_Generation_Done` bound** is what surfaces it, as a
`Timeout_Error` from `Close`/`Reconnect`. The existing "callbacks must
not block" contract is therefore load-bearing and must be documented as
such.

## Paths

| Path | Behavior |
|---|---|
| **Failed upgrade before handoff** | Session never published. `Connect` closes and frees it directly, `Abandon_Connect` → `Disconnected`. Object immediately reusable — the bug fix. |
| **Dial failure** | Same shape one step earlier; `Abandon_Connect` still runs. |
| **Peer failure** | Receiver's read raises, loop exits, full reclamation, `On_Error` fires. → `Disconnected`. |
| **Graceful close** | `Close` gets `Won_Teardown`, runs the RFC handshake on the pinned session, releases its lease, waits (bounded) on `Wait_Generation_Done`. |
| **Forced reconnect, receiver parked in Read** | `Reconnect` gets `Won_Teardown`, marks the inbox closed, aborts I/O, drops its lease, waits. Receiver wakes with `Aborted_Error`, suppresses `On_Error`, reclaims, signals; only then is the new generation dialed. |
| **Concurrent Close and Reconnect** | One gets `Won_Teardown` and drives it; the other gets `Join_Teardown`, touches nothing, waits for the same completion. A *later* `Reconnect` can likewise join a teardown still running after an earlier caller timed out. |
| **Send concurrent with teardown** | Lease refused (`Closed_Error`), or granted and step 5 waits for it; step 4 plus I7 guarantee it cannot park forever. |
| **Receiver echo racing a forced teardown** | I7: the echo re-checks `Draining_Forced` after acquiring the guard and bails without latching or writing. |
| **Blocked user callback** | Receiver never reaches `Reclaim`; the caller's bounded wait raises `Timeout_Error` and the client stays `Closing`. |
| **Exception during cleanup** | Gates (2, 3, 7) propagate; best-effort steps (4, 6, 8) are locally handled. |
| **Client finalization** | **`Client_Type` stays uncontrolled; `Close` before scope exit remains required.** See below. |

### Why finalization cannot do the teardown

RM 9.3(5) makes *waiting for dependent tasks* the **first** step of
finalizing a master; object finalization — and therefore any
`Client_Type.Finalize` — happens only afterwards. A receiver parked in
`Read` prevents `Finalize` from ever running, so it can never be the
thing that unparks it.

- `Close` (or `Reconnect` then `Close`) before scope exit stands, as
  today. Pre-existing property, not introduced here.
- The receiver's `terminate` alternative covers the safe cases: never
  connected, and idle after a completed reclamation.
- Any future automatic shutdown must be initiated *before* master
  finalization — an explicit `Shutdown` or a supervisor owning the
  client — never `Finalize`.

## Effect on existing tests

- `tests/src/test_ws_echo.adb` case 6 (line 216) genuinely pins
  single-use-after-close and must be **inverted**: the reconnect
  succeeds and carries a new generation.
- `tests/src/test_ws_handshake.adb` case 6 (`Connect` while open) keeps
  raising — unchanged.
- Everything else — close-race case 14, receive timeout, post-close
  `Closed_Error`, ordering, callbacks, large frames, TLS cases — must
  pass untouched. They are the regression net.

## Implementation order

1. **Extract `Session_Type`** as the limited discriminated record with
   the transport variant and the `Active (S)` accessor; make all
   per-connection receiver state local to `Run_Session`, with the
   controlled accumulator holder. Suite passes unchanged.
1b. **Bounds**: the `Decode` allowance parameter and `Message_Too_Big`
   (the only change outside the client, and the one that actually
   bounds memory); bounded inbox with `Try_Push` and the queued-byte
   counter; `Delivery_Mode` including the `Callback_Only`
   missing-callback rule; the `Limits` discriminants. `Configure`'s
   public lifecycle check lands with the controller in step 2.
   Defaults confirmed against the 13 MB echo test and an Autobahn run,
   not assumed.
2. **Controller, borrows, callback registry**; route every public
   operation through them. Still single-use.
3. **Persistent receiver and reclamation**: the loop, the gate /
   best-effort split, the unbounded `Wait_No_Borrowers`, I7's
   forced-teardown re-check in the echo paths.
4. **Allow repeated `Connect`**: admission from `Disconnected`;
   `Abandon_Connect` on every post-`Begin_Connect` failure; add
   `Generation`. Invert `test_ws_echo` case 6.
5. **Saved parameters, `Reconnect`** (drain-then-redial,
   winner/joiner, caller-side bound, caller-teardown suppression),
   reentrancy rejection.
6. **Documentation**: fold the durable rules into `websocket.md`,
   including the now load-bearing "callbacks must not block", and
   delete this file.

Files: `src/aht-websocket-client.ads` / `.adb` carry almost all of it;
`src/aht-websocket.ads` gains `Reentrant_Error`, `Mode_Error` and
`Message_Too_Big`; `src/aht-websocket-frames.ads` / `.adb` gain the
`Allowance` parameter — the only change outside the client package.

## Verification

Every step ends with `bash tests/run_tests.sh` under **both** backends
(`AHT_TLS_BACKEND=openssl` and `=mbedtls`) plus
`bash examples/run_examples.sh`.

New tests, all bounded, both backends:

- `test_ws_reconnect` — reconnect after graceful close; after peer
  drop; after a **failed upgrade** (fixture returns 401, then the same
  object connects successfully); after a **dial failure** (closed port,
  then retry succeeds); after **TLS poisoning** on wss. Assert
  `Generation` advances and `Selected_Subprotocol` resets.
- `test_ws_reconnect_fragment` — force a reconnect **mid-fragment**
  (fixture sends `FIN = 0`, then stalls); the next generation delivers
  a clean message, proving no reassembly state survived.
- `test_ws_reconnect_isolation` — a `Receive` blocked across a forced
  reconnect raises `Closed_Error` and never yields a new-session
  message; unread old-inbox messages discarded; callbacks installed
  once fire for both generations with no old-generation callback after
  the new session opens; a caller-initiated reconnect fires **no**
  `On_Error`.
- `test_ws_reconnect_concurrency` — **exception sets are per scenario,
  deliberately narrow.** Against a *stable stalled fixture* with forced
  teardown, only `Closed_Error` (admission refused) or `Aborted_Error`
  (in-flight write cancelled) are acceptable; `Transport_Error` and
  `TLS_Error` are **rejected** there, since accepting them would hide
  premature transport closure or session poisoning. Those two are
  admissible only in the separate cases that deliberately introduce
  peer/socket/TLS failure. Never `Program_Error`, `Storage_Error` or a
  hang.
- `test_ws_reconnect_echo_race` — the I7 probe: an application writer
  blocked in `Write` **and** a receiver queued on `Send_Guard` to emit
  a Pong or Close echo, then a forced `Reconnect`. Must complete within
  the caller's bound; a regression manifests as `Timeout_Error`.
- `test_ws_reconnect_reentrancy` — `Close`/`Reconnect`/`Receive` from
  inside `On_Message`/`On_Close`/`On_Error` raise `Reentrant_Error`
  promptly; `Send_Text` from a callback still works.
- `test_ws_reconnect_blocked_callback` — an `On_Message` that blocks
  past the bound: `Reconnect` raises `Timeout_Error`, the client stays
  `Closing`, and once the callback returns a later `Reconnect` joins
  the completing teardown and succeeds.
- `test_ws_reconnect_leak` — 50 reconnect cycles, task and fd counts
  stable (read `/proc/self/fd` on Linux, skip elsewhere).
- `test_ws_limits` — the decisive case is a fixture that sends **only a
  huge-length header** and then holds the socket open, sending no body
  at all: rejection must be **prompt** with 1009, which is only
  possible if the check lives in the decoder. A post-hoc check would
  hang there instead, so this test distinguishes the two designs.
  Also: a fragment sequence crossing the ceiling closes with 1009
  mid-sequence; flooding a non-draining `Pull_Only` client past
  `Max_Inbox_Messages` or `Max_Inbox_Bytes` closes with 1008;
  `Callback_Only` delivers via callback while `Inbox.Count` stays 0 and
  `Receive` raises `Mode_Error`; `Connect` in `Callback_Only` with no
  `On_Message` raises `Mode_Error`; `Configure` raises while
  connecting, open or closing.
- `test_ws_frames` gains decoder-level cases (pure, no fixture): a data
  frame declaring more than the allowance raises `Message_Too_Big` from
  the header alone; a control frame is never subject to the allowance;
  a declared length of `Natural'Last + 1` raises `Message_Too_Big`
  under a finite allowance but today's `Protocol_Error` under the
  default; a `Text` frame arriving with `Fragment => In_Message` raises
  `Protocol_Error` **even when it also exceeds the allowance** (the
  precedence case); and both parameters at their defaults reproduce
  today's behavior exactly — including case 8's standalone
  `Continuation` decode, which is what forces `Unchecked` to be the
  default rather than `No_Message`.

Each new test is validated the way the TLS fault tests were: back the
relevant guard out, confirm the test fails, restore it.

## Risks

- **Borrow deadlock** remains the main hazard, and I7 is the subtlest
  part of it: any receiver-side transport operation that can *start*
  after `Abort_Pending` has fired reintroduces it.
  `test_ws_reconnect_echo_race` is the probe. Note the failure mode is
  now a caller `Timeout_Error` rather than a hang, which makes it
  observable in tests instead of wedging the suite.
- **`Close` semantics drift**: the existing `Begin_Closing` /
  `Already_Closed` handling must move into the session verbatim, and
  the I7 re-check must not disturb the `Try_Mark_Local_Close` race.
  `test_ws_handshake` case 14 guards it.
- **The caller bound is a liveness knob, not a safety one.** Setting it
  too low only produces spurious `Timeout_Error`s: teardown continues,
  nothing is freed early, and a later `Close`/`Reconnect` joins it.
- **Default limits are a compatibility surface.** They are the one
  change here that can break a working application silently (a message
  that used to arrive now closes the connection with 1009). The
  existing suite plus an Autobahn run are the guard; a default below
  the 16 MiB §9 cases would fail them, which is the intended tripwire.

## Out of scope

Automatic reconnect — retry policy, delays, exponential backoff with
jitter, attempt limits, retryable-closure classification,
reconnecting/reconnected callbacks — belongs in a later managed-client
layer driven by its own supervisor task, never from `On_Error`, which
runs on the receiver. Authentication failures and caller-initiated
`Close` should not retry by default.
