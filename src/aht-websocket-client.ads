with Ada.Containers;
with Ada.Task_Identification;
with Ada.Containers.Bounded_Doubly_Linked_Lists;
with Ada.Strings.Unbounded;

with AHT.Bytes;
with AHT.HTTP.Headers;
with AHT.Transport;
with AHT.Transport.TCP;
with AHT.Transport.TLS;
with AHT.Websocket.Send_Guards;

package AHT.Websocket.Client is

   type Client_Type is tagged limited private;
   type Client_Access is access all Client_Type;

   type Message_Type (Kind : Message_Kind := Binary_Message) is record
      Payload : AHT.Bytes.Buffer;
   end record;

   type On_Message_Callback is access procedure (Msg : Message_Type);
   type On_Close_Callback   is access procedure
     (Info : Close_Info; Reason : String);
   type On_Error_Callback   is access procedure (Message : String);

   procedure Connect
     (Self          : in out Client_Type;
      URL           : String;
      Extra_Headers : AHT.HTTP.Headers.Map;
      Subprotocols  : String := "";
      Origin        : String := "";
      Insecure      : Boolean := False;
      CA_Path       : String := "");

   procedure Connect
     (Self     : in out Client_Type;
      URL      : String;
      Insecure : Boolean := False;
      CA_Path  : String := "");

   --  How decoded messages reach the application.
   --
   --  Callback_Only does not enqueue at all, which is the only mode
   --  that removes the inbox as a growth path outright; the others
   --  keep a bounded queue that Receive drains. It also requires an
   --  On_Message callback, since with none there is no consumer and
   --  every message would be dropped in silence.
   type Delivery_Mode is (Pull_Only, Callback_Only, Both);

   --  Ceilings for one connection. Defaults are policy, not minimums:
   --  32 MiB covers the Autobahn §9 cases (~16 MiB) with room to
   --  spare and matches what the test fixture itself accepts.
   --
   --  Max_Message_Bytes bounds the *logical* message — a fragment
   --  sequence is measured across its parts, not per frame. It bounds
   --  what the library will accumulate, not peak RSS: framing overhead
   --  and copies sit on top.
   type Limits is record
      Max_Message_Bytes  : Natural := 32 * 1024 * 1024;
      Max_Inbox_Messages : Ada.Containers.Count_Type := 1_024;
      Max_Inbox_Bytes    : Natural := 64 * 1024 * 1024;
      Delivery           : Delivery_Mode := Both;
   end record;

   --  Sets what the NEXT connection is built from. Legal only while
   --  fully disconnected; raises Mode_Error during Connecting, Open or
   --  Closing, because every limit becomes an immutable property of a
   --  session at the moment it is allocated. A running connection
   --  therefore cannot have its ceilings moved underneath it, and the
   --  receiver never has to re-read a limit that might have changed
   --  since it last looked.
   procedure Configure (Self : in out Client_Type; L : Limits);

   function Is_Open (Self : Client_Type) return Boolean;

   --  Send_Text / Send_Binary / Send_Ping raise Closed_Error if the
   --  connection is not Open. `Is_Open` is deliberately NOT a
   --  precondition: the receiver task can tear the connection down
   --  concurrently (e.g. the peer closes between the app pulling a
   --  message and echoing it), so the caller cannot guarantee it
   --  across the call. The check is therefore a runtime guard raising
   --  a catchable Closed_Error rather than an Assertion_Error, and it
   --  is expressed as a *borrow*: a sender that cannot borrow the
   --  current session — because none was ever published, or because
   --  teardown has begun — raises instead of touching a session it
   --  does not hold.
   procedure Send_Text
     (Self : in out Client_Type;
      Text : String);

   procedure Send_Binary
     (Self : in out Client_Type;
      Data : AHT.Bytes.Byte_Array);

   procedure Send_Ping
     (Self    : in out Client_Type;
      Payload : AHT.Bytes.Byte_Array := []);

   --  How long a caller waits for its own receiver to finish
   --  reclaiming a connection, once the peer is out of the picture.
   Default_Drain_Timeout : constant Duration := 5.0;

   procedure Close
     (Self          : in out Client_Type;
      Code          : Valid_Close_Code := 1000;
      Reason        : String := "";
      Timeout       : Duration := 5.0;
      Drain_Timeout : Duration := Default_Drain_Timeout);
   --  Runs the RFC 6455 §1.4 close handshake: send our Close frame
   --  (if we haven't already), then wait up to `Timeout` seconds
   --  for the peer's echo before forcing the receiver out via
   --  the active transport's Abort_Pending. The receiver then owns
   --  the teardown — it closes the transport and reclaims the
   --  session — and Close returns only once that has completed, so
   --  it is synchronous with respect to receiver exit and callbacks.
   --
   --  The two bounds measure different things, which is why they are
   --  separate knobs rather than one.
   --
   --  `Timeout` bounds the PEER: how long to wait for its Close echo
   --  before giving up on the handshake and forcing the receiver out.
   --    * Default 5.0 s — safe for a cooperating peer on a LAN
   --      / loopback.
   --    * Duration'Last — wait indefinitely (only sensible when
   --      you trust the peer to echo).
   --    * 0.0 — don't wait at all; tear the receiver out via
   --      Abort_Pending immediately. Useful when the caller
   --      already knows the peer is unresponsive.
   --
   --  `Drain_Timeout` bounds US: how long to wait for our own
   --  receiver to finish reclaiming the session afterwards. Telling
   --  Close not to wait for an unresponsive peer says nothing about
   --  how long our own cleanup may take, so a single knob would make
   --  `Timeout => 0.0` mean "and fail if reclamation is not already
   --  finished", which is not what anyone asking for it wants.
   --
   --  On expiry Close raises `Timeout_Error`. Nothing is abandoned:
   --  the client stays Closing, reclamation continues, and a later
   --  Close joins the same completion. What the bound reports is a
   --  liveness problem, not a safety decision — most often a callback
   --  that has not returned, since the receiver cannot reclaim a
   --  connection while it is inside user code. That is why "callbacks
   --  must not block" is a contract and not advice.
   --
   --  Concurrent Close calls are safe: one drives the teardown and
   --  the others simply wait for the same completion.
   --
   --  The synthetic codes 1005/1006/1015 are ruled out by the
   --  Valid_Close_Code subtype so they cannot be sent on the wire.

   --  Re-establish the connection this client last had, using the
   --  parameters of its last SUCCESSFUL Connect. Reconnect therefore
   --  always means "the connection I had", never "the one I last
   --  asked for" — a failed attempt does not become the thing that
   --  gets replayed.
   --
   --    Idle          raises Handshake_Error: nothing to repeat.
   --    Disconnected  redials.
   --    Connecting    raises Handshake_Error: an attempt is already
   --                  in flight, and this would race it.
   --    Open/Closing  drains the current connection first, then
   --                  redials. This is the one operation that will
   --                  displace a live connection, and it does so
   --                  explicitly rather than silently — Connect
   --                  refuses instead.
   --
   --  The bounds are Close's, and mean the same things: Timeout for
   --  the peer, Drain_Timeout for our own receiver. If the drain does
   --  not finish in time this raises Timeout_Error WITHOUT redialing,
   --  leaving the teardown to continue; a later Reconnect joins it.
   --
   --  Raises Reentrant_Error from inside a callback, for the same
   --  reason Close does.
   procedure Reconnect
     (Self          : in out Client_Type;
      Timeout       : Duration := 5.0;
      Drain_Timeout : Duration := Default_Drain_Timeout);


   --  Blocking pull API: blocks up to Timeout for the next decoded message.
   --  Raises Closed_Error if the connection has been closed, and
   --  Mode_Error under Callback_Only delivery -- where nothing is ever
   --  enqueued, so blocking here would wait on an inbox that by
   --  construction no one will fill.
   procedure Receive
     (Self    : in out Client_Type;
      Msg     : out Message_Type;
      Timeout : Duration := Duration'Last);

   --  Push API: callbacks fire from inside the receiver task as
   --  frames arrive.
   --
   --  Which of them fire depends on the delivery mode, and only
   --  On_Message is affected by it: under Both it fires alongside the
   --  inbox, so Receive still sees every accepted message; under
   --  Callback_Only it is the sole consumer; under Pull_Only it does
   --  not fire at all, even if one is installed. On_Close and
   --  On_Error are not message delivery and fire in every mode.
   --
   --  Under Both, a message the inbox refuses is not passed to the
   --  callback either — pull and push consumers observe exactly the
   --  same accepted set.
   --
   --  Callbacks run on the receiver task, so they must be
   --  task-safe and must not block: the receiver cannot reclaim a
   --  connection while it is inside user code, so a callback that
   --  never returns stalls Close. Exceptions raised inside a
   --  callback are swallowed by the receiver so the task can keep
   --  draining the wire.
   --
   --  The installed callbacks live in the client, not in a
   --  connection, so they are read afresh for every event rather
   --  than captured once.
   --  Set_On_Message raises Mode_Error if it would clear the callback
   --  while a Callback_Only connection is in force -- that is, from
   --  admission through to the end of teardown. Both ends matter: the
   --  gap before publication is where a race could strip the only
   --  consumer from a session already committed to callback delivery,
   --  and during teardown a message may already be decoded and waiting
   --  to be dispatched.
   procedure Set_On_Message (Self : in out Client_Type; CB : On_Message_Callback);
   procedure Set_On_Close   (Self : in out Client_Type; CB : On_Close_Callback);
   procedure Set_On_Error   (Self : in out Client_Type; CB : On_Error_Callback);

   --  What the peer selected for the connection currently in place,
   --  or "" if there is none. It belongs to the connection, not to
   --  the client, so it stops answering once that connection has been
   --  reclaimed rather than lingering until some later one overwrites
   --  it — read it while the connection is up.
   function Selected_Subprotocol (Self : Client_Type) return String;

   --  How many connections this client has successfully established:
   --  0 before the first, then one more on each. Reserved numbers are
   --  not counted, so a failed attempt does not advance it — which is
   --  what makes it usable as "am I looking at the same connection I
   --  was?" across a reconnect.
   function Generation (Self : Client_Type) return Natural;

private

   --  Connection state machine (RFC 6455 §1.4), scoped to ONE
   --  connection.
   --    Connecting → Open    : on successful handshake.
   --    Open       → Closing : on a Close frame sent (locally or
   --                           echoed by the receiver).
   --    *          → Closed  : receiver has exited; no more
   --                           messages will arrive.
   --  Not to be confused with Client_State below, which is the
   --  *client*-level lifecycle and outlives any single connection.
   type State_Kind is (Connecting, Open, Closing, Closed);

   protected type State_PO is
      procedure Set (S : State_Kind);
      function  Get return State_Kind;
      entry     Wait_Closed;
      --  Atomically move Open/Closing -> Closing without ever
      --  downgrading a Closed the receiver published concurrently.
      --  Returns Already_Closed = True iff Current is already Closed
      --  (the receiver has marked the connection closed -- via its
      --  EOF/echo/protocol-failure paths -- and will not touch the
      --  transport again); the caller must then skip the close
      --  handshake, since Wait_Closed is already open and no further
      --  Closed will ever be published.
      procedure Begin_Closing (Already_Closed : out Boolean);
      --  Atomic "did we already send a Close on the wire?". Both
      --  the user-initiated Close path and the receiver's echo
      --  path call this; whichever wins (returns True via the
      --  out parameter) is the one that emits the Close frame.
      procedure Try_Mark_Local_Close (Should_Send : out Boolean);
      function  Local_Close_Sent return Boolean;
   private
      Current      : State_Kind := Connecting;
      Local_Closed : Boolean    := False;
   end State_PO;

   package Message_Lists is new Ada.Containers.Bounded_Doubly_Linked_Lists
     (Message_Type);

   --  Bounded FIFO of decoded messages. Receiver pushes; the user's
   --  Receive entry pulls. Mark_Closed flips the barrier so a parked
   --  Receive wakes and raises Closed_Error if the connection went
   --  away while it was blocked.
   --
   --  Two ceilings, because one does not imply the other: the list's
   --  capacity bounds how many messages are held, and Max_Bytes bounds
   --  how much payload they amount to. A thousand queued megabytes is
   --  as much a runaway as a million queued empties.
   protected type Inbox_PO
     (Capacity  : Ada.Containers.Count_Type;
      Max_Bytes : Natural) is
      entry Receive (Msg : out Message_Type);
      --  Non-raising: a full inbox means the peer is outrunning the
      --  application, which is a policy outcome for the receiver to
      --  act on, not an exception to unwind through it.
      procedure Try_Push (Msg : Message_Type; Accepted : out Boolean);
      procedure Mark_Closed;
      function  Count return Natural;
      function  Byte_Count return Natural;
      function  Is_Closed return Boolean;
   private
      Q            : Message_Lists.List (Capacity);
      --  Maintained in the same protected action as the list itself,
      --  and only ever after an insertion actually succeeded.
      Queued_Bytes : Natural := 0;
      Closed_F     : Boolean := False;
   end Inbox_PO;

   --  ws:// runs on the plain TCP transport, wss:// on the TLS
   --  transport (TLS over the same TCP machinery via custom BIO). The
   --  variant constructs only the one actually needed, instead of one
   --  of each; `Active` in the body maps Kind to the transport, so
   --  there is no stored pointer that could be left stale.
   type Transport_Kind is (Plain_Transport, Secure_Transport);

   --  Everything belonging to ONE connection: heap-allocated per
   --  generation, with NO task inside it. `limited` makes a record
   --  holding protected and controlled components impossible to copy.
   --
   --  Ownership passes through three phases, and this is the whole
   --  memory-safety argument:
   --
   --    Unpublished — the connecting task owns it exclusively; it is
   --                  not reachable from the controller, and that
   --                  task frees it if the attempt fails.
   --    Published   — the receiver owns it. Other tasks may touch it
   --                  only while holding a borrow from the
   --                  controller.
   --    Draining    — still the receiver's, but no new borrows are
   --                  granted; it is freed once the outstanding ones
   --                  reach zero.
   --  The limits are discriminants, not fields, and that is the whole
   --  reason they are here: discriminants are immutable for the life
   --  of the object, so a session carries the ceilings it was built
   --  with and Configure cannot move them underneath a running
   --  receiver. Every one of them is a discrete type, so every one of
   --  them can be a discriminant.
   type Session_Type
     (Kind              : Transport_Kind;
      Inbox_Capacity    : Ada.Containers.Count_Type;
      Max_Message_Bytes : Natural;
      Max_Inbox_Bytes   : Natural;
      Delivery          : Delivery_Mode) is limited record
      State             : State_PO;
      Inbox             : Inbox_PO (Inbox_Capacity, Max_Inbox_Bytes);
      Guard             : aliased AHT.Websocket.Send_Guards.Send_Guard;
      Selected_Protocol : Ada.Strings.Unbounded.Unbounded_String;
      Generation        : Positive := 1;

      case Kind is
         when Plain_Transport =>
            Plain  : aliased AHT.Transport.TCP.TCP_Transport;
         when Secure_Transport =>
            Secure : aliased AHT.Transport.TLS.TLS_Transport;
      end case;
   end record;

   type Session_Access is access Session_Type;

   --  Client-level lifecycle, spanning connections.
   --    Idle         : nothing dialed yet.
   --    Connecting   : an attempt is in flight, nothing published.
   --    Open         : a session is published and borrowable.
   --    Closing      : teardown started, no new borrows granted.
   --    Disconnected : the generation has been fully reclaimed.
   type Client_State is (Idle, Connecting, Open, Closing, Disconnected);

   --  Who drives a teardown. Exactly one caller wins and is handed a
   --  pinned session; everyone else joins and touches nothing.
   type Teardown_Result is (Won_Teardown, Join_Teardown, No_Session);

   --  No_Callback is refused admission for the same reason a full
   --  inbox is refused a message: there would be no consumer, and
   --  silently discarding is not an option the caller could detect.
   type Admission_Result is (Admitted, Wrong_State, No_Callback);

   --  Everything a Reconnect needs to repeat a connect, deep-copied
   --  so a caller mutating its own buffers afterwards cannot change
   --  what gets redialed.
   type Connect_Params is record
      URL          : Ada.Strings.Unbounded.Unbounded_String;
      Extra        : AHT.HTTP.Headers.Map;
      Subprotocols : Ada.Strings.Unbounded.Unbounded_String;
      Origin       : Ada.Strings.Unbounded.Unbounded_String;
      Insecure     : Boolean := False;
      CA_Path      : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   --  Snapshot of the installed callbacks. The receiver takes one per
   --  event so it never runs user code while holding the lock.
   type Callbacks is record
      On_Message : On_Message_Callback := null;
      On_Close   : On_Close_Callback   := null;
      On_Error   : On_Error_Callback   := null;
   end record;

   --  The single point of truth for "which session may be touched,
   --  and by whom". Every field that outlives a connection lives
   --  here, under the protected lock: plain fields written by one
   --  task and read by the receiver would be an unsynchronized
   --  conflicting access (RM 9.10).
   --
   --  Nothing in here may block: Abort_Pending, transport Close and
   --  user callbacks are all performed by tasks, never from a
   --  protected body.
   protected type Lifecycle_Controller is

      --  Admission. One protected action does the state check, the
      --  transition to Connecting and the generation reservation, so
      --  two tasks cannot both be admitted. Gen is Natural rather
      --  than Positive because it must hold a defined value (0) when
      --  admission is refused; only Admitted has any effect.
      --  One protected action does all of it: the state check, the
      --  transition, the generation reservation, the limits snapshot
      --  the session will be built from, and the
      --  Callback_Only-has-a-callback check. Split into a sequence,
      --  Configure would race the state check and Set_On_Message
      --  (null) would race the callback check.
      procedure Begin_Connect
        (P      : Connect_Params;
         Gen    : out Natural;
         L      : out Limits;
         Result : out Admission_Result);
      --  The parameters of the last connect that actually succeeded.
      --  OK is False before there has been one.
      procedure Saved_Params (P : out Connect_Params; OK : out Boolean);
      --  Public Configure. OK is False unless fully disconnected.
      procedure Set_Pending_Limits (L : Limits; OK : out Boolean);
      --  MUST run on every failure after a successful Begin_Connect,
      --  or the client is stranded in Connecting. The attempt was by
      --  definition unpublished, so the client returns to where
      --  admission found it and the caller may retry — and that retry
      --  genuinely works, because it builds a fresh session rather
      --  than re-dialing a transport already latched by the attempt
      --  that failed.
      --
      --  Takes the attempt's reserved generation and does nothing
      --  unless that attempt is still the one in flight. Without that
      --  check a slow cleanup could release an admission belonging to
      --  a LATER Connect: once repeated connects exist, an early
      --  generation can be published, reclaimed and replaced before
      --  its connecting frame finalizes.
      procedure Abandon_Connect (Gen : Positive);
      --  Called from INSIDE the Start rendezvous, so publication is
      --  atomic with the receiver taking ownership: a receiver that
      --  hits instant EOF cannot begin reclaiming a session the
      --  controller has not yet published.
      procedure Publish (S : Session_Access);
      --  Whether the attempt that reserved Gen handed its session to
      --  the receiver. Publish records the generation it published,
      --  from inside the Start rendezvous and inside a protected
      --  action, so the record is atomic with the handoff and cannot
      --  be lost to an abort of the connecting task.
      --
      --  Comparing >= rather than = is what makes it attempt-specific
      --  without keeping a set. Generations are assigned in
      --  increasing order, and an attempt that did NOT publish still
      --  holds admission until its own cleanup releases it -- so no
      --  later generation can have published by the time it asks. A
      --  later generation's number therefore only ever appears here
      --  if this attempt published too.
      function  Attempt_Handed_Off (Gen : Positive) return Boolean;

      --  Borrowing. The owner never borrows; this is exclusively how
      --  a task that does NOT own the session gets to touch it.
      procedure Acquire (S : out Session_Access; OK : out Boolean);
      procedure Release;

      --  Teardown. The winner is handed a pinned session (its borrow
      --  is granted in the same protected action that stopped
      --  admission, so the session cannot be freed under it) and
      --  drives the close handshake. Joiners get a null session and
      --  only wait for completion.
      procedure Begin_Teardown
        (S         : out Session_Access;
         Result    : out Teardown_Result;
         By_Caller : Boolean);
      --  Receiver-side, idempotent: stops admission without claiming
      --  a borrow.
      procedure Stop_Admission;
      --  True once a teardown the *application* asked for is under
      --  way. Abort_Pending is non-sticky — it wakes the waiters that
      --  exist when it fires and nothing more — so the receiver must
      --  consult this before starting any new transport write, or a
      --  write begun after the abort would park with nothing left to
      --  cancel it and the borrow count would never reach zero.
      function  Draining_Forced return Boolean;
      --  The memory-safety gate, deliberately unbounded: the receiver
      --  must not close or free a session while a borrower is still
      --  inside it. A timer here would force a choice between freeing
      --  a live session and leaking one.
      entry     Wait_No_Borrowers;
      procedure Clear_Published;
      procedure Signal_Generation_Done;
      entry     Wait_Generation_Done;

      --  Callback registry. Survives connections; read per event.
      --  OK is False when this would clear the only consumer of a
      --  Callback_Only connection that is already in force.
      procedure Set_On_Message (CB : On_Message_Callback; OK : out Boolean);
      procedure Set_On_Close   (CB : On_Close_Callback);
      procedure Set_On_Error   (CB : On_Error_Callback);
      function  Current_Callbacks return Callbacks;

      --  Queries, answered without a borrow.
      function  Is_Open return Boolean;
      function  State return Client_State;
      function  Generation return Natural;
      --  Copied out of the session by Publish, so reading it never
      --  races reclamation.
      function  Protocol return String;
      --  Whether the caller IS the receiver. The identity is recorded
      --  once the receiver has a client to belong to; before that
      --  nobody can be it.
      procedure Set_Receiver_Id (Id : Ada.Task_Identification.Task_Id);
      function  Is_Receiver
        (Id : Ada.Task_Identification.Task_Id) return Boolean;

   private
      Cur           : Session_Access := null;
      St            : Client_State   := Idle;
      Leases        : Natural := 0;
      Admitting     : Boolean := False;
      --  Two counters, deliberately, and they count different things.
      --  Next_Gen is handed out per ATTEMPT and is never reused, so
      --  it identifies an attempt's cleanup even long after the
      --  attempt is over; it has gaps wherever an attempt failed.
      --  Published_Gen counts CONNECTIONS and has none, which is what
      --  the public Generation reports.
      Next_Gen      : Natural := 0;
      Published_Gen : Natural := 0;
      Done          : Boolean := True;    --  no generation in flight
      Forced        : Boolean := False;
      --  Highest generation ever published; never reset.
      Handed_Off_Gen : Natural := 0;
      CBs           : Callbacks;
      Proto         : Ada.Strings.Unbounded.Unbounded_String;
      --  What the NEXT session is built from.
      Pending       : Limits;
      --  Snapshotted by an admitted Begin_Connect and held until the
      --  generation is done, so it still answers during Connecting --
      --  before any session exists -- and through Closing, while the
      --  receiver may still be dispatching.
      Active_Mode   : Delivery_Mode := Both;
      Rx            : Ada.Task_Identification.Task_Id :=
                        Ada.Task_Identification.Null_Task_Id;
      --  Pending is what the attempt in flight is using; Saved is
      --  what last worked. Publish promotes one to the other, so a
      --  failed attempt never becomes what Reconnect repeats.
      Pending_Conn  : Connect_Params;
      Saved_Conn    : Connect_Params;
      Has_Saved     : Boolean := False;
   end Lifecycle_Controller;

   --  Persistent per-client task: it outlives any single connection,
   --  looping over generations. Blocks at `accept Start or terminate`
   --  between them, which is what keeps the RM 9.3 guarantee that
   --  makes `Self'Unchecked_Access` sound — the enclosing master
   --  awaits this task before finalizing its sibling components. A
   --  heap-owned session containing the task would delete that
   --  language guarantee, so only the passive state moved to the
   --  heap.
   --
   --  Per generation it reads frames off the transport, reassembles
   --  fragmented messages, handles control frames in place, surfaces
   --  complete data messages to the session inbox, fires the push
   --  callbacks, and finally reclaims the session. Because there is
   --  exactly one receiver for the client's whole life, callbacks are
   --  strictly serialized across generations.
   --
   --  Takes a Client_Access plus the session it is to own; RM 9.5.2
   --  forbids anonymous access on entry parameters, and both are
   --  named access types.
   task type Receiver_Task is
      entry Start (Owner : Client_Access; Sess : Session_Access);
   end Receiver_Task;

   type Client_Type is tagged limited record
      Ctl      : aliased Lifecycle_Controller;
      Receiver : Receiver_Task;
   end record;

end AHT.Websocket.Client;
