with Ada.Containers.Doubly_Linked_Lists;
with Ada.Numerics.Discrete_Random;
with Ada.Strings.Unbounded;

with AHT.Bytes;
with AHT.HTTP.Headers;
with AHT.Transport;
with AHT.Transport.TCP;
with AHT.Transport.TLS;

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

   procedure Close
     (Self    : in out Client_Type;
      Code    : Valid_Close_Code := 1000;
      Reason  : String := "";
      Timeout : Duration := 5.0);
   --  Runs the RFC 6455 §1.4 close handshake: send our Close frame
   --  (if we haven't already), then wait up to `Timeout` seconds
   --  for the peer's echo before forcing the receiver out via
   --  the active transport's Abort_Pending. The receiver then owns
   --  the teardown — it closes the transport and reclaims the
   --  session — and Close returns only once that has completed, so
   --  it is synchronous with respect to receiver exit and callbacks.
   --
   --  Timeout knobs (they bound the *close handshake*, not the
   --  reclamation that follows it):
   --    * Default 5.0 s — safe for a cooperating peer on a LAN
   --      / loopback.
   --    * Duration'Last — wait indefinitely (only sensible when
   --      you trust the peer to echo).
   --    * 0.0 — don't wait at all; tear the receiver out via
   --      Abort_Pending immediately. Useful when the caller
   --      already knows the peer is unresponsive.
   --
   --  Concurrent Close calls are safe: one drives the teardown and
   --  the others simply wait for the same completion.
   --
   --  The synthetic codes 1005/1006/1015 are ruled out by the
   --  Valid_Close_Code subtype so they cannot be sent on the wire.

   --  Blocking pull API: blocks up to Timeout for the next decoded message.
   --  Raises Closed_Error if the connection has been closed.
   procedure Receive
     (Self    : in out Client_Type;
      Msg     : out Message_Type;
      Timeout : Duration := Duration'Last);

   --  Push API: callbacks fire from inside the receiver task on
   --  every inbound message / close / fatal error. Both modes
   --  (push + pull) are active simultaneously — Receive still
   --  sees every message and Closed_Error / timeouts still apply.
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
   procedure Set_On_Message (Self : in out Client_Type; CB : On_Message_Callback);
   procedure Set_On_Close   (Self : in out Client_Type; CB : On_Close_Callback);
   procedure Set_On_Error   (Self : in out Client_Type; CB : On_Error_Callback);

   function Selected_Subprotocol (Self : Client_Type) return String;

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

   --  Random-byte source for client-side frame masks. Per-connection
   --  generator state lives in the Send_Guard PO; seeded lazily on
   --  the first Random_Mask call. RFC 6455 §5.3 doesn't require
   --  cryptographic randomness.
   package Random_Bytes is new Ada.Numerics.Discrete_Random
     (AHT.Bytes.Octet);

   protected type Send_Guard is
      --  Acquire / Release serialize the actual socket writes
      --  across tasks (Client.Send_*, Receiver echoing Pong /
      --  Close). The Write is performed *outside* the lock so a
      --  slow socket doesn't hold up the protected region.
      entry Acquire;
      procedure Release;
      --  Fresh 4-byte mask per frame, drawn under the protected
      --  lock so concurrent senders can't share generator state.
      procedure Random_Mask (Mask : out AHT.Bytes.Byte_Array);
      --  Latched the moment a Close frame is written (by Close or the
      --  receiver's echo). Both Mark_Close_Sent and the senders'
      --  Close_Frame_Sent check run between Acquire and Release, so
      --  they are serialized with data-frame writes: whoever wins the
      --  Acquire race acts first. A Send_* that loses to a concurrent
      --  close therefore observes Close_Frame_Sent and raises
      --  Closed_Error instead of writing a data frame behind the Close
      --  (RFC 6455 §5.5.1: nothing follows a Close frame).
      procedure Mark_Close_Sent;
      function  Close_Frame_Sent return Boolean;
   private
      Busy       : Boolean := False;
      Close_Sent : Boolean := False;
      Gen        : Random_Bytes.Generator;
      Seeded     : Boolean := False;
   end Send_Guard;

   package Message_Lists is new Ada.Containers.Doubly_Linked_Lists
     (Message_Type);

   --  FIFO of decoded messages. Receiver pushes; the user's Receive
   --  entry pulls. Mark_Closed flips the barrier so a parked Receive
   --  wakes and raises Closed_Error if the connection went away while
   --  it was blocked.
   protected type Inbox_PO is
      entry Receive (Msg : out Message_Type);
      procedure Push (Msg : Message_Type);
      procedure Mark_Closed;
      function  Count return Natural;
      function  Is_Closed return Boolean;
   private
      Q        : Message_Lists.List;
      Closed_F : Boolean := False;
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
   type Session_Type (Kind : Transport_Kind) is limited record
      State             : State_PO;
      Inbox             : Inbox_PO;
      Guard             : Send_Guard;
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

   type Admission_Result is (Admitted, Wrong_State);

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
      procedure Begin_Connect
        (Gen    : out Natural;
         Result : out Admission_Result);
      --  MUST run on every failure after a successful Begin_Connect,
      --  or the client is stranded in Connecting. The attempt was by
      --  definition unpublished, so the client returns to Idle and
      --  the caller may retry.
      procedure Abandon_Connect;
      --  Called from INSIDE the Start rendezvous, so publication is
      --  atomic with the receiver taking ownership: a receiver that
      --  hits instant EOF cannot begin reclaiming a session the
      --  controller has not yet published.
      procedure Publish (S : Session_Access);

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
      procedure Set_On_Message (CB : On_Message_Callback);
      procedure Set_On_Close   (CB : On_Close_Callback);
      procedure Set_On_Error   (CB : On_Error_Callback);
      function  Current_Callbacks return Callbacks;

      --  Queries, answered without a borrow.
      function  Is_Open return Boolean;
      function  State return Client_State;
      --  Copied out of the session by Publish, so reading it never
      --  races reclamation.
      function  Protocol return String;

   private
      Cur           : Session_Access := null;
      St            : Client_State   := Idle;
      Leases        : Natural := 0;
      Admitting     : Boolean := False;
      --  Two counters, deliberately: a failed attempt consumes a
      --  reserved number without publishing it, so Next_Gen has gaps
      --  while Published_Gen advances only on success.
      Next_Gen      : Natural := 0;
      Published_Gen : Natural := 0;
      Done          : Boolean := True;    --  no generation in flight
      Forced        : Boolean := False;
      CBs           : Callbacks;
      Proto         : Ada.Strings.Unbounded.Unbounded_String;
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
