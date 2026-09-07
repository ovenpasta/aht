--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Containers;
with Ada.Task_Identification;
with Ada.Containers.Bounded_Doubly_Linked_Lists;
with Ada.Strings.Unbounded;

with AHT.Bytes;
with AHT.HTTP.Headers;
with AHT.Transport;
with AHT.Transport.TCP;
with AHT.Transport.TLS;
with AHT.Websocket.Handoffs;
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
   --  Dials URL and runs the opening handshake. Legal from Idle or
   --  Disconnected; raises Handshake_Error from Connecting, Open or
   --  Closing (a live connection is never displaced; use Reconnect).
   --  Raises Mode_Error if delivery is Callback_Only and no
   --  On_Message callback is installed.
   --
   --  Four bounds, each on one stage, all Duration'Last by default:
   --    Resolve_Timeout     the DNS lookup; unused for an IP literal.
   --    Connect_Timeout     the TCP connect, one budget across every
   --                        resolved address.
   --    Handshake_Deadline  the TLS handshake; ignored on ws://.
   --    Upgrade_Deadline    writing the GET and reading the 101;
   --                        cleared once the 101 is validated.
   --  Exhausting any of them raises AHT.Transport.Timeout_Error, not
   --  Handshake_Error. Handshake_Error means the peer answered and
   --  the answer was wrong; Timeout_Error means it did not answer in
   --  time.
   --
   --  A failed or timed-out Connect releases the admission and frees
   --  the half-built session; the client is back where admission
   --  found it and a retry is legal.
   --
   --  Supplying both CA_Path and CA_PEM raises
   --  AHT.Transport.TLS.TLS_Error before dialling; there is no
   --  precedence. Host stays the name for SNI; see AHT.DNS.

   --  How decoded messages reach the application. Callback_Only
   --  never enqueues, so the inbox is not a growth path in that
   --  mode, and it requires an On_Message callback.
   type Delivery_Mode is (Pull_Only, Callback_Only, Both);

   --  Ceilings for one connection. Max_Message_Bytes bounds the
   --  logical message across its fragments, not per frame, and what
   --  is accumulated, not peak RSS. The 32 MiB default covers the
   --  Autobahn section 9 cases.
   type Limits is record
      Max_Message_Bytes  : Natural := 32 * 1024 * 1024;
      Max_Inbox_Messages : Ada.Containers.Count_Type := 1_024;
      Max_Inbox_Bytes    : Natural := 64 * 1024 * 1024;
      Delivery           : Delivery_Mode := Both;
   end record;

   --  Sets what the next connection is built from. Raises Mode_Error
   --  unless fully disconnected: a session's limits are fixed when
   --  it is allocated.
   procedure Configure (Self : in out Client_Type; L : Limits);

   function Is_Open (Self : Client_Type) return Boolean;

   --  Send_Text / Send_Binary / Send_Ping raise Closed_Error if the
   --  connection is not Open. Is_Open is not a precondition: the
   --  receiver can tear the connection down concurrently, so the
   --  check is a runtime guard. Safe to call from a callback.
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
   --  Runs the RFC 6455 sec. 1.4 close handshake: sends our Close
   --  frame unless one was already sent, waits up to Timeout for the
   --  peer's echo, then forces the receiver out via Abort_Pending.
   --  The receiver closes the transport and reclaims the session;
   --  Close returns once that has completed, so it is synchronous
   --  with respect to receiver exit and callbacks.
   --
   --  Timeout bounds the peer's Close echo: 0.0 does not wait,
   --  Duration'Last waits indefinitely. Drain_Timeout bounds our own
   --  receiver's reclamation, which Timeout says nothing about.
   --
   --  On expiry raises AHT.Transport.Timeout_Error. Nothing is
   --  abandoned: the client stays Closing, reclamation continues, and
   --  a later Close joins the same completion. The usual cause is a
   --  callback that has not returned; the receiver cannot reclaim
   --  while inside user code.
   --
   --  Concurrent Close calls are safe: one drives the teardown, the
   --  others wait for the same completion. Must not be called from a
   --  callback; raises Reentrant_Error.
   --
   --  Valid_Close_Code excludes the synthetic 1005/1006/1015.

   --  Re-establishes the connection using the parameters of the last
   --  successful Connect; a failed attempt is never replayed.
   --    Idle          raises Handshake_Error: nothing to repeat.
   --    Disconnected  redials.
   --    Connecting    raises Handshake_Error: an attempt is in flight.
   --    Open/Closing  drains the current connection, then redials.
   --
   --  Timeout and Drain_Timeout are Close's and bound the drain only;
   --  if it does not finish in time this raises Timeout_Error without
   --  redialling, and a later Reconnect joins the teardown.
   --  Resolve_Timeout, Connect_Timeout, Handshake_Deadline and
   --  Upgrade_Deadline are Connect's and bound the redial; they are
   --  per call, not replayed.
   --
   --  Must not be called from a callback; raises Reentrant_Error.
   procedure Reconnect
     (Self               : in out Client_Type;
      Timeout            : Duration := 5.0;
      Drain_Timeout      : Duration := Default_Drain_Timeout;
      Connect_Timeout    : Duration := Duration'Last;
      Handshake_Deadline : Duration := Duration'Last;
      Upgrade_Deadline   : Duration := Duration'Last;
      Resolve_Timeout    : Duration := Duration'Last);


   --  Blocks up to Timeout for the next decoded message. Raises
   --  Closed_Error if the connection has been closed, Timeout_Error
   --  on expiry, and Mode_Error under Callback_Only delivery, where
   --  nothing is ever enqueued. Must not be called from a callback;
   --  raises Reentrant_Error.
   procedure Receive
     (Self    : in out Client_Type;
      Msg     : out Message_Type;
      Timeout : Duration := Duration'Last);

   --  Callbacks fire from the receiver task as frames arrive. Only
   --  On_Message depends on the delivery mode: it fires under Both
   --  and Callback_Only, never under Pull_Only. Under Both, a message
   --  the inbox refuses is not passed to the callback either; one
   --  enqueued but not yet pulled when the connection ends is
   --  discarded with its session (Autobahn case 5.15; see
   --  tests/autobahn/BASELINE.md). Callbacks must be task-safe and
   --  must not block: the receiver cannot reclaim a connection while
   --  inside user code. Exceptions raised in a callback are
   --  swallowed. Callbacks are read afresh per event. Set_On_Message
   --  raises Mode_Error if it would clear the callback while a
   --  Callback_Only connection is in force, admission to teardown.
   procedure Set_On_Message (Self : in out Client_Type; CB : On_Message_Callback);
   procedure Set_On_Close   (Self : in out Client_Type; CB : On_Close_Callback);
   procedure Set_On_Error   (Self : in out Client_Type; CB : On_Error_Callback);

   --  What the peer selected for the connection currently in place,
   --  or "" if there is none or it has been reclaimed.
   function Selected_Subprotocol (Self : Client_Type) return String;

   --  How many connections this client has successfully established.
   --  A failed attempt does not advance it.
   function Generation (Self : Client_Type) return Natural;

private

   --  Per-connection state (RFC 6455 sec. 1.4): Connecting -> Open on
   --  handshake; Open -> Closing on a Close frame sent; * -> Closed
   --  when no more messages will arrive. Closed does not mean the
   --  receiver has exited or the transport is closed: reclamation
   --  runs after it, and Teardown_Pin.Finalize may publish it from
   --  another task. Ctl.Wait_Generation_Done waits for reclamation,
   --  not Wait_Closed. Client_State below is the client-level
   --  lifecycle and outlives any connection.
   type State_Kind is (Connecting, Open, Closing, Closed);

   protected type State_PO is
      procedure Set (S : State_Kind);
      function  Get return State_Kind;
      entry     Wait_Closed;
      --  Moves Open/Closing -> Closing without downgrading a Closed
      --  published concurrently. Already_Closed is True iff the
      --  connection was already Closed; the caller must then skip the
      --  close handshake, since no further Closed will be published.
      procedure Begin_Closing (Already_Closed : out Boolean);
      --  Whichever of the user's Close and the receiver's echo path
      --  gets Should_Send = True emits the Close frame.
      procedure Try_Mark_Local_Close (Should_Send : out Boolean);
   private
      Current      : State_Kind := Connecting;
      Local_Closed : Boolean    := False;
   end State_PO;

   package Message_Lists is new Ada.Containers.Bounded_Doubly_Linked_Lists
     (Message_Type);

   --  Bounded FIFO of decoded messages: the receiver pushes, Receive
   --  pulls. Mark_Closed wakes a parked Receive, which raises
   --  Closed_Error. Capacity bounds the count, Max_Bytes the payload
   --  total.
   protected type Inbox_PO
     (Capacity  : Ada.Containers.Count_Type;
      Max_Bytes : Natural) is
      entry Receive (Msg : out Message_Type);
      --  Non-raising: a full inbox is a policy outcome for the
      --  receiver to act on.
      procedure Try_Push (Msg : Message_Type; Accepted : out Boolean);
      procedure Mark_Closed;
      function  Count return Natural;
      function  Byte_Count return Natural;
   private
      Q            : Message_Lists.List (Capacity);
      --  Updated in the same protected action as the list, only
      --  after an insertion succeeded.
      Queued_Bytes : Natural := 0;
      Closed_F     : Boolean := False;
   end Inbox_PO;

   --  ws:// runs on the TCP transport, wss:// on the TLS transport.
   --  The variant constructs only the one needed; Active in the body
   --  maps Kind to it.
   type Transport_Kind is (Plain_Transport, Secure_Transport);

   --  Everything belonging to one connection, heap-allocated per
   --  generation, with no task inside. Ownership:
   --    Unpublished   the connecting task's; it frees it on failure.
   --    Published     the receiver's; other tasks touch it only under
   --                  a borrow from the controller.
   --    Draining      no new borrows; freed when they reach zero.
   --  The limits are discriminants so Configure cannot move them
   --  under a running receiver.
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

   --  Exactly one caller wins a teardown and is handed a pinned
   --  session; everyone else joins and touches nothing.
   type Teardown_Result is (Won_Teardown, Join_Teardown, No_Session);

   --  No_Callback: Callback_Only delivery with no On_Message would
   --  have no consumer.
   type Admission_Result is (Admitted, Wrong_State, No_Callback);

   --  Everything a Reconnect needs to repeat a connect; deep copies,
   --  so a caller mutating its buffers afterwards changes nothing.
   type Connect_Params is record
      URL          : Ada.Strings.Unbounded.Unbounded_String;
      Extra        : AHT.HTTP.Headers.Map;
      Subprotocols : Ada.Strings.Unbounded.Unbounded_String;
      Origin       : Ada.Strings.Unbounded.Unbounded_String;
      Insecure     : Boolean := False;
      CA_Path      : Ada.Strings.Unbounded.Unbounded_String;
      CA_PEM       : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   --  Snapshot of the installed callbacks. The receiver takes one per
   --  event so it never runs user code while holding the lock.
   type Callbacks is record
      On_Message : On_Message_Callback := null;
      On_Close   : On_Close_Callback   := null;
      On_Error   : On_Error_Callback   := null;
   end record;

   --  The single point of truth for which session may be touched
   --  and by whom. Every field that outlives a connection lives here
   --  under the lock (RM 9.10). Nothing in here blocks: Abort_Pending,
   --  transport Close and callbacks run in tasks, never here.
   protected type Lifecycle_Controller is

      --  Admission. One protected action checks the state, moves to
      --  Connecting, reserves the generation, snapshots the limits
      --  and checks Callback_Only has a callback; only Admitted has
      --  any effect, and Gen is 0 otherwise. The reserved generation
      --  is written through Owner_Gen inside this action: abort takes
      --  effect the moment the action ends, so a record made by the
      --  caller afterwards, or an out parameter's copy-back, can be
      --  skipped. See docs/websocket.md, "Abort safety is structural".
      procedure Begin_Connect
        (P         : Connect_Params;
         Owner_Gen : access Natural;
         Gen       : out Natural;
         L         : out Limits;
         Result    : out Admission_Result);
      --  Builds the attempt's session into Into from inside a
      --  protected action, so an abort finds either nothing allocated
      --  or a complete session the attempt owner will free. A bare
      --  `new` is not abort-safe: an abort inside it leaves an
      --  attached, uninitialized object (AHT.Guarded_New), whose
      --  zero-filled CRITICAL_SECTION hangs Windows finalization. See
      --  docs/websocket.md, "Abort safety is structural".
      procedure Create_Session
        (Into              : access Session_Access;
         Kind              : Transport_Kind;
         Inbox_Capacity    : Ada.Containers.Count_Type;
         Max_Message_Bytes : Natural;
         Max_Inbox_Bytes   : Natural;
         Delivery          : Delivery_Mode;
         Generation        : Positive);
      --  The parameters of the last connect that succeeded. OK is
      --  False before there has been one.
      procedure Saved_Params (P : out Connect_Params; OK : out Boolean);
      --  Public Configure. OK is False unless fully disconnected.
      procedure Set_Pending_Limits (L : Limits; OK : out Boolean);
      --  Must run on every failure after a successful Begin_Connect,
      --  or the client is stranded in Connecting. Returns the client
      --  to where admission found it. No-op unless Gen is the attempt
      --  still in flight: an early generation can be published,
      --  reclaimed and replaced before its connecting frame
      --  finalizes.
      procedure Abandon_Connect (Gen : Positive);
      --  Called from inside the Start rendezvous, so publication is
      --  atomic with the receiver taking ownership: a receiver that
      --  hits instant EOF cannot reclaim an unpublished session.
      procedure Publish (S : Session_Access);
      --  Whether the attempt that reserved Gen handed its session to
      --  the receiver. Publish records the generation inside the Start
      --  rendezvous and inside a protected action, so an abort of the
      --  connecting task cannot lose the record. True once any
      --  generation >= Gen is recorded: an attempt that did not
      --  publish holds admission until its cleanup, so no later
      --  generation can have published first.
      function  Attempt_Handed_Off (Gen : Positive) return Boolean;

      --  Borrowing. The owner never borrows; this is exclusively how
      --  a task that does not own the session gets to touch it.
      procedure Acquire (S : out Session_Access; OK : out Boolean);
      procedure Release;

      --  Teardown. The winner's borrow is granted in the same action
      --  that stops admission, so the session cannot be freed under
      --  it; joiners get a null session and only wait.
      procedure Begin_Teardown
        (S         : out Session_Access;
         Result    : out Teardown_Result;
         By_Caller : Boolean);
      --  Receiver-side, idempotent: stops admission without claiming
      --  a borrow.
      procedure Stop_Admission;
      --  True once a teardown the application asked for is under way.
      --  Abort_Pending wakes only the waiters that exist when it
      --  fires, so the receiver must consult this before any new
      --  transport write, or the write parks with nothing to cancel
      --  it.
      function  Draining_Forced return Boolean;
      --  The memory-safety gate, unbounded: the receiver must not
      --  close or free a session while a borrower is inside it.
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
      --  Whether the caller is the receiver. Recorded once the
      --  receiver has a client to belong to.
      procedure Set_Receiver_Id (Id : Ada.Task_Identification.Task_Id);
      function  Is_Receiver
        (Id : Ada.Task_Identification.Task_Id) return Boolean;

   private
      Cur           : Session_Access := null;
      St            : Client_State   := Idle;
      Leases        : Natural := 0;
      Admitting     : Boolean := False;
      --  Next_Gen is per attempt, never reused, with gaps where
      --  attempts failed; Published_Gen counts connections and is
      --  what Generation reports.
      Next_Gen      : Natural := 0;
      Published_Gen : Natural := 0;
      Done          : Boolean := True;    --  no generation in flight
      Forced        : Boolean := False;
      --  In its own protected type so test_ws_handoff can drive it
      --  directly.
      Handed_Off     : AHT.Websocket.Handoffs.Handoff;
      CBs           : Callbacks;
      Proto         : Ada.Strings.Unbounded.Unbounded_String;
      --  What the next session is built from.
      Pending       : Limits;
      --  Snapshotted by an admitted Begin_Connect and held until the
      --  generation is done, so it answers before any session exists
      --  and through Closing.
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

   --  Persistent per-client task, looping over generations and
   --  blocking at `accept Start or terminate` between them. The
   --  enclosing master awaits it before finalizing its sibling
   --  components (RM 9.3), which keeps `Self'Unchecked_Access` sound;
   --  a task inside the heap session would lose that. Per generation
   --  it reads frames, reassembles messages, handles control frames,
   --  feeds the inbox, fires callbacks and reclaims the session, so
   --  callbacks are serialized across generations. Entry parameters
   --  are named access types (RM 9.5.2).
   task type Receiver_Task is
      entry Start (Owner : Client_Access; Sess : Session_Access);
   end Receiver_Task;

   type Client_Type is tagged limited record
      Ctl      : aliased Lifecycle_Controller;
      Receiver : Receiver_Task;
   end record;

end AHT.Websocket.Client;
