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
   --  precondition: the receiver task can move the connection to
   --  Closing/Closed concurrently (e.g. the peer closes between the
   --  app pulling a message and echoing it), so the caller cannot
   --  guarantee it across the call. The check is therefore a runtime
   --  guard raising a catchable Closed_Error rather than an
   --  Assertion_Error, and it also keeps a never-connected Client from
   --  dereferencing its null `Active` transport.
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
   --  the active transport's Abort_Pending and tearing that
   --  transport (TCP for ws://, TLS for wss://) down.
   --
   --  Timeout knobs:
   --    * Default 5.0 s — safe for a cooperating peer on a LAN
   --      / loopback.
   --    * Duration'Last — wait indefinitely (only sensible when
   --      you trust the peer to echo).
   --    * 0.0 — don't wait at all; tear the receiver out via
   --      Abort_Pending immediately. Useful when the caller
   --      already knows the peer is unresponsive.
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
   --  task-safe and should not block (a slow callback delays
   --  every subsequent inbound frame for this connection).
   --  Exceptions raised inside a callback are swallowed by the
   --  receiver so the task can keep draining the wire.
   procedure Set_On_Message (Self : in out Client_Type; CB : On_Message_Callback);
   procedure Set_On_Close   (Self : in out Client_Type; CB : On_Close_Callback);
   procedure Set_On_Error   (Self : in out Client_Type; CB : On_Error_Callback);

   function Selected_Subprotocol (Self : Client_Type) return String;

private

   --  Connection state machine (RFC 6455 §1.4).
   --    Connecting → Open    : on successful handshake.
   --    Open       → Closing : on a Close frame sent (locally or
   --                           echoed by the receiver).
   --    *          → Closed  : receiver has exited; no more
   --                           messages will arrive.
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

   --  Random-byte source for client-side frame masks. Per-Client
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

   --  Bounded-ish FIFO of decoded messages. Receiver pushes; the
   --  user's Receive entry pulls. Mark_Closed flips the barrier so
   --  a parked Receive wakes and raises Closed_Error if the
   --  connection went away while it was blocked.
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

   --  Per-connection task. Auto-started when Client_Type is
   --  elaborated; blocks at `accept Start or terminate` until
   --  Connect kicks it off after a successful handshake. Reads
   --  frames off the transport, reassembles fragmented messages,
   --  handles control frames in place, surfaces complete data
   --  messages to the Inbox, and fires the push-mode callbacks
   --  (Owner.On_Message / On_Close / On_Error) if the user
   --  installed any. Takes a single Client_Access so the body
   --  has access to every component plus the callback slots —
   --  RM 9.5.2 forbids anonymous access on entry parameters,
   --  but Client_Access is a named access already declared
   --  publicly.
   task type Receiver_Task is
      entry Start (Owner : Client_Access);
   end Receiver_Task;

   type Client_Type is tagged limited record
      --  ws:// runs on the plain TCP transport, wss:// on the TLS
      --  transport (TLS over the same TCP machinery via custom BIO).
      --  Both are inline (not heap) so the Client owns its transport
      --  for its full lifetime with no finalization bookkeeping;
      --  Connect dials exactly one per scheme and points `Active` at
      --  it, and everything downstream (receiver, senders, Close)
      --  goes through `Active` polymorphically. `Active` stays null
      --  until a successful dial, so a never-Connect'd Client never
      --  dereferences it.
      Plain              : aliased AHT.Transport.TCP.TCP_Transport;
      Secure             : aliased AHT.Transport.TLS.TLS_Transport;
      Active             : AHT.Transport.Transport_Access := null;
      State              : aliased State_PO;
      Inbox              : aliased Inbox_PO;
      Guard              : aliased Send_Guard;
      Receiver           : Receiver_Task;
      Open               : Boolean := False;
      Selected_Protocol  : Ada.Strings.Unbounded.Unbounded_String;
      On_Message         : On_Message_Callback := null;
      On_Close           : On_Close_Callback   := null;
      On_Error           : On_Error_Callback   := null;
   end record;

end AHT.Websocket.Client;
