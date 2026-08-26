with Ada.Real_Time;
with Ada.Strings.Unbounded;

with AHT.Bytes;
with AHT.URL;

private with GNAT.Sockets;

package AHT.Transport.TCP is

   type TCP_Transport is new Transport_Type with private;
   type TCP_Transport_Access is access all TCP_Transport;

   procedure Connect
     (Self            : in out TCP_Transport;
      Host            : String;
      Port            : AHT.URL.Port_Number;
      Connect_Timeout : Duration := Duration'Last;
      Resolve_Timeout : Duration := Duration'Last);
   --  `Connect_Timeout` is a single total budget for the TCP connect
   --  phase, shared across every address DNS resolves to — not a
   --  per-candidate timeout. If the budget runs out before any
   --  candidate connects, raises `Timeout_Error`. `Duration'Last`
   --  (the default) leaves connect unbounded.
   --
   --  `Resolve_Timeout` bounds the DNS lookup that runs *before* it,
   --  via `AHT.DNS` — a separate budget because it is a separate
   --  wait, and because folding it into `Connect_Timeout` would
   --  silently change what that parameter has always meant for
   --  callers already passing one. Exhaustion raises `Timeout_Error`,
   --  distinct from the `Transport_Error` a lookup that *answered*
   --  with no usable address raises: a slow resolver and a bad name
   --  deserve different retry decisions. `Duration'Last` (the
   --  default) leaves resolution unbounded, which is what it was
   --  before this existed.
   --
   --  Neither budget is consulted when `Host` is already an IP
   --  literal for the resolve half — there is nothing to look up.
   --
   --  Resolution goes through `getaddrinfo`, so an `AAAA` answer is
   --  used where one exists; candidates are then tried in the order
   --  the resolver returned them, with the usual fallback.
   --
   --  A transport is **permanently single-use**: once it has been
   --  successfully connected, every later Connect raises `Transport_Error`
   --  — even after `Close`, and even for a still-owning object (live or
   --  poisoned by a fatal `Write`; see `Poison`). It deliberately does NOT
   --  recycle an object in place, because a reader parked in `Read` on the
   --  old session could wake after a new fd was swapped in and read the
   --  wrong connection; latching single-use also closes the window where a
   --  `Close` that raced a parked reader could leave the object *looking*
   --  reusable. To open another connection, use a fresh transport object.
   --  (A Connect that *fails* before establishing a session leaves the
   --  object usable, so a fresh attempt can retry.)

   type Endpoint is record
      Host : Ada.Strings.Unbounded.Unbounded_String;
      Port : AHT.URL.Port_Number := 1;
   end record;

   type Endpoint_List is array (Positive range <>) of Endpoint;

   procedure Connect_Candidates
     (Self            : in out TCP_Transport;
      Endpoints       : Endpoint_List;
      Connect_Timeout : Duration := Duration'Last)
     with Pre => Endpoints'Length > 0;
   --  Each `Host` must already be a numeric IP literal (IPv4 or IPv6);
   --  this entry point skips DNS resolution. Tries each endpoint in
   --  order — on `Socket_Error` from an attempt, closes that socket
   --  and moves on. First success wins. If every attempt fails for a
   --  non-timeout reason, raises `Transport_Error` with the last
   --  error message.
   --
   --  `Connect_Timeout` is one total budget across all candidates (see
   --  `Connect` above); when it runs out, raises `Timeout_Error`
   --  instead. `Duration'Last` leaves the attempts unbounded.
   --
   --  Public so tests can drive the multi-address fallback with an
   --  explicit `[bad, good]` list; `Connect (Host, Port)` above
   --  delegates to this after DNS lookup.

   overriding procedure Write
     (Self : in out TCP_Transport;
      Data : AHT.Bytes.Byte_Array);

   overriding procedure Read
     (Self : in out TCP_Transport;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural);
   --  Concurrency contract: at most ONE task in Read and ONE task in
   --  Write concurrently (the receiver-task-plus-sender shape). Each
   --  direction parks on its own single-waiter selector, so a second
   --  concurrent reader (or writer) is not supported.

   procedure Read
     (Self     : in out TCP_Transport;
      Data     : out AHT.Bytes.Byte_Array;
      Last     : out Natural;
      Deadline : Ada.Real_Time.Time);

   procedure Write
     (Self     : in out TCP_Transport;
      Data     : AHT.Bytes.Byte_Array;
      Deadline : Ada.Real_Time.Time);
   --  Deadline-explicit overloads for callers that must bound ONE
   --  operation by an absolute instant, independent of the compound
   --  deadlines installed via Set_*_Deadline (which are ignored for
   --  that call). Semantics are otherwise identical, including
   --  Abort_Pending and the write-poison rules. Used by the TLS
   --  backends, e.g. to bound a network wait performed on behalf of
   --  the other direction's operation by THAT operation's deadline.

   overriding procedure Close (Self : in out TCP_Transport);
   --  Single-threaded lifecycle reclaim: closes the socket and both
   --  selectors and clears the deadlines. Idempotent and safe to call on a
   --  clean or poisoned object.
   --
   --  Precondition (caller's responsibility, not enforceable here): no other
   --  task may be inside ANY operation on this transport when `Close` runs.
   --  The whole object, as the parent contract in `AHT.Transport` says, and
   --  for the same reason it stopped enumerating. `Close` reclaims the
   --  socket, both selectors and the deadline state; `Poison` reaches the
   --  socket and the selectors; the deadline setters reach the deadline
   --  fields. No single primitive overlaps everything `Close` touches,
   --  which is exactly why naming a few of them reads as a complete list
   --  and is not one.
   --
   --  The sharpest instance is the selector: GNAT forbids `Close_Selector`
   --  while another task is parked in `Check_Selector`, so a `Close` that
   --  races a live reader is a contract violation — the selector teardown
   --  can only be best-effort and the object is then left permanently
   --  non-reusable (see `Used`). For the concurrent fatal-write case use
   --  `Poison` (reader-safe) and defer `Close` until the reader has exited.
   --
   --  `Websocket.Client` follows this, but not by any caller waiting on the
   --  receiver: the receiver closes the transport itself during
   --  reclamation, having first stopped handing out borrows and then
   --  waited, in `Wait_No_Borrowers`, for the outstanding ones to reach
   --  zero. There is a wait — it is just on the borrow count, performed by
   --  the same task that then closes, rather than a handshake between two.

   overriding function Is_Connected (Self : TCP_Transport) return Boolean;

   overriding procedure Set_Read_Deadline
     (Self     : in out TCP_Transport;
      Deadline : Duration);

   overriding procedure Set_Write_Deadline
     (Self     : in out TCP_Transport;
      Deadline : Duration);

   overriding procedure Abort_Pending (Self : in out TCP_Transport);
   --  Calls `Abort_Selector` on the persistent selector created in
   --  `Connect`, unblocking any `Read` or `Write` parked in
   --  `Check_Selector` and causing it to raise `Aborted_Error`. Safe
   --  cross-task.

   procedure Poison (Self : in out TCP_Transport);
   --  Mark a desynchronised/dead connection unusable after a fatal
   --  mid-stream error, *without* freeing OS resources. Sets
   --  `Is_Connected` False, shuts the socket down, and aborts both
   --  selectors so that anything parked in `Check_Selector` wakes; it
   --  does NOT `Close_Socket`/`Close_Selector`. Closing the selectors
   --  here would race a concurrent reader still inside `Check_Selector`
   --  (GNAT forbids `Close_Selector` while another task waits on it), so
   --  the FD/selector reclamation is deferred to the single-threaded
   --  lifecycle `Close`. Safe to call while another task is parked in
   --  `Read`/`Abort_Pending` on the same transport — this is the path the
   --  `Write` failure handler and TLS's `Drop_Connection` take. Note the
   --  second one: `Drop_Connection` fires from read-side fatal paths too,
   --  so the caller is not necessarily the writer and a writer may well
   --  be parked at the time. Both selectors are aborted for that reason.
   --
   --  A `Read` or `Write` woken by this raises `Transport_Error`, not
   --  `Aborted_Error` and not an EOF. The wake can arrive by either
   --  mechanism, so the outcome is decided on `Is_Connected` rather than
   --  on which `Selector_Status` won, and it says the true thing: the
   --  connection was torn down underneath the operation, which is
   --  neither a caller-requested abort nor the peer closing. Its message
   --  says "poisoned after its entry check", distinct from the message
   --  an operation that finds the transport already dead at that check
   --  gets.
   --
   --  The entry check is named because it is the only landmark either
   --  message establishes. In particular:
   --
   --  * The other message does not mean the poison preceded the call.
   --    The caller may have entered, been descheduled, and been
   --    poisoned before it got as far as the check.
   --  * This one does not mean the caller was blocked. `Abort_Selector`
   --    queues an event that the *next* `Check_Selector` consumes just
   --    as happily as a current one, so an operation that passes the
   --    check, loses the CPU, and reaches the selector after the poison
   --    lands gets this message without ever having waited.
   --
   --  A poisoned transport is single-use: it cannot be reconnected in place
   --  (`Connect` rejects it — see above). `Close` it and use a fresh object.

private

   type TCP_Transport is new Transport_Type with record
      Socket             : GNAT.Sockets.Socket_Type := GNAT.Sockets.No_Socket;
      Selector           : GNAT.Sockets.Selector_Type;
      Write_Selector     : GNAT.Sockets.Selector_Type;
      --  A separate selector for the write path. Read and Write can run
      --  concurrently on one transport (e.g. Websocket.Client's receiver
      --  task reads while the owner task writes), and a single
      --  Selector_Type does not support two simultaneous Check_Selector
      --  waiters. Each direction parks on its own selector; Abort_Pending
      --  aborts both. Created/closed together with Selector under
      --  Selector_Open.
      Selector_Open      : Boolean := False;
      Has_Deadline       : Boolean := False;
      Deadline_At        : Ada.Real_Time.Time := Ada.Real_Time.Time_First;
      Has_Write_Deadline : Boolean := False;
      Write_Deadline_At  : Ada.Real_Time.Time := Ada.Real_Time.Time_First;
      Connected          : Boolean := False with Atomic;
      --  Atomic because it is genuinely written by one task and read by
      --  another: `Poison` clears it from whichever task hit the fatal
      --  error, while a reader parked in `Check_Selector` is waiting to
      --  see exactly that. `Read` decides what a wake means by reading
      --  this, so it is a synchronization mechanism and has to be one an
      --  Ada implementation is required to honour -- an ordinary Boolean
      --  read across tasks is not.
      --
      --  The neighbouring flags are NOT atomic, and the difference is
      --  real rather than an oversight. `Selector_Open`, `Used` and the
      --  deadline fields are written only by `Connect` and `Close`, which
      --  the lifecycle contract above already requires to be
      --  single-threaded with respect to this object. `Connected` is the
      --  one flag a *concurrent* operation writes.
      Used               : Boolean := False;
      --  Latched True at the first fully-successful Connect and never
      --  cleared (not even by Close). Makes the transport permanently
      --  single-use: Connect rejects a reused object even if a Close that
      --  raced a parked reader left the ownership bits looking clean. A
      --  failed Connect leaves it False so a fresh attempt can retry.
   end record;

end AHT.Transport.TCP;
