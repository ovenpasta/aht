with Ada.Strings.Unbounded;

with AHT.Bytes;
with AHT.URL;

private with Ada.Real_Time;
private with GNAT.Sockets;

package AHT.Transport.TCP is

   type TCP_Transport is new Transport_Type with private;
   type TCP_Transport_Access is access all TCP_Transport;

   procedure Connect
     (Self            : in out TCP_Transport;
      Host            : String;
      Port            : AHT.URL.Port_Number;
      Connect_Timeout : Duration := Duration'Last);
   --  `Connect_Timeout` is a single total budget for the TCP connect
   --  phase, shared across every address DNS resolves to — not a
   --  per-candidate timeout. If the budget runs out before any
   --  candidate connects, raises `Timeout_Error`. `Duration'Last`
   --  (the default) leaves connect unbounded. DNS resolution itself
   --  is bounded only by the OS, not by this budget.
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

   overriding procedure Close (Self : in out TCP_Transport);
   --  Single-threaded lifecycle reclaim: closes the socket and both
   --  selectors and clears the deadlines. Idempotent and safe to call on a
   --  clean or poisoned object.
   --
   --  Precondition (caller's responsibility, not enforceable here): no other
   --  task may be inside `Read`/`Write`/`Abort_Pending` on this transport
   --  when `Close` runs. GNAT forbids `Close_Selector` while another task is
   --  parked in `Check_Selector`, so a `Close` that races a live reader is a
   --  contract violation — the selector teardown can only be best-effort and
   --  the object is then left permanently non-reusable (see `Used`). For the
   --  concurrent fatal-write case use `Poison` (reader-safe) and defer
   --  `Close` until the reader has exited. `Websocket.Client` follows this:
   --  it waits on the receiver task (`Wait_Closed`) *before* closing the
   --  transport.

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
   --  mid-stream write, *without* freeing OS resources. Sets
   --  `Is_Connected` False and shuts the socket down (waking a reader
   --  parked in `Check_Selector` with EOF, and a writer with EPIPE), but
   --  does NOT `Close_Socket`/`Close_Selector`. Closing the selectors
   --  here would race a concurrent reader still inside `Check_Selector`
   --  (GNAT forbids `Close_Selector` while another task waits on it), so
   --  the FD/selector reclamation is deferred to the single-threaded
   --  lifecycle `Close`. Safe to call while another task is parked in
   --  `Read`/`Abort_Pending` on the same transport — this is the path the
   --  `Write` failure handler and TLS's `Drop_Connection` take.
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
      Deadline_At        : Ada.Real_Time.Time;
      Has_Write_Deadline : Boolean := False;
      Write_Deadline_At  : Ada.Real_Time.Time;
      Connected          : Boolean := False;
      Used               : Boolean := False;
      --  Latched True at the first fully-successful Connect and never
      --  cleared (not even by Close). Makes the transport permanently
      --  single-use: Connect rejects a reused object even if a Close that
      --  raced a parked reader left the ownership bits looking clean. A
      --  failed Connect leaves it False so a fresh attempt can retry.
   end record;

end AHT.Transport.TCP;
