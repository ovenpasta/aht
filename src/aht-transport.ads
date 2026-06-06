with Ada.Finalization;

with AHT.Bytes;

package AHT.Transport is

   pragma Preelaborate;

   type Transport_Type is
     abstract new Ada.Finalization.Limited_Controlled with null record;
   type Transport_Access is access all Transport_Type'Class;

   Transport_Error : exception;
   Timeout_Error   : exception;
   Aborted_Error   : exception;

   procedure Write
     (Self : in out Transport_Type;
      Data : AHT.Bytes.Byte_Array)
   is abstract;
   --  Sends every byte of `Data` or raises. May raise `Timeout_Error`
   --  or `Aborted_Error` on implementations that support the write-side
   --  hooks below (`Set_Write_Deadline` / `Abort_Pending`).
   --
   --  Retry-safety: a `Timeout_Error`/`Aborted_Error` (or `Transport_Error`)
   --  can be raised *after* some bytes have already reached the peer — a
   --  write that fails mid-stream is **not** all-or-nothing on the wire.
   --  Such a failure therefore leaves the request/message partially sent and
   --  is **retry-unsafe** for anything non-idempotent. Implementations that
   --  can desynchronise the stream this way must fail-closed (mark the
   --  connection dead so it is never silently reused — see TCP's `Poison`);
   --  the caller still owns the decision to retry or not.

   procedure Read
     (Self : in out Transport_Type;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural)
   is abstract;
   --  Blocking read: fills `Data` up to its bound or until peer closes;
   --  Last is the index of the last valid byte (0 if nothing was read,
   --  which signals a clean peer close). May raise `Timeout_Error` or
   --  `Aborted_Error` on implementations that support the hooks below.

   procedure Close (Self : in out Transport_Type) is abstract;

   function Is_Connected (Self : Transport_Type) return Boolean is abstract;

   --  Optional read-side deadline / cancel hooks. The default bodies
   --  are no-ops, so implementations that can't enforce them do
   --  nothing and Read blocks indefinitely.

   procedure Set_Read_Deadline
     (Self     : in out Transport_Type;
      Deadline : Duration) is null
     with Pre'Class => Deadline >= 0.0;
   --  Sets a wall-clock budget, measured from this call, for every
   --  subsequent `Read` until it is reset. When the budget elapses,
   --  any `Read` in progress or started thereafter raises
   --  `Timeout_Error`. The budget is **compound** — it is not
   --  refreshed per `Read`, so a slow-drip peer that dribbles one
   --  byte every (Deadline / N) seconds still trips the deadline on
   --  call N+1. Pass `Duration'Last` to clear the deadline (the
   --  default initial state).

   procedure Set_Write_Deadline
     (Self     : in out Transport_Type;
      Deadline : Duration) is null
     with Pre'Class => Deadline >= 0.0;
   --  Write-side parallel of `Set_Read_Deadline`: a **compound**
   --  wall-clock budget, measured from this call, for every subsequent
   --  `Write` until it is reset. When the budget elapses, a `Write` in
   --  progress or started thereafter raises `Timeout_Error`. The default
   --  body is a no-op, so an implementation that can't enforce it leaves
   --  `Write` blocking. Pass `Duration'Last` to clear the deadline (the
   --  default initial state).

   procedure Abort_Pending (Self : in out Transport_Type) is null;
   --  Unblock a Read or Write in progress (typically from another task)
   --  by causing it to raise `Aborted_Error`. Idempotent; safe to call
   --  when nothing is pending.

   overriding procedure Finalize (Self : in out Transport_Type);
   --  Best-effort reclaim of an abandoned transport: dispatches to the
   --  concrete `Close` so a TCP/TLS transport that goes out of scope
   --  without an explicit Close still drops its socket / mbedTLS
   --  contexts. Never raises — any exception from `Close` is swallowed,
   --  because Finalize runs during stack unwinding where a propagating
   --  exception would become Program_Error. Relies on every `Close`
   --  being idempotent, since component/parent finalization can drive a
   --  second Close after an explicit one.
   --
   --  Finalize performs the **full** reclaiming `Close`, not a
   --  poison/shutdown-only path: a poison-only finalizer would leak the
   --  fd, both selectors and (for TLS) the mbedTLS contexts on every
   --  normal scope exit, since nothing else would ever free them. That
   --  means Finalize inherits `Close`'s single-threaded precondition (no
   --  task may be inside Read/Write/Abort_Pending on this transport while
   --  it runs). For the owners in this library that is satisfied
   --  structurally, not by luck:
   --    * Standalone transports (the HTTP client's fresh-per-request
   --      `T`) are used on one task only — no concurrent reader exists at
   --      scope exit.
   --    * For a higher-level owner that runs a *separate* receiver task
   --      against the transport (Websocket.Client), that task is a
   --      **component** of the owner (`Receiver : Receiver_Task`), so Ada
   --      awaits its termination before finalizing the owner's transport
   --      components (RM 9.3 / 7.6.1): the receiver has provably left
   --      Read before this Finalize can run. The owner's own `Close`
   --      additionally joins the receiver (`Wait_Closed`) before closing
   --      the transport, so the explicit path is quiesced too.
   --  A bare `access`-held transport with a detached task reading it would
   --  break this precondition — but no such ownership exists here, and the
   --  task-on-an-`access`-transport shape is not offered by the API.

end AHT.Transport;
