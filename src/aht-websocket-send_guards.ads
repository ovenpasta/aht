with Ada.Finalization;
with Ada.Numerics.Discrete_Random;
with System;

with AHT.Bytes;

--  Serialization of frame writes on one connection, plus the scope
--  guard that pairs taking the latch with giving it back.
--
--  This lives in its own unit rather than inside the client's private
--  part for one reason: its correctness argument is about abort, and
--  an abort-safety claim tested against a hand-written replica of the
--  protocol is not tested at all — the replica can stay correct while
--  the original rots. Here `test_ws_send_guard` drives these exact
--  types, in its own binary so that a hang in a client test cannot
--  stop it running.
package AHT.Websocket.Send_Guards is

   --  Random-byte source for client-side frame masks. RFC 6455 §5.3
   --  doesn't require cryptographic randomness.
   package Random_Bytes is new Ada.Numerics.Discrete_Random
     (AHT.Bytes.Octet);

   --  Acquire / Release_If_Owner serialize the actual socket writes
   --  across tasks (the client's Send_*, the receiver echoing Pong /
   --  Close). The Write is performed *outside* the lock so a slow
   --  socket doesn't hold up the protected region.
   --
   --  Ownership is passed IN and recorded inside the same protected
   --  action that takes the latch, and the release is conditional on
   --  it. That is what makes the pairing survive an abort. A caller
   --  cannot instead record "I hold it" in its own state once Acquire
   --  returns: a pending abort takes effect at the END of the
   --  protected action, before any such assignment, and the release
   --  would then decline to free a latch the task really holds.
   --  Recording it inside leaves no interval at all — a cancelled
   --  acquisition records nothing and its release is a no-op, a
   --  completed one is always matched by its release.
   --
   --  Callers identify themselves by the address of the scope guard
   --  making the call, which is unique among live guards.
   protected type Send_Guard is
      entry     Acquire (Owner : System.Address);
      procedure Release_If_Owner (Owner : System.Address);

      --  Fresh 4-byte mask per frame, drawn under the protected lock
      --  so concurrent senders can't share generator state.
      procedure Random_Mask (Mask : out AHT.Bytes.Byte_Array);

      --  Latched the moment a Close frame is written (by the client's
      --  Close or the receiver's echo). Both Mark_Close_Sent and the
      --  senders' Close_Frame_Sent check run while holding the latch,
      --  so they are serialized with data-frame writes: whoever wins
      --  the Acquire race acts first. A Send_* that loses to a
      --  concurrent close therefore observes Close_Frame_Sent and
      --  raises instead of writing a data frame behind the Close
      --  (RFC 6455 §5.5.1: nothing follows a Close frame).
      procedure Mark_Close_Sent;
      function  Close_Frame_Sent return Boolean;

      --  Observability: whether the latch is held, how many callers
      --  are queued for it, and how many acquisitions have completed.
      --
      --  All three are diagnostics and none is a control primitive.
      --  Waiters reports the queue length at the instant of the
      --  protected read and nothing more: a caller may join or leave
      --  immediately after, so the value is stale as soon as it is
      --  returned and must never gate a decision about who gets the
      --  latch. Acquisitions saturates at
      --  Natural'Last rather than overflowing; it exists so a test can
      --  confirm a handover it arranged really happened without
      --  looking between the release and the abort it is timing
      --  against, since looking there would itself give the other task
      --  a chance to run.
      function  Is_Held return Boolean;
      function  Waiters return Natural;
      function  Acquisitions return Natural;
   private
      Busy       : Boolean := False;
      Taken      : Natural := 0;
      Held_By    : System.Address := System.Null_Address;
      Close_Sent : Boolean := False;
      Gen        : Random_Bytes.Generator;
      Seeded     : Boolean := False;
   end Send_Guard;

   --  Scope guard for one frame write.
   --
   --  Take is deliberately NOT Initialize. Initialize is
   --  abort-deferred (RM 9.8), and blocking inside it makes the caller
   --  UNABORTABLE for as long as the latch is contended — so a close
   --  under an asynchronous select would hang instead of being
   --  cancelled, whenever some other writer were stuck. Measured on
   --  GNAT: an ATC cannot interrupt a queued entry call made from
   --  Initialize, though it interrupts the same call made directly.
   --  Acquiring through a plain call keeps the caller abortable while
   --  it waits, and Finalize — which IS abort-deferred — always runs.
   type Guard_Token (G : access Send_Guard) is
     new Ada.Finalization.Limited_Controlled with null record;

   procedure Take (T : in out Guard_Token);

   --  Bounded acquisition, for callers that must not be outwaited by
   --  whoever currently holds the latch.
   --
   --  Taken is False if it could not be had within `Within`, and then
   --  the token owns nothing: ownership is recorded only by an
   --  acquisition that completed, so its release is a no-op and it is
   --  safe to simply not use the latch. `Within` of 0.0 still takes a
   --  free latch — a timed entry call selects a call it can accept
   --  immediately — so "do not wait" does not mean "do not try".
   procedure Try_Take
     (T      : in out Guard_Token;
      Within : Duration;
      Taken  : out Boolean);

   overriding procedure Finalize (T : in out Guard_Token);

end AHT.Websocket.Send_Guards;
