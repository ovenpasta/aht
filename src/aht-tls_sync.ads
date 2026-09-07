--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Synchronization primitives shared by BOTH TLS backend engines
--  (AHT.Transport.TLS). Neither TLS library permits two tasks inside
--  one connection object, so each backend serializes its engine calls
--  and does all waiting outside the lock; this unit provides the
--  mutex and the coordinator that arbitrates which task performs the
--  single socket read while the other parks. Kept separate from the
--  bodies so the claim/arm/wake/abort behavior is directly unit-
--  testable (test_tls_keyupdate drives it white-box) as well as being
--  exercised end-to-end. See docs/tls.md for the design.
package AHT.TLS_Sync is

   --  Plain mutex as a protected object so callers can do TIMED entry
   --  calls (select ... or delay until ...) — a blocked seize must be
   --  bounded by the seizing operation's deadline.
   protected type Lock_Type is
      entry Seize;
      procedure Release;
   private
      Locked : Boolean := False;
   end Lock_Type;

   type Epoch_Type is mod 2 ** 32;

   --  Feeder-claim arbitration, the single-waiter armed latch, the
   --  EOF/Fatal latches and the abort epoch. At most one task can
   --  ever be parked in Await_Wakeup (the claim owner never waits;
   --  the transport contract allows one reader + one writer), so a
   --  single Armed/Fired pair suffices — and claim-failure + arming
   --  are one protected action, so no event can slip between them.
   protected type Coordinator_Type is

      procedure Try_Claim_Or_Arm (Granted : out Boolean);
      --  Either grants the (unique) feeder claim, or — atomically in
      --  the same protected action — arms the wait latch. A latched
      --  EOF/Fatal pre-fires the latch so the subsequent Await_Wakeup
      --  cannot park past an event that already happened.

      procedure Release_Feeder;
      --  Drops the claim and fires the latch when armed (the waiter
      --  may now claim, or observe whatever state was published).

      entry Await_Wakeup;
      --  Barrier: the latch fired. Clears Armed/Fired on the way out;
      --  the caller re-evaluates ALL state — it never assumes which
      --  event fired. Use a timed entry call bounded by the waiting
      --  operation's deadline, and Disarm on the timeout path.

      procedure Disarm;

      procedure Latch_EOF;
      procedure Latch_Fatal;
      function EOF return Boolean;
      function Fatal return Boolean;

      procedure Bump_Abort;
      --  Fires the latch and advances the epoch. Operations snapshot
      --  the epoch at entry and re-check it after every blocking step
      --  (raising Aborted_Error on change); operations started after
      --  the bump snapshot the new value — non-sticky, matching
      --  Abort_Pending's contract.

      function Abort_Epoch return Epoch_Type;

   private
      Feeder_Claimed : Boolean := False;
      Armed          : Boolean := False;
      Fired          : Boolean := False;
      Is_EOF         : Boolean := False;
      Is_Fatal       : Boolean := False;
      Epoch          : Epoch_Type := 0;
   end Coordinator_Type;

end AHT.TLS_Sync;
