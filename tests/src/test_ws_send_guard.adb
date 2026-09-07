--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  AHT.Websocket.Send_Guards: the write latch and its scope guard,
--  driven on the production types. Self-contained: no sockets, no
--  fixtures, no client. A failing case leaves a latch permanently
--  held, so this runs ahead of every fixture-dependent WebSocket test
--  and a detected leak stops the run.
--
--  Cases:
--    1. ordinary pairing: Take marks held, Finalize gives it back
--    2. a cancelled acquisition releases nothing
--    3. an aborted acquirer never leaves the latch held
--
--  Covers:
--    - property 2: a caller aborted while queued still runs Finalize,
--      which must not free a latch somebody else holds
--    - property 3 confirms per round, from a counter inside the entry,
--      that the handover happened, so a cancelled call is not a pass
--    - every wait is bounded and every task is aborted on the way
--      out; the runner's per-test cap is the backstop
--
--  Validated by:
--    property 2 fails with an unconditional release in Finalize; the
--    address key is what it checks.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Websocket.Send_Guards;

procedure Test_WS_Send_Guard is

   package Guards renames AHT.Websocket.Send_Guards;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_send_guard: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Bounded spin on an observable fact, so nothing here waits on a
   --  guessed delay and nothing here can hang the suite.
   function Await (Bound : Duration; Ready : access function return Boolean)
      return Boolean
   is
      Waited : Duration := 0.0;
   begin
      while not Ready.all and then Waited < Bound loop
         delay 0.002;
         Waited := Waited + 0.002;
      end loop;
      return Ready.all;
   end Await;

begin
   --  Property 1: ordinary pairing.
   declare
      G : aliased Guards.Send_Guard;
   begin
      if G.Is_Held then
         Fail ("fresh: a new guard reports itself held");
      end if;

      declare
         T : Guards.Guard_Token (G'Access);
      begin
         T.Take;
         if not G.Is_Held then
            Fail ("pairing: the guard is not held after Take");
         end if;
      end;

      if G.Is_Held then
         Fail ("pairing: the guard is still held after the token"
               & " went out of scope");
      end if;
   end;

   --  Property 2: a cancelled acquisition releases nothing.
   declare
      G : aliased Guards.Send_Guard;

      function Queued return Boolean is (G.Waiters = 1);
      Queued_Ref : constant access function return Boolean :=
        Queued'Unrestricted_Access;

      task Waiter is
         entry Go;
      end Waiter;

      task body Waiter is
         T : Guards.Guard_Token (G'Access);
      begin
         accept Go;
         T.Take;              --  never granted: Holder keeps it
         delay 30.0;
      exception
         when others => null;
      end Waiter;

      function Gone return Boolean is (Waiter'Terminated);
      Gone_Ref : constant access function return Boolean :=
        Gone'Unrestricted_Access;

      Holder : Guards.Guard_Token (G'Access);
   begin
      Holder.Take;
      Waiter.Go;

      if not Await (2.0, Queued_Ref) then
         Fail ("cancelled: the waiter never reached the entry queue,"
               & " so nothing was cancelled");
      end if;
      --  Unconditional: the abort is also what unblocks the waiter so
      --  this block can be left at all.
      abort Waiter;

      if not Await (2.0, Gone_Ref) then
         --  Reporting is not enough here. Leaving this block with a
         --  live dependent task blocks at `end`, however tightly the
         --  poll above was bounded, so try harder before giving up.
         abort Waiter;
         if not Await (10.0, Gone_Ref) then
            Fail ("cancelled: the aborted waiter is still running; the"
                  & " scope exit below will block and the runner's"
                  & " per-test cap is what will report it");
         end if;
      end if;

      --  The waiter's token has been finalized by now. It never owned
      --  the latch, so its release must have been a no-op.
      if not G.Is_Held then
         Fail ("cancelled: a caller aborted while queued released the"
               & " holder's latch — the release is not checking who"
               & " owns it");
      end if;
   end;

   --  Property 3: an aborted acquirer never leaves the latch held.
   declare
      Rounds    : constant := 50;
      Leaked    : Natural := 0;
      Sampled   : Natural := 0;
      Cancelled : Natural := 0;
      Broke     : Boolean := False;

      G : aliased Guards.Send_Guard;

      function Queued return Boolean is (G.Waiters = 1);
      Queued_Ref : constant access function return Boolean :=
        Queued'Unrestricted_Access;
   begin
      for I in 1 .. Rounds loop
         declare
            Holder : Guards.Guard_Token (G'Access);

            --  Gated: an ungated task activates at this block's
            --  `begin`, before Holder has taken the latch, and would
            --  acquire it outright instead of queueing behind it.
            task Victim is
               entry Go;
            end Victim;

            task body Victim is
               T : Guards.Guard_Token (G'Access);
            begin
               accept Go;
               T.Take;
               delay 30.0;      --  aborted long before this
            exception
               when others => null;
            end Victim;

            function Gone return Boolean is (Victim'Terminated);
            Gone_Ref : constant access function return Boolean :=
              Gone'Unrestricted_Access;

            Before   : Natural := 0;
            Took_It  : Boolean := False;
         begin
            Holder.Take;
            Victim.Go;

            if not Await (2.0, Queued_Ref) then
               Fail ("handover: round" & I'Image & " never put a"
                     & " waiter on the queue");
               Broke := True;
            else
               Before  := G.Acquisitions;
               Took_It := True;
               --  The release hands the latch to the queued Victim
               --  inside its own protected action; the abort follows
               --  immediately.
               G.Release_If_Owner (Holder'Address);
            end if;

            --  Unconditional, and the only thing that lets this block
            --  be left: a Victim still queued on the latch would
            --  otherwise be waited for forever at scope exit.
            abort Victim;

            if not Await (2.0, Gone_Ref) then
               --  Same as above: a live dependent task blocks the
               --  scope exit no matter what bound we polled with.
               abort Victim;
               if not Await (10.0, Gone_Ref) then
                  Fail ("handover: round" & I'Image & " left an aborted"
                        & " victim running; the scope exit will block"
                        & " and the runner's per-test cap is what will"
                        & " report it");
                  Broke := True;
               end if;
            end if;

            --  Counted inside Acquire, so this shows the handover
            --  happened.
            if Took_It then
               if G.Acquisitions > Before then
                  Sampled := Sampled + 1;
               else
                  Cancelled := Cancelled + 1;
               end if;
            end if;
         end;

         --  Holder gave the latch away above and its Finalize cannot
         --  take it back, so anything still held is the victim's. Stop
         --  at the first one: the next round's Holder.Take would block
         --  on it forever.
         if G.Is_Held then
            Leaked := Leaked + 1;
            Fail ("handover: round" & I'Image & " left the latch held"
                  & " after its acquirer was aborted");
            exit;
         end if;
         exit when Broke;
      end loop;

      --  A run in which every victim was cancelled before acquiring
      --  never exercised the property, and a clean result would mean
      --  nothing.
      if not Broke and then Leaked = 0 and then Sampled = 0 then
         Fail ("handover: none of" & Rounds'Image & " rounds completed"
               & " an acquisition (" & Cancelled'Image & " cancelled)"
               & " — the property was never exercised");
      end if;
   end;

   if Failures = 0 then
      Put_Line ("test_ws_send_guard: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_send_guard:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Send_Guard;
