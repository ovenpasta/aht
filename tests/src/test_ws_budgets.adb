--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  AHT.Websocket.Budgets — the close handshake's budget arithmetic.
--
--  Self-contained: no sockets, no client, no fixtures. That is the
--  point. Both of these expressions were wrong once, and neither
--  mistake was reachable from a socket test at a resolution that
--  would not be flaky — one was a fraction of a second on a small
--  timeout, the other a sentinel that only misbehaved later, at
--  conversion time, in a different unit. As arithmetic they are
--  exhaustively checkable, so they are checked here rather than
--  argued about.
--
--  What each table pins:
--
--    Remaining     — the sentinel survives; an exhausted budget
--                    returns zero rather than going negative; an
--                    overspent one is not credit.
--    Close_Frame   — the grace is for a budget of exactly zero and
--                    nothing else, so a positive budget cannot be
--                    topped back up after the latch has eaten it.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Websocket.Budgets;

procedure Test_WS_Budgets is

   package B renames AHT.Websocket.Budgets;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_budgets: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   procedure Check
     (What           : String;
      Got, Expected  : Duration)
   is
   begin
      if Got /= Expected then
         Fail (What & ": got" & Duration'Image (Got)
               & ", expected" & Duration'Image (Expected));
      end if;
   end Check;

begin
   --  Remaining: the unbounded sentinel is not arithmetic.
   Check ("remaining/sentinel-untouched",
          B.Remaining (Duration'Last, 0.000_001), Duration'Last);
   Check ("remaining/sentinel-large-spend",
          B.Remaining (Duration'Last, 3_600.0), Duration'Last);

   --  Remaining: ordinary subtraction.
   Check ("remaining/partly-spent", B.Remaining (2.0, 0.5), 1.5);
   Check ("remaining/untouched",    B.Remaining (2.0, 0.0), 2.0);

   --  Remaining: exhausted and overspent both floor at zero. Going
   --  negative would be read as an enormous budget by anything that
   --  compares it, and overspend is not credit for the next phase.
   Check ("remaining/exact",     B.Remaining (2.0, 2.0), 0.0);
   Check ("remaining/overspent", B.Remaining (2.0, 3.0), 0.0);
   Check ("remaining/zero",      B.Remaining (0.0, 0.0), 0.0);
   Check ("remaining/zero-overspent", B.Remaining (0.0, 1.0), 0.0);

   --  Close_Frame_Budget: zero is the one budget that gets a grace,
   --  because a zero deadline means "fail before parking" rather than
   --  "try once".
   Check ("close-frame/zero-gets-grace",
          B.Close_Frame_Budget (0.0, 0.0), B.Close_Frame_Grace);

   --  ... and nothing else does. A small positive budget gets its own
   --  size, not the grace: treating the grace as a floor would hand a
   --  caller asking for 0.05 a quarter second.
   Check ("close-frame/small-positive-not-raised",
          B.Close_Frame_Budget (0.05, 0.05), 0.05);

   --  The case that matters most: a positive budget already spent
   --  acquiring the latch gets nothing more. A floor here would
   --  refill it, which is the per-phase renewal the compound budget
   --  exists to prevent.
   Check ("close-frame/exhausted-positive-stays-exhausted",
          B.Close_Frame_Budget (2.0, 0.0), 0.0);

   Check ("close-frame/partly-spent", B.Close_Frame_Budget (2.0, 1.5), 1.5);
   Check ("close-frame/unbounded",
          B.Close_Frame_Budget (Duration'Last, Duration'Last),
          Duration'Last);

   --  The two composed the way the client composes them, which is the
   --  only way they are ever used.
   Check ("composed/exhausted-positive",
          B.Close_Frame_Budget (2.0, B.Remaining (2.0, 2.5)), 0.0);
   Check ("composed/zero-budget",
          B.Close_Frame_Budget (0.0, B.Remaining (0.0, 0.0)),
          B.Close_Frame_Grace);
   Check ("composed/unbounded",
          B.Close_Frame_Budget
            (Duration'Last, B.Remaining (Duration'Last, 1.0)),
          Duration'Last);

   if Failures = 0 then
      Put_Line ("test_ws_budgets: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_budgets:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Budgets;
