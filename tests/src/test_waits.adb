--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Check_Selector's timeout contract, without a socket: Waits.Bounded
--  never returns GNAT.Sockets.Forever, the sentinel for "no timeout"
--  that would park a bounded operation forever and skip its Expired
--  branch. Pure and fixture-free; arithmetic on a subtype bound.
--
--  Cases:
--    Duration'Last handed to a bounded path comes back finite.
--    Values at or past the finite ceiling, the sentinel included, too.
--    Ordinary values pass through unchanged.
--    Zero and negative collapse to Immediate.
--
--  Does not cover:
--    - the Expired branches in AHT.Transport.TCP rechecking the
--      absolute deadline and re-parking instead of raising; reverting
--      either recheck leaves this test green. That branch runs when a
--      remaining budget exceeds Longest_Finite: never on Linux
--      (Duration'Pred (Duration'Last)), after about 49.7 days on
--      Windows. It rests on the structural argument that an expired
--      chunk is not the deadline and the code asks Clock first.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with GNAT.Sockets;
with AHT.Transport.Waits;

procedure Test_Waits is
   package W renames AHT.Transport.Waits;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_waits: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   procedure Never_Sentinel (What : String; D : Duration) is
      R : constant GNAT.Sockets.Selector_Duration := W.Bounded (D);
   begin
      if R = GNAT.Sockets.Forever then
         Fail (What & ": mapped to Forever, which Check_Selector reads "
               & "as no timeout at all — the deadline would stop "
               & "existing and the caller would park indefinitely");
      end if;
   end Never_Sentinel;

begin
   --  "No deadline" spelled as Duration'Last, handed to a bounded
   --  path.
   Never_Sentinel ("duration-last", Duration'Last);

   --  Anything at or past the finite ceiling, including the sentinel
   --  itself.
   Never_Sentinel ("at-forever", GNAT.Sockets.Forever);
   Never_Sentinel ("at-ceiling", W.Longest_Finite);

   --  Ordinary values pass through unchanged.
   if W.Bounded (5.0) /= 5.0 then
      Fail ("ordinary: 5.0 came back as"
            & Duration'Image (W.Bounded (5.0)));
   end if;

   --  Zero and negative collapse to Immediate; there is nothing to
   --  wait for and a negative would be outside the subtype.
   if W.Bounded (0.0) /= GNAT.Sockets.Immediate then
      Fail ("zero: did not map to Immediate");
   end if;
   if W.Bounded (-1.0) /= GNAT.Sockets.Immediate then
      Fail ("negative: did not map to Immediate");
   end if;

   --  The checks above are non-vacuous only if the ceiling is strictly
   --  below the sentinel; 'Pred guarantees it, so this is an assertion,
   --  not a Fail case. GNAT folds it statically. The debug test build
   --  enables assertions (-gnata); release does not.
   pragma Assert (W.Longest_Finite < GNAT.Sockets.Forever);

   if Failures = 0 then
      Put_Line ("test_waits: OK (a bounded wait is never the sentinel)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_waits:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_Waits;
