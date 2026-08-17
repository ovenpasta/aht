--  Check_Selector's timeout contract, without a socket.
--
--  The property is one line and cost a Windows hang to learn:
--  GNAT.Sockets.Forever is a sentinel meaning "no timeout at all", not
--  a long duration. A bounded operation handed it parks forever and
--  its Expired branch never runs, so the deadline silently stops
--  existing.
--
--  Pure and fixture-free: it is arithmetic on a subtype bound.

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
   --  The case that produced the bug: "no deadline" spelled as
   --  Duration'Last, handed to a bounded path.
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

   --  That the ceiling is strictly below the sentinel is what makes
   --  the checks above non-vacuous. It holds by construction ('Pred),
   --  so it is asserted at compile time rather than tested -- a
   --  runtime check for it is dead code the compiler already knows
   --  the answer to.
   pragma Assert (W.Longest_Finite < GNAT.Sockets.Forever);

   if Failures = 0 then
      Put_Line ("test_waits: OK (a bounded wait is never the sentinel)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_waits:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_Waits;
