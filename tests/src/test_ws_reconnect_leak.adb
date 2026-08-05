--  Reconnecting many times over, watching the process rather than the
--  client.
--
--  Every generation allocates a session, a pair of transports and the
--  file descriptors under them, and every generation is supposed to
--  give all of it back. Nothing in the client's own API can show that
--  it does: Generation counts connections, not resources, and a client
--  that leaked one descriptor per cycle would keep answering every
--  question correctly right up until the process ran out.
--
--  So this counts from outside, in /proc. One leaked descriptor is
--  invisible; fifty is unmistakable, and that is the whole reason the
--  cycle count is what it is.
--
--  Two shapes, because they leak differently:
--
--    1. One client, many generations, driven by Reconnect — which is
--       the operation the plan asked to be cycled. The connection is
--       never closed in between: each Reconnect drains the live one
--       and redials from the saved parameters. That covers the
--       drain-and-redial path and the parameter copying that goes
--       with it, neither of which a Connect/Close loop reaches. The
--       receiver task is persistent here — it outlives every session
--       it runs — so anything this finds is per-session: a transport
--       not closed, a session not freed, an fd left behind by
--       reclamation.
--
--       Note what running that path does NOT buy. Reconnect copies
--       the saved parameters on every redial, and a copy that
--       accumulated would be ordinary heap growth — invisible to
--       both counters here, since neither a descriptor nor a thread
--       is involved. The path is exercised, and a leak of anything
--       the OS accounts for is caught; plain memory is not, and this
--       test should not be read as covering it.
--
--    2. Many clients, one generation each. Here the receiver task
--       itself is created and terminated every cycle, so this is the
--       one that would catch a receiver that never exits — which
--       shows up as a thread count that climbs and, eventually, as a
--       process that will not terminate at all.
--
--  Linux-only: it reads /proc/self/fd and /proc/self/task. Elsewhere
--  it SKIPs rather than pretending to check something.

with Ada.Command_Line;
with Ada.Directories;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.Websocket;
with AHT.Websocket.Client;

procedure Test_WS_Reconnect_Leak is

   Echo : constant String := "ws://127.0.0.1:8765/";

   --  Enough that a one-per-cycle leak clears any plausible noise
   --  floor, and few enough that the whole thing stays well inside the
   --  runner's per-test cap.
   Cycles : constant := 50;

   --  Cycles run before the baseline is taken. The first connection
   --  through a backend pulls in whatever that backend allocates once
   --  and keeps — TLS contexts, the runtime's own bookkeeping — and
   --  charging that to the measurement would make the baseline
   --  unrepeatable. Three is more than enough to reach steady state
   --  while still leaving the count honest.
   Warmup : constant := 3;

   --  What the counts are allowed to move by.
   --
   --  Not zero, and not a guess. A live session costs about five
   --  descriptors — measured, by backing out the receiver's Free and
   --  watching this test report 250 across 50 cycles — so a single
   --  session still winding down when the sample is taken moves the
   --  count by that much on its own. Anything at or below two such
   --  stragglers is therefore not evidence of a leak.
   --
   --  What separates the two cases is the factor of Cycles: a leak of
   --  one session per iteration lands at 250, twenty times this bound.
   --  There is no plausible reading in which noise reaches that and no
   --  plausible leak that hides under it.
   Slack : constant := 12;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_reconnect_leak: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function To_String (V : AHT.Bytes.Buffer) return String is
     (AHT.Bytes.To_String (V));

   --  Entries in a /proc directory, minus . and ..
   --
   --  The search itself holds a descriptor open while it runs, so the
   --  count includes one that is not a leak. That is fine and is the
   --  reason this is only ever compared against another call to
   --  itself: the bias is identical in the baseline and in the final
   --  sample, so it cancels.
   function Count_Entries (Path : String) return Natural is
      use Ada.Directories;
      S : Search_Type;
      D : Directory_Entry_Type;
      N : Natural := 0;
   begin
      Start_Search (S, Path, "");
      while More_Entries (S) loop
         Get_Next_Entry (S, D);
         declare
            Nm : constant String := Simple_Name (D);
         begin
            if Nm /= "." and then Nm /= ".." then
               N := N + 1;
            end if;
         end;
      end loop;
      End_Search (S);
      return N;
   end Count_Entries;

   function Have_Proc return Boolean is
     (Ada.Directories.Exists ("/proc/self/fd")
      and then Ada.Directories.Exists ("/proc/self/task"));

   --  One full connection: dial, prove it works, tear it down. The
   --  round-trip matters — a Connect that returned without a usable
   --  connection would allocate less, and could hide a leak by never
   --  reaching the code that leaks.
   procedure Round_Trip
     (What : String;
      C    : in out AHT.Websocket.Client.Client_Type;
      Text : String)
   is
      Msg : AHT.Websocket.Client.Message_Type;
   begin
      AHT.Websocket.Client.Send_Text (C, Text);
      AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);
      if To_String (Msg.Payload) /= Text then
         Fail (What & ": echoed """ & To_String (Msg.Payload)
               & """, expected """ & Text & """");
      end if;
   end Round_Trip;

   --  One full connection, dialled and torn down. Used by shape 2,
   --  where the point is that the client itself comes and goes.
   procedure Cycle
     (What : String;
      C    : in out AHT.Websocket.Client.Client_Type;
      Text : String)
   is
   begin
      AHT.Websocket.Client.Connect (C, Echo);
      Round_Trip (What, C, Text);
      AHT.Websocket.Client.Close (C);
   end Cycle;

   --  One generation replaced by the next, with no Close in between.
   --  The round-trip matters as much as the redial: it proves the new
   --  connection is real, so a Reconnect that quietly did nothing
   --  cannot pass for a clean cycle.
   procedure Redial
     (What : String;
      C    : in out AHT.Websocket.Client.Client_Type;
      Text : String)
   is
   begin
      AHT.Websocket.Client.Reconnect (C);
      Round_Trip (What, C, Text);
   end Redial;

   procedure Check
     (What     : String;
      Before   : Natural;
      After    : Natural;
      Resource : String)
   is
   begin
      if After > Before + Slack then
         Fail (What & ": " & Resource & " went from"
               & Natural'Image (Before) & " to" & Natural'Image (After)
               & " across" & Natural'Image (Cycles)
               & " cycles — a growth of"
               & Natural'Image (After - Before)
               & " where at most" & Natural'Image (Slack)
               & " is noise");
      end if;
   end Check;

begin
   if not Have_Proc then
      Put_Line ("test_ws_reconnect_leak: SKIP (no /proc; "
                & "fd and task counts are not observable here)");
      Ada.Command_Line.Set_Exit_Status (0);
      return;
   end if;

   --  Shape 1: one client, many generations. The receiver persists,
   --  so anything that grows here is per-session.
   declare
      C : AHT.Websocket.Client.Client_Type;
      FD_Before, FD_After     : Natural;
      Task_Before, Task_After : Natural;
   begin
      begin
         --  One Connect, and from here on nothing but Reconnect: the
         --  connection stays live across every sample and is closed
         --  only after the final one.
         AHT.Websocket.Client.Connect (C, Echo);
         Round_Trip ("one-client warmup", C, "warm0");
         for I in 1 .. Warmup loop
            Redial ("one-client warmup", C, "warm" & Integer'Image (I));
         end loop;
      exception
         when E : others =>
            Fail ("one-client: the warmup raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E)
                  & " (is server_ws.py running?)");
            Put_Line ("test_ws_reconnect_leak:" & Failures'Image
                      & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;

      FD_Before   := Count_Entries ("/proc/self/fd");
      Task_Before := Count_Entries ("/proc/self/task");

      for I in 1 .. Cycles loop
         Redial ("one-client", C, "cycle" & Integer'Image (I));
         exit when Failures > 0;
      end loop;

      --  Sampled while the last connection is still OPEN, so the one
      --  live session is present in the baseline and in this reading
      --  alike and does not show up as growth.
      FD_After   := Count_Entries ("/proc/self/fd");
      Task_After := Count_Entries ("/proc/self/task");

      --  The counts above are only meaningful if the cycles actually
      --  happened. A stable fd count across fifty connections that
      --  were never made proves nothing at all, so the generation
      --  counter is what stops this test from passing vacuously.
      declare
         Got : constant Natural :=
           AHT.Websocket.Client.Generation (C);
      begin
         if Got /= 1 + Warmup + Cycles then
            Fail ("one-client: Generation =" & Natural'Image (Got)
                  & " after" & Natural'Image (1 + Warmup + Cycles)
                  & " connections — the cycles did not all run, so the "
                  & "counts below mean nothing");
         end if;
      end;

      Check ("one-client", FD_Before, FD_After, "open descriptors");
      Check ("one-client", Task_Before, Task_After, "live threads");

      AHT.Websocket.Client.Close (C);
   end;

   --  Shape 2: a fresh client per cycle, so the receiver task is
   --  created and terminated every time. A receiver that never exits
   --  shows up here and nowhere else.
   declare
      FD_Before, FD_After     : Natural;
      Task_Before, Task_After : Natural;
   begin
      for I in 1 .. Warmup loop
         declare
            C : AHT.Websocket.Client.Client_Type;
         begin
            Cycle ("fresh-client warmup", C, "warm" & Integer'Image (I));
         end;
      end loop;

      FD_Before   := Count_Entries ("/proc/self/fd");
      Task_Before := Count_Entries ("/proc/self/task");

      for I in 1 .. Cycles loop
         declare
            C : AHT.Websocket.Client.Client_Type;
         begin
            Cycle ("fresh-client", C, "cycle" & Integer'Image (I));
         end;
         exit when Failures > 0;
      end loop;

      FD_After   := Count_Entries ("/proc/self/fd");
      Task_After := Count_Entries ("/proc/self/task");

      Check ("fresh-client", FD_Before, FD_After, "open descriptors");
      Check ("fresh-client", Task_Before, Task_After, "live threads");
   end;

   if Failures = 0 then
      Put_Line ("test_ws_reconnect_leak: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_reconnect_leak:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Reconnect_Leak;
