--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Reconnecting many times over, counting descriptors and threads in
--  /proc, since Generation counts connections, not resources. Fifty
--  cycles make a one-per-cycle leak unmistakable. Echo fixture.
--  Linux-only: it reads /proc/self/fd and /proc/self/task, and SKIPs
--  elsewhere.
--
--  Cases:
--    1. one client, many generations driven by Reconnect, never
--       closed in between
--    2. many clients, one generation each
--
--  Covers:
--    - shape 1: the drain-and-redial path and the parameter copying;
--      the receiver persists, so anything found is per-session
--    - shape 2: the receiver task is created and terminated every
--      cycle, so a receiver that never exits shows as thread growth
--    - the generation counter proves the cycles happened
--
--  Does not cover:
--    - heap growth, such as a saved-parameter copy that accumulates:
--      neither counter sees plain memory
--
--  Validated by:
--    with the receiver's Free backed out, fd growth is 250 across 50
--    cycles, twenty times the bound.

with Ada.Command_Line;
with Ada.Directories;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

with GNAT.Directory_Operations;

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
   --  and keeps (TLS contexts, the runtime's own bookkeeping), and
   --  charging that to the measurement would make the baseline
   --  unrepeatable.
   Warmup : constant := 3;

   --  What the counts are allowed to move by: runtime jitter, a
   --  couple of sessions' worth. Both Reconnect and Close finish
   --  reclamation before returning, so each sample sees exactly one
   --  live connection. A session costs about five descriptors; a leak
   --  of one per iteration lands at 250, twenty times this bound.
   Slack : constant := 12;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_reconnect_leak: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function To_String (V : AHT.Bytes.Buffer) return String is
     (AHT.Bytes.To_String (V));

   --  Entries in a /proc directory, minus . and ..  Use the raw GNAT
   --  iterator: Ada.Directories.Start_Search stats every entry, which races
   --  descriptors disappearing from /proc/self/fd.  The iterator holds a
   --  descriptor open while it runs, so the count is biased by one; it is
   --  only ever compared against another call to itself, so the bias cancels.
   function Count_Entries (Path : String) return Natural is
      use GNAT.Directory_Operations;
      Dir  : Dir_Type;
      Name : String (1 .. 256);
      Last : Natural;
      N    : Natural := 0;
   begin
      Open (Dir, Path);
      loop
         Read (Dir, Name, Last);
         exit when Last = 0;
         if Name (1 .. Last) /= "." and then Name (1 .. Last) /= ".." then
            N := N + 1;
         end if;
      end loop;
      Close (Dir);
      return N;
   exception
      when others =>
         if Is_Open (Dir) then
            Close (Dir);
         end if;
         raise;
   end Count_Entries;

   function Have_Proc return Boolean is
     (Ada.Directories.Exists ("/proc/self/fd")
      and then Ada.Directories.Exists ("/proc/self/task"));

   --  One full connection: dial, prove it works, tear it down. The
   --  round-trip matters: a Connect that returned without a usable
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
   --  where the client itself comes and goes.
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
