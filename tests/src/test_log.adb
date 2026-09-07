--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Command_Line;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Log;
with AHT.Log.Tag;

procedure Test_Log is

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_log: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Capture sink: append each record to a module-level vector
   --  protected by a binary semaphore so the concurrent case can
   --  race safely without depending on Synchronized_Sink being
   --  already proven correct.

   Max_Records : constant := 256;

   type Record_Array is array (1 .. Max_Records) of Unbounded_String;

   protected Capture is
      procedure Reset;
      procedure Append (Line : String);
      function  Count return Natural;
      function  Entry_At (I : Positive) return String;
   private
      Records : Record_Array;
      N       : Natural := 0;
   end Capture;

   protected body Capture is

      procedure Reset is
      begin
         N := 0;
      end Reset;

      procedure Append (Line : String) is
      begin
         if N < Max_Records then
            N := N + 1;
            Records (N) := To_Unbounded_String (Line);
         end if;
      end Append;

      function Count return Natural is (N);

      function Entry_At (I : Positive) return String is
        (To_String (Records (I)));

   end Capture;

   procedure Capture_Sink
     (Lvl       : AHT.Log.Level;
      Subsystem : String;
      Message   : String)
   is
   begin
      Capture.Append
        (AHT.Log.Level'Image (Lvl) & "|" & Subsystem & "|" & Message);
   end Capture_Sink;

   --  A helper sink that *is not* thread-safe: it touches a plain
   --  global counter and sleeps between read and write to amplify
   --  any race. Used only to prove Synchronized_Sink serializes
   --  access (non-interleaved output is a looser check; counter-
   --  correctness is a stronger one).

   Race_Counter : Natural := 0;

   procedure Racy_Sink
     (Lvl       : AHT.Log.Level;
      Subsystem : String;
      Message   : String)
   is
      pragma Unreferenced (Lvl, Subsystem, Message);
      Snap : constant Natural := Race_Counter;
   begin
      delay 0.001;
      Race_Counter := Snap + 1;
   end Racy_Sink;

   package TCP_Log   is new AHT.Log.Tag ("tcp");
   package Frame_Log is new AHT.Log.Tag ("ws.frames");

begin
   --  Case 1: silent by default — no sink installed.
   declare
   begin
      Capture.Reset;
      AHT.Log.Set_Sink (null);
      AHT.Log.Set_Default_Level (AHT.Log.Trace);
      if AHT.Log.Is_Enabled (AHT.Log.Error, "anything") then
         Fail ("silent: Is_Enabled true with no sink installed");
      end if;
      AHT.Log.Emit (AHT.Log.Error, "x", "should not reach sink");
      TCP_Log.Error ("also should not reach");
      if Capture.Count /= 0 then
         Fail ("silent: capture observed"
               & Natural'Image (Capture.Count)
               & " records without a sink");
      end if;
   end;

   --  Case 2: captured sink records level/subsystem/message verbatim.
   declare
   begin
      Capture.Reset;
      AHT.Log.Set_Sink (Capture_Sink'Unrestricted_Access);
      AHT.Log.Set_Default_Level (AHT.Log.Info);
      AHT.Log.Emit (AHT.Log.Info, "tcp", "hello");
      AHT.Log.Emit (AHT.Log.Warning, "tcp", "ouch");
      if Capture.Count /= 2 then
         Fail ("capture: expected 2 records, got"
               & Natural'Image (Capture.Count));
      else
         if Capture.Entry_At (1) /= "INFO|tcp|hello" then
            Fail ("capture: record 1 = " & Capture.Entry_At (1));
         end if;
         if Capture.Entry_At (2) /= "WARNING|tcp|ouch" then
            Fail ("capture: record 2 = " & Capture.Entry_At (2));
         end if;
      end if;
   end;

   --  Case 3: global level filter — default Warning drops Info/Debug.
   declare
   begin
      Capture.Reset;
      AHT.Log.Set_Sink (Capture_Sink'Unrestricted_Access);
      AHT.Log.Set_Default_Level (AHT.Log.Warning);
      AHT.Log.Emit (AHT.Log.Debug,   "x", "dropped");
      AHT.Log.Emit (AHT.Log.Info,    "x", "dropped");
      AHT.Log.Emit (AHT.Log.Warning, "x", "kept");
      AHT.Log.Emit (AHT.Log.Error,   "x", "kept");
      if Capture.Count /= 2 then
         Fail ("default-filter: expected 2 kept, got"
               & Natural'Image (Capture.Count));
      end if;
      if AHT.Log.Is_Enabled (AHT.Log.Info, "x") then
         Fail ("default-filter: Is_Enabled Info returned true under Warning");
      end if;
      if not AHT.Log.Is_Enabled (AHT.Log.Error, "x") then
         Fail ("default-filter: Is_Enabled Error returned false under Warning");
      end if;
   end;

   --  Case 4: per-subsystem override wins both ways.
   declare
   begin
      Capture.Reset;
      AHT.Log.Set_Sink (Capture_Sink'Unrestricted_Access);
      AHT.Log.Set_Default_Level (AHT.Log.Error);
      --  tcp: turn *up* to Debug against a strict default
      AHT.Log.Set_Subsystem_Level ("tcp", AHT.Log.Debug);
      --  ws.frames: turn *down* to Error+1-equivalent — only Errors pass
      AHT.Log.Set_Subsystem_Level ("ws.frames", AHT.Log.Error);

      TCP_Log.Debug ("debug-tcp-kept");       -- kept: tcp override is Debug
      TCP_Log.Info ("info-tcp-kept");         -- kept
      Frame_Log.Info ("info-frame-dropped");  -- dropped: frame override Error
      Frame_Log.Error ("error-frame-kept");   -- kept
      AHT.Log.Emit (AHT.Log.Warning, "other", "dropped"); -- default Error

      if Capture.Count /= 3 then
         Fail ("override: expected 3 kept, got"
               & Natural'Image (Capture.Count));
         for I in 1 .. Capture.Count loop
            Put_Line ("  seen: " & Capture.Entry_At (I));
         end loop;
      end if;

      AHT.Log.Clear_Subsystem_Level ("tcp");
      if AHT.Log.Is_Enabled (AHT.Log.Debug, "tcp") then
         Fail ("override: Clear_Subsystem_Level did not drop override");
      end if;
   end;

   --  Case 5: concurrent emit via Synchronized_Sink. With the racy
   --  inner sink, unserialized concurrent calls drop counter bumps;
   --  Synchronized_Sink must serialize so the count matches exactly.
   declare
      Per_Task  : constant := 200;
      Tasks     : constant := 4;
      Expected  : constant Natural := Per_Task * Tasks;

      task type Emitter;
      task body Emitter is
      begin
         for I in 1 .. Per_Task loop
            AHT.Log.Emit (AHT.Log.Info, "race", "tick");
         end loop;
      end Emitter;

      type Emitter_Access is access Emitter;
      Runners : array (1 .. Tasks) of Emitter_Access;
   begin
      Race_Counter := 0;
      AHT.Log.Set_Sink (AHT.Log.Synchronized_Sink (Racy_Sink'Unrestricted_Access));
      AHT.Log.Set_Default_Level (AHT.Log.Info);
      AHT.Log.Clear_Subsystem_Level ("race");

      for I in Runners'Range loop
         Runners (I) := new Emitter;
      end loop;
      --  Wait for every runner to terminate. Block scope alone
      --  waits on declared task objects, but Runners are accessed
      --  through pointers, so join explicitly.
      for I in Runners'Range loop
         while not Runners (I).all'Terminated loop
            delay 0.01;
         end loop;
      end loop;

      if Race_Counter /= Expected then
         Fail ("synchronized-sink: expected"
               & Natural'Image (Expected)
               & " bumps, got"
               & Natural'Image (Race_Counter));
      end if;
   end;

   --  Case 6: Synchronized_Sink single-wrap contract. A second wrap
   --  with a different Inner must raise Program_Error rather than
   --  silently repointing the first wrap at the new callback.
   --  Idempotent re-wrap (same Inner) is allowed and returns the
   --  same trampoline. Passing null clears the wrap.
   declare
      use type AHT.Log.Sink_Callback;
      W1, W2, W3 : AHT.Log.Sink_Callback;
      Raised     : Boolean := False;
   begin
      AHT.Log.Set_Sink (null);
      --  Case 5 installed a wrap around Racy_Sink; release it so
      --  the first call below starts from a clean slate.
      W3 := AHT.Log.Synchronized_Sink (null);

      W1 := AHT.Log.Synchronized_Sink (Capture_Sink'Unrestricted_Access);
      if W1 = null then
         Fail ("single-wrap: first wrap returned null");
      end if;

      W2 := AHT.Log.Synchronized_Sink (Capture_Sink'Unrestricted_Access);
      if W2 /= W1 then
         Fail ("single-wrap: idempotent re-wrap returned a different "
               & "trampoline");
      end if;

      begin
         W3 := AHT.Log.Synchronized_Sink (Racy_Sink'Unrestricted_Access);
         Fail ("single-wrap: second wrap with different Inner did not "
               & "raise Program_Error");
      exception
         when Program_Error => Raised := True;
      end;
      if not Raised then
         Fail ("single-wrap: Program_Error not raised");
      end if;

      --  Clearing should make the next wrap succeed.
      W3 := AHT.Log.Synchronized_Sink (null);
      if W3 /= null then
         Fail ("single-wrap: Synchronized_Sink (null) did not return null");
      end if;
      W3 := AHT.Log.Synchronized_Sink (Racy_Sink'Unrestricted_Access);
      if W3 = null then
         Fail ("single-wrap: post-clear wrap returned null");
      end if;
   end;

   AHT.Log.Set_Sink (null);

   if Failures = 0 then
      Put_Line ("test_log: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_log:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_Log;
