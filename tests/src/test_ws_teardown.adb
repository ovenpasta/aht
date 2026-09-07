--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  The caller-side bound on reclamation.
--
--  Close waits for its own receiver to finish reclaiming the
--  connection, and that wait cannot be made safe by shortening it:
--  the receiver still owns the session either way. So the bound is a
--  liveness report rather than a safety decision — it says "this is
--  taking too long", not "I have given up on it".
--
--  The case that makes it necessary is a callback that does not
--  return. Abort_Pending cancels transport I/O; it cannot cancel user
--  code, so a receiver sitting inside On_Message will never reach
--  reclamation and no receiver-side mechanism can notice. Only the
--  caller can, which is why "callbacks must not block" is a contract
--  and not advice.
--
--  Cases, in the order they run:
--    1. With a callback still running, Close reports Timeout_Error
--       instead of blocking.
--    2. Nothing was abandoned by that report. The client is still
--       Closing immediately afterwards — checked, because a timeout
--       that wrongly marked the generation done would leave every
--       later assertion here passing anyway — and once the callback
--       returns, a later Close finds the same teardown, completes it,
--       and the client is reusable.
--    3. A writer parked in the transport does not outwait Close. The
--       close handshake takes the send latch BEFORE it reaches its
--       timed wait, so taking it unconditionally would let a stuck
--       writer outlast Timeout without Timeout ever being consulted —
--       and a WebSocket write carries no deadline of its own, so a
--       peer that stops reading is all it takes to arrange that.
--    4. Telling Close not to wait for the peer still sends the Close
--       frame when nothing is in the way. "Do not wait" must not
--       quietly become "do not try".
--    5. A teardown the caller asked for is not reported through
--       On_Error. The abort that ends it is the mechanism, not a
--       fault; a peer-driven one still reaches the callback.
--
--  Not covered: the close frame's own write parking on a full socket
--  buffer. Reaching it needs a writer that SUCCEEDS while leaving the
--  buffer exactly full — interrupting one instead poisons the
--  transport by design, so the next write fails fast rather than
--  parking — and that could not be arranged deterministically here.

with Ada.Calendar; use Ada.Calendar;
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Unchecked_Deallocation;

with AHT.Bytes;
with AHT.Transport;
with AHT.Websocket;
with AHT.Websocket.Client;

procedure Test_WS_Teardown is

   Echo    : constant String := "ws://127.0.0.1:8765/";
   Hostile : constant String := "ws://127.0.0.1:8777";

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_teardown: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Counts what the receiver reports as an error.
   protected Errors is
      procedure Note (Message : String);
      procedure Reset;
      function  Count return Natural;
      function  Last return String;
   private
      N    : Natural := 0;
      Text : Unbounded_String;
   end Errors;

   protected body Errors is
      procedure Note (Message : String) is
      begin
         N    := N + 1;
         Text := To_Unbounded_String (Message);
      end Note;
      procedure Reset is
      begin
         N    := 0;
         Text := Null_Unbounded_String;
      end Reset;
      function Count return Natural is (N);
      function Last return String is (To_String (Text));
   end Errors;

   procedure On_Error (Message : String) is
   begin
      Errors.Note (Message);
   end On_Error;

   --  Lets the test hold a callback inside the receiver for as long
   --  as it needs, and know for a fact that it is in there. The hold
   --  is itself bounded: if the test never releases it, the receiver
   --  must still eventually come back rather than wedging the suite.
   protected Gate is
      procedure Enter;
      function  Entered return Boolean;
      procedure Release;
      entry     Hold;
   private
      In_Callback : Boolean := False;
      Released    : Boolean := False;
   end Gate;

   protected body Gate is
      procedure Enter is
      begin
         In_Callback := True;
      end Enter;
      function Entered return Boolean is (In_Callback);
      procedure Release is
      begin
         Released := True;
      end Release;
      entry Hold when Released is
      begin
         null;
      end Hold;
   end Gate;

   procedure On_Message (Msg : AHT.Websocket.Client.Message_Type) is
      pragma Unreferenced (Msg);
   begin
      Gate.Enter;
      select
         Gate.Hold;
      or
         delay 30.0;   --  backstop; the test releases long before
      end select;
   end On_Message;

   --  Asks the peer whether the connection using this token has put
   --  anything on the wire. The peer peeks rather than reads, so
   --  asking does not unblock a writer that is deliberately stuck.
   function Peer_Saw_Traffic (Token : String) return Boolean is
      Q   : AHT.Websocket.Client.Client_Type;
      Msg : AHT.Websocket.Client.Message_Type;
   begin
      AHT.Websocket.Client.Connect (Q, Hostile & "/traffic/" & Token);
      AHT.Websocket.Client.Receive (Q, Msg, Timeout => 10.0);
      declare
         Answer : constant String := AHT.Bytes.To_String (Msg.Payload);
      begin
         AHT.Websocket.Client.Close (Q, Timeout => 1.0);
         return Answer = "traffic=yes";
      end;
   exception
      when others =>
         begin
            AHT.Websocket.Client.Close (Q, Timeout => 0.0);
         exception
            when others => null;
         end;
         return False;
   end Peer_Saw_Traffic;

   function Await_In_Callback (Bound : Duration) return Boolean is
      Waited : Duration := 0.0;
   begin
      while not Gate.Entered and then Waited < Bound loop
         delay 0.02;
         Waited := Waited + 0.02;
      end loop;
      return Gate.Entered;
   end Await_In_Callback;

   C : AHT.Websocket.Client.Client_Type;
   Started, Ended : Time;
   Reported : Boolean := False;

begin
   AHT.Websocket.Client.Set_On_Message (C, On_Message'Unrestricted_Access);

   begin
      AHT.Websocket.Client.Connect (C, Echo);
   exception
      when E : others =>
         Fail ("Connect raised " & Ada.Exceptions.Exception_Name (E)
               & " (is server_ws.py running?)");
         Put_Line ("test_ws_teardown:" & Failures'Image & " failure(s)");
         Ada.Command_Line.Set_Exit_Status (1);
         return;
   end;

   --  Park the receiver inside user code.
   AHT.Websocket.Client.Send_Text (C, "hold the receiver");
   if not Await_In_Callback (5.0) then
      Fail ("the callback never ran, so nothing was holding the "
            & "receiver and this proves nothing");
      Gate.Release;
      AHT.Websocket.Client.Close (C);
      Put_Line ("test_ws_teardown:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
      return;
   end if;

   --  Case 1: Close cannot complete, and must say so rather than
   --  block. Timeout is small because there is no peer to wait for
   --  here; what is being bounded is our own receiver.
   Started := Clock;
   begin
      AHT.Websocket.Client.Close
        (C, Timeout => 0.1, Drain_Timeout => 1.0);
      Ended := Clock;
      --  Without the bound this does not hang outright -- it waits
      --  for the callback, which has a backstop of its own -- so the
      --  elapsed time is what distinguishes "reported" from "gave up
      --  waiting eventually".
      Fail ("Close returned normally after"
            & Duration'Image (Ended - Started)
            & "s instead of reporting its 1.0s drain bound");
   exception
      when AHT.Transport.Timeout_Error =>
         Ended    := Clock;
         Reported := True;
      when E : others =>
         Ended := Clock;
         Fail ("Close raised " & Ada.Exceptions.Exception_Name (E)
               & ", expected Timeout_Error");
   end;

   --  Bounded on both sides. Too slow means the bound was not
   --  honoured; too fast means it was not waited on at all, and an
   --  implementation that raised Timeout_Error the moment it was
   --  asked would satisfy an upper bound alone.
   if Reported and then Ended - Started > 3.0 then
      Fail ("Close took" & Duration'Image (Ended - Started)
            & "s to report a 1.0s drain bound");
   end if;
   if Reported and then Ended - Started < 0.5 then
      Fail ("Close reported after only"
            & Duration'Image (Ended - Started)
            & "s against a 1.0s drain bound — it did not wait");
   end if;

   --  The report was a liveness complaint, not a conclusion. If the
   --  timeout had marked the generation done, or abandoned the
   --  session, the client would read as Disconnected here and
   --  everything below would still pass. Configure answers that
   --  without blocking: it is refused anywhere but Idle and
   --  Disconnected, so Mode_Error here means the client is still
   --  Closing and the teardown is still somebody's business.
   begin
      AHT.Websocket.Client.Configure
        (C, AHT.Websocket.Client.Limits'(others => <>));
      Fail ("Configure was accepted after the drain timeout — the "
            & "client is no longer Closing, so the teardown was "
            & "abandoned rather than left running");
   exception
      when AHT.Websocket.Mode_Error => null;
      when E : others =>
         Fail ("Configure after the drain timeout raised "
               & Ada.Exceptions.Exception_Name (E)
               & ", expected Mode_Error");
   end;

   --  Case 2: the report was not an abandonment. The receiver still
   --  owns the session and is still reclaiming it, so releasing the
   --  callback lets that finish and a second Close joins it.
   Gate.Release;

   Started := Clock;
   begin
      AHT.Websocket.Client.Close (C, Drain_Timeout => 10.0);
   exception
      when E : others =>
         Fail ("the second Close raised "
               & Ada.Exceptions.Exception_Name (E)
               & " — the teardown did not continue in the background");
   end;
   Ended := Clock;

   if Ended - Started > 5.0 then
      Fail ("the second Close took" & Duration'Image (Ended - Started)
            & "s");
   end if;

   if AHT.Websocket.Client.Is_Open (C) then
      Fail ("Is_Open true after the teardown completed");
   end if;

   --  And the client came through it usable, which is the practical
   --  claim behind "nothing was abandoned".
   begin
      AHT.Websocket.Client.Connect (C, Echo);
   exception
      when E : others =>
         Fail ("reconnect after the bounded teardown raised "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E));
   end;
   if AHT.Websocket.Client.Generation (C) /= 2 then
      Fail ("Generation ="
            & Natural'Image (AHT.Websocket.Client.Generation (C))
            & " after reconnecting (expected 2)");
   end if;
   AHT.Websocket.Client.Close (C);

   --  Case 3: a writer stuck in the transport must not be able to
   --  outwait Close by holding the send latch.
   declare
      D : AHT.Websocket.Client.Client_Type;

      --  Far more than the fixture's 4 KiB receive window, so the
      --  write provably cannot complete while it is not reading. On
      --  the heap: this would not fit the environment task's stack.
      type Bulk_Access is access AHT.Bytes.Byte_Array;
      procedure Free_Bulk is new Ada.Unchecked_Deallocation
        (AHT.Bytes.Byte_Array, Bulk_Access);
      Bulk : constant Bulk_Access :=
        new AHT.Bytes.Byte_Array'(1 .. 4 * 1024 * 1024 => 16#5A#);

      protected Writer is
         procedure Note_Done;
         function  Done return Boolean;
      private
         Finished : Boolean := False;
      end Writer;

      protected body Writer is
         procedure Note_Done is
         begin
            Finished := True;
         end Note_Done;
         function Done return Boolean is (Finished);
      end Writer;

      --  Gated on an entry: an ungated task activates at this block's
      --  `begin`, before Connect has run, and its send would raise
      --  Closed_Error at once — indistinguishable from a write that
      --  completed.
      task Stuck_Writer is
         entry Go;
      end Stuck_Writer;

      task body Stuck_Writer is
      begin
         accept Go;
         AHT.Websocket.Client.Send_Binary (D, Bulk.all);
         Writer.Note_Done;
      exception
         when others =>
            Writer.Note_Done;
      end Stuck_Writer;

      Connected : Boolean := False;
   begin
      begin
         AHT.Websocket.Client.Connect (D, Hostile & "/deaf/stuck");
         Connected := True;
      exception
         when E : others =>
            Fail ("stuck-writer: Connect raised "
                  & Ada.Exceptions.Exception_Name (E)
                  & " (is server_ws_hostile.py running?)");
      end;

      if Connected then
         Stuck_Writer.Go;
      end if;

      --  Positive confirmation, not an inference from a delay. The
      --  peer reports (by peeking, so it stays deaf and the writer
      --  stays blocked) that bytes really arrived; combined with the
      --  send not having returned, that puts the writer inside the
      --  transport holding the latch. A bare "it has not finished
      --  yet" would equally describe a task that had not started.
      if Connected and then not Peer_Saw_Traffic ("stuck") then
         Fail ("stuck-writer: the peer never saw any of the write, so "
               & "nothing was holding the send latch — this case "
               & "proved nothing");
      elsif Connected and then Writer.Done then
         Fail ("stuck-writer: the bulk write completed against a peer "
               & "that is not reading, so nothing was holding the "
               & "send latch — this case proved nothing");
      elsif Connected then
         Started := Clock;
         begin
            AHT.Websocket.Client.Close
              (D, Timeout => 2.0, Drain_Timeout => 5.0);
         exception
            when AHT.Transport.Timeout_Error =>
               null;   --  acceptable: bounded either way
            when E : others =>
               Fail ("stuck-writer: Close raised "
                     & Ada.Exceptions.Exception_Name (E));
         end;
         Ended := Clock;

         --  The fixture stays deaf for 20s, so waiting it out is
         --  unmistakable against a 2.0s budget.
         if Ended - Started > 3.5 then
            Fail ("stuck-writer: Close took"
                  & Duration'Image (Ended - Started)
                  & "s against a 2.0s handshake budget — it waited "
                  & "out the stuck writer instead of bounding the "
                  & "latch acquisition");
         end if;
      end if;

      --  Release the gated task if Connect never happened, and let
      --  the aborted writer finish either way.
      if not Connected then
         abort Stuck_Writer;
      end if;
      declare
         Waited : Duration := 0.0;
      begin
         while not Stuck_Writer'Terminated and then Waited < 10.0 loop
            delay 0.05;
            Waited := Waited + 0.05;
         end loop;
         if not Stuck_Writer'Terminated then
            Fail ("stuck-writer: the writer never came back");
            abort Stuck_Writer;
         end if;
      end;

      --  Only once the task that was writing from it is provably
      --  gone: freeing it while the write is still in flight would be
      --  a use-after-free, and freeing it not at all leaks 4 MiB per
      --  run of this case.
      if Stuck_Writer'Terminated then
         declare
            Owned : Bulk_Access := Bulk;
         begin
            Free_Bulk (Owned);
         end;
      end if;
   end;

   --  Case 4: "do not wait for the peer" still means "send the Close
   --  frame if nothing is in the way". The bounded acquisition takes
   --  a free latch immediately, so a healthy connection closed with
   --  Timeout => 0.0 still says goodbye properly.
   declare
      E : AHT.Websocket.Client.Client_Type;
      R : AHT.Websocket.Client.Client_Type;
      Msg : AHT.Websocket.Client.Message_Type;
   begin
      AHT.Websocket.Client.Connect (E, Hostile & "/echo/nowait");
      AHT.Websocket.Client.Close (E, Timeout => 0.0);

      AHT.Websocket.Client.Connect (R, Hostile & "/report/nowait");
      AHT.Websocket.Client.Receive (R, Msg, Timeout => 10.0);
      declare
         Seen : constant String := AHT.Bytes.To_String (Msg.Payload);
      begin
         if Seen /= "close=1000" then
            Fail ("no-wait-close: the peer saw """ & Seen
                  & """, expected ""close=1000"" — Timeout => 0.0 "
                  & "skipped the Close frame instead of taking a "
                  & "free latch");
         end if;
      end;
      AHT.Websocket.Client.Close (R, Timeout => 1.0);
   exception
      when Err : others =>
         Fail ("no-wait-close: raised "
               & Ada.Exceptions.Exception_Name (Err) & ": "
               & Ada.Exceptions.Exception_Message (Err));
   end;

   --  Case 5: a teardown the caller asked for is not an error.
   --
   --  Close stops a parked receiver by aborting its transport I/O, so
   --  the receiver sees Aborted_Error on the way out. Reporting that
   --  through On_Error would tell the application its connection
   --  failed every single time it closed one — the abort is the
   --  mechanism working, not a fault. A peer-driven abort still
   --  reaches On_Error; only the caller's own does not.
   --
   --  The peer here drains but never echoes a Close, so the handshake
   --  can only end by the caller aborting it.
   declare
      Q : AHT.Websocket.Client.Client_Type;
   begin
      Errors.Reset;
      AHT.Websocket.Client.Set_On_Error (Q, On_Error'Unrestricted_Access);

      begin
         AHT.Websocket.Client.Connect (Q, Hostile & "/echo/quiet");
      exception
         when E : others =>
            Fail ("forced-abort: Connect raised "
                  & Ada.Exceptions.Exception_Name (E));
      end;

      AHT.Websocket.Client.Close (Q, Timeout => 0.1);

      --  Settle: On_Error would fire from the receiver during the
      --  teardown, so give it every chance before concluding silence.
      delay 0.3;

      if Errors.Count /= 0 then
         Fail ("forced-abort: On_Error fired"
               & Natural'Image (Errors.Count)
               & " time(s) for a teardown the caller asked for: "
               & Errors.Last);
      end if;
   end;

   if Failures = 0 then
      Put_Line ("test_ws_teardown: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_teardown:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Teardown;
