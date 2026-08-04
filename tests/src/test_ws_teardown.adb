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
--  Cases:
--    1. With a callback still running, Close reports Timeout_Error
--       instead of blocking.
--    2. Nothing was abandoned by that report. The client is still
--       Closing immediately afterwards — checked, because a timeout
--       that wrongly marked the generation done would leave every
--       later assertion here passing anyway — and once the callback
--       returns, a later Close finds the same teardown, completes it,
--       and the client is reusable.

with Ada.Calendar; use Ada.Calendar;
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Transport;
with AHT.Websocket;
with AHT.Websocket.Client;

procedure Test_WS_Teardown is

   Echo : constant String := "ws://127.0.0.1:8765/";

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_teardown: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

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

   if Failures = 0 then
      Put_Line ("test_ws_teardown: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_teardown:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Teardown;
