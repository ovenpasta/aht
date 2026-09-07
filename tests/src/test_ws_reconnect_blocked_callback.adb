--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Reconnecting while a callback refuses to return. Callbacks run on
--  the receiver task, the only task that can complete a teardown, so
--  an On_Message that does not return stops what Reconnect waits for.
--  Echo fixture; the callback blocks on a gate the test opens, with a
--  bound as backstop.
--
--  Cases:
--    1. Reconnect raises Timeout_Error
--    2. it did not redial: generation unchanged, still Closing
--    3. once the callback returns, a later Reconnect joins the
--       teardown in progress and succeeds
--
--  Covers:
--    - a Reconnect that timed out and redialled anyway satisfies
--      claim 1 and fails claim 2
--    - claim 2 is asserted separately, so relaxing both guards (the
--      failed-drain check and admission) is still caught
--
--  Validated by:
--    with Reconnect made to swallow the failed drain and redial, claim
--    1 fails with Handshake_Error: admission refuses a Closing client.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.Transport;
with AHT.Websocket;
with AHT.Websocket.Client;

procedure Test_WS_Reconnect_Blocked_Callback is

   Echo : constant String := "ws://127.0.0.1:8765/";

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_reconnect_blocked_callback: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function To_String (V : AHT.Bytes.Buffer) return String is
     (AHT.Bytes.To_String (V));

   --  Holds the receiver inside On_Message until the test lets go.
   protected Gate is
      --  Barrier, so a released gate lets every later callback
      --  straight through: the connection is used again afterwards
      --  and must not re-block.
      entry Wait;
      procedure Release;
      procedure Note_Entered;
      function  Entered return Boolean;
   private
      Opened  : Boolean := False;
      Arrived : Boolean := False;
   end Gate;

   protected body Gate is
      entry Wait when Opened is
      begin
         null;
      end Wait;
      procedure Release is
      begin
         Opened := True;
      end Release;
      procedure Note_Entered is
      begin
         Arrived := True;
      end Note_Entered;
      function Entered return Boolean is (Arrived);
   end Gate;

   procedure On_Message (Msg : AHT.Websocket.Client.Message_Type) is
      pragma Unreferenced (Msg);
   begin
      Gate.Note_Entered;
      --  A backstop: if the test fails before it reaches Release,
      --  this returns on its own and the suite gets a report instead
      --  of a hang. The bound is far longer than anything the test
      --  waits for.
      select
         Gate.Wait;
      or
         delay 30.0;
      end select;
   end On_Message;

   function Callback_Blocked return Boolean is (Gate.Entered);

   function Await
     (Flag : access function return Boolean; Bound : Duration)
      return Boolean
   is
      Waited : Duration := 0.0;
   begin
      while not Flag.all and then Waited < Bound loop
         delay 0.02;
         Waited := Waited + 0.02;
      end loop;
      return Flag.all;
   end Await;

begin
   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      AHT.Websocket.Client.Set_On_Message (C, On_Message'Unrestricted_Access);

      begin
         AHT.Websocket.Client.Connect (C, Echo);
      exception
         when E : others =>
            Fail ("Connect raised " & Ada.Exceptions.Exception_Name (E)
                  & " (is server_ws.py running?)");
            Put_Line ("test_ws_reconnect_blocked_callback:"
                      & Failures'Image & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;

      --  Provoke the callback and wait until the receiver is inside
      --  it; everything below depends on that.
      AHT.Websocket.Client.Send_Text (C, "provoke");

      if not Await (Callback_Blocked'Unrestricted_Access, 10.0) then
         Fail ("the callback never ran, so nothing was blocking the "
               & "receiver and the bounds below would be measuring "
               & "an idle teardown");
         Gate.Release;
         AHT.Websocket.Client.Close (C, Timeout => 1.0);
         Put_Line ("test_ws_reconnect_blocked_callback:" & Failures'Image
                   & " failure(s)");
         Ada.Command_Line.Set_Exit_Status (1);
         return;
      end if;

      --  Claim 1: bounded, and it says so.
      begin
         AHT.Websocket.Client.Reconnect
           (C, Timeout => 1.0, Drain_Timeout => 1.0);
         Fail ("Reconnect returned while the callback still had the "
               & "receiver — it cannot have drained anything");
      exception
         when AHT.Transport.Timeout_Error =>
            null;   --  correct
         when E : others =>
            Fail ("Reconnect raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E)
                  & ", expected Timeout_Error");
      end;

      --  Claim 2, first half: nothing was redialled.
      if AHT.Websocket.Client.Generation (C) /= 1 then
         Fail ("Generation ="
               & Natural'Image (AHT.Websocket.Client.Generation (C))
               & " after a Reconnect that timed out — it redialled "
               & "over a connection that was still being reclaimed");
      end if;

      --  Claim 2, second half: still Closing, not Disconnected.
      --  Configure is legal only while fully disconnected, so a client
      --  that had finished tearing down would accept it. Refusal
      --  distinguishes "teardown continues in the background" from
      --  "teardown was abandoned".
      begin
         AHT.Websocket.Client.Configure
           (C, AHT.Websocket.Client.Limits'(others => <>));
         Fail ("Configure was accepted after the timed-out Reconnect "
               & "— the client is no longer Closing, so the teardown "
               & "was abandoned rather than left running");
      exception
         when AHT.Websocket.Mode_Error =>
            null;   --  correct: still winding down
         when E : others =>
            Fail ("Configure raised "
                  & Ada.Exceptions.Exception_Name (E)
                  & ", expected Mode_Error");
      end;

      --  Let the receiver go. The teardown that was already running
      --  can now finish.
      Gate.Release;

      --  Claim 3: the next Reconnect joins the teardown in progress.
      begin
         AHT.Websocket.Client.Reconnect (C);
      exception
         when E : others =>
            Fail ("the Reconnect after the callback returned raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E)
                  & " — it did not join the teardown already in "
                  & "progress");
      end;

      if AHT.Websocket.Client.Generation (C) /= 2 then
         Fail ("Generation ="
               & Natural'Image (AHT.Websocket.Client.Generation (C))
               & " after the joining Reconnect (expected 2)");
      end if;

      --  And the connection it produced is real, so "succeeded" means
      --  more than "returned".
      declare
         Msg : AHT.Websocket.Client.Message_Type;
      begin
         AHT.Websocket.Client.Send_Text (C, "after");
         AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);
         if To_String (Msg.Payload) /= "after" then
            Fail ("the joined connection echoed """
                  & To_String (Msg.Payload) & """, expected ""after""");
         end if;
      exception
         when E : others =>
            Fail ("the joined connection did not work: "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
      end;

      AHT.Websocket.Client.Close (C);
   end;

   if Failures = 0 then
      Put_Line ("test_ws_reconnect_blocked_callback: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_reconnect_blocked_callback:" & Failures'Image
                & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Reconnect_Blocked_Callback;
