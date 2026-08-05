--  Reconnecting while a callback refuses to return.
--
--  Callbacks run ON the receiver task. That is what makes them cheap,
--  and it is also what makes a blocking one dangerous: the receiver
--  is the only task that can complete a teardown, so an On_Message
--  that will not return is an On_Message that has stopped the one
--  thing a Close or a Reconnect is waiting for.
--
--  The library's answer is that the caller's wait is bounded and the
--  teardown is not abandoned. Reconnect gives up waiting and says so;
--  it does NOT redial, because redialing over a connection that is
--  still being reclaimed would be exactly the silent displacement the
--  design refuses everywhere else. The teardown continues in the
--  background, and whoever asks next joins it rather than starting a
--  second one.
--
--  So there are three claims here, and the middle one is the easiest
--  to lose in a refactor:
--
--    1. Reconnect raises Timeout_Error rather than hanging.
--    2. It did not redial. The generation must NOT have advanced, and
--       the client must still be Closing — not Disconnected, not Open.
--       A Reconnect that timed out and redialled anyway would satisfy
--       claim 1 and be badly wrong.
--    3. Once the callback returns, a later Reconnect joins the
--       teardown already in progress and succeeds. If it started a
--       fresh one instead, this is where a second teardown would race
--       the first.
--
--  The blocking is done with a gate the test opens, not a delay, so
--  the callback is released at a known point rather than a guessed
--  one. The gate has its own bound as a backstop: a regression that
--  left the main task never reaching Release would otherwise hang
--  here rather than reporting.
--
--  Validated by making Reconnect swallow the failed drain and redial
--  anyway. Worth recording what that produced, because it is not what
--  claim 2 predicts: the redial is attempted and ADMISSION refuses
--  it, since Connect dials only from Idle or Disconnected and the
--  client is Closing. So the case fails on claim 1 — Handshake_Error
--  where Timeout_Error was expected — rather than on a generation
--  that advanced.
--
--  That is defence in depth working, and it is why claim 2 is still
--  worth asserting separately. The two guards are independent: one
--  keeps Reconnect from redialing over a teardown it could not
--  finish, the other keeps admission shut while a session is still
--  owned. This case would notice the first one going only because
--  the second one caught what it let through; if both were relaxed,
--  the generation check is what remains.

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
      --  straight through — the connection is used again afterwards
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
      --  Timed, purely as a backstop. If the test fails before it
      --  reaches Release, this returns on its own and the suite gets
      --  a report instead of a hang — the bound is far longer than
      --  anything the test legitimately waits for.
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

      --  Provoke the callback and wait until the receiver is really
      --  inside it. Everything below depends on that being true, so
      --  it is observed rather than assumed.
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

      --  Claim 2, second half: still Closing, and specifically not
      --  Disconnected. Configure is the observable: it is legal only
      --  while fully disconnected, so a client that has really
      --  finished tearing down would accept it. Refusal here is what
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

      --  Claim 3: the next Reconnect joins it rather than racing it.
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
