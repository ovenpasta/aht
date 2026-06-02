--  Regression for the Send_* close-race: Send_Text / Send_Binary /
--  Send_Ping on a connection that is not Open must raise the catchable
--  Closed_Error, not Assertion_Error (the old `Pre => Is_Open` aspect
--  tripped under -gnata on a benign close race) and must never
--  dereference a null transport on a never-connected Client.
--
--  Two deterministic cases:
--    1. Never connected — a fresh Client has Active = null and
--       Is_Open = False; each of the three senders raises Closed_Error
--       (needs no server).
--    2. Closed after connect — Connect to the echo fixture, Close, then
--       Send_Text: the connection is Closed so the sender raises
--       Closed_Error. This is the real shape of the race the fix
--       targets (peer/handshake gone before the app sends).

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Websocket;
with AHT.Websocket.Client;

procedure Test_WS_Send_Closed is

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_send_closed: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Run Op and record whether it raised Closed_Error (the wanted
   --  outcome), some other exception, or nothing at all.
   procedure Expect_Closed
     (What : String;
      Op   : not null access procedure)
   is
   begin
      Op.all;
      Fail (What & ": returned without raising (expected Closed_Error)");
   exception
      when AHT.Websocket.Closed_Error =>
         null;  -- wanted
      when E : others =>
         Fail (What & ": raised "
               & Ada.Exceptions.Exception_Name (E)
               & " (expected Closed_Error)");
   end Expect_Closed;

begin
   --  Case 1: never-connected Client. No server required.
   declare
      C : AHT.Websocket.Client.Client_Type;

      procedure Do_Text is
      begin
         AHT.Websocket.Client.Send_Text (C, "nope");
      end Do_Text;

      procedure Do_Binary is
      begin
         AHT.Websocket.Client.Send_Binary (C, [1, 2, 3]);
      end Do_Binary;

      procedure Do_Ping is
      begin
         AHT.Websocket.Client.Send_Ping (C);
      end Do_Ping;
   begin
      Expect_Closed ("unconnected Send_Text", Do_Text'Access);
      Expect_Closed ("unconnected Send_Binary", Do_Binary'Access);
      Expect_Closed ("unconnected Send_Ping", Do_Ping'Access);
   end;

   --  Case 2: connect to the echo fixture, Close, then Send_Text.
   declare
      C : AHT.Websocket.Client.Client_Type;

      procedure Do_Text is
      begin
         AHT.Websocket.Client.Send_Text (C, "after-close");
      end Do_Text;
   begin
      begin
         AHT.Websocket.Client.Connect (C, "ws://127.0.0.1:8765/");
      exception
         when E : others =>
            Fail ("closed: Connect raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E)
                  & " (is server_ws.py running?)");
            Put_Line ("test_ws_send_closed:" & Failures'Image
                      & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;

      AHT.Websocket.Client.Close (C);
      if AHT.Websocket.Client.Is_Open (C) then
         Fail ("closed: Is_Open true after Close");
      end if;
      Expect_Closed ("post-close Send_Text", Do_Text'Access);
   end;

   if Failures = 0 then
      Put_Line ("test_ws_send_closed: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_send_closed:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Send_Closed;
