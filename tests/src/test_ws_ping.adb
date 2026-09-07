--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  End-to-end exercise of the user-driven Send_Ping surface against
--  the Python `websockets` echo fixture on 127.0.0.1:8765.
--
--  The `websockets` library auto-replies to a Ping with a Pong at the
--  protocol layer and never surfaces the Ping to its echo handler, so
--  these cases lean on two observable facts: (a) a malformed control
--  frame (e.g. unmasked, wrong opcode) would make the server close the
--  connection with 1002, so a clean round-trip *after* a ping proves
--  Send_Ping put a valid masked Ping on the wire; (b) the client's
--  receiver drops inbound Pongs, so they must never show up as messages.
--
--  Three cases:
--    1. Empty ping — Send_Ping with no payload, then a text round-trip
--       still succeeds and Close flips Is_Open to False.
--    2. Ping with payload — Send_Ping ("aht-ping-payload"), then a text
--       round-trip still succeeds (exercises the control-frame payload
--       path through the masking / framing code).
--    3. Ping interleaved with data — Send_Text "before", Send_Ping,
--       Send_Text "after"; the two echoes come back in order and a
--       follow-up Receive times out, proving the server's auto-Pong was
--       dropped (the `Pong_Op => null` branch) rather than delivered as
--       a phantom message, and that the control frame did not corrupt
--       the surrounding data framing.

with Ada.Calendar; use Ada.Calendar;
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.Transport;
with AHT.Websocket;
with AHT.Websocket.Client;

procedure Test_WS_Ping is

   use type AHT.Websocket.Message_Kind;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_ping: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function To_String (V : AHT.Bytes.Buffer) return String is
     (AHT.Bytes.To_String (V));

   Ping_Payload : constant AHT.Bytes.Byte_Array :=
     AHT.Bytes.From_String ("aht-ping-payload");

begin
   --  Case 1: empty ping, stream stays alive.
   declare
      C   : AHT.Websocket.Client.Client_Type;
      Msg : AHT.Websocket.Client.Message_Type;
   begin
      begin
         AHT.Websocket.Client.Connect (C, "ws://127.0.0.1:8765/");
      exception
         when E : others =>
            Fail ("empty: Connect raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E)
                  & " (is server_ws.py running?)");
            Put_Line ("test_ws_ping:" & Failures'Image & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;

      AHT.Websocket.Client.Send_Ping (C);

      AHT.Websocket.Client.Send_Text (C, "alive");
      AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);
      if Msg.Kind /= AHT.Websocket.Text_Message
        or else To_String (Msg.Payload) /= "alive"
      then
         Fail ("empty: post-ping echo failed (kind=" & Msg.Kind'Image
               & ", payload=""" & To_String (Msg.Payload) & """)");
      end if;

      AHT.Websocket.Client.Close (C);
      if AHT.Websocket.Client.Is_Open (C) then
         Fail ("empty: Is_Open true after Close");
      end if;
   end;

   --  Case 2: ping with payload, stream stays alive.
   declare
      C   : AHT.Websocket.Client.Client_Type;
      Msg : AHT.Websocket.Client.Message_Type;
   begin
      AHT.Websocket.Client.Connect (C, "ws://127.0.0.1:8765/");
      AHT.Websocket.Client.Send_Ping (C, Ping_Payload);

      AHT.Websocket.Client.Send_Text (C, "alive-2");
      AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);
      if To_String (Msg.Payload) /= "alive-2" then
         Fail ("payload: post-ping echo failed (payload="""
               & To_String (Msg.Payload) & """)");
      end if;

      AHT.Websocket.Client.Close (C);
   end;

   --  Case 3: ping interleaved with data preserves ordering and the
   --  auto-Pong is dropped, not delivered as a message.
   declare
      C      : AHT.Websocket.Client.Client_Type;
      M1, M2 : AHT.Websocket.Client.Message_Type;
      Extra  : AHT.Websocket.Client.Message_Type;
      Started, Ended : Time;
      Got_Timeout    : Boolean := False;
   begin
      AHT.Websocket.Client.Connect (C, "ws://127.0.0.1:8765/");

      AHT.Websocket.Client.Send_Text (C, "before");
      AHT.Websocket.Client.Send_Ping (C, Ping_Payload);
      AHT.Websocket.Client.Send_Text (C, "after");

      AHT.Websocket.Client.Receive (C, M1, Timeout => 5.0);
      AHT.Websocket.Client.Receive (C, M2, Timeout => 5.0);
      if To_String (M1.Payload) /= "before"
        or else To_String (M2.Payload) /= "after"
      then
         Fail ("interleave: ordering — """ & To_String (M1.Payload)
               & """ / """ & To_String (M2.Payload)
               & """ (expected ""before"" / ""after"")");
      end if;

      --  Only two data messages were sent; the server's Pong must not
      --  surface as a third. A short Receive should time out.
      Started := Clock;
      begin
         AHT.Websocket.Client.Receive (C, Extra, Timeout => 0.3);
         Fail ("interleave: a third message arrived — payload="""
               & To_String (Extra.Payload)
               & """ (Pong leaked as a message?)");
      exception
         when AHT.Transport.Timeout_Error =>
            Got_Timeout := True;
         when E : others =>
            Fail ("interleave: wrong exception waiting for no-message — "
                  & Ada.Exceptions.Exception_Name (E));
      end;
      Ended := Clock;
      if Got_Timeout and then Ended - Started > 1.0 then
         Fail ("interleave: no-message Receive took"
               & Duration'Image (Ended - Started)
               & "s (Timeout was 0.3)");
      end if;

      AHT.Websocket.Client.Close (C);
   end;

   if Failures = 0 then
      Put_Line ("test_ws_ping: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_ping:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Ping;
