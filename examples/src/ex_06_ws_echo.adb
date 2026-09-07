--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Example 6 — the minimal WebSocket lifecycle.
--
--  A WebSocket connection is long-lived and bidirectional, unlike the
--  one-shot HTTP request/response of the earlier rungs. The four calls
--  here are the whole story for the simple, blocking style:
--    * Connect  — dial the URL and run the RFC 6455 upgrade handshake.
--    * Send_Text — frame and send a text message (masked, per spec).
--    * Receive   — block for the next decoded message off the wire.
--    * Close     — run the closing handshake and tear the socket down.
--  The fixture echoes whatever we send, so what we Receive is our own
--  message coming back.
--
--  Run:  ./examples/bin/<mode>/ex_06_ws_echo [URL]
--  URL defaults to the bundled echo fixture on :8765; pass any ws://
--  (or wss://) URL to retarget.

with Ada.Command_Line; use Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO;      use Ada.Text_IO;

with AHT.Bytes;
with AHT.Websocket.Client;

procedure Ex_06_WS_Echo is

   Default_URL : constant String := "ws://127.0.0.1:8765/";

   URL : constant String :=
     (if Argument_Count >= 1 then Argument (1) else Default_URL);

   C   : AHT.Websocket.Client.Client_Type;
   Msg : AHT.Websocket.Client.Message_Type;
begin
   Put_Line ("WS connect " & URL);
   AHT.Websocket.Client.Connect (C, URL);
   Put_Line ("  open : " & AHT.Websocket.Client.Is_Open (C)'Image);

   AHT.Websocket.Client.Send_Text (C, "hello over a socket");
   Put_Line ("  sent : hello over a socket");

   AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);
   Put_Line ("  kind : " & Msg.Kind'Image);
   Put_Line ("  echo : " & AHT.Bytes.To_String (Msg.Payload));

   AHT.Websocket.Client.Close (C);
   Put_Line ("  open : " & AHT.Websocket.Client.Is_Open (C)'Image
             & " (after Close)");

   Set_Exit_Status (Success);

exception
   when E : others =>
      Put_Line ("ws failed: "
                & Ada.Exceptions.Exception_Name (E) & ": "
                & Ada.Exceptions.Exception_Message (E));
      Put_Line ("(is the fixture up? try: bash examples/run_examples.sh)");
      --  If the socket opened before the failure, close it so the
      --  client's receiver task is torn down (Timeout 0.0 = abort now,
      --  don't wait for a peer echo). Skipping this leaves the receiver
      --  blocked on a read and hangs scope exit.
      if AHT.Websocket.Client.Is_Open (C) then
         begin
            AHT.Websocket.Client.Close (C, Timeout => 0.0);
         exception
            when others => null;
         end;
      end if;
      Set_Exit_Status (Failure);
end Ex_06_WS_Echo;
