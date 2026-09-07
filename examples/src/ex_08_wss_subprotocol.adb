--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Example 8: wss:// with subprotocol negotiation against the TLS
--  echo fixture on :8768. Insecure => True accepts the self-signed
--  fixture cert (production sets CA_Path instead). Connect's offer
--  form takes a subprotocol list and Extra_Headers (an empty map is
--  fine); Selected_Subprotocol reports the server's pick, "" if none.
--
--  Run:  ./examples/bin/<mode>/ex_08_wss_subprotocol [URL]
--  Needs the cert from scripts/generate_cert.sh.

with Ada.Command_Line; use Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO;      use Ada.Text_IO;

with AHT.Bytes;
with AHT.HTTP.Headers;
with AHT.Websocket.Client;

procedure Ex_08_WSS_Subprotocol is

   Default_URL : constant String := "wss://127.0.0.1:8768/";

   URL : constant String :=
     (if Argument_Count >= 1 then Argument (1) else Default_URL);

   No_Extra_Headers : AHT.HTTP.Headers.Map;  --  empty: client adds its own

   C   : AHT.Websocket.Client.Client_Type;
   Msg : AHT.Websocket.Client.Message_Type;
begin
   Put_Line ("WSS connect " & URL & " (offering subprotocol ""chat"")");
   AHT.Websocket.Client.Connect
     (C, URL,
      Extra_Headers => No_Extra_Headers,
      Subprotocols  => "chat",
      Insecure      => True);

   Put_Line ("  subprotocol : """
             & AHT.Websocket.Client.Selected_Subprotocol (C) & """");

   AHT.Websocket.Client.Send_Text (C, "secure hello");
   AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);
   Put_Line ("  echo        : " & AHT.Bytes.To_String (Msg.Payload));

   AHT.Websocket.Client.Close (C);
   Set_Exit_Status (Success);

exception
   when E : others =>
      Put_Line ("wss failed: "
                & Ada.Exceptions.Exception_Name (E) & ": "
                & Ada.Exceptions.Exception_Message (E));
      Put_Line ("(is the wss fixture up + cert generated? "
                & "try: bash examples/run_examples.sh)");
      --  Tear down the receiver task if the socket opened before the
      --  failure (Timeout 0.0 = abort now); otherwise scope exit blocks
      --  on the still-running receiver.
      if AHT.Websocket.Client.Is_Open (C) then
         begin
            AHT.Websocket.Client.Close (C, Timeout => 0.0);
         exception
            when others => null;
         end;
      end if;
      Set_Exit_Status (Failure);
end Ex_08_WSS_Subprotocol;
