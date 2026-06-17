--  Example 8 — a secure socket (wss://) with subprotocol negotiation.
--
--  Two things layered on the basic socket of ex_06:
--    * wss:// — the WebSocket runs over TLS. Here we pass Insecure =>
--      True so the bundled self-signed fixture cert is accepted without a
--      CA; in production you would instead set CA_Path to your trust
--      anchor and leave Insecure False (the secure default).
--    * subprotocols — at handshake time the client offers a list of
--      application protocols in Sec-WebSocket-Protocol; the server picks
--      at most one. Selected_Subprotocol reports the server's choice
--      ("" if it declined). The fixture is configured to offer "chat",
--      so offering "chat" here gets it echoed back as the selection.
--
--  Using the offer/header form of Connect means supplying Extra_Headers;
--  an empty Headers.Map is fine (the client fills in the required
--  handshake headers itself).
--
--  Run:  ./examples/bin/<mode>/ex_08_wss_subprotocol [URL]
--  URL defaults to the bundled wss echo fixture on :8768. Needs the
--  cert from scripts/generate_cert.sh (run_examples.sh generates it).

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
      --  on the still-running receiver. See ex_06 for the full rationale.
      if AHT.Websocket.Client.Is_Open (C) then
         begin
            AHT.Websocket.Client.Close (C, Timeout => 0.0);
         exception
            when others => null;
         end;
      end if;
      Set_Exit_Status (Failure);
end Ex_08_WSS_Subprotocol;
