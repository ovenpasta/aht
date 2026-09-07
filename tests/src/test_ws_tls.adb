--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  WebSocket client over wss://: Connect routes wss:// through
--  AHT.Transport.TLS with Insecure / CA_Path threaded into the
--  handshake; frame and close mechanics are in test_ws_echo. Against
--  server_ws_tls.py on localhost:8768 (named, so SNI matches the
--  cert's SAN); run from the repo root so the CA path resolves.
--
--  Cases:
--    1. CA_Path at the fixture's cert: text round-trip, clean Close
--    2. Insecure => True, no CA: binary round-trip
--    3. verify required, no CA: Connect propagates TLS_Error,
--       unwrapped, since the dial is outside the Handshake_Error
--       wrapper

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.Transport.TLS;
with AHT.Websocket;
with AHT.Websocket.Client;

procedure Test_WS_TLS is

   use type AHT.Bytes.Octet;
   use type AHT.Websocket.Message_Kind;

   URL     : constant String := "wss://localhost:8768/";
   CA_File : constant String := "tests/server/certs/server.crt";

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_tls: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function To_String (V : AHT.Bytes.Buffer) return String is
     (AHT.Bytes.To_String (V));

begin
   --  Case 1: verify against the fixture's own CA, then a text
   --  round-trip + clean Close over the TLS-wrapped WS connection.
   declare
      C   : AHT.Websocket.Client.Client_Type;
      Msg : AHT.Websocket.Client.Message_Type;
   begin
      begin
         AHT.Websocket.Client.Connect
           (C, URL, CA_Path => CA_File);
      exception
         when E : others =>
            Fail ("verify: Connect raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E)
                  & " (is server_ws_tls.py running?)");
            Put_Line ("test_ws_tls:" & Failures'Image & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;

      AHT.Websocket.Client.Send_Text (C, "secure, AHT!");

      begin
         AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);
      exception
         when E : others =>
            Fail ("verify: Receive raised "
                  & Ada.Exceptions.Exception_Name (E));
      end;

      if Msg.Kind /= AHT.Websocket.Text_Message then
         Fail ("verify: Kind = " & Msg.Kind'Image
               & " (expected Text_Message)");
      end if;
      if To_String (Msg.Payload) /= "secure, AHT!" then
         Fail ("verify: payload = """ & To_String (Msg.Payload)
               & """ (expected ""secure, AHT!"")");
      end if;

      AHT.Websocket.Client.Close (C);
      if AHT.Websocket.Client.Is_Open (C) then
         Fail ("verify: Is_Open true after Close");
      end if;
   end;

   --  Case 2: Insecure bypasses verification: no CA supplied, the
   --  self-signed cert is accepted and a 16-byte binary payload
   --  round-trips intact through the masking / framing path.
   declare
      C    : AHT.Websocket.Client.Client_Type;
      Msg  : AHT.Websocket.Client.Message_Type;
      Data : AHT.Bytes.Byte_Array (1 .. 16);
   begin
      begin
         AHT.Websocket.Client.Connect (C, URL, Insecure => True);
      exception
         when E : others =>
            Fail ("insecure: Connect raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
            Put_Line ("test_ws_tls:" & Failures'Image & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;

      for I in Data'Range loop
         Data (I) := AHT.Bytes.Octet (I - 1);
      end loop;

      AHT.Websocket.Client.Send_Binary (C, Data);
      AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);

      if Msg.Kind /= AHT.Websocket.Binary_Message then
         Fail ("insecure: Kind = " & Msg.Kind'Image
               & " (expected Binary_Message)");
      end if;
      if Msg.Payload.Length /= Data'Length then
         Fail ("insecure: payload length ="
               & Msg.Payload.Length'Image);
      else
         for I in Data'Range loop
            if Msg.Payload.Element (I) /= Data (I) then
               Fail ("insecure: byte" & I'Image & " differs");
               exit;
            end if;
         end loop;
      end if;

      AHT.Websocket.Client.Close (C);
   end;

   --  Case 3: verify required, no CA configured. The self-signed cert
   --  chains to no trusted root, so the TLS handshake must be rejected
   --  with TLS_Error propagated out of Connect (the dial sits before
   --  the handshake's Handshake_Error wrapper, so it stays unwrapped).
   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      AHT.Websocket.Client.Connect (C, URL);
      Fail ("untrusted: Connect returned without raising "
            & "(expected TLS_Error)");
   exception
      when AHT.Transport.TLS.TLS_Error =>
         null;  --  expected: untrusted chain rejected
      when E : others =>
         Fail ("untrusted: expected TLS_Error, got "
               & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end;

   if Failures = 0 then
      Put_Line ("test_ws_tls: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_tls:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_TLS;
