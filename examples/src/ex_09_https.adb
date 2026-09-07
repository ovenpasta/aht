--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Example 9: the one-line GET of ex_01 over https:// against the TLS
--  fixture on :8766. Client.Get sees the scheme and runs the round
--  trip over AHT.Transport.TLS. Trust is two Client_Type fields:
--  Insecure => True accepts any certificate (the fixture's is
--  self-signed); production leaves it False and sets CA_Path instead.
--
--  Run:  ./examples/bin/<mode>/ex_09_https [URL]
--  A public https:// host works with Insecure left False.

with Ada.Command_Line; use Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO;      use Ada.Text_IO;

with AHT.HTTP.Client;
with AHT.HTTP.Response;

procedure Ex_09_HTTPS is

   Default_URL : constant String := "https://127.0.0.1:8766/hello";

   URL  : constant String :=
     (if Argument_Count >= 1 then Argument (1) else Default_URL);

   Client : AHT.HTTP.Client.Client_Type;
   Resp   : AHT.HTTP.Response.Response_Type;
begin
   Put_Line ("GET " & URL & " (TLS, accepting self-signed cert)");

   --  Trust the fixture's self-signed cert; production sets CA_Path
   --  and leaves this False.
   Client.Insecure := True;

   Resp := AHT.HTTP.Client.Get (Client, URL);

   Put_Line ("  status : " & Resp.Status'Image);
   Put_Line ("  body   : " & Resp.Body_Text);
   Set_Exit_Status (Success);

exception
   when E : others =>
      Put_Line ("request failed: "
                & Ada.Exceptions.Exception_Name (E) & ": "
                & Ada.Exceptions.Exception_Message (E));
      Put_Line ("(is the TLS fixture up + cert generated? "
                & "try: bash examples/run_examples.sh)");
      Set_Exit_Status (Failure);
end Ex_09_HTTPS;
