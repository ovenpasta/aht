--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Example 9: the one-line GET of ex_01 over https:// against the TLS
--  fixture on :8766. Client.Get sees the scheme and runs the round
--  trip over AHT.Transport.TLS. Trust is never implicit: the client
--  chooses one source of anchors (Use_System_Roots, CA_Path or
--  CA_PEM) or sets Insecure. This one trusts the platform's store,
--  which AHT.Root_Store reads; SSL_CERT_FILE replaces it, and
--  examples/run_examples.sh points it at the fixture's self-signed
--  certificate.
--
--  Run:  SSL_CERT_FILE=tests/server/certs/server.crt \
--          ./examples/bin/<mode>/ex_09_https
--  or:   ./examples/bin/<mode>/ex_09_https https://example.org/

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
   Put_Line ("GET " & URL & " (TLS, verified against the system store)");

   Client.Use_System_Roots := True;

   Resp := AHT.HTTP.Client.Get (Client, URL);

   Put_Line ("  status : " & Resp.Status'Image);
   Put_Line ("  body   : " & Resp.Body_Text);
   Set_Exit_Status (Success);

exception
   when E : others =>
      Put_Line ("request failed: "
                & Ada.Exceptions.Exception_Name (E) & ": "
                & Ada.Exceptions.Exception_Message (E));
      Put_Line ("(is the TLS fixture up, the cert generated and "
                & "SSL_CERT_FILE pointing at it? "
                & "try: bash examples/run_examples.sh)");
      Set_Exit_Status (Failure);
end Ex_09_HTTPS;
