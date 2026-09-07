--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Example 1 — the simplest possible request.
--
--  `AHT.HTTP.Client.Get` is a one-line convenience wrapper: give it a
--  URL string, it parses the URL, builds a GET with no body, runs the
--  round trip, and hands back the full response. A fresh `Client_Type`
--  needs no configuration for plain HTTP. `Resp.Body_Text` renders the
--  body bytes as a String to print.
--
--  Run:  ./examples/bin/<mode>/ex_01_get [URL]
--  Default URL is the bundled fixture's /hello route; pass any http://
--  or https:// URL to point it elsewhere.

with Ada.Command_Line; use Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO;      use Ada.Text_IO;

with AHT.HTTP.Client;
with AHT.HTTP.Response;

procedure Ex_01_Get is

   Default_URL : constant String := "http://127.0.0.1:8764/hello";

   URL  : constant String :=
     (if Argument_Count >= 1 then Argument (1) else Default_URL);

   Client : AHT.HTTP.Client.Client_Type;
   Resp   : AHT.HTTP.Response.Response_Type;
begin
   Put_Line ("GET " & URL);

   Resp := AHT.HTTP.Client.Get (Client, URL);

   Put_Line ("  status : " & Resp.Status'Image);
   Put_Line ("  body   : " & Resp.Body_Text);
   Set_Exit_Status (Success);

exception
   when E : others =>
      Put_Line ("request failed: "
                & Ada.Exceptions.Exception_Name (E) & ": "
                & Ada.Exceptions.Exception_Message (E));
      Put_Line ("(is the fixture up? try: bash examples/run_examples.sh)");
      Set_Exit_Status (Failure);
end Ex_01_Get;
