--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Example 2: a hand-built Request_Type (verb, URL, headers, body)
--  and the HEAD special case. A POST to /echo comes back with the body
--  and Content-Type reflected; a HEAD to /hello returns headers only,
--  with Content-Length set and Body_B empty. The client supplies
--  Host, Content-Length and Connection itself.
--
--  Run:  ./examples/bin/<mode>/ex_02_request [HOST]
--  HOST defaults to the fixture origin http://127.0.0.1:8764.

with Ada.Command_Line; use Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO;      use Ada.Text_IO;

with AHT.HTTP.Client;
with AHT.HTTP.Methods;
with AHT.HTTP.Request;
with AHT.HTTP.Response;
with AHT.URL;

procedure Ex_02_Request is

   Default_Host : constant String := "http://127.0.0.1:8764";

   Host : constant String :=
     (if Argument_Count >= 1 then Argument (1) else Default_Host);

   Client : AHT.HTTP.Client.Client_Type;
   Req    : AHT.HTTP.Request.Request_Type;
   Resp   : AHT.HTTP.Response.Response_Type;

   Payload : constant String := "name=AHT&kind=client";
begin
   --  POST: set the verb, target, a Content-Type, and the body bytes.
   Put_Line ("POST " & Host & "/echo");
   Req.Method := AHT.HTTP.Methods.POST;
   Req.Target := AHT.URL.Parse (Host & "/echo");
   Req.Headers.Set ("content-type", "application/x-www-form-urlencoded");
   Req.Set_Body (Payload);

   AHT.HTTP.Client.Send (Client, Req, Resp);
   Put_Line ("  status : " & Resp.Status'Image);
   Put_Line ("  echoed : " & Resp.Body_Text);

   --  HEAD: headers only on the wire; Content-Length survives, the
   --  body is empty.
   New_Line;
   Put_Line ("HEAD " & Host & "/hello");
   declare
      Head_Req  : AHT.HTTP.Request.Request_Type;
      Head_Resp : AHT.HTTP.Response.Response_Type;
   begin
      Head_Req.Method := AHT.HTTP.Methods.HEAD;
      Head_Req.Target := AHT.URL.Parse (Host & "/hello");
      AHT.HTTP.Client.Send (Client, Head_Req, Head_Resp);
      Put_Line ("  status         : " & Head_Resp.Status'Image);
      Put_Line ("  content-length : "
                & Head_Resp.Headers.Get ("content-length"));
      Put_Line ("  body bytes     :"
                & Natural'Image (Head_Resp.Body_B.Length));
   end;

   Set_Exit_Status (Success);

exception
   when E : others =>
      Put_Line ("request failed: "
                & Ada.Exceptions.Exception_Name (E) & ": "
                & Ada.Exceptions.Exception_Message (E));
      Put_Line ("(is the fixture up? try: bash examples/run_examples.sh)");
      Set_Exit_Status (Failure);
end Ex_02_Request;
