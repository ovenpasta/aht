--  Example 2 — build a request by hand, and the HEAD special case.
--
--  `Client.Get` only does GET-with-no-body. For anything else you
--  fill in a `Request_Type`: the verb, the target URL, any headers,
--  and (for POST/PUT/PATCH) the body bytes. The client supplies the
--  routing headers (Host, Content-Length, Connection) for you.
--
--  Two round trips here:
--    * a POST to /echo — the fixture reflects our body + Content-Type
--      so you can see the bytes made the trip intact.
--    * a HEAD to /hello — same wire as GET, but the server sends only
--      headers. The client suppresses body framing for HEAD, so the
--      response advertises a Content-Length while Body_B stays empty.
--
--  Run:  ./examples/bin/ex_02_request [HOST]
--  HOST defaults to the bundled fixture's origin; pass e.g.
--  http://127.0.0.1:8764 to retarget. Paths (/echo, /hello) are
--  appended for you.

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

   --  HEAD: headers only on the wire. Note the Content-Length header
   --  survives while the body is empty.
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
