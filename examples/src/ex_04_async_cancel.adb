--  Example 4 — fire a request off to the side, and cancel one.
--
--  `Send_Async` runs a request on a worker task and returns straight
--  away, so the caller can do other work; `Await` collects the result
--  (or re-raises whatever the worker hit). `Cancel`, from any task,
--  aborts an in-flight request — `Await` then re-raises
--  `Aborted_Error`.
--
--  Two parts:
--    * happy path — Send_Async to /hello, do a little work, Await the
--      200.
--    * cancel — point a second handle at the stall fixture (accepts
--      the connection, then never answers), fire it, Cancel after a
--      moment, and watch Await surface Aborted_Error instead of
--      hanging.
--
--  Run:  ./examples/bin/<mode>/ex_04_async_cancel [URL] [STALL_URL]
--  URL defaults to the fixture's /hello; STALL_URL defaults to the
--  stall fixture on :8767. Cancel takes effect on the response read,
--  so the stall target must accept the connection first.

with Ada.Command_Line; use Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO;      use Ada.Text_IO;

with AHT.HTTP.Client;
with AHT.HTTP.Methods;
with AHT.HTTP.Request;
with AHT.HTTP.Response;
with AHT.Transport;
with AHT.URL;

procedure Ex_04_Async_Cancel is

   Default_URL   : constant String := "http://127.0.0.1:8764/hello";
   Default_Stall : constant String := "http://127.0.0.1:8767/";

   URL : constant String :=
     (if Argument_Count >= 1 then Argument (1) else Default_URL);
   Stall_URL : constant String :=
     (if Argument_Count >= 2 then Argument (2) else Default_Stall);

   Client : AHT.HTTP.Client.Client_Type;
begin
   --  Happy path: kick it off, do other work, then collect.
   Put_Line ("async GET " & URL);
   declare
      Req  : AHT.HTTP.Request.Request_Type;
      Resp : AHT.HTTP.Response.Response_Type;
      H    : AHT.HTTP.Client.Async_Handle;
   begin
      Req.Method := AHT.HTTP.Methods.GET;
      Req.Target := AHT.URL.Parse (URL);
      AHT.HTTP.Client.Send_Async (Client, Req, H);

      Put_Line ("  (request running on a worker — doing other work)");

      AHT.HTTP.Client.Await (H, Resp);
      Put_Line ("  status : " & Resp.Status'Image);
      Put_Line ("  body   : " & Resp.Body_Text);
   end;

   --  Cancel: the stall target never answers, so without Cancel this
   --  would block until the timeout. Cancel makes Await raise.
   New_Line;
   Put_Line ("async GET " & Stall_URL & " (will cancel)");
   declare
      Req  : AHT.HTTP.Request.Request_Type;
      Resp : AHT.HTTP.Response.Response_Type;
      H    : AHT.HTTP.Client.Async_Handle;
   begin
      Client.Timeout_Seconds := 5;  --  backstop if Cancel never lands
      Req.Method := AHT.HTTP.Methods.GET;
      Req.Target := AHT.URL.Parse (Stall_URL);
      AHT.HTTP.Client.Send_Async (Client, Req, H);

      delay 0.2;  --  let the worker reach the (silent) response read
      Put_Line ("  cancelling ...");
      AHT.HTTP.Client.Cancel (H);

      begin
         AHT.HTTP.Client.Await (H, Resp);
         Put_Line ("  unexpected: Await returned status "
                   & Resp.Status'Image);
      exception
         when AHT.Transport.Aborted_Error =>
            Put_Line ("  Await raised Aborted_Error (as expected)");
      end;
   end;

   Set_Exit_Status (Success);

exception
   when E : others =>
      Put_Line ("request failed: "
                & Ada.Exceptions.Exception_Name (E) & ": "
                & Ada.Exceptions.Exception_Message (E));
      Put_Line ("(are the fixtures up? try: bash examples/run_examples.sh)");
      Set_Exit_Status (Failure);
end Ex_04_Async_Cancel;
