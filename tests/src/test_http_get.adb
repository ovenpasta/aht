--  Hits the Python fixture's /hello route and asserts the
--  response body bytes round-trip. The route returns a fixed
--  "hello, world\n" with Content-Length framing, so this is the
--  thinnest possible end-to-end check that AHT.HTTP.Client.Get can
--  drive a real HTTP/1.1 peer at all.
--
--  Server-bring-up is the orchestrator's job (tests/run_tests.sh).
--  If the server isn't running, Client.Get raises Transport_Error
--  on connect — the test catches it and reports clearly.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.HTTP.Client;
with AHT.HTTP.Response;

procedure Test_HTTP_Get is

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_http_get: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function Body_To_String (V : AHT.Bytes.Buffer) return String is
     (AHT.Bytes.To_String (V));

   C    : AHT.HTTP.Client.Client_Type;
   Resp : AHT.HTTP.Response.Response_Type;
begin
   begin
      Resp := AHT.HTTP.Client.Get
        (C, "http://127.0.0.1:8764/hello");
   exception
      when E : others =>
         Fail ("Client.Get raised "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E)
               & " (is tests/server/server.py running?)");
         Put_Line ("test_http_get:" & Failures'Image & " failure(s)");
         Ada.Command_Line.Set_Exit_Status (1);
         return;
   end;

   if Resp.Status /= 200 then
      Fail ("status =" & Resp.Status'Image);
   end if;
   if Resp.Headers.Get ("content-type") /= "text/plain" then
      Fail ("content-type = """
            & Resp.Headers.Get ("content-type") & """");
   end if;
   if Body_To_String (Resp.Body_B) /= "hello, world" & ASCII.LF then
      Fail ("body = """ & Body_To_String (Resp.Body_B) & """");
   end if;

   if Failures = 0 then
      Put_Line ("test_http_get: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_http_get:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_HTTP_Get;
