--  /protected returns 401 with WWW-Authenticate when the request
--  carries no Authorization header, and 200 echoing the header value
--  otherwise. Two cases:
--    1. unauthenticated → 401, WWW-Authenticate present.
--    2. with Authorization → 200, body == the header value we sent
--       (so we know AHT actually transmitted it; otherwise a server
--       that flipped on header *presence* alone could pass while AHT
--       had silently dropped the value).
--
--  Non-2xx is not an exception in v1 — Resp.Status carries the
--  signal — so the 401 case asserts on the response, not on a raised
--  exception.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.HTTP.Client;
with AHT.HTTP.Methods;
with AHT.HTTP.Request;
with AHT.HTTP.Response;
with AHT.URL;

procedure Test_HTTP_Auth is

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_http_auth: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function Body_To_String (V : AHT.Bytes.Buffer) return String is
     (AHT.Bytes.To_String (V));

   Bearer : constant String := "Bearer test-token-12345";

   C : AHT.HTTP.Client.Client_Type;
begin
   --  Case 1: no Authorization → 401.
   declare
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      begin
         Resp := AHT.HTTP.Client.Get
           (C, "http://127.0.0.1:8764/protected");
      exception
         when E : others =>
            Fail ("anon Get raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E)
                  & " (is tests/server/server.py running?)");
            Put_Line ("test_http_auth:" & Failures'Image & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;

      if Resp.Status /= 401 then
         Fail ("anon: status =" & Resp.Status'Image
               & " (expected 401)");
      end if;
      if not Resp.Headers.Contains ("www-authenticate") then
         Fail ("anon: WWW-Authenticate header missing");
      end if;
   end;

   --  Case 2: with Authorization → 200, body == the bearer string.
   declare
      Req  : AHT.HTTP.Request.Request_Type;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Req.Method := AHT.HTTP.Methods.GET;
      Req.Target := AHT.URL.Parse ("http://127.0.0.1:8764/protected");
      Req.Headers.Set ("authorization", Bearer);

      begin
         AHT.HTTP.Client.Send (C, Req, Resp);
      exception
         when E : others =>
            Fail ("auth Send raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
            Put_Line ("test_http_auth:" & Failures'Image & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;

      if Resp.Status /= 200 then
         Fail ("auth: status =" & Resp.Status'Image
               & " (expected 200)");
      end if;
      if Body_To_String (Resp.Body_B) /= Bearer & ASCII.LF then
         Fail ("auth: echoed header = """
               & Body_To_String (Resp.Body_B) & """");
      end if;
   end;

   if Failures = 0 then
      Put_Line ("test_http_auth: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_http_auth:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_HTTP_Auth;
