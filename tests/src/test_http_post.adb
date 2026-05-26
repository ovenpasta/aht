--  POST round-trip against /echo. Verifies that AHT.HTTP.Client.Send
--  forwards the body bytes intact and that the server's echo comes
--  back via Content-Length framing. Also pins down the auto-added
--  Content-Type round-trip — the server reflects whatever we sent,
--  so a regression that mangles Content-Type on the request would
--  show up here.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.HTTP.Client;
with AHT.HTTP.Methods;
with AHT.HTTP.Request;
with AHT.HTTP.Response;
with AHT.URL;

procedure Test_HTTP_Post is

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_http_post: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function Body_To_String (V : AHT.Bytes.Byte_Vector) return String is
      S : String (1 .. Natural (V.Length));
   begin
      for I in S'Range loop
         declare
            B : constant AHT.Bytes.Octet :=
              V.Element (V.First_Index + (I - 1));
         begin
            S (I) := Character'Val (Natural (B));
         end;
      end loop;
      return S;
   end Body_To_String;

   Payload : constant String :=
     "name=AHT&kind=client&note=integration%20test";

   C    : AHT.HTTP.Client.Client_Type;
   Req  : AHT.HTTP.Request.Request_Type;
   Resp : AHT.HTTP.Response.Response_Type;
begin
   Req.Method := AHT.HTTP.Methods.POST;
   Req.Target := AHT.URL.Parse ("http://127.0.0.1:8764/echo");
   Req.Headers.Set
     ("content-type", "application/x-www-form-urlencoded");
   for I in Payload'Range loop
      Req.Body_B.Append (Character'Pos (Payload (I)));
   end loop;

   begin
      AHT.HTTP.Client.Send (C, Req, Resp);
   exception
      when E : others =>
         Fail ("Client.Send raised "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E)
               & " (is tests/server/server.py running?)");
         Put_Line ("test_http_post:" & Failures'Image & " failure(s)");
         Ada.Command_Line.Set_Exit_Status (1);
         return;
   end;

   if Resp.Status /= 200 then
      Fail ("status =" & Resp.Status'Image);
   end if;
   if Resp.Headers.Get ("content-type")
      /= "application/x-www-form-urlencoded"
   then
      Fail ("content-type round-trip = """
            & Resp.Headers.Get ("content-type") & """");
   end if;
   if Body_To_String (Resp.Body_B) /= Payload then
      Fail ("echoed body = """
            & Body_To_String (Resp.Body_B) & """");
   end if;

   if Failures = 0 then
      Put_Line ("test_http_post: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_http_post:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_HTTP_Post;
