--  End-to-end exercise of the chunked-transfer decoder. The /chunked
--  route emits three deliberately uneven chunks ("AHT ", "rocks",
--  "!\n") with hex-length lines and a zero-size terminator; the
--  decoder in AHT.HTTP.IO has unit tests for the framing rules, but
--  this is the first time it runs against a real HTTP server rather
--  than a hand-built mock script. If reassembly is wrong (off-by-one
--  in chunk-size parsing, mishandled CRLFs between chunks) the body
--  string won't match.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.HTTP.Client;
with AHT.HTTP.Response;

procedure Test_HTTP_Chunked is

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_http_chunked: FAIL — " & Msg);
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

   Expected : constant String := "AHT rocks!" & ASCII.LF;
   C        : AHT.HTTP.Client.Client_Type;
   Resp     : AHT.HTTP.Response.Response_Type;
begin
   begin
      Resp := AHT.HTTP.Client.Get
        (C, "http://127.0.0.1:8764/chunked");
   exception
      when E : others =>
         Fail ("Client.Get raised "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E)
               & " (is tests/server/server.py running?)");
         Put_Line ("test_http_chunked:" & Failures'Image & " failure(s)");
         Ada.Command_Line.Set_Exit_Status (1);
         return;
   end;

   if Resp.Status /= 200 then
      Fail ("status =" & Resp.Status'Image);
   end if;
   if Resp.Headers.Get ("transfer-encoding") /= "chunked" then
      Fail ("transfer-encoding = """
            & Resp.Headers.Get ("transfer-encoding") & """");
   end if;
   if Resp.Headers.Contains ("content-length") then
      Fail ("Content-Length leaked into chunked response headers");
   end if;
   if Body_To_String (Resp.Body_B) /= Expected then
      Fail ("reassembled body = """
            & Body_To_String (Resp.Body_B) & """ "
            & "(expected """ & Expected & """)");
   end if;

   if Failures = 0 then
      Put_Line ("test_http_chunked: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_http_chunked:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_HTTP_Chunked;
