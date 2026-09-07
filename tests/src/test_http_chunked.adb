--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  End-to-end exercise of the chunked-transfer decoder against the
--  Python fixture. /chunked emits three uneven chunks ("AHT ",
--  "rocks", "!\n") with hex-length lines and a zero-size terminator; a
--  wrong reassembly (chunk-size off-by-one, mishandled CRLFs) fails the
--  body comparison. AHT.HTTP.IO's unit tests cover the framing rules.

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

   function Body_To_String (V : AHT.Bytes.Buffer) return String is
     (AHT.Bytes.To_String (V));

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

   --  Large single-chunk body (>12 MB): the chunk-size line names a
   --  size far bigger than the thread stack, so the decoder must read
   --  the chunk in bounded windows. The body is a 0..255 ramp compared
   --  element-wise, never materialised as a String, which would
   --  overflow the test's own stack.
   declare
      C2    : AHT.HTTP.Client.Client_Type;
      Resp2 : AHT.HTTP.Response.Response_Type;
      N     : constant := 13_000_000;
      Got   : Boolean := False;
   begin
      begin
         Resp2 := AHT.HTTP.Client.Get
           (C2, "http://127.0.0.1:8764/chunked-big");
         Got := True;
      exception
         when E : others =>
            Fail ("chunked-big: Client.Get raised "
                  & Ada.Exceptions.Exception_Name (E)
                  & " (did the chunk reader overflow the stack?)");
      end;

      if Got then
         if Resp2.Status /= 200 then
            Fail ("chunked-big: status =" & Resp2.Status'Image);
         elsif Resp2.Body_B.Length /= N then
            Fail ("chunked-big: body length ="
                  & Natural'Image (Resp2.Body_B.Length)
                  & " (expected" & Integer'Image (N) & ")");
         else
            for I in 0 .. N - 1 loop
               if Natural (Resp2.Body_B.Element (Resp2.Body_B.First_Index + I))
                 /= I mod 256
               then
                  Fail ("chunked-big: byte" & I'Image & " differs");
                  exit;
               end if;
            end loop;
         end if;
      end if;
   end;

   if Failures = 0 then
      Put_Line ("test_http_chunked: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_http_chunked:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_HTTP_Chunked;
