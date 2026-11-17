--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Content decoding through AHT.HTTP.Client against the HTTP
--  fixture's /coded routes (see tests/server/server.py). The decoder
--  itself is test_inflate's; this test covers what the client and the
--  response reader add around it:
--
--    1. Max_Decoded_Bytes set: every gzip, x-gzip and deflate variant decodes
--       to the fixture's plain bytes, under Content-Length, chunked
--       (1-byte and 7-byte chunks, so the decoder's reads straddle
--       chunk boundaries) and read-until-close framing; Decoded is
--       set and Content-Encoding / Content-Length are gone.
--    2. Max_Decoded_Bytes 0 (the default): wire bytes and headers as sent.
--    3. Left alone even with Max_Decoded_Bytes set: an unknown coding,
--       identity, and a 206.
--    4. Accept-Encoding: sent only when decoding, never over the
--       caller's own.
--    5. A body that fails its CRC raises Protocol_Error, as does one
--       that decodes past Max_Decoded_Bytes, after exactly that many
--       bytes were delivered.
--    6. Streaming: Sink slices are non-empty, at most 4 KiB, and
--       concatenate to the plain body; Send_Async decodes too.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes; use AHT.Bytes;
with AHT.HTTP;
with AHT.HTTP.Client;
with AHT.HTTP.Methods;
with AHT.HTTP.Request;
with AHT.HTTP.Response;
with AHT.URL;

procedure Test_HTTP_Decompress is

   package Client renames AHT.HTTP.Client;

   use type AHT.Bytes.Octet;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_http_decompress: FAIL - " & Msg);
      Failures := Failures + 1;
   end Fail;

   procedure Guard (Label : String; E : Ada.Exceptions.Exception_Occurrence) is
   begin
      Fail (Label & ": raised " & Ada.Exceptions.Exception_Name (E)
            & ": " & Ada.Exceptions.Exception_Message (E));
   end Guard;

   Base : constant String := "http://127.0.0.1:8764";

   function Plain_Of (Variant : String) return Byte_Array is
      C : Client.Client_Type;
   begin
      return Client.Get (C, Base & "/coded/" & Variant & "?plain")
               .Body_B.To_Array;
   end Plain_Of;

   function "+" (S : String) return Unbounded_String
     renames To_Unbounded_String;

   Variants : constant array (Positive range <>) of Unbounded_String :=
     [+"gzip-text",  +"gzip-random", +"gzip-small",  +"gzip-mixed",
      +"gzip-empty", +"gzip-fields", +"gzip-multi",  +"gzip-level0",
      +"gzip-x",     +"zlib-text",   +"zlib-mixed",  +"raw-text",
      +"raw-mixed",  +"raw-level0"];

   Untouched : constant array (Positive range <>) of Unbounded_String :=
     [+"br-opaque", +"identity"];

   Framings : constant array (Positive range <>) of Unbounded_String :=
     [+"", +"?framing=chunked&chunk=1", +"?framing=chunked&chunk=7",
      +"?framing=eof"];

begin
   ------------------------------------------------------------------
   --  1. Every variant, every framing.
   ------------------------------------------------------------------
   for V of Variants loop
      declare
         Name  : constant String := To_String (V);
         Plain : constant Byte_Array := Plain_Of (Name);
         C     : Client.Client_Type;
      begin
         C.Max_Decoded_Bytes := 1_000_000;
         for F of Framings loop
            declare
               URL  : constant String :=
                 Base & "/coded/" & Name & To_String (F);
               Resp : AHT.HTTP.Response.Response_Type;
            begin
               Resp := Client.Get (C, URL);
               if Resp.Body_B.To_Array /= Plain then
                  Fail (URL & ": decoded" & Resp.Body_B.Length'Image
                        & " bytes differ from the" & Plain'Length'Image
                        & " plain ones");
               end if;
               if not Resp.Decoded
                 or else Resp.Headers.Contains ("content-encoding")
                 or else Resp.Headers.Contains ("content-length")
               then
                  Fail (URL & ": Decoded / coding headers not updated");
               end if;
            exception
               when E : others => Guard (URL, E);
            end;
         end loop;
      exception
         when E : others => Guard (Name, E);
      end;
   end loop;

   ------------------------------------------------------------------
   --  2. Off by default.
   ------------------------------------------------------------------
   declare
      C    : Client.Client_Type;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Resp := Client.Get (C, Base & "/coded/gzip-small");
      if Resp.Decoded
        or else Resp.Headers.Get ("content-encoding") /= "gzip"
        or else Resp.Body_B.Length < 2
        or else Resp.Body_B.Element (1) /= 16#1F#
        or else Resp.Body_B.Element (2) /= 16#8B#
      then
         Fail ("default: gzip body was not delivered as sent");
      end if;
   exception
      when E : others => Guard ("default", E);
   end;

   ------------------------------------------------------------------
   --  3. Codings left alone.
   ------------------------------------------------------------------
   declare
      C    : Client.Client_Type;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      C.Max_Decoded_Bytes := 1_000_000;
      for Name of Untouched loop
         Resp := Client.Get (C, Base & "/coded/" & To_String (Name));
         if Resp.Decoded
           or else not Resp.Headers.Contains ("content-encoding")
           or else Resp.Body_B.To_Array /= Plain_Of (To_String (Name))
         then
            Fail (To_String (Name) & ": was touched");
         end if;
      end loop;

      Resp := Client.Get (C, Base & "/coded-partial");
      if Resp.Status /= 206
        or else Resp.Decoded
        or else Resp.Body_B.Length /= 100
      then
         Fail ("206: status" & Resp.Status'Image & ", decoded "
               & Resp.Decoded'Image & "," & Resp.Body_B.Length'Image
               & " bytes");
      end if;
   exception
      when E : others => Guard ("left alone", E);
   end;

   ------------------------------------------------------------------
   --  4. Accept-Encoding.
   ------------------------------------------------------------------
   declare
      C    : Client.Client_Type;
      Resp : AHT.HTTP.Response.Response_Type;
      Req  : AHT.HTTP.Request.Request_Type;
   begin
      Resp := Client.Get (C, Base & "/accept-encoding");
      if Resp.Body_Text /= "<none>" then
         Fail ("off: sent Accept-Encoding " & Resp.Body_Text);
      end if;

      C.Max_Decoded_Bytes := 1_000_000;
      Resp := Client.Get (C, Base & "/accept-encoding");
      if Resp.Body_Text /= "gzip, deflate" then
         Fail ("on: Accept-Encoding " & Resp.Body_Text);
      end if;

      Req.Method := AHT.HTTP.Methods.GET;
      Req.Target := AHT.URL.Parse (Base & "/accept-encoding");
      Req.Headers.Set ("Accept-Encoding", "identity");
      Client.Send (C, Req, Resp);
      if Resp.Body_Text /= "identity" then
         Fail ("caller's Accept-Encoding replaced by " & Resp.Body_Text);
      end if;

      C.Default_Headers.Set ("accept-encoding", "gzip");
      Resp := Client.Get (C, Base & "/accept-encoding");
      if Resp.Body_Text /= "gzip" then
         Fail ("default header replaced by " & Resp.Body_Text);
      end if;
   exception
      when E : others => Guard ("accept-encoding", E);
   end;

   ------------------------------------------------------------------
   --  5. A bad CRC is a Protocol_Error.
   ------------------------------------------------------------------
   declare
      C    : Client.Client_Type;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      C.Max_Decoded_Bytes := 1_000_000;
      Resp := Client.Get (C, Base & "/coded/gzip-bad-crc");
      Fail ("bad CRC: no exception, status" & Resp.Status'Image);
   exception
      when E : AHT.HTTP.Protocol_Error =>
         if Ada.Strings.Fixed.Index
              (Ada.Exceptions.Exception_Message (E), "CRC-32") = 0
         then
            Fail ("bad CRC: message " & Ada.Exceptions.Exception_Message (E));
         end if;
      when E : others => Guard ("bad CRC", E);
   end;

   ------------------------------------------------------------------
   --  5b. The decoded-size bound. gzip-small decodes to 26 bytes: a
   --  bound of 26 passes, 25 raises after delivering 25. A streaming
   --  Sink shows what was delivered before the raise.
   ------------------------------------------------------------------
   declare
      C    : Client.Client_Type;
      Resp : AHT.HTTP.Response.Response_Type;
      Seen : Natural := 0;

      procedure Sink (Chunk : Byte_Array) is
      begin
         Seen := Seen + Chunk'Length;
      end Sink;

      Req : AHT.HTTP.Request.Request_Type;
   begin
      C.Max_Decoded_Bytes := 26;
      Resp := Client.Get (C, Base & "/coded/gzip-small");
      if Resp.Body_B.Length /= 26 then
         Fail ("bound 26:" & Resp.Body_B.Length'Image & " bytes");
      end if;

      C.Max_Decoded_Bytes := 25;
      Req.Method := AHT.HTTP.Methods.GET;
      Req.Target := AHT.URL.Parse (Base & "/coded/gzip-small");
      begin
         Client.Send_Streaming (C, Req, Resp, Sink'Access);
         Fail ("bound 25: no exception");
      exception
         when E : AHT.HTTP.Protocol_Error =>
            if Ada.Strings.Fixed.Index
                 (Ada.Exceptions.Exception_Message (E),
                  "exceeds Max_Decoded (25 bytes)") = 0
            then
               Guard ("bound 25", E);
            end if;
      end;
      if Seen /= 25 then
         Fail ("bound 25: Sink saw" & Seen'Image & " bytes");
      end if;

      --  A large body against a small bound.
      C.Max_Decoded_Bytes := 10_000;
      Seen := 0;
      Req.Target := AHT.URL.Parse (Base & "/coded/gzip-text");
      begin
         Client.Send_Streaming (C, Req, Resp, Sink'Access);
         Fail ("bound 10000: no exception");
      exception
         when AHT.HTTP.Protocol_Error => null;
      end;
      if Seen /= 10_000 then
         Fail ("bound 10000: Sink saw" & Seen'Image & " bytes");
      end if;
   exception
      when E : others => Guard ("bound", E);
   end;

   ------------------------------------------------------------------
   --  6. Streaming and async.
   ------------------------------------------------------------------
   declare
      C     : Client.Client_Type;
      Resp  : AHT.HTTP.Response.Response_Type;
      Got   : Buffer;
      Calls : Natural := 0;
      Bad   : Boolean := False;
      Plain : constant Byte_Array := Plain_Of ("gzip-mixed");

      procedure Sink (Chunk : Byte_Array) is
      begin
         Calls := Calls + 1;
         if Chunk'Length = 0 or else Chunk'Length > 4_096 then
            Bad := True;
         end if;
         Got.Append (Chunk);
      end Sink;

      Req : AHT.HTTP.Request.Request_Type;
   begin
      C.Max_Decoded_Bytes := 1_000_000;
      Req.Method := AHT.HTTP.Methods.GET;
      Req.Target := AHT.URL.Parse
        (Base & "/coded/gzip-mixed?framing=chunked&chunk=1000");
      Client.Send_Streaming (C, Req, Resp, Sink'Access);
      if Bad then
         Fail ("streaming: a slice was empty or over 4 KiB");
      end if;
      if Got.To_Array /= Plain then
         Fail ("streaming: bytes differ");
      end if;
      if Calls < Plain'Length / 4_096 then
         Fail ("streaming:" & Calls'Image & " Sink calls");
      end if;
      if Resp.Body_B.Length /= 0 or else not Resp.Decoded then
         Fail ("streaming: Body_B filled or Decoded unset");
      end if;

      declare
         Async : Client.Async_Handle;
      begin
         Client.Send_Async (C, Req, Async);
         Client.Await (Async, Resp);
         if Resp.Body_B.To_Array /= Plain then
            Fail ("async: bytes differ");
         end if;
      end;
   exception
      when E : others => Guard ("streaming", E);
   end;

   if Failures = 0 then
      Put_Line ("test_http_decompress: OK");
   else
      Put_Line ("test_http_decompress:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_HTTP_Decompress;
