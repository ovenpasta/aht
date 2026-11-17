--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Interop check against go-httpbin (mccutchen/go-httpbin), a
--  third-party HTTP/1.1 server. run_tests.sh starts it only with a Go
--  toolchain and exports its base URL in AHT_HTTPBIN_URL; unset, this
--  test SKIPs (exit 0).
--
--  Cases:
--    /status/204, /status/418: status passthrough; non-2xx not raised.
--    /bytes/256: Content-Length framing round-trips.
--    /redirect/1: with the default Max_Redirects (0) a 3xx surfaces
--      raw with Location.
--    /redirect/3, /absolute-redirect/2, /relative-redirect/2: followed
--      to /get with Max_Redirects set; /redirect-to with 307 keeps a
--      POST and its body, with 303 turns it into a GET.
--    /gzip, /deflate: decoded with Max_Decoded_Bytes set; the JSON they carry
--      says which coding the server applied.
--    Two GETs through one Pool leave one idle connection.
--    /get: JSON content-type on a vanilla GET.
--    POST /post: a buffered request body reaches the peer.

with Ada.Command_Line;
with Ada.Environment_Variables;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.HTTP.Client;
with AHT.HTTP.Connection_Pools;
with AHT.HTTP.Methods;
with AHT.HTTP.Request;
with AHT.HTTP.Response;
with AHT.URL;

procedure Test_HTTPbin is

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_httpbin: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   Base : constant String :=
     Ada.Environment_Variables.Value ("AHT_HTTPBIN_URL", "");

   function "+" (S : String) return Unbounded_String
     renames To_Unbounded_String;

   Follow_Paths : constant array (1 .. 3) of Unbounded_String :=
     [+"/redirect/3", +"/absolute-redirect/2", +"/relative-redirect/2"];

   type Code_List is array (Positive range <>) of Positive;
   Redirect_Codes : constant Code_List := [303, 307];

   Codings : constant array (1 .. 2) of Unbounded_String :=
     [+"gzip", +"deflate"];

   --  GET Path and assert the status equals Want.
   procedure Check_Status (Title, Path : String; Want : Integer) is
      C    : AHT.HTTP.Client.Client_Type;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Resp := AHT.HTTP.Client.Get (C, Base & Path);
      if Resp.Status /= Want then
         Fail (Title & ": status =" & Resp.Status'Image
               & " (want" & Want'Image & ")");
      end if;
   exception
      when E : others =>
         Fail (Title & ": raised " & Ada.Exceptions.Exception_Name (E)
               & " — " & Ada.Exceptions.Exception_Message (E));
   end Check_Status;

begin
   if Base = "" then
      Put_Line ("test_httpbin: SKIP (AHT_HTTPBIN_URL unset; "
                & "install Go to enable the go-httpbin fixture)");
      Ada.Command_Line.Set_Exit_Status (0);
      return;
   end if;

   Check_Status ("status-204", "/status/204", 204);
   Check_Status ("status-418", "/status/418", 418);

   --  Content-Length framing: /bytes/N returns exactly N bytes.
   declare
      C    : AHT.HTTP.Client.Client_Type;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Resp := AHT.HTTP.Client.Get (C, Base & "/bytes/256");
      if Resp.Status /= 200 then
         Fail ("bytes-256: status =" & Resp.Status'Image);
      end if;
      if Resp.Body_B.Length /= 256 then
         Fail ("bytes-256: body_len =" & Natural'Image (Resp.Body_B.Length));
      end if;
      if Resp.Headers.Get ("content-length") /= "256" then
         Fail ("bytes-256: content-length = """
               & Resp.Headers.Get ("content-length") & """");
      end if;
   exception
      when E : others =>
         Fail ("bytes-256: raised " & Ada.Exceptions.Exception_Name (E)
               & " — " & Ada.Exceptions.Exception_Message (E));
   end;

   --  With Max_Redirects left at 0 a redirect is delivered raw: a 3xx
   --  status plus a non-empty Location header.
   declare
      C    : AHT.HTTP.Client.Client_Type;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Resp := AHT.HTTP.Client.Get (C, Base & "/redirect/1");
      case Resp.Status is
         when 301 | 302 | 303 | 307 | 308 => null;
         when others =>
            Fail ("redirect: status =" & Resp.Status'Image
                  & " (want a 3xx)");
      end case;
      if Resp.Headers.Get ("location") = "" then
         Fail ("redirect: missing Location header");
      end if;
   exception
      when E : others =>
         Fail ("redirect: raised " & Ada.Exceptions.Exception_Name (E)
               & " — " & Ada.Exceptions.Exception_Message (E));
   end;

   --  Followed redirects end at /get.
   for P of Follow_Paths loop
      declare
         Path : constant String := To_String (P);
         C    : AHT.HTTP.Client.Client_Type;
         Resp : AHT.HTTP.Response.Response_Type;
      begin
         C.Max_Redirects := 5;
         Resp := AHT.HTTP.Client.Get (C, Base & Path);
         if Resp.Status /= 200
           or else To_String (Resp.Final_URL.Path) /= "/get"
         then
            Fail (Path & ": status" & Resp.Status'Image
                  & ", ended at " & AHT.URL.To_String (Resp.Final_URL));
         end if;
      exception
         when E : others =>
            Fail (Path & ": raised " & Ada.Exceptions.Exception_Name (E)
                  & " — " & Ada.Exceptions.Exception_Message (E));
      end;
   end loop;

   --  /redirect-to: 307 keeps the POST and its body, 303 does not.
   for Code of Redirect_Codes loop
      declare
         C    : AHT.HTTP.Client.Client_Type;
         Req  : AHT.HTTP.Request.Request_Type;
         Resp : AHT.HTTP.Response.Response_Type;
         Img  : constant String :=
           Ada.Strings.Fixed.Trim (Code'Image, Ada.Strings.Both);
         Want : constant String := (if Code = 307 then "/post" else "/get");
      begin
         C.Max_Redirects := 1;
         Req.Method := AHT.HTTP.Methods.POST;
         Req.Target := AHT.URL.Parse
           (Base & "/redirect-to?url=" & Want & "&status_code=" & Img);
         Req.Headers.Set ("content-type", "text/plain");
         Req.Set_Body ("redirected payload");
         AHT.HTTP.Client.Send (C, Req, Resp);
         if Resp.Status /= 200 then
            Fail ("redirect-to " & Img & ": status" & Resp.Status'Image);
         elsif Code = 307
           and then Ada.Strings.Fixed.Index
                      (Resp.Body_Text, "redirected payload") = 0
         then
            Fail ("redirect-to 307: body lost: " & Resp.Body_Text);
         end if;
      exception
         when E : others =>
            Fail ("redirect-to " & Img & ": raised "
                  & Ada.Exceptions.Exception_Name (E)
                  & " — " & Ada.Exceptions.Exception_Message (E));
      end;
   end loop;

   --  Content codings, as go-httpbin applies them.
   for Name of Codings loop
      declare
         Coding : constant String := To_String (Name);
         C      : AHT.HTTP.Client.Client_Type;
         Resp   : AHT.HTTP.Response.Response_Type;
         Flag   : constant String :=
           (if Coding = "gzip" then """gzipped""" else """deflated""");
      begin
         C.Max_Decoded_Bytes := 1_000_000;
         Resp := AHT.HTTP.Client.Get (C, Base & "/" & Coding);
         if Resp.Status /= 200 or else not Resp.Decoded
           or else Ada.Strings.Fixed.Index (Resp.Body_Text, Flag) = 0
         then
            Fail ("/" & Coding & ": status" & Resp.Status'Image
                  & ", decoded " & Resp.Decoded'Image & ": "
                  & Resp.Body_Text);
         end if;
      exception
         when E : others =>
            Fail ("/" & Coding & ": raised "
                  & Ada.Exceptions.Exception_Name (E)
                  & " — " & Ada.Exceptions.Exception_Message (E));
      end;
   end loop;

   --  Keep-alive: go-httpbin keeps HTTP/1.1 connections open.
   declare
      C    : AHT.HTTP.Client.Client_Type;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      C.Pool := AHT.HTTP.Connection_Pools.Create;
      Resp := AHT.HTTP.Client.Get (C, Base & "/get");
      Resp := AHT.HTTP.Client.Get (C, Base & "/bytes/64");
      if Resp.Status /= 200
        or else AHT.HTTP.Connection_Pools.Idle_Count (C.Pool) /= 1
      then
         Fail ("keep-alive: status" & Resp.Status'Image & ", idle"
               & AHT.HTTP.Connection_Pools.Idle_Count (C.Pool)'Image);
      end if;
   exception
      when E : others =>
         Fail ("keep-alive: raised " & Ada.Exceptions.Exception_Name (E)
               & " — " & Ada.Exceptions.Exception_Message (E));
   end;

   --  Vanilla GET advertises JSON.
   declare
      C    : AHT.HTTP.Client.Client_Type;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Resp := AHT.HTTP.Client.Get (C, Base & "/get");
      if Resp.Status /= 200 then
         Fail ("get: status =" & Resp.Status'Image);
      end if;
      declare
         Got : constant String := Resp.Headers.Get ("content-type");
      begin
         if Ada.Strings.Fixed.Index (Got, "application/json") = 0 then
            Fail ("get: content-type = """ & Got & """");
         end if;
      end;
   exception
      when E : others =>
         Fail ("get: raised " & Ada.Exceptions.Exception_Name (E)
               & " — " & Ada.Exceptions.Exception_Message (E));
   end;

   --  Buffered upload: POST a body and confirm the peer echoes it back.
   declare
      C     : AHT.HTTP.Client.Client_Type;
      Req   : AHT.HTTP.Request.Request_Type;
      Resp  : AHT.HTTP.Response.Response_Type;
      Token : constant String := "aht-httpbin-probe-42";
   begin
      Req.Method := AHT.HTTP.Methods.POST;
      Req.Target := AHT.URL.Parse (Base & "/post");
      Req.Headers.Set ("content-type", "text/plain");
      Req.Body_B.Set (Token);
      AHT.HTTP.Client.Send (C, Req, Resp);
      if Resp.Status /= 200 then
         Fail ("post: status =" & Resp.Status'Image);
      end if;
      if Ada.Strings.Fixed.Index
           (AHT.Bytes.To_String (Resp.Body_B), Token) = 0
      then
         Fail ("post: echoed body did not contain the sent token");
      end if;
   exception
      when E : others =>
         Fail ("post: raised " & Ada.Exceptions.Exception_Name (E)
               & " — " & Ada.Exceptions.Exception_Message (E));
   end;

   if Failures = 0 then
      Put_Line ("test_httpbin: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_httpbin:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_HTTPbin;
