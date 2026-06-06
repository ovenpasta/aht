--  Interop check against go-httpbin (mccutchen/go-httpbin), a real,
--  widely-used third-party HTTP/1.1 server — proof that AHT.HTTP.Client
--  talks to more than its own Python fixture. The orchestrator
--  (tests/run_tests.sh) installs/starts go-httpbin only when a Go
--  toolchain is available and exports its base URL in AHT_HTTPBIN_URL;
--  when that variable is unset this test SKIPs cleanly (exit 0) so the
--  suite stays green on machines without Go.
--
--  Endpoints exercised (all deterministic, no JSON parsing required):
--    /status/204, /status/418   status-code passthrough (non-2xx is not
--                               an exception)
--    /bytes/256                 Content-Length framing round-trips
--    /redirect/1                a redirect surfaces raw (AHT does not
--                               auto-follow) with a Location header
--    /get                       JSON content-type on a vanilla GET
--    POST /post                 a buffered request body reaches the peer

with Ada.Command_Line;
with Ada.Environment_Variables;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.HTTP.Client;
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

   --  A redirect is delivered raw (AHT does not auto-follow): a 3xx
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
