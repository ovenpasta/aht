--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Redirect following in AHT.HTTP.Client, against the HTTP fixture
--  (8764) and the HTTPS fixture (8766), which share one route table.
--  /r/<status>?to=<location> answers any method with that status and
--  Location and a body that must never reach the caller; /inspect
--  answers with the method, body length and headers it received, so
--  every rule below is checked on what the last hop actually sent,
--  not on what the client meant to send.
--
--    1. Max_Redirects = 0 (the default) returns the 3xx as it came.
--    2. GET through 301, 302, 303, 307 and 308; 304 is not followed.
--    3. Method and body: POST becomes a bodiless GET through 301,
--       302 and 303 and stays a POST with its body through 307 and
--       308; PUT keeps method and body through 301; HEAD stays HEAD
--       through 303.
--    4. Relative Location, fragment inheritance, Final_URL.
--    5. Max_Redirects bounds the hops: the loop route counts them.
--    6. Credentials and Host: kept on the same origin, dropped on
--       another (from Req.Headers and Default_Headers alike).
--    7. Streaming: the Sink sees only the final body.
--    8. Streaming upload: a redirect that needs the body back is
--       returned as it came; one that drops it is followed.
--    9. Refusals: unparsable or non-HTTP Location, https to http.
--   10. http to https upgrade; Send_Async follows too.
--   11. The redirect filter: asked once per hop the built-in rules
--       allow, after them; Follow, Stop and Refuse; the per-request
--       form sees the caller's state, the field form works through
--       Send_Async and is asked first.
--   12. A redirect with an endless body is followed without reading
--       it to the end.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.HTTP;
with AHT.HTTP.Client;
with AHT.HTTP.Methods;
with AHT.HTTP.Request;
with AHT.HTTP.Response;
with AHT.HTTP.Status;
with AHT.URL;

with Test_Filters;

procedure Test_HTTP_Redirect is

   use type AHT.HTTP.Methods.Method_Type;
   use type AHT.URL.Scheme_Kind;

   package Client renames AHT.HTTP.Client;
   package Methods renames AHT.HTTP.Methods;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_http_redirect: FAIL - " & Msg);
      Failures := Failures + 1;
   end Fail;

   Base     : constant String := "http://127.0.0.1:8764";
   TLS_Base : constant String := "https://localhost:8766";
   CA_File  : constant String := "tests/server/certs/server.crt";
   Hello    : constant String := "hello, world" & ASCII.LF;

   function Contains (S, Pattern : String) return Boolean is
     (Ada.Strings.Fixed.Index (S, Pattern) > 0);

   --  The value of "name=value" on its own line of an /inspect body.
   function Field (Text, Name : String) return String is
      Key   : constant String := ASCII.LF & Name & "=";
      Whole : constant String := ASCII.LF & Text;
      At_K  : constant Natural := Ada.Strings.Fixed.Index (Whole, Key);
   begin
      if At_K = 0 then
         return "<missing>";
      end if;
      declare
         Start : constant Positive := At_K + Key'Length;
         Stop  : constant Natural :=
           Ada.Strings.Fixed.Index (Whole (Start .. Whole'Last), "" & ASCII.LF);
      begin
         return Whole (Start .. (if Stop = 0 then Whole'Last else Stop - 1));
      end;
   end Field;

   function Make
     (Method : Methods.Method_Type;
      URL    : String;
      Body_S : String := "") return AHT.HTTP.Request.Request_Type
   is
      R : AHT.HTTP.Request.Request_Type;
   begin
      R.Method := Method;
      R.Target := AHT.URL.Parse (URL);
      if Body_S'Length > 0 then
         R.Headers.Set ("content-type", "text/plain");
         R.Set_Body (Body_S);
      end if;
      return R;
   end Make;

   function Following (N : Natural := 5) return Client.Client_Type is
      C : Client.Client_Type;
   begin
      C.Max_Redirects := N;
      C.CA_Path := To_Unbounded_String (CA_File);
      return C;
   end Following;

   procedure Expect_Redirect_Error
     (Label : String;
      C     : in out Client.Client_Type;
      Req   : AHT.HTTP.Request.Request_Type;
      Says  : String)
   is
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Client.Send (C, Req, Resp);
      Fail (Label & ": no Redirect_Error, status" & Resp.Status'Image);
   exception
      when E : AHT.HTTP.Redirect_Error =>
         if not Contains (Ada.Exceptions.Exception_Message (E), Says) then
            Fail (Label & ": message """
                  & Ada.Exceptions.Exception_Message (E)
                  & """ lacks """ & Says & """");
         end if;
      when E : others =>
         Fail (Label & ": raised " & Ada.Exceptions.Exception_Name (E)
               & ": " & Ada.Exceptions.Exception_Message (E));
   end Expect_Redirect_Error;

   procedure Guard (Label : String; E : Ada.Exceptions.Exception_Occurrence) is
   begin
      Fail (Label & ": raised " & Ada.Exceptions.Exception_Name (E)
            & ": " & Ada.Exceptions.Exception_Message (E));
   end Guard;

begin
   ------------------------------------------------------------------
   --  1. Default: not followed.
   ------------------------------------------------------------------
   declare
      C    : Client.Client_Type;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Resp := Client.Get (C, Base & "/r/302?to=/hello");
      if Resp.Status /= 302
        or else Resp.Headers.Get ("location") /= "/hello"
        or else not Contains (Resp.Body_Text, "redirect body")
      then
         Fail ("default: got" & Resp.Status'Image & " """
               & Resp.Body_Text & """");
      end if;
      if To_String (Resp.Final_URL.Path) /= "/r/302" then
         Fail ("default: Final_URL path "
               & To_String (Resp.Final_URL.Path));
      end if;
   exception
      when E : others => Guard ("default", E);
   end;

   ------------------------------------------------------------------
   --  2 and 3. Status x method.
   ------------------------------------------------------------------
   declare
      type Code_List is array (Positive range <>) of Positive;
      Codes : constant Code_List := [301, 302, 303, 307, 308];
   begin
      for Code of Codes loop
         declare
            Img   : constant String :=
              Ada.Strings.Fixed.Trim (Code'Image, Ada.Strings.Both);
            Route : constant String := Base & "/r/" & Img & "?to=/inspect";
            C     : Client.Client_Type := Following;
            Resp  : AHT.HTTP.Response.Response_Type;
            Keeps : constant Boolean := Code in 307 | 308;
         begin
            --  GET through every code.
            Client.Send (C, Make (Methods.GET, Route), Resp);
            if Resp.Status /= 200
              or else Field (Resp.Body_Text, "method") /= "GET"
              or else Contains (Resp.Body_Text, "redirect body")
            then
               Fail ("GET via" & Code'Image & ":" & Resp.Status'Image
                     & " " & Resp.Body_Text);
            end if;
            if To_String (Resp.Final_URL.Path) /= "/inspect" then
               Fail ("GET via" & Code'Image & ": Final_URL "
                     & AHT.URL.To_String (Resp.Final_URL));
            end if;

            --  POST: kept by 307 / 308 only.
            Client.Send (C, Make (Methods.POST, Route, "abc"), Resp);
            declare
               T : constant String := Resp.Body_Text;
            begin
               if Keeps then
                  if Field (T, "method") /= "POST"
                    or else Field (T, "body") /= "3"
                    or else Field (T, "content-type") /= "text/plain"
                  then
                     Fail ("POST via" & Code'Image & " lost its body: " & T);
                  end if;
               elsif Field (T, "method") /= "GET"
                 or else Field (T, "body") /= "0"
                 or else Field (T, "content-type") /= "-"
               then
                  Fail ("POST via" & Code'Image
                        & " did not become a bodiless GET: " & T);
               end if;
            end;

            --  PUT: only 303 rewrites it.
            Client.Send (C, Make (Methods.PUT, Route, "abcd"), Resp);
            declare
               T : constant String := Resp.Body_Text;
            begin
               if Code = 303 then
                  if Field (T, "method") /= "GET"
                    or else Field (T, "body") /= "0"
                  then
                     Fail ("PUT via 303: " & T);
                  end if;
               elsif Field (T, "method") /= "PUT"
                 or else Field (T, "body") /= "4"
               then
                  Fail ("PUT via" & Code'Image & ": " & T);
               end if;
            end;
         exception
            when E : others => Guard ("code" & Code'Image, E);
         end;
      end loop;
   end;

   declare
      C    : Client.Client_Type := Following;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      --  HEAD stays HEAD through 303: the fixture's HEAD /hello
      --  answers 200 with no body.
      Client.Send (C, Make (Methods.HEAD, Base & "/r/303?to=/hello"), Resp);
      if Resp.Status /= 200
        or else To_String (Resp.Final_URL.Path) /= "/hello"
        or else Resp.Body_B.Length /= 0
      then
         Fail ("HEAD via 303:" & Resp.Status'Image & " "
               & AHT.URL.To_String (Resp.Final_URL));
      end if;

      --  304 is not a redirect.
      Resp := Client.Get (C, Base & "/r/304?to=/hello");
      if Resp.Status /= 304 then
         Fail ("304 was followed:" & Resp.Status'Image);
      end if;
   exception
      when E : others => Guard ("HEAD / 304", E);
   end;

   ------------------------------------------------------------------
   --  4. Relative Location, fragment, Final_URL.
   ------------------------------------------------------------------
   declare
      C    : Client.Client_Type := Following;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Resp := Client.Get (C, Base & "/r/302?to=../hello#frag");
      if Resp.Body_Text /= Hello then
         Fail ("relative: body """ & Resp.Body_Text & """");
      end if;
      if AHT.URL.To_String (Resp.Final_URL)
        /= "http://127.0.0.1:8764/hello#frag"
      then
         Fail ("relative: Final_URL "
               & AHT.URL.To_String (Resp.Final_URL));
      end if;
   exception
      when E : others => Guard ("relative", E);
   end;

   ------------------------------------------------------------------
   --  5. The hop bound. /r/loop?n=k points at n=k+1, so the Location
   --  of the last response read names how many requests were made:
   --  with Max_Redirects = 3 the fourth response, from n=3, points at
   --  n=4.
   ------------------------------------------------------------------
   declare
      C : Client.Client_Type := Following (3);
   begin
      Expect_Redirect_Error
        ("loop", C, Make (Methods.GET, Base & "/r/loop?n=0"),
         "redirects, last to /r/loop?n=4");
      C.Max_Redirects := 1;
      Expect_Redirect_Error
        ("loop, 1", C, Make (Methods.GET, Base & "/r/loop?n=0"),
         "last to /r/loop?n=2");
   end;

   ------------------------------------------------------------------
   --  6. Credentials and Host.
   ------------------------------------------------------------------
   declare
      C    : Client.Client_Type := Following;
      Resp : AHT.HTTP.Response.Response_Type;

      function Authed (URL : String) return AHT.HTTP.Request.Request_Type is
         R : AHT.HTTP.Request.Request_Type := Make (Methods.GET, URL);
      begin
         R.Headers.Set ("authorization", "Basic c2VjcmV0");
         return R;
      end Authed;
   begin
      C.Default_Headers.Set ("cookie", "session=1");

      Client.Send (C, Authed (Base & "/r/302?to=/inspect"), Resp);
      if Field (Resp.Body_Text, "authorization") /= "Basic c2VjcmV0"
        or else Field (Resp.Body_Text, "cookie") /= "session=1"
      then
         Fail ("same origin dropped credentials: " & Resp.Body_Text);
      end if;

      --  localhost is not 127.0.0.1 as an origin.
      Client.Send
        (C, Authed (Base & "/r/302?to=http://localhost:8764/inspect"), Resp);
      if Field (Resp.Body_Text, "authorization") /= "-"
        or else Field (Resp.Body_Text, "cookie") /= "-"
      then
         Fail ("other host got credentials: " & Resp.Body_Text);
      end if;
      if Field (Resp.Body_Text, "host") /= "localhost:8764" then
         Fail ("other host: Host " & Field (Resp.Body_Text, "host"));
      end if;

      --  Another scheme and port.
      Client.Send
        (C, Authed (Base & "/r/302?to=https://localhost:8766/inspect"), Resp);
      if Resp.Status /= 200
        or else Field (Resp.Body_Text, "authorization") /= "-"
      then
         Fail ("https origin got credentials:" & Resp.Status'Image & " "
               & Resp.Body_Text);
      end if;

      --  A caller's Host is the first hop's only.
      declare
         R : AHT.HTTP.Request.Request_Type :=
           Make (Methods.GET, Base & "/r/302?to=/inspect");
      begin
         R.Headers.Set ("host", "custom.example");
         Client.Send (C, R, Resp);
         if Field (Resp.Body_Text, "host") /= "127.0.0.1:8764" then
            Fail ("caller Host followed the redirect: "
                  & Field (Resp.Body_Text, "host"));
         end if;
      end;
   exception
      when E : others => Guard ("credentials", E);
   end;

   ------------------------------------------------------------------
   --  7. Streaming download: only the final body reaches the Sink.
   ------------------------------------------------------------------
   declare
      C    : Client.Client_Type := Following;
      Resp : AHT.HTTP.Response.Response_Type;
      Got  : AHT.Bytes.Buffer;

      procedure Sink (Chunk : AHT.Bytes.Byte_Array) is
      begin
         Got.Append (Chunk);
      end Sink;
   begin
      Client.Send_Streaming
        (C, Make (Methods.GET, Base & "/r/301?to=/r/302%3Fto%3D/hello"),
         Resp, Sink'Access);
      if Got.To_String /= Hello then
         Fail ("streaming: Sink got """ & Got.To_String & """");
      end if;
   exception
      when E : others => Guard ("streaming", E);
   end;

   ------------------------------------------------------------------
   --  8. Streaming upload.
   ------------------------------------------------------------------
   declare
      type Text_Source is new AHT.HTTP.Request.Body_Source with record
         Sent : Boolean := False;
      end record;

      overriding procedure Read_Chunk
        (Self : in out Text_Source;
         Buf  : out AHT.Bytes.Byte_Array;
         Last : out Natural) is
      begin
         if Self.Sent then
            Last := Buf'First - 1;
         else
            Buf (Buf'First .. Buf'First + 4) := AHT.Bytes.From_String ("hello");
            Last := Buf'First + 4;
            Self.Sent := True;
         end if;
      end Read_Chunk;

      C    : Client.Client_Type := Following;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      declare
         Src : Text_Source;
      begin
         Client.Send_Streaming_Body
           (C, Make (Methods.POST, Base & "/r/307?to=/inspect"), Resp, Src);
         if Resp.Status /= 307
           or else not Contains (Resp.Body_Text, "redirect body")
         then
            Fail ("upload via 307 was followed:" & Resp.Status'Image);
         end if;
      end;
      declare
         Src : Text_Source;
      begin
         Client.Send_Streaming_Body
           (C, Make (Methods.POST, Base & "/r/303?to=/inspect"), Resp, Src);
         if Resp.Status /= 200
           or else Field (Resp.Body_Text, "method") /= "GET"
           or else Field (Resp.Body_Text, "body") /= "0"
         then
            Fail ("upload via 303:" & Resp.Status'Image & " "
                  & Resp.Body_Text);
         end if;
      end;
   exception
      when E : others => Guard ("upload", E);
   end;

   ------------------------------------------------------------------
   --  9. Refusals.
   ------------------------------------------------------------------
   declare
      C : Client.Client_Type := Following;
   begin
      Expect_Redirect_Error
        ("gopher", C, Make (Methods.GET, Base & "/r/302?to=gopher://x/"),
         "unusable Location");
      Expect_Redirect_Error
        ("ws", C, Make (Methods.GET, Base & "/r/302?to=ws://127.0.0.1:8765/"),
         "non-HTTP");
      Expect_Redirect_Error
        ("downgrade", C,
         Make (Methods.GET,
               TLS_Base & "/r/302?to=http://127.0.0.1:8764/inspect"),
         "refusing https to http");

      C.Allow_Redirect_Downgrade := True;
      declare
         Resp : AHT.HTTP.Response.Response_Type;
      begin
         Client.Send
           (C, Make (Methods.GET,
                     TLS_Base & "/r/302?to=http://127.0.0.1:8764/inspect"),
            Resp);
         if Resp.Status /= 200
           or else Resp.Final_URL.Scheme /= AHT.URL.HTTP
         then
            Fail ("allowed downgrade:" & Resp.Status'Image);
         end if;
      exception
         when E : others => Guard ("allowed downgrade", E);
      end;
   end;

   ------------------------------------------------------------------
   --  10. Upgrade to https, and the async surface.
   ------------------------------------------------------------------
   declare
      C    : Client.Client_Type := Following;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Resp := Client.Get
        (C, Base & "/r/308?to=https://localhost:8766/hello");
      if Resp.Status /= 200 or else Resp.Body_Text /= Hello
        or else Resp.Final_URL.Scheme /= AHT.URL.HTTPS
      then
         Fail ("upgrade:" & Resp.Status'Image & " " & Resp.Body_Text);
      end if;
   exception
      when E : others => Guard ("upgrade", E);
   end;

   declare
      C     : Client.Client_Type := Following;
      Async : Client.Async_Handle;
      Resp  : AHT.HTTP.Response.Response_Type;
   begin
      Client.Send_Async (C, Make (Methods.GET, Base & "/r/302?to=/hello"),
                         Async);
      Client.Await (Async, Resp);
      if Resp.Body_Text /= Hello then
         Fail ("async: """ & Resp.Body_Text & """");
      end if;
   exception
      when E : others => Guard ("async", E);
   end;

   ------------------------------------------------------------------
   --  11. The redirect filter. The per-request form is a nested
   --  function writing to this block's variables, which is the point
   --  of it: the decision can depend on the request in hand.
   ------------------------------------------------------------------
   declare
      Calls   : Natural := 0;
      Trail   : Unbounded_String;
      Stop_At : Natural := 0;     --  0: never
      Refuse_At : Natural := 0;

      function Filter
        (From, To : AHT.URL.URL_Type;
         Status   : AHT.HTTP.Status.Status_Code;
         Hop      : Positive) return Client.Redirect_Decision is
      begin
         Calls := Calls + 1;
         Append (Trail, Hop'Image & ":" & To_String (From.Path) & ">"
                 & To_String (To.Path) & Status'Image);
         if Hop = Stop_At then
            return Client.Stop;
         elsif Hop = Refuse_At then
            return Client.Refuse;
         end if;
         return Client.Follow;
      end Filter;

      Chain : constant String := Base & "/r/301?to=/r/302%3Fto%3D/hello";
      C     : Client.Client_Type := Following;
      Resp  : AHT.HTTP.Response.Response_Type;
   begin
      --  Asked once per hop, with what the hop is.
      Client.Send (C, Make (Methods.GET, Chain), Resp,
                   On_Redirect => Filter'Access);
      if Resp.Body_Text /= Hello
        or else To_String (Trail)
                /= " 1:/r/301>/r/302 301 2:/r/302>/hello 302"
      then
         Fail ("filter trail: """ & To_String (Trail) & """, body """
               & Resp.Body_Text & """");
      end if;

      --  Stop: the second 3xx is the response, headers kept, body gone.
      Stop_At := 2;
      Client.Send (C, Make (Methods.GET, Chain), Resp,
                   On_Redirect => Filter'Access);
      if Resp.Status /= 302
        or else Resp.Headers.Get ("location") /= "/hello"
        or else To_String (Resp.Final_URL.Path) /= "/r/302"
        or else Resp.Body_B.Length /= 0
      then
         Fail ("filter Stop:" & Resp.Status'Image & " at "
               & AHT.URL.To_String (Resp.Final_URL));
      end if;

      --  Refuse.
      Stop_At := 0;
      Refuse_At := 1;
      begin
         Client.Send (C, Make (Methods.GET, Chain), Resp,
                      On_Redirect => Filter'Access);
         Fail ("filter Refuse: no exception");
      exception
         when E : AHT.HTTP.Redirect_Error =>
            if not Contains (Ada.Exceptions.Exception_Message (E),
                             "/r/302?to=/hello refused by the redirect filter")
            then
               Guard ("filter Refuse", E);
            end if;
      end;

      --  The built-in rules come first: a hop they refuse never
      --  reaches the filter, and the hop bound still counts.
      Refuse_At := 0;
      Calls := 0;
      begin
         Client.Send
           (C, Make (Methods.GET,
                     TLS_Base & "/r/302?to=http://127.0.0.1:8764/inspect"),
            Resp, On_Redirect => Filter'Access);
         Fail ("filter after downgrade: no exception");
      exception
         when AHT.HTTP.Redirect_Error => null;
      end;
      if Calls /= 0 then
         Fail ("filter was asked about a refused downgrade");
      end if;
      C.Max_Redirects := 2;
      begin
         Client.Send (C, Make (Methods.GET, Base & "/r/loop?n=0"), Resp,
                      On_Redirect => Filter'Access);
         Fail ("filter with loop: no exception");
      exception
         when AHT.HTTP.Redirect_Error => null;
      end;
      if Calls /= 2 then
         Fail ("filter with Max_Redirects 2: asked" & Calls'Image & " times");
      end if;

      --  The field form, through Send_Async; and field before
      --  parameter, so a field's Refuse leaves the parameter unasked.
      C.Max_Redirects := 5;
      C.On_Redirect := Test_Filters.Refuse_Redirects'Access;
      Calls := 0;
      Test_Filters.Redirect_Calls := 0;
      declare
         Async : Client.Async_Handle;
      begin
         Client.Send_Async (C, Make (Methods.GET, Chain), Async);
         Client.Await (Async, Resp);
         Fail ("field filter, async: no exception");
      exception
         when AHT.HTTP.Redirect_Error => null;
      end;
      begin
         Client.Send (C, Make (Methods.GET, Chain), Resp,
                      On_Redirect => Filter'Access);
         Fail ("field filter, sync: no exception");
      exception
         when AHT.HTTP.Redirect_Error => null;
      end;
      if Test_Filters.Redirect_Calls /= 2 or else Calls /= 0 then
         Fail ("field filter: field asked"
               & Test_Filters.Redirect_Calls'Image & ", parameter"
               & Calls'Image);
      end if;
   exception
      when E : others => Guard ("redirect filter", E);
   end;

   ------------------------------------------------------------------
   --  12. A redirect whose body never ends. The fixture writes until
   --  the client closes; a client that drained it would sit there
   --  until the read deadline and raise Timeout_Error.
   ------------------------------------------------------------------
   declare
      C    : Client.Client_Type := Following;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      C.Read_Deadline := Client.Seconds (5.0);
      Resp := Client.Get (C, Base & "/r-endless?to=/hello");
      if Resp.Status /= 200 or else Resp.Body_Text /= Hello then
         Fail ("endless redirect body:" & Resp.Status'Image);
      end if;
   exception
      when E : others => Guard ("endless redirect body", E);
   end;

   if Failures = 0 then
      Put_Line ("test_http_redirect: OK");
   else
      Put_Line ("test_http_redirect:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_HTTP_Redirect;
