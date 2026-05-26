with Ada.Calendar; use Ada.Calendar;
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Streams; use Ada.Streams;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;
with GNAT.Sockets; use GNAT.Sockets;

with AHT.Bytes;
with AHT.HTTP;
with AHT.HTTP.Client;
with AHT.HTTP.Headers;
with AHT.HTTP.Methods;
with AHT.HTTP.Request;
with AHT.HTTP.Response;
with AHT.URL;

procedure Test_HTTP_Client is

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_http_client: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  In-process HTTP/1.1 server. One connection per task instance.
   --  The test configures the canned response and optional fixed
   --  Content-Length of the request body to drain; the task surfaces
   --  the full captured request (head + body) so tests can inspect
   --  what AHT actually put on the wire.
   --
   --  Set_Response is a separate entry so callers can build the
   --  response string (which may include the bound port) before the
   --  socket is bound. The task accepts Set_Response first, then
   --  binds, then yields the port via Get_Port — that way callers
   --  pass a fully-formed response that may reference no per-request
   --  state.
   task type HTTP_Server is
      entry Set_Response
        (R                   : String;
         Body_Bytes_To_Drain : Natural);
      entry Get_Port
        (P   : out AHT.URL.Port_Number;
         Err : out Unbounded_String);
      entry Wait_Done
        (Captured : out Unbounded_String;
         Err      : out Unbounded_String);
   end HTTP_Server;

   task body HTTP_Server is
      Server         : Socket_Type := No_Socket;
      Client         : Socket_Type;
      Peer           : Sock_Addr_Type;
      Bind_To        : Sock_Addr_Type;
      Bound          : Port_Type := 0;
      Setup_Error    : Unbounded_String;
      Runtime_Error  : Unbounded_String;
      Captured_Bytes : Unbounded_String;
      Response       : Unbounded_String;
      Body_Drain     : Natural := 0;

      function Contains_CRLFCRLF (S : Unbounded_String) return Natural is
      begin
         return Ada.Strings.Fixed.Index (To_String (S),
                                         ASCII.CR & ASCII.LF
                                         & ASCII.CR & ASCII.LF);
      end Contains_CRLFCRLF;
   begin
      accept Set_Response
        (R                   : String;
         Body_Bytes_To_Drain : Natural)
      do
         Response   := To_Unbounded_String (R);
         Body_Drain := Body_Bytes_To_Drain;
      end Set_Response;

      begin
         Create_Socket (Server, Family_Inet, Socket_Stream);
         Set_Socket_Option
           (Server, Socket_Level, (Name => Reuse_Address, Enabled => True));
         Bind_To.Addr := Inet_Addr ("127.0.0.1");
         Bind_To.Port := 0;
         Bind_Socket (Server, Bind_To);
         Listen_Socket (Server, 1);
         Bound := Get_Socket_Name (Server).Port;
      exception
         when E : others =>
            Setup_Error := To_Unbounded_String
              ("HTTP_Server setup: "
               & Ada.Exceptions.Exception_Message (E));
      end;

      accept Get_Port
        (P   : out AHT.URL.Port_Number;
         Err : out Unbounded_String)
      do
         if Length (Setup_Error) > 0 then
            P := 1;
         else
            P := AHT.URL.Port_Number (Bound);
         end if;
         Err := Setup_Error;
      end Get_Port;

      if Length (Setup_Error) = 0 then
         declare
            Selector : Selector_Type;
            R_Set    : Socket_Set_Type;
            W_Set    : Socket_Set_Type;
            Status   : Selector_Status;
         begin
            Create_Selector (Selector);
            Set (R_Set, Server);
            Check_Selector
              (Selector, R_Set, W_Set, Status, Timeout => 2.0);
            Close_Selector (Selector);

            if Status /= Completed then
               Runtime_Error := To_Unbounded_String
                 ("HTTP_Server: accept timed out");
            else
               begin
                  Accept_Socket (Server, Client, Peer);

                  --  Read until we have the full request: head ends
                  --  at the first CRLFCRLF, then exactly Body_Drain
                  --  more bytes for the body. The body may arrive in
                  --  the same TCP segment as the headers, so we
                  --  track total length against (separator + 3 +
                  --  Body_Drain) rather than reading head and body
                  --  in separate phases.
                  declare
                     Buf     : Stream_Element_Array (1 .. 4_096);
                     Last    : Stream_Element_Offset;
                     Sep_Idx : Natural := 0;
                  begin
                     loop
                        Receive_Socket (Client, Buf, Last);
                        exit when Last < Buf'First;
                        for I in Buf'First .. Last loop
                           Append (Captured_Bytes,
                                   Character'Val (Natural (Buf (I))));
                        end loop;
                        if Sep_Idx = 0 then
                           Sep_Idx := Contains_CRLFCRLF (Captured_Bytes);
                        end if;
                        exit when Sep_Idx /= 0
                          and then Length (Captured_Bytes)
                                     >= Sep_Idx + 3 + Body_Drain;
                     end loop;
                  end;

                  --  Send the canned response, then half-close so the
                  --  client's read-until-EOF (if it falls back to it)
                  --  terminates cleanly.
                  declare
                     R_Str : constant String := To_String (Response);
                     R_Buf : Stream_Element_Array
                       (1 .. Stream_Element_Offset (R_Str'Length));
                     Sent  : Stream_Element_Offset;
                  begin
                     for I in R_Str'Range loop
                        R_Buf
                          (Stream_Element_Offset
                             (I - R_Str'First + 1)) :=
                          Stream_Element (Character'Pos (R_Str (I)));
                     end loop;
                     if R_Buf'Length > 0 then
                        Send_Socket (Client, R_Buf, Sent);
                     end if;
                  end;

                  Shutdown_Socket (Client, Shut_Write);
                  Close_Socket (Client);
               exception
                  when E : others =>
                     Runtime_Error := To_Unbounded_String
                       ("HTTP_Server runtime: "
                        & Ada.Exceptions.Exception_Name (E) & " — "
                        & Ada.Exceptions.Exception_Message (E));
               end;
            end if;
         exception
            when E : others =>
               Runtime_Error := To_Unbounded_String
                 ("HTTP_Server selector: "
                  & Ada.Exceptions.Exception_Message (E));
         end;

         begin
            Close_Socket (Server);
         exception
            when others => null;
         end;
      end if;

      --  If the test bails out before calling Wait_Done (e.g. when
      --  Get_Port reported a setup error and the case skipped the
      --  client path), the parent declare block would otherwise wait
      --  forever for this rendezvous and hang the binary. The
      --  terminate alternative lets the task collapse cleanly once
      --  the master is waiting for it.
      select
         accept Wait_Done
           (Captured : out Unbounded_String;
            Err      : out Unbounded_String)
         do
            Captured := Captured_Bytes;
            Err      := Runtime_Error;
         end Wait_Done;
      or
         terminate;
      end select;
   end HTTP_Server;

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

   function Contains (Haystack, Needle : String) return Boolean is
     (Ada.Strings.Fixed.Index (Haystack, Needle) /= 0);

   --  Bounded helper: build the URL string for a port.
   function URL_For (Port : AHT.URL.Port_Number; Path : String) return String is
     ("http://127.0.0.1:"
      & Ada.Strings.Fixed.Trim
          (AHT.URL.Port_Number'Image (Port), Ada.Strings.Both)
      & Path);

begin

   --  Case 1: GET — default headers (Host, User-Agent, Connection:
   --  close) are auto-added; response body comes back intact.
   declare
      Server   : HTTP_Server;
      Port     : AHT.URL.Port_Number;
      Setup_Err, Run_Err : Unbounded_String;
      Captured : Unbounded_String;
      C        : AHT.HTTP.Client.Client_Type;
      Resp     : AHT.HTTP.Response.Response_Type;
   begin
      Server.Set_Response
        ("HTTP/1.1 200 OK" & ASCII.CR & ASCII.LF
         & "Content-Type: text/plain" & ASCII.CR & ASCII.LF
         & "Content-Length: 11" & ASCII.CR & ASCII.LF
         & ASCII.CR & ASCII.LF
         & "hello world",
         Body_Bytes_To_Drain => 0);

      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("GET: server setup: " & To_String (Setup_Err));
      else
         begin
            Resp := AHT.HTTP.Client.Get (C, URL_For (Port, "/hello"));
         exception
            when E : others =>
               Fail ("GET: client raised "
                     & Ada.Exceptions.Exception_Name (E) & ": "
                     & Ada.Exceptions.Exception_Message (E));
         end;

         Server.Wait_Done (Captured, Run_Err);
         if Length (Run_Err) > 0 then
            Fail ("GET: server runtime: " & To_String (Run_Err));
         end if;

         if Resp.Status /= 200 then
            Fail ("GET: status =" & Resp.Status'Image);
         end if;
         if Body_To_String (Resp.Body_B) /= "hello world" then
            Fail ("GET: body = """ & Body_To_String (Resp.Body_B) & """");
         end if;

         declare
            Req : constant String := To_String (Captured);
            Expected_Host : constant String :=
              "host: 127.0.0.1:"
              & Ada.Strings.Fixed.Trim
                  (AHT.URL.Port_Number'Image (Port), Ada.Strings.Both);
         begin
            if not Contains
              (Req, "GET /hello HTTP/1.1" & ASCII.CR & ASCII.LF)
            then
               Fail ("GET: request line missing/wrong");
            end if;
            if not Contains (Req, Expected_Host) then
               Fail ("GET: Host header missing: " & Expected_Host);
            end if;
            if not Contains (Req, "user-agent: AHT/0.1") then
               Fail ("GET: User-Agent default missing");
            end if;
            if not Contains (Req, "connection: close") then
               Fail ("GET: Connection: close default missing");
            end if;
         end;
      end if;
   end;

   --  Case 2: POST with body — Content-Length auto-injected,
   --  body bytes forwarded to the server, response body returned.
   declare
      Server   : HTTP_Server;
      Port     : AHT.URL.Port_Number;
      Setup_Err, Run_Err : Unbounded_String;
      Captured : Unbounded_String;
      C        : AHT.HTTP.Client.Client_Type;
      Req      : AHT.HTTP.Request.Request_Type;
      Resp     : AHT.HTTP.Response.Response_Type;
   begin
      Server.Set_Response
        ("HTTP/1.1 200 OK" & ASCII.CR & ASCII.LF
         & "Content-Length: 4" & ASCII.CR & ASCII.LF
         & ASCII.CR & ASCII.LF
         & "PONG",
         Body_Bytes_To_Drain => 4);

      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("POST: server setup: " & To_String (Setup_Err));
      else
         Req.Method := AHT.HTTP.Methods.POST;
         Req.Target := AHT.URL.Parse (URL_For (Port, "/echo"));
         declare
            Payload : constant String := "PING";
         begin
            for I in Payload'Range loop
               Req.Body_B.Append (Character'Pos (Payload (I)));
            end loop;
         end;

         begin
            AHT.HTTP.Client.Send (C, Req, Resp);
         exception
            when E : others =>
               Fail ("POST: client raised "
                     & Ada.Exceptions.Exception_Name (E) & ": "
                     & Ada.Exceptions.Exception_Message (E));
         end;

         Server.Wait_Done (Captured, Run_Err);
         if Length (Run_Err) > 0 then
            Fail ("POST: server runtime: " & To_String (Run_Err));
         end if;

         if Resp.Status /= 200 then
            Fail ("POST: status =" & Resp.Status'Image);
         end if;
         if Body_To_String (Resp.Body_B) /= "PONG" then
            Fail ("POST: body = """ & Body_To_String (Resp.Body_B) & """");
         end if;

         declare
            Req_Wire : constant String := To_String (Captured);
         begin
            if not Contains (Req_Wire, "content-length: 4" & ASCII.CR & ASCII.LF) then
               Fail ("POST: auto Content-Length missing");
            end if;
            if not Contains (Req_Wire,
                             ASCII.CR & ASCII.LF & ASCII.CR & ASCII.LF & "PING")
            then
               Fail ("POST: body bytes missing after head separator");
            end if;
         end;
      end if;
   end;

   --  Case 3: HEAD — the peer advertises Content-Length but sends no
   --  body. Client.Send with Method = HEAD must not block reading
   --  the announced body bytes.
   declare
      Server   : HTTP_Server;
      Port     : AHT.URL.Port_Number;
      Setup_Err, Run_Err : Unbounded_String;
      Captured : Unbounded_String;
      C        : AHT.HTTP.Client.Client_Type;
      Req      : AHT.HTTP.Request.Request_Type;
      Resp     : AHT.HTTP.Response.Response_Type;
      Started  : constant Ada.Calendar.Time := Ada.Calendar.Clock;
   begin
      C.Timeout_Seconds := 2;  -- safety: if we ever did block, fail fast
      Server.Set_Response
        ("HTTP/1.1 200 OK" & ASCII.CR & ASCII.LF
         & "Content-Length: 9999" & ASCII.CR & ASCII.LF
         & ASCII.CR & ASCII.LF,
         Body_Bytes_To_Drain => 0);

      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("HEAD: server setup: " & To_String (Setup_Err));
      else
         Req.Method := AHT.HTTP.Methods.HEAD;
         Req.Target := AHT.URL.Parse (URL_For (Port, "/big"));

         begin
            AHT.HTTP.Client.Send (C, Req, Resp);
         exception
            when E : others =>
               Fail ("HEAD: client raised "
                     & Ada.Exceptions.Exception_Name (E) & ": "
                     & Ada.Exceptions.Exception_Message (E));
         end;

         Server.Wait_Done (Captured, Run_Err);
         if Length (Run_Err) > 0 then
            Fail ("HEAD: server runtime: " & To_String (Run_Err));
         end if;

         if Resp.Status /= 200 then
            Fail ("HEAD: status =" & Resp.Status'Image);
         end if;
         if Natural (Resp.Body_B.Length) /= 0 then
            Fail ("HEAD: body non-empty, length ="
                  & Natural'Image (Natural (Resp.Body_B.Length)));
         end if;
         if Ada.Calendar.Clock - Started > 1.5 then
            Fail ("HEAD: Send took >1.5s — body suppression likely "
                  & "didn't fire");
         end if;
      end if;
   end;

   --  Case 4: interim 1xx — server sends 100 Continue then 200.
   --  Client must loop past the 1xx and return the 200.
   declare
      Server   : HTTP_Server;
      Port     : AHT.URL.Port_Number;
      Setup_Err, Run_Err : Unbounded_String;
      Captured : Unbounded_String;
      C        : AHT.HTTP.Client.Client_Type;
      Resp     : AHT.HTTP.Response.Response_Type;
   begin
      Server.Set_Response
        ("HTTP/1.1 100 Continue" & ASCII.CR & ASCII.LF
         & ASCII.CR & ASCII.LF
         & "HTTP/1.1 200 OK" & ASCII.CR & ASCII.LF
         & "Content-Length: 2" & ASCII.CR & ASCII.LF
         & ASCII.CR & ASCII.LF
         & "OK",
         Body_Bytes_To_Drain => 0);

      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("1xx: server setup: " & To_String (Setup_Err));
      else
         begin
            Resp := AHT.HTTP.Client.Get (C, URL_For (Port, "/wait"));
         exception
            when E : others =>
               Fail ("1xx: client raised "
                     & Ada.Exceptions.Exception_Name (E) & ": "
                     & Ada.Exceptions.Exception_Message (E));
         end;

         Server.Wait_Done (Captured, Run_Err);
         if Length (Run_Err) > 0 then
            Fail ("1xx: server runtime: " & To_String (Run_Err));
         end if;

         if Resp.Status /= 200 then
            Fail ("1xx: final status =" & Resp.Status'Image);
         end if;
         if Body_To_String (Resp.Body_B) /= "OK" then
            Fail ("1xx: final body = """
                  & Body_To_String (Resp.Body_B) & """");
         end if;
      end if;
   end;

   --  Case 5: non-2xx (500) is returned as a Response, not raised
   --  as an exception. Caller-visible signal must be Resp.Status.
   declare
      Server   : HTTP_Server;
      Port     : AHT.URL.Port_Number;
      Setup_Err, Run_Err : Unbounded_String;
      Captured : Unbounded_String;
      C        : AHT.HTTP.Client.Client_Type;
      Resp     : AHT.HTTP.Response.Response_Type;
   begin
      Server.Set_Response
        ("HTTP/1.1 500 Internal Server Error" & ASCII.CR & ASCII.LF
         & "Content-Length: 5" & ASCII.CR & ASCII.LF
         & ASCII.CR & ASCII.LF
         & "boom!",
         Body_Bytes_To_Drain => 0);

      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("500: server setup: " & To_String (Setup_Err));
      else
         begin
            Resp := AHT.HTTP.Client.Get (C, URL_For (Port, "/err"));
         exception
            when E : others =>
               Fail ("500: client raised "
                     & Ada.Exceptions.Exception_Name (E) & ": "
                     & Ada.Exceptions.Exception_Message (E));
         end;

         Server.Wait_Done (Captured, Run_Err);
         if Length (Run_Err) > 0 then
            Fail ("500: server runtime: " & To_String (Run_Err));
         end if;

         if Resp.Status /= 500 then
            Fail ("500: status =" & Resp.Status'Image);
         end if;
         if Body_To_String (Resp.Body_B) /= "boom!" then
            Fail ("500: body = """ & Body_To_String (Resp.Body_B) & """");
         end if;
      end if;
   end;

   --  Case 6: header precedence — Default_Headers["user-agent"]
   --  overrides Self.User_Agent, and an explicit Connection on the
   --  request beats the auto Connection: close default.
   declare
      Server   : HTTP_Server;
      Port     : AHT.URL.Port_Number;
      Setup_Err, Run_Err : Unbounded_String;
      Captured : Unbounded_String;
      C        : AHT.HTTP.Client.Client_Type;
      Req      : AHT.HTTP.Request.Request_Type;
      Resp     : AHT.HTTP.Response.Response_Type;
   begin
      Server.Set_Response
        ("HTTP/1.1 204 No Content" & ASCII.CR & ASCII.LF
         & ASCII.CR & ASCII.LF,
         Body_Bytes_To_Drain => 0);

      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("hdrs: server setup: " & To_String (Setup_Err));
      else
         C.Default_Headers.Set ("user-agent", "custom/9");
         C.Default_Headers.Set ("x-extra",    "1");

         Req.Method := AHT.HTTP.Methods.GET;
         Req.Target := AHT.URL.Parse (URL_For (Port, "/ping"));
         Req.Headers.Set ("connection", "keep-alive");

         begin
            AHT.HTTP.Client.Send (C, Req, Resp);
         exception
            when E : others =>
               Fail ("hdrs: client raised "
                     & Ada.Exceptions.Exception_Name (E) & ": "
                     & Ada.Exceptions.Exception_Message (E));
         end;

         Server.Wait_Done (Captured, Run_Err);
         if Length (Run_Err) > 0 then
            Fail ("hdrs: server runtime: " & To_String (Run_Err));
         end if;

         declare
            Wire : constant String := To_String (Captured);
         begin
            if not Contains (Wire, "user-agent: custom/9") then
               Fail ("hdrs: Default_Headers user-agent did not win "
                     & "over Self.User_Agent");
            end if;
            if Contains (Wire, "user-agent: AHT/0.1") then
               Fail ("hdrs: both User-Agent variants on the wire");
            end if;
            if not Contains (Wire, "x-extra: 1") then
               Fail ("hdrs: x-extra default missing");
            end if;
            if not Contains (Wire, "connection: keep-alive") then
               Fail ("hdrs: request Connection lost");
            end if;
            if Contains (Wire, "connection: close") then
               Fail ("hdrs: auto Connection: close overrode request");
            end if;
         end;
      end if;
   end;

   --  Case 7: wss:// URL is refused by the HTTP client.
   declare
      C    : AHT.HTTP.Client.Client_Type;
      Req  : AHT.HTTP.Request.Request_Type;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Req.Method := AHT.HTTP.Methods.GET;
      Req.Target := AHT.URL.Parse ("wss://example.com/sock");
      begin
         AHT.HTTP.Client.Send (C, Req, Resp);
         Fail ("wss: Send returned without raising");
      exception
         when AHT.HTTP.HTTP_Error => null;
         when E : others =>
            Fail ("wss: wrong exception "
                  & Ada.Exceptions.Exception_Name (E));
      end;
   end;

   if Failures = 0 then
      Put_Line ("test_http_client: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_http_client:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_HTTP_Client;
