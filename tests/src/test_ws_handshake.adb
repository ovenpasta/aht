--  WebSocket handshake-only integration test (commit 1 of the WS
--  client work). Exercises the deterministic protocol foundation:
--  Base64 encoding, the HTTP upgrade request, and the 101 / Upgrade
--  / Connection / Sec-WebSocket-Accept validation. Frame I/O comes
--  in commit 2.
--
--  Routing:
--    * ws://127.0.0.1:8765/ — the Python `websockets` echo fixture.
--      Successful handshake leaves the transport ready for frames.
--    * http://127.0.0.1:8764/hello — the plain HTTP fixture.
--      Returns 200, not 101 → Handshake_Error.
--    * wss://127.0.0.1:8766/ (Insecure) — TLS dials the HTTPS-only
--      fixture, which answers the upgrade non-101 → Handshake_Error.
--    * http://…/… — refused with Handshake_Error (not a WS URL).

with Ada.Calendar; use Ada.Calendar;
with Ada.Characters.Handling;
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Streams; use Ada.Streams;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;
with GNAT.Sockets; use GNAT.Sockets;

with GNAT.SHA1;

with AHT.Bytes;
with AHT.HTTP.Headers;
with AHT.URL;
with AHT.Websocket;
with AHT.Websocket.Client;
with AHT.Websocket.Frames;

procedure Test_WS_Handshake is

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_handshake: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Re-implementation of Connect's internal Sec-WebSocket-Accept
   --  computation so the fake server can answer with a valid Accept
   --  given the client's randomly-generated Key. The body is
   --  identical to the one in aht-websocket-client.adb (Hex digest
   --  → bytes → Base64) by design — these need to agree exactly.
   function Hex_To_Bytes (Hex : String) return AHT.Bytes.Byte_Array is
      function Val (C : Character) return Natural is
        (case C is
           when '0' .. '9' =>
             Character'Pos (C) - Character'Pos ('0'),
           when 'a' .. 'f' =>
             10 + Character'Pos (C) - Character'Pos ('a'),
           when 'A' .. 'F' =>
             10 + Character'Pos (C) - Character'Pos ('A'),
           when others => raise Program_Error);
      B : AHT.Bytes.Byte_Array (1 .. Hex'Length / 2);
   begin
      for I in 0 .. B'Length - 1 loop
         B (B'First + I) :=
           AHT.Bytes.Octet
             (16 * Val (Hex (Hex'First + 2 * I))
              +    Val (Hex (Hex'First + 2 * I + 1)));
      end loop;
      return B;
   end Hex_To_Bytes;

   function Compute_Accept (Key : String) return String is
      Guid : constant String :=
        "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
      Hex  : constant String := GNAT.SHA1.Digest (Key & Guid);
   begin
      return AHT.Bytes.Base64_Encode (Hex_To_Bytes (Hex));
   end Compute_Accept;

   --  Scan the request bytes for "sec-websocket-key:" (case-
   --  insensitive) and return the value up to the next CRLF,
   --  trimmed of surrounding whitespace.
   function Extract_Key (Request_Bytes : String) return String is
      Lower : constant String :=
        Ada.Characters.Handling.To_Lower (Request_Bytes);
      Marker : constant String := "sec-websocket-key:";
      Idx    : constant Natural := Ada.Strings.Fixed.Index
                                     (Lower, Marker);
      Value_Start : Natural;
      Value_End   : Natural;
   begin
      if Idx = 0 then
         return "";
      end if;
      Value_Start := Idx + Marker'Length;
      Value_End := Ada.Strings.Fixed.Index
                     (Request_Bytes
                        (Value_Start .. Request_Bytes'Last),
                      ASCII.CR & ASCII.LF);
      if Value_End = 0 then
         return "";
      end if;
      return Ada.Strings.Fixed.Trim
        (Request_Bytes (Value_Start .. Value_End - 1),
         Ada.Strings.Both);
   end Extract_Key;

   --  In-process fake WS handshake server. Accepts one connection,
   --  reads the request, computes the correct Sec-WebSocket-Accept
   --  for the client's Key, and writes a 101 response whose extra
   --  header lines come from `Extra` — verbatim, so the test can
   --  inject a malformed or unsolicited Sec-WebSocket-Protocol and
   --  watch the client reject the handshake.
   --
   --  After the 101 head section, the server optionally writes
   --  `Post_Bytes` to the wire so tests of the post-handshake
   --  receiver path (e.g. "what does the client do when the
   --  server sends a masked frame?") can inject any frame bytes
   --  they need.
   task type Fake_Server is
      entry Configure
        (Extra_Headers : String;
         Post_Bytes    : AHT.Bytes.Byte_Array;
         Hold_Seconds  : Duration := 0.0);
      entry Get_Port
        (P   : out AHT.URL.Port_Number;
         Err : out Unbounded_String);
      entry Wait_Done (Runtime_Err : out Unbounded_String);
   end Fake_Server;

   task body Fake_Server is
      Server         : Socket_Type := No_Socket;
      Client         : Socket_Type;
      Peer           : Sock_Addr_Type;
      Bind_To        : Sock_Addr_Type;
      Bound          : Port_Type := 0;
      Setup_Error    : Unbounded_String;
      Runtime_Error  : Unbounded_String;
      Extra          : Unbounded_String;
      Post           : AHT.Bytes.Buffer;
      Hold           : Duration := 0.0;
   begin
      accept Configure
        (Extra_Headers : String;
         Post_Bytes    : AHT.Bytes.Byte_Array;
         Hold_Seconds  : Duration := 0.0)
      do
         Extra := To_Unbounded_String (Extra_Headers);
         for B of Post_Bytes loop
            Post.Append (B);
         end loop;
         Hold := Hold_Seconds;
      end Configure;

      begin
         Create_Socket (Server, Family_Inet, Socket_Stream);
         Set_Socket_Option
           (Server, Socket_Level,
            (Name => Reuse_Address, Enabled => True));
         Bind_To.Addr := Inet_Addr ("127.0.0.1");
         Bind_To.Port := 0;
         Bind_Socket (Server, Bind_To);
         Listen_Socket (Server, 1);
         Bound := Get_Socket_Name (Server).Port;
      exception
         when E : others =>
            Setup_Error := To_Unbounded_String
              ("Fake_Server setup: "
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
            R_Set, W_Set : Socket_Set_Type;
            Status   : Selector_Status;
         begin
            Create_Selector (Selector);
            Set (R_Set, Server);
            Check_Selector
              (Selector, R_Set, W_Set, Status, Timeout => 3.0);
            Close_Selector (Selector);

            if Status = Completed then
               begin
                  Accept_Socket (Server, Client, Peer);
                  --  Drain bytes until CRLFCRLF.
                  declare
                     Buf  : Stream_Element_Array (1 .. 4_096);
                     Last : Stream_Element_Offset;
                     Req  : Unbounded_String;
                  begin
                     loop
                        Receive_Socket (Client, Buf, Last);
                        exit when Last < Buf'First;
                        for I in Buf'First .. Last loop
                           Append (Req,
                                   Character'Val (Natural (Buf (I))));
                        end loop;
                        exit when Ada.Strings.Fixed.Index
                          (To_String (Req),
                           ASCII.CR & ASCII.LF
                             & ASCII.CR & ASCII.LF) /= 0;
                     end loop;

                     declare
                        Key  : constant String :=
                          Extract_Key (To_String (Req));
                        Acc  : constant String := Compute_Accept (Key);
                        --  Head section terminates with CRLFCRLF —
                        --  one CRLF ends the last header line, the
                        --  second CRLF is the empty line.
                        Body_S : constant String :=
                          "HTTP/1.1 101 Switching Protocols"
                          & ASCII.CR & ASCII.LF
                          & "Upgrade: websocket"
                          & ASCII.CR & ASCII.LF
                          & "Connection: Upgrade"
                          & ASCII.CR & ASCII.LF
                          & "Sec-WebSocket-Accept: " & Acc
                          & ASCII.CR & ASCII.LF
                          & To_String (Extra)
                          & ASCII.CR & ASCII.LF
                          & ASCII.CR & ASCII.LF;
                        R_Buf : Stream_Element_Array
                          (1 .. Stream_Element_Offset (Body_S'Length));
                        Sent  : Stream_Element_Offset;
                     begin
                        for I in Body_S'Range loop
                           R_Buf
                             (Stream_Element_Offset
                                (I - Body_S'First + 1)) :=
                             Stream_Element (Character'Pos (Body_S (I)));
                        end loop;
                        Send_Socket (Client, R_Buf, Sent);
                     end;

                     --  After the 101 head section, write any
                     --  configured post-handshake bytes (e.g. a
                     --  malformed frame to exercise the receiver
                     --  side).
                     if Post.Length > 0 then
                        declare
                           P_Buf : Stream_Element_Array
                             (1 .. Stream_Element_Offset
                                     (Post.Length));
                           Sent  : Stream_Element_Offset;
                        begin
                           for I in 1 .. Post.Length loop
                              P_Buf
                                (Stream_Element_Offset (I)) :=
                                Stream_Element
                                  (Post.Element
                                     (Post.First_Index + I - 1));
                           end loop;
                           Send_Socket (Client, P_Buf, Sent);
                        end;
                     end if;

                     --  Hold the connection open silently for the
                     --  configured duration before tearing it
                     --  down. Lets tests of the client's
                     --  close-handshake timeout exercise a
                     --  non-echoing peer.
                     if Hold > 0.0 then
                        delay Hold;
                     end if;
                  end;
                  Shutdown_Socket (Client, Shut_Read_Write);
                  Close_Socket (Client);
               exception
                  when E : others =>
                     Runtime_Error := To_Unbounded_String
                       ("Fake_Server runtime: "
                        & Ada.Exceptions.Exception_Name (E) & " — "
                        & Ada.Exceptions.Exception_Message (E));
               end;
            end if;
         exception
            when E : others =>
               Runtime_Error := To_Unbounded_String
                 ("Fake_Server selector: "
                  & Ada.Exceptions.Exception_Message (E));
         end;

         begin
            Close_Socket (Server);
         exception
            when others => null;
         end;
      end if;

      select
         accept Wait_Done (Runtime_Err : out Unbounded_String) do
            Runtime_Err := Runtime_Error;
         end Wait_Done;
      or
         terminate;
      end select;
   end Fake_Server;

   function URL_For
     (Port : AHT.URL.Port_Number) return String
   is
   begin
      return "ws://127.0.0.1:"
        & Ada.Strings.Fixed.Trim
            (AHT.URL.Port_Number'Image (Port), Ada.Strings.Both)
        & "/";
   end URL_For;

begin
   --  Case 1: RFC 4648 §10 base64 test vectors. Catches off-by-one
   --  in padding / index math before any networking is involved.
   declare
      type Const_String_Ref is access constant String;
      Vectors : constant array (Positive range <>) of Const_String_Ref :=
          [new String'(""),       new String'(""),
           new String'("f"),      new String'("Zg=="),
           new String'("fo"),     new String'("Zm8="),
           new String'("foo"),    new String'("Zm9v"),
           new String'("foob"),   new String'("Zm9vYg=="),
           new String'("fooba"),  new String'("Zm9vYmE="),
           new String'("foobar"), new String'("Zm9vYmFy")];
   begin
      for I in 1 .. Vectors'Length / 2 loop
         declare
            Input    : constant String := Vectors (2 * I - 1).all;
            Expected : constant String := Vectors (2 * I).all;
            Got      : constant String :=
              AHT.Bytes.Base64_Encode (AHT.Bytes.From_String (Input));
         begin
            if Got /= Expected then
               Fail ("base64 """ & Input & """ -> """ & Got
                     & """ (expected """ & Expected & """)");
            end if;
         end;
      end loop;
   end;

   --  Case 2: successful handshake against the websockets echo
   --  fixture. After Connect returns, Is_Open is true and a Close
   --  tears the transport down without raising.
   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      begin
         AHT.Websocket.Client.Connect
           (C, "ws://127.0.0.1:8765/");
      exception
         when E : others =>
            Fail ("connect: raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E)
                  & " (is tests/server/server_ws.py running?)");
            Put_Line ("test_ws_handshake:" & Failures'Image
                      & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;

      if not AHT.Websocket.Client.Is_Open (C) then
         Fail ("connect: Is_Open false after successful Connect");
      end if;

      AHT.Websocket.Client.Close (C);
      if AHT.Websocket.Client.Is_Open (C) then
         Fail ("connect: Is_Open true after Close");
      end if;
   end;

   --  Case 3: ws:// scheme pointed at a server that doesn't speak
   --  WebSocket. The HTTP fixture returns 200 OK on /hello;
   --  Connect must refuse with Handshake_Error rather than treat
   --  the response as a successful upgrade.
   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      begin
         AHT.Websocket.Client.Connect
           (C, "ws://127.0.0.1:8764/hello");
         Fail ("non-ws-server: Connect returned without raising");
      exception
         when AHT.Websocket.Handshake_Error => null;
         when E : others =>
            Fail ("non-ws-server: wrong exception "
                  & Ada.Exceptions.Exception_Name (E)
                  & " (expected Handshake_Error)");
      end;
      if AHT.Websocket.Client.Is_Open (C) then
         Fail ("non-ws-server: Is_Open true after failed handshake");
      end if;
   end;

   --  Case 4: wss:// now runs a real TLS handshake (split C3). Point
   --  it at the HTTPS-only fixture on 8766 with Insecure => True so
   --  the TLS dial succeeds, but the server answers the upgrade with a
   --  non-101 status → Handshake_Error. This proves the wss:// path
   --  reaches handshake validation rather than being refused upfront;
   --  the TLS verify / round-trip behaviour is covered by test_ws_tls.
   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      begin
         AHT.Websocket.Client.Connect
           (C, "wss://127.0.0.1:8766/", Insecure => True);
         Fail ("wss: Connect returned without raising");
      exception
         when AHT.Websocket.Handshake_Error => null;
         when E : others =>
            Fail ("wss: wrong exception "
                  & Ada.Exceptions.Exception_Name (E));
      end;
   end;

   --  Case 5: http:// is not a WebSocket URL → Handshake_Error.
   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      begin
         AHT.Websocket.Client.Connect
           (C, "http://127.0.0.1:8765/");
         Fail ("http-scheme: Connect returned without raising");
      exception
         when AHT.Websocket.Handshake_Error => null;
         when E : others =>
            Fail ("http-scheme: wrong exception "
                  & Ada.Exceptions.Exception_Name (E));
      end;
   end;

   --  Case 6: Connect on an already-open Client raises. Not because
   --  the client is single-use — it is not, since the per-generation
   --  session work — but because a live connection is never silently
   --  displaced to make room for a new one. Admission accepts Idle
   --  and Disconnected; Open is refused, and the caller closes first.
   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      AHT.Websocket.Client.Connect (C, "ws://127.0.0.1:8765/");
      begin
         AHT.Websocket.Client.Connect (C, "ws://127.0.0.1:8765/");
         Fail ("double-connect: second Connect returned without "
               & "raising");
      exception
         when AHT.Websocket.Handshake_Error => null;
         when E : others =>
            Fail ("double-connect: wrong exception "
                  & Ada.Exceptions.Exception_Name (E));
      end;
      AHT.Websocket.Client.Close (C);
   end;

   --  Case 7: Extra_Headers are forwarded but the headers we own
   --  (Sec-WebSocket-Key etc.) are not overridable. Hard to assert
   --  on the wire without intercepting, but at minimum verify a
   --  benign extra header doesn't break the handshake — and that
   --  passing an override for Sec-WebSocket-Key is silently
   --  ignored (the handshake succeeds because our internally-
   --  generated Key is what the server's Accept echoes).
   declare
      C : AHT.Websocket.Client.Client_Type;
      H : AHT.HTTP.Headers.Map;
   begin
      H.Set ("x-aht-test", "1");
      H.Set ("sec-websocket-key", "this-would-break-the-handshake");
      begin
         AHT.Websocket.Client.Connect
           (Self          => C,
            URL           => "ws://127.0.0.1:8765/",
            Extra_Headers => H);
      exception
         when E : others =>
            Fail ("extras: Connect raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
      end;
      if AHT.Websocket.Client.Is_Open (C) then
         AHT.Websocket.Client.Close (C);
      end if;
   end;

   --  Case 8: server returns a Sec-WebSocket-Protocol the client
   --  did not offer → Handshake_Error. Uses the in-process Fake
   --  server so we can inject an exact response.
   declare
      Server   : Fake_Server;
      Port     : AHT.URL.Port_Number;
      Setup_Err, Run_Err : Unbounded_String;
      C        : AHT.Websocket.Client.Client_Type;
      Headers  : AHT.HTTP.Headers.Map;
   begin
      Server.Configure
        (Extra_Headers => "Sec-WebSocket-Protocol: evil-proto",
         Post_Bytes    => AHT.Bytes.Byte_Array'(1 .. 0 => 0));
      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("unsolicited: server setup: "
               & To_String (Setup_Err));
      else
         begin
            AHT.Websocket.Client.Connect
              (Self          => C,
               URL           => URL_For (Port),
               Extra_Headers => Headers);
            Fail ("unsolicited: Connect returned without raising");
         exception
            when AHT.Websocket.Handshake_Error => null;
            when E : others =>
               Fail ("unsolicited: wrong exception "
                     & Ada.Exceptions.Exception_Name (E));
         end;
         Server.Wait_Done (Run_Err);
         if AHT.Websocket.Client.Is_Open (C) then
            Fail ("unsolicited: Is_Open true after failed "
                  & "handshake");
         end if;
      end if;
   end;

   --  Case 9: server returns a subprotocol that was not in the
   --  client's offered list → Handshake_Error.
   declare
      Server   : Fake_Server;
      Port     : AHT.URL.Port_Number;
      Setup_Err, Run_Err : Unbounded_String;
      C        : AHT.Websocket.Client.Client_Type;
      Headers  : AHT.HTTP.Headers.Map;
   begin
      Server.Configure
        (Extra_Headers => "Sec-WebSocket-Protocol: evil-proto",
         Post_Bytes    => AHT.Bytes.Byte_Array'(1 .. 0 => 0));
      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("not-offered: server setup: "
               & To_String (Setup_Err));
      else
         begin
            AHT.Websocket.Client.Connect
              (Self          => C,
               URL           => URL_For (Port),
               Extra_Headers => Headers,
               Subprotocols  => "good-proto-v1, good-proto-v2");
            Fail ("not-offered: Connect returned without raising");
         exception
            when AHT.Websocket.Handshake_Error => null;
            when E : others =>
               Fail ("not-offered: wrong exception "
                     & Ada.Exceptions.Exception_Name (E));
         end;
         Server.Wait_Done (Run_Err);
      end if;
   end;

   --  Case 10: server returns *two* Sec-WebSocket-Protocol header
   --  lines — RFC 6455 §4.1 allows at most one → Handshake_Error.
   declare
      Server   : Fake_Server;
      Port     : AHT.URL.Port_Number;
      Setup_Err, Run_Err : Unbounded_String;
      C        : AHT.Websocket.Client.Client_Type;
      Headers  : AHT.HTTP.Headers.Map;
   begin
      Server.Configure
        (Extra_Headers =>
           "Sec-WebSocket-Protocol: a"
           & ASCII.CR & ASCII.LF
           & "Sec-WebSocket-Protocol: b",
         Post_Bytes => AHT.Bytes.Byte_Array'(1 .. 0 => 0));
      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("two-proto: server setup: "
               & To_String (Setup_Err));
      else
         begin
            AHT.Websocket.Client.Connect
              (Self          => C,
               URL           => URL_For (Port),
               Extra_Headers => Headers,
               Subprotocols  => "a, b");
            Fail ("two-proto: Connect returned without raising");
         exception
            when AHT.Websocket.Handshake_Error => null;
            when E : others =>
               Fail ("two-proto: wrong exception "
                     & Ada.Exceptions.Exception_Name (E));
         end;
         Server.Wait_Done (Run_Err);
      end if;
   end;

   --  Case 11: positive subprotocol path — server returns one of
   --  the offered values; Connect succeeds and
   --  Selected_Subprotocol matches what came back.
   declare
      Server   : Fake_Server;
      Port     : AHT.URL.Port_Number;
      Setup_Err, Run_Err : Unbounded_String;
      C        : AHT.Websocket.Client.Client_Type;
      Headers  : AHT.HTTP.Headers.Map;
   begin
      --  Held open on purpose. The negotiated subprotocol belongs to
      --  the connection, so it is only answerable while there is one:
      --  a fixture that drops the socket the moment it has sent the
      --  101 leaves the receiver racing to reclaim, and the
      --  assertion racing the receiver. Holding removes the race
      --  rather than hiding it behind whichever side usually wins.
      Server.Configure
        (Extra_Headers => "Sec-WebSocket-Protocol: aht.echo.v1",
         Post_Bytes    => AHT.Bytes.Byte_Array'(1 .. 0 => 0),
         Hold_Seconds  => 2.0);
      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("proto-good: server setup: "
               & To_String (Setup_Err));
      else
         begin
            AHT.Websocket.Client.Connect
              (Self          => C,
               URL           => URL_For (Port),
               Extra_Headers => Headers,
               Subprotocols  => "aht.echo.v1, aht.echo.v2");
         exception
            when E : others =>
               Fail ("proto-good: Connect raised "
                     & Ada.Exceptions.Exception_Name (E) & ": "
                     & Ada.Exceptions.Exception_Message (E));
         end;

         --  Asserted while the connection is still up, which is the
         --  only time the question has an answer.
         if AHT.Websocket.Client.Selected_Subprotocol (C)
            /= "aht.echo.v1"
         then
            Fail ("proto-good: Selected_Subprotocol = """
                  & AHT.Websocket.Client.Selected_Subprotocol (C)
                  & """");
         end if;

         AHT.Websocket.Client.Close (C, Timeout => 0.1);
         Server.Wait_Done (Run_Err);
      end if;
   end;

   --  Case 12: server sends a masked Text frame after the 101.
   --  RFC 6455 §5.1 forbids server-side masking, so the receiver
   --  task should reject it and shut the connection. The user
   --  observes that via Receive raising Closed_Error (the
   --  receiver Mark_Closed's the Inbox on its way out).
   declare
      Server   : Fake_Server;
      Port     : AHT.URL.Port_Number;
      Setup_Err, Run_Err : Unbounded_String;
      C        : AHT.Websocket.Client.Client_Type;
      Headers  : AHT.HTTP.Headers.Map;
      Msg      : AHT.Websocket.Client.Message_Type;
      --  Build the masked frame the same way a (misbehaving)
      --  server would. Frames.Encode is direction-neutral, so we
      --  can ask it for Masked=True even though we're emulating
      --  the server side.
      Bad_Frame : constant AHT.Bytes.Byte_Array :=
        AHT.Websocket.Frames.Encode
          (Hdr =>
             (FIN     => True,
              Op      => AHT.Websocket.Text,
              Masked  => True,
              Mask_Key => [16#37#, 16#FA#, 16#21#, 16#3D#],
              others  => <>),
           Payload => AHT.Bytes.From_String ("evil"));
   begin
      Server.Configure
        (Extra_Headers => "",
         Post_Bytes    => Bad_Frame);
      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("server-mask: server setup: "
               & To_String (Setup_Err));
      else
         begin
            AHT.Websocket.Client.Connect
              (Self          => C,
               URL           => URL_For (Port),
               Extra_Headers => Headers);
         exception
            when E : others =>
               Fail ("server-mask: Connect raised "
                     & Ada.Exceptions.Exception_Name (E));
         end;
         Server.Wait_Done (Run_Err);

         --  The receiver should see the masked frame, raise
         --  Protocol_Error internally, Mark_Closed the Inbox.
         --  Our Receive then surfaces Closed_Error rather than
         --  delivering "evil" as a valid message.
         begin
            AHT.Websocket.Client.Receive (C, Msg, Timeout => 1.0);
            Fail ("server-mask: Receive returned without "
                  & "raising (delivered """
                  & Msg.Payload.Length'Image
                  & " bytes)");
         exception
            when AHT.Websocket.Closed_Error => null;
            when E : others =>
               Fail ("server-mask: wrong exception "
                     & Ada.Exceptions.Exception_Name (E));
         end;
      end if;
   end;

   --  Case 13: Close's `Timeout` parameter is honoured. The fake
   --  server completes the handshake and then holds the socket
   --  silently for 2 s — long enough that the default 5.0 s
   --  close-echo grace would dominate. With Timeout => 0.1, Close
   --  must return well under 0.5 s via the Abort_Pending fallback
   --  path.
   declare
      Server   : Fake_Server;
      Port     : AHT.URL.Port_Number;
      Setup_Err, Run_Err : Unbounded_String;
      C        : AHT.Websocket.Client.Client_Type;
      Headers  : AHT.HTTP.Headers.Map;
      Started, Ended : Time;
   begin
      Server.Configure
        (Extra_Headers => "",
         Post_Bytes    => AHT.Bytes.Byte_Array'(1 .. 0 => 0),
         Hold_Seconds  => 2.0);
      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("close-timeout: server setup: "
               & To_String (Setup_Err));
      else
         AHT.Websocket.Client.Connect
           (Self          => C,
            URL           => URL_For (Port),
            Extra_Headers => Headers);
         Started := Clock;
         AHT.Websocket.Client.Close (C, Timeout => 0.1);
         Ended := Clock;
         Server.Wait_Done (Run_Err);
         if Ended - Started > 0.5 then
            Fail ("close-timeout: Close took"
                  & Duration'Image (Ended - Started)
                  & "s (Timeout was 0.1, should fall through "
                  & "to Abort_Pending fast)");
         end if;
      end if;
   end;

   --  Case 14: close-during-receiver-EOF race (regression). The fake
   --  server completes the handshake then immediately drops the socket
   --  (Hold => 0.0), which gives the receiver a chance to hit EOF and
   --  reach Closed while Close is still mid-handshake. A chance and not
   --  a guarantee -- which of the two gets there first is up to the
   --  scheduler, and is exactly what this case is about.
   --
   --  The old Close did an unconditional State.Set (Closing) after
   --  sending its Close frame, clobbering the Closed the receiver had
   --  just published — and that publication was the last one the
   --  receiver of the day would make, so nothing came after it to
   --  repair the clobber and Wait_Closed (barrier Current = Closed)
   --  parked forever. That deadlocked ~1-in-5 process runs.
   --
   --  Stated as the historical fact it is, because neither half of it
   --  describes the code this test now runs against: that receiver had
   --  no Reclaim and set Closed as it wound down, whereas today's
   --  publishes Closed from Reclaim and a teardown pin can publish it
   --  too. What survives is the shape — a caller overwriting a Closed
   --  it did not publish — which is what the loop below is here to
   --  catch if it comes back.
   --
   --  What catches a re-introduced clobber is the one-second bound on
   --  Close below, not the suite timeout, and it no longer hangs to
   --  get there: the select around Wait_Closed is bounded by the
   --  handshake Timeout, and Teardown_Pin.Finalize republishes Closed
   --  on the way out regardless.
   --
   --  Measured, by putting the old unconditional transition back: that
   --  run failed at iteration 1 with "Close took 5.000736000s" — the
   --  whole Timeout.
   --
   --  That shows the bound doing its job, and no more. It is what the
   --  intended shape produces — the receiver published Closed, the
   --  clobber overwrote it, and nothing was left to republish it — but
   --  it does not distinguish that from a receiver that had simply not
   --  published within the five seconds, which looks identical from
   --  out here. So this run does not say where the receiver was when
   --  the bound expired, and nothing here says whether Abort_Pending
   --  found it in transport I/O or not.
   --
   --  What holds either way is structural. Reclamation cannot pass
   --  Wait_No_Borrowers while the closer holds its teardown pin, so
   --  Teardown_Pin.Finalize — republishing Closed, then releasing that
   --  borrow as its last statement — is on the path in both shapes.
   --  Which is the part that matters here: a re-introduced clobber
   --  ends in a failed one-second assertion rather than a hung run.
   --
   --  Which iteration trips is not fixed either, and that run failing
   --  at its first says nothing about the next one. Whether the
   --  receiver's EOF beats the caller's Close is a scheduling
   --  question — that is the whole point of the case — so the loop is
   --  here to keep offering the ordering chances to happen.
   declare
      Iterations : constant := 50;
   begin
      Race_Loop :
      for I in 1 .. Iterations loop
         declare
            Server   : Fake_Server;
            Port     : AHT.URL.Port_Number;
            Setup_Err, Run_Err : Unbounded_String;
            C        : AHT.Websocket.Client.Client_Type;
            Headers  : AHT.HTTP.Headers.Map;
            Started, Ended : Time;
         begin
            Server.Configure
              (Extra_Headers => "",
               Post_Bytes    => AHT.Bytes.Byte_Array'(1 .. 0 => 0),
               Hold_Seconds  => 0.0);
            Server.Get_Port (Port, Setup_Err);
            if Length (Setup_Err) > 0 then
               Fail ("close-race: server setup: " & To_String (Setup_Err));
               exit Race_Loop;
            end if;

            begin
               AHT.Websocket.Client.Connect
                 (Self          => C,
                  URL           => URL_For (Port),
                  Extra_Headers => Headers);
            exception
               when E : others =>
                  Fail ("close-race: connect raised "
                        & Ada.Exceptions.Exception_Name (E)
                        & " (iter" & Integer'Image (I) & ")");
                  Server.Wait_Done (Run_Err);
                  exit Race_Loop;
            end;

            Started := Clock;
            AHT.Websocket.Client.Close (C);
            Ended := Clock;
            Server.Wait_Done (Run_Err);

            if AHT.Websocket.Client.Is_Open (C) then
               Fail ("close-race: Is_Open true after Close (iter"
                     & Integer'Image (I) & ")");
               exit Race_Loop;
            end if;
            if Ended - Started > 1.0 then
               Fail ("close-race: Close took"
                     & Duration'Image (Ended - Started)
                     & "s (iter" & Integer'Image (I)
                     & "); handshake not completing promptly");
               exit Race_Loop;
            end if;
         end;
      end loop Race_Loop;
   end;

   if Failures = 0 then
      Put_Line ("test_ws_handshake: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_handshake:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Handshake;
