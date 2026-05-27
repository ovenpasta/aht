with Ada.Characters.Handling;
with Ada.Exceptions;
with Ada.Numerics.Discrete_Random;
with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;

with GNAT.SHA1;

with AHT.HTTP.Methods;
with AHT.HTTP.Request;
with AHT.HTTP.Response;
with AHT.URL;

package body AHT.Websocket.Client is

   ---------------------------------------------------------------
   --  Local helpers (commit 1 — handshake only)
   ---------------------------------------------------------------

   --  Fixed string the WebSocket handshake mixes into the Accept
   --  computation (RFC 6455 §1.3 / §4.2.2).
   WS_GUID : constant String := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

   --  Non-cryptographic random byte source for Sec-WebSocket-Key.
   --  RFC 6455 §4.1 calls for 16 random bytes, base64-encoded. It
   --  isn't a secret; it's a transport-layer nonce the server must
   --  echo through SHA1+base64 in Sec-WebSocket-Accept. Quality of
   --  randomness only matters to the extent that an off-path
   --  attacker can't pre-compute the Accept value, which any
   --  halfway-decent PRNG defeats.
   package Random_Bytes is new Ada.Numerics.Discrete_Random
     (AHT.Bytes.Octet);

   function To_Lower (S : String) return String renames
     Ada.Characters.Handling.To_Lower;

   --  Strip ASCII HT/SP from both ends of S (RFC 7230 "OWS").
   function Strip_OWS (S : String) return String is
      First : Natural := S'First;
      Last  : Integer := S'Last;
   begin
      while First <= Last
        and then (S (First) = ' ' or else S (First) = ASCII.HT)
      loop
         First := First + 1;
      end loop;
      while Last >= First
        and then (S (Last) = ' ' or else S (Last) = ASCII.HT)
      loop
         Last := Last - 1;
      end loop;
      return S (First .. Last);
   end Strip_OWS;

   --  True iff Haystack contains Needle as a comma-separated token
   --  (with optional OWS), case-insensitive. Used to validate the
   --  server's `Connection: Upgrade` — which may list extra tokens
   --  on either side of the literal "Upgrade".
   function Contains_Token (Haystack, Needle : String) return Boolean is
      Lower_Hay  : constant String := To_Lower (Haystack);
      Lower_Need : constant String := To_Lower (Needle);
      First      : Positive := Lower_Hay'First;
   begin
      if Lower_Hay'Length = 0 then
         return False;
      end if;
      loop
         declare
            Comma : constant Natural :=
              Ada.Strings.Fixed.Index
                (Lower_Hay (First .. Lower_Hay'Last), ",");
            Token_Last : constant Natural :=
              (if Comma = 0 then Lower_Hay'Last else Comma - 1);
            T : constant String :=
              Strip_OWS (Lower_Hay (First .. Token_Last));
         begin
            if T = Lower_Need then
               return True;
            end if;
            exit when Comma = 0;
            First := Comma + 1;
         end;
      end loop;
      return False;
   end Contains_Token;

   --  Convert a 40-char hex string (GNAT.SHA1.Digest's output) into
   --  the 20 raw bytes. Inverse of "format hex". Used to feed the
   --  digest into Base64_Encode.
   function Hex_To_Bytes (Hex : String) return AHT.Bytes.Byte_Array is
      function Val (C : Character) return Natural is
        (case C is
           when '0' .. '9' =>
             Character'Pos (C) - Character'Pos ('0'),
           when 'a' .. 'f' =>
             10 + Character'Pos (C) - Character'Pos ('a'),
           when 'A' .. 'F' =>
             10 + Character'Pos (C) - Character'Pos ('A'),
           when others =>
             raise Program_Error
               with "Hex_To_Bytes: non-hex character '" & C & "'");
      Bytes : AHT.Bytes.Byte_Array (1 .. Hex'Length / 2);
   begin
      for I in 0 .. Bytes'Length - 1 loop
         Bytes (Bytes'First + I) :=
           AHT.Bytes.Octet
             (16 * Val (Hex (Hex'First + 2 * I))
              +    Val (Hex (Hex'First + 2 * I + 1)));
      end loop;
      return Bytes;
   end Hex_To_Bytes;

   --  base64( SHA1( Key & WS_GUID ) ) — the server's expected
   --  echo per RFC 6455 §4.2.2.
   function Expected_Accept (Key : String) return String is
      Hex : constant String := GNAT.SHA1.Digest (Key & WS_GUID);
      --  Hex is 40 chars (20 bytes). Convert to raw bytes, then
      --  base64. The RFC asks for base64 of the raw digest, not of
      --  the hex representation.
   begin
      return AHT.Bytes.Base64_Encode (Hex_To_Bytes (Hex));
   end Expected_Accept;

   --  True iff Wanted appears as a case-sensitive token in the
   --  comma-separated Subprotocols list. Subprotocol names are
   --  registry tokens matched case-sensitively (RFC 6455 §11.5);
   --  this is *not* the case-insensitive Connection-header check.
   function Is_Offered_Subprotocol
     (Wanted : String; Subprotocols : String) return Boolean
   is
      First : Positive := Subprotocols'First;
   begin
      if Subprotocols'Length = 0 then
         return False;
      end if;
      loop
         declare
            Comma : constant Natural :=
              Ada.Strings.Fixed.Index
                (Subprotocols (First .. Subprotocols'Last), ",");
            End_Idx : constant Natural :=
              (if Comma = 0 then Subprotocols'Last else Comma - 1);
            T : constant String :=
              Strip_OWS (Subprotocols (First .. End_Idx));
         begin
            if T = Wanted then
               return True;
            end if;
            exit when Comma = 0;
            First := Comma + 1;
         end;
      end loop;
      return False;
   end Is_Offered_Subprotocol;

   --  Host[:port] for the `Host:` header. Default port is elided
   --  (browsers + curl do the same).
   function Host_Header (U : AHT.URL.URL_Type) return String is
      Default : constant AHT.URL.Port_Number :=
        AHT.URL.Default_Port (U.Scheme);
      Host_S  : constant String := AHT.URL.Host_Literal (U);
   begin
      if U.Port = Default then
         return Host_S;
      end if;
      return Host_S
        & ":"
        & Ada.Strings.Fixed.Trim
            (AHT.URL.Port_Number'Image (U.Port), Ada.Strings.Both);
   end Host_Header;

   --  Fill B with non-cryptographic random bytes for Sec-WebSocket-Key.
   --  A fresh generator + Reset (seeds from Ada.Calendar.Clock by
   --  default) per call is fine — Connect runs at most once per
   --  Client and we just need each connection to pick a different
   --  key.
   procedure Fill_Random (B : out AHT.Bytes.Byte_Array) is
      Gen : Random_Bytes.Generator;
   begin
      Random_Bytes.Reset (Gen);
      for I in B'Range loop
         B (I) := Random_Bytes.Random (Gen);
      end loop;
   end Fill_Random;

   ---------------------------------------------------------------
   --  Public surface
   ---------------------------------------------------------------

   procedure Connect
     (Self          : in out Client_Type;
      URL           : String;
      Extra_Headers : AHT.HTTP.Headers.Map;
      Subprotocols  : String := "";
      Origin        : String := "";
      Insecure      : Boolean := False;
      CA_Path       : String := "")
   is
      pragma Unreferenced (Insecure, CA_Path);
      --  Insecure / CA_Path only matter for wss:// (TLS). v1 plain
      --  WS doesn't use them; accepted-but-ignored here and wired
      --  through once TLS lands.

      Parsed    : constant AHT.URL.URL_Type := AHT.URL.Parse (URL);
      Key_Bytes : AHT.Bytes.Byte_Array (1 .. 16);

      Req  : AHT.HTTP.Request.Request_Type;
      Resp : AHT.HTTP.Response.Response_Type;

      procedure Add_Extra (Name, Value : String) is
      begin
         --  Skip headers we set ourselves so the caller can't break
         --  the handshake by overriding (e.g.) Sec-WebSocket-Key.
         if Name = "host"
           or else Name = "upgrade"
           or else Name = "connection"
           or else Name = "sec-websocket-version"
           or else Name = "sec-websocket-key"
         then
            return;
         end if;
         Req.Headers.Append (Name, Value);
      end Add_Extra;

   begin
      if Self.Open then
         raise AHT.Websocket.Handshake_Error
           with "Websocket.Client.Connect: Client_Type is already "
             & "open; declare a fresh Client per connection";
      end if;

      --  Scheme dispatch. http/https aren't WS URLs (RFC 6455 §3
      --  requires ws or wss); wss is plumbed but not yet wired.
      case Parsed.Scheme is
         when AHT.URL.WS =>
            null;
         when AHT.URL.WSS =>
            raise AHT.Websocket.Handshake_Error
              with "Websocket.Client.Connect: wss:// not yet "
                & "implemented (pending TLS transport); use ws://";
         when AHT.URL.HTTP | AHT.URL.HTTPS =>
            raise AHT.Websocket.Handshake_Error
              with "Websocket.Client.Connect: URL must be ws:// "
                & "(or wss://); got " & URL;
      end case;

      --  Fresh Sec-WebSocket-Key per connection.
      Fill_Random (Key_Bytes);
      declare
         Key_B64 : constant String :=
           AHT.Bytes.Base64_Encode (Key_Bytes);
      begin
         --  HTTP upgrade request. Method GET with the WS URL's
         --  path; Request.Write only emits path+query so leaving
         --  the WS scheme on Req.Target doesn't reach the wire.
         Req.Method  := AHT.HTTP.Methods.GET;
         Req.Target  := Parsed;
         Req.Headers.Set ("host", Host_Header (Parsed));
         Req.Headers.Set ("upgrade", "websocket");
         Req.Headers.Set ("connection", "Upgrade");
         Req.Headers.Set ("sec-websocket-version", "13");
         Req.Headers.Set ("sec-websocket-key", Key_B64);
         if Subprotocols /= "" then
            Req.Headers.Set ("sec-websocket-protocol", Subprotocols);
         end if;
         if Origin /= "" then
            Req.Headers.Set ("origin", Origin);
         end if;
         Extra_Headers.Iterate (Add_Extra'Access);

         --  TCP connect (plain only in v1).
         AHT.Transport.TCP.Connect
           (Self.Transport,
            Host => To_String (Parsed.Host),
            Port => Parsed.Port);

         begin
            AHT.HTTP.Request.Write (Req, Self.Transport);

            --  Method => GET keeps the 101 no-body suppression
            --  fast-path in Response.Read: it parses status +
            --  headers and stops at byte-after-CRLFCRLF without
            --  consuming any frame bytes. Commit 2's receiver
            --  will pick up from that exact position.
            AHT.HTTP.Response.Read
              (Resp, Self.Transport,
               Method => AHT.HTTP.Methods.GET);

            if Resp.Status /= 101 then
               raise AHT.Websocket.Handshake_Error
                 with "Websocket.Client.Connect: server returned "
                   & Resp.Status'Image & " "
                   & To_String (Resp.Reason)
                   & " (expected 101 Switching Protocols)";
            end if;

            if To_Lower (Resp.Headers.Get ("upgrade")) /= "websocket"
            then
               raise AHT.Websocket.Handshake_Error
                 with "Websocket.Client.Connect: Upgrade header "
                   & "should be 'websocket', got '"
                   & Resp.Headers.Get ("upgrade") & "'";
            end if;

            if not Contains_Token
                     (Resp.Headers.Get ("connection"), "upgrade")
            then
               raise AHT.Websocket.Handshake_Error
                 with "Websocket.Client.Connect: Connection header "
                   & "must contain 'Upgrade' token (got '"
                   & Resp.Headers.Get ("connection") & "')";
            end if;

            declare
               Want : constant String := Expected_Accept (Key_B64);
               Got  : constant String :=
                 Resp.Headers.Get ("sec-websocket-accept");
            begin
               if Want /= Got then
                  raise AHT.Websocket.Handshake_Error
                    with "Websocket.Client.Connect: "
                      & "Sec-WebSocket-Accept mismatch; expected '"
                      & Want & "', got '" & Got & "'";
               end if;
            end;

            --  Validate Sec-WebSocket-Protocol per RFC 6455 §4.1:
            --
            --   * If the response carries the header, its value
            --     MUST match exactly one of the subprotocols the
            --     client offered. Anything else is a server
            --     protocol violation — the client must not
            --     silently accept semantics it never asked for.
            --   * The server MUST select at most one. Multiple
            --     Sec-WebSocket-Protocol header lines are illegal.
            --   * Empty (server elected not to pick one, or the
            --     client offered none) is fine.
            declare
               Values : constant AHT.HTTP.Headers.Value_List :=
                 Resp.Headers.Values ("sec-websocket-protocol");
               Got : constant String :=
                 Resp.Headers.Get ("sec-websocket-protocol");
            begin
               if Natural (Values.Length) > 1 then
                  raise AHT.Websocket.Handshake_Error
                    with "Websocket.Client.Connect: server returned"
                      & Natural'Image (Natural (Values.Length))
                      & " Sec-WebSocket-Protocol header values "
                      & "(spec allows at most one)";
               end if;

               if Got /= "" then
                  if Subprotocols = "" then
                     raise AHT.Websocket.Handshake_Error
                       with "Websocket.Client.Connect: server "
                         & "returned Sec-WebSocket-Protocol '"
                         & Got & "' but the client offered none";
                  end if;
                  if not Is_Offered_Subprotocol (Got, Subprotocols)
                  then
                     raise AHT.Websocket.Handshake_Error
                       with "Websocket.Client.Connect: server "
                         & "selected subprotocol '" & Got
                         & "', not in the client-offered list '"
                         & Subprotocols & "'";
                  end if;
               end if;

               Self.Selected_Protocol := To_Unbounded_String (Got);
            end;

            Self.Open := True;
         exception
            when AHT.Websocket.Handshake_Error =>
               --  Drop the TCP transport on a failed handshake so
               --  HTTP-layer state doesn't linger on the socket.
               Self.Transport.Close;
               raise;
            when E : others =>
               Self.Transport.Close;
               raise AHT.Websocket.Handshake_Error
                 with "Websocket.Client.Connect: "
                   & Ada.Exceptions.Exception_Name (E) & ": "
                   & Ada.Exceptions.Exception_Message (E);
         end;
      end;
   end Connect;

   procedure Connect
     (Self     : in out Client_Type;
      URL      : String;
      Insecure : Boolean := False;
      CA_Path  : String := "")
   is
      No_Extras : AHT.HTTP.Headers.Map;
   begin
      Connect
        (Self,
         URL           => URL,
         Extra_Headers => No_Extras,
         Insecure      => Insecure,
         CA_Path       => CA_Path);
   end Connect;

   function Is_Open (Self : Client_Type) return Boolean is (Self.Open);

   function Selected_Subprotocol (Self : Client_Type) return String is
     (To_String (Self.Selected_Protocol));

   ---------------------------------------------------------------
   --  Stubs — bodies land in commit 2 (frames + receiver task +
   --  send guard + close handshake).
   ---------------------------------------------------------------

   procedure Send_Text
     (Self : in out Client_Type;
      Text : String)
   is
      pragma Unreferenced (Self, Text);
   begin
      raise AHT.Websocket.Protocol_Error
        with "Websocket.Client.Send_Text: not yet implemented "
          & "(commit 2)";
   end Send_Text;

   procedure Send_Binary
     (Self : in out Client_Type;
      Data : AHT.Bytes.Byte_Array)
   is
      pragma Unreferenced (Self, Data);
   begin
      raise AHT.Websocket.Protocol_Error
        with "Websocket.Client.Send_Binary: not yet implemented "
          & "(commit 2)";
   end Send_Binary;

   procedure Send_Ping
     (Self    : in out Client_Type;
      Payload : AHT.Bytes.Byte_Array := [])
   is
      pragma Unreferenced (Self, Payload);
   begin
      raise AHT.Websocket.Protocol_Error
        with "Websocket.Client.Send_Ping: not yet implemented "
          & "(commit 2)";
   end Send_Ping;

   procedure Close
     (Self   : in out Client_Type;
      Code   : Valid_Close_Code := 1000;
      Reason : String := "")
   is
      pragma Unreferenced (Code, Reason);
   begin
      --  Commit 1 has no Send path so we can't emit a proper Close
      --  frame; tear the TCP transport down instead. Commit 2 will
      --  replace this with the RFC 6455 §1.4 close handshake (send
      --  Close frame, wait for peer echo, then close transport).
      if Self.Open then
         Self.Open := False;
         Self.Transport.Close;
      end if;
   end Close;

   procedure Receive
     (Self    : in out Client_Type;
      Msg     : out Message_Type;
      Timeout : Duration := Duration'Last)
   is
      pragma Unreferenced (Self, Timeout);
   begin
      Msg := (Kind => Binary_Message, Payload => <>);
      raise AHT.Websocket.Protocol_Error
        with "Websocket.Client.Receive: not yet implemented "
          & "(commit 2)";
   end Receive;

   procedure Set_On_Message
     (Self : in out Client_Type;
      CB   : On_Message_Callback) is
   begin
      Self.On_Message := CB;
   end Set_On_Message;

   procedure Set_On_Close
     (Self : in out Client_Type;
      CB   : On_Close_Callback) is
   begin
      Self.On_Close := CB;
   end Set_On_Close;

   procedure Set_On_Error
     (Self : in out Client_Type;
      CB   : On_Error_Callback) is
   begin
      Self.On_Error := CB;
   end Set_On_Error;

end AHT.Websocket.Client;
