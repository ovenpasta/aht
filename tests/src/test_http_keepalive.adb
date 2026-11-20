--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Keep-alive: AHT.HTTP.Connection_Pools on its own and under
--  AHT.HTTP.Client, against tests/server/server_keepalive.py (8779
--  plain, 8780 TLS). The fixture stamps every response with X-Conn
--  (which connection) and X-Req (its ordinal there), so reuse is read
--  off the wire, and counts accepted, ended and deliberately dropped
--  connections at /ka/stats.
--
--  Client cases, over http and https alike:
--    1. No pool: one connection per request.
--    2. A pool: consecutive requests share one connection, across
--       Content-Length, chunked and decoded gzip bodies and across a
--       redirect's hops. A read deadline armed by one client does not
--       follow the connection to the next client using the pool.
--    3. Not pooled: a body read until close, a response or a request
--       with Connection: close.
--    4. A pooled connection the peer closed while idle is detected and
--       skipped. The test parks the connection, then itself watches
--       it through the pool until Peer_Quiet reports the close, so the
--       premise is observed rather than waited for; the request that
--       follows is a POST, which nothing would retry.
--    5. A pooled connection that fails under the request without a
--       status line: a GET is retried once on a new connection, a
--       POST is not. The fixture's drop counter proves the failure
--       happened. One that answers with a malformed head is not
--       retried. Bytes past the end of a response keep the connection
--       from being reused; conflicting Content-Length is refused and
--       Transfer-Encoding with Content-Length is not pooled.
--       A redirect body past the discard bound costs the hop its
--       connection. The address filter is asked about every address
--       dialled and about a pooled connection's address; a request it
--       refuses neither dials nor rides a pooled connection.
--    6. A Cancel after the Send returned leaves the connection
--       pooled and usable.
--  Client case, over https only:
--   10. CA_PEM in the key. Clients sharing a pool reuse a connection
--       when their CA_PEM is equal and dial afresh when it differs in
--       one byte at the same length; the key's length does not grow
--       with the bundle. Over a 9 KB CA_PEM, every one-byte change
--       changes the key.
--  Pool cases:
--    7. Per-endpoint and total limits, and idle expiry. Each dialled
--       connection learns its X-Conn, and the fixture lists the ids
--       it has seen end, so "closed" is asserted per connection.
--    8. The last Pool_Ref closes what is idle; a copy keeps it open.
--  Transport cases:
--    9. Peer_Quiet over TCP: quiet on a silent connection; not quiet
--       once data or a FIN is pending, which it leaves unconsumed.
--
--  Not covered: a Cancel landing after the last response byte is read
--  but before the transport is unbound. No test can place a Cancel in
--  that window; the argument that such a connection is never pooled
--  is in AHT.HTTP.Client's Exchange.

with Ada.Calendar; use Ada.Calendar;
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.HTTP;
with AHT.HTTP.Client;
with AHT.HTTP.Connection_Pools;
with AHT.HTTP.Methods;
with AHT.HTTP.Request;
with AHT.HTTP.Response;
with AHT.Transport;
with AHT.Transport.TCP;
with AHT.URL;

with Test_Filters;

procedure Test_HTTP_Keepalive is

   package Client renames AHT.HTTP.Client;
   package Pools renames AHT.HTTP.Connection_Pools;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_http_keepalive: FAIL - " & Msg);
      Failures := Failures + 1;
   end Fail;

   procedure Guard (Label : String; E : Ada.Exceptions.Exception_Occurrence) is
   begin
      Fail (Label & ": raised " & Ada.Exceptions.Exception_Name (E)
            & ": " & Ada.Exceptions.Exception_Message (E));
   end Guard;

   Plain_Base : constant String := "http://127.0.0.1:8779";
   TLS_Base   : constant String := "https://localhost:8780";
   CA_File    : constant String := "tests/server/certs/server.crt";

   --  Liveness backstop for the loops that wait on an observed fact.
   Backstop : constant Duration := 10.0;

   function Stat (Name : String) return Natural is
      C    : Client.Client_Type;   --  no pool: never disturbs one
      Text : constant String :=
        Client.Get (C, Plain_Base & "/ka/stats").Body_Text;
      Key  : constant String := Name & "=";
      At_K : constant Natural := Ada.Strings.Fixed.Index (Text, Key);
      Stop : Natural := At_K + Key'Length;
   begin
      while Stop <= Text'Last and then Text (Stop) in '0' .. '9' loop
         Stop := Stop + 1;
      end loop;
      return Natural'Value (Text (At_K + Key'Length .. Stop - 1));
   end Stat;

   function Make
     (Method : AHT.HTTP.Methods.Method_Type;
      URL    : String) return AHT.HTTP.Request.Request_Type
   is
      R : AHT.HTTP.Request.Request_Type;
   begin
      R.Method := Method;
      R.Target := AHT.URL.Parse (URL);
      return R;
   end Make;

   function Conn (R : AHT.HTTP.Response.Response_Type) return String is
     (R.Headers.Get ("x-conn"));
   function Nth (R : AHT.HTTP.Response.Response_Type) return String is
     (R.Headers.Get ("x-req"));

   Unpooled : constant array (1 .. 2) of Unbounded_String :=
     [To_Unbounded_String ("/ka/eof"), To_Unbounded_String ("/ka/close")];

   function New_Client (Pooled : Boolean) return Client.Client_Type is
      C : Client.Client_Type;
   begin
      C.CA_Path := To_Unbounded_String (CA_File);
      if Pooled then
         C.Pool := Pools.Create;
      end if;
      return C;
   end New_Client;

   procedure Client_Cases (Base : String) is
      Tag : constant String := "[" & Base & "] ";
   begin
      --  1. No pool.
      declare
         C      : Client.Client_Type := New_Client (Pooled => False);
         R1, R2 : AHT.HTTP.Response.Response_Type;
      begin
         R1 := Client.Get (C, Base & "/ka/hello");
         R2 := Client.Get (C, Base & "/ka/hello");
         if Conn (R1) = Conn (R2) or else Nth (R2) /= "1" then
            Fail (Tag & "no pool: reused connection " & Conn (R2));
         end if;
      exception
         when E : others => Guard (Tag & "no pool", E);
      end;

      --  2. Reuse across body framings, decoding and a redirect.
      declare
         C    : Client.Client_Type := New_Client (Pooled => True);
         R    : AHT.HTTP.Response.Response_Type;
         Home : Unbounded_String;

         procedure Expect (Path : String; N : String) is
         begin
            R := Client.Get (C, Base & Path);
            if R.Status /= 200 or else Conn (R) /= To_String (Home)
              or else Nth (R) /= N
            then
               Fail (Tag & Path & ": conn " & Conn (R) & " req " & Nth (R)
                     & ", want conn " & To_String (Home) & " req " & N);
            end if;
         end Expect;
      begin
         C.Max_Decoded_Bytes    := 1_000_000;
         C.Max_Redirects := 2;
         R := Client.Get (C, Base & "/ka/hello");
         Home := To_Unbounded_String (Conn (R));
         Expect ("/ka/chunked", "2");
         if R.Body_Text /= "kept alive, chunked" & ASCII.LF then
            Fail (Tag & "chunked body " & R.Body_Text);
         end if;
         Expect ("/ka/gzip", "3");
         if not R.Decoded or else R.Body_B.Length /= 26 * 200 then
            Fail (Tag & "gzip: not decoded");
         end if;
         Expect ("/ka/hello", "4");
         --  The 302 is request 5, its target request 6.
         Expect ("/ka/redirect", "6");
         if Pools.Idle_Count (C.Pool) /= 1 then
            Fail (Tag & "idle count" & Pools.Idle_Count (C.Pool)'Image);
         end if;
      exception
         when E : others => Guard (Tag & "reuse", E);
      end;

      --  2b. Deadlines do not travel with a pooled connection.
      declare
         C1, C2 : Client.Client_Type := New_Client (Pooled => True);
         R1, R2 : AHT.HTTP.Response.Response_Type;
         Armed  : Time;
      begin
         C1.Read_Deadline := Client.Seconds (0.3);
         C2.Pool := C1.Pool;
         C2.Timeout_Seconds := 0;   --  no bound at all
         R1 := Client.Get (C1, Base & "/ka/hello");
         Armed := Clock;
         delay until Armed + 0.5;   --  C1's deadline is now past
         R2 := Client.Get (C2, Base & "/ka/hello");
         if Conn (R2) /= Conn (R1) or else Nth (R2) /= "2" then
            Fail (Tag & "deadline: connection not reused");
         end if;
      exception
         when E : others => Guard (Tag & "deadline", E);
      end;

      --  3. Not pooled.
      declare
         C : Client.Client_Type := New_Client (Pooled => True);
         R : AHT.HTTP.Response.Response_Type;
      begin
         for Path of Unpooled loop
            R := Client.Get (C, Base & To_String (Path));
            if R.Status /= 200 or else Pools.Idle_Count (C.Pool) /= 0 then
               Fail (Tag & To_String (Path) & ": pooled");
            end if;
         end loop;

         declare
            Req : AHT.HTTP.Request.Request_Type :=
              Make (AHT.HTTP.Methods.GET, Base & "/ka/hello");
         begin
            Req.Headers.Set ("connection", "close");
            Client.Send (C, Req, R);
            if Pools.Idle_Count (C.Pool) /= 0 then
               Fail (Tag & "request Connection: close was pooled");
            end if;
         end;
      exception
         when E : others => Guard (Tag & "not pooled", E);
      end;

      --  4. Closed while idle.
      declare
         C     : Client.Client_Type := New_Client (Pooled => True);
         R     : AHT.HTTP.Response.Response_Type;
         Where : constant Pools.Endpoint :=
           Client.Pool_Endpoint (C, AHT.URL.Parse (Base & "/"));
         Lease : aliased Pools.Connection;
         Found : Boolean;
         Give_Up : constant Time := Clock + Backstop;
         Seen  : Boolean := False;
         First : Unbounded_String;
      begin
         R := Client.Get (C, Base & "/ka/idle-close");
         First := To_Unbounded_String (Conn (R));
         Pools.Acquire (C.Pool, Where, Lease'Access, Found);
         if not Found then
            Fail (Tag & "idle-close: connection was not pooled");
         else
            loop
               Seen := not Pools.Transport (Lease).Peer_Quiet;
               exit when Seen or else Clock > Give_Up;
               delay 0.01;
            end loop;
            if not Seen then
               Fail (Tag & "idle-close: the close was never seen");
            end if;
            Pools.Release (C.Pool, Where, Lease'Access);

            Client.Send (C, Make (AHT.HTTP.Methods.POST, Base & "/ka/hello"), R);
            if R.Status /= 200 or else Conn (R) = To_String (First) then
               Fail (Tag & "idle-close: POST went to conn " & Conn (R));
            end if;
         end if;
      exception
         when E : others => Guard (Tag & "idle-close", E);
      end;

      --  5. Failure under the request.
      declare
         C       : Client.Client_Type := New_Client (Pooled => True);
         R       : AHT.HTTP.Response.Response_Type;
         Dropped : constant Natural := Stat ("dropped");
         First   : Unbounded_String;
      begin
         R := Client.Get (C, Base & "/ka/drop-second");
         First := To_Unbounded_String (Conn (R));
         R := Client.Get (C, Base & "/ka/drop-second");
         if Stat ("dropped") /= Dropped + 1 then
            Fail (Tag & "drop: the fixture dropped"
                  & Natural'Image (Stat ("dropped") - Dropped));
         end if;
         if R.Status /= 200 or else Conn (R) = To_String (First)
           or else Nth (R) /= "1"
         then
            Fail (Tag & "drop: GET not retried on a new connection");
         end if;

         --  POST: the same failure surfaces. Clear the pool so the
         --  first POST is its connection's first request.
         Pools.Clear (C.Pool);
         Client.Send (C, Make (AHT.HTTP.Methods.POST,
                               Base & "/ka/drop-second"), R);
         begin
            Client.Send (C, Make (AHT.HTTP.Methods.POST,
                                  Base & "/ka/drop-second"), R);
            Fail (Tag & "drop: POST was retried, conn " & Conn (R));
         exception
            when AHT.HTTP.Protocol_Error
               | AHT.Transport.Transport_Error =>
               null;
         end;
         if Stat ("dropped") /= Dropped + 2 then
            Fail (Tag & "drop: POST case dropped"
                  & Natural'Image (Stat ("dropped") - Dropped));
         end if;
      exception
         when E : others => Guard (Tag & "drop", E);
      end;

      --  5b. A peer that answers badly is not asked again: the second
      --  request on the connection gets a status line and a malformed
      --  header. A retry would land on a new connection and succeed.
      declare
         C       : Client.Client_Type := New_Client (Pooled => True);
         R       : AHT.HTTP.Response.Response_Type;
         Garbled : constant Natural := Stat ("garbled");
      begin
         R := Client.Get (C, Base & "/ka/garble-second");
         begin
            R := Client.Get (C, Base & "/ka/garble-second");
            Fail (Tag & "garble: retried, conn " & Conn (R));
         exception
            when AHT.HTTP.Protocol_Error => null;
         end;
         if Stat ("garbled") /= Garbled + 1 then
            Fail (Tag & "garble: the fixture garbled"
                  & Natural'Image (Stat ("garbled") - Garbled));
         end if;
      exception
         when E : others => Guard (Tag & "garble", E);
      end;

      --  5c. Bytes after the framed end of a response. The fixture
      --  sends them in the body's own write, so they are with the
      --  client (in the socket, or inside the TLS engine as decrypted
      --  plaintext) by the time the body has been read. They form a
      --  complete response marked X-Conn: stale; the next request
      --  must not be answered by it. A POST, so no retry hides it.
      declare
         C     : Client.Client_Type := New_Client (Pooled => True);
         R     : AHT.HTTP.Response.Response_Type;
         First : Unbounded_String;
      begin
         R := Client.Get (C, Base & "/ka/extra");
         First := To_Unbounded_String (Conn (R));
         if R.Body_Text /= "exact" or else Pools.Idle_Count (C.Pool) /= 1 then
            Fail (Tag & "extra: body """ & R.Body_Text & """, idle"
                  & Pools.Idle_Count (C.Pool)'Image);
         end if;
         Client.Send (C, Make (AHT.HTTP.Methods.POST, Base & "/ka/hello"), R);
         if R.Status /= 200 or else Conn (R) = "stale"
           or else Conn (R) = To_String (First) or else Nth (R) /= "1"
         then
            Fail (Tag & "extra: next request answered on conn " & Conn (R));
         end if;
      exception
         when E : others => Guard (Tag & "extra", E);
      end;

      --  5d. Ambiguous framing: lengths that disagree are refused; a
      --  chunked response that also carries a length is read but its
      --  connection is not kept.
      declare
         C : Client.Client_Type := New_Client (Pooled => True);
         R : AHT.HTTP.Response.Response_Type;
      begin
         begin
            R := Client.Get (C, Base & "/ka/dup-length");
            Fail (Tag & "dup-length: accepted," & R.Body_B.Length'Image
                  & " bytes");
         exception
            when E : AHT.HTTP.Protocol_Error =>
               if Ada.Strings.Fixed.Index
                    (Ada.Exceptions.Exception_Message (E), "conflicting") = 0
               then
                  Guard (Tag & "dup-length", E);
               end if;
         end;
         R := Client.Get (C, Base & "/ka/te-and-cl");
         if R.Body_Text /= "hello" or else Pools.Idle_Count (C.Pool) /= 0 then
            Fail (Tag & "te-and-cl: body """ & R.Body_Text & """, idle"
                  & Pools.Idle_Count (C.Pool)'Image);
         end if;
      exception
         when E : others => Guard (Tag & "ambiguous framing", E);
      end;

      --  2c. A redirect with a body past the discard bound: the hop's
      --  connection is given up, so the target is the first request
      --  on another one (compare /ka/redirect above, which shares).
      declare
         C : Client.Client_Type := New_Client (Pooled => True);
         R : AHT.HTTP.Response.Response_Type;
      begin
         C.Max_Redirects := 2;
         R := Client.Get (C, Base & "/ka/redirect-big");
         if R.Status /= 200 or else Nth (R) /= "1" then
            Fail (Tag & "redirect-big: status" & R.Status'Image
                  & ", request " & Nth (R) & " on its connection");
         end if;
      exception
         when E : others => Guard (Tag & "redirect-big", E);
      end;

      --  5e. The address filter. Per-request, so nested functions
      --  with this block's state.
      declare
         C        : Client.Client_Type := New_Client (Pooled => True);
         R        : AHT.HTTP.Response.Response_Type;
         Want_Host : constant String :=
           To_String (AHT.URL.Parse (Base & "/").Host);
         Asked    : Natural := 0;
         Bad      : Unbounded_String;
         Allow    : Boolean := True;
         Accepted : Natural;
         First    : Unbounded_String;

         function Filter (Host, Address : String) return Boolean is
         begin
            Asked := Asked + 1;
            if Host /= Want_Host
              or else (Address /= "127.0.0.1" and then Address /= "::1")
            then
               Bad := To_Unbounded_String (Host & " / " & Address);
            end if;
            --  Only the loopback the fixture listens on.
            return Allow and then Address = "127.0.0.1";
         end Filter;
      begin
         --  Asked about each address, with the name it came from.
         Client.Send (C, Make (AHT.HTTP.Methods.GET, Base & "/ka/hello"), R,
                      On_Address => Filter'Access);
         First := To_Unbounded_String (Conn (R));
         if R.Status /= 200 or else Asked = 0 or else Length (Bad) > 0 then
            Fail (Tag & "address filter: asked" & Asked'Image
                  & ", unexpected " & To_String (Bad));
         end if;

         --  The connection is now pooled. A request whose filter
         --  refuses everything must not ride on it, and must not dial:
         --  the fixture accepts nothing new.
         Allow := False;
         Asked := 0;
         Accepted := Stat ("accepted");
         begin
            Client.Send (C, Make (AHT.HTTP.Methods.GET, Base & "/ka/hello"),
                         R, On_Address => Filter'Access);
            Fail (Tag & "address filter: refused request served on conn "
                  & Conn (R));
         exception
            when E : AHT.Transport.Transport_Error =>
               if Ada.Strings.Fixed.Index
                    (Ada.Exceptions.Exception_Message (E),
                     Want_Host & ": every address was refused") = 0
               then
                  Guard (Tag & "address filter refusal", E);
               end if;
         end;
         if Stat ("accepted") /= Accepted then
            Fail (Tag & "address filter: a refused request dialled");
         end if;
         if Asked < 2 then
            Fail (Tag & "address filter: asked" & Asked'Image
                  & " times; the pooled connection was not vetted");
         end if;

         --  The refused pooled connection was closed, not kept.
         R := Client.Get (C, Base & "/ka/hello");
         if Conn (R) = To_String (First) or else Nth (R) /= "1" then
            Fail (Tag & "address filter: refused connection reused");
         end if;

         --  The field form, through Send_Async.
         C.On_Address := Test_Filters.Refuse_Addresses'Access;
         Test_Filters.Address_Calls := 0;
         declare
            Async : Client.Async_Handle;
         begin
            Client.Send_Async
              (C, Make (AHT.HTTP.Methods.GET, Base & "/ka/hello"), Async);
            Client.Await (Async, R);
            Fail (Tag & "address field filter: served");
         exception
            when AHT.Transport.Transport_Error => null;
         end;
         if Test_Filters.Address_Calls = 0 then
            Fail (Tag & "address field filter: never asked");
         end if;
      exception
         when E : others => Guard (Tag & "address filter", E);
      end;

      --  6. Cancel after the Send.
      declare
         C      : Client.Client_Type := New_Client (Pooled => True);
         R1, R2 : AHT.HTTP.Response.Response_Type;
         H      : Client.Cancel_Handle;
      begin
         Client.Send (C, Make (AHT.HTTP.Methods.GET, Base & "/ka/hello"),
                      R1, H);
         Client.Cancel (H);
         R2 := Client.Get (C, Base & "/ka/hello");
         if Conn (R2) /= Conn (R1) or else Nth (R2) /= "2" then
            Fail (Tag & "cancel after: connection not reused");
         end if;
      exception
         when E : others => Guard (Tag & "cancel after", E);
      end;
   end Client_Cases;

   function Read_File (Path : String) return String is
      F : File_Type;
      R : Unbounded_String;
   begin
      Open (F, In_File, Path);
      while not End_Of_File (F) loop
         Append (R, Get_Line (F));
         Append (R, ASCII.LF);
      end loop;
      Close (F);
      return To_String (R);
   end Read_File;

   --  10. CA_PEM in the key. The two bundles have one length and
   --  differ in one byte, the whitespace after the certificate, so
   --  both trust the fixture: whichever connection a request rides,
   --  it succeeds, and X-Conn and X-Req show which one the key chose.
   procedure PEM_Key_Cases is
      Tag : constant String := "[" & TLS_Base & "] ";
   begin
      --  In a block, so that a raise while elaborating these reaches
      --  the handler below.
      declare
         Cert : constant String := Read_File (CA_File);
         Pool : constant Pools.Pool_Ref := Pools.Create;

         function Using (PEM : String) return Client.Client_Type is
            C : Client.Client_Type;
         begin
            C.CA_PEM := To_Unbounded_String (PEM);
            C.Pool := Pool;
            return C;
         end Using;

         A1 : Client.Client_Type := Using (Cert & ' ');
         A2 : Client.Client_Type := Using (Cert & ' ');
         B  : Client.Client_Type := Using (Cert & ASCII.HT);
         R1, R2, R3, R4 : AHT.HTTP.Response.Response_Type;

         function Key_Length (PEM : String) return Natural is
           (Length (Client.Pool_Endpoint
                      (Using (PEM), AHT.URL.Parse (TLS_Base & "/"))
                      .TLS_Profile));
      begin
         R1 := Client.Get (A1, TLS_Base & "/ka/hello");
         R2 := Client.Get (A2, TLS_Base & "/ka/hello");
         if Conn (R2) /= Conn (R1) or else Nth (R2) /= "2" then
            Fail (Tag & "pem key: equal CA_PEM got conn " & Conn (R2)
                  & " req " & Nth (R2) & ", want conn " & Conn (R1)
                  & " req 2");
         end if;

         R3 := Client.Get (B, TLS_Base & "/ka/hello");
         if Conn (R3) = Conn (R1) or else Nth (R3) /= "1" then
            Fail (Tag & "pem key: CA_PEM one byte apart got conn "
                  & Conn (R3) & " req " & Nth (R3)
                  & ", want a new connection");
         end if;
         if Pools.Idle_Count (Pool) /= 2 then
            Fail (Tag & "pem key: idle count"
                  & Pools.Idle_Count (Pool)'Image & ", want 2");
         end if;

         R4 := Client.Get (A1, TLS_Base & "/ka/hello");
         if Conn (R4) /= Conn (R1) or else Nth (R4) /= "3" then
            Fail (Tag & "pem key: A's connection gone, got conn "
                  & Conn (R4) & " req " & Nth (R4));
         end if;

         if Key_Length (Cert) /= Key_Length (Cert & Cert) then
            Fail (Tag & "pem key: key length" & Key_Length (Cert)'Image
                  & " for one certificate,"
                  & Key_Length (Cert & Cert)'Image & " for two");
         end if;

         --  The key alone, over CA_PEM far longer than any slice the
         --  digest might be fed in: equal text, in separate client
         --  records, gives an equal key, and a change to any one byte a different one.
         --  Pool_Endpoint does not validate the PEM, so any text does.
         declare
            Size : constant := 9_001;
            Base : constant String (1 .. Size) :=
              [for I in 1 .. Size => Character'Val (32 + I mod 95)];

            function Key (PEM : String) return Pools.Endpoint is
              (Client.Pool_Endpoint
                 (Using (PEM), AHT.URL.Parse (TLS_Base & "/")));

            use type Pools.Endpoint;

            Base_Key : constant Pools.Endpoint := Key (Base);
            Collided : Natural := 0;
         begin
            if Key (Base) /= Base_Key then
               Fail (Tag & "pem key: equal long CA_PEM, different keys");
            end if;
            for I in Base'Range loop
               declare
                  Other : String := Base;
               begin
                  Other (I) := '~';
                  if Base (I) /= '~' and then Key (Other) = Base_Key then
                     Collided := Collided + 1;
                  end if;
               end;
            end loop;
            if Collided > 0 then
               Fail (Tag & "pem key:" & Collided'Image
                     & " one-byte changes kept the key");
            end if;
         end;
      end;
   exception
      when E : others => Guard (Tag & "pem key", E);
   end PEM_Key_Cases;

   --  Whether the fixture has seen connection Id end.
   function Has_Closed (Id : String) return Boolean is
      C    : Client.Client_Type;
      Text : constant String :=
        Client.Get (C, Plain_Base & "/ka/stats").Body_Text;
      Ids  : constant Natural := Ada.Strings.Fixed.Index (Text, "closed_ids=");
   begin
      return Ada.Strings.Fixed.Index
               (Text (Ids .. Text'Last), "," & Id & ",") > 0;
   end Has_Closed;

   --  Wait until the fixture has seen connection Id end, or the
   --  backstop passes.
   function Closes (Id : String) return Boolean is
      Give_Up : constant Time := Clock + Backstop;
   begin
      loop
         if Has_Closed (Id) then
            return True;
         end if;
         exit when Clock > Give_Up;
         delay 0.02;
      end loop;
      return False;
   end Closes;

   --  Dial the plain listener as Host and make one request, so the
   --  fixture's name for the connection (X-Conn) is known.
   procedure Dial
     (C    : not null access Pools.Connection;
      Host : String;
      Id   : out Unbounded_String)
   is
      Buf  : AHT.Bytes.Byte_Array (1 .. 1_024);
      Last : Natural;
      Got  : AHT.Bytes.Buffer;
      Mark : constant String := "X-Conn: ";
   begin
      Pools.Allocate (C.all, AHT.URL.HTTP);
      AHT.Transport.TCP.Connect
        (AHT.Transport.TCP.TCP_Transport (Pools.Transport (C.all).all),
         Host => Host, Port => 8779);
      Pools.Transport (C.all).Write
        (AHT.Bytes.From_String
           ("GET /ka/hello HTTP/1.1" & ASCII.CR & ASCII.LF
            & "Host: x" & ASCII.CR & ASCII.LF & ASCII.CR & ASCII.LF));
      loop
         Pools.Transport (C.all).Read (Buf, Last);
         exit when Last = 0;
         Got.Append (Buf (1 .. Last));
         exit when Ada.Strings.Fixed.Index
                     (Got.To_String, "hello, kept alive") > 0;
      end loop;
      declare
         Text  : constant String := Got.To_String;
         Start : constant Natural :=
           Ada.Strings.Fixed.Index (Text, Mark) + Mark'Length;
         Stop  : constant Natural :=
           Ada.Strings.Fixed.Index (Text (Start .. Text'Last), "" & ASCII.CR);
      begin
         Id := To_Unbounded_String (Text (Start .. Stop - 1));
      end;
   end Dial;

   Plain_A : constant Pools.Endpoint :=
     (Scheme => AHT.URL.HTTP, Host => To_Unbounded_String ("127.0.0.1"),
      Port => 8779, TLS_Profile => Null_Unbounded_String);

   procedure Pool_Cases is
   begin
      --  7a. Limits. Two endpoints on one listener; a timeout long
      --  enough that nothing here expires.
      declare
         P     : constant Pools.Pool_Ref :=
           Pools.Create (Max_Idle_Per_Host => 2, Max_Idle => 3,
                         Idle_Timeout => 3_600.0);
         B     : constant Pools.Endpoint :=
           (Plain_A with delta Host => To_Unbounded_String ("LOCALHOST"));
         Conns : array (1 .. 5) of aliased Pools.Connection;
         Ids   : array (1 .. 5) of Unbounded_String;
         Found : Boolean;
         Got   : aliased Pools.Connection;
      begin
         for I in 1 .. 3 loop
            Dial (Conns (I)'Access, "127.0.0.1", Ids (I));
         end loop;
         for I in 4 .. 5 loop
            Dial (Conns (I)'Access, "localhost", Ids (I));
         end loop;

         for I in 1 .. 3 loop
            Pools.Release (P, Plain_A, Conns (I)'Access);
         end loop;
         if Pools.Idle_Count (P) /= 2 then
            Fail ("per-host limit: idle" & Pools.Idle_Count (P)'Image);
         end if;
         for I in 4 .. 5 loop
            Pools.Release (P, B, Conns (I)'Access);
         end loop;
         if Pools.Idle_Count (P) /= 3 then
            Fail ("total limit: idle" & Pools.Idle_Count (P)'Image);
         end if;
         --  Pushed out, both from A: its oldest (1) when the third
         --  came, and the pool's oldest (2) when B's second came.
         for I in 1 .. 2 loop
            if not Closes (To_String (Ids (I))) then
               Fail ("limits: evicted connection" & I'Image & " not closed");
            end if;
         end loop;
         for I in 3 .. 5 loop
            if Has_Closed (To_String (Ids (I))) then
               Fail ("limits: kept connection" & I'Image & " was closed");
            end if;
         end loop;

         --  Host is matched case-insensitively.
         Pools.Acquire
           (P, (B with delta Host => To_Unbounded_String ("localhost")),
            Got'Access, Found);
         if not Found then
            Fail ("acquire: LOCALHOST entry not found as localhost");
         else
            Pools.Release (P, B, Got'Access);
         end if;
      exception
         when E : others => Guard ("limits", E);
      end;

      --  7b. Expiry. The delay is the premise: the connection has been
      --  idle for longer than the timeout when Acquire looks.
      declare
         P     : constant Pools.Pool_Ref := Pools.Create (Idle_Timeout => 0.3);
         C     : aliased Pools.Connection;
         Id    : Unbounded_String;
         Found : Boolean;
         Parked : Time;
      begin
         Dial (C'Access, "127.0.0.1", Id);
         Pools.Release (P, Plain_A, C'Access);
         Parked := Clock;
         delay until Parked + 0.5;
         Pools.Acquire (P, Plain_A, C'Access, Found);
         if Found or else Pools.Idle_Count (P) /= 0 then
            Fail ("expiry: found " & Found'Image & ", idle"
                  & Pools.Idle_Count (P)'Image);
            Pools.Discard (C);
         end if;
         if not Closes (To_String (Id)) then
            Fail ("expiry: expired connection was not closed");
         end if;
      exception
         when E : others => Guard ("expiry", E);
      end;

      --  8. Reference counting.
      declare
         Id : Unbounded_String;
      begin
         declare
            P1 : Pools.Pool_Ref := Pools.Create;
            C  : aliased Pools.Connection;
         begin
            Dial (C'Access, "127.0.0.1", Id);
            Pools.Release (P1, Plain_A, C'Access);
            declare
               P2 : constant Pools.Pool_Ref := P1;
            begin
               P1 := Pools.Create;   --  drops one reference
               if Pools.Idle_Count (P2) /= 1
                 or else Has_Closed (To_String (Id))
               then
                  Fail ("refcount: copy lost the idle connection");
               end if;
            end;
            --  P2 was the last reference to the first pool.
            if not Closes (To_String (Id)) then
               Fail ("refcount: last reference did not close");
            end if;
         end;
      exception
         when E : others => Guard ("refcount", E);
      end;
   end Pool_Cases;

   --  9. Peer_Quiet over TCP. /ka/hello answers and /ka/eof answers
   --  then closes; the loops wait until the probe reports what has
   --  arrived and then check it was left in place.
   procedure Transport_Cases is
      function Request (Path : String) return AHT.Bytes.Byte_Array is
        (AHT.Bytes.From_String
           ("GET " & Path & " HTTP/1.1" & ASCII.CR & ASCII.LF
            & "Host: 127.0.0.1" & ASCII.CR & ASCII.LF & ASCII.CR & ASCII.LF));

      procedure Wait_Loud (T : AHT.Transport.TCP.TCP_Transport; Label : String) is
         Give_Up : constant Time := Clock + Backstop;
      begin
         while T.Peer_Quiet loop
            if Clock > Give_Up then
               Fail (Label & ": still quiet at the backstop");
               return;
            end if;
            delay 0.01;
         end loop;
      end Wait_Loud;
   begin
      declare
         T    : AHT.Transport.TCP.TCP_Transport;
         Buf  : AHT.Bytes.Byte_Array (1 .. 4_096);
         Last : Natural;
         Got  : AHT.Bytes.Buffer;
      begin
         if T.Peer_Quiet then
            Fail ("TCP: quiet before Connect");
         end if;
         if T.Peer_Address /= "" then
            Fail ("TCP: Peer_Address before Connect");
         end if;
         AHT.Transport.TCP.Connect (T, "127.0.0.1", 8779);
         if T.Peer_Address /= "127.0.0.1" then
            Fail ("TCP: Peer_Address " & T.Peer_Address);
         end if;
         if not T.Peer_Quiet then
            Fail ("TCP: not quiet on a silent connection");
         end if;

         T.Write (Request ("/ka/hello"));
         Wait_Loud (T, "TCP data");
         T.Read (Buf, Last);
         if Last < 4 or else AHT.Bytes.To_String (Buf (1 .. 4)) /= "HTTP" then
            Fail ("TCP data: the probe consumed the response start");
         end if;

         T.Write (Request ("/ka/eof"));
         --  Read the whole exchange up to EOF, then probe again: the
         --  FIN must still be visible, and Read must still see it.
         loop
            Wait_Loud (T, "TCP eof");
            T.Read (Buf, Last);
            exit when Last = 0;
            Got.Append (Buf (1 .. Last));
            exit when Ada.Strings.Fixed.Index (Got.To_String, "until close") > 0;
         end loop;
         Wait_Loud (T, "TCP fin");
         T.Read (Buf, Last);
         if Last /= 0 then
            Fail ("TCP fin: Read after the probe returned data");
         end if;
         T.Close;
      exception
         when E : others => Guard ("TCP probe", E);
      end;
   end Transport_Cases;

begin
   Client_Cases (Plain_Base);
   Client_Cases (TLS_Base);
   PEM_Key_Cases;
   Pool_Cases;
   Transport_Cases;

   if Failures = 0 then
      Put_Line ("test_http_keepalive: OK");
   else
      Put_Line ("test_http_keepalive:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_HTTP_Keepalive;
