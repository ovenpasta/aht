--  TLS handshake-timeout test. Drives both the transport-level
--  Handshake_Deadline and the HTTP client's Timeout_Seconds wiring
--  against tests/server/server_stall.py (127.0.0.1:8767), which
--  accepts the TCP connection but never sends a ServerHello. Without a
--  bounded handshake the client would block forever; with one it must
--  raise Timeout_Error promptly.
--
--  Run from the repo root (run_tests.sh chdir's there). The stall
--  server must be up — if it isn't, Connect fails on the TCP connect
--  with Transport_Error and the cases report that instead.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Real_Time; use Ada.Real_Time;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;
with Ada.Unchecked_Deallocation;

with AHT.Bytes;
with AHT.HTTP.Client;
with AHT.HTTP.Response;
with AHT.Transport;
with AHT.Transport.TLS;
with AHT.URL;

procedure Test_TLS_Timeout is

   Host     : constant String := "localhost";
   Port     : constant AHT.URL.Port_Number := 8767;
   Deadline : constant Duration := 1.0;
   --  Generous upper bound: the deadline is 1 s, so anything past this
   --  means the budget was ignored and the read effectively hung.
   Max_Wait : constant Duration := 8.0;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_timeout: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

begin
   --  Case 1: transport level. Insecure isolates this from cert
   --  verification — the server never presents a cert anyway, so the
   --  only way out is the handshake deadline.
   declare
      T       : AHT.Transport.TLS.TLS_Transport;
      Started : constant Time := Clock;
   begin
      begin
         T.Connect (Host, Port, Insecure => True,
                    Handshake_Deadline => Deadline);
         Fail ("transport: Connect returned without timing out");
      exception
         when AHT.Transport.Timeout_Error =>
            declare
               Elapsed : constant Duration := To_Duration (Clock - Started);
            begin
               if Elapsed > Max_Wait then
                  Fail ("transport: timed out but took"
                        & Elapsed'Image & "s (>" & Max_Wait'Image & "s)");
               end if;
            end;
         when E : others =>
            Fail ("transport: expected Timeout_Error, got "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E)
                  & " (is tests/server/server_stall.py running?)");
      end;
      begin
         T.Close;
      exception
         when others => null;
      end;
   end;

   --  Case 2: HTTP client wiring. Client.Timeout_Seconds must flow
   --  through to Connect's Handshake_Deadline, so a Get against the
   --  stall server raises Timeout_Error instead of hanging.
   declare
      C       : AHT.HTTP.Client.Client_Type;
      Resp    : AHT.HTTP.Response.Response_Type;
      Started : constant Time := Clock;
   begin
      C.Insecure := True;
      C.Timeout_Seconds := 1;
      begin
         Resp := AHT.HTTP.Client.Get (C, "https://localhost:8767/hello");
         Fail ("client: Get returned status" & Resp.Status'Image
               & " without timing out");
      exception
         when AHT.Transport.Timeout_Error =>
            declare
               Elapsed : constant Duration := To_Duration (Clock - Started);
            begin
               if Elapsed > Max_Wait then
                  Fail ("client: timed out but took"
                        & Elapsed'Image & "s (>" & Max_Wait'Image & "s)");
               end if;
            end;
         when E : others =>
            Fail ("client: expected Timeout_Error, got "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E));
      end;
   end;

   --  Case 3: write-poison. Against the deaf-TLS fixture (8769) — which
   --  completes the handshake then never reads — a large Write with a short
   --  write deadline must fire Timeout_Error *mid-record*. Because a partial
   --  TLS record may already be on the wire while mbedTLS thinks nothing was
   --  sent, the session is now record-desynchronised and the transport must
   --  drop it: Is_Connected goes False and a second Write raises rather than
   --  emitting onto the corrupt stream (Codex slice-1 F1).
   declare
      type Byte_Array_Access is access AHT.Bytes.Byte_Array;
      procedure Free is
        new Ada.Unchecked_Deallocation
          (AHT.Bytes.Byte_Array, Byte_Array_Access);

      Big_Len : constant := 4 * 1024 * 1024;
      T       : AHT.Transport.TLS.TLS_Transport;
      Big     : Byte_Array_Access :=
        new AHT.Bytes.Byte_Array'(1 .. Big_Len => 65);
   begin
      begin
         T.Connect (Host, 8769, Insecure => True,
                    Handshake_Deadline => 2.0);
      exception
         when E : others =>
            Fail ("write-poison: Connect — "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E)
                  & " (is tests/server/server_tls_deaf.py running?)");
      end;

      if T.Is_Connected then
         T.Set_Write_Deadline (1.0);
         declare
            Started : constant Time := Clock;
         begin
            T.Write (Big.all);
            Fail ("write-poison: first Write returned without timing out");
         exception
            when AHT.Transport.Timeout_Error =>
               declare
                  Elapsed : constant Duration :=
                    To_Duration (Clock - Started);
               begin
                  if Elapsed > Max_Wait then
                     Fail ("write-poison: timed out but took"
                           & Elapsed'Image & "s (>" & Max_Wait'Image & "s)");
                  end if;
               end;
            when E : others =>
               Fail ("write-poison: expected Timeout_Error on first Write, "
                     & "got " & Ada.Exceptions.Exception_Name (E) & " — "
                     & Ada.Exceptions.Exception_Message (E));
         end;

         --  The desynced session must be marked dead by Drop_Connection.
         if T.Is_Connected then
            Fail ("write-poison: session still connected after a fatal "
                  & "write timeout (record stream left reusable)");
         end if;

         --  And a retry must refuse to write onto the broken stream.
         begin
            T.Write (Big.all);
            Fail ("write-poison: second Write succeeded on a dropped "
                  & "session (should raise)");
         exception
            when AHT.Transport.Transport_Error =>
               null;  --  expected: "TLS write on closed transport"
            when E : others =>
               Fail ("write-poison: second Write raised unexpected "
                     & Ada.Exceptions.Exception_Name (E) & " — "
                     & Ada.Exceptions.Exception_Message (E));
         end;
      end if;

      --  Phase 2 (Codex slice-1 F-E / F-F, TLS counterpart): a TLS transport
      --  is single-use. The poisoned object (Drop_Connection flipped
      --  Connected False but left the inner TCP poisoned and the mbedTLS
      --  contexts live) must NOT be reconnected in place — freeing/reusing
      --  the SSL/config/CA/RNG objects while a WSS receiver could still be
      --  inside TLS.Read would be a use-after-free. So an in-place reconnect
      --  must be rejected (the inner TCP still owns its fd → TCP.Connect
      --  raises before any TLS state is touched); the caller has to Close and
      --  use a fresh transport.
      begin
         T.Connect (Host, 8766, Insecure => True, Handshake_Deadline => 2.0);
         Fail ("reconnect: in-place Connect on a poisoned TLS transport "
               & "succeeded (must reject; transport is single-use)");
      exception
         when AHT.Transport.Transport_Error =>
            null;  --  expected: inner TCP "still owns a connection"
         when E : others =>
            Fail ("reconnect: in-place Connect raised unexpected "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E));
      end;

      --  Close reclaims the mbedTLS contexts + inner TCP (single-threaded),
      --  then a FRESH transport must handshake the HTTPS fixture (8766) and
      --  GET /hello cleanly — proving the dead session was fully released
      --  and nothing leaked into a new connection.
      begin
         T.Close;
      exception
         when others => null;
      end;

      declare
         CRLF  : constant String := ASCII.CR & ASCII.LF;
         Req   : constant AHT.Bytes.Byte_Array := AHT.Bytes.From_String
           ("GET /hello HTTP/1.1" & CRLF
            & "Host: " & Host & CRLF
            & "Connection: close" & CRLF & CRLF);
         Buf   : AHT.Bytes.Byte_Array (1 .. 4096);
         Last  : Natural;
         Acc   : Unbounded_String;
         Fresh : AHT.Transport.TLS.TLS_Transport;
      begin
         Fresh.Connect (Host, 8766, Insecure => True,
                        Handshake_Deadline => 2.0);
         if not Fresh.Is_Connected then
            Fail ("reconnect: fresh transport not connected to 8766");
         else
            Fresh.Write (Req);
            loop
               Fresh.Read (Buf, Last);
               exit when Last = 0;
               Append (Acc, AHT.Bytes.To_String (Buf (1 .. Last)));
            end loop;
            if Ada.Strings.Fixed.Index (To_String (Acc), "hello, world") = 0
            then
               Fail ("reconnect: GET /hello body missing on a fresh "
                     & "transport (resp: """ & To_String (Acc) & """)");
            end if;
         end if;
         begin
            Fresh.Close;
         exception
            when others => null;
         end;
      exception
         when E : others =>
            Fail ("reconnect: fresh transport — "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E)
                  & " (is tests/server/server_tls.py on 8766 running?)");
      end;
      Free (Big);
   end;

   if Failures = 0 then
      Put_Line ("test_tls_timeout: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_timeout:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Timeout;
