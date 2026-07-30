with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.Transport;
with AHT.Transport.TLS;
with AHT.URL;

--  Failed-Connect retryability (backend-neutral). The TLS transport is
--  single-use only AFTER a successful handshake; a Connect that fails —
--  at the TCP layer, at CA loading, or at certificate verification —
--  must release everything it allocated and leave the SAME object ready
--  for another attempt. Regression test for the embedded-TCP design,
--  whose inner Used latch made any post-TCP failure permanent.
--
--  Uses the HTTPS fixture (tests/server/server_tls.py on
--  127.0.0.1:8766). Run from the repo root so the CA path resolves.

procedure Test_TLS_Retry is

   Host        : constant String := "localhost";
   Port        : constant AHT.URL.Port_Number := 8766;
   Closed_Port : constant AHT.URL.Port_Number := 8759;  --  nothing listens
   CA_File     : constant String := "tests/server/certs/server.crt";

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_retry: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function Contains (Haystack, Needle : String) return Boolean is
     (Ada.Strings.Fixed.Index (Haystack, Needle) /= 0);

   --  Send GET /hello and collect the response until the peer closes.
   function Fetch_Hello
     (T : in out AHT.Transport.TLS.TLS_Transport) return String
   is
      CRLF : constant String := ASCII.CR & ASCII.LF;
      Req  : constant AHT.Bytes.Byte_Array := AHT.Bytes.From_String
        ("GET /hello HTTP/1.1" & CRLF
         & "Host: " & Host & CRLF
         & "Connection: close" & CRLF
         & CRLF);
      Buf  : AHT.Bytes.Byte_Array (1 .. 4096);
      Last : Natural;
      Acc  : Unbounded_String;
   begin
      T.Write (Req);
      loop
         T.Read (Buf, Last);
         exit when Last = 0;
         Append (Acc, AHT.Bytes.To_String (Buf (1 .. Last)));
      end loop;
      return To_String (Acc);
   end Fetch_Hello;

   --  Assert the good-path Connect + fetch works on T (used after each
   --  induced failure to prove the object survived it).
   procedure Expect_Good_Connect
     (T    : in out AHT.Transport.TLS.TLS_Transport;
      What : String) is
   begin
      T.Connect (Host, Port, Insecure => False, CA_Path => CA_File);
      if not T.Is_Connected then
         Fail (What & ": Is_Connected false after good Connect");
      elsif not Contains (Fetch_Hello (T), "hello, world") then
         Fail (What & ": body missing after retry Connect");
      end if;
   exception
      when E : others =>
         Fail (What & ": retry Connect failed — "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E));
   end Expect_Good_Connect;

begin
   --  Case 1: TCP-level failure (connection refused), then success on
   --  the same object.
   declare
      T : AHT.Transport.TLS.TLS_Transport;
   begin
      begin
         T.Connect (Host, Closed_Port, Insecure => True,
                    Connect_Timeout => 5.0);
         Fail ("refused: Connect to closed port returned normally");
      exception
         when AHT.Transport.Transport_Error
            | AHT.Transport.Timeout_Error =>
            null;  --  expected
         when E : others =>
            Fail ("refused: unexpected "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E));
      end;
      if T.Is_Connected then
         Fail ("refused: Is_Connected true after failed Connect");
      end if;
      Expect_Good_Connect (T, "refused");
      T.Close;
   end;

   --  Case 2: certificate verification failure (no CA configured for a
   --  self-signed peer), then success with the right CA — the central
   --  retryability case: the TCP connect and part of the handshake DID
   --  run before the failure.
   declare
      T : AHT.Transport.TLS.TLS_Transport;
   begin
      begin
         T.Connect (Host, Port, Insecure => False);
         Fail ("untrusted: Connect returned normally");
      exception
         when AHT.Transport.TLS.TLS_Error =>
            null;  --  expected
         when E : others =>
            Fail ("untrusted: expected TLS_Error, got "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E));
      end;
      Expect_Good_Connect (T, "untrusted");
      T.Close;
   end;

   --  Case 3: CA loading failure (nonexistent bundle), then success.
   declare
      T : AHT.Transport.TLS.TLS_Transport;
   begin
      begin
         T.Connect (Host, Port, Insecure => False,
                    CA_Path => "tests/no/such/bundle.pem");
         Fail ("badca: Connect returned normally");
      exception
         when AHT.Transport.TLS.TLS_Error =>
            null;  --  expected
         when E : others =>
            Fail ("badca: expected TLS_Error, got "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E));
      end;
      Expect_Good_Connect (T, "badca");
      T.Close;
   end;

   --  Case 4: single-use is preserved — after a SUCCESSFUL session, a
   --  second Connect on the same object must be rejected, even after
   --  Close.
   declare
      T : AHT.Transport.TLS.TLS_Transport;
   begin
      Expect_Good_Connect (T, "single-use setup");
      T.Close;
      begin
         T.Connect (Host, Port, Insecure => False, CA_Path => CA_File);
         Fail ("single-use: second Connect on a used object succeeded");
      exception
         when AHT.Transport.TLS.TLS_Error =>
            null;  --  expected
         when E : others =>
            Fail ("single-use: expected TLS_Error, got "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E));
      end;
   end;

   if Failures = 0 then
      Put_Line ("test_tls_retry: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_retry:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Retry;
