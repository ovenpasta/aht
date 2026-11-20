--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.Transport;
with AHT.Transport.TLS;
with AHT.URL;

with Test_Untrusted;

--  Transport-level TLS test. Drives AHT.Transport.TLS against the HTTPS
--  fixture (tests/server/server_tls.py on 127.0.0.1:8766) by speaking a
--  minimal HTTP/1.1 GET over the established session: enough to
--  exercise the handshake, certificate verification, Write and Read
--  without involving the HTTP client.
--
--  Run from the repo root (tests/run_tests.sh chdir's there) so the
--  relative CA path resolves.

procedure Test_TLS is

   Host    : constant String := "localhost";
   Port    : constant AHT.URL.Port_Number := 8766;
   CA_File : constant String := "tests/server/certs/server.crt";

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Send GET /hello and collect the response until the peer closes
   --  (Read => Last = 0). The fixture answers Connection: close, so the
   --  read loop terminates on EOF without keep-alive parsing.
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

   procedure Close_Quietly (T : in out AHT.Transport.TLS.TLS_Transport) is
   begin
      T.Close;
   exception
      when others => null;
   end Close_Quietly;

   function Contains (Haystack, Needle : String) return Boolean is
     (Ada.Strings.Fixed.Index (Haystack, Needle) /= 0);

begin
   --  Case 1: verify against the fixture's own CA. The cert chains to
   --  CA_File and its SAN matches "localhost", so the handshake must
   --  succeed and /hello must echo back intact.
   declare
      T : AHT.Transport.TLS.TLS_Transport;
   begin
      begin
         T.Connect (Host, Port, Insecure => False, CA_Path => CA_File);
         if not T.Is_Connected then
            Fail ("verify: Is_Connected false after Connect");
         else
            declare
               Resp : constant String := Fetch_Hello (T);
            begin
               if not Contains (Resp, "200") then
                  Fail ("verify: no 200 status line — """ & Resp & """");
               elsif not Contains (Resp, "hello, world") then
                  Fail ("verify: body missing — """ & Resp & """");
               end if;
            end;
         end if;
      exception
         when E : others =>
            Fail ("verify: unexpected "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E));
      end;
      Close_Quietly (T);
   end;

   --  Case 2: Insecure bypasses verification. Same self-signed cert,
   --  no CA supplied; the handshake must still complete and serve
   --  /hello.
   declare
      T : AHT.Transport.TLS.TLS_Transport;
   begin
      begin
         T.Connect (Host, Port, Insecure => True);
         if not T.Is_Connected then
            Fail ("insecure: Is_Connected false after Connect");
         elsif not Contains (Fetch_Hello (T), "hello, world") then
            Fail ("insecure: body missing from response");
         end if;
      exception
         when E : others =>
            Fail ("insecure: unexpected "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E));
      end;
      Close_Quietly (T);
   end;

   --  Case 3: verify required, trusting an unrelated certificate. The
   --  self-signed cert chains to no trusted root, so the handshake
   --  must be rejected with TLS_Error. The anchor is checked first and
   --  the dial counted, so a refusal while loading it cannot pass for
   --  a handshake rejection. (No trust at all is refused before
   --  dialling; test_tls_trust covers that.)
   if Test_Untrusted.Anchor_Problem /= "" then
      Fail ("untrusted: " & Test_Untrusted.Anchor_Problem);
   else
      declare
         T : AHT.Transport.TLS.TLS_Transport;
      begin
         Test_Untrusted.Dials := 0;
         T.Connect (Host, Port, Insecure => False,
                    CA_Path        => Test_Untrusted.Other_File,
                    Address_Filter => Test_Untrusted.Count_Dial'Access);
         Fail ("untrusted: Connect returned normally (Is_Connected="
               & Boolean'Image (T.Is_Connected) & ")");
         Close_Quietly (T);
      exception
         when E : AHT.Transport.TLS.TLS_Error =>
            if Test_Untrusted.Dials = 0
              or else not Test_Untrusted.Is_Handshake_Rejection
                            (Ada.Exceptions.Exception_Message (E))
            then
               Fail ("untrusted: not rejected by the handshake ("
                     & Test_Untrusted.Dials'Image & " dial(s)): "
                     & Ada.Exceptions.Exception_Message (E));
            end if;
         when E : others =>
            Fail ("untrusted: expected TLS_Error, got "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E));
      end;
   end if;

   if Failures = 0 then
      Put_Line ("test_tls: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS;
