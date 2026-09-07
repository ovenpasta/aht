--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Trust anchors supplied as PEM data (CA_PEM) instead of a filesystem
--  path (CA_Path). The same certificate, once by path and once as
--  bytes, must produce the same verified handshake. Against
--  server_ws_tls.py on localhost:8768 with the fixture's self-signed
--  cert; run from the repo root so the relative CA path resolves.
--
--  Cases:
--    1. the anchor as a path, as a baseline
--    2. the same bytes in memory
--    3. the anchor repeated: a duplicate is not malformed input
--    4. CA_Path and CA_PEM together: refused before dialling
--    5. nothing parseable: refused
--    6. a valid certificate followed by corrupt data: refused
--    6b. a valid certificate followed by ordinary text: refused
--    6c. ordinary text before the first certificate: refused
--    7. a truncated certificate: refused
--    7b. malformed PEM is refused under Insecure
--    8. the WebSocket client's own guard on a ws:// dial
--    9. Reconnect replays the PEM
--
--  Covers:
--    - parsing is all-or-nothing: an implementation that reads until
--      one fails installs a prefix and reports success; case 6 catches
--      it, case 5 is refused by any implementation
--    - 6b is caught by neither library's own error reporting
--    - 7b: the answer does not depend on which backend is linked
--    - case 8: Generation reads 0 afterwards, so the refusal comes
--      before admission reserves a generation
--    - case 9: a reference kept instead of a copy fails the second
--      handshake

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Transport;
with AHT.Transport.TLS;
with AHT.URL;
with AHT.Websocket.Client;

procedure Test_TLS_CA_PEM is

   Host    : constant String := "localhost";
   Port    : constant AHT.URL.Port_Number := 8766;
   CA_File : constant String := "tests/server/certs/server.crt";

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_ca_pem: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   procedure Close_Quietly (T : in out AHT.Transport.TLS.TLS_Transport) is
   begin
      T.Close;
   exception
      when others => null;
   end Close_Quietly;

   --  Slurp the fixture's certificate so the same bytes can be handed
   --  over both routes.
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
   exception
      when others =>
         if Is_Open (F) then
            Close (F);
         end if;
         return "";
   end Read_File;

   --  Dial with the given anchors and report only whether the
   --  handshake verified. Each case says what it expects.
   procedure Expect_Connects (What : String; PEM : String) is
      T : AHT.Transport.TLS.TLS_Transport;
   begin
      T.Connect (Host, Port, Insecure => False, CA_PEM => PEM);
      if not T.Is_Connected then
         Fail (What & ": Connect returned but Is_Connected is false");
      end if;
      Close_Quietly (T);
   exception
      when E : others =>
         Fail (What & ": handshake raised "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E));
   end Expect_Connects;

   procedure Expect_Refused
     (What : String; Path : String; PEM : String; Because : String)
   is
      T : AHT.Transport.TLS.TLS_Transport;
   begin
      T.Connect (Host, Port, Insecure => False,
                 CA_Path => Path, CA_PEM => PEM);
      Close_Quietly (T);
      Fail (What & ": Connect succeeded, but " & Because);
   exception
      when AHT.Transport.TLS.TLS_Error =>
         null;   --  correct
      when E : others =>
         Fail (What & ": expected TLS_Error, got "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E));
   end Expect_Refused;

   Cert : constant String := Read_File (CA_File);

begin
   if Cert = "" then
      Fail ("could not read " & CA_File
            & " — run from the repo root, after the fixtures have "
            & "generated a cert");
      Put_Line ("test_tls_ca_pem:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
      return;
   end if;

   if Ada.Strings.Fixed.Index (Cert, "-----BEGIN CERTIFICATE-----") = 0
   then
      Fail ("the fixture cert does not look like PEM, so every case "
            & "below would be testing the wrong thing");
      Put_Line ("test_tls_ca_pem:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
      return;
   end if;

   --  Case 1: the same anchor as a path, as a baseline. If this fails
   --  the fixture or the cert is wrong and nothing below means
   --  anything.
   declare
      T : AHT.Transport.TLS.TLS_Transport;
   begin
      T.Connect (Host, Port, Insecure => False, CA_Path => CA_File);
      if not T.Is_Connected then
         Fail ("baseline: CA_Path connected but Is_Connected is false");
      end if;
      Close_Quietly (T);
   exception
      when E : others =>
         Fail ("baseline: CA_Path handshake raised "
               & Ada.Exceptions.Exception_Name (E)
               & " (is server_tls.py running?)");
         Put_Line ("test_tls_ca_pem:" & Failures'Image & " failure(s)");
         Ada.Command_Line.Set_Exit_Status (1);
         return;
   end;

   --  Case 2: the same bytes, in memory.
   Expect_Connects ("ca-pem", Cert);

   --  Case 3: the anchor repeated. A real bundle may legitimately
   --  contain a root twice, and a duplicate must not be mistaken for
   --  malformed input.
   Expect_Connects ("ca-pem-duplicated", Cert & Cert);

   --  Case 4: both routes at once. No precedence; refused before
   --  anything is dialled.
   Expect_Refused
     ("both-supplied", CA_File, Cert,
      "CA_Path and CA_PEM together are contradictory and must be "
      & "refused rather than silently resolved");

   --  Case 5: nothing parseable at all. Any implementation refuses
   --  this; it is the baseline for the cases below.
   Expect_Refused
     ("garbage-only", "", "not a certificate at all",
      "the PEM contained no certificate");

   --  Case 6: a valid certificate followed by corrupt data. An
   --  implementation that reads certificates until one fails would
   --  install this one and report success, trusting a prefix of what
   --  was supplied.
   Expect_Refused
     ("valid-then-garbage",
      "", Cert & "-----BEGIN CERTIFICATE-----" & ASCII.LF
          & "bm90IGEgY2VydGlmaWNhdGU=" & ASCII.LF
          & "-----END CERTIFICATE-----" & ASCII.LF,
      "the bundle's tail is corrupt, so the whole bundle must be "
      & "rejected rather than the leading certificate installed");

   --  Case 6b: a valid certificate followed by ORDINARY text, not a
   --  malformed PEM block: the shape a stray log line or a
   --  concatenation accident takes. Neither library's own error
   --  reporting catches it: OpenSSL's PEM_R_NO_START_LINE also means
   --  "no further header", and mbedTLS stops at the missing header
   --  and returns the earlier success count.
   Expect_Refused
     ("valid-then-plain-garbage",
      "", Cert & "this is trailing garbage" & ASCII.LF,
      "the bundle has trailing non-PEM data, so it is not wholly what "
      & "the caller supplied and must be refused");

   --  Case 6c: the same, leading. A prefix of junk before the first
   --  certificate is equally not a well-formed bundle.
   Expect_Refused
     ("garbage-then-valid",
      "", "this is leading garbage" & ASCII.LF & Cert,
      "the bundle has leading non-PEM data");

   --  Case 7: a truncated certificate, the shape a partial copy or a
   --  clipped build artefact takes.
   Expect_Refused
     ("truncated",
      "", Cert (Cert'First .. Cert'First + Cert'Length / 2),
      "the certificate is cut short, so it cannot be trusted in part");

   --  Case 7b: malformed PEM is refused even under Insecure. Broken
   --  trust material is a caller error whether or not this dial would
   --  use it, and the answer must not depend on the backend: OpenSSL
   --  skips CA loading when verification is off, mbedTLS parses it.
   declare
      T : AHT.Transport.TLS.TLS_Transport;
   begin
      T.Connect (Host, Port, Insecure => True,
                 CA_PEM => "not a certificate at all");
      Close_Quietly (T);
      Fail ("insecure-malformed: a malformed CA_PEM was accepted "
            & "because Insecure was set — the check must not depend "
            & "on whether verification is on");
   exception
      when AHT.Transport.TLS.TLS_Error =>
         null;   --  correct
      when E : others =>
         Fail ("insecure-malformed: expected TLS_Error, got "
               & Ada.Exceptions.Exception_Name (E));
   end;

   --  Case 8: the WebSocket client's own guard. On a ws:// dial no TLS
   --  transport is built, so the transport-level refusal cannot fire.
   --  Generation must still read 0 afterwards: the refusal comes
   --  before admission reserves a generation.
   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      AHT.Websocket.Client.Connect
        (C, "ws://127.0.0.1:8765/", Insecure => False,
         CA_Path => "unused", CA_PEM => "unused");
      Fail ("ws-guard: both CA_Path and CA_PEM were accepted on a "
            & "ws:// dial, where no TLS transport exists to refuse "
            & "them");
   exception
      when AHT.Transport.TLS.TLS_Error =>
         if AHT.Websocket.Client.Generation (C) /= 0 then
            Fail ("ws-guard: refused, but Generation ="
                  & Natural'Image (AHT.Websocket.Client.Generation (C))
                  & " — admission was reserved before the check");
         end if;
      when E : others =>
         Fail ("ws-guard: expected TLS_Error, got "
               & Ada.Exceptions.Exception_Name (E));
   end;

   --  Case 9: Reconnect replays the PEM.
   --
   --  Connect_Params deep-copies it like every other parameter, so a
   --  redial must verify against the same anchors without the caller
   --  holding anything alive. A reference kept instead of a copy shows
   --  up here as a failed second handshake.
   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      declare
         --  A temporary: it is out of scope by the time Reconnect
         --  runs, so only a copy taken at Connect can work.
         Anchors : constant String := Cert;
      begin
         --  localhost, not the IP literal, so this exercises the
         --  dNSName path; the iPAddress path is covered by
         --  test_tls_ip_host, so a failure here points at CA_PEM.
         AHT.Websocket.Client.Connect
           (C, "wss://localhost:8768/", Insecure => False,
            CA_PEM => Anchors);
      end;

      if AHT.Websocket.Client.Generation (C) /= 1 then
         Fail ("ws-reconnect: first wss Connect did not establish");
      else
         AHT.Websocket.Client.Reconnect (C);
         if AHT.Websocket.Client.Generation (C) /= 2 then
            Fail ("ws-reconnect: Generation ="
                  & Natural'Image (AHT.Websocket.Client.Generation (C))
                  & " after Reconnect (expected 2)");
         end if;
      end if;
      AHT.Websocket.Client.Close (C);
   exception
      when E : others =>
         Fail ("ws-reconnect: raised "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E)
               & " — the saved CA_PEM was not replayed");
   end;

   if Failures = 0 then
      Put_Line ("test_tls_ca_pem: OK (in-memory anchors verify the same "
                & "chain as the file; partial bundles refused; "
                & "replayed by Reconnect)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_ca_pem:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_CA_PEM;
