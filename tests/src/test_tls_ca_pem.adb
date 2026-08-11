--  Trust anchors supplied as PEM data rather than as a filesystem path.
--
--  The point of CA_PEM is anchors compiled into the binary, so the
--  decisive comparison is against CA_Path: the SAME certificate, once
--  by path and once as bytes, must produce the same verified
--  handshake. Anything else means the in-memory route is not really
--  loading what it was given.
--
--  The rest of the cases are about refusing, and they matter more than
--  the happy path:
--
--    * Both CA_Path and CA_PEM supplied is an error, with no
--      precedence, before anything is dialled. A caller who passed two
--      sets of anchors is wrong about which is in force, and honouring
--      one silently leaves that belief intact.
--
--    * Parsing is ALL-OR-NOTHING. A bundle whose tail is truncated or
--      corrupt must be rejected whole. This is the case worth having:
--      the natural implementation on both backends reads certificates
--      until one fails to parse, which would install everything before
--      the damage and report success -- trusting a prefix of what the
--      caller meant to trust, silently. The valid-cert-plus-garbage
--      case below is the one that catches it, because the
--      garbage-only case is refused by any implementation.
--
--  Run from the repo root, like the other TLS tests, so the relative
--  CA path resolves.

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

   --  Case 2: the same bytes, in memory. This is the feature.
   Expect_Connects ("ca-pem", Cert);

   --  Case 3: the anchor repeated. A real bundle may legitimately
   --  contain a root twice, and a duplicate must not be mistaken for
   --  malformed input.
   Expect_Connects ("ca-pem-duplicated", Cert & Cert);

   --  Case 4: both routes at once. No precedence — refused before
   --  anything is dialled.
   Expect_Refused
     ("both-supplied", CA_File, Cert,
      "CA_Path and CA_PEM together are contradictory and must be "
      & "refused rather than silently resolved");

   --  Case 5: nothing parseable at all. Any implementation refuses
   --  this; it is here so the harder cases below can be read as
   --  strictly stronger.
   Expect_Refused
     ("garbage-only", "", "not a certificate at all",
      "the PEM contained no certificate");

   --  Case 6: a valid certificate followed by corrupt data. THE case.
   --  An implementation that reads certificates until one fails would
   --  install this one and report success, trusting a prefix of what
   --  was supplied.
   Expect_Refused
     ("valid-then-garbage",
      "", Cert & "-----BEGIN CERTIFICATE-----" & ASCII.LF
          & "bm90IGEgY2VydGlmaWNhdGU=" & ASCII.LF
          & "-----END CERTIFICATE-----" & ASCII.LF,
      "the bundle's tail is corrupt, so the whole bundle must be "
      & "rejected rather than the leading certificate installed");

   --  Case 7: a truncated certificate — the shape a partial copy or a
   --  clipped build artefact actually takes.
   Expect_Refused
     ("truncated",
      "", Cert (Cert'First .. Cert'First + Cert'Length / 2),
      "the certificate is cut short, so it cannot be trusted in part");

   --  Case 8: the WebSocket client's own guard.
   --
   --  On a ws:// dial no TLS transport is ever built, so the
   --  transport-level refusal cannot fire and this is the only thing
   --  that catches the contradiction. Generation must still read 0
   --  afterwards: the refusal has to come before admission reserves a
   --  generation, not after.
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
         --  Deliberately a temporary: it is out of scope by the time
         --  Reconnect runs, so only a copy taken at Connect can work.
         Anchors : constant String := Cert;
      begin
         --  localhost, not the IP literal: mbedTLS 2.28 matches
         --  dNSName SANs and the CN but not iPAddress SANs, so a
         --  verifying dial to 127.0.0.1 fails there for reasons that
         --  have nothing to do with CA_PEM. The cert carries both
         --  SANs; this picks the one both backends honour.
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
