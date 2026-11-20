--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  The trust choice at Connect: no implicit trust, Use_System_Roots
--  as an explicit source, and the rule that exactly one source is
--  chosen. Against server_tls.py on localhost:8766 and
--  server_ws_tls.py on localhost:8768 (server_ws.py on 8765 and
--  server.py on 8764 are dialled only if a guard fails).
--  SSL_CERT_FILE points AHT.Root_Store at a chosen file, so the System
--  path is exercised deterministically on every OS; the platform's
--  own store appears in cases 7 and 8. Run from the repo root.
--
--  Cases:
--    1. no source, verifying: refused before dialling, on the
--       transport, the HTTP client and the WebSocket client
--    2. Use_System_Roots with the fixture's certificate as the store:
--       the handshake verifies, on all three; Reconnect replays it
--    3. Use_System_Roots with an unrelated certificate as the store:
--       dialled, and rejected by the handshake
--    4. Use_System_Roots with an empty store: refused before dialling
--    5. Use_System_Roots with CA_Path or CA_PEM: refused before
--       dialling, under Insecure too, and on a ws:// or http:// dial
--    6. Use_System_Roots under Insecure: the store is not read
--    7. the platform's own store plus the fixture certificate:
--       verifies, so the whole platform store installs on this backend
--    8. the platform's own store alone: dialled and rejected by the
--       handshake, not by loading the store
--
--  Dialling is observed through Address_Filter, which
--  AHT.Transport.TCP.Connect consults for every candidate address
--  before connecting; the control in case 2 shows it counts.

with Ada.Command_Line;
with Ada.Directories;
with Ada.Environment_Variables;
with Ada.Exceptions;
with Ada.Streams.Stream_IO;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.HTTP.Client;
with AHT.HTTP.Response;
with AHT.Root_Store;
with AHT.Transport.TLS;
with AHT.URL;
with AHT.Websocket.Client;

with Test_Untrusted;

procedure Test_TLS_Trust is

   package Env renames Ada.Environment_Variables;

   Host     : constant String := "localhost";
   Port     : constant AHT.URL.Port_Number := 8766;
   HTTPS    : constant String := "https://localhost:8766/hello";
   WSS      : constant String := "wss://localhost:8768/";
   Fixture  : constant String := "tests/server/certs/server.crt";
   Other    : constant String := "tests/server/certs/other.crt";
   Work     : constant String := "tests/obj/tls_trust_files";
   Empty    : constant String := Work & "/empty.pem";
   Combined : constant String := Work & "/platform_and_fixture.pem";

   No_Trust  : constant String := "no trust anchors configured";
   Exclusive : constant String := "mutually exclusive";
   No_Store  : constant String := "no certificate found";

   Failures : Natural := 0;

   --  Written only by the connecting task, which is this one.
   Dials : Natural := 0;

   function Counting_Filter (Host, Address : String) return Boolean is
      pragma Unreferenced (Host, Address);
   begin
      Dials := Dials + 1;
      return True;
   end Counting_Filter;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_trust: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function Contains (Haystack, Needle : String) return Boolean is
     (Ada.Strings.Fixed.Index (Haystack, Needle) /= 0);

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

   procedure Write_File (Path : String; Data : String) is
      package SIO renames Ada.Streams.Stream_IO;
      F : SIO.File_Type;
   begin
      SIO.Create (F, SIO.Out_File, Path);
      String'Write (SIO.Stream (F), Data);
      SIO.Close (F);
   end Write_File;

   procedure Use_Store (File : String) is
   begin
      Env.Clear ("SSL_CERT_DIR");
      if File = "" then
         Env.Clear ("SSL_CERT_FILE");
      else
         Env.Set ("SSL_CERT_FILE", File);
      end if;
   end Use_Store;

   procedure Close_Quietly (T : in out AHT.Transport.TLS.TLS_Transport) is
   begin
      T.Close;
   exception
      when others => null;
   end Close_Quietly;

   --  A transport Connect expected to succeed; Dials must move.
   procedure Expect_Connects
     (What             : String;
      Insecure         : Boolean := False;
      CA_Path          : String := "";
      Use_System_Roots : Boolean := False)
   is
      T : AHT.Transport.TLS.TLS_Transport;
   begin
      Dials := 0;
      T.Connect (Host, Port,
                 Insecure         => Insecure,
                 CA_Path          => CA_Path,
                 Address_Filter   => Counting_Filter'Access,
                 Use_System_Roots => Use_System_Roots);
      if not T.Is_Connected then
         Fail (What & ": Connect returned but Is_Connected is false");
      end if;
      if Dials = 0 then
         Fail (What & ": connected, but Address_Filter saw no dial; "
               & "it cannot show that a refusal came before dialling");
      end if;
      Close_Quietly (T);
   exception
      when E : others =>
         Fail (What & ": raised " & Ada.Exceptions.Exception_Name (E)
               & ": " & Ada.Exceptions.Exception_Message (E));
   end Expect_Connects;

   --  A transport Connect expected to raise TLS_Error whose message
   --  contains Why. Dialled says whether the refusal comes after the
   --  TCP connect (a handshake rejection) or before it.
   procedure Expect_Refused
     (What             : String;
      Why              : String;
      Dialled          : Boolean;
      Insecure         : Boolean := False;
      CA_Path          : String := "";
      CA_PEM           : String := "";
      Use_System_Roots : Boolean := False)
   is
      T : AHT.Transport.TLS.TLS_Transport;
   begin
      Dials := 0;
      T.Connect (Host, Port,
                 Insecure         => Insecure,
                 CA_Path          => CA_Path,
                 CA_PEM           => CA_PEM,
                 Address_Filter   => Counting_Filter'Access,
                 Use_System_Roots => Use_System_Roots);
      Close_Quietly (T);
      Fail (What & ": Connect succeeded");
   exception
      when E : AHT.Transport.TLS.TLS_Error =>
         declare
            Msg : constant String := Ada.Exceptions.Exception_Message (E);
         begin
            if Why /= "" and then not Contains (Msg, Why) then
               Fail (What & ": TLS_Error without """ & Why & """: " & Msg);
            end if;
            if Dialled and then Dials = 0 then
               Fail (What & ": refused before dialling: " & Msg);
            elsif not Dialled and then Dials /= 0 then
               Fail (What & ": refused only after dialling ("
                     & Dials'Image & " dial(s)): " & Msg);
            end if;
            if Dialled and then Contains (Msg, "Use_System_Roots") then
               Fail (What & ": the store failed to load: " & Msg);
            end if;
         end;
      when E : others =>
         Fail (What & ": expected TLS_Error, got "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E));
   end Expect_Refused;

   Cert : constant String := Read_File (Fixture);

begin
   if Cert = "" or else Read_File (Other) = "" then
      Fail ("cannot read " & Fixture & " and " & Other
            & "; run scripts/generate_cert.sh from the repo root");
      Put_Line ("test_tls_trust:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
      return;
   end if;

   if Ada.Directories.Exists (Work) then
      Ada.Directories.Delete_Tree (Work);
   end if;
   Ada.Directories.Create_Path (Work);
   Write_File (Empty, "");

   --  The platform's store, read before any case sets SSL_CERT_FILE.
   Use_Store ("");
   declare
      Platform : constant AHT.Root_Store.Roots := AHT.Root_Store.Load;
   begin
      if Platform.Count = 0 then
         Fail ("the platform store yielded no certificate; cases 7 and "
               & "8 cannot run");
      else
         Write_File (Combined, To_String (Platform.PEM) & Cert);
      end if;
   end;

   --  Case 2 control first: CA_Path at the fixture connects, and the
   --  filter counts the dial. Without this a zero below proves
   --  nothing.
   Use_Store (Empty);
   Expect_Connects ("control", CA_Path => Fixture);

   --  Case 1: no source. The store is set to the fixture, so an
   --  implementation that fell back to it would connect.
   Use_Store (Fixture);
   Expect_Refused ("no-trust", No_Trust, Dialled => False);

   declare
      C    : AHT.HTTP.Client.Client_Type;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Resp := AHT.HTTP.Client.Get (C, HTTPS);
      Fail ("no-trust http: Get returned status" & Resp.Status'Image);
   exception
      when E : AHT.Transport.TLS.TLS_Error =>
         if not Contains (Ada.Exceptions.Exception_Message (E), No_Trust)
         then
            Fail ("no-trust http: "
                  & Ada.Exceptions.Exception_Message (E));
         end if;
      when E : others =>
         Fail ("no-trust http: expected TLS_Error, got "
               & Ada.Exceptions.Exception_Name (E));
   end;

   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      AHT.Websocket.Client.Connect (C, WSS);
      AHT.Websocket.Client.Close (C);
      Fail ("no-trust wss: Connect succeeded");
   exception
      when E : AHT.Transport.TLS.TLS_Error =>
         if not Contains (Ada.Exceptions.Exception_Message (E), No_Trust)
         then
            Fail ("no-trust wss: "
                  & Ada.Exceptions.Exception_Message (E));
         end if;
      when E : others =>
         Fail ("no-trust wss: expected TLS_Error, got "
               & Ada.Exceptions.Exception_Name (E));
   end;

   --  Case 2: the fixture's certificate as the platform store.
   Use_Store (Fixture);
   Expect_Connects ("system", Use_System_Roots => True);

   declare
      C    : AHT.HTTP.Client.Client_Type;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      C.Use_System_Roots := True;
      Resp := AHT.HTTP.Client.Get (C, HTTPS);
      if Resp.Status /= 200 or else not Contains (Resp.Body_Text, "hello, world")
      then
         Fail ("system http: status" & Resp.Status'Image & ", body """
               & Resp.Body_Text & """");
      end if;
   exception
      when E : others =>
         Fail ("system http: raised " & Ada.Exceptions.Exception_Name (E)
               & ": " & Ada.Exceptions.Exception_Message (E));
   end;

   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      AHT.Websocket.Client.Connect (C, WSS, Use_System_Roots => True);
      --  The saved choice is replayed; with no source a redial would
      --  be refused.
      AHT.Websocket.Client.Reconnect (C);
      if AHT.Websocket.Client.Generation (C) /= 2 then
         Fail ("system wss: Generation ="
               & AHT.Websocket.Client.Generation (C)'Image
               & " after Reconnect (expected 2)");
      end if;
      AHT.Websocket.Client.Close (C);
   exception
      when E : others =>
         Fail ("system wss: raised " & Ada.Exceptions.Exception_Name (E)
               & ": " & Ada.Exceptions.Exception_Message (E));
   end;

   --  Case 3: a store that does not cover the fixture. Same subject
   --  and SANs, different key: only the signature check rejects it.
   Use_Store (Other);
   Expect_Refused ("system-untrusted", "", Dialled => True,
                   Use_System_Roots => True);

   --  Case 4: an empty store.
   Use_Store (Empty);
   Expect_Refused ("system-empty", No_Store, Dialled => False,
                   Use_System_Roots => True);

   --  Case 5: more than one source, with a store that would verify.
   Use_Store (Fixture);
   Expect_Refused ("system+path", Exclusive, Dialled => False,
                   CA_Path => Fixture, Use_System_Roots => True);
   Expect_Refused ("system+pem", Exclusive, Dialled => False,
                   CA_PEM => Cert, Use_System_Roots => True);
   Expect_Refused ("system+pem insecure", Exclusive, Dialled => False,
                   Insecure => True, CA_PEM => Cert,
                   Use_System_Roots => True);

   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      AHT.Websocket.Client.Connect
        (C, "ws://127.0.0.1:8765/", CA_PEM => Cert,
         Use_System_Roots => True);
      AHT.Websocket.Client.Close (C);
      Fail ("ws guard: System and CA_PEM accepted on a ws:// dial");
   exception
      when E : AHT.Transport.TLS.TLS_Error =>
         if not Contains (Ada.Exceptions.Exception_Message (E), Exclusive)
         then
            Fail ("ws guard: " & Ada.Exceptions.Exception_Message (E));
         end if;
         if AHT.Websocket.Client.Generation (C) /= 0 then
            Fail ("ws guard: refused after admission");
         end if;
      when E : others =>
         Fail ("ws guard: expected TLS_Error, got "
               & Ada.Exceptions.Exception_Name (E));
   end;

   declare
      C    : AHT.HTTP.Client.Client_Type;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      C.CA_PEM := To_Unbounded_String (Cert);
      C.Use_System_Roots := True;
      C.On_Address := Test_Untrusted.Count_Dial'Access;
      Test_Untrusted.Dials := 0;
      Resp := AHT.HTTP.Client.Get (C, "http://127.0.0.1:8764/hello");
      Fail ("http guard: System and CA_PEM accepted on an http:// "
            & "request (status" & Resp.Status'Image & ")");
   exception
      when E : AHT.Transport.TLS.TLS_Error =>
         if not Contains (Ada.Exceptions.Exception_Message (E), Exclusive)
         then
            Fail ("http guard: " & Ada.Exceptions.Exception_Message (E));
         end if;
         if Test_Untrusted.Dials /= 0 then
            Fail ("http guard: refused only after dialling");
         end if;
      when E : others =>
         Fail ("http guard: expected TLS_Error, got "
               & Ada.Exceptions.Exception_Name (E));
   end;

   --  Case 6: Insecure with an empty store. Reading it would refuse.
   Use_Store (Empty);
   Expect_Connects ("system insecure", Insecure => True,
                    Use_System_Roots => True);

   --  Cases 7 and 8: the platform's own store.
   if Ada.Directories.Exists (Combined) then
      Use_Store (Combined);
      Expect_Connects ("platform+fixture", Use_System_Roots => True);

      Use_Store ("");
      Expect_Refused ("platform", "", Dialled => True,
                      Use_System_Roots => True);
   end if;

   Use_Store ("");
   Ada.Directories.Delete_Tree (Work);

   if Failures = 0 then
      Put_Line ("test_tls_trust: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_trust:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Trust;
