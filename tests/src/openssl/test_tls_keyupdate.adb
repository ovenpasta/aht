--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Coordinator + TLS 1.3 KeyUpdate coverage, openssl backend.
--
--  A. The shared white-box coordinator cases (TLS_Sync_Cases, run by
--     both backends' copies of this main).
--
--  B. End-to-end KeyUpdate: drives `openssl s_server` and triggers
--     'K' (key update with request) from its stdin while exchanging
--     data, so the engine processes KeyUpdate records inside Read and
--     generates its own update on the following Write.
--
--  Half B needs an OpenSSL 3 CLI at ${AHT_OPENSSL_DIR:-/usr}/bin/
--  openssl — a bare `openssl` on PATH is NOT trusted (LibreSSL ships
--  under that name); without it half B SKIPs with a notice (CI
--  installs the CLI, so it always runs there). The mbedtls source of
--  this test main is a plain SKIP (TLS 1.2 has no KeyUpdate).

with Ada.Command_Line;
with Ada.Directories;
with Ada.Environment_Variables;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with GNAT.Expect;
with GNAT.OS_Lib;

with TLS_Sync_Cases;

with AHT.Bytes;
with AHT.Transport;
with AHT.Transport.TLS;
with AHT.URL;

procedure Test_TLS_Keyupdate is

   Port    : constant AHT.URL.Port_Number := 8772;
   CA_File : constant String := "tests/server/certs/server.crt";
   Key_File : constant String := "tests/server/certs/server.key";

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_keyupdate: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  First writer-task error, if any: the concurrent half's writer
   --  runs in its own task, so it cannot touch Failures directly.
   protected Sender_Status is
      procedure Note (Msg : String);
      function Message return String;
      function Failed return Boolean;
   private
      Has : Boolean := False;
      Txt : Unbounded_String;
   end Sender_Status;

   protected body Sender_Status is
      procedure Note (Msg : String) is
      begin
         if not Has then
            Has := True;
            Txt := To_Unbounded_String (Msg);
         end if;
      end Note;
      function Message return String is (To_String (Txt));
      function Failed return Boolean is (Has);
   end Sender_Status;

   ------------------------------------------------------------------
   --  Half B — s_server KeyUpdate end-to-end
   ------------------------------------------------------------------

   function Openssl_Bin return String is
      Dir : constant String :=
        (if Ada.Environment_Variables.Exists ("AHT_OPENSSL_DIR")
         then Ada.Environment_Variables.Value ("AHT_OPENSSL_DIR")
         else "/usr");
   begin
      return Dir & "/bin/openssl";
   end Openssl_Bin;

   function CLI_Is_Openssl3 (Bin : String) return Boolean is
      use GNAT.OS_Lib;
      Status : aliased Integer;
      Args   : constant Argument_List :=
        [1 => new String'("version")];
      Output : constant String :=
        GNAT.Expect.Get_Command_Output
          (Bin, Args, "", Status'Access, Err_To_Out => True);
   begin
      for A of Args loop
         declare
            P : GNAT.OS_Lib.String_Access := A;
         begin
            Free (P);
         end;
      end loop;
      return Status = 0
        and then Ada.Strings.Fixed.Index (Output, "OpenSSL 3") = 1;
   end CLI_Is_Openssl3;

   procedure Keyupdate_Case (Bin : String) is
      use GNAT.Expect;
      use GNAT.OS_Lib;

      Fd : Process_Descriptor;

      Q : constant Character := '"';

      --  Run under `sh -c` with stdout discarded. s_server echoes every
      --  byte the client sends to its stdout; on a pipe that nobody
      --  drains it blocks in write() and stops reading the socket,
      --  stalling our writer for reasons that have nothing to do with
      --  the engine. stdin stays our pipe, so Send (Fd, "K") still
      --  reaches it.
      Command : constant String :=
        Q & Bin & Q & " s_server -accept 8772"
        & " -cert " & Q & CA_File & Q
        & " -key " & Q & Key_File & Q
        & " -naccept 1 -quiet >/dev/null 2>&1";

      Args : constant Argument_List :=
        [new String'("-c"), new String'(Command)];

      T : AHT.Transport.TLS.TLS_Transport;

      procedure Cleanup_Args is
      begin
         for A of Args loop
            declare
               P : GNAT.OS_Lib.String_Access := A;
            begin
               Free (P);
            end;
         end loop;
      end Cleanup_Args;

   begin
      Non_Blocking_Spawn (Fd, "/bin/sh", Args, Buffer_Size => 8192);
      Cleanup_Args;

      --  Connect with retry: s_server needs a moment to listen (a
      --  failed Connect leaves the transport retryable by design).
      declare
         Connected : Boolean := False;
      begin
         for Attempt in 1 .. 50 loop
            begin
               T.Connect ("localhost", Port,
                          Insecure => False, CA_Path => CA_File,
                          Connect_Timeout    => 2.0,
                          Handshake_Deadline => 5.0);
               Connected := True;
               exit;
            exception
               when others =>
                  delay 0.1;
            end;
         end loop;
         if not Connected then
            Fail ("B: could not connect to s_server on 8772");
            Close (Fd);
            return;
         end if;
      end;

      T.Set_Read_Deadline (15.0);

      for Round in 1 .. 5 loop
         --  'K' = send KeyUpdate with update_requested: the server
         --  rekeys AND our engine must answer with its own KeyUpdate.
         Send (Fd, "K");
         delay 0.05;
         declare
            Token : constant String :=
              "marker" & Ada.Strings.Fixed.Trim
                           (Round'Image, Ada.Strings.Left);
            Buf   : AHT.Bytes.Byte_Array (1 .. 4096);
            Last  : Natural;
            Acc   : Unbounded_String;
         begin
            Send (Fd, Token);
            --  Read across the KeyUpdate until the token arrives —
            --  the rekey itself must be invisible here.
            loop
               T.Read (Buf, Last);
               if Last = 0 then
                  Fail ("B round" & Round'Image
                        & ": EOF before token");
                  exit;
               end if;
               Append (Acc, AHT.Bytes.To_String (Buf (1 .. Last)));
               exit when Ada.Strings.Fixed.Index
                 (To_String (Acc), Token) /= 0;
            end loop;
            --  And write back through the rekeyed state.
            T.Write (AHT.Bytes.From_String ("pong" & Round'Image));
         exception
            when E : others =>
               Fail ("B round" & Round'Image & ": "
                     & Ada.Exceptions.Exception_Name (E) & " — "
                     & Ada.Exceptions.Exception_Message (E));
               exit;
         end;
      end loop;

      --  Half C: the SAME session, now with a writer task running
      --  CONCURRENTLY with the main task's reads while the server
      --  rekeys. This is the path the engine documentation calls out —
      --  a writer that needs input (SSL_write -> WANT_READ across a
      --  post-handshake message) while the reader owns the feeder
      --  claim, so it must park on the coordinator latch and be woken
      --  by the reader's feed. Sequential rounds above cannot reach it.
      --  Re-arm both budgets: Set_*_Deadline measures from the CALL
      --  (a compound budget), so half B's rounds have already eaten
      --  the 15 s read allowance. The write deadline matters just as
      --  much here: a writer that hits WANT_READ parks until input
      --  arrives, and with no deadline that wait is unbounded by
      --  design — if the reader stops (a failed round), an unbounded
      --  writer would hang the test rather than fail it.
      T.Set_Read_Deadline (20.0);
      T.Set_Write_Deadline (20.0);

      declare
         Rounds  : constant := 6;
         --  Small, paced writes on purpose: s_server echoes everything
         --  the client sends to ITS stdout, which is a pipe nobody
         --  drains here, so a flood would stall the server (and time
         --  our writer out) long before it proved anything. What this
         --  phase needs is overlap — a writer inside Write while the
         --  reader is parked — not throughput.
         Chunk   : constant AHT.Bytes.Byte_Array (1 .. 64) :=
           [others => 16#5A#];
         Done    : Boolean := False with Volatile;

         task Writer;
         task body Writer is
         begin
            --  Hammer the write side for the whole read phase: every
            --  Write contends with the reader for the engine lock and
            --  may hit WANT_READ when a KeyUpdate lands mid-record.
            while not Done loop
               T.Write (Chunk);
               delay 0.02;
            end loop;
         exception
            when E : others =>
               Sender_Status.Note
                 (Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
         end Writer;

         Buf  : AHT.Bytes.Byte_Array (1 .. 4096);
         Last : Natural;
         Acc  : Unbounded_String;
      begin
         for Round in 1 .. Rounds loop
            declare
               Token : constant String :=
                 "conc" & Ada.Strings.Fixed.Trim
                            (Round'Image, Ada.Strings.Left);
            begin
               Send (Fd, "K");        --  rekey while both directions run
               Send (Fd, Token);
               loop
                  T.Read (Buf, Last);
                  if Last = 0 then
                     Fail ("C round" & Round'Image
                           & ": EOF before token");
                     exit;
                  end if;
                  Append (Acc, AHT.Bytes.To_String (Buf (1 .. Last)));
                  exit when Ada.Strings.Fixed.Index
                    (To_String (Acc), Token) /= 0;
               end loop;
            exception
               when E : others =>
                  Fail ("C round" & Round'Image & ": "
                        & Ada.Exceptions.Exception_Name (E) & " — "
                        & Ada.Exceptions.Exception_Message (E));
                  exit;
            end;
         end loop;
         Done := True;
      end;  --  joins Writer

      if Sender_Status.Failed then
         Fail ("C concurrent writer: " & Sender_Status.Message);
      end if;

      begin
         T.Close;
      exception
         when others => null;
      end;
      Close (Fd);
   exception
      when E : others =>
         Fail ("B: " & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
         begin
            Close (Fd);
         exception
            when others => null;
         end;
   end Keyupdate_Case;

begin
   Failures := Failures + TLS_Sync_Cases.Run ("test_tls_keyupdate");

   declare
      Bin : constant String := Openssl_Bin;
   begin
      if Ada.Directories.Exists (Bin)
        and then CLI_Is_Openssl3 (Bin)
      then
         Keyupdate_Case (Bin);
      else
         Put_Line ("test_tls_keyupdate: SKIP end-to-end half (no "
                   & "OpenSSL 3 CLI at " & Bin
                   & "; coordinator cases still ran)");
      end if;
   end;

   if Failures = 0 then
      Put_Line ("test_tls_keyupdate: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_keyupdate:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Keyupdate;
