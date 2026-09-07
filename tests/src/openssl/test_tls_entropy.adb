--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Where the TLS engine gets its entropy, openssl backend. The engine
--  has its own RNG and never reaches AHT.Random, so a verified TLS
--  connect against the HTTPS fixture (8766) must leave AHT.Random's
--  counters where it found them. The mbedtls source of this test
--  asserts the opposite on the same connect.
--
--  Cases:
--    - Draws and Bytes_Requested are unchanged across the connect
--
--  Covers:
--    - the accounting test_ws_masking reads: its arithmetic assumes the
--      only AHT.Random callers are frame masking and the handshake nonce

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Random;
with AHT.Transport.TLS;
with AHT.URL;

procedure Test_TLS_Entropy is

   Port    : constant AHT.URL.Port_Number := 8766;
   CA_File : constant String := "tests/server/certs/server.crt";

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_entropy: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   Draws_Before : constant Natural := AHT.Random.Draws;
   Bytes_Before : constant Natural := AHT.Random.Bytes_Requested;

   Draws_After  : Natural;
   Bytes_After  : Natural;

begin
   declare
      T : AHT.Transport.TLS.TLS_Transport;
   begin
      begin
         T.Connect ("127.0.0.1", Port, Insecure => False,
                    CA_Path => CA_File);
      exception
         when E : others =>
            Fail ("connect failed — "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E)
                  & " (is tests/server/server_tls.py running?)");
      end;
      begin
         T.Close;
      exception
         when others => null;
      end;
   end;

   Draws_After := AHT.Random.Draws;
   Bytes_After := AHT.Random.Bytes_Requested;

   Put_Line ("  draws" & Natural'Image (Draws_Before)
             & " ->" & Natural'Image (Draws_After)
             & ", bytes" & Natural'Image (Bytes_Before)
             & " ->" & Natural'Image (Bytes_After));

   if Draws_After /= Draws_Before
     or else Bytes_After /= Bytes_Before
   then
      Fail ("a TLS connect drew from AHT.Random on the openssl "
            & "backend — this engine seeds itself, and test_ws_masking "
            & "reads these counters assuming only masking and the "
            & "handshake nonce move them");
   end if;

   if Failures = 0 then
      Put_Line ("test_tls_entropy: OK (openssl seeds itself; "
                & "AHT.Random untouched by a TLS connect)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_entropy:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Entropy;
