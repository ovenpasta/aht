--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Where mbedTLS gets its entropy, mbedtls backend. The library is built
--  MBEDTLS_NO_PLATFORM_ENTROPY and its pool is fed by
--  AHT.Mbedtls.Entropy.Poll, registered from aht_mbedtls_entropy_new. A
--  verified TLS connect against the HTTPS fixture (8766) must move
--  AHT.Random's counters. The openssl source asserts the opposite.
--
--  Cases:
--    - Draws and Bytes_Requested both increase across the connect
--
--  Covers:
--    - which source delivered: nothing in the mbedtls transport calls
--      AHT.Random itself and a raw TLS_Transport draws no masks and no
--      nonce, so any movement came through the entropy callback
--  Does not cover:
--    - that the pool is fed at all; every other TLS test shows that,
--      since without a source mbedtls_ctr_drbg_seed fails

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

   --  Snapshots, since the counters are process-global and this test
   --  does not own them.
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

   if Draws_After <= Draws_Before then
      Fail ("a TLS connect drew nothing from AHT.Random — mbedTLS "
            & "seeded from some other source, so the platform entropy "
            & "this build excludes is reachable after all");
   end if;

   --  Both counters, because Draws alone would also be satisfied by a
   --  zero-length request, which delivers no entropy.
   if Bytes_After <= Bytes_Before then
      Fail ("Draws moved but Bytes_Requested did not — the callback "
            & "asked for zero bytes");
   end if;

   if Failures = 0 then
      Put_Line ("test_tls_entropy: OK (mbedTLS seeded through "
                & "AHT.Random:" & Natural'Image (Draws_After - Draws_Before)
                & " draw(s),"
                & Natural'Image (Bytes_After - Bytes_Before) & " bytes)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_entropy:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Entropy;
