--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Where mbedTLS gets its entropy, mbedtls backend.
--
--  The library is built MBEDTLS_NO_PLATFORM_ENTROPY and its pool is
--  fed by AHT.Mbedtls.Entropy.Poll, registered from
--  aht_mbedtls_entropy_new. That the wiring works at all is already
--  implied by every other TLS test passing -- with no platform source
--  and no working callback, mbedtls_ctr_drbg_seed fails and no
--  handshake happens. What that argument cannot show is *which* source
--  delivered, and "the DRBG got seeded somehow" is a weaker claim than
--  the one the build rests on.
--
--  So this observes the counters directly: a TLS connect must move
--  AHT.Random's accounting. Nothing in the mbedtls transport calls
--  AHT.Random itself, and a raw TLS_Transport draws no masks and no
--  handshake nonce, so any movement here came through the entropy
--  callback and nowhere else.
--
--  The openssl source of this test asserts the opposite on the same
--  operation -- that engine has its own RNG and must not reach
--  AHT.Random at all. The two together are what make either one
--  meaningful: the same connect, opposite expectations, both green.

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

   --  Snapshot rather than absolute values: the counters are
   --  process-global and this test does not own them.
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
