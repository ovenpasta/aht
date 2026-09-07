--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Smoke test for the mbedTLS bind/link chain, the mbedtls source of the
--  backend-neutral test_tls_version main. Calling
--  AHT.Mbedtls.Version.Full_Version_String exercises the Linker_Options
--  pragmas in AHT.Mbedtls, the curated Import of
--  mbedtls_version_get_string_full, and the char_array round-trip.
--
--  Cases:
--    - Version_String, Full_Version_String and Major/Minor/Patch match
--      the literals below
--
--  Covers:
--    - a disagreement between aht.gpr's Mbedtls_Tree and VERSION in
--      scripts/fetch_mbedtls.sh, which name one tree twice with nothing
--      reconciling them; the literals are spelled out, not derived from
--      the build, so they can disagree with the linked library's answer
--    - if this passes, the rest of the binding surface (ssl_*,
--      ctr_drbg_*, entropy_*, x509_*) is wired

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Mbedtls.Version;

procedure Test_TLS_Version is
   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_version: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   Short : constant String := AHT.Mbedtls.Version.Version_String;
   Full  : constant String := AHT.Mbedtls.Version.Full_Version_String;
begin
   if Short /= "3.6.7" then
      Fail ("Version_String = """ & Short & """ (expected ""3.6.7"")");
   end if;
   if Full /= "Mbed TLS 3.6.7" then
      Fail ("Full_Version_String = """ & Full
            & """ (expected ""Mbed TLS 3.6.7"")");
   end if;
   if AHT.Mbedtls.Version.Major /= 3
     or else AHT.Mbedtls.Version.Minor /= 6
     or else AHT.Mbedtls.Version.Patch /= 7
   then
      Fail ("compile-time constants drifted from the linked library");
   end if;

   if Failures = 0 then
      Put_Line ("test_tls_version: OK (mbedtls backend)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_version:" & Failures'Image
                & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Version;
