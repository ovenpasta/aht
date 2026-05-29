--  Smoke test for the mbedTLS bind/link chain. By calling
--  AHT.Mbedtls.Version.Full_Version_String we exercise:
--    * the Linker_Options pragmas in AHT.Mbedtls finding
--      libmbedtls / libmbedx509 / libmbedcrypto in
--      third_party/mbedtls-2.28.9/library/;
--    * the curated Import of mbedtls_version_get_string_full;
--    * the char_array <-> Ada String round-trip.
--
--  If this passes, the rest of the binding surface (ssl_*,
--  ctr_drbg_*, entropy_*, x509_*) can land in subsequent commits
--  with confidence that the build wiring is correct.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Mbedtls.Version;

procedure Test_Mbedtls_Version is
   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_mbedtls_version: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   Short : constant String := AHT.Mbedtls.Version.Version_String;
   Full  : constant String := AHT.Mbedtls.Version.Full_Version_String;
begin
   if Short /= "2.28.9" then
      Fail ("Version_String = """ & Short & """ (expected ""2.28.9"")");
   end if;
   if Full /= "Mbed TLS 2.28.9" then
      Fail ("Full_Version_String = """ & Full
            & """ (expected ""Mbed TLS 2.28.9"")");
   end if;
   if AHT.Mbedtls.Version.Major /= 2
     or else AHT.Mbedtls.Version.Minor /= 28
     or else AHT.Mbedtls.Version.Patch /= 9
   then
      Fail ("compile-time constants drifted from the linked library");
   end if;

   if Failures = 0 then
      Put_Line ("test_mbedtls_version: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_mbedtls_version:" & Failures'Image
                & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_Mbedtls_Version;
