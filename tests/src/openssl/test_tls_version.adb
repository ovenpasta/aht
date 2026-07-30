--  Smoke test for the OpenSSL bind/link chain (the openssl source of
--  the backend-neutral test_tls_version main), and the LibreSSL
--  tripwire: OPENSSL_version_major/minor/patch only exist since
--  OpenSSL 3.0, so linking this at all already excludes LibreSSL and
--  OpenSSL 1.1 — and the Major >= 3 assertion makes it explicit.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Openssl.Version;

procedure Test_TLS_Version is
   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_version: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   Banner : constant String := AHT.Openssl.Version.Version_String;
begin
   if AHT.Openssl.Version.Major < 3 then
      Fail ("linked library is not OpenSSL 3 (major ="
            & AHT.Openssl.Version.Major'Image & "; banner: """
            & Banner & """)");
   end if;
   if Banner'Length = 0 then
      Fail ("OpenSSL_version returned an empty banner");
   end if;

   if Failures = 0 then
      Put_Line ("test_tls_version: OK (" & Banner & ")");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_version:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Version;
