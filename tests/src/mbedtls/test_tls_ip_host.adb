--  IP-literal certificate identity, mbedtls backend: mbedTLS 2.28
--  matches the expected name against dNSName SANs and the CN only —
--  it does NOT match iPAddress SANs — so verifying a connection to
--  "127.0.0.1" fails even though the fixture cert carries
--  IP:127.0.0.1. This test pins that documented limitation (the
--  openssl source of this test asserts the verification succeeds);
--  Insecure connects to the same endpoint must still work.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Transport.TLS;
with AHT.URL;

procedure Test_TLS_IP_Host is

   Port    : constant AHT.URL.Port_Number := 8766;
   CA_File : constant String := "tests/server/certs/server.crt";

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_ip_host: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

begin
   --  Verified connect to the IP literal: expected to be REJECTED on
   --  this backend (no iPAddress-SAN matching in mbedTLS 2.28).
   declare
      T : AHT.Transport.TLS.TLS_Transport;
   begin
      begin
         T.Connect ("127.0.0.1", Port, Insecure => False,
                    CA_Path => CA_File);
         Fail ("IP-host verification unexpectedly succeeded "
               & "(mbedTLS 2.28 has no IP-SAN matching — did the "
               & "backend change?)");
      exception
         when AHT.Transport.TLS.TLS_Error =>
            null;  --  expected
         when E : others =>
            Fail ("expected TLS_Error, got "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E));
      end;
      begin
         T.Close;
      exception
         when others => null;
      end;
   end;

   --  Insecure connect to the same endpoint must work.
   declare
      T : AHT.Transport.TLS.TLS_Transport;
   begin
      begin
         T.Connect ("127.0.0.1", Port, Insecure => True);
         if not T.Is_Connected then
            Fail ("insecure IP connect: not connected");
         end if;
      exception
         when E : others =>
            Fail ("insecure IP connect failed — "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
      end;
      begin
         T.Close;
      exception
         when others => null;
      end;
   end;

   if Failures = 0 then
      Put_Line ("test_tls_ip_host: OK (IP-SAN verify rejected; "
                & "documented mbedtls-backend limitation)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_ip_host:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_IP_Host;
