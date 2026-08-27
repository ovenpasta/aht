--  IP-literal certificate identity, openssl backend: connecting to
--  https://127.0.0.1:8766 with the fixture CA must verify via the
--  cert's IP:127.0.0.1 SAN (X509_VERIFY_PARAM_set1_ip_asc; no SNI is
--  sent for IP literals). The DNS-name path stays covered by test_tls
--  ("localhost"). The mbedtls source of this test asserts the same
--  property: both backends match iPAddress SANs.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
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

   T    : AHT.Transport.TLS.TLS_Transport;
begin
   begin
      T.Connect ("127.0.0.1", Port, Insecure => False,
                 CA_Path => CA_File);
      declare
         CRLF : constant String := ASCII.CR & ASCII.LF;
         Req  : constant AHT.Bytes.Byte_Array := AHT.Bytes.From_String
           ("GET /hello HTTP/1.1" & CRLF
            & "Host: 127.0.0.1" & CRLF
            & "Connection: close" & CRLF & CRLF);
         Buf  : AHT.Bytes.Byte_Array (1 .. 4096);
         Last : Natural;
         Acc  : Unbounded_String;
      begin
         T.Write (Req);
         loop
            T.Read (Buf, Last);
            exit when Last = 0;
            Append (Acc, AHT.Bytes.To_String (Buf (1 .. Last)));
         end loop;
         if Ada.Strings.Fixed.Index
             (To_String (Acc), "hello, world") = 0
         then
            Fail ("body missing after IP-SAN verified connect");
         end if;
      end;
   exception
      when E : others =>
         Fail ("IP-SAN verify connect failed — "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E));
   end;

   begin
      T.Close;
   exception
      when others => null;
   end;

   if Failures = 0 then
      Put_Line ("test_tls_ip_host: OK (IP-SAN verification)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_ip_host:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_IP_Host;
