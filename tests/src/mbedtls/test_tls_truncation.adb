--  Truncation policy, mbedtls backend: an abrupt TCP close without
--  close_notify (tests/server/server_tls_abrupt.py, 127.0.0.1:8771)
--  reads as a clean EOF (Last = 0) on this backend — the documented
--  difference from the openssl backend, which raises TLS_Error. This
--  test pins the behavior down so a change is deliberate, not
--  accidental.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.Transport.TLS;
with AHT.URL;

procedure Test_TLS_Truncation is

   Port : constant AHT.URL.Port_Number := 8771;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_truncation: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   T    : AHT.Transport.TLS.TLS_Transport;
   Buf  : AHT.Bytes.Byte_Array (1 .. 4096);
   Last : Natural;
   Acc  : Unbounded_String;
begin
   T.Connect ("127.0.0.1", Port, Insecure => True);
   begin
      loop
         T.Read (Buf, Last);
         exit when Last = 0;  --  expected: abrupt EOF reads clean here
         Append (Acc, AHT.Bytes.To_String (Buf (1 .. Last)));
      end loop;
   exception
      when E : others =>
         Fail ("expected clean EOF on this backend, got "
               & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end;

   if Ada.Strings.Fixed.Index
       (To_String (Acc), "HELLO-THEN-TRUNCATE") = 0
   then
      Fail ("banner not received before EOF (got """
            & To_String (Acc) & """)");
   end if;

   begin
      T.Close;
   exception
      when others => null;
   end;

   if Failures = 0 then
      Put_Line ("test_tls_truncation: OK (abrupt EOF reads clean; "
                & "documented mbedtls-backend behavior)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_truncation:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Truncation;
