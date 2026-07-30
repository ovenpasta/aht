--  Truncation policy, openssl backend: an abrupt TCP close without
--  close_notify (tests/server/server_tls_abrupt.py, 127.0.0.1:8771)
--  must surface as TLS_Error, never as a clean EOF — AHT supports
--  EOF-framed HTTP bodies, so a silent truncation would be a data-
--  integrity hole. The mbedtls source of this test asserts that
--  backend's (documented) opposite behavior.

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
   Saw_Error : Boolean := False;
begin
   T.Connect ("127.0.0.1", Port, Insecure => True);
   begin
      loop
         T.Read (Buf, Last);
         if Last = 0 then
            Fail ("abrupt close read as clean EOF (Last = 0) — "
                  & "truncation must raise TLS_Error on this backend");
            exit;
         end if;
         Append (Acc, AHT.Bytes.To_String (Buf (1 .. Last)));
      end loop;
   exception
      when AHT.Transport.TLS.TLS_Error =>
         Saw_Error := True;  --  expected
      when E : others =>
         Fail ("expected TLS_Error, got "
               & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end;

   if Saw_Error
     and then Ada.Strings.Fixed.Index
       (To_String (Acc), "HELLO-THEN-TRUNCATE") = 0
   then
      Fail ("banner not received before the truncation error (got """
            & To_String (Acc) & """)");
   end if;

   begin
      T.Close;
   exception
      when others => null;
   end;

   if Failures = 0 then
      Put_Line ("test_tls_truncation: OK (truncation raises TLS_Error)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_truncation:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Truncation;
