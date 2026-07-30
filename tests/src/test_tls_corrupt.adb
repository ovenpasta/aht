--  Integrity-failure fail-closed check (backend-neutral).
--
--  Against tests/server/server_tls_corrupt.py (127.0.0.1:8773), which
--  sends a valid banner and then injects a record whose MAC cannot
--  verify: Read must raise TLS_Error, AND the transport must stop
--  reporting Is_Connected. Regression test — the mbedtls engine used
--  to latch its internal Engine_Dead flag on a fatal read without
--  latching the coordinator's Fatal (what Is_Connected reads) or
--  poisoning the socket, so a session killed by a bad record MAC kept
--  claiming it was connected and a retry would have written onto a
--  stream whose integrity had already failed.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.Transport.TLS;
with AHT.URL;

procedure Test_TLS_Corrupt is

   Port : constant AHT.URL.Port_Number := 8773;

   --  Generous: recognising a bad MAC is immediate, so this only ever
   --  bounds a failure.
   Read_Budget : constant Duration := 10.0;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_corrupt: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   T         : AHT.Transport.TLS.TLS_Transport;
   Buf       : AHT.Bytes.Byte_Array (1 .. 4096);
   Last      : Natural;
   Saw_Error : Boolean := False;
begin
   T.Connect ("127.0.0.1", Port, Insecure => True);

   --  Bound the read. The fixture deliberately HOLDS the connection
   --  open after injecting the bad record, so a client that failed to
   --  recognise the corruption would block forever and hang the whole
   --  suite rather than failing this test.
   T.Set_Read_Deadline (Read_Budget);

   --  Read until the corrupted record surfaces. The banner arrives
   --  first and must read normally; the next record must fail.
   begin
      loop
         T.Read (Buf, Last);
         if Last = 0 then
            Fail ("clean EOF instead of an integrity failure");
            exit;
         end if;
      end loop;
   exception
      when AHT.Transport.TLS.TLS_Error =>
         Saw_Error := True;   --  expected: MAC / decrypt failure
      when AHT.Transport.Timeout_Error =>
         Fail ("read deadline expired — the corrupted record was"
               & " never recognised (the fixture holds the connection"
               & " open, so nothing else would end the read)");
      when E : others =>
         Fail ("expected TLS_Error, got "
               & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end;

   --  The point of the test: the failure must be fail-closed.
   if Saw_Error and then T.Is_Connected then
      Fail ("Is_Connected still True after an integrity failure "
            & "(session must be poisoned, not reusable)");
   end if;

   --  And a subsequent operation must refuse rather than write onto
   --  the compromised stream.
   if Saw_Error then
      begin
         T.Write (AHT.Bytes.From_String ("must not reach the wire"));
         Fail ("Write succeeded on a poisoned session");
      exception
         when AHT.Transport.Transport_Error
            | AHT.Transport.TLS.TLS_Error =>
            null;  --  expected
         when E : others =>
            Fail ("Write after failure raised unexpected "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E));
      end;
   end if;

   begin
      T.Close;
   exception
      when others => null;
   end;

   if Failures = 0 then
      Put_Line ("test_tls_corrupt: OK (integrity failure fails closed)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_corrupt:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Corrupt;
