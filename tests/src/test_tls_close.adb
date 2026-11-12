--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  TLS Close delivers close_notify to a peer that is reading, on both
--  backends. Against server_tls_closewatch.py (8778): one connection
--  WATCHes a token and is closed with Close; a second connection
--  QUERYs how the fixture saw that stream end. The fixture records
--  "eof" for a TCP EOF without close_notify, so a Close that dropped
--  close_notify fails here rather than passing silently.
--
--  Not covered: a Close against a peer that has stopped reading. That
--  needs a live session with a full send buffer, which the public API
--  reaches only through kernel buffer sizing; Close's bound there
--  rests on TCP.Try_Write never parking, checked in test_tcp.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.Transport.TLS;
with AHT.URL;

procedure Test_TLS_Close is

   use AHT.Transport.TLS;

   Port          : constant AHT.URL.Port_Number := 8778;
   Answer_Budget : constant Duration := 10.0;
   --  Read deadline for each exchange; a liveness backstop only.

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_close: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Send one command line and return the fixture's one-line answer.
   function Exchange
     (T : in out TLS_Transport; Line : String) return String
   is
      Buf  : AHT.Bytes.Byte_Array (1 .. 256);
      Last : Natural;
      Acc  : Unbounded_String;
   begin
      T.Write (AHT.Bytes.From_String (Line & ASCII.LF));
      while Ada.Strings.Fixed.Index (To_String (Acc), [1 => ASCII.LF]) = 0
      loop
         T.Read (Buf, Last);
         exit when Last = 0;
         Append (Acc, AHT.Bytes.To_String (Buf (1 .. Last)));
      end loop;
      declare
         S  : constant String := To_String (Acc);
         LF : constant Natural :=
           Ada.Strings.Fixed.Index (S, [1 => ASCII.LF]);
      begin
         return (if LF = 0 then S else S (S'First .. LF - 1));
      end;
   end Exchange;

   procedure Check_Close (Token : String) is
   begin
      declare
         T : TLS_Transport;
      begin
         T.Connect ("127.0.0.1", Port, Insecure => True);
         T.Set_Read_Deadline (Answer_Budget);
         declare
            Answer : constant String := Exchange (T, "WATCH " & Token);
         begin
            if Answer /= "OK" then
               Fail (Token & ": WATCH answered """ & Answer & """");
            end if;
         end;
         T.Close;
      end;

      declare
         T : TLS_Transport;
      begin
         T.Connect ("127.0.0.1", Port, Insecure => True);
         T.Set_Read_Deadline (Answer_Budget);
         declare
            Answer : constant String := Exchange (T, "QUERY " & Token);
         begin
            if Answer /= "close_notify" then
               Fail (Token & ": the fixture saw the stream end as """
                     & Answer & """, not close_notify");
            end if;
         end;
         T.Close;
      end;
   exception
      when E : others =>
         Fail (Token & ": " & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end Check_Close;

begin
   Check_Close ("graceful");

   --  The QUERY answer comes from what the fixture recorded, not a
   --  default: a token nothing WATCHed reads "none".
   declare
      T : TLS_Transport;
   begin
      T.Connect ("127.0.0.1", Port, Insecure => True);
      T.Set_Read_Deadline (Answer_Budget);
      declare
         Answer : constant String := Exchange (T, "QUERY unwatched");
      begin
         if Answer /= "none" then
            Fail ("unwatched: QUERY answered """ & Answer & """");
         end if;
      end;
      T.Close;
   exception
      when E : others =>
         Fail ("unwatched: " & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end;

   if Failures = 0 then
      Put_Line ("test_tls_close: OK (close_notify delivered)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_close:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Close;
