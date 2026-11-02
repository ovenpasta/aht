--  Copyright (C) 2026 Contributors to AHT
--  SPDX-License-Identifier: Apache-2.0

--  TLS.Try_Read and TLS.Abortive_Close, both backends. Each Try_Read
--  must return promptly; the bound below is generous so a loaded
--  runner cannot fail it, while a call that parks on the socket or a
--  deadline would exceed it by orders of magnitude.
--
--  Cases:
--    1. a silent peer (server_tls_deaf.py, 8769): Would_Block at once,
--       repeatedly; Abortive_Close is prompt and idempotent and a
--       later Try_Read is rejected as closed
--    2. a record split across two TCP sends, the second gated on a
--       byte from us (server_tls_fragment.py, 8778): Would_Block while
--       only the first half is buffered, Data_Ready with the whole
--       banner once the rest arrives, then Peer_Closed for the peer's
--       close_notify, repeated on the next call
--    3. a TCP close without close_notify (server_tls_abrupt.py, 8771):
--       the banner, then TLS_Error, never Peer_Closed, on both
--       backends; the session is poisoned; Abortive_Close still works
--    4. Try_Read alongside the blocking Write and the graceful Close
--       on the HTTPS fixture (server_tls.py, 8766)
--    5. Abortive_Close on a never-connected object

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Real_Time; use Ada.Real_Time;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.Transport;
with AHT.Transport.TLS;
with AHT.URL;

procedure Test_TLS_Try_Read is

   use AHT.Transport.TLS;

   Deaf_Port     : constant AHT.URL.Port_Number := 8769;
   Fragment_Port : constant AHT.URL.Port_Number := 8778;
   Abrupt_Port   : constant AHT.URL.Port_Number := 8771;
   HTTPS_Port    : constant AHT.URL.Port_Number := 8766;

   Call_Bound : constant Time_Span := Milliseconds (500);
   --  Upper bound for one Try_Read or Abortive_Close.
   Settle     : constant Time_Span := Milliseconds (300);
   --  How long case 2 polls with only the first fragment on the wire.
   Patience   : constant Time_Span := Seconds (5);
   --  How long a poll loop may wait for the peer.
   Poll_Gap   : constant Duration := 0.005;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_try_read: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function Contains (Haystack, Needle : String) return Boolean is
     (Ada.Strings.Fixed.Index (Haystack, Needle) /= 0);

   --  One Try_Read, timed against Call_Bound.
   procedure Timed_Try_Read
     (T      : in out TLS_Transport;
      Data   : out AHT.Bytes.Byte_Array;
      Last   : out Natural;
      Status : out Try_Read_Status;
      Where  : String)
   is
      Started : constant Time := Clock;
   begin
      T.Try_Read (Data, Last, Status);
      if Clock - Started > Call_Bound then
         Fail (Where & ": Try_Read took "
               & Duration'Image (To_Duration (Clock - Started)) & " s");
      end if;
   end Timed_Try_Read;

   --  Poll until Try_Read reports something other than Would_Block or
   --  Patience runs out (then Status is Would_Block and Timed_Out).
   procedure Poll
     (T         : in out TLS_Transport;
      Data      : out AHT.Bytes.Byte_Array;
      Last      : out Natural;
      Status    : out Try_Read_Status;
      Timed_Out : out Boolean;
      Where     : String)
   is
      Give_Up : constant Time := Clock + Patience;
   begin
      Timed_Out := False;
      loop
         Timed_Try_Read (T, Data, Last, Status, Where);
         exit when Status /= Would_Block;
         if Clock > Give_Up then
            Timed_Out := True;
            exit;
         end if;
         delay Poll_Gap;
      end loop;
   end Poll;

   procedure Timed_Abortive_Close
     (T : in out TLS_Transport; Where : String)
   is
      Started : constant Time := Clock;
   begin
      T.Abortive_Close;
      if Clock - Started > Call_Bound then
         Fail (Where & ": Abortive_Close took "
               & Duration'Image (To_Duration (Clock - Started)) & " s");
      end if;
      if T.Is_Connected then
         Fail (Where & ": Is_Connected after Abortive_Close");
      end if;
   exception
      when E : others =>
         Fail (Where & ": Abortive_Close raised "
               & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end Timed_Abortive_Close;

   Buf       : AHT.Bytes.Byte_Array (1 .. 4096);
   Last      : Natural;
   Status    : Try_Read_Status;
   Timed_Out : Boolean;

begin
   --  Case 1: silent peer. Nothing arrives after the handshake, so
   --  every call is Would_Block and none of them may park.
   declare
      T : TLS_Transport;
   begin
      T.Connect ("127.0.0.1", Deaf_Port, Insecure => True);
      for I in 1 .. 20 loop
         Timed_Try_Read (T, Buf, Last, Status, "deaf");
         if Status /= Would_Block or else Last /= 0 then
            Fail ("deaf: expected Would_Block/0, got "
                  & Status'Image & Last'Image);
            exit;
         end if;
      end loop;
      declare
         Empty : AHT.Bytes.Byte_Array (1 .. 0);
      begin
         Timed_Try_Read (T, Empty, Last, Status, "deaf/empty");
         if Status /= Would_Block or else Last /= 0 then
            Fail ("deaf: empty Data must be Would_Block/0");
         end if;
      end;
      Timed_Abortive_Close (T, "deaf");
      Timed_Abortive_Close (T, "deaf (second)");
      begin
         T.Try_Read (Buf, Last, Status);
         Fail ("deaf: Try_Read after Abortive_Close returned "
               & Status'Image);
      exception
         when AHT.Transport.Transport_Error => null;  --  expected
         when E : others =>
            Fail ("deaf: Try_Read after Abortive_Close raised "
                  & Ada.Exceptions.Exception_Name (E));
      end;
      T.Close;  --  a no-op after Abortive_Close
   exception
      when E : others =>
         Fail ("deaf: " & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end;

   --  Case 2: fragmented record. The fixture holds the second half of
   --  the record until we send a byte, so during Settle the engine
   --  holds an incomplete record and must report Would_Block, not
   --  data and not an error; once we release the rest, the record
   --  completes from the buffered half and the new bytes.
   declare
      T    : TLS_Transport;
      Till : Time;
   begin
      T.Connect ("127.0.0.1", Fragment_Port, Insecure => True);
      Till := Clock + Settle;
      loop
         Timed_Try_Read (T, Buf, Last, Status, "fragment/half");
         if Status /= Would_Block then
            Fail ("fragment: " & Status'Image
                  & " with only the first half of the record sent");
            exit;
         end if;
         exit when Clock > Till;
         delay Poll_Gap;
      end loop;

      T.Write ([1 => 65]);
      Poll (T, Buf, Last, Status, Timed_Out, "fragment/rest");
      if Timed_Out then
         Fail ("fragment: no data within Patience after releasing the rest");
      elsif Status /= Data_Ready then
         Fail ("fragment: expected Data_Ready, got " & Status'Image);
      elsif AHT.Bytes.To_String (Buf (1 .. Last))
        /= "FRAGMENTED-RECORD-BANNER"
      then
         Fail ("fragment: banner mangled — """
               & AHT.Bytes.To_String (Buf (1 .. Last)) & """");
      end if;

      Poll (T, Buf, Last, Status, Timed_Out, "fragment/close");
      if Timed_Out then
         Fail ("fragment: no close_notify within Patience");
      elsif Status /= Peer_Closed or else Last /= 0 then
         Fail ("fragment: expected Peer_Closed/0, got "
               & Status'Image & Last'Image);
      else
         Timed_Try_Read (T, Buf, Last, Status, "fragment/again");
         if Status /= Peer_Closed then
            Fail ("fragment: Peer_Closed not repeated, got "
                  & Status'Image);
         end if;
      end if;
      T.Close;
   exception
      when E : others =>
         Fail ("fragment: " & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end;
   --  Case 2b: Read consumes close_notify; Try_Read must remember it.
   declare
      T : TLS_Transport;
   begin
      T.Connect ("127.0.0.1", Fragment_Port, Insecure => True);
      T.Set_Read_Deadline (To_Duration (Patience));
      T.Write ([1 => 65]);
      T.Read (Buf, Last);
      if AHT.Bytes.To_String (Buf (1 .. Last)) /= "FRAGMENTED-RECORD-BANNER"
      then
         Fail ("read-then-try: banner mangled — """
               & AHT.Bytes.To_String (Buf (1 .. Last)) & """");
      end if;
      T.Read (Buf, Last);
      if Last /= 0 then
         Fail ("read-then-try: expected Last = 0 for close_notify, got"
               & Last'Image);
      end if;
      for I in 1 .. 2 loop
         Timed_Try_Read (T, Buf, Last, Status, "read-then-try");
         if Status /= Peer_Closed or else Last /= 0 then
            Fail ("read-then-try: expected Peer_Closed/0, got "
                  & Status'Image & Last'Image);
         end if;
      end loop;
      T.Close;
   exception
      when E : others =>
         Fail ("read-then-try: " & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end;

   --  Case 3: TCP close without close_notify. The banner arrives,
   --  then the stream ends; that end must be TLS_Error on both
   --  backends (the mbedtls blocking Read reads it as clean EOF, the
   --  documented difference; Try_Read does not).
   declare
      T   : TLS_Transport;
      Acc : Unbounded_String;
   begin
      T.Connect ("127.0.0.1", Abrupt_Port, Insecure => True);
      begin
         loop
            Poll (T, Buf, Last, Status, Timed_Out, "abrupt");
            if Timed_Out then
               Fail ("abrupt: stream end not seen within Patience");
               exit;
            end if;
            case Status is
               when Data_Ready =>
                  Append (Acc, AHT.Bytes.To_String (Buf (1 .. Last)));
               when Peer_Closed =>
                  Fail ("abrupt: TCP EOF reported as Peer_Closed");
                  exit;
               when Would_Block =>
                  null;
            end case;
         end loop;
      exception
         when TLS_Error =>
            if not Contains (To_String (Acc), "HELLO-THEN-TRUNCATE") then
               Fail ("abrupt: banner missing before the error — """
                     & To_String (Acc) & """");
            end if;
            if T.Is_Connected then
               Fail ("abrupt: Is_Connected after the truncation error");
            end if;
         when E : others =>
            Fail ("abrupt: expected TLS_Error, got "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E));
      end;
      Timed_Abortive_Close (T, "abrupt");
      Timed_Abortive_Close (T, "abrupt (second)");
   exception
      when E : others =>
         Fail ("abrupt: " & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end;

   --  Case 4: the blocking Write, Try_Read and the graceful Close on
   --  one session. The fixture answers Connection: close with a
   --  close_notify, so the poll ends in Peer_Closed.
   declare
      T    : TLS_Transport;
      CRLF : constant String := ASCII.CR & ASCII.LF;
      Acc  : Unbounded_String;
   begin
      T.Connect ("localhost", HTTPS_Port, Insecure => False,
                 CA_Path => "tests/server/certs/server.crt");
      T.Write (AHT.Bytes.From_String
        ("GET /hello HTTP/1.1" & CRLF
         & "Host: localhost" & CRLF
         & "Connection: close" & CRLF & CRLF));
      loop
         Poll (T, Buf, Last, Status, Timed_Out, "https");
         if Timed_Out then
            Fail ("https: response not completed within Patience");
            exit;
         end if;
         exit when Status = Peer_Closed;
         Append (Acc, AHT.Bytes.To_String (Buf (1 .. Last)));
      end loop;
      if not Contains (To_String (Acc), "200")
        or else not Contains (To_String (Acc), "hello, world")
      then
         Fail ("https: bad response — """ & To_String (Acc) & """");
      end if;
      T.Close;
      if T.Is_Connected then
         Fail ("https: Is_Connected after Close");
      end if;
   exception
      when E : others =>
         Fail ("https: " & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end;

   --  Case 5: never connected.
   declare
      T : TLS_Transport;
   begin
      Timed_Abortive_Close (T, "unconnected");
      Timed_Abortive_Close (T, "unconnected (second)");
   end;

   if Failures = 0 then
      Put_Line ("test_tls_try_read: OK (would-block, fragment, "
                & "truncation, mixed, abortive close)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_try_read:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Try_Read;
