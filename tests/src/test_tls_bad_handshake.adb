--  Handshake-path fault injection (backend-neutral), the counterpart
--  to test_tls_corrupt's post-handshake case.
--
--  Two cases, both served by tests/server/server_tls_badhandshake.py,
--  which HOLDS each connection open so that neither assertion can be
--  satisfied by an EOF the client didn't have to understand:
--
--    * 8774, an undefined record content type. Connect must fail
--      promptly with TLS_Error — a Timeout_Error would mean the
--      record was waited out rather than diagnosed.
--    * 8775, a record header dribbled in two pieces around a pause,
--      then silence. Connect must fail with Timeout_Error at roughly
--      the handshake deadline, NOT at deadline + pause, which is
--      where a per-read (rather than from-Connect) budget would land.
--
--  Both must leave Is_Connected False. The invalid-record case then
--  goes on to Connect the SAME object successfully, pinning that a
--  pre-session failure releases everything and does not set the
--  single-use latch; the dribble case shares that cleanup path, so it
--  only checks the failure itself and closes.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Real_Time; use Ada.Real_Time;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.Transport.TLS;
with AHT.URL;

procedure Test_TLS_Bad_Handshake is

   Bad_Port   : constant AHT.URL.Port_Number := 8774;
   Drib_Port  : constant AHT.URL.Port_Number := 8775;
   Good_Port  : constant AHT.URL.Port_Number := 8766;
   CA_File    : constant String := "tests/server/certs/server.crt";

   Deadline : constant Duration := 5.0;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_bad_handshake: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   T       : AHT.Transport.TLS.TLS_Transport;
   Started : Ada.Real_Time.Time;
   Elapsed : Duration := 0.0;
begin
   Started := Clock;
   begin
      T.Connect ("localhost", Bad_Port,
                 Insecure           => True,
                 Connect_Timeout    => Deadline,
                 Handshake_Deadline => Deadline);
      Fail ("Connect succeeded against a garbage handshake");
   exception
      when AHT.Transport.TLS.TLS_Error =>
         null;  --  expected: the record could not be made sense of
      when AHT.Transport.Timeout_Error =>
         Fail ("handshake deadline expired instead of diagnosing the "
               & "garbage record (waited it out rather than failing)");
      when E : others =>
         Fail ("expected TLS_Error, got "
               & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end;
   Elapsed := To_Duration (Clock - Started);

   --  Promptness: the record must have been DIAGNOSED, not waited
   --  out. The fixture holds the connection open precisely so this
   --  means something — with a close, an undiagnosed client would
   --  still fail fast on the EOF and this assertion would be vacuous.
   if Elapsed >= Deadline * 0.5 then
      Fail ("Connect took" & Elapsed'Image
            & " s — the invalid record looks waited out rather than"
            & " diagnosed");
   end if;

   if T.Is_Connected then
      Fail ("Is_Connected True after a failed handshake");
   end if;

   --  Retryability: nothing was established, so the object must be
   --  reusable — the same guarantee test_tls_retry pins for
   --  certificate failures, here for an unparsable peer.
   declare
      CRLF : constant String := ASCII.CR & ASCII.LF;
      Req  : constant AHT.Bytes.Byte_Array := AHT.Bytes.From_String
        ("GET /hello HTTP/1.1" & CRLF
         & "Host: localhost" & CRLF
         & "Connection: close" & CRLF & CRLF);
      Buf  : AHT.Bytes.Byte_Array (1 .. 4096);
      Last : Natural;
      Acc  : Unbounded_String;
   begin
      T.Connect ("localhost", Good_Port,
                 Insecure => False, CA_Path => CA_File);
      T.Write (Req);
      loop
         T.Read (Buf, Last);
         exit when Last = 0;
         Append (Acc, AHT.Bytes.To_String (Buf (1 .. Last)));
      end loop;
      if Ada.Strings.Fixed.Index (To_String (Acc), "hello, world") = 0
      then
         Fail ("retry after a bad handshake: body missing");
      end if;
   exception
      when E : others =>
         Fail ("retry after a bad handshake failed — "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E));
   end;

   begin
      T.Close;
   exception
      when others => null;
   end;

   --  Case 2: a DRIBBLED record header — part of it, a pause, one
   --  more byte, then silence. Distinct from the stall fixture, which
   --  sends nothing at all: here the engine has consumed bytes and is
   --  waiting for the rest of a record. The handshake deadline must
   --  still fire, and — the property worth pinning — the bytes that
   --  arrive mid-wait must NOT refresh it, because it is a budget
   --  measured from Connect rather than per read.
   declare
      T2      : AHT.Transport.TLS.TLS_Transport;
      --  The fixture pauses this long between its two dribbles.
      Pause   : constant Duration := 3.0;
      Started : constant Ada.Real_Time.Time := Clock;
      Took    : Duration := 0.0;
   begin
      begin
         T2.Connect ("localhost", Drib_Port,
                     Insecure           => True,
                     Connect_Timeout    => Deadline,
                     Handshake_Deadline => Deadline);
         Fail ("dribble: Connect succeeded on a partial record");
      exception
         when AHT.Transport.Timeout_Error =>
            null;  --  expected: the budget ran out waiting for the rest
         when E : others =>
            Fail ("dribble: expected Timeout_Error, got "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E));
      end;
      Took := To_Duration (Clock - Started);

      --  The discriminating assertion. The fixture dribbles a byte,
      --  pauses, dribbles another, then goes silent:
      --    * a budget measured from Connect expires at ~Deadline;
      --    * a budget restarted on each read would expire at
      --      ~Deadline + Pause.
      --  Those are far enough apart to tell apart, which is the whole
      --  reason the fixture pauses rather than sending everything at
      --  once.
      if Took < Deadline - 1.0 then
         Fail ("dribble: gave up after" & Took'Image
               & " s, well short of the" & Deadline'Image & " s budget");
      elsif Took > Deadline + Pause * 0.5 then
         Fail ("dribble: took" & Took'Image
               & " s — expected ~" & Deadline'Image
               & " s; a deadline refreshed by the dribbled byte would"
               & " land near" & Duration'Image (Deadline + Pause) & " s");
      end if;

      if T2.Is_Connected then
         Fail ("dribble: Is_Connected True after a failed handshake");
      end if;

      begin
         T2.Close;
      exception
         when others => null;
      end;
   end;

   if Failures = 0 then
      Put_Line ("test_tls_bad_handshake: OK (invalid record"
                & " diagnosed in" & Elapsed'Image
                & " s, dribbled header bounded by the handshake"
                & " budget, object still reusable)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_bad_handshake:" & Failures'Image
                & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Bad_Handshake;
