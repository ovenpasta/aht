--  Mid-session corruption under concurrency (backend-neutral).
--
--  test_tls_corrupt proves a corrupted record fails closed on a single
--  task. This proves it does so in the production topology — one
--  reader task and one writer task on ONE session — which is the case
--  that crosses the engines' coordinator, and so the one where the two
--  backends could plausibly diverge.
--
--  Against tests/server/server_tls_concurrent.py (127.0.0.1:8776),
--  which sends a banner, waits for a payload from our WRITER, emits
--  an overlap marker, injects a record whose MAC cannot verify, and
--  then keeps draining (so backpressure never stalls the writer)
--  while holding the connection open:
--
--    * the reader must raise TLS_Error;
--    * the read stream must contain the overlap marker, which the
--      fixture emits only after receiving writer traffic — so the
--      concurrency is asserted rather than assumed from a sleep, and
--      a run where the writer never got going cannot pass;
--    * the writer must not hang, and must eventually observe the
--      poisoned session — by a session-death exception specifically,
--      since a timeout or a Constraint_Error would say nothing about
--      poisoning;
--    * Is_Connected must become False;
--    * operations STARTED after poisoning must fail.
--
--  Deliberately NOT required: that any particular write fails. A write
--  already in flight may linearize before the fatal latch and succeed;
--  demanding otherwise would make this test race-dependent. Every
--  operation and the task join are bounded, so a failure to notice the
--  poisoning shows up as a test failure, never as a hung suite.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Real_Time; use Ada.Real_Time;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.Transport.TLS;
with AHT.URL;

procedure Test_TLS_Concurrent_Corrupt is

   Port : constant AHT.URL.Port_Number := 8776;

   --  Budgets. Generous: they only ever bound a failure, since the
   --  fixture corrupts within a second.
   Read_Budget  : constant Duration := 15.0;
   Write_Budget : constant Duration := 15.0;
   --  The writer's own give-up bound, so the task terminates (and the
   --  join completes) even if it somehow never observes the poisoning.
   Writer_Bound : constant Duration := 20.0;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tls_concurrent_corrupt: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   T : AHT.Transport.TLS.TLS_Transport;

   --  What became of the writer task. It runs concurrently with the
   --  main task, so it reports through a protected object rather than
   --  touching Failures.
   protected Writer_Result is
      procedure Note_Poisoned (Name, Message : String);
      procedure Note_Unexpected (Name, Message : String);
      procedure Note_Gave_Up;
      function Saw_Poisoning return Boolean;
      function Saw_Unexpected return Boolean;
      function Gave_Up return Boolean;
      function Detail return String;
      procedure Count_Write;
      function Writes return Natural;
   private
      Poisoned    : Boolean := False;
      Unexpected  : Boolean := False;
      Bound_Hit   : Boolean := False;
      Text        : Unbounded_String;
      Write_Count : Natural := 0;
   end Writer_Result;

   protected body Writer_Result is
      procedure Note_Poisoned (Name, Message : String) is
      begin
         Poisoned := True;
         Text := To_Unbounded_String (Name & ": " & Message);
      end Note_Poisoned;
      procedure Note_Unexpected (Name, Message : String) is
      begin
         Unexpected := True;
         Text := To_Unbounded_String (Name & ": " & Message);
      end Note_Unexpected;
      procedure Note_Gave_Up is
      begin
         Bound_Hit := True;
      end Note_Gave_Up;
      function Saw_Poisoning return Boolean is (Poisoned);
      function Saw_Unexpected return Boolean is (Unexpected);
      function Gave_Up return Boolean is (Bound_Hit);
      function Detail return String is (To_String (Text));
      procedure Count_Write is
      begin
         Write_Count := Write_Count + 1;
      end Count_Write;
      function Writes return Natural is (Write_Count);
   end Writer_Result;

   Reader_Saw_Error : Boolean := False;
   Received         : Unbounded_String;

   --  The fixture emits this only AFTER it has received a payload from
   --  our writer, so finding it in the read stream is positive proof
   --  that reader and writer really did overlap on this session.
   Overlap_Marker : constant String := "OVERLAP-CONFIRMED";

begin
   T.Connect ("127.0.0.1", Port, Insecure => True);
   T.Set_Read_Deadline (Read_Budget);
   T.Set_Write_Deadline (Write_Budget);

   declare
      --  The writer runs until it observes a failure or hits its own
      --  bound; either way it terminates, so the join below is
      --  bounded and the suite cannot hang here.
      task Writer;

      task body Writer is
         Chunk : constant AHT.Bytes.Byte_Array (1 .. 256) :=
           [others => 16#41#];
         Give_Up : constant Ada.Real_Time.Time :=
           Clock + To_Time_Span (Writer_Bound);
      begin
         while Clock < Give_Up loop
            T.Write (Chunk);
            Writer_Result.Count_Write;
            delay 0.02;
         end loop;
         --  Ran the whole bound without a single write failing: the
         --  poisoning was never observed on this side.
         Writer_Result.Note_Gave_Up;
      exception
         when E : AHT.Transport.Transport_Error
                | AHT.Transport.TLS.TLS_Error =>
            --  Expected outcome: some write after the fatal latch is
            --  refused. WHICH one is racy and deliberately unchecked.
            Writer_Result.Note_Poisoned
              (Ada.Exceptions.Exception_Name (E),
               Ada.Exceptions.Exception_Message (E));
         when E : others =>
            --  Anything else — a timeout, an abort, Constraint_Error,
            --  a fixture mishap — is NOT evidence that the session was
            --  poisoned, and must not be allowed to satisfy the test.
            Writer_Result.Note_Unexpected
              (Ada.Exceptions.Exception_Name (E),
               Ada.Exceptions.Exception_Message (E));
      end Writer;

      Buf  : AHT.Bytes.Byte_Array (1 .. 4096);
      Last : Natural;
   begin
      --  Reader: consume the valid records, then meet the corrupted
      --  one. Bounded by Read_Budget.
      begin
         loop
            T.Read (Buf, Last);
            if Last = 0 then
               Fail ("reader: clean EOF instead of an integrity failure");
               exit;
            end if;
            Append (Received, AHT.Bytes.To_String (Buf (1 .. Last)));
         end loop;
      exception
         when AHT.Transport.TLS.TLS_Error =>
            Reader_Saw_Error := True;   --  expected
         when AHT.Transport.Timeout_Error =>
            Fail ("reader: read deadline expired — the corrupted record"
                  & " was never recognised (the fixture holds the"
                  & " connection open, so nothing else ends the read)");
         when E : others =>
            Fail ("reader: expected TLS_Error, got "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E));
      end;
   end;  --  joins Writer (bounded by Writer_Bound)

   if not Reader_Saw_Error then
      Fail ("reader never saw TLS_Error");
   end if;

   --  Overlap is asserted, not assumed: the marker exists only
   --  because the fixture received writer traffic before corrupting.
   if Ada.Strings.Fixed.Index (To_String (Received), Overlap_Marker) = 0
   then
      Fail ("marker " & Overlap_Marker & " absent from the read stream"
            & " — the fixture never saw writer traffic, so reader and"
            & " writer did not actually overlap ("
            & Writer_Result.Writes'Image & " writes counted)");
   end if;

   --  The writer must have noticed, and must not have needed its own
   --  give-up bound to stop.
   if Writer_Result.Gave_Up then
      Fail ("writer ran its full" & Writer_Bound'Image
            & " s bound without ever observing the poisoned session"
            & " (" & Writer_Result.Writes'Image & " writes succeeded)");
   elsif Writer_Result.Saw_Unexpected then
      Fail ("writer failed, but not with a session-death exception: "
            & Writer_Result.Detail
            & " — that is not evidence of poisoning");
   elsif not Writer_Result.Saw_Poisoning then
      Fail ("writer terminated without observing the poisoned session");
   end if;

   if T.Is_Connected then
      Fail ("Is_Connected True after a concurrent integrity failure");
   end if;

   --  Operations STARTED after poisoning must fail — the in-flight
   --  allowance above does not extend to fresh calls.
   begin
      T.Write (AHT.Bytes.From_String ("must not reach the wire"));
      Fail ("Write started after poisoning succeeded");
   exception
      when AHT.Transport.Transport_Error
         | AHT.Transport.TLS.TLS_Error =>
         null;  --  expected
      when E : others =>
         Fail ("post-poison Write raised unexpected "
               & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end;

   declare
      Buf  : AHT.Bytes.Byte_Array (1 .. 256);
      Last : Natural;
   begin
      T.Read (Buf, Last);
      Fail ("Read started after poisoning succeeded (Last ="
            & Last'Image & ")");
   exception
      when AHT.Transport.Transport_Error
         | AHT.Transport.TLS.TLS_Error =>
         null;  --  expected
      when E : others =>
         Fail ("post-poison Read raised unexpected "
               & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end;

   begin
      T.Close;
   exception
      when others => null;
   end;

   if Failures = 0 then
      Put_Line ("test_tls_concurrent_corrupt: OK (reader raised, writer"
                & " observed the poisoning after"
                & Writer_Result.Writes'Image & " writes: "
                & Writer_Result.Detail & ")");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_concurrent_corrupt:" & Failures'Image
                & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Concurrent_Corrupt;
