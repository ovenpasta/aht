--  The handover record's own protocol, driven directly.
--
--  This replaces test_ws_abort's calibrated sweep, which tried to
--  reach the same window by timing an abort against a handshake. That
--  never worked: the window is a few instructions wide, the sweep had
--  to bracket a duration that varies several-fold under load, and it
--  failed in both directions -- some runs tore every sample, others
--  none. Three attempts at re-tuning the span moved which direction it
--  failed in and nothing else.
--
--  Driving the primitive directly removes the timing entirely. These
--  are the production types, not a replica: AHT.Websocket.Handoffs is
--  what Lifecycle_Controller records handovers in.
--
--  Every wait here is on an OBSERVED FACT -- a counter the protected
--  type maintains, or a task's 'Terminated -- polled under a bound.
--  Nothing sleeps in the hope that something has happened by now.
--
--  Fixture-free: no socket, no server, nothing to be running.
--
--  Properties:
--
--    1. One call is the whole record. After Record_Taken returns
--       there is nothing left for the caller to do, so a caller
--       aborted at any later point cannot leave the record half made.
--       This is what the client depends on -- the connecting task
--       hands a session over and may be aborted immediately after,
--       and its cleanup must still see that the handover happened.
--
--       Note what this does NOT show: that an abort arriving DURING
--       the call cannot lose the record. See the note below Property
--       4 -- that window could not be reached from a test.
--
--    2. A caller that is aborted and never reaches the call records
--       nothing. The complement of 1, and what stops "always true"
--       from passing as a correct implementation.
--
--    3. The record is monotone. An attempt's cleanup can run long
--       after later attempts have published, so an earlier
--       generation's answer must not be overwritten by a higher one.
--
--    4. Concurrent recorders all land. The controller is reached from
--       several tasks and the record is a shared counter; this checks
--       the obvious lost-update.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Websocket.Handoffs;

procedure Test_WS_Handoff is

   package H renames AHT.Websocket.Handoffs;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_handoff: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Bounded spin on a fact. The bound exists so a broken build
   --  reports instead of hanging; it is never the thing being waited
   --  for.
   function Await
     (Bound : Duration; Ready : access function return Boolean)
      return Boolean
   is
      Waited : Duration := 0.0;
   begin
      while not Ready.all and then Waited < Bound loop
         delay 0.01;
         Waited := Waited + 0.01;
      end loop;
      return Ready.all;
   end Await;

begin
   ---------------------------------------------------------------
   --  Property 1: a record survives the abort of its maker.
   ---------------------------------------------------------------
   declare
      Rec : aliased H.Handoff;

      --  Gated, so the recording happens when this test says so
      --  rather than at task activation.
      task Maker is
         entry Go;
      end Maker;

      task body Maker is
      begin
         accept Go;
         Rec.Record_Taken (7);
         --  Parks. The abort below is what ends this task, so the
         --  record is made by a task that never runs another
         --  meaningful statement afterwards.
         loop
            delay 3600.0;
         end loop;
      exception
         when others => null;
      end Maker;

      function Recorded return Boolean is (Rec.Records = 1);
      Recorded_Ref : constant access function return Boolean :=
        Recorded'Unrestricted_Access;

      function Gone return Boolean is (Maker'Terminated);
      Gone_Ref : constant access function return Boolean :=
        Gone'Unrestricted_Access;
   begin
      Maker.Go;

      --  Waited for as a fact: the counter is incremented inside the
      --  protected action, so this returning means the action
      --  completed. A delay here would only mean time passed.
      if not Await (5.0, Recorded_Ref) then
         Fail ("survives-abort: the recording never completed, so the "
               & "abort below would prove nothing");
      end if;

      abort Maker;

      if not Await (5.0, Gone_Ref) then
         Fail ("survives-abort: the maker did not terminate");
      end if;

      if not Rec.Taken (7) then
         Fail ("survives-abort: generation 7 is not recorded after the "
               & "task that recorded it was aborted — the record was "
               & "completed by the caller rather than inside the "
               & "protected action");
      end if;

      if Rec.Taken (8) then
         Fail ("survives-abort: generation 8 reads as taken, but only "
               & "7 was recorded");
      end if;
   end;

   --  There is no property here for the abort BOUNDARY, and that is
   --  a finding rather than an omission.
   --
   --  The dangerous shape is a record completed by the caller after
   --  the call returns, where a pending abort lands between the two.
   --  Reaching that window from a test needs the abort to arrive in
   --  the couple of instructions between the protected action ending
   --  and the next statement. It was attempted -- an asynchronous
   --  select whose trigger fires while the victim is in the abortable
   --  part, over 200 rounds, counting how many were conclusive and
   --  how many had the abort arrive in time to cut the follow-up.
   --  Conclusive rounds were plentiful, around thirty per run. Rounds
   --  with the abort inside the window: zero, every run.
   --
   --  So that probe could not distinguish a correct implementation
   --  from a caller-side one, and it was removed rather than left to
   --  look like coverage. What caught the backed-out version was the
   --  test simply not making the second call -- which detects a
   --  changed protocol, not a lost race.
   --
   --  The placement of the record inside the protected action, and of
   --  the Publish call inside the Start rendezvous, therefore rests
   --  on the structural argument: abort is deferred inside a
   --  protected action, so there is no interval. Same standing as the
   --  Send_Guard flag shape, which was likewise falsified out of tree
   --  rather than pinned by the suite.

   ---------------------------------------------------------------
   --  Property 2: a caller that never reaches the call records
   --  nothing.
   ---------------------------------------------------------------
   declare
      Rec : aliased H.Handoff;

      --  A barrier nothing opens. The idler parks on it and is
      --  aborted there, so it never reaches the call below -- which
      --  is the state this property is about. Expressed as a barrier
      --  rather than an un-accepted task entry so there is no
      --  entry sitting in the source that is deliberately never
      --  called.
      protected Never is
         entry Wait;
      private
         Lit : Boolean := False;
      end Never;

      protected body Never is
         entry Wait when Lit is
         begin
            null;
         end Wait;
      end Never;

      task Idler;

      task body Idler is
      begin
         Never.Wait;
         Rec.Record_Taken (3);
      exception
         when others => null;
      end Idler;

      function Gone return Boolean is (Idler'Terminated);
      Gone_Ref : constant access function return Boolean :=
        Gone'Unrestricted_Access;
   begin
      abort Idler;

      if not Await (5.0, Gone_Ref) then
         Fail ("never-reached: the idler did not terminate");
      end if;

      if Rec.Records /= 0 then
         Fail ("never-reached: Records ="
               & Natural'Image (Rec.Records)
               & " though no call was made");
      end if;

      if Rec.Taken (1) then
         Fail ("never-reached: generation 1 reads as taken though "
               & "nothing was ever recorded — Taken is not answering "
               & "from the record");
      end if;
   end;

   ---------------------------------------------------------------
   --  Property 3: monotone.
   ---------------------------------------------------------------
   declare
      Rec : aliased H.Handoff;
   begin
      Rec.Record_Taken (2);
      Rec.Record_Taken (5);
      --  Out of order, as a late attempt's cleanup would see it.
      Rec.Record_Taken (3);

      if not Rec.Taken (2) then
         Fail ("monotone: generation 2 was un-recorded by a later one "
               & "— an earlier attempt's cleanup would then free a "
               & "session the receiver owns");
      end if;
      if not Rec.Taken (5) then
         Fail ("monotone: generation 5 is not recorded");
      end if;
      if Rec.Taken (6) then
         Fail ("monotone: generation 6 reads as taken");
      end if;
      if Rec.High_Water /= 5 then
         Fail ("monotone: High_Water ="
               & Natural'Image (Rec.High_Water) & ", expected 5");
      end if;
      if Rec.Records /= 3 then
         Fail ("monotone: Records =" & Natural'Image (Rec.Records)
               & ", expected 3");
      end if;
   end;

   ---------------------------------------------------------------
   --  Property 4: concurrent recorders all land.
   ---------------------------------------------------------------
   declare
      Movers : constant := 16;
      Rec    : aliased H.Handoff;

      --  Each mover pulls its own generation instead of being told
      --  it through an entry. That removes the only synchronisation
      --  this property does not need -- the point is concurrent
      --  recording, not ordered starting.
      protected Dispenser is
         procedure Next (G : out Natural);
      private
         N : Natural := 0;
      end Dispenser;

      protected body Dispenser is
         procedure Next (G : out Natural) is
         begin
            if N < Movers then
               N := N + 1;
               G := N;
            else
               G := 0;
            end if;
         end Next;
      end Dispenser;

      task type Mover;

      task body Mover is
         Mine : Natural;
      begin
         Dispenser.Next (Mine);
         if Mine > 0 then
            Rec.Record_Taken (Mine);
         end if;
      exception
         when others => null;
      end Mover;

      Pool : array (1 .. Movers) of Mover;

      function All_Done return Boolean is
      begin
         return Rec.Records = Movers;
      end All_Done;

      All_Done_Ref : constant access function return Boolean :=
        All_Done'Unrestricted_Access;
   begin
      if not Await (10.0, All_Done_Ref) then
         Fail ("concurrent: only" & Natural'Image (Rec.Records) & " of"
               & Natural'Image (Movers)
               & " recordings completed — an update was lost");
      elsif Rec.High_Water /= Movers then
         Fail ("concurrent: High_Water ="
               & Natural'Image (Rec.High_Water) & ", expected"
               & Natural'Image (Movers));
      else
         for I in 1 .. Movers loop
            if not Rec.Taken (I) then
               Fail ("concurrent: generation" & Natural'Image (I)
                     & " is not recorded");
            end if;
         end loop;
      end if;
   end;

   if Failures = 0 then
      Put_Line ("test_ws_handoff: OK (the record survives its maker's "
                & "abort, is monotone, and loses no concurrent update)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_handoff:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Handoff;
