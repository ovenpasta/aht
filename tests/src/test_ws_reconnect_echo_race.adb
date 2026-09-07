--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  The I7 probe: tearing down while the write latch is contended.
--
--  One connection has one send guard, and everything that writes a
--  frame goes through it — the application's Send_*, and the
--  receiver's own echoes, the Pong it owes a Ping and the Close it
--  owes a Close. A teardown therefore has to reach tasks in three
--  quite different positions, and they fail differently enough that
--  one probe would not find all three.
--
--  Shapes:
--
--    1. RECEIVER-SIDE GATE. An application writer is parked in the
--       transport holding the guard, and the peer sends a Ping — so
--       the receiver wants the guard to answer with a Pong and is
--       queued behind a writer that will not finish.
--
--    2. SENDER-SIDE GATE. Further application senders are queued on
--       the guard behind the blocked one when the teardown fires.
--       This is the one that needs the post-guard state re-check:
--       without it a queued sender acquires the guard after the
--       one-shot Abort_Pending has already been consumed, starts a
--       write on a session that is being torn down, and the borrow
--       drain never reaches zero. Close_Frame_Sent does not cover
--       this — a peer-initiated teardown never latches it — which is
--       why the re-check is on the state and not on that flag.
--
--    3. BLOCKED IN THE TRANSPORT, not merely queued on the guard.
--       The teardown needs the guard to write its Close frame, and
--       the holder is parked in a write that has no deadline of its
--       own. Try_Take plus the skip-the-Close-frame fallback is what
--       makes this terminate.
--
--  ---------------------------------------------------------------
--  How the premise is established, because a delay does not do it
--  ---------------------------------------------------------------
--
--  Every shape needs a writer genuinely parked in the transport
--  before the teardown starts. Sleeping and assuming does not show
--  that, and the first version of this test proved the point twice:
--  its writer tasks were declared where they activated BEFORE
--  Connect, so every one took Closed_Error off an unconnected client
--  and finished instantly; and its "did they park?" check counted
--  writers that had RETURNED, which is zero both when they are all
--  parked and when they never ran. The case passed having raced
--  nothing.
--
--  So three independent facts are established before any teardown:
--
--    * Every writer has ENTERED Send_Text. Counted on the way in,
--      not on the way out.
--    * No writer has returned. With one guard serialising them, that
--      means one holds it and the rest are queued on it — which is
--      shapes 2 and 3's premise, directly rather than inferred from
--      a clock.
--    * The peer has OBSERVED bytes arriving. That is what separates
--      "holding the guard, about to write" from "holding the guard
--      and parked in the transport". The fixture detects it by
--      peeking, so asking does not consume the bytes and the peer
--      stays deaf.
--
--  The Ping in shape 1 is likewise sent only once the fixture has
--  seen that traffic, so the receiver queues behind a writer that
--  really is stuck rather than racing one that may not have started.
--
--  ---------------------------------------------------------------
--  What counts as success
--  ---------------------------------------------------------------
--
--  The teardown must abort the stuck writer and reclaim within its
--  bound. Timeout_Error is therefore a FAILURE here, not an accepted
--  outcome: it means the drain did not finish, which is exactly the
--  regression these shapes exist to catch.
--
--  And the elapsed time is measured through the task joins, not only
--  to the point where Close returns. A teardown that returns
--  promptly and then leaves writers stuck for another half minute
--  has bounded nothing; the joining is where that shows, so the
--  clock has to still be running when it happens.

with Ada.Calendar; use Ada.Calendar;
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.Transport;
with AHT.Websocket;
with AHT.Websocket.Client;

procedure Test_WS_Reconnect_Echo_Race is

   Host : constant String := "ws://127.0.0.1:8777";

   --  What the caller asks for, and what it must come back inside.
   Bound : constant Duration := 3.0;

   --  Headroom over Bound for reclamation and the joins. Far smaller
   --  than the ~34 s a missing guard bound produces, so the two are
   --  never confusable.
   Slack : constant Duration := 5.0;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_reconnect_echo_race: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function To_String (V : AHT.Bytes.Buffer) return String is
     (AHT.Bytes.To_String (V));

   --  The writers loop over this: one message of any size is simply
   --  absorbed by the local socket send buffer and returns, so it
   --  takes repeated writes to fill that and the peer's window.
   Payload : constant String (1 .. 64 * 1024) := [others => 'x'];

   --  Entry and exit counted separately. Entered is what proves the
   --  writers reached the client at all; Returned staying at zero is
   --  what proves they are still inside it.
   protected Writers is
      procedure Note_Entered;
      procedure Note_Returned;
      procedure Note_Bad (Name : String);
      procedure Reset;
      function  Entered return Natural;
      function  Returned return Natural;
      function  Bad return String;
   private
      In_N  : Natural := 0;
      Out_N : Natural := 0;
      Text  : Unbounded_String;
   end Writers;

   protected body Writers is
      procedure Note_Entered is
      begin
         In_N := In_N + 1;
      end Note_Entered;
      procedure Note_Returned is
      begin
         Out_N := Out_N + 1;
      end Note_Returned;
      procedure Note_Bad (Name : String) is
      begin
         Append (Text, Name & " ");
      end Note_Bad;
      procedure Reset is
      begin
         In_N  := 0;
         Out_N := 0;
         Text  := Null_Unbounded_String;
      end Reset;
      function Entered return Natural is (In_N);
      function Returned return Natural is (Out_N);
      function Bad return String is (To_String (Text));
   end Writers;

   --  Ask the fixture whether the connection tagged Token has put
   --  bytes on the wire. Answered over a separate connection; the
   --  fixture peeks rather than reads, so the parked writer stays
   --  parked.
   --
   --  Closed on every path: leaving this open would park its receiver
   --  on a socket the fixture holds for thirty seconds, and the
   --  enclosing scope would wait for it.
   function Peer_Saw_Traffic (Token : String) return Boolean is
      Q      : AHT.Websocket.Client.Client_Type;
      Msg    : AHT.Websocket.Client.Message_Type;
      Answer : Unbounded_String;

      procedure Shut_Down is
      begin
         AHT.Websocket.Client.Close (Q, Timeout => 1.0);
      exception
         when others => null;
      end Shut_Down;
   begin
      AHT.Websocket.Client.Connect (Q, Host & "/traffic/" & Token);
      begin
         AHT.Websocket.Client.Receive (Q, Msg, Timeout => 8.0);
         Answer := To_Unbounded_String (To_String (Msg.Payload));
      exception
         when others => null;
      end;
      Shut_Down;
      return To_String (Answer) = "traffic=yes";
   exception
      when others =>
         Shut_Down;
         return False;
   end Peer_Saw_Traffic;

   --  One shape.
   --
   --  Ask_Traffic says whether this shape should confirm the peer saw
   --  bytes by querying /traffic. The deafping route consumes that
   --  same record itself, to decide when to send its Ping, so shape 1
   --  must not also ask — there is one record per token.
   procedure Probe
     (What         : String;
      Route        : String;
      Token        : String;
      Count        : Positive;
      Ask_Traffic  : Boolean)
   is
      C : AHT.Websocket.Client.Client_Type;

      Started : Time;
      Took    : Duration := 0.0;
      Ready   : Boolean  := False;

      --  Inside a procedure so the tasks activate only once the
      --  connection exists, and are joined when it returns. Declared
      --  alongside C they would activate before Connect had run.
      procedure With_Writers is
         task type Writer;
         task body Writer is
         begin
            Writers.Note_Entered;
            --  Capped rather than infinite, so a teardown that never
            --  arrives still ends the task and leaves a report.
            for I in 1 .. 10_000 loop
               AHT.Websocket.Client.Send_Text (C, Payload);
            end loop;
            Writers.Note_Returned;
         exception
            --  Refused before it started, or cancelled once it had.
            when AHT.Websocket.Closed_Error =>
               Writers.Note_Returned;
            when AHT.Transport.Aborted_Error =>
               Writers.Note_Returned;
            when E : others =>
               Writers.Note_Bad (Ada.Exceptions.Exception_Name (E));
               Writers.Note_Returned;
         end Writer;

         Pool : array (1 .. Count) of Writer;
         pragma Unreferenced (Pool);
      begin
         --  Time for the writers to reach the transport and fill it.
         --  This delay is not the evidence; the checks below are. If
         --  it is too short they fail loudly instead of passing
         --  hollow.
         delay 2.0;

         if Writers.Entered < Count then
            Fail (What & ": only" & Natural'Image (Writers.Entered)
                  & " of" & Natural'Image (Count)
                  & " writers reached Send_Text — the teardown would "
                  & "not be racing what this shape is about");
         elsif Writers.Returned > 0 then
            Fail (What & ":" & Natural'Image (Writers.Returned)
                  & " writer(s) had already returned before the "
                  & "teardown — nothing was holding the guard, so this "
                  & "shape raced nothing");
         elsif Ask_Traffic and then not Peer_Saw_Traffic (Token) then
            Fail (What & ": the peer never saw any bytes, so no writer "
                  & "was parked IN the transport — one may only have "
                  & "been about to write, which is a different case");
         else
            Ready := True;
         end if;

         Started := Clock;
         begin
            AHT.Websocket.Client.Close
              (C, Timeout => Bound, Drain_Timeout => Bound);
         exception
            --  A drain that did not finish is the regression, not an
            --  accepted outcome: the teardown is supposed to abort
            --  the stuck writer and reclaim inside its bound.
            when AHT.Transport.Timeout_Error =>
               Fail (What & ": Close raised Timeout_Error — the drain "
                     & "did not finish within" & Duration'Image (Bound)
                     & "s, so the stuck writer was never aborted and "
                     & "reclaimed");
            when E : others =>
               Fail (What & ": Close raised "
                     & Ada.Exceptions.Exception_Name (E) & ": "
                     & Ada.Exceptions.Exception_Message (E));
         end;
         --  Took is deliberately NOT computed here. The writers are
         --  joined at the end of this procedure, and a teardown that
         --  returns promptly and then leaves them stuck for another
         --  half minute has bounded nothing. The clock has to still
         --  be running through the join.
      end With_Writers;

   begin
      begin
         AHT.Websocket.Client.Connect (C, Host & Route & "/" & Token);
      exception
         when E : others =>
            Fail (What & ": Connect raised "
                  & Ada.Exceptions.Exception_Name (E)
                  & " (is server_ws_hostile.py running?)");
            return;
      end;

      With_Writers;                --  joins the writers on return
      Took := Clock - Started;

      if not Ready then
         return;                   --  premise already reported
      end if;

      if Writers.Bad /= "" then
         Fail (What & ": a writer raised " & Writers.Bad
               & "— against a peer that is merely not reading, a "
               & "teardown must refuse or cancel a send, not break the "
               & "transport under it");
      end if;

      if Took > Bound + Slack then
         Fail (What & ": the teardown and its joins took"
               & Duration'Image (Took) & "s against a bound of"
               & Duration'Image (Bound)
               & "s — the caller's bound did not reach a writer parked "
               & "in the transport, which is what bounding the guard "
               & "acquisition is for");
      end if;
   end Probe;

begin
   --  Shape 1: the receiver is queued on the guard, wanting to answer
   --  a Ping. The fixture waits for this connection's traffic before
   --  pinging, and consumes that record doing so — hence no /traffic
   --  query of our own here.
   Writers.Reset;
   Probe ("receiver-gate", "/deafping", "r1", 1, Ask_Traffic => False);

   --  Shape 2: senders queued on the guard behind the blocked one.
   --  Entered = 3 with Returned = 0 is the direct evidence: one holds
   --  the guard, the other two are on its queue.
   Writers.Reset;
   Probe ("sender-gate", "/deaf", "s1", 3, Ask_Traffic => True);

   --  Shape 3: a single writer, so nothing is queued behind it and
   --  the only way the teardown gets the guard is by bounding its own
   --  acquisition and giving up on the Close frame.
   Writers.Reset;
   Probe ("transport-blocked", "/deaf", "t1", 1, Ask_Traffic => True);

   if Failures = 0 then
      Put_Line ("test_ws_reconnect_echo_race: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_reconnect_echo_race:" & Failures'Image
                & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Reconnect_Echo_Race;
