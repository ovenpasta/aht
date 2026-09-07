--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Sends racing a forced teardown. A Reconnect displaces a live
--  connection while application tasks are still in a Send_* (queued
--  on the write latch, inside the transport, or not yet started), and
--  each position unwinds differently. Echo fixture on 8765, and an
--  in-file deaf peer that accepts the handshake and stops reading.
--
--  Cases:
--    1. several senders against a live connection, then Reconnect
--    2. the same against a peer that has stopped reading, so senders
--       are parked in the transport when the teardown arrives
--
--  Covers:
--    - only Closed_Error (refused, never reached the wire) and
--      Aborted_Error (in flight, transport I/O cancelled) are accepted
--    - Transport_Error and TLS_Error are findings: no case here
--      introduces peer, socket or TLS failure
--    - Program_Error, Storage_Error and a hang are never acceptable;
--      every task is bounded and joined before the case reports
--    - at least one sender was Refused or Cancelled, so the teardown
--      reached a sender and the exception sets were exercised
--    - a missing bound shows up in case 2 as a hang

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Transport;
with AHT.Websocket;
with AHT.Websocket.Client;

procedure Test_WS_Reconnect_Concurrency is

   Echo : constant String := "ws://127.0.0.1:8765/";

   --  Accepts the handshake, then stops reading, so a sender backs up
   --  in the transport after a few KB.
   Deaf : constant String := "ws://127.0.0.1:8777/deaf";

   Senders : constant := 4;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_reconnect_concurrency: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Records how each sender ended, by category. "No bad exceptions"
   --  is also true of a run in which the teardown never reached a
   --  sender, so Raced is checked separately: at least one Refused or
   --  Cancelled has to have happened.
   protected Outcomes is
      procedure Note_Refused;     --  Closed_Error: admission had shut
      procedure Note_Cancelled;   --  Aborted_Error: in flight, killed
      procedure Note_Stopped;     --  ended on the flag, raced nothing
      procedure Note_Bad (Name : String);
      procedure Reset;
      function  Raced return Natural;
      function  Finished return Natural;
      function  Bad_Count return Natural;
      function  Report return String;
   private
      Refused   : Natural := 0;
      Cancelled : Natural := 0;
      Stopped   : Natural := 0;
      Bad       : Natural := 0;
      Text      : Unbounded_String;
   end Outcomes;

   protected body Outcomes is
      procedure Note_Refused is
      begin
         Refused := Refused + 1;
      end Note_Refused;

      procedure Note_Cancelled is
      begin
         Cancelled := Cancelled + 1;
      end Note_Cancelled;

      procedure Note_Stopped is
      begin
         Stopped := Stopped + 1;
      end Note_Stopped;

      procedure Note_Bad (Name : String) is
      begin
         Bad := Bad + 1;
         Append (Text, Name & " ");
      end Note_Bad;

      procedure Reset is
      begin
         Refused   := 0;
         Cancelled := 0;
         Stopped   := 0;
         Bad       := 0;
         Text      := Null_Unbounded_String;
      end Reset;

      function Raced return Natural is (Refused + Cancelled);
      function Finished return Natural is
        (Refused + Cancelled + Stopped + Bad);
      function Bad_Count return Natural is (Bad);
      function Report return String is
        ("refused=" & Natural'Image (Refused)
         & " cancelled=" & Natural'Image (Cancelled)
         & " stopped=" & Natural'Image (Stopped)
         & (if Bad = 0 then "" else " bad=[" & To_String (Text) & "]"));
   end Outcomes;

   --  Set once the scenario is over, so senders still succeeding on
   --  the replacement connection stop. Without it the deaf case never
   --  ends: the senders park in the new session and nothing waits to
   --  cancel them. Reset per scenario, or the first one's Request
   --  would end the second one's senders before they had sent.
   protected Stop is
      procedure Request;
      procedure Reset;
      function  Asked return Boolean;
   private
      Flag : Boolean := False;
   end Stop;

   protected body Stop is
      procedure Request is
      begin
         Flag := True;
      end Request;
      procedure Reset is
      begin
         Flag := False;
      end Reset;
      function Asked return Boolean is (Flag);
   end Stop;

   --  One scenario. The client is connected here and torn down while
   --  the senders run; the senders are joined before anything is
   --  asserted, so a hang is a timeout, not a false pass.
   procedure Run (What : String; URL : String) is
      C : AHT.Websocket.Client.Client_Type;

      --  Big enough that a deaf peer's receive buffer fills and the
      --  writer parks before the teardown arrives.
      Payload : constant String (1 .. 32 * 1024) := [others => 'x'];

      task type Sender;
      task body Sender is
         --  A task body cannot return, so the outcome is recorded by
         --  leaving the loop.
         Ended : Boolean := False;
      begin
         --  Keeps sending across the teardown boundary, so whichever
         --  position this task happens to be in when Reconnect lands
         --  is the one that gets exercised.
         while not Ended and then not Stop.Asked loop
            begin
               AHT.Websocket.Client.Send_Text (C, Payload);
            exception
               --  The two legitimate outcomes.
               when AHT.Websocket.Closed_Error =>
                  Outcomes.Note_Refused;
                  Ended := True;
               when AHT.Transport.Aborted_Error =>
                  Outcomes.Note_Cancelled;
                  Ended := True;

               --  Everything else is a finding, named.
               when E : others =>
                  Outcomes.Note_Bad (Ada.Exceptions.Exception_Name (E));
                  Ended := True;
            end;
         end loop;

         --  Only when the teardown never reached this sender.
         if not Ended then
            Outcomes.Note_Stopped;
         end if;
      end Sender;

      Pool : array (1 .. Senders) of Sender;
      pragma Unreferenced (Pool);
   begin
      begin
         AHT.Websocket.Client.Connect (C, URL);
      exception
         when E : others =>
            Fail (What & ": Connect raised "
                  & Ada.Exceptions.Exception_Name (E)
                  & " (are the fixtures running?)");
            return;
      end;

      --  Let the senders get into the connection before it is pulled
      --  out from under them. Without this they would all still be
      --  starting up and every one would take the "refused" path.
      delay 0.3;

      begin
         AHT.Websocket.Client.Reconnect
           (C, Timeout => 2.0, Drain_Timeout => 5.0);
      exception
         --  A Reconnect that cannot finish the drain in time is
         --  entitled to say so; what it must not do is take longer
         --  than its bound, and the runner's cap is what enforces
         --  that.
         when AHT.Transport.Timeout_Error =>
            null;
         when E : others =>
            Fail (What & ": Reconnect raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
      end;

      --  A sender parked in the replacement connection cannot see the
      --  flag until its write returns, and against a deaf peer that
      --  write has no deadline of its own. Close reaches it: it aborts
      --  the new session's transport as the Reconnect aborted the old
      --  one. Setting the flag first means a sender freed by this does
      --  not park again.
      Stop.Request;
      begin
         AHT.Websocket.Client.Close (C, Timeout => 1.0);
      exception
         when others => null;   --  already gone; the join is what matters
      end;

      --  Joined here, at the end of the declarative region's scope.
      --  Nothing is asserted until every sender has stopped, so a
      --  sender still running cannot make this look clean.
   end Run;

   procedure Check (What : String; Note : String) is
   begin
      if Outcomes.Bad_Count > 0 then
         Fail (What & ": " & Note & " (" & Outcomes.Report & ") — only "
               & "Closed_Error (refused by admission) and "
               & "Aborted_Error (cancelled in flight) are legitimate "
               & "against a peer nobody asked to fail; a "
               & "transport-level failure means the connection broke "
               & "for a reason nobody asked for");
      end if;

      if Outcomes.Finished < Senders then
         Fail (What & ": only" & Natural'Image (Outcomes.Finished)
               & " of" & Natural'Image (Senders)
               & " senders finished (" & Outcomes.Report & ")");
      end if;

      --  Anti-vacuity. Every sender ending on the flag means the
      --  teardown never reached one of them, so the exception sets
      --  above were never exercised and this scenario checked
      --  nothing.
      if Outcomes.Raced = 0 then
         Fail (What & ": no sender was ended by the teardown ("
               & Outcomes.Report & ") — they all stopped on the flag, "
               & "so nothing raced the reconnect and the exception "
               & "sets were never tested");
      end if;
   end Check;

begin
   Stop.Reset;
   Outcomes.Reset;
   Run ("stable-peer", Echo);
   Check ("stable-peer",
          "senders racing a caller-requested teardown against a "
          & "healthy peer");

   Stop.Reset;
   Outcomes.Reset;
   Run ("deaf-peer", Deaf);
   Check ("deaf-peer",
          "senders parked in a peer that stopped reading");

   if Failures = 0 then
      Put_Line ("test_ws_reconnect_concurrency: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_reconnect_concurrency:" & Failures'Image
                & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Reconnect_Concurrency;
