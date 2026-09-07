--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  What must NOT cross a generation boundary, and what must.
--
--  A reconnect replaces the connection under a client that the
--  application is still holding. Everything tied to the old
--  connection has to end with it — a caller parked in Receive, the
--  messages that connection queued and nobody read — while everything
--  the application configured on the client has to survive, because it
--  never belonged to the connection in the first place.
--
--  Getting this wrong is not loud. A blocked Receive that is handed
--  the NEXT connection's message looks like a working Receive; it is
--  only wrong in that the caller asked the old connection a question
--  and the new one answered. So each case here pins the boundary
--  rather than the happy path.
--
--  Cases:
--    1. A Receive blocked across a forced Reconnect raises
--       Closed_Error, and never returns a message belonging to the
--       session that replaced the one it was waiting on.
--    2. Messages queued but unread on the old connection are gone.
--       The inbox belonged to the session, so the new generation
--       starts empty rather than inheriting a backlog whose ordering
--       relative to the new connection's traffic would be undefined.
--    3. Callbacks are installed on the CLIENT, so one installation
--       serves every generation — and no callback for an old
--       generation arrives once the new session is open.
--    4. A caller-initiated Reconnect fires no On_Error. The teardown
--       it performs aborts the receiver's transport I/O, and reporting
--       that to the application would mean telling it its connection
--       failed every time it deliberately replaced one.
--
--  How these were validated, and what it took:
--
--    * Case 4 needs a peer that will not answer a Close frame. See
--      the note there — against an echo peer it passed with the
--      suppression backed out, which is to say it checked nothing.
--    * Case 1 only fails when BOTH wake sites are backed out. Waking
--      a parked borrower is done by the receiver's own reclamation
--      and again by the caller's Teardown_Pin.Finalize, deliberately
--      and idempotently, so removing either one alone changes no
--      observable behaviour. With both gone the case reports the
--      parked Receive timing out instead of ending with its
--      connection — and the drain stalls behind the borrower it can
--      no longer wake, which is the deadlock the redundancy exists to
--      prevent.
--    * Cases 2 and 3 are NOT backout-validated. Both properties come
--      from where the state is declared — the inbox inside the
--      session, the callbacks on the client — so backing them out
--      means moving a declaration rather than removing a guard, and
--      the result does not compile as a smaller change. They are
--      still worth asserting: a later refactor that hoists the inbox
--      for convenience compiles fine and fails here.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.Transport;
with AHT.Websocket;
with AHT.Websocket.Client;

procedure Test_WS_Reconnect_Isolation is

   Echo : constant String := "ws://127.0.0.1:8765/";

   --  Drains whatever it is sent and holds the socket open, but never
   --  answers a Close frame. Tearing this connection down therefore
   --  cannot finish the RFC handshake and must abort the receiver
   --  instead, which is the path case 4 needs.
   Silent : constant String := "ws://127.0.0.1:8777/echo";

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_reconnect_isolation: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function To_String (V : AHT.Bytes.Buffer) return String is
     (AHT.Bytes.To_String (V));

   ---------------------------------------------------------------
   --  Case 1 plumbing
   ---------------------------------------------------------------

   --  What the parked reader saw. It runs on its own task, so it
   --  reports through a protected object rather than touching
   --  Failures.
   protected Parked is
      procedure Note (Outcome : String; Detail : String);
      function  Done return Boolean;
      function  Report return String;
   private
      Finished : Boolean := False;
      Text     : Unbounded_String;
   end Parked;

   protected body Parked is
      procedure Note (Outcome : String; Detail : String) is
      begin
         Text     := To_Unbounded_String (Outcome & Detail);
         Finished := True;
      end Note;
      function Done return Boolean is (Finished);
      function Report return String is (To_String (Text));
   end Parked;

   --  Bounded wait for a protected flag, so nothing here depends on a
   --  guessed delay.
   function Await (Flag : access function return Boolean; Bound : Duration)
      return Boolean
   is
      Waited : Duration := 0.0;
   begin
      while not Flag.all and then Waited < Bound loop
         delay 0.02;
         Waited := Waited + 0.02;
      end loop;
      return Flag.all;
   end Await;

   function Parked_Done return Boolean is (Parked.Done);

   ---------------------------------------------------------------
   --  Case 2 plumbing
   ---------------------------------------------------------------

   Backlog_Size : constant := 3;

   --  Counts echoes as they arrive, so case 2 can wait for the whole
   --  backlog to exist before it consumes any of it.
   protected Arrived is
      procedure Note;
      function  Count return Natural;
   private
      N : Natural := 0;
   end Arrived;

   protected body Arrived is
      procedure Note is
      begin
         N := N + 1;
      end Note;
      function Count return Natural is (N);
   end Arrived;

   procedure Count_Backlog (Msg : AHT.Websocket.Client.Message_Type) is
      pragma Unreferenced (Msg);
   begin
      Arrived.Note;
   end Count_Backlog;

   function Backlog_Arrived return Boolean is
     (Arrived.Count >= Backlog_Size);

   ---------------------------------------------------------------
   --  Case 3 plumbing
   ---------------------------------------------------------------

   --  Every message the callback saw, tagged with the generation that
   --  was current when it arrived. The tag is the point: "the callback
   --  fired twice" would also be true if both firings belonged to the
   --  same connection, and an old-generation message delivered after
   --  the new session opened is exactly the failure this has to name.
   protected Seen is
      procedure Note (Payload : String; Gen : Natural);
      function  Count return Natural;
      function  Report return String;
   private
      N    : Natural := 0;
      Text : Unbounded_String;
   end Seen;

   protected body Seen is
      procedure Note (Payload : String; Gen : Natural) is
      begin
         N := N + 1;
         Append (Text, Payload & "@" & Natural'Image (Gen) & " ");
      end Note;
      function Count return Natural is (N);
      function Report return String is (To_String (Text));
   end Seen;

   ---------------------------------------------------------------
   --  Case 4 plumbing
   ---------------------------------------------------------------

   protected Errors is
      procedure Note (Message : String);
      function  Count return Natural;
      function  Report return String;
   private
      N    : Natural := 0;
      Text : Unbounded_String;
   end Errors;

   protected body Errors is
      procedure Note (Message : String) is
      begin
         N := N + 1;
         Append (Text, Message & " | ");
      end Note;
      function Count return Natural is (N);
      function Report return String is (To_String (Text));
   end Errors;

begin
   ---------------------------------------------------------------
   --  Case 1: a parked Receive belongs to the connection it parked on.
   ---------------------------------------------------------------
   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      begin
         AHT.Websocket.Client.Connect (C, Echo);
      exception
         when E : others =>
            Fail ("parked-receive: Connect raised "
                  & Ada.Exceptions.Exception_Name (E)
                  & " (is server_ws.py running?)");
            Put_Line ("test_ws_reconnect_isolation:" & Failures'Image
                      & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;

      declare
         --  Bounded, so a regression that leaves this parked forever
         --  still lets the test report rather than hang. The bound is
         --  far longer than the reconnect it is supposed to outlive.
         task Reader;
         task body Reader is
            Msg : AHT.Websocket.Client.Message_Type;
         begin
            AHT.Websocket.Client.Receive (C, Msg, Timeout => 15.0);
            Parked.Note ("delivered:", To_String (Msg.Payload));
         exception
            when AHT.Websocket.Closed_Error =>
               Parked.Note ("closed", "");
            when AHT.Transport.Timeout_Error =>
               Parked.Note ("timeout", "");
            when E : others =>
               Parked.Note ("raised:", Ada.Exceptions.Exception_Name (E));
         end Reader;
      begin
         --  Let the reader reach the inbox before the ground moves.
         --  Nothing is queued, so once it is in Receive it stays there
         --  until the session it captured is reclaimed.
         delay 0.5;

         begin
            AHT.Websocket.Client.Reconnect (C);
         exception
            when E : others =>
               Fail ("parked-receive: Reconnect raised "
                     & Ada.Exceptions.Exception_Name (E) & ": "
                     & Ada.Exceptions.Exception_Message (E));
         end;

         --  Traffic on the NEW connection. If the parked reader is
         --  still able to observe an inbox, this is what it would
         --  wrongly pick up — so sending it is what turns "did not
         --  crash" into a real check.
         begin
            AHT.Websocket.Client.Send_Text (C, "new-generation");
         exception
            when E : others =>
               Fail ("parked-receive: sending on the new connection "
                     & "raised " & Ada.Exceptions.Exception_Name (E));
         end;
      end;   --  waits for Reader

      if not Await (Parked_Done'Access, 20.0) then
         Fail ("parked-receive: the parked Receive never returned at "
               & "all");
      else
         declare
            R : constant String := Parked.Report;
         begin
            if R /= "closed" then
               Fail ("parked-receive: the parked Receive reported """
                     & R & """, expected ""closed"" — it must end with "
                     & "the connection it was waiting on, and must "
                     & "never be handed the next one's message");
            end if;
         end;
      end if;

      AHT.Websocket.Client.Close (C);
   end;

   ---------------------------------------------------------------
   --  Case 2: an unread backlog does not outlive its connection.
   ---------------------------------------------------------------
   declare
      C   : AHT.Websocket.Client.Client_Type;
      Msg : AHT.Websocket.Client.Message_Type;
   begin
      --  Delivery is Both by default, so the callback counts arrivals
      --  while the inbox keeps them. That is what makes the wait
      --  below exact instead of a guess.
      AHT.Websocket.Client.Set_On_Message
        (C, Count_Backlog'Unrestricted_Access);
      AHT.Websocket.Client.Connect (C, Echo);

      --  Queue several and read none of them.
      for I in 1 .. Backlog_Size loop
         AHT.Websocket.Client.Send_Text (C, "backlog" & Integer'Image (I));
      end loop;

      --  Wait for ALL of them, rather than sleeping and hoping.
      --
      --  A fixed delay was not good enough: it establishes only that
      --  at least one arrived, and taking that one would then leave
      --  nothing unread — so the "new connection's inbox is empty"
      --  check below would pass with no backlog to discard, proving
      --  nothing. The case needs a backlog that outlives the message
      --  it consumes.
      if not Await (Backlog_Arrived'Unrestricted_Access, 10.0) then
         Fail ("backlog: only" & Natural'Image (Arrived.Count) & " of"
               & Natural'Image (Backlog_Size)
               & " echoes arrived, so there is no unread backlog and "
               & "discarding it proves nothing");
      end if;

      --  Take exactly one. The rest stay unread, and are what the
      --  reconnect below has to discard.
      begin
         AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);
      exception
         when E : others =>
            Fail ("backlog: nothing was queued to begin with — "
                  & Ada.Exceptions.Exception_Name (E)
                  & " — so discarding it proves nothing");
      end;

      AHT.Websocket.Client.Reconnect (C);

      --  The new connection's inbox starts empty. Anything delivered
      --  here is a message the previous connection queued.
      begin
         AHT.Websocket.Client.Receive (C, Msg, Timeout => 1.0);
         Fail ("backlog: the new connection delivered """
               & To_String (Msg.Payload)
               & """ — a message queued by the connection it "
               & "replaced");
      exception
         when AHT.Transport.Timeout_Error =>
            null;   --  correct: the backlog went with its session
         when E : others =>
            Fail ("backlog: reading the new connection raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
      end;

      --  And the new connection is genuinely usable, so the empty
      --  inbox above is "nothing stale" rather than "nothing at all".
      AHT.Websocket.Client.Send_Text (C, "fresh");
      begin
         AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);
         if To_String (Msg.Payload) /= "fresh" then
            Fail ("backlog: the new connection echoed """
                  & To_String (Msg.Payload) & """, expected ""fresh""");
         end if;
      exception
         when E : others =>
            Fail ("backlog: the new connection did not work: "
                  & Ada.Exceptions.Exception_Name (E));
      end;

      AHT.Websocket.Client.Close (C);
   end;

   ---------------------------------------------------------------
   --  Case 3: callbacks belong to the client, not the connection.
   ---------------------------------------------------------------
   declare
      Client_Ref : aliased AHT.Websocket.Client.Client_Type;

      procedure On_Message (Msg : AHT.Websocket.Client.Message_Type) is
      begin
         Seen.Note (To_String (Msg.Payload),
                    AHT.Websocket.Client.Generation (Client_Ref));
      end On_Message;

      function Seen_Both return Boolean is (Seen.Count >= 2);
   begin
      --  Installed ONCE, before any connection exists.
      AHT.Websocket.Client.Set_On_Message
        (Client_Ref, On_Message'Unrestricted_Access);

      AHT.Websocket.Client.Connect (Client_Ref, Echo);
      AHT.Websocket.Client.Send_Text (Client_Ref, "gen-one");
      delay 0.5;

      AHT.Websocket.Client.Reconnect (Client_Ref);
      AHT.Websocket.Client.Send_Text (Client_Ref, "gen-two");

      if not Await (Seen_Both'Unrestricted_Access, 10.0) then
         Fail ("callbacks: the callback fired"
               & Natural'Image (Seen.Count)
               & " time(s) across two generations (" & Seen.Report
               & ") — one installation has to serve both");
      else
         --  Both firings must be tagged with the generation that was
         --  current when they arrived. "gen-one@ 2" would mean the
         --  first connection's message was delivered after the second
         --  session opened.
         declare
            R : constant String := Seen.Report;
         begin
            if R /= "gen-one@ 1 gen-two@ 2 " then
               Fail ("callbacks: got """ & R
                     & """, expected ""gen-one@ 1 gen-two@ 2 "" — each "
                     & "message must be delivered under the generation "
                     & "that carried it");
            end if;
         end;
      end if;

      AHT.Websocket.Client.Close (Client_Ref);
   end;

   ---------------------------------------------------------------
   --  Case 4: a teardown the caller asked for is not a failure.
   ---------------------------------------------------------------
   --
   --  The peer matters here, and an ordinary echo peer will not do.
   --  It answers the Close frame, so the receiver reads the reply and
   --  exits on its own; nothing is ever aborted, the suppression is
   --  never reached, and the case would pass whether or not it
   --  existed. That is not a hypothetical — this case was written
   --  against the echo peer first and did not notice the suppression
   --  being backed out.
   --
   --  This peer drains but never answers, so the handshake cannot
   --  complete and the teardown has to fall back to aborting the
   --  receiver's transport I/O. That abort is the mechanism working,
   --  and it is the one the application must not be told about.
   declare
      C : AHT.Websocket.Client.Client_Type;

      procedure On_Error (Message : String) is
      begin
         Errors.Note (Message);
      end On_Error;
   begin
      AHT.Websocket.Client.Set_On_Error (C, On_Error'Unrestricted_Access);

      begin
         AHT.Websocket.Client.Connect (C, Silent);
      exception
         when E : others =>
            Fail ("no-error: Connect to the silent peer raised "
                  & Ada.Exceptions.Exception_Name (E)
                  & " (is server_ws_hostile.py running?)");
            Put_Line ("test_ws_reconnect_isolation:" & Failures'Image
                      & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;

      --  Short, because the peer will never answer and waiting the
      --  default out would only make the test slow.
      AHT.Websocket.Client.Reconnect (C, Timeout => 1.0);

      --  Let anything the reconnect was going to report arrive before
      --  the count is read.
      delay 0.5;

      if Errors.Count /= 0 then
         Fail ("no-error: On_Error fired" & Natural'Image (Errors.Count)
               & " time(s) for a reconnect the caller asked for ("
               & Errors.Report
               & ") — the application would be told its connection "
               & "failed every time it deliberately replaced one");
      end if;

      --  The reconnect really happened, so the silence above is "no
      --  error reported" rather than "nothing was torn down".
      if AHT.Websocket.Client.Generation (C) /= 2 then
         Fail ("no-error: Generation ="
               & Natural'Image (AHT.Websocket.Client.Generation (C))
               & " — no teardown happened, so On_Error had nothing to "
               & "stay silent about");
      end if;

      AHT.Websocket.Client.Close (C);
      delay 0.5;

      if Errors.Count /= 0 then
         Fail ("no-error: On_Error fired" & Natural'Image (Errors.Count)
               & " time(s) once Close was included (" & Errors.Report
               & ")");
      end if;
   end;

   if Failures = 0 then
      Put_Line ("test_ws_reconnect_isolation: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_reconnect_isolation:" & Failures'Image
                & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Reconnect_Isolation;
