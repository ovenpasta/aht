--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Reconnecting a client, by calling Connect again.
--
--  A Client_Type used to be single-use: the receiver was a one-shot
--  task and every per-connection resource was an inline component, so
--  a second Connect had to be refused. This exercises what replaced
--  that — a persistent receiver over heap-owned per-generation
--  sessions — from the outside, where it is visible as "the same
--  object connects again".
--
--  Generation is what makes that observable. It counts *successful*
--  connections, so a case can distinguish "reconnected" from "the
--  call returned", and a failed attempt from one that quietly did
--  nothing.
--
--  Cases:
--    1. After the receiver tore the connection down on its own —
--       not via Close. That path reclaims the session from inside the
--       receiver, which is the harder one to get right, and the
--       client must come back from it as readily as from a graceful
--       close.
--    2. After a failed upgrade that follows a *successful dial*.
--       This is the bug the whole design started from: the transport
--       was already latched by the time the handshake was rejected,
--       so the documented retry died inside it with a misleading
--       error. Generation must still read 0 across the failure.
--    3. After a dial that never connected at all.
--    4. Connect is still refused while a connection is live. Widening
--       admission to Disconnected must not have widened it to Open.
--    6. Reconnect repeats the last connect that WORKED, not the last
--       one attempted.
--    8. Close, Reconnect and Receive refuse to be called from inside
--       a callback, where they would wait on the task making the
--       call; Send_* stay legal there.
--    7. Reconnect displaces a live connection — the one thing Connect
--       refuses to do — draining it first.
--
--    5. Across transport kinds, wss to ws, checking that the
--       subprotocol is a property of the connection rather than of
--       the client — a session carries its own transport variant, so
--       the two generations here are not even the same shape. The
--       subprotocol is checked after Close and after a failed
--       attempt, not just after the next success: "overwritten by
--       whatever connects next" is not the same as "gone with the
--       connection".

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;

with AHT.Bytes;
with AHT.HTTP.Headers;
with AHT.Transport;
with AHT.Websocket;
with AHT.Websocket.Client;

procedure Test_WS_Reconnect is

   Echo   : constant String := "ws://127.0.0.1:8765/";
   Secure : constant String := "wss://127.0.0.1:8768/";
   Plain_HTTP : constant String := "ws://127.0.0.1:8764/hello";
   Huge   : constant String := "ws://127.0.0.1:8777/huge/reconnect";
   Closed : constant String := "ws://127.0.0.1:1/";

   Failures : Natural := 0;

   --  Records what the reentrancy callback observed. It runs on the
   --  receiver task, so it reports through a protected object rather
   --  than touching Failures.
   protected Reentry is
      --  First is True for exactly one caller. The callback sends a
      --  message as part of what it checks, the fixture echoes it,
      --  and that would re-enter the callback forever otherwise.
      procedure Claim (First : out Boolean);
      procedure Note (What : String; Ex : String);
      --  Set once the callback has finished ALL of its checks. The
      --  main task waits on this rather than on "something was
      --  recorded": the four calls are made one after another, so a
      --  reader woken by the first would read a partial report, and
      --  would go on to Close while the callback was still sending.
      procedure Note_Complete;
      function  Done return Boolean;
      function  Report return String;
   private
      Claimed  : Boolean := False;
      Finished : Boolean := False;
      Text     : Unbounded_String;
   end Reentry;

   protected body Reentry is
      procedure Claim (First : out Boolean) is
      begin
         First   := not Claimed;
         Claimed := True;
      end Claim;
      procedure Note (What : String; Ex : String) is
      begin
         Append (Text, What & "=" & Ex & " ");
      end Note;
      procedure Note_Complete is
      begin
         Finished := True;
      end Note_Complete;
      function Done return Boolean is (Finished);
      function Report return String is (To_String (Text));
   end Reentry;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_reconnect: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function To_String (V : AHT.Bytes.Buffer) return String is
     (AHT.Bytes.To_String (V));

   --  Round-trip a message, so a case proves it has a working
   --  connection rather than merely a Connect that returned.
   procedure Expect_Echo
     (What : String;
      C    : in out AHT.Websocket.Client.Client_Type;
      Text : String)
   is
      Msg : AHT.Websocket.Client.Message_Type;
   begin
      AHT.Websocket.Client.Send_Text (C, Text);
      AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);
      if To_String (Msg.Payload) /= Text then
         Fail (What & ": echoed """ & To_String (Msg.Payload)
               & """, expected """ & Text & """");
      end if;
   exception
      when E : others =>
         Fail (What & ": round-trip raised "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E));
   end Expect_Echo;

   procedure Expect_Generation
     (What : String;
      C    : AHT.Websocket.Client.Client_Type;
      N    : Natural)
   is
      Got : constant Natural := AHT.Websocket.Client.Generation (C);
   begin
      if Got /= N then
         Fail (What & ": Generation =" & Natural'Image (Got)
               & " (expected" & Natural'Image (N) & ")");
      end if;
   end Expect_Generation;

   --  Wait (bounded) for the receiver to finish tearing a connection
   --  down, so nothing here depends on a guessed delay.
   function Await_Closed
     (C : AHT.Websocket.Client.Client_Type; Bound : Duration)
      return Boolean
   is
      Waited : Duration := 0.0;
   begin
      while AHT.Websocket.Client.Is_Open (C) and then Waited < Bound loop
         delay 0.02;
         Waited := Waited + 0.02;
      end loop;
      return not AHT.Websocket.Client.Is_Open (C);
   end Await_Closed;

begin
   --  Case 1: the receiver reclaims on its own, then the client
   --  reconnects. The oversize header is just a convenient way to
   --  make the receiver — rather than the caller — decide the
   --  connection is over.
   declare
      C : AHT.Websocket.Client.Client_Type;
      L : AHT.Websocket.Client.Limits;
   begin
      L.Max_Message_Bytes := 64 * 1024;
      AHT.Websocket.Client.Configure (C, L);

      begin
         AHT.Websocket.Client.Connect (C, Huge);
      exception
         when E : others =>
            Fail ("receiver-teardown: Connect raised "
                  & Ada.Exceptions.Exception_Name (E)
                  & " (is server_ws_hostile.py running?)");
            Put_Line ("test_ws_reconnect:" & Failures'Image & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;
      Expect_Generation ("receiver-teardown", C, 1);

      if not Await_Closed (C, 10.0) then
         Fail ("receiver-teardown: the connection never went down");
      end if;

      --  Is_Open goes false the moment admission stops, which is the
      --  FIRST step of reclamation — the session is not yet freed and
      --  the client is still Closing. Close joins that teardown and
      --  returns once it has completed, which is what makes the
      --  reconfigure below deterministic rather than a race against
      --  the receiver. Timeout => 0.0 because there is no handshake
      --  left to wait for; this is a join, not a close.
      AHT.Websocket.Client.Close (C, Timeout => 0.0);

      --  Between connections, so the limits may be changed again.
      begin
         AHT.Websocket.Client.Configure
           (C, AHT.Websocket.Client.Limits'(others => <>));
      exception
         when E : others =>
            Fail ("receiver-teardown: Configure after the teardown "
                  & "raised " & Ada.Exceptions.Exception_Name (E)
                  & " — reclamation had not finished");
      end;

      begin
         AHT.Websocket.Client.Connect (C, Echo);
      exception
         when E : others =>
            Fail ("receiver-teardown: reconnect raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
      end;
      Expect_Generation ("receiver-teardown", C, 2);
      Expect_Echo ("receiver-teardown", C, "back again");
      AHT.Websocket.Client.Close (C);
   end;

   --  Case 2: the bug. The dial succeeds and the upgrade is rejected,
   --  which used to leave the client's one transport latched and the
   --  documented retry impossible.
   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      begin
         AHT.Websocket.Client.Connect (C, Plain_HTTP);
         Fail ("failed-upgrade: Connect returned without raising");
      exception
         when AHT.Websocket.Handshake_Error => null;
         when E : others =>
            Fail ("failed-upgrade: expected Handshake_Error, got "
                  & Ada.Exceptions.Exception_Name (E));
      end;

      --  A refused attempt is not a connection.
      Expect_Generation ("failed-upgrade", C, 0);

      begin
         AHT.Websocket.Client.Connect (C, Echo);
      exception
         when E : others =>
            Fail ("failed-upgrade: the retry raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E)
                  & " — the failed attempt left the client unusable");
      end;
      Expect_Generation ("failed-upgrade", C, 1);
      Expect_Echo ("failed-upgrade", C, "retry works");
      AHT.Websocket.Client.Close (C);
   end;

   --  Case 3: nothing ever connected, so nothing was latched — but
   --  the attempt still held admission, and releasing it is what lets
   --  the next one in.
   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      begin
         AHT.Websocket.Client.Connect (C, Closed);
         Fail ("dial-failure: Connect returned without raising");
      exception
         when AHT.Transport.Transport_Error => null;
         when E : others =>
            Fail ("dial-failure: expected Transport_Error, got "
                  & Ada.Exceptions.Exception_Name (E));
      end;
      Expect_Generation ("dial-failure", C, 0);

      begin
         AHT.Websocket.Client.Connect (C, Echo);
      exception
         when E : others =>
            Fail ("dial-failure: the retry raised "
                  & Ada.Exceptions.Exception_Name (E));
      end;
      Expect_Generation ("dial-failure", C, 1);
      AHT.Websocket.Client.Close (C);
   end;

   --  Case 4: a live connection is never displaced silently.
   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      AHT.Websocket.Client.Connect (C, Echo);
      begin
         AHT.Websocket.Client.Connect (C, Echo);
         Fail ("while-open: a second Connect was accepted over a live "
               & "connection");
      exception
         when AHT.Websocket.Handshake_Error => null;
         when E : others =>
            Fail ("while-open: expected Handshake_Error, got "
                  & Ada.Exceptions.Exception_Name (E));
      end;
      Expect_Generation ("while-open", C, 1);
      --  Refusing the second Connect is only half of it: the first
      --  connection has to come through untouched.
      Expect_Echo ("while-open", C, "still mine");
      AHT.Websocket.Client.Close (C);
   end;

   --  Case 5: the two generations are not even the same shape — one
   --  runs over TLS and negotiates a subprotocol, the other does
   --  neither. The subprotocol has to follow the connection, not the
   --  client.
   declare
      C : AHT.Websocket.Client.Client_Type;
      No_Extras : AHT.HTTP.Headers.Map;
   begin
      begin
         AHT.Websocket.Client.Connect
           (Self          => C,
            URL           => Secure,
            Extra_Headers => No_Extras,
            Subprotocols  => "chat",
            Insecure      => True);
      exception
         when E : others =>
            Fail ("across-kinds: wss Connect raised "
                  & Ada.Exceptions.Exception_Name (E)
                  & " (is server_ws_tls.py running?)");
            Put_Line ("test_ws_reconnect:" & Failures'Image & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;

      if AHT.Websocket.Client.Selected_Subprotocol (C) /= "chat" then
         Fail ("across-kinds: Selected_Subprotocol = """
               & AHT.Websocket.Client.Selected_Subprotocol (C)
               & """ on the wss connection");
      end if;
      Expect_Echo ("across-kinds", C, "secure hello");
      AHT.Websocket.Client.Close (C);

      --  Gone with the connection it belonged to, not merely
      --  overwritten by whatever connects next.
      if AHT.Websocket.Client.Selected_Subprotocol (C) /= "" then
         Fail ("across-kinds: Selected_Subprotocol = """
               & AHT.Websocket.Client.Selected_Subprotocol (C)
               & """ after Close, with no session to speak for");
      end if;

      --  And a failed attempt does not resurrect it either.
      begin
         AHT.Websocket.Client.Connect (C, Closed);
         Fail ("across-kinds: the closed-port dial succeeded");
      exception
         when AHT.Transport.Transport_Error => null;
         when E : others =>
            Fail ("across-kinds: closed-port dial raised "
                  & Ada.Exceptions.Exception_Name (E));
      end;
      if AHT.Websocket.Client.Selected_Subprotocol (C) /= "" then
         Fail ("across-kinds: Selected_Subprotocol = """
               & AHT.Websocket.Client.Selected_Subprotocol (C)
               & """ after a failed attempt");
      end if;

      begin
         AHT.Websocket.Client.Connect (C, Echo);
      exception
         when E : others =>
            Fail ("across-kinds: the plain reconnect raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
      end;
      Expect_Generation ("across-kinds", C, 2);

      if AHT.Websocket.Client.Selected_Subprotocol (C) /= "" then
         Fail ("across-kinds: Selected_Subprotocol = """
               & AHT.Websocket.Client.Selected_Subprotocol (C)
               & """ carried over from the previous connection");
      end if;
      Expect_Echo ("across-kinds", C, "plain hello");
      AHT.Websocket.Client.Close (C);
   end;

   --  Case 6: Reconnect repeats the last connect that WORKED.
   --
   --  A failed attempt in between must not become the thing that gets
   --  replayed — otherwise "reconnect" would mean "retry whatever I
   --  last asked for", and a typo would be permanent.
   declare
      C : AHT.Websocket.Client.Client_Type;
      No_Extras : AHT.HTTP.Headers.Map;
   begin
      --  Nothing to repeat yet.
      begin
         AHT.Websocket.Client.Reconnect (C);
         Fail ("saved-params: Reconnect succeeded before any Connect");
      exception
         when AHT.Websocket.Handshake_Error => null;
         when E : others =>
            Fail ("saved-params: expected Handshake_Error, got "
                  & Ada.Exceptions.Exception_Name (E));
      end;

      AHT.Websocket.Client.Connect
        (Self          => C,
         URL           => Secure,
         Extra_Headers => No_Extras,
         Subprotocols  => "chat",
         Insecure      => True);
      Expect_Generation ("saved-params", C, 1);
      AHT.Websocket.Client.Close (C);

      --  A failed attempt between the good one and the Reconnect.
      begin
         AHT.Websocket.Client.Connect (C, Closed);
         Fail ("saved-params: the closed-port dial succeeded");
      exception
         when AHT.Transport.Transport_Error => null;
         when E : others =>
            Fail ("saved-params: closed-port dial raised "
                  & Ada.Exceptions.Exception_Name (E));
      end;

      --  Repeats the wss connect, subprotocol and all — not the
      --  closed port that was tried more recently.
      begin
         AHT.Websocket.Client.Reconnect (C);
      exception
         when E : others =>
            Fail ("saved-params: Reconnect raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
      end;
      Expect_Generation ("saved-params", C, 2);
      if AHT.Websocket.Client.Selected_Subprotocol (C) /= "chat" then
         Fail ("saved-params: Selected_Subprotocol = """
               & AHT.Websocket.Client.Selected_Subprotocol (C)
               & """ — the offered subprotocol was not replayed");
      end if;
      Expect_Echo ("saved-params", C, "replayed");
      AHT.Websocket.Client.Close (C);
   end;

   --  Case 7: Reconnect displaces a LIVE connection, which is the one
   --  thing Connect refuses to do. It drains first, so the generation
   --  advances exactly once.
   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      AHT.Websocket.Client.Connect (C, Echo);
      Expect_Generation ("live-redial", C, 1);
      Expect_Echo ("live-redial", C, "first");

      begin
         AHT.Websocket.Client.Reconnect (C);
      exception
         when E : others =>
            Fail ("live-redial: Reconnect over a live connection "
                  & "raised " & Ada.Exceptions.Exception_Name (E));
      end;
      Expect_Generation ("live-redial", C, 2);
      Expect_Echo ("live-redial", C, "second");
      AHT.Websocket.Client.Close (C);
   end;
   --  Case 8: the operations that wait for the receiver refuse to be
   --  called FROM it.
   --
   --  Each of these would otherwise wait on the very task making the
   --  call: Close and Reconnect for a teardown only the receiver can
   --  complete, Receive for a message only the receiver can deliver.
   --  Send_* wait for nothing the receiver owes them and stay legal,
   --  which is what keeps echo-from-On_Message working.
   declare
      Client_Ref : aliased AHT.Websocket.Client.Client_Type;

      procedure On_Message (Msg : AHT.Websocket.Client.Message_Type) is
         pragma Unreferenced (Msg);
         Got   : AHT.Websocket.Client.Message_Type;
         First : Boolean;
      begin
         Reentry.Claim (First);
         if not First then
            return;   --  our own echo coming back
         end if;

         begin
            AHT.Websocket.Client.Close (Client_Ref);
            Reentry.Note ("close", "returned");
         exception
            when AHT.Websocket.Reentrant_Error =>
               Reentry.Note ("close", "refused");
            when E : others =>
               Reentry.Note ("close", Ada.Exceptions.Exception_Name (E));
         end;

         begin
            AHT.Websocket.Client.Reconnect (Client_Ref);
            Reentry.Note ("reconnect", "returned");
         exception
            when AHT.Websocket.Reentrant_Error =>
               Reentry.Note ("reconnect", "refused");
            when E : others =>
               Reentry.Note
                 ("reconnect", Ada.Exceptions.Exception_Name (E));
         end;

         begin
            AHT.Websocket.Client.Receive (Client_Ref, Got, Timeout => 1.0);
            Reentry.Note ("receive", "returned");
         exception
            when AHT.Websocket.Reentrant_Error =>
               Reentry.Note ("receive", "refused");
            when E : others =>
               Reentry.Note ("receive", Ada.Exceptions.Exception_Name (E));
         end;

         --  Still legal, and the reason the rule is per-operation
         --  rather than "no client calls from callbacks".
         begin
            AHT.Websocket.Client.Send_Text (Client_Ref, "echoed back");
            Reentry.Note ("send", "ok");
         exception
            when E : others =>
               Reentry.Note ("send", Ada.Exceptions.Exception_Name (E));
         end;

         Reentry.Note_Complete;
      end On_Message;

      Waited : Duration := 0.0;
   begin
      AHT.Websocket.Client.Set_On_Message
        (Client_Ref, On_Message'Unrestricted_Access);
      AHT.Websocket.Client.Connect (Client_Ref, Echo);
      AHT.Websocket.Client.Send_Text (Client_Ref, "provoke");

      while not Reentry.Done and then Waited < 10.0 loop
         delay 0.05;
         Waited := Waited + 0.05;
      end loop;

      if not Reentry.Done then
         Fail ("reentrancy: the callback did not finish its checks ("
               & Reentry.Report
               & "), so nothing conclusive was called from the "
               & "receiver");
      else
         declare
            R : constant String := Reentry.Report;
         begin
            if R /= "close=refused reconnect=refused receive=refused "
                    & "send=ok "
            then
               Fail ("reentrancy: got """ & R
                     & """, expected close/reconnect/receive refused "
                     & "and send ok");
            end if;
         end;
      end if;

      AHT.Websocket.Client.Close (Client_Ref);
   end;

   if Failures = 0 then
      Put_Line ("test_ws_reconnect: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_reconnect:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Reconnect;
