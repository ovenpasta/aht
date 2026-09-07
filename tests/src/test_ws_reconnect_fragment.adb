--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Reconnecting out of a half-received message. The decoder holds
--  fragments until the FIN frame arrives, and that accumulator
--  belongs to the connection, not the client. The hostile fixture's
--  fragstall route opens a text message with FIN = 0 and stops,
--  holding the socket open; what follows must deliver a clean message.
--
--  Cases:
--    1. Close, then Connect to the echo peer: the first message is
--       exactly what the peer sent back
--    2. Reconnect, which redials the stalling fixture, so generation
--       two is mid-fragment too; then a second teardown
--
--  Covers:
--    - the reassembly flag surviving: the next Text frame violates
--      RFC 6455 5.4 and the test observes Closed_Error, not a payload
--    - only the buffer surviving: the leftovers (STALE-FRAGMENT-) are
--      prepended to the next message
--    - the client was holding an incomplete message: a Ping sent
--      after the fragment is answered, so the fragment was consumed
--    - case 2 reaches the drain-and-redial path, which case 1 does not
--
--  Validated by:
--    with the reassembly state hoisted out of Run_Session, case 1
--    reports Closed_Error.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.Transport;
with AHT.Websocket;
with AHT.Websocket.Client;

procedure Test_WS_Reconnect_Fragment is

   Echo   : constant String := "ws://127.0.0.1:8765/";

   --  Tokenised, so the Pong that proves consumption is tied to the
   --  connection that produced it.
   function Stall (Token : String) return String is
     ("ws://127.0.0.1:8777/fragstall/" & Token);

   --  What the fixture leaves in the accumulator. Kept in step with
   --  FRAGSTALL_PART in server_ws_hostile.py.
   Stale : constant String := "STALE-FRAGMENT-";

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_reconnect_fragment: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function To_String (V : AHT.Bytes.Buffer) return String is
     (AHT.Bytes.To_String (V));

   --  Ask the fixture whether the connection tagged Token produced a
   --  Pong, on a second, ordinary connection. Q is closed on every
   --  path: left open, its receiver parks on a socket the fixture
   --  holds for thirty seconds and scope exit waits for it. Close is
   --  itself wrapped so its failure cannot displace the diagnosis.
   procedure Saw_Pong
     (Token : String;
      Seen  : out Boolean;
      Why   : out Unbounded_String)
   is
      Q   : AHT.Websocket.Client.Client_Type;
      Msg : AHT.Websocket.Client.Message_Type;

      procedure Shut_Down is
      begin
         AHT.Websocket.Client.Close (Q, Timeout => 1.0);
      exception
         when others => null;
      end Shut_Down;
   begin
      Seen := False;
      Why  := Null_Unbounded_String;

      AHT.Websocket.Client.Connect
        (Q, "ws://127.0.0.1:8777/pong/" & Token);
      begin
         AHT.Websocket.Client.Receive (Q, Msg, Timeout => 8.0);
         declare
            Answer : constant String := To_String (Msg.Payload);
         begin
            Seen := Answer = "pong=yes";
            if not Seen then
               Why := To_Unbounded_String
                 ("the fixture answered """ & Answer & """");
            end if;
         end;
      exception
         when E : others =>
            Why := To_Unbounded_String
              ("reading the report raised "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E));
      end;
      Shut_Down;
   exception
      when E : others =>
         --  Could not even reach the fixture to ask.
         Why := To_Unbounded_String
           ("the report connection raised "
            & Ada.Exceptions.Exception_Name (E) & ": "
            & Ada.Exceptions.Exception_Message (E));
         Shut_Down;
   end Saw_Pong;

   --  Confirm the client is holding an incomplete message: nothing
   --  is delivered (no FIN) and the fragment was received. A timeout
   --  alone cannot tell a fixture that sent nothing from a fragment
   --  consumed, so the fixture sends a Ping after the fragment;
   --  frames are processed in order, so the Pong proves the fragment
   --  ahead of it was consumed.
   procedure Expect_Held_Incomplete
     (What  : String;
      C     : in out AHT.Websocket.Client.Client_Type;
      Token : String)
   is
      Msg : AHT.Websocket.Client.Message_Type;
   begin
      begin
         AHT.Websocket.Client.Receive (C, Msg, Timeout => 1.0);
         Fail (What & ": Receive delivered """ & To_String (Msg.Payload)
               & """ from a message that has no final frame");
         return;
      exception
         when AHT.Transport.Timeout_Error =>
            null;   --  correct: incomplete, so nothing to deliver
         when E : others =>
            Fail (What & ": waiting on the incomplete message raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
            return;
      end;

      declare
         Seen : Boolean;
         Why  : Unbounded_String;
      begin
         Saw_Pong (Token, Seen, Why);
         if not Seen then
            Fail (What & ": the fixture never saw a Pong, so the "
                  & "fragment was never consumed — nothing was being "
                  & "held, and the silence above proves nothing about "
                  & "reassembly state (" & To_String (Why) & ")");
         end if;
      end;
   end Expect_Held_Incomplete;

   --  Round-trip on a connection that is expected to be clean, and
   --  say what went wrong when it is not.
   procedure Expect_Clean_Echo
     (What : String;
      C    : in out AHT.Websocket.Client.Client_Type;
      Text : String)
   is
      Msg : AHT.Websocket.Client.Message_Type;
   begin
      AHT.Websocket.Client.Send_Text (C, Text);
      AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);
      declare
         Got : constant String := To_String (Msg.Payload);
      begin
         if Got = Text then
            return;
         end if;
         if Ada.Strings.Fixed.Index (Got, Stale) /= 0 then
            Fail (What & ": the new connection's first message came "
                  & "back as """ & Got & """ — the previous "
                  & "connection's half-received message was still in "
                  & "the accumulator");
         else
            Fail (What & ": echoed """ & Got & """, expected """
                  & Text & """");
         end if;
      end;
   exception
      when E : others =>
         Fail (What & ": the round-trip raised "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E));
   end Expect_Clean_Echo;

begin
   --  Case 1: torn down explicitly, then dialled somewhere else. The
   --  two connections are not even to the same peer, so nothing about
   --  the second one could legitimately carry the first one's bytes.
   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      begin
         AHT.Websocket.Client.Connect (C, Stall ("a1"));
      exception
         when E : others =>
            Fail ("close-then-connect: Connect raised "
                  & Ada.Exceptions.Exception_Name (E)
                  & " (is server_ws_hostile.py running?)");
            Put_Line ("test_ws_reconnect_fragment:" & Failures'Image
                      & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;

      Expect_Held_Incomplete ("close-then-connect", C, "a1");
      AHT.Websocket.Client.Close (C);

      begin
         AHT.Websocket.Client.Connect (C, Echo);
      exception
         when E : others =>
            Fail ("close-then-connect: the second Connect raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
      end;
      Expect_Clean_Echo ("close-then-connect", C, "first clean message");
      AHT.Websocket.Client.Close (C);
   end;

   --  Case 2: Reconnect, which drains and redials in one operation
   --  and lands back on the same stalling fixture. Generation two is
   --  therefore mid-fragment as well, and the reset has to have
   --  happened on this path too, so after a second teardown the clean
   --  peer still sees a clean first message.
   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      AHT.Websocket.Client.Connect (C, Stall ("b1"));
      Expect_Held_Incomplete ("reconnect", C, "b1");

      begin
         AHT.Websocket.Client.Reconnect (C);
      exception
         when E : others =>
            Fail ("reconnect: Reconnect from mid-fragment raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
      end;

      if AHT.Websocket.Client.Generation (C) /= 2 then
         Fail ("reconnect: Generation ="
               & Natural'Image (AHT.Websocket.Client.Generation (C))
               & " after Reconnect (expected 2)");
      end if;

      --  Generation two is mid-fragment in its own right: a fresh
      --  accumulator, not the old one topped up. Same token as
      --  generation one: await_pong consumed that record above, so a
      --  "yes" here can only come from a Pong this generation
      --  produced.
      Expect_Held_Incomplete ("reconnect", C, "b1");

      AHT.Websocket.Client.Close (C);
      AHT.Websocket.Client.Connect (C, Echo);
      Expect_Clean_Echo ("reconnect", C, "clean after two stalls");
      AHT.Websocket.Client.Close (C);
   end;

   if Failures = 0 then
      Put_Line ("test_ws_reconnect_fragment: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_reconnect_fragment:" & Failures'Image
                & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Reconnect_Fragment;
