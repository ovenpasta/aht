--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Reconnecting out of a half-received message.
--
--  A fragmented WebSocket message is spread over several frames, and
--  the decoder holds the parts it has seen until the one with FIN
--  arrives. That accumulator belongs to the connection, not to the
--  client — but it is exactly the kind of state that gets hoisted for
--  convenience, and once it is, a reconnect inherits it: the first
--  message of the new generation arrives with the previous
--  connection's leftovers glued to the front of it.
--
--  The fixture opens a text message with FIN = 0 and then stops,
--  holding the socket open. The client is left mid-message with no
--  way to finish it, which is the state under test. What follows must
--  deliver a clean message and nothing else.
--
--  Carried-over state has two shapes and they fail differently, so
--  both are checked:
--
--    * The reassembly FLAG survives. The next generation's first Text
--      frame then arrives while the decoder still believes a message
--      is open, which is an RFC 6455 §5.4 violation — so the
--      connection is closed and what this test observes is
--      Closed_Error, not a payload. Hoisting the state out of
--      Run_Session produces exactly this, and is how the test was
--      validated.
--    * Only the BUFFER survives. With the flag reset, the leftovers
--      are simply prepended to the next message, and the recognisable
--      payload (STALE-FRAGMENT-) is what names the cause — a length
--      mismatch on its own would not.
--
--  Cases:
--    1. Close, then Connect elsewhere. The new generation's first
--       message must be exactly what the echo peer sent back.
--    2. Reconnect, which redials the stalling fixture — so generation
--       two is mid-fragment too. This is the path case 1 does not
--       reach: Close tears down before the redial, Reconnect drains
--       and redials as one operation, and the reset has to happen
--       there as well.

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
   --  connection that produced it rather than to whatever happened
   --  most recently on the fixture.
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

   --  Ask the fixture whether the connection tagged `Token` produced a
   --  Pong. It answers on a second, ordinary connection.
   --
   --  Q is closed on EVERY path, including the failing ones. Simply
   --  returning would leave its receiver task parked on a socket this
   --  fixture holds open for thirty seconds, and Ada waits for
   --  dependent tasks at scope exit — so a failed report would stall
   --  the test for half a minute rather than reporting promptly.
   --  Close is itself wrapped, because by then the connection may
   --  already be gone and its failure must not displace the original
   --  diagnosis.
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

   --  Confirm the client really is holding an incomplete message.
   --
   --  Two things have to be true, and checking only the first is what
   --  makes this kind of check quietly useless: nothing may be
   --  delivered (the message has no FIN), AND the fragment must
   --  actually have been received. A timeout alone cannot tell those
   --  apart — a fixture that sent nothing at all produces exactly the
   --  same silence, and then a client that DOES carry reassembly
   --  state forward would still look clean here.
   --
   --  So the fixture sends a Ping after the fragment. Frames are
   --  processed in order, so the Pong coming back proves the fragment
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
   --  say precisely what went wrong when it is not.
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
   --  happened on this path too — so after a second teardown the
   --  clean peer still sees a clean first message.
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

      --  Generation two is mid-fragment in its own right: one
      --  accumulator was discarded and a fresh one started, rather
      --  than the old one being carried forward and topped up.
      --
      --  Deliberately the SAME token as generation one, and safe
      --  because await_pong consumes its record: the first
      --  generation's Pong was already taken by the check above, so
      --  the fixture has nothing left to answer with and a "yes" here
      --  can only come from a Pong this generation produced. A stale
      --  answer would report the fragment as consumed when this
      --  connection had never received one.
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
