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
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.Transport;
with AHT.Websocket;
with AHT.Websocket.Client;

procedure Test_WS_Reconnect_Fragment is

   Echo   : constant String := "ws://127.0.0.1:8765/";
   Stall  : constant String := "ws://127.0.0.1:8777/fragstall";

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

   --  Confirm the client really is holding an incomplete message.
   --
   --  Without this the test could pass for the wrong reason: if the
   --  fragment never arrived, there would be no reassembly state to
   --  survive, and a client that carries such state forward would
   --  still look clean. Nothing may be delivered here — the message
   --  has no FIN — so a Receive that returns is itself the failure.
   procedure Expect_Nothing_Deliverable
     (What : String;
      C    : in out AHT.Websocket.Client.Client_Type)
   is
      Msg : AHT.Websocket.Client.Message_Type;
   begin
      AHT.Websocket.Client.Receive (C, Msg, Timeout => 1.0);
      Fail (What & ": Receive delivered """ & To_String (Msg.Payload)
            & """ from a message that has no final frame");
   exception
      when AHT.Transport.Timeout_Error =>
         null;   --  correct: incomplete, so nothing to deliver
      when E : others =>
         Fail (What & ": waiting on the incomplete message raised "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E));
   end Expect_Nothing_Deliverable;

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
         AHT.Websocket.Client.Connect (C, Stall);
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

      Expect_Nothing_Deliverable ("close-then-connect", C);
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
      AHT.Websocket.Client.Connect (C, Stall);
      Expect_Nothing_Deliverable ("reconnect", C);

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
      Expect_Nothing_Deliverable ("reconnect", C);

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
