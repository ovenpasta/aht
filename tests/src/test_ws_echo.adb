--  End-to-end WebSocket exercise against the Python `websockets`
--  echo fixture on 127.0.0.1:8765 (commit 2 of the WS client work
--  — handshake + frame I/O + clean close handshake).
--
--  Five cases:
--    1. Text round-trip — Connect, Send_Text "hello, AHT!",
--       Receive, assert Kind = Text_Message and the bytes match.
--       Then Close cleanly and assert Is_Open flips to False.
--    2. Binary round-trip — Send_Binary (16 byte payload), Receive
--       a Binary_Message with identical bytes.
--    3. Receive timeout — Connect, do not send anything, Receive
--       with Timeout = 0.2s → Transport.Timeout_Error within a
--       tight window; the connection is still usable afterwards.
--    4. Receive after Close raises Closed_Error — Close the
--       connection, then call Receive; the receiver task has
--       Mark_Closed'd the Inbox so the entry barrier opens and
--       raises.
--    5. Multi-message ordering — Send three text messages in
--       sequence, Receive three messages, assert payloads come
--       back in send order (websockets preserves ordering).

with Ada.Calendar; use Ada.Calendar;
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;
with Ada.Unchecked_Deallocation;

with AHT.Bytes;
with AHT.Transport;
with AHT.Websocket;
with AHT.Websocket.Client;

procedure Test_WS_Echo is

   use type AHT.Bytes.Octet;
   use type AHT.Websocket.Message_Kind;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_echo: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function To_String (V : AHT.Bytes.Byte_Vector) return String is
      S : String (1 .. Natural (V.Length));
   begin
      for I in S'Range loop
         S (I) := Character'Val
           (Natural (V.Element (V.First_Index + I - 1)));
      end loop;
      return S;
   end To_String;

begin
   --  Case 1: text round-trip + clean Close.
   declare
      C   : AHT.Websocket.Client.Client_Type;
      Msg : AHT.Websocket.Client.Message_Type;
   begin
      begin
         AHT.Websocket.Client.Connect
           (C, "ws://127.0.0.1:8765/");
      exception
         when E : others =>
            Fail ("text: Connect raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E)
                  & " (is server_ws.py running?)");
            Put_Line ("test_ws_echo:" & Failures'Image
                      & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;

      AHT.Websocket.Client.Send_Text (C, "hello, AHT!");

      begin
         AHT.Websocket.Client.Receive
           (C, Msg, Timeout => 5.0);
      exception
         when E : others =>
            Fail ("text: Receive raised "
                  & Ada.Exceptions.Exception_Name (E));
      end;

      if Msg.Kind /= AHT.Websocket.Text_Message then
         Fail ("text: Kind = " & Msg.Kind'Image
               & " (expected Text_Message)");
      end if;
      if To_String (Msg.Payload) /= "hello, AHT!" then
         Fail ("text: payload = """ & To_String (Msg.Payload)
               & """ (expected ""hello, AHT!"")");
      end if;

      AHT.Websocket.Client.Close (C);
      if AHT.Websocket.Client.Is_Open (C) then
         Fail ("text: Is_Open true after Close");
      end if;
   end;

   --  Case 2: binary round-trip — payload is the 16 bytes
   --  0x00..0x0F so a byte-by-byte comparison catches any
   --  masking / framing slip.
   declare
      C   : AHT.Websocket.Client.Client_Type;
      Msg : AHT.Websocket.Client.Message_Type;
      Data : AHT.Bytes.Byte_Array (1 .. 16);
   begin
      AHT.Websocket.Client.Connect (C, "ws://127.0.0.1:8765/");
      for I in Data'Range loop
         Data (I) := AHT.Bytes.Octet (I - 1);
      end loop;

      AHT.Websocket.Client.Send_Binary (C, Data);
      AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);

      if Msg.Kind /= AHT.Websocket.Binary_Message then
         Fail ("bin: Kind = " & Msg.Kind'Image
               & " (expected Binary_Message)");
      end if;
      if Natural (Msg.Payload.Length) /= Data'Length then
         Fail ("bin: payload length ="
               & Natural'Image (Natural (Msg.Payload.Length)));
      else
         for I in Data'Range loop
            if Msg.Payload.Element (I) /= Data (I) then
               Fail ("bin: byte" & I'Image & " differs");
               exit;
            end if;
         end loop;
      end if;

      AHT.Websocket.Client.Close (C);
   end;

   --  Case 3: Receive timeout on an idle connection. The fixture
   --  only echoes, so Receive blocks until either a message
   --  arrives or the Timeout elapses. The bound is generous (0.5
   --  s) so a slow CI box doesn't flake.
   declare
      C   : AHT.Websocket.Client.Client_Type;
      Msg : AHT.Websocket.Client.Message_Type;
      Started, Ended : Time;
      Got_Timeout : Boolean := False;
   begin
      AHT.Websocket.Client.Connect (C, "ws://127.0.0.1:8765/");
      Started := Clock;
      begin
         AHT.Websocket.Client.Receive
           (C, Msg, Timeout => 0.2);
         Fail ("timeout: Receive returned without raising");
      exception
         when AHT.Transport.Timeout_Error =>
            Got_Timeout := True;
         when E : others =>
            Fail ("timeout: wrong exception "
                  & Ada.Exceptions.Exception_Name (E));
      end;
      Ended := Clock;
      if Got_Timeout and then Ended - Started > 0.5 then
         Fail ("timeout: Receive took"
               & Duration'Image (Ended - Started)
               & "s (Timeout was 0.2)");
      end if;

      --  Connection still usable — round-trip a message to confirm.
      AHT.Websocket.Client.Send_Text (C, "still alive");
      AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);
      if To_String (Msg.Payload) /= "still alive" then
         Fail ("timeout: post-timeout echo failed");
      end if;
      AHT.Websocket.Client.Close (C);
   end;

   --  Case 4: Receive after Close raises Closed_Error. The
   --  receiver task Mark_Closed's the Inbox during its shutdown,
   --  which opens the entry barrier and lets queued Receives
   --  observe the close cleanly.
   declare
      C   : AHT.Websocket.Client.Client_Type;
      Msg : AHT.Websocket.Client.Message_Type;
   begin
      AHT.Websocket.Client.Connect (C, "ws://127.0.0.1:8765/");
      AHT.Websocket.Client.Close (C);
      begin
         AHT.Websocket.Client.Receive
           (C, Msg, Timeout => 1.0);
         Fail ("post-close: Receive returned without raising");
      exception
         when AHT.Websocket.Closed_Error => null;
         when E : others =>
            Fail ("post-close: wrong exception "
                  & Ada.Exceptions.Exception_Name (E));
      end;
   end;

   --  Case 5: send three messages, receive them in order.
   declare
      C : AHT.Websocket.Client.Client_Type;
      M1, M2, M3 : AHT.Websocket.Client.Message_Type;
   begin
      AHT.Websocket.Client.Connect (C, "ws://127.0.0.1:8765/");
      AHT.Websocket.Client.Send_Text (C, "first");
      AHT.Websocket.Client.Send_Text (C, "second");
      AHT.Websocket.Client.Send_Text (C, "third");
      AHT.Websocket.Client.Receive (C, M1, Timeout => 5.0);
      AHT.Websocket.Client.Receive (C, M2, Timeout => 5.0);
      AHT.Websocket.Client.Receive (C, M3, Timeout => 5.0);
      if To_String (M1.Payload) /= "first"
        or else To_String (M2.Payload) /= "second"
        or else To_String (M3.Payload) /= "third"
      then
         Fail ("order: """ & To_String (M1.Payload) & """ / """
               & To_String (M2.Payload) & """ / """
               & To_String (M3.Payload) & """");
      end if;
      AHT.Websocket.Client.Close (C);
   end;

   --  Case 6: single-use lifecycle. After Close, a second Connect
   --  on the same Client_Type must fail upfront with
   --  Handshake_Error — not silently re-dial and crash inside the
   --  one-shot Receiver_Task.
   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      AHT.Websocket.Client.Connect (C, "ws://127.0.0.1:8765/");
      AHT.Websocket.Client.Close (C);
      begin
         AHT.Websocket.Client.Connect (C, "ws://127.0.0.1:8765/");
         Fail ("reuse: second Connect returned without raising");
      exception
         when AHT.Websocket.Handshake_Error => null;
         when E : others =>
            Fail ("reuse: wrong exception "
                  & Ada.Exceptions.Exception_Name (E));
      end;
   end;

   --  Case 7: callbacks fire from the receiver task. The On_Message
   --  callback writes into a protected sink so the main task can
   --  observe how many messages it saw without racing. The
   --  On_Close callback bumps a separate counter on the §1.4
   --  close echo.
   declare
      protected Sink is
         procedure Note_Message (S : String);
         procedure Note_Close (Has_Code : Boolean; Code : Natural);
         function  Message_Count return Natural;
         function  Close_Count return Natural;
         function  Last_Message return String;
         function  Saw_Close_Code return Boolean;
      private
         Msgs    : Natural := 0;
         Closes  : Natural := 0;
         Last    : Unbounded_String;
         Has_Code_F : Boolean := False;
         Saw_Code   : Natural := 0;
      end Sink;

      protected body Sink is
         procedure Note_Message (S : String) is
         begin
            Msgs := Msgs + 1;
            Last := To_Unbounded_String (S);
         end Note_Message;
         procedure Note_Close
           (Has_Code : Boolean; Code : Natural) is
         begin
            Closes := Closes + 1;
            Has_Code_F := Has_Code;
            Saw_Code := Code;
         end Note_Close;
         function Message_Count return Natural is (Msgs);
         function Close_Count return Natural is (Closes);
         function Last_Message return String is (To_String (Last));
         function Saw_Close_Code return Boolean is (Has_Code_F);
      end Sink;

      procedure On_Message
        (Msg : AHT.Websocket.Client.Message_Type) is
      begin
         Sink.Note_Message (To_String (Msg.Payload));
      end On_Message;

      procedure On_Close
        (Info : AHT.Websocket.Close_Info; Reason : String) is
         pragma Unreferenced (Reason);
      begin
         Sink.Note_Close
           (Info.Has_Code,
            (if Info.Has_Code then Info.Code else 0));
      end On_Close;

      C : AHT.Websocket.Client.Client_Type;
      Msg : AHT.Websocket.Client.Message_Type;
   begin
      AHT.Websocket.Client.Set_On_Message
        (C, On_Message'Unrestricted_Access);
      AHT.Websocket.Client.Set_On_Close
        (C, On_Close'Unrestricted_Access);

      AHT.Websocket.Client.Connect (C, "ws://127.0.0.1:8765/");
      AHT.Websocket.Client.Send_Text (C, "callback-payload");
      AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);
      AHT.Websocket.Client.Close (C);

      --  Settle: receiver task may still be in the middle of
      --  firing On_Close when Close returns. Wait briefly.
      delay 0.1;

      if Sink.Message_Count = 0 then
         Fail ("callbacks: On_Message never fired");
      end if;
      if Sink.Last_Message /= "callback-payload" then
         Fail ("callbacks: On_Message last payload = """
               & Sink.Last_Message & """");
      end if;
      if Sink.Close_Count = 0 then
         Fail ("callbacks: On_Close never fired");
      end if;
   end;

   --  Case 8: large binary round-trip — the §9 throughput guard.
   --  A single ~1 MB frame is the worst case for the receiver: the
   --  old accumulator drained each consumed frame with a per-byte
   --  Delete_First (O(N²)) and recopied the whole unconsumed buffer
   --  on every read, so a megabyte echo would not come back within
   --  the timeout. With the index-cursor Recv_Buffer the path is
   --  linear. The payload is a deterministic byte ramp so the
   --  full-length comparison catches any framing / block-move slip.
   declare
      C    : AHT.Websocket.Client.Client_Type;
      Msg  : AHT.Websocket.Client.Message_Type;
      Size : constant := 1_000_000;
      Data : AHT.Bytes.Byte_Array (1 .. Size);
      Got  : Boolean := False;
   begin
      for I in Data'Range loop
         Data (I) := AHT.Bytes.Octet ((I - 1) mod 256);
      end loop;

      AHT.Websocket.Client.Connect (C, "ws://127.0.0.1:8765/");
      AHT.Websocket.Client.Send_Binary (C, Data);

      begin
         AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);
         Got := True;
      exception
         when E : others =>
            Fail ("large: Receive raised "
                  & Ada.Exceptions.Exception_Name (E)
                  & " (did the O(N^2) receive drain regress?)");
      end;

      if Got then
         if Msg.Kind /= AHT.Websocket.Binary_Message then
            Fail ("large: Kind = " & Msg.Kind'Image
                  & " (expected Binary_Message)");
         elsif Natural (Msg.Payload.Length) /= Size then
            Fail ("large: payload length ="
                  & Natural'Image (Natural (Msg.Payload.Length))
                  & " (expected" & Integer'Image (Size) & ")");
         else
            for I in Data'Range loop
               if Msg.Payload.Element (I) /= Data (I) then
                  Fail ("large: byte" & I'Image & " differs");
                  exit;
               end if;
            end loop;
         end if;
      end if;

      AHT.Websocket.Client.Close (C);
   end;

   --  Case 9: large text round-trip (>12 MB) — the §9 *send*-path
   --  guard. Send_Text builds the wire frame through
   --  AHT.Bytes.From_String -> Frames.Encode -> TCP Write; before those
   --  three were reworked to keep their working buffers off the fixed
   --  thread stack, a multi-MB send raised Storage_Error (the RFC 6455
   --  §9 8M/16M Autobahn cases). The source string is heap-allocated so
   --  the *test* doesn't overflow its own stack, and it's an ASCII ramp
   --  (valid UTF-8, so the fixture accepts it as a text frame). The
   --  echoed copy is compared byte-for-byte without ever materialising
   --  a multi-MB String on the stack. Needs the fixture's raised
   --  max_size (server_ws.py) to be accepted.
   declare
      type String_Access is access String;
      procedure Free is new Ada.Unchecked_Deallocation
        (String, String_Access);
      C    : AHT.Websocket.Client.Client_Type;
      Msg  : AHT.Websocket.Client.Message_Type;
      Size : constant := 13_000_000;
      Src  : String_Access := new String (1 .. Size);
      Got  : Boolean := False;
   begin
      for I in Src'Range loop
         Src (I) := Character'Val (32 + ((I - 1) mod 95));
      end loop;

      AHT.Websocket.Client.Connect (C, "ws://127.0.0.1:8765/");
      AHT.Websocket.Client.Send_Text (C, Src.all);

      begin
         AHT.Websocket.Client.Receive (C, Msg, Timeout => 30.0);
         Got := True;
      exception
         when E : others =>
            Fail ("large-send: Receive raised "
                  & Ada.Exceptions.Exception_Name (E)
                  & " (did the multi-MB send path regress?)");
      end;

      if Got then
         if Msg.Kind /= AHT.Websocket.Text_Message then
            Fail ("large-send: Kind = " & Msg.Kind'Image
                  & " (expected Text_Message)");
         elsif Natural (Msg.Payload.Length) /= Size then
            Fail ("large-send: payload length ="
                  & Natural'Image (Natural (Msg.Payload.Length))
                  & " (expected" & Integer'Image (Size) & ")");
         else
            for I in Src'Range loop
               if Msg.Payload.Element (I)
                 /= AHT.Bytes.Octet (Character'Pos (Src (I)))
               then
                  Fail ("large-send: byte" & I'Image & " differs");
                  exit;
               end if;
            end loop;
         end if;
      end if;

      AHT.Websocket.Client.Close (C);
      Free (Src);
   end;

   if Failures = 0 then
      Put_Line ("test_ws_echo: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_echo:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Echo;
