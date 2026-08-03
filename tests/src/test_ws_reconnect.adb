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
--    5. Across transport kinds, wss to ws, checking that the
--       subprotocol is a property of the connection rather than of
--       the client — a session carries its own transport variant, so
--       the two generations here are not even the same shape.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

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
                  & " (is server_ws_limits.py running?)");
            Put_Line ("test_ws_reconnect:" & Failures'Image & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;
      Expect_Generation ("receiver-teardown", C, 1);

      if not Await_Closed (C, 10.0) then
         Fail ("receiver-teardown: the connection never went down");
      end if;

      --  Between connections, so the limits may be changed again.
      AHT.Websocket.Client.Configure
        (C, AHT.Websocket.Client.Limits'(others => <>));

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

   if Failures = 0 then
      Put_Line ("test_ws_reconnect: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_reconnect:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Reconnect;
