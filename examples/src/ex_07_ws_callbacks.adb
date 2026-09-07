--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Example 7: the push API. Set_On_Message, Set_On_Close and
--  Set_On_Error install callbacks that the client's receiver task
--  calls as frames arrive from the echo fixture on :8765. Callbacks
--  run on the receiver task, so each writes through a protected
--  object and the main task reads the tally afterwards.
--
--  Run:  ./examples/bin/<mode>/ex_07_ws_callbacks [URL]

with Ada.Command_Line; use Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO;      use Ada.Text_IO;

with AHT.Bytes;
with AHT.Websocket;
with AHT.Websocket.Client;

procedure Ex_07_WS_Callbacks is

   Default_URL : constant String := "ws://127.0.0.1:8765/";

   URL : constant String :=
     (if Argument_Count >= 1 then Argument (1) else Default_URL);

   --  Shared sink: the receiver task writes through it from the
   --  callbacks; the main task reads the totals once everything is done.
   protected Sink is
      procedure Note_Message (Text : String);
      procedure Note_Close;
      procedure Note_Error (Text : String);
      function  Messages return Natural;
      function  Closes return Natural;
      function  Errors return Natural;
      function  Last return String;
      function  Last_Error return String;
   private
      Msg_Count   : Natural := 0;
      Close_Count : Natural := 0;
      Err_Count   : Natural := 0;
      Last_Text   : AHT.Bytes.Buffer;
      Last_Err    : AHT.Bytes.Buffer;
   end Sink;

   protected body Sink is
      procedure Note_Message (Text : String) is
      begin
         Msg_Count := Msg_Count + 1;
         Last_Text.Set (Text);
      end Note_Message;
      procedure Note_Close is
      begin
         Close_Count := Close_Count + 1;
      end Note_Close;
      --  Only record the error here: I/O inside a protected action is
      --  a bounded error in Ada. The main task prints the tally
      --  afterwards.
      procedure Note_Error (Text : String) is
      begin
         Err_Count := Err_Count + 1;
         Last_Err.Set (Text);
      end Note_Error;
      function Messages return Natural is (Msg_Count);
      function Closes return Natural is (Close_Count);
      function Errors return Natural is (Err_Count);
      function Last return String is (AHT.Bytes.To_String (Last_Text));
      function Last_Error return String is (AHT.Bytes.To_String (Last_Err));
   end Sink;

   procedure On_Message (Msg : AHT.Websocket.Client.Message_Type) is
   begin
      Sink.Note_Message (AHT.Bytes.To_String (Msg.Payload));
   end On_Message;

   procedure On_Close
     (Info : AHT.Websocket.Close_Info; Reason : String) is
      pragma Unreferenced (Info, Reason);
   begin
      Sink.Note_Close;
   end On_Close;

   procedure On_Error (Message : String) is
   begin
      Sink.Note_Error (Message);
   end On_Error;

   C : AHT.Websocket.Client.Client_Type;
begin
   --  'Unrestricted_Access: the callback access types are library-level
   --  and these handlers are nested here, so plain 'Access is rejected.
   --  The handlers outlive the connection (Close returns before this
   --  scope ends).
   AHT.Websocket.Client.Set_On_Message (C, On_Message'Unrestricted_Access);
   AHT.Websocket.Client.Set_On_Close   (C, On_Close'Unrestricted_Access);
   AHT.Websocket.Client.Set_On_Error   (C, On_Error'Unrestricted_Access);

   Put_Line ("WS connect (callback style) " & URL);
   AHT.Websocket.Client.Connect (C, URL);

   --  Fire off a few messages. The echoes come back on the receiver
   --  task and land in On_Message without us calling Receive.
   for I in 1 .. 3 loop
      AHT.Websocket.Client.Send_Text
        (C, "message" & Integer'Image (I));
   end loop;
   Put_Line ("  sent 3 messages; letting the receiver task drive ...");

   --  Wait (bounded) for the callback count to reach 3; the echoes
   --  arrive on the receiver task, and a fixed sleep could undercount.
   declare
      Waited : Duration := 0.0;
   begin
      while Sink.Messages < 3 and then Waited < 5.0 loop
         delay 0.05;
         Waited := Waited + 0.05;
      end loop;
   end;

   AHT.Websocket.Client.Close (C);

   --  On_Close fires from the receiver during the close handshake; wait
   --  (bounded) for it the same way.
   declare
      Waited : Duration := 0.0;
   begin
      while Sink.Closes < 1 and then Waited < 2.0 loop
         delay 0.05;
         Waited := Waited + 0.05;
      end loop;
   end;

   Put_Line ("  on_message fired :" & Natural'Image (Sink.Messages)
             & " time(s)");
   Put_Line ("  last message     : " & Sink.Last);
   Put_Line ("  on_close fired   :" & Natural'Image (Sink.Closes)
             & " time(s)");
   if Sink.Errors > 0 then
      Put_Line ("  on_error fired   :" & Natural'Image (Sink.Errors)
                & " time(s); last: " & Sink.Last_Error);
   end if;

   Set_Exit_Status (Success);

exception
   when E : others =>
      Put_Line ("ws failed: "
                & Ada.Exceptions.Exception_Name (E) & ": "
                & Ada.Exceptions.Exception_Message (E));
      Put_Line ("(is the fixture up? try: bash examples/run_examples.sh)");
      --  Tear down the receiver task if the socket opened before the
      --  failure (Timeout 0.0 = abort now); otherwise scope exit blocks
      --  on the still-running receiver.
      if AHT.Websocket.Client.Is_Open (C) then
         begin
            AHT.Websocket.Client.Close (C, Timeout => 0.0);
         exception
            when others => null;
         end;
      end if;
      Set_Exit_Status (Failure);
end Ex_07_WS_Callbacks;
