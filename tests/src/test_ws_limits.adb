--  Configured ceilings, end to end.
--
--  test_ws_frames pins the decoder's own arithmetic. This pins that
--  the client actually wires it up: that the allowance it passes is
--  what remains of the *logical message*, that the two overrun kinds
--  are reported as the different failures they are, and that the
--  delivery modes mean what they say.
--
--  Against tests/server/server_ws_limits.py (127.0.0.1:8777), which
--  holds every connection open and keeps draining, so a failure here
--  can only be the client's own limits acting — never the peer going
--  away or stalling.
--
--  Cases:
--    1. Callback_Only with no callback is refused before dialing.
--       Needs no server at all: nothing should reach the network.
--    2. Configure is refused once a session exists, and accepted
--       again once there is none.
--    3. Callback_Only delivers to the callback, and Receive says so
--       rather than blocking on a queue nothing fills.
--    4. A frame declaring more than the ceiling fails the connection
--       with Message_Too_Big, promptly — the peer sends the header
--       and then nothing, so a client that waited for the body would
--       hang here rather than report.
--    5. A fragment sequence crossing the ceiling fails the same way,
--       which only happens if the allowance is tracked across parts:
--       every individual part here is far below the limit.
--    6. Flooding a client that never drains fails with a *different*
--       diagnosis — backpressure, not size — by message count.
--    7. The same by queued bytes, with the count limit set beyond the
--       entire flood so only the byte budget can be what acted.
--    8. Pull_Only does not fire an installed On_Message.
--
--  Every overrun case also checks the close code that reached the
--  peer, not just the local diagnostic: swapping 1008 for 1009 in the
--  client is invisible from this side otherwise, and the code is the
--  half of the contract the peer can see.

with Ada.Calendar; use Ada.Calendar;
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.Websocket;
with AHT.Websocket.Client;

procedure Test_WS_Limits is

   Base : constant String := "ws://127.0.0.1:8777";
   Echo : constant String := "ws://127.0.0.1:8765/";

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_limits: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Collects what the receiver task reports, so the main task can
   --  read it without racing.
   protected Sink is
      procedure Note_Error (Text : String);
      procedure Note_Message;
      function  Errors return Natural;
      function  Last_Error return String;
      function  Messages return Natural;
      procedure Reset;
   private
      Err_Count : Natural := 0;
      Msg_Count : Natural := 0;
      Text_S    : Unbounded_String;
   end Sink;

   protected body Sink is
      procedure Note_Error (Text : String) is
      begin
         Err_Count := Err_Count + 1;
         Text_S    := To_Unbounded_String (Text);
      end Note_Error;
      procedure Note_Message is
      begin
         Msg_Count := Msg_Count + 1;
      end Note_Message;
      function Errors return Natural is (Err_Count);
      function Last_Error return String is (To_String (Text_S));
      function Messages return Natural is (Msg_Count);
      procedure Reset is
      begin
         Err_Count := 0;
         Msg_Count := 0;
         Text_S    := Null_Unbounded_String;
      end Reset;
   end Sink;

   procedure On_Error (Message : String) is
   begin
      Sink.Note_Error (Message);
   end On_Error;

   procedure On_Message (Msg : AHT.Websocket.Client.Message_Type) is
      pragma Unreferenced (Msg);
   begin
      Sink.Note_Message;
   end On_Message;

   --  Wait (bounded) for the receiver to report something, so no case
   --  here depends on a guessed delay.
   function Await_Error (Bound : Duration) return Boolean is
      Waited : Duration := 0.0;
   begin
      while Sink.Errors = 0 and then Waited < Bound loop
         delay 0.02;
         Waited := Waited + 0.02;
      end loop;
      return Sink.Errors > 0;
   end Await_Error;

   function Mentions (Haystack, Needle : String) return Boolean is
     (Ada.Strings.Fixed.Index (Haystack, Needle) /= 0);

   --  What close code actually reached the peer on the connection
   --  just torn down. The fixture records it and forgets it on read,
   --  so a stale value cannot carry one case's result into the next.
   function Observed_Close return String is
      C   : AHT.Websocket.Client.Client_Type;
      Msg : AHT.Websocket.Client.Message_Type;
   begin
      AHT.Websocket.Client.Connect (C, Base & "/report");
      AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);
      declare
         Text : constant String := AHT.Bytes.To_String (Msg.Payload);
      begin
         AHT.Websocket.Client.Close (C, Timeout => 1.0);
         return Text;
      end;
   exception
      when E : others =>
         return "unavailable (" & Ada.Exceptions.Exception_Name (E) & ")";
   end Observed_Close;

   --  Drive one overrun scenario: check what the receiver reported
   --  locally AND what it put on the wire. The local text alone would
   --  not catch the two close codes being swapped, and the code is the
   --  half of the contract the peer can actually see.
   procedure Expect_Failure
     (What    : String;
      Path    : String;
      L       : AHT.Websocket.Client.Limits;
      Marker  : String;
      Code    : String;
      Bound   : Duration := 10.0)
   is
      C : AHT.Websocket.Client.Client_Type;
      Started, Ended : Time;
   begin
      Sink.Reset;
      AHT.Websocket.Client.Set_On_Error (C, On_Error'Unrestricted_Access);
      AHT.Websocket.Client.Configure (C, L);

      begin
         AHT.Websocket.Client.Connect (C, Base & Path);
      exception
         when E : others =>
            Fail (What & ": Connect raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E)
                  & " (is server_ws_limits.py running?)");
            return;
      end;

      Started := Clock;
      if not Await_Error (Bound) then
         Fail (What & ": the receiver reported nothing within"
               & Duration'Image (Bound) & "s — the ceiling never bit");
      else
         Ended := Clock;
         if not Mentions (Sink.Last_Error, Marker) then
            Fail (What & ": reported """ & Sink.Last_Error
                  & """, which does not mention " & Marker);
         end if;
         if Ended - Started > Bound then
            Fail (What & ": took" & Duration'Image (Ended - Started) & "s");
         end if;
      end if;

      AHT.Websocket.Client.Close (C, Timeout => 1.0);

      declare
         Seen : constant String := Observed_Close;
      begin
         if Seen /= "close=" & Code then
            Fail (What & ": the peer saw """ & Seen
                  & """, expected ""close=" & Code & """");
         end if;
      end;
   end Expect_Failure;

begin
   --  Case 1: Callback_Only with no callback never reaches the wire.
   declare
      C : AHT.Websocket.Client.Client_Type;
      L : AHT.Websocket.Client.Limits;
   begin
      L.Delivery := AHT.Websocket.Client.Callback_Only;
      AHT.Websocket.Client.Configure (C, L);
      begin
         --  A port nothing is listening on: if admission is doing its
         --  job this never gets far enough to notice.
         AHT.Websocket.Client.Connect (C, "ws://127.0.0.1:1/");
         Fail ("no-callback: Connect returned without raising");
      exception
         when AHT.Websocket.Mode_Error => null;
         when E : others =>
            Fail ("no-callback: expected Mode_Error, got "
                  & Ada.Exceptions.Exception_Name (E)
                  & " — the attempt reached the network before the "
                  & "delivery mode was checked");
      end;
   end;

   --  Case 2: Configure is a between-connections operation.
   declare
      C : AHT.Websocket.Client.Client_Type;
      L : AHT.Websocket.Client.Limits;
   begin
      L.Max_Inbox_Messages := 8;
      AHT.Websocket.Client.Configure (C, L);          --  Idle: fine

      begin
         AHT.Websocket.Client.Connect (C, Echo);
      exception
         when E : others =>
            Fail ("configure: Connect raised "
                  & Ada.Exceptions.Exception_Name (E)
                  & " (is server_ws.py running?)");
            Put_Line ("test_ws_limits:" & Failures'Image & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;

      begin
         AHT.Websocket.Client.Configure (C, L);
         Fail ("configure: accepted while the connection was open");
      exception
         when AHT.Websocket.Mode_Error => null;
         when E : others =>
            Fail ("configure: expected Mode_Error, got "
                  & Ada.Exceptions.Exception_Name (E));
      end;

      AHT.Websocket.Client.Close (C);

      begin
         AHT.Websocket.Client.Configure (C, L);       --  Disconnected
      exception
         when E : others =>
            Fail ("configure: refused after Close: "
                  & Ada.Exceptions.Exception_Name (E));
      end;
   end;

   --  Case 3: Callback_Only delivers, and says so when asked to queue.
   declare
      C   : AHT.Websocket.Client.Client_Type;
      L   : AHT.Websocket.Client.Limits;
      Msg : AHT.Websocket.Client.Message_Type;
      Waited : Duration := 0.0;
   begin
      Sink.Reset;
      L.Delivery := AHT.Websocket.Client.Callback_Only;
      AHT.Websocket.Client.Configure (C, L);
      AHT.Websocket.Client.Set_On_Message (C, On_Message'Unrestricted_Access);

      begin
         AHT.Websocket.Client.Connect (C, Echo);
      exception
         when E : others =>
            Fail ("callback-only: Connect raised "
                  & Ada.Exceptions.Exception_Name (E));
            return;
      end;

      AHT.Websocket.Client.Send_Text (C, "push me");
      while Sink.Messages = 0 and then Waited < 5.0 loop
         delay 0.02;
         Waited := Waited + 0.02;
      end loop;
      if Sink.Messages = 0 then
         Fail ("callback-only: the callback never fired");
      end if;

      begin
         AHT.Websocket.Client.Receive (C, Msg, Timeout => 1.0);
         Fail ("callback-only: Receive returned a message");
      exception
         when AHT.Websocket.Mode_Error => null;
         when E : others =>
            Fail ("callback-only: expected Mode_Error from Receive, got "
                  & Ada.Exceptions.Exception_Name (E));
      end;

      --  The one consumer cannot be taken away while this is up.
      begin
         AHT.Websocket.Client.Set_On_Message (C, null);
         Fail ("callback-only: clearing On_Message was allowed");
      exception
         when AHT.Websocket.Mode_Error => null;
         when E : others =>
            Fail ("callback-only: expected Mode_Error clearing the "
                  & "callback, got " & Ada.Exceptions.Exception_Name (E));
      end;

      AHT.Websocket.Client.Close (C);
   end;

   --  Case 4: a declared payload past the ceiling, with no body ever
   --  sent. Only a decoder-level check can answer this one.
   declare
      L : AHT.Websocket.Client.Limits;
   begin
      L.Max_Message_Bytes := 64 * 1024;
      Expect_Failure
        ("huge-header", "/huge", L, "MESSAGE_TOO_BIG", "1009",
         Bound => 5.0);
   end;

   --  Case 5: a fragment sequence crossing the ceiling. Every part is
   --  64 KiB, well under the limit; only tracking the accumulated
   --  message catches it.
   declare
      L : AHT.Websocket.Client.Limits;
   begin
      L.Max_Message_Bytes := 256 * 1024;
      Expect_Failure
        ("fragment-total", "/frag", L, "MESSAGE_TOO_BIG", "1009");
   end;

   --  Case 6: backpressure by message count. The frames are small and
   --  legal, and the size ceiling is generous — what fails is that
   --  nothing is draining. The byte budget is deliberately far out of
   --  reach so this case can only be the count limit acting.
   declare
      L : AHT.Websocket.Client.Limits;
   begin
      L.Delivery           := AHT.Websocket.Client.Pull_Only;
      L.Max_Message_Bytes  := 32 * 1024 * 1024;
      L.Max_Inbox_Messages := 16;
      L.Max_Inbox_Bytes    := 32 * 1024 * 1024;
      Expect_Failure ("inbox-count", "/flood", L, "inbox full", "1008");
   end;

   --  Case 7: backpressure by queued bytes.
   --
   --  The count limit is set beyond the whole flood, so it cannot be
   --  what acts here — only the byte budget can. That matters: with a
   --  merely large count the byte check could be deleted and the
   --  count limit would still fire, later, reporting the same thing.
   --  This way removing it leaves nothing to refuse the flood at all.
   declare
      L : AHT.Websocket.Client.Limits;
   begin
      L.Delivery           := AHT.Websocket.Client.Pull_Only;
      L.Max_Message_Bytes  := 32 * 1024 * 1024;
      L.Max_Inbox_Messages := 32_768;       --  > the fixture's flood
      L.Max_Inbox_Bytes    := 4 * 1024;     --  ~16 messages' worth
      Expect_Failure ("inbox-bytes", "/flood", L, "inbox full", "1008");
   end;

   --  Case 8: Pull_Only does not fire On_Message. A callback outliving
   --  a reconfiguration must not start delivering behind the
   --  application's back, so this installs one and requires silence
   --  from it while Receive still works.
   declare
      C   : AHT.Websocket.Client.Client_Type;
      L   : AHT.Websocket.Client.Limits;
      Msg : AHT.Websocket.Client.Message_Type;
   begin
      Sink.Reset;
      L.Delivery := AHT.Websocket.Client.Pull_Only;
      AHT.Websocket.Client.Configure (C, L);
      AHT.Websocket.Client.Set_On_Message (C, On_Message'Unrestricted_Access);

      begin
         AHT.Websocket.Client.Connect (C, Echo);
      exception
         when E : others =>
            Fail ("pull-only: Connect raised "
                  & Ada.Exceptions.Exception_Name (E));
            return;
      end;

      AHT.Websocket.Client.Send_Text (C, "pull me");
      begin
         AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);
      exception
         when E : others =>
            Fail ("pull-only: Receive raised "
                  & Ada.Exceptions.Exception_Name (E));
      end;

      --  Settle: the callback would fire from the receiver task right
      --  after the push, so give it every chance to before concluding
      --  it stayed quiet.
      delay 0.2;
      if Sink.Messages /= 0 then
         Fail ("pull-only: On_Message fired"
               & Natural'Image (Sink.Messages)
               & " time(s) under Pull_Only");
      end if;

      AHT.Websocket.Client.Close (C);
   end;

   if Failures = 0 then
      Put_Line ("test_ws_limits: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_limits:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Limits;
