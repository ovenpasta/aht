--  Asynchronous transfer of control across the WebSocket client's
--  ownership handoffs.
--
--  Every other test drives the client through ordinary returns and
--  exceptions, so none of them can reach the paths where an Ada task
--  is torn out of a call it is blocked in. Those paths are exactly
--  where hand-written cleanup fails and controlled finalization has
--  to carry the invariant instead, which is why they are worth
--  pinning separately.
--
--  Two cases, both bounded so a regression FAILS rather than hanging
--  the suite:
--
--    1. Abort the winner of a teardown. Winning stops admission and
--       makes that caller the only task that can wake the receiver:
--       every later Close joins and waits. If the abort skips the
--       wake gates, the receiver stays parked in Read and the join
--       cannot complete until the fixture drops the socket seconds
--       later — which is what the timing bound detects.
--
--    2. Abort a connect attempt in flight. The attempt owns an
--       unpublished session and holds the client's admission; if its
--       cleanup does not run, the client is stranded in Connecting
--       and can never be connected again.
--
--  Both fixtures outlast the assertions deliberately, so a failure
--  can only mean the client did the wrong thing, never that the peer
--  went away underneath it.

with Ada.Calendar; use Ada.Calendar;
with Ada.Characters.Handling;
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Streams; use Ada.Streams;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;
with GNAT.Sockets; use GNAT.Sockets;

with GNAT.SHA1;

with AHT.Bytes;
with AHT.URL;
with AHT.Websocket;
with AHT.Websocket.Client;

procedure Test_WS_Abort is

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_abort: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Same computation the client does internally, so the fake server
   --  can answer a valid Accept for whatever Key the client generated.
   function Hex_To_Bytes (Hex : String) return AHT.Bytes.Byte_Array is
      function Val (C : Character) return Natural is
        (case C is
           when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
           when 'a' .. 'f' => 10 + Character'Pos (C) - Character'Pos ('a'),
           when 'A' .. 'F' => 10 + Character'Pos (C) - Character'Pos ('A'),
           when others     => raise Program_Error with "bad hex");
      B : AHT.Bytes.Byte_Array (1 .. Hex'Length / 2);
   begin
      for I in 0 .. B'Length - 1 loop
         B (B'First + I) :=
           AHT.Bytes.Octet
             (16 * Val (Hex (Hex'First + 2 * I))
              +    Val (Hex (Hex'First + 2 * I + 1)));
      end loop;
      return B;
   end Hex_To_Bytes;

   function Compute_Accept (Key : String) return String is
      Guid : constant String := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
      Hex  : constant String := GNAT.SHA1.Digest (Key & Guid);
   begin
      return AHT.Bytes.Base64_Encode (Hex_To_Bytes (Hex));
   end Compute_Accept;

   function Extract_Key (Request_Bytes : String) return String is
      Marker : constant String := "sec-websocket-key:";
      Lower  : constant String :=
        Ada.Characters.Handling.To_Lower (Request_Bytes);
      Idx    : constant Natural :=
        Ada.Strings.Fixed.Index (Lower, Marker);
      Value_Start, Value_End : Natural;
   begin
      if Idx = 0 then
         return "";
      end if;
      Value_Start := Idx + Marker'Length;
      Value_End :=
        Ada.Strings.Fixed.Index
          (Request_Bytes (Value_Start .. Request_Bytes'Last),
           ASCII.CR & ASCII.LF);
      if Value_End = 0 then
         return "";
      end if;
      return Ada.Strings.Fixed.Trim
        (Request_Bytes (Value_Start .. Value_End - 1), Ada.Strings.Both);
   end Extract_Key;

   --  Completes the WebSocket handshake and then goes silent: it never
   --  echoes a Close, so a client waiting for the peer's echo waits
   --  forever and the only thing that can end the wait is the client's
   --  own machinery. Holds well past every assertion below, then drops
   --  the socket so a stranded receiver still terminates and the suite
   --  reports a failure rather than deadlocking.
   task type Silent_Server is
      entry Get_Port (P : out AHT.URL.Port_Number; Err : out Unbounded_String);
      entry Wait_Done;
   end Silent_Server;

   Hold_Seconds : constant Duration := 6.0;

   task body Silent_Server is
      Server      : Socket_Type := No_Socket;
      Client      : Socket_Type;
      Peer        : Sock_Addr_Type;
      Bind_To     : Sock_Addr_Type;
      Bound       : Port_Type := 0;
      Setup_Error : Unbounded_String;
   begin
      begin
         Create_Socket (Server, Family_Inet, Socket_Stream);
         Set_Socket_Option
           (Server, Socket_Level, (Name => Reuse_Address, Enabled => True));
         Bind_To.Addr := Inet_Addr ("127.0.0.1");
         Bind_To.Port := 0;
         Bind_Socket (Server, Bind_To);
         Listen_Socket (Server, 1);
         Bound := Get_Socket_Name (Server).Port;
      exception
         when E : others =>
            Setup_Error := To_Unbounded_String
              ("setup: " & Ada.Exceptions.Exception_Message (E));
      end;

      accept Get_Port
        (P : out AHT.URL.Port_Number; Err : out Unbounded_String)
      do
         P   := (if Length (Setup_Error) > 0
                 then 1 else AHT.URL.Port_Number (Bound));
         Err := Setup_Error;
      end Get_Port;

      if Length (Setup_Error) = 0 then
         begin
            Accept_Socket (Server, Client, Peer);
            declare
               Buf  : Stream_Element_Array (1 .. 4_096);
               Last : Stream_Element_Offset;
               Req  : Unbounded_String;
            begin
               loop
                  Receive_Socket (Client, Buf, Last);
                  exit when Last < Buf'First;
                  for I in Buf'First .. Last loop
                     Append (Req, Character'Val (Natural (Buf (I))));
                  end loop;
                  exit when Ada.Strings.Fixed.Index
                    (To_String (Req),
                     ASCII.CR & ASCII.LF & ASCII.CR & ASCII.LF) /= 0;
               end loop;

               declare
                  Acc : constant String :=
                    Compute_Accept (Extract_Key (To_String (Req)));
                  Resp : constant String :=
                    "HTTP/1.1 101 Switching Protocols" & ASCII.CR & ASCII.LF
                    & "Upgrade: websocket" & ASCII.CR & ASCII.LF
                    & "Connection: Upgrade" & ASCII.CR & ASCII.LF
                    & "Sec-WebSocket-Accept: " & Acc & ASCII.CR & ASCII.LF
                    & ASCII.CR & ASCII.LF;
                  R_Buf : Stream_Element_Array
                    (1 .. Stream_Element_Offset (Resp'Length));
                  Sent  : Stream_Element_Offset;
               begin
                  for I in Resp'Range loop
                     R_Buf (Stream_Element_Offset (I - Resp'First + 1)) :=
                       Stream_Element (Character'Pos (Resp (I)));
                  end loop;
                  Send_Socket (Client, R_Buf, Sent);
               end;
            end;

            --  Silence. Anything the client sends is left unread and
            --  unanswered; in particular its Close frame is never
            --  echoed. Held until the test says it is done, or until
            --  the cap expires -- so a client that fails to tear
            --  itself down still gets an EOF eventually and the suite
            --  reports a failure instead of deadlocking.
            select
               accept Wait_Done;
            or
               delay Hold_Seconds;
            end select;
            Shutdown_Socket (Client, Shut_Read_Write);
            Close_Socket (Client);
         exception
            when others => null;
         end;

         begin
            Close_Socket (Server);
         exception
            when others => null;
         end;
      end if;

      select
         accept Wait_Done;
      or
         terminate;
      end select;
   end Silent_Server;

   function URL_For (Port : AHT.URL.Port_Number) return String is
     ("ws://127.0.0.1:"
      & Ada.Strings.Fixed.Trim
          (AHT.URL.Port_Number'Image (Port), Ada.Strings.Both) & "/");

begin
   --  Case 1: abort the task that won the teardown.
   --
   --  Close (Timeout => Duration'Last) parks waiting for a Close echo
   --  the fixture will never send. Aborting it there leaves a client
   --  whose admission is already stopped and whose receiver has not
   --  been woken — so the invariant under test is that the abort still
   --  released the receiver, and a later Close therefore completes at
   --  once instead of waiting out the fixture.
   declare
      Server    : Silent_Server;
      Port      : AHT.URL.Port_Number;
      Setup_Err : Unbounded_String;
      C         : AHT.Websocket.Client.Client_Type;
      Started, Ended : Time;
      Bound     : constant Duration := 2.0;
   begin
      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("close-abort: " & To_String (Setup_Err));
      else
         begin
            AHT.Websocket.Client.Connect (C, URL_For (Port));
         exception
            when E : others =>
               Fail ("close-abort: Connect raised "
                     & Ada.Exceptions.Exception_Name (E));
         end;

         --  Tear the closing task out mid-handshake.
         select
            delay 0.3;
         then abort
            AHT.Websocket.Client.Close (C, Timeout => Duration'Last);
         end select;

         --  The aborted winner must still have woken the receiver, so
         --  this join finds a teardown that actually completes. If the
         --  wake gates were skipped, the receiver is still parked in
         --  Read and this cannot return until the fixture drops the
         --  socket at Hold_Seconds.
         Started := Clock;
         select
            delay Hold_Seconds + 2.0;
            Fail ("close-abort: the joining Close never returned at all");
         then abort
            AHT.Websocket.Client.Close (C);
         end select;
         Ended := Clock;

         if Ended - Started > Bound then
            Fail ("close-abort: joining Close took"
                  & Duration'Image (Ended - Started)
                  & "s (bound" & Duration'Image (Bound)
                  & "s) — the aborted winner left the receiver parked"
                  & " and the join waited for the fixture instead");
         end if;

         if AHT.Websocket.Client.Is_Open (C) then
            Fail ("close-abort: Is_Open true after the teardown");
         end if;

         --  Let the fixture go rather than waiting out its cap at
         --  block exit.
         Server.Wait_Done;
      end if;
   end;

   --  Case 2: abort a connect attempt in flight.
   --
   --  The stall fixture on 8767 accepts and then says nothing, so the
   --  upgrade response never arrives and Connect blocks. The attempt
   --  holds both the client's admission and an unpublished session; if
   --  the abort does not run its cleanup, the client is stuck in
   --  Connecting and the next Connect is refused.
   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      begin
         select
            delay 0.5;
         then abort
            AHT.Websocket.Client.Connect (C, "ws://127.0.0.1:8767/");
         end select;
      exception
         when E : others =>
            --  The attempt is supposed to still be blocked when the
            --  abort fires. Anything else means the fixture is not
            --  what this case assumes, so say so rather than letting
            --  the assertion below report a misleading cause.
            Fail ("connect-abort: the attempt ended on its own with "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E)
                  & " (is the stall fixture on 8767 up?)");
      end;

      begin
         AHT.Websocket.Client.Connect (C, "ws://127.0.0.1:8765/");
         if not AHT.Websocket.Client.Is_Open (C) then
            Fail ("connect-abort: reconnect reported not open");
         end if;
         AHT.Websocket.Client.Close (C);
      exception
         when AHT.Websocket.Handshake_Error =>
            Fail ("connect-abort: the client stayed admitted to the "
                  & "aborted attempt — its cleanup did not run");
         when E : others =>
            Fail ("connect-abort: second Connect raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E)
                  & " (is server_ws.py running?)");
      end;
   end;

   if Failures = 0 then
      Put_Line ("test_ws_abort: OK (teardown winner and connect attempt "
                & "both survive being aborted)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_abort:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Abort;
