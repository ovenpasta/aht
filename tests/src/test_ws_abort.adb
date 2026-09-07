--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Asynchronous transfer of control across the WebSocket client's
--  ownership handoffs: tasks torn out of calls they are blocked in,
--  where controlled finalization has to carry the invariant. Runs
--  against a fake server in this file (completes the handshake, then
--  drains without answering) and the stall fixture on 8767.
--
--  Cases:
--    1. abort the winner of a teardown; the receiver must still wake
--    2. abort a connect attempt in flight; the client must redial
--    3. does not exist: the handover record is pinned by test_ws_handoff
--    4. abort a sender holding Send_Guard and one queued on it
--    5. abort across admission, then redial
--
--  Covers:
--    - case 1 aborts only after two observed facts: the teardown was
--      taken (Is_Open false) and the Close frame reached the peer
--    - case 4 aborts a writer provably parked in Write holding the
--      guard, and a second sender on its entry queue
--    - case 5: a client left admitted-but-unowned refuses every later
--      Connect with Wrong_State; the retry is the check
--    - every fixture outlasts the assertions that depend on it, and
--      the bounds make a regression a FAIL, not a hung suite
--
--  Does not cover:
--    - case 2 is timing-based: a fixed delay against a fixture that is
--      silent for far longer
--    - case 4 does not reach the window where the abort lands as the
--      acquisition completes; case 5 pins that
--    - case 5 cannot steer the abort into the admission window: with
--      the generation record moved out of the protected action it
--      still passes, and nothing in the suite catches that
--    - cases 2 and 4 are skipped on Windows, where an abort cannot
--      reach a task parked in a socket call (Abortable_Socket_Wait)
--
--  Validated by:
--    case 1: if the abort skips the wake gates the receiver stays
--    parked in Read and the join waits until the fixture drops the
--    socket seconds later, which the timing bound detects.

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

--  System.OS_Constants is an internal GNAT unit. It is used here only
--  to ask which OS this binary targets, which no portable unit
--  answers. A gpr-fed external would let a build knob decide what a
--  test claims; a target-generated constant cannot be set wrong.
pragma Warnings (Off, "*internal GNAT unit*");
pragma Warnings (Off, "*non-portable and version-dependent*");
with System.OS_Constants;
pragma Warnings (On, "*internal GNAT unit*");
pragma Warnings (On, "*non-portable and version-dependent*");

with AHT.Bytes;
with AHT.Transport;
with AHT.URL;
with AHT.Websocket;
with AHT.Websocket.Client;

procedure Test_WS_Abort is

   Echo_URL : constant String := "ws://127.0.0.1:8765/";

   Failures : Natural := 0;

   --  Whether `abort` can reach a task parked in a blocking socket
   --  call. GNAT on Linux interrupts the syscall with a signal and the
   --  task unwinds; Windows defers the abort until the call returns,
   --  never for a Forever wait. Measured with a standalone probe
   --  (Check_Selector, abort, 'Terminated). Cases 2 and 4 aim at a
   --  socket call and are skipped; cases 1 and 5 unwind everywhere.
   use type System.OS_Constants.OS_Type;
   Abortable_Socket_Wait : constant Boolean :=
     System.OS_Constants.Target_OS /= System.OS_Constants.Windows;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_abort: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Spin until Cond holds or the bound expires, so every wait in
   --  this test is on an observable fact.
   generic
      with function Cond return Boolean;
   function Await (Bound : Duration) return Boolean;

   function Await (Bound : Duration) return Boolean is
      Waited : Duration := 0.0;
   begin
      while not Cond and then Waited < Bound loop
         delay 0.02;
         Waited := Waited + 0.02;
      end loop;
      return Cond;
   end Await;

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

   --  Set by the fixture the moment it reads anything the client sent
   --  after the handshake, in practice the Close frame. Case 1 waits
   --  on this, so "the closer is parked waiting for an echo" is an
   --  observed fact.
   protected Peer_Traffic is
      procedure Note;
      function  Seen return Boolean;
   private
      Got : Boolean := False;
   end Peer_Traffic;

   protected body Peer_Traffic is
      procedure Note is
      begin
         Got := True;
      end Note;
      function Seen return Boolean is (Got);
   end Peer_Traffic;

   function Traffic_Seen return Boolean is (Peer_Traffic.Seen);
   function Await_Traffic is new Await (Traffic_Seen);

   --  Completes the WebSocket handshake, then drains without ever
   --  answering: it reads the client's Close frame but never echoes
   --  it. Holds past every assertion, then drops the socket so a
   --  stranded receiver still terminates and the suite reports a
   --  failure. Deaf_Ms delays the drain loop; a client writing more
   --  than the socket buffers hold then blocks in Write.
   task type Silent_Server (Deaf_Ms : Natural := 0) is
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
         if Deaf_Ms > 0 then
            --  Tiny receive buffer, inherited by the accepted socket:
            --  it shrinks the TCP window so a deaf peer backs the
            --  client's writer up after a few KB instead of after
            --  however many megabytes the kernel felt like buffering.
            Set_Socket_Option
              (Server, Socket_Level,
               (Name => Receive_Buffer, Size => 4_096));
         end if;
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
            if Deaf_Ms > 0 then
               Set_Socket_Option
                 (Client, Socket_Level,
                  (Name => Receive_Buffer, Size => 4_096));
            end if;
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
                  From  : Stream_Element_Offset := 1;
                  Sent  : Stream_Element_Offset;
               begin
                  for I in Resp'Range loop
                     R_Buf (Stream_Element_Offset (I - Resp'First + 1)) :=
                       Stream_Element (Character'Pos (Resp (I)));
                  end loop;
                  --  Send_Socket may write short. A truncated 101 would
                  --  leave the client's unbounded Connect waiting for
                  --  the rest of a response that never comes, which
                  --  would look exactly like a client-side hang.
                  while From <= R_Buf'Last loop
                     Send_Socket (Client, R_Buf (From .. R_Buf'Last), Sent);
                     exit when Sent < From;   --  peer gone
                     From := Sent + 1;
                  end loop;
               end;
            end;

            if Deaf_Ms > 0 then
               delay Duration (Deaf_Ms) / 1000.0;
            end if;

            --  Drain, never answer. A short receive timeout keeps this
            --  loop responsive to Wait_Done and to the cap.
            declare
               Buf     : Stream_Element_Array (1 .. 65_536);
               Last    : Stream_Element_Offset;
               Stop_At : constant Time := Clock + Hold_Seconds;
               Told    : Boolean := False;
            begin
               Set_Socket_Option
                 (Client, Socket_Level,
                  (Name => Receive_Timeout, Timeout => 0.25));
               while not Told and then Clock < Stop_At loop
                  select
                     accept Wait_Done;
                     Told := True;
                  else
                     null;
                  end select;
                  exit when Told;
                  begin
                     Receive_Socket (Client, Buf, Last);
                     exit when Last < Buf'First;   --  client closed
                     Peer_Traffic.Note;
                  exception
                     when Socket_Error => null;    --  idle tick
                  end;
               end loop;
            end;

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

      --  A Wait_Done that arrives after the drain loop ended still has
      --  somewhere to land, so the test never blocks calling it.
      select
         accept Wait_Done;
      or
         terminate;
      end select;
   end Silent_Server;

   --  Runs a Close that cannot return, on its own task, so the test
   --  can abort it once it has provably taken the teardown.
   task type Closer_Task is
      entry Go (Target : AHT.Websocket.Client.Client_Access);
   end Closer_Task;

   task body Closer_Task is
      C : AHT.Websocket.Client.Client_Access;
   begin
      accept Go (Target : AHT.Websocket.Client.Client_Access) do
         C := Target;
      end Go;
      AHT.Websocket.Client.Close (C.all, Timeout => Duration'Last);
   exception
      when others => null;
   end Closer_Task;

   function URL_For (Port : AHT.URL.Port_Number) return String is
     ("ws://127.0.0.1:"
      & Ada.Strings.Fixed.Trim
          (AHT.URL.Port_Number'Image (Port), Ada.Strings.Both) & "/");

begin
   --  Case 1: abort the task that won the teardown.
   declare
      Server    : Silent_Server;
      Port      : AHT.URL.Port_Number;
      Setup_Err : Unbounded_String;
      C         : aliased AHT.Websocket.Client.Client_Type;

      function Not_Open return Boolean is
        (not AHT.Websocket.Client.Is_Open (C));
      function Await_Closing is new Await (Not_Open);

      Started, Ended : Time;
      Join_Bound     : constant Duration := 2.0;
      Connected      : Boolean := False;
   begin
      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("close-abort: " & To_String (Setup_Err));
      else
         begin
            AHT.Websocket.Client.Connect (C, URL_For (Port));
            Connected := True;
         exception
            when E : others =>
               Fail ("close-abort: Connect raised "
                     & Ada.Exceptions.Exception_Name (E) & ": "
                     & Ada.Exceptions.Exception_Message (E));
         end;
      end if;

      if Connected then
         declare
            Closer : Closer_Task;
         begin
            Closer.Go (C'Unchecked_Access);

             --  Positive evidence before aborting: Is_Open false proves
             --  the closer won (Begin_Teardown ran); the fixture seeing
             --  traffic proves the Close frame is on the wire. Together
             --  they place it in the wait for an echo that never comes.
            if not Await_Closing (3.0) then
               Fail ("close-abort: the closer never took the teardown"
                     & " — nothing was aborted mid-handshake, so this"
                     & " case proved nothing");
            elsif not Await_Traffic (3.0) then
               Fail ("close-abort: the Close frame never reached the"
                     & " peer — the closer cannot be parked waiting"
                     & " for an echo, so this case proved nothing");
            else
               abort Closer;

               --  Its finalization is what has to have woken the
               --  receiver, so wait for it to finish before timing.
               declare
                  function Gone return Boolean is (Closer'Terminated);
                  function Await_Gone is new Await (Gone);
               begin
                  if not Await_Gone (3.0) then
                     Fail ("close-abort: the aborted closer never"
                           & " terminated");
                  end if;
               end;

               --  If the abort skipped the wake gates, the receiver is
               --  still parked in Read and this join cannot return
               --  until the fixture drops the socket at Hold_Seconds.
               Started := Clock;
               select
                  delay Hold_Seconds + 2.0;
                  Fail ("close-abort: the joining Close never returned");
               then abort
                  AHT.Websocket.Client.Close (C);
               end select;
               Ended := Clock;

               if Ended - Started > Join_Bound then
                  Fail ("close-abort: joining Close took"
                        & Duration'Image (Ended - Started)
                        & "s (bound" & Duration'Image (Join_Bound)
                        & "s) — the aborted winner left the receiver"
                        & " parked and the join waited for the fixture");
               end if;

               if AHT.Websocket.Client.Is_Open (C) then
                  Fail ("close-abort: Is_Open true after the teardown");
               end if;
            end if;
         end;
      end if;

      --  Release the fixture; do not wait out its cap.
      Server.Wait_Done;
   end;

   --  Case 2: abort a connect attempt in flight. The stall fixture on
   --  8767 accepts and says nothing, so Connect blocks reading the
   --  upgrade response. The attempt holds the client's admission and
   --  an unpublished session; if its cleanup does not run the client
   --  is stuck in Connecting and the next Connect is refused. Skipped
   --  on Windows: an asynchronous select cannot reach a socket call.
   if not Abortable_Socket_Wait then
      Put_Line
        ("test_ws_abort: SKIP connect-abort (case 2) — this target"
         & " cannot abort a Connect parked reading the handshake"
         & " response, so the select would never complete.");
   else
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
                --  what this case assumes, so say so.
               Fail ("connect-abort: the attempt ended on its own with "
                     & Ada.Exceptions.Exception_Name (E) & ": "
                     & Ada.Exceptions.Exception_Message (E)
                     & " (is the stall fixture on 8767 up?)");
         end;

         begin
            AHT.Websocket.Client.Connect (C, Echo_URL);
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
   end if;

   --  Case 3 does not exist: the handover record is its own type and
   --  is driven directly by test_ws_handoff, which asserts its
   --  survival of its maker's abort.

   --  Case 4: abort a sender parked inside Send_Guard. The guard is a
   --  plain busy latch; a task aborted while holding it leaves it
   --  latched and every later sender, the close handshake included,
   --  blocks forever. Park a writer in Write against a peer that has
   --  stopped reading, abort it, then require Close to complete once
   --  the peer drains. Skipped on Windows: see Abortable_Socket_Wait.
   if not Abortable_Socket_Wait then
      Put_Line
        ("test_ws_abort: SKIP guard-abort (case 4) — this target"
         & " cannot abort a task parked in a blocking socket call,"
         & " so the aborted sender would never terminate. The"
         & " Send_Guard property itself is unaffected and is driven"
         & " directly by test_ws_send_guard.");
   else
      declare
         Server    : Silent_Server (Deaf_Ms => 2_000);
         Port      : AHT.URL.Port_Number;
         Setup_Err : Unbounded_String;
         C         : aliased AHT.Websocket.Client.Client_Type;
         Connected : Boolean := False;

         --  Far larger than the 4 KB receive buffer the fixture sets for
         --  its deaf window, so the write provably cannot complete while
         --  the peer is not reading. On the heap: 4 MB would not fit the
         --  environment task's stack, and Storage_Error here would look
         --  like a client bug.
         type Bulk_Access is access AHT.Bytes.Byte_Array;
         Bulk : constant Bulk_Access :=
           new AHT.Bytes.Byte_Array'(1 .. 4 * 1024 * 1024 => 16#5A#);

         protected Writer_State is
            procedure Note_Returned (Why : String);
            function  Returned return Boolean;
            function  Detail return String;
         private
            Done : Boolean := False;
            Text : Unbounded_String;
         end Writer_State;

         protected body Writer_State is
            procedure Note_Returned (Why : String) is
            begin
               Done := True;
               Text := To_Unbounded_String (Why);
            end Note_Returned;
            function Returned return Boolean is (Done);
            function Detail return String is (To_String (Text));
         end Writer_State;

         --  Gated on an entry: a task declared here would otherwise
         --  activate at this block's `begin`, i.e. before Connect has
         --  run, and its Send_Binary would raise Closed_Error at once --
         --  which is indistinguishable from a write that completed.
         task Bulk_Writer is
            entry Go;
         end Bulk_Writer;

          --  Queues behind the parked writer and is aborted with it, so
          --  the cancellation path (abort while still on the entry
          --  queue) is exercised alongside the holder's. The window
          --  where the abort arrives as the acquisition completes is
          --  not reachable from this side of the API; case 5 pins it.
         task Queued_Sender is
            entry Go;
         end Queued_Sender;

         task body Queued_Sender is
         begin
            accept Go;
            AHT.Websocket.Client.Send_Text (C, "queued");
         exception
            when others => null;
         end Queued_Sender;

         task body Bulk_Writer is
         begin
            accept Go;
            AHT.Websocket.Client.Send_Binary (C, Bulk.all);
            Writer_State.Note_Returned ("returned normally");
         exception
            when E : others =>
               Writer_State.Note_Returned
                 (Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
         end Bulk_Writer;

         Started, Ended : Time;
         Close_Bound    : constant Duration := 6.0;
      begin
         Server.Get_Port (Port, Setup_Err);
         if Length (Setup_Err) > 0 then
            Fail ("guard-abort: " & To_String (Setup_Err));
         else
            begin
               AHT.Websocket.Client.Connect (C, URL_For (Port));
               Connected := True;
            exception
               when E : others =>
                  Fail ("guard-abort: Connect raised "
                        & Ada.Exceptions.Exception_Name (E));
            end;
         end if;

         if Connected then
            Bulk_Writer.Go;
         end if;

         --  Give the writer time to fill the buffers and park. If it
         --  finished instead, it never held the guard across a block and
         --  this case would prove nothing -- so say so.
         delay 1.0;

         if Connected and then Writer_State.Returned then
            Fail ("guard-abort: the bulk write ended ("
                  & Writer_State.Detail & ") instead of parking, so no"
                  & " sender was ever holding the guard across a block"
                  & " — this case proved nothing");
            abort Queued_Sender;
         elsif Connected then
            --  Put a second sender on the guard's queue, then tear both
            --  out together: the writer's release and the queued
            --  sender's acquisition happen in the same instant.
            Queued_Sender.Go;
            delay 0.3;
            abort Bulk_Writer;
            abort Queued_Sender;

            declare
               function Gone return Boolean is
                 (Bulk_Writer'Terminated and then Queued_Sender'Terminated);
               function Await_Gone is new Await (Gone);
            begin
               if not Await_Gone (3.0) then
                  Fail ("guard-abort: an aborted sender never terminated");
               end if;
            end;

            --  The peer resumes draining at Deaf_Ms, so the only thing
            --  that can keep Close out now is a guard the aborted writer
            --  never gave back.
            Started := Clock;
            select
               delay Close_Bound;
               Fail ("guard-abort: Close never returned within"
                     & Duration'Image (Close_Bound)
                     & "s — the aborted writer left Send_Guard latched");
            then abort
               AHT.Websocket.Client.Close (C, Timeout => 2.0);
            end select;
            Ended := Clock;

            if AHT.Websocket.Client.Is_Open (C) then
               Fail ("guard-abort: Is_Open true after Close (took"
                     & Duration'Image (Ended - Started) & "s)");
            end if;
         end if;

         if not Connected then
            --  Release the gated tasks so this block can finish.
            abort Bulk_Writer;
            abort Queued_Sender;
         end if;

         Server.Wait_Done;
      end;
   end if;

   --  Case 5: abort across admission, then redial. Admission is one
   --  protected action at the top of Connect: it moves the client to
   --  Connecting and records the generation that makes the attempt
   --  owner release it. An abort between the halves leaves the client
   --  Connecting for good, seen only on the NEXT Connect. The window
   --  cannot be steered into (header); the retry guards the result.
   declare
      Samples  : constant := 60;
      Torn     : Natural := 0;
      Admitted : Natural := 0;
      Stranded : Natural := 0;
   begin
      for I in 1 .. Samples loop
         declare
            --  Clustered where admission happens: the first sample
            --  aborts before Connect has run at all, and the last is
            --  still inside the dial on loopback.
            When_To_Abort : constant Duration :=
              Duration (I - 1) * 0.000_05;
            C : AHT.Websocket.Client.Client_Type;
         begin
            begin
               select
                  delay When_To_Abort;
               then abort
                  AHT.Websocket.Client.Connect (C, Echo_URL);
               end select;
            exception
               when AHT.Websocket.Handshake_Error
                  | AHT.Transport.Transport_Error =>
                  null;   --  ordinary failure of a torn attempt
               when E : others =>
                  Fail ("admission-sweep: sample" & I'Image
                        & " raised "
                        & Ada.Exceptions.Exception_Name (E) & ": "
                        & Ada.Exceptions.Exception_Message (E));
            end;

            if AHT.Websocket.Client.Is_Open (C) then
               --  Got all the way through despite the abort.
               AHT.Websocket.Client.Close (C, Timeout => 2.0);
            else
               Torn := Torn + 1;

               --  A client whose admission was orphaned is stuck in
               --  Connecting, and every later Connect is refused with
               --  Wrong_State, permanently, because the owner that
               --  would have called Abandon_Connect never existed.
               begin
                  AHT.Websocket.Client.Connect (C, Echo_URL);
                  Admitted := Admitted + 1;
                  AHT.Websocket.Client.Close (C, Timeout => 2.0);
               exception
                  when AHT.Websocket.Handshake_Error =>
                     Stranded := Stranded + 1;
                     Fail ("admission-sweep: sample" & I'Image
                           & " (aborted at"
                           & Duration'Image (When_To_Abort)
                           & "s) left the client refusing every later "
                           & "Connect — admission was taken and never "
                           & "released, so it is stuck in Connecting");
                  when E : others =>
                     Fail ("admission-sweep: sample" & I'Image
                           & " retry raised "
                           & Ada.Exceptions.Exception_Name (E) & ": "
                           & Ada.Exceptions.Exception_Message (E));
               end;
            end if;
         end;

         exit when Stranded > 0;   --  one is proof; sixty is noise
      end loop;

      --  A sweep where nothing was ever torn never reached the window
      --  and is not sampling admission at all, in which case the
      --  clean retries above prove nothing.
      if Torn = 0 then
         Fail ("admission-sweep: no sample was torn, so the abort "
               & "never landed anywhere near admission and the "
               & "retries checked nothing");
      elsif Admitted /= Torn then
         --  Every torn sample must have been redialled successfully.
         --  Anything else means a retry neither raised Handshake_Error
         --  nor got in, which the loop above would not otherwise
         --  account for.
         Fail ("admission-sweep:" & Torn'Image & " samples torn but"
               & Admitted'Image & " readmitted — the difference is"
               & " unaccounted for");
      end if;
   end;

   if Failures = 0 then
      Put_Line ("test_ws_abort: OK (teardown winner, connect attempt,"
                & " senders around the guard and"
                & " admission all survive being aborted)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_abort:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Abort;
