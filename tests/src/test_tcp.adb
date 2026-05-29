with Ada.Calendar; use Ada.Calendar;
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Streams; use Ada.Streams;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;
with GNAT.Sockets; use GNAT.Sockets;

with AHT.Bytes;
with AHT.Transport;
with AHT.Transport.TCP;
with AHT.URL;

procedure Test_TCP is

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_tcp: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   task type Echo_Server is
      entry Get_Port
        (P   : out AHT.URL.Port_Number;
         Err : out Unbounded_String);
      entry Wait_Done (Runtime_Err : out Unbounded_String);
   end Echo_Server;

   task body Echo_Server is
      Server        : Socket_Type := No_Socket;
      Client        : Socket_Type;
      Peer          : Sock_Addr_Type;
      Bind_To       : Sock_Addr_Type;
      Bound         : Port_Type := 0;
      Setup_Error   : Unbounded_String;
      Runtime_Error : Unbounded_String;
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
              ("Echo_Server setup: "
               & Ada.Exceptions.Exception_Message (E));
      end;

      accept Get_Port
        (P   : out AHT.URL.Port_Number;
         Err : out Unbounded_String)
      do
         if Length (Setup_Error) > 0 then
            P := 1;
         else
            P := AHT.URL.Port_Number (Bound);
         end if;
         Err := Setup_Error;
      end Get_Port;

      if Length (Setup_Error) = 0 then
         declare
            Selector : Selector_Type;
            R_Set    : Socket_Set_Type;
            W_Set    : Socket_Set_Type;
            Status   : Selector_Status;
         begin
            Create_Selector (Selector);
            Set (R_Set, Server);
            --  Bounded wait so the task never hangs if a client-side
            --  failure means nobody ever connects.
            Check_Selector
              (Selector, R_Set, W_Set, Status, Timeout => 2.0);
            Close_Selector (Selector);

            if Status /= Completed then
               Runtime_Error := To_Unbounded_String
                 ("accept timed out (no client connected within 2s)");
            else
               begin
                  Accept_Socket (Server, Client, Peer);
                  declare
                     Buf  : Stream_Element_Array (1 .. 1024);
                     Last : Stream_Element_Offset;
                     Sent : Stream_Element_Offset;
                  begin
                     Receive_Socket (Client, Buf, Last);
                     if Last >= Buf'First then
                        Send_Socket
                          (Client, Buf (Buf'First .. Last), Sent);
                     end if;
                  end;
                  Shutdown_Socket (Client, Shut_Read_Write);
                  Close_Socket (Client);
               exception
                  when E : others =>
                     Runtime_Error := To_Unbounded_String
                       ("Echo_Server runtime: "
                        & Ada.Exceptions.Exception_Name (E) & " — "
                        & Ada.Exceptions.Exception_Message (E));
               end;
            end if;
         exception
            when E : others =>
               Runtime_Error := To_Unbounded_String
                 ("Echo_Server selector: "
                  & Ada.Exceptions.Exception_Message (E));
         end;

         begin
            Close_Socket (Server);
         exception
            when others => null;
         end;
      end if;

      accept Wait_Done (Runtime_Err : out Unbounded_String) do
         Runtime_Err := Runtime_Error;
      end Wait_Done;
   end Echo_Server;

   --  A server that accepts one client and then holds the connection
   --  open without ever sending. Used by the cancel/timeout cases —
   --  the client's Read is guaranteed to block with zero bytes in
   --  flight, so the only way for Read to return is via
   --  `Set_Read_Deadline` expiry or `Abort_Pending`.

   task type Silent_Server is
      entry Get_Port
        (P   : out AHT.URL.Port_Number;
         Err : out Unbounded_String);
      entry Wait_Done (Runtime_Err : out Unbounded_String);
   end Silent_Server;

   task body Silent_Server is
      Server        : Socket_Type := No_Socket;
      Client        : Socket_Type;
      Peer          : Sock_Addr_Type;
      Bind_To       : Sock_Addr_Type;
      Bound         : Port_Type := 0;
      Setup_Error   : Unbounded_String;
      Runtime_Error : Unbounded_String;
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
              ("Silent_Server setup: "
               & Ada.Exceptions.Exception_Message (E));
      end;

      accept Get_Port
        (P   : out AHT.URL.Port_Number;
         Err : out Unbounded_String)
      do
         if Length (Setup_Error) > 0 then
            P := 1;
         else
            P := AHT.URL.Port_Number (Bound);
         end if;
         Err := Setup_Error;
      end Get_Port;

      if Length (Setup_Error) = 0 then
         declare
            Selector : Selector_Type;
            R_Set    : Socket_Set_Type;
            W_Set    : Socket_Set_Type;
            Status   : Selector_Status;
         begin
            Create_Selector (Selector);
            Set (R_Set, Server);
            Check_Selector
              (Selector, R_Set, W_Set, Status, Timeout => 2.0);
            Close_Selector (Selector);

            if Status /= Completed then
               Runtime_Error := To_Unbounded_String
                 ("silent accept timed out (no client connected within 2s)");
            else
               begin
                  Accept_Socket (Server, Client, Peer);
                  --  Block here until the client closes its half: a
                  --  single Receive on a silent connection returns
                  --  0 bytes on peer close, ≥ 1 on data (we ignore
                  --  either way — the point is to outlive the client's
                  --  cancel/timeout attempt, not to interact).
                  declare
                     Buf  : Stream_Element_Array (1 .. 16);
                     Last : Stream_Element_Offset;
                  begin
                     Receive_Socket (Client, Buf, Last);
                  end;
                  Shutdown_Socket (Client, Shut_Read_Write);
                  Close_Socket (Client);
               exception
                  when E : others =>
                     Runtime_Error := To_Unbounded_String
                       ("Silent_Server runtime: "
                        & Ada.Exceptions.Exception_Name (E) & " — "
                        & Ada.Exceptions.Exception_Message (E));
               end;
            end if;
         exception
            when E : others =>
               Runtime_Error := To_Unbounded_String
                 ("Silent_Server selector: "
                  & Ada.Exceptions.Exception_Message (E));
         end;

         begin
            Close_Socket (Server);
         exception
            when others => null;
         end;
      end if;

      accept Wait_Done (Runtime_Err : out Unbounded_String) do
         Runtime_Err := Runtime_Error;
      end Wait_Done;
   end Silent_Server;

   Payload : constant AHT.Bytes.Byte_Array :=
               AHT.Bytes.From_String ("ping");

   procedure Close_Quietly (T : in out AHT.Transport.TCP.TCP_Transport) is
   begin
      T.Close;
   exception
      when others => null;
   end Close_Quietly;

   procedure Drive_Echo
     (Label : String;
      T     : in out AHT.Transport.TCP.TCP_Transport)
   is
      Buf  : AHT.Bytes.Byte_Array (1 .. 64);
      Last : Natural;
   begin
      if not T.Is_Connected then
         Fail (Label & ": Is_Connected false after Connect");
         return;
      end if;

      T.Write (Payload);

      T.Read (Buf, Last);
      if Last /= 4
        or else AHT.Bytes.To_String (Buf (1 .. Last)) /= "ping"
      then
         Fail
           (Label & ": echo mismatch, got """
            & (if Last > 0 then AHT.Bytes.To_String (Buf (1 .. Last)) else "")
            & """");
         return;
      end if;

      T.Read (Buf, Last);
      if Last /= 0 then
         Fail (Label & ": expected clean EOF, got"
               & Natural'Image (Last));
         return;
      end if;

      T.Close;
      if T.Is_Connected then
         Fail (Label & ": Is_Connected true after Close");
      end if;
   end Drive_Echo;

   procedure Check_Server_Runtime
     (Label : String;
      Err   : Unbounded_String)
   is
   begin
      if Length (Err) > 0 then
         Fail (Label & ": " & To_String (Err));
      end if;
   end Check_Server_Runtime;

   procedure Run_Connect
     (Label : String;
      Host  : String;
      Port  : AHT.URL.Port_Number)
   is
      T : AHT.Transport.TCP.TCP_Transport;
   begin
      begin
         T.Connect (Host, Port);
         Drive_Echo (Label, T);
      exception
         when E : others =>
            Fail (Label & ": unexpected "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E));
      end;
      --  Always close, regardless of how the above exited. TCP_Transport
      --  Close is idempotent, so double-close after a clean exit is a
      --  no-op; the point is that assertion-style early returns in
      --  Drive_Echo never leave the socket open.
      Close_Quietly (T);
   end Run_Connect;

   function Reserve_Unreachable_Port
     (Holder : out Socket_Type) return AHT.URL.Port_Number
   is
      Addr : Sock_Addr_Type;
   begin
      --  Bind-without-listen: the port is reserved to Holder for its
      --  lifetime, and TCP connects to it are refused by the kernel
      --  (no LISTEN queue). Gives a deterministic "bad" address.
      Create_Socket (Holder, Family_Inet, Socket_Stream);
      Addr.Addr := Inet_Addr ("127.0.0.1");
      Addr.Port := 0;
      Bind_Socket (Holder, Addr);
      return AHT.URL.Port_Number (Get_Socket_Name (Holder).Port);
   end Reserve_Unreachable_Port;

begin
   --  Case 1: literal path — Inet_Addr parses, single candidate.
   declare
      Srv         : Echo_Server;
      Port        : AHT.URL.Port_Number;
      Err         : Unbounded_String;
      Runtime_Err : Unbounded_String;
   begin
      Srv.Get_Port (Port, Err);
      if Length (Err) > 0 then
         Fail ("literal: server setup — " & To_String (Err));
      else
         Run_Connect ("literal 127.0.0.1", "127.0.0.1", Port);
      end if;
      Srv.Wait_Done (Runtime_Err);
      Check_Server_Runtime ("literal 127.0.0.1 (server)", Runtime_Err);
   end;

   --  Case 2: DNS path — Inet_Addr fails, Get_Host_By_Name iterates.
   declare
      Srv         : Echo_Server;
      Port        : AHT.URL.Port_Number;
      Err         : Unbounded_String;
      Runtime_Err : Unbounded_String;
   begin
      Srv.Get_Port (Port, Err);
      if Length (Err) > 0 then
         Fail ("DNS: server setup — " & To_String (Err));
      else
         Run_Connect ("DNS localhost", "localhost", Port);
      end if;
      Srv.Wait_Done (Runtime_Err);
      Check_Server_Runtime ("DNS localhost (server)", Runtime_Err);
   end;

   --  Case 3: deterministic multi-address fallback. The first
   --  candidate is a bound-but-not-listening port (refused by the
   --  kernel), the second is the echo server. Exercises iteration +
   --  per-attempt socket cleanup.
   declare
      Srv         : Echo_Server;
      Good_Port   : AHT.URL.Port_Number;
      Bad_Port    : AHT.URL.Port_Number;
      Refuser     : Socket_Type := No_Socket;
      Err         : Unbounded_String;
      Runtime_Err : Unbounded_String;
      Skip        : Boolean := False;
   begin
      Srv.Get_Port (Good_Port, Err);
      if Length (Err) > 0 then
         Fail ("multi-addr: server setup — " & To_String (Err));
         Skip := True;
      else
         begin
            Bad_Port := Reserve_Unreachable_Port (Refuser);
         exception
            when E : others =>
               Fail ("multi-addr: could not reserve bad port — "
                     & Ada.Exceptions.Exception_Message (E));
               Skip := True;
         end;
      end if;

      if not Skip then
         declare
            T : AHT.Transport.TCP.TCP_Transport;
            Candidates : constant AHT.Transport.TCP.Endpoint_List :=
              [(Host => To_Unbounded_String ("127.0.0.1"),
                Port => Bad_Port),
               (Host => To_Unbounded_String ("127.0.0.1"),
                Port => Good_Port)];
         begin
            begin
               T.Connect_Candidates (Candidates);
               Drive_Echo ("multi-addr [bad,good]", T);
            exception
               when E : others =>
                  Fail
                    ("multi-addr [bad,good]: unexpected "
                     & Ada.Exceptions.Exception_Name (E) & " — "
                     & Ada.Exceptions.Exception_Message (E));
            end;
            Close_Quietly (T);
         end;
      end if;

      if Refuser /= No_Socket then
         begin
            Close_Socket (Refuser);
         exception
            when others => null;
         end;
      end if;

      Srv.Wait_Done (Runtime_Err);
      if not Skip then
         Check_Server_Runtime ("multi-addr [bad,good] (server)", Runtime_Err);
      end if;
   end;

   --  Case 4: all-candidates-fail. Two bound-but-not-listening ports
   --  so every attempt is refused. Verifies Connect_Candidates raises
   --  Transport_Error with the *last* address's error in the message —
   --  the "last error wins" contract.
   declare
      Refuser_A, Refuser_B : Socket_Type := No_Socket;
      Port_A, Port_B       : AHT.URL.Port_Number;
      Err_Msg              : Unbounded_String;
      Got_Expected         : Boolean := False;
      Skip                 : Boolean := False;
   begin
      begin
         Port_A := Reserve_Unreachable_Port (Refuser_A);
         Port_B := Reserve_Unreachable_Port (Refuser_B);
      exception
         when E : others =>
            Fail ("all-fail: could not reserve bad ports — "
                  & Ada.Exceptions.Exception_Message (E));
            Skip := True;
      end;

      if not Skip then
         declare
            T : AHT.Transport.TCP.TCP_Transport;
            Candidates : constant AHT.Transport.TCP.Endpoint_List :=
              [(Host => To_Unbounded_String ("127.0.0.1"),
                Port => Port_A),
               (Host => To_Unbounded_String ("127.0.0.1"),
                Port => Port_B)];
         begin
            begin
               T.Connect_Candidates (Candidates);
               Fail
                 ("all-fail: expected Transport_Error, "
                  & "Connect_Candidates returned normally "
                  & "(Is_Connected="
                  & Boolean'Image (T.Is_Connected) & ")");
            exception
               when E : AHT.Transport.Transport_Error =>
                  Got_Expected := True;
                  Err_Msg := To_Unbounded_String
                    (Ada.Exceptions.Exception_Message (E));
               when E : others =>
                  Fail ("all-fail: expected Transport_Error, got "
                        & Ada.Exceptions.Exception_Name (E) & " — "
                        & Ada.Exceptions.Exception_Message (E));
            end;
            Close_Quietly (T);
         end;

         if Got_Expected then
            declare
               Needle : constant String :=
                 AHT.URL.Port_Number'Image (Port_B);
               Stale  : constant String :=
                 AHT.URL.Port_Number'Image (Port_A);
               Msg    : constant String := To_String (Err_Msg);
               Has_Last  : constant Boolean :=
                 Ada.Strings.Fixed.Index (Msg, Needle) /= 0;
               Has_Only_First : constant Boolean :=
                 not Has_Last
                 and then Ada.Strings.Fixed.Index (Msg, Stale) /= 0;
            begin
               if not Has_Last then
                  Fail
                    ("all-fail: last-error contract: message "
                     & "does not mention last port " & Needle
                     & " — """ & Msg & """");
               end if;
               if Has_Only_First then
                  Fail
                    ("all-fail: last-error contract: message "
                     & "reports the first failure instead of the last");
               end if;
            end;
         end if;
      end if;

      if Refuser_A /= No_Socket then
         begin Close_Socket (Refuser_A); exception when others => null; end;
      end if;
      if Refuser_B /= No_Socket then
         begin Close_Socket (Refuser_B); exception when others => null; end;
      end if;
   end;

   --  Case 5: Abort_Pending unblocks a Read parked on a silent peer.
   --  A sibling task calls Abort_Pending after a short delay; the
   --  main task's Read must raise Aborted_Error without the server
   --  sending anything.
   declare
      Srv         : Silent_Server;
      Port        : AHT.URL.Port_Number;
      Err         : Unbounded_String;
      Runtime_Err : Unbounded_String;
   begin
      Srv.Get_Port (Port, Err);
      if Length (Err) > 0 then
         Fail ("abort: server setup — " & To_String (Err));
      else
         declare
            T    : AHT.Transport.TCP.TCP_Transport;
            Data : AHT.Bytes.Byte_Array (1 .. 64);
            Last : Natural;

            task Aborter;
            task body Aborter is
            begin
               delay 0.1;
               T.Abort_Pending;
            exception
               when others => null;
            end Aborter;
         begin
            begin
               T.Connect ("127.0.0.1", Port);
            exception
               when E : others =>
                  Fail ("abort: Connect — "
                        & Ada.Exceptions.Exception_Message (E));
            end;

            if T.Is_Connected then
               declare
                  T_Start : constant Time := Clock;
                  Elapsed : Duration;
               begin
                  T.Read (Data, Last);
                  Fail ("abort: Read returned normally, Last="
                        & Natural'Image (Last));
               exception
                  when AHT.Transport.Aborted_Error =>
                     Elapsed := Clock - T_Start;
                     if Elapsed > 1.0 then
                        Fail ("abort: took too long — "
                              & Duration'Image (Elapsed) & "s");
                     end if;
                  when E : others =>
                     Fail ("abort: unexpected "
                           & Ada.Exceptions.Exception_Name (E) & " — "
                           & Ada.Exceptions.Exception_Message (E));
               end;
            end if;

            Close_Quietly (T);
            --  Aborter is declared in this block, so the enclosing
            --  end joins it before we return to the outer scope.
         end;
      end if;
      Srv.Wait_Done (Runtime_Err);
      Check_Server_Runtime ("abort (server)", Runtime_Err);
   end;

   --  Case 6: Set_Read_Deadline causes Read to raise Timeout_Error
   --  after the configured duration when the peer stays silent.
   declare
      Srv         : Silent_Server;
      Port        : AHT.URL.Port_Number;
      Err         : Unbounded_String;
      Runtime_Err : Unbounded_String;
   begin
      Srv.Get_Port (Port, Err);
      if Length (Err) > 0 then
         Fail ("timeout: server setup — " & To_String (Err));
      else
         declare
            T    : AHT.Transport.TCP.TCP_Transport;
            Data : AHT.Bytes.Byte_Array (1 .. 64);
            Last : Natural;
         begin
            begin
               T.Connect ("127.0.0.1", Port);
            exception
               when E : others =>
                  Fail ("timeout: Connect — "
                        & Ada.Exceptions.Exception_Message (E));
            end;

            if T.Is_Connected then
               T.Set_Read_Deadline (0.1);
               declare
                  T_Start : constant Time := Clock;
                  Elapsed : Duration;
               begin
                  T.Read (Data, Last);
                  Fail ("timeout: Read returned normally, Last="
                        & Natural'Image (Last));
               exception
                  when AHT.Transport.Timeout_Error =>
                     Elapsed := Clock - T_Start;
                     if Elapsed < 0.05 then
                        Fail ("timeout: fired too early — "
                              & Duration'Image (Elapsed) & "s");
                     end if;
                     if Elapsed > 1.0 then
                        Fail ("timeout: took too long — "
                              & Duration'Image (Elapsed) & "s");
                     end if;
                  when E : others =>
                     Fail ("timeout: unexpected "
                           & Ada.Exceptions.Exception_Name (E) & " — "
                           & Ada.Exceptions.Exception_Message (E));
               end;
            end if;

            Close_Quietly (T);
         end;
      end if;
      Srv.Wait_Done (Runtime_Err);
      Check_Server_Runtime ("timeout (server)", Runtime_Err);
   end;

   --  Case 7: Set_Read_Deadline is compound (wall-clock from the
   --  call), not per-Read. If the deadline has already elapsed by
   --  the time Read is invoked, it raises Timeout_Error almost
   --  immediately — it does not grant another full budget. This is
   --  the semantic HTTP.IO's line/body loops rely on, so a
   --  slow-drip peer cannot dodge the deadline by keeping each
   --  individual Read under it.
   declare
      Srv         : Silent_Server;
      Port        : AHT.URL.Port_Number;
      Err         : Unbounded_String;
      Runtime_Err : Unbounded_String;
   begin
      Srv.Get_Port (Port, Err);
      if Length (Err) > 0 then
         Fail ("compound-timeout: server setup — " & To_String (Err));
      else
         declare
            T    : AHT.Transport.TCP.TCP_Transport;
            Data : AHT.Bytes.Byte_Array (1 .. 64);
            Last : Natural;
         begin
            begin
               T.Connect ("127.0.0.1", Port);
            exception
               when E : others =>
                  Fail ("compound-timeout: Connect — "
                        & Ada.Exceptions.Exception_Message (E));
            end;

            if T.Is_Connected then
               T.Set_Read_Deadline (0.1);
               delay 0.25;  --  Burn the whole budget before Read.
               declare
                  T_Start : constant Time := Clock;
                  Elapsed : Duration;
               begin
                  T.Read (Data, Last);
                  Fail ("compound-timeout: Read returned normally, Last="
                        & Natural'Image (Last));
               exception
                  when AHT.Transport.Timeout_Error =>
                     Elapsed := Clock - T_Start;
                     --  Deadline already gone when we called Read;
                     --  the raise should be effectively instant, not
                     --  another ~0.1 s. Budget covers GNAT scheduler
                     --  jitter without admitting a fresh per-Read
                     --  deadline interpretation.
                     if Elapsed > 0.05 then
                        Fail ("compound-timeout: Read waited"
                              & Duration'Image (Elapsed)
                              & "s past an expired deadline");
                     end if;
                  when E : others =>
                     Fail ("compound-timeout: unexpected "
                           & Ada.Exceptions.Exception_Name (E) & " — "
                           & Ada.Exceptions.Exception_Message (E));
               end;
            end if;

            Close_Quietly (T);
         end;
      end if;
      Srv.Wait_Done (Runtime_Err);
      Check_Server_Runtime ("compound-timeout (server)", Runtime_Err);
   end;

   --  Case 8: a refused connect under a Connect_Timeout budget must
   --  still raise Transport_Error, not Timeout_Error — a fast failure
   --  is not a timeout. Exercises the budgeted Connect_Socket path
   --  (positive remaining budget) and its Socket_Error handler: the
   --  refusal lands well within the generous 5 s budget, so a regression
   --  that classified any budgeted failure as a timeout would be caught.
   declare
      Refuser  : Socket_Type := No_Socket;
      Bad_Port : AHT.URL.Port_Number;
      Skip     : Boolean := False;
   begin
      begin
         Bad_Port := Reserve_Unreachable_Port (Refuser);
      exception
         when E : others =>
            Fail ("budget-refused: could not reserve bad port — "
                  & Ada.Exceptions.Exception_Message (E));
            Skip := True;
      end;

      if not Skip then
         declare
            T : AHT.Transport.TCP.TCP_Transport;
            Candidates : constant AHT.Transport.TCP.Endpoint_List :=
              [(Host => To_Unbounded_String ("127.0.0.1"),
                Port => Bad_Port)];
         begin
            begin
               T.Connect_Candidates (Candidates, Connect_Timeout => 5.0);
               Fail ("budget-refused: expected Transport_Error, "
                     & "Connect_Candidates returned normally");
            exception
               when AHT.Transport.Transport_Error =>
                  null;  --  expected
               when AHT.Transport.Timeout_Error =>
                  Fail ("budget-refused: refusal misclassified as "
                        & "Timeout_Error under a non-exhausted budget");
               when E : others =>
                  Fail ("budget-refused: unexpected "
                        & Ada.Exceptions.Exception_Name (E) & " — "
                        & Ada.Exceptions.Exception_Message (E));
            end;
            Close_Quietly (T);
         end;
      end if;

      if Refuser /= No_Socket then
         begin Close_Socket (Refuser); exception when others => null; end;
      end if;
   end;

   --  Case 9: multi-candidate fallback survives a budget. First
   --  candidate refused (instant, leaving nearly the whole budget),
   --  second is the echo server — connect + echo must still succeed, so
   --  budgeting does not short-circuit the fallback loop after one
   --  budgeted-but-failed attempt.
   declare
      Srv         : Echo_Server;
      Good_Port   : AHT.URL.Port_Number;
      Bad_Port    : AHT.URL.Port_Number;
      Refuser     : Socket_Type := No_Socket;
      Err         : Unbounded_String;
      Runtime_Err : Unbounded_String;
      Skip        : Boolean := False;
   begin
      Srv.Get_Port (Good_Port, Err);
      if Length (Err) > 0 then
         Fail ("budget-fallback: server setup — " & To_String (Err));
         Skip := True;
      else
         begin
            Bad_Port := Reserve_Unreachable_Port (Refuser);
         exception
            when E : others =>
               Fail ("budget-fallback: could not reserve bad port — "
                     & Ada.Exceptions.Exception_Message (E));
               Skip := True;
         end;
      end if;

      if not Skip then
         declare
            T : AHT.Transport.TCP.TCP_Transport;
            Candidates : constant AHT.Transport.TCP.Endpoint_List :=
              [(Host => To_Unbounded_String ("127.0.0.1"),
                Port => Bad_Port),
               (Host => To_Unbounded_String ("127.0.0.1"),
                Port => Good_Port)];
         begin
            begin
               T.Connect_Candidates (Candidates, Connect_Timeout => 5.0);
               Drive_Echo ("budget-fallback [bad,good]", T);
            exception
               when E : others =>
                  Fail ("budget-fallback [bad,good]: unexpected "
                        & Ada.Exceptions.Exception_Name (E) & " — "
                        & Ada.Exceptions.Exception_Message (E));
            end;
            Close_Quietly (T);
         end;
      end if;

      if Refuser /= No_Socket then
         begin Close_Socket (Refuser); exception when others => null; end;
      end if;

      Srv.Wait_Done (Runtime_Err);
      if not Skip then
         Check_Server_Runtime ("budget-fallback [bad,good] (server)",
                               Runtime_Err);
      end if;
   end;

   --  Case 10: an exhausted budget raises Timeout_Error before a
   --  connect is even attempted. Connect_Timeout => 0.0 puts the
   --  deadline in the past by the time the first candidate is tried, so
   --  the pre-attempt budget check trips. A reserved (refusing) port
   --  proves the dial never happens: had it attempted, the refusal
   --  would surface as Transport_Error, which this case rejects. This
   --  is the only deterministic way to drive the budget-exhausted
   --  branch — a genuine mid-connect stall would need an
   --  unroutable/firewalled peer, too environment-dependent for CI.
   declare
      Refuser  : Socket_Type := No_Socket;
      Bad_Port : AHT.URL.Port_Number;
      Skip     : Boolean := False;
   begin
      begin
         Bad_Port := Reserve_Unreachable_Port (Refuser);
      exception
         when E : others =>
            Fail ("budget-exhausted: could not reserve port — "
                  & Ada.Exceptions.Exception_Message (E));
            Skip := True;
      end;

      if not Skip then
         declare
            T : AHT.Transport.TCP.TCP_Transport;
            Candidates : constant AHT.Transport.TCP.Endpoint_List :=
              [(Host => To_Unbounded_String ("127.0.0.1"),
                Port => Bad_Port)];
         begin
            begin
               T.Connect_Candidates (Candidates, Connect_Timeout => 0.0);
               Fail ("budget-exhausted: expected Timeout_Error, "
                     & "Connect_Candidates returned normally");
            exception
               when AHT.Transport.Timeout_Error =>
                  null;  --  expected
               when E : others =>
                  Fail ("budget-exhausted: expected Timeout_Error, got "
                        & Ada.Exceptions.Exception_Name (E) & " — "
                        & Ada.Exceptions.Exception_Message (E));
            end;
            Close_Quietly (T);
         end;
      end if;

      if Refuser /= No_Socket then
         begin Close_Socket (Refuser); exception when others => null; end;
      end if;
   end;

   if Failures = 0 then
      Put_Line ("test_tcp: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tcp:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TCP;
