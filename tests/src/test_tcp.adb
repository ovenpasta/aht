--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Calendar; use Ada.Calendar;
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Streams; use Ada.Streams;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;
with Ada.Unchecked_Deallocation;
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

   procedure Close_Peer_Quietly (S : in out Socket_Type) is
   begin
      if S = No_Socket then
         return;
      end if;
      begin
         Shutdown_Socket (S, Shut_Read_Write);
      exception
         --  Darwin reports ENOTCONN when the peer has already closed.
         when Socket_Error => null;
      end;
      begin
         Close_Socket (S);
      exception
         when Socket_Error => null;
      end;
      S := No_Socket;
   end Close_Peer_Quietly;

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
                  Close_Peer_Quietly (Client);
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
   --  open without ever sending. Used by the cancel/timeout cases:
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
                  --  0 bytes on peer close, 1 or more on data. Either
                  --  is ignored; the server only has to outlive the
                  --  client's cancel/timeout attempt.
                  declare
                     Buf  : Stream_Element_Array (1 .. 16);
                     Last : Stream_Element_Offset;
                  begin
                     Receive_Socket (Client, Buf, Last);
                  end;
                  Close_Peer_Quietly (Client);
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

   --  A server that accepts one client, shrinks its receive buffer so the
   --  kernel absorbs almost nothing, and then never reads: it parks on the
   --  Release rendezvous, holding the connection open. The client's Write
   --  fills the send + receive buffers and blocks on a full window, so the
   --  only way Write can return is via Set_Write_Deadline expiry or
   --  Abort_Pending. The main task calls Release once its write attempt has
   --  resolved, letting the server drop the connection and finish.

   task type Deaf_Server is
      entry Get_Port
        (P   : out AHT.URL.Port_Number;
         Err : out Unbounded_String);
      entry Release;
      entry Wait_Done (Runtime_Err : out Unbounded_String);
   end Deaf_Server;

   task body Deaf_Server is
      Server        : Socket_Type := No_Socket;
      Client        : Socket_Type;
      Peer          : Sock_Addr_Type;
      Bind_To       : Sock_Addr_Type;
      Bound         : Port_Type := 0;
      Setup_Error   : Unbounded_String;
      Runtime_Error : Unbounded_String;
      Accepted      : Boolean := False;
   begin
      begin
         Create_Socket (Server, Family_Inet, Socket_Stream);
         Set_Socket_Option
           (Server, Socket_Level, (Name => Reuse_Address, Enabled => True));
         --  Tiny receive buffer (inherited by the accepted socket) so the
         --  peer side absorbs almost nothing and the client's Write blocks
         --  on a full window quickly and deterministically.
         Set_Socket_Option
           (Server, Socket_Level, (Name => Receive_Buffer, Size => 2048));
         Bind_To.Addr := Inet_Addr ("127.0.0.1");
         Bind_To.Port := 0;
         Bind_Socket (Server, Bind_To);
         Listen_Socket (Server, 1);
         Bound := Get_Socket_Name (Server).Port;
      exception
         when E : others =>
            Setup_Error := To_Unbounded_String
              ("Deaf_Server setup: "
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
                 ("deaf accept timed out (no client connected within 2s)");
            else
               begin
                  Accept_Socket (Server, Client, Peer);
                  Accepted := True;
               exception
                  when E : others =>
                     Runtime_Error := To_Unbounded_String
                       ("Deaf_Server accept: "
                        & Ada.Exceptions.Exception_Name (E) & " — "
                        & Ada.Exceptions.Exception_Message (E));
               end;
            end if;
         exception
            when E : others =>
               Runtime_Error := To_Unbounded_String
                 ("Deaf_Server selector: "
                  & Ada.Exceptions.Exception_Message (E));
         end;
      end if;

      --  Hold the connection open without ever reading until the client's
      --  write attempt resolves, then drop it.
      accept Release;

      if Accepted then
         Close_Peer_Quietly (Client);
      end if;
      if Server /= No_Socket then
         begin Close_Socket (Server); exception when others => null; end;
      end if;

      accept Wait_Done (Runtime_Err : out Unbounded_String) do
         Runtime_Err := Runtime_Error;
      end Wait_Done;
   end Deaf_Server;

   --  Accepts one client and, like Deaf_Server, never reads, so the
   --  client's large Write parks in the selector after at least one
   --  partial send. Drops the connection only on Close_Now, once the
   --  client is blocked, so case 13 exercises the resume-after-partial
   --  -send path waking on the peer's RST.
   task type Closer_Server is
      entry Get_Port
        (P   : out AHT.URL.Port_Number;
         Err : out Unbounded_String);
      entry Close_Now;
      entry Wait_Done (Runtime_Err : out Unbounded_String);
   end Closer_Server;

   task body Closer_Server is
      Server        : Socket_Type := No_Socket;
      Client        : Socket_Type;
      Peer          : Sock_Addr_Type;
      Bind_To       : Sock_Addr_Type;
      Bound         : Port_Type := 0;
      Setup_Error   : Unbounded_String;
      Runtime_Error : Unbounded_String;
      Accepted      : Boolean := False;
   begin
      begin
         Create_Socket (Server, Family_Inet, Socket_Stream);
         Set_Socket_Option
           (Server, Socket_Level, (Name => Reuse_Address, Enabled => True));
         --  Tiny receive buffer so the client fills the buffers and parks
         --  almost immediately, guaranteeing it is blocked in the selector
         --  (past its first partial send) by the time Close_Now fires.
         Set_Socket_Option
           (Server, Socket_Level, (Name => Receive_Buffer, Size => 2048));
         Bind_To.Addr := Inet_Addr ("127.0.0.1");
         Bind_To.Port := 0;
         Bind_Socket (Server, Bind_To);
         Listen_Socket (Server, 1);
         Bound := Get_Socket_Name (Server).Port;
      exception
         when E : others =>
            Setup_Error := To_Unbounded_String
              ("Closer_Server setup: "
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
                 ("closer accept timed out (no client connected within 2s)");
            else
               begin
                  Accept_Socket (Server, Client, Peer);
                  Accepted := True;
               exception
                  when E : others =>
                     Runtime_Error := To_Unbounded_String
                       ("Closer_Server accept: "
                        & Ada.Exceptions.Exception_Name (E) & " — "
                        & Ada.Exceptions.Exception_Message (E));
               end;
            end if;
         exception
            when E : others =>
               Runtime_Error := To_Unbounded_String
                 ("Closer_Server selector: "
                  & Ada.Exceptions.Exception_Message (E));
         end;
      end if;

      --  Hold the connection open (never reading) until the caller, which
      --  has by now started the big write and let it block, says to drop
      --  it. The shutdown+close sends a RST that wakes the parked write.
      accept Close_Now;

      if Accepted then
         Close_Peer_Quietly (Client);
      end if;
      if Server /= No_Socket then
         begin Close_Socket (Server); exception when others => null; end;
      end if;

      accept Wait_Done (Runtime_Err : out Unbounded_String) do
         Runtime_Err := Runtime_Error;
      end Wait_Done;
   end Closer_Server;

   --  Accepts one client and, only once the caller signals Reset_Now,
   --  RST-closes it (SO_LINGER 0), so a client that connects, triggers the
   --  reset, lets it settle, then writes hits a dead endpoint on its FIRST
   --  send, with zero bytes accepted. This drives the zero-progress poison
   --  path: a peer reset must tear the transport down even though no byte
   --  of the write went out. The reset is caller-gated (not fired right at
   --  accept) so it can never race the client's connect-completion check;
   --  under load an accept-time RST surfaces as a Connect failure instead
   --  of the first-send failure this case exercises.
   task type Resetter_Server is
      entry Get_Port
        (P   : out AHT.URL.Port_Number;
         Err : out Unbounded_String);
      entry Reset_Now;
      entry Wait_Done (Runtime_Err : out Unbounded_String);
   end Resetter_Server;

   task body Resetter_Server is
      Server        : Socket_Type := No_Socket;
      Client        : Socket_Type;
      Peer          : Sock_Addr_Type;
      Bind_To       : Sock_Addr_Type;
      Bound         : Port_Type := 0;
      Setup_Error   : Unbounded_String;
      Runtime_Error : Unbounded_String;
      Accepted      : Boolean := False;
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
              ("Resetter_Server setup: "
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
                 ("resetter accept timed out (no client within 2s)");
            else
               begin
                  Accept_Socket (Server, Client, Peer);
                  Accepted := True;
               exception
                  when E : others =>
                     Runtime_Error := To_Unbounded_String
                       ("Resetter_Server accept: "
                        & Ada.Exceptions.Exception_Name (E) & " — "
                        & Ada.Exceptions.Exception_Message (E));
               end;
            end if;
         exception
            when E : others =>
               Runtime_Error := To_Unbounded_String
                 ("Resetter_Server selector: "
                  & Ada.Exceptions.Exception_Message (E));
         end;
      end if;

      --  Always accepted (even on the setup/accept error path) so the client,
      --  which calls Reset_Now unconditionally, never deadlocks. The reset
      --  fires only after the client has finished connecting and signalled.
      accept Reset_Now;

      if Accepted then
         begin
            --  Linger with a 0-second timeout makes Close send a RST
            --  instead of a FIN, so the peer's next send fails at once.
            Set_Socket_Option
              (Client, Socket_Level,
               (Name => Linger, Enabled => True, Seconds => 0));
            Close_Socket (Client);
         exception
            when others => null;
         end;
      end if;

      if Server /= No_Socket then
         begin Close_Socket (Server); exception when others => null; end;
      end if;

      accept Wait_Done (Runtime_Err : out Unbounded_String) do
         Runtime_Err := Runtime_Error;
      end Wait_Done;
   end Resetter_Server;

   Payload : constant AHT.Bytes.Byte_Array :=
               AHT.Bytes.From_String ("ping");

   type Byte_Array_Access is access AHT.Bytes.Byte_Array;
   procedure Free is
     new Ada.Unchecked_Deallocation
       (AHT.Bytes.Byte_Array, Byte_Array_Access);

   --  Bigger than any plausible socket send + receive buffer, so a Write
   --  to a peer that never reads is guaranteed to block. Heap-allocated to
   --  keep it off the (fixed) task stack.
   Big_Write_Len : constant := 4 * 1024 * 1024;

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
      --  no-op, and assertion-style early returns in Drive_Echo never
      --  leave the socket open.
      Close_Quietly (T);
   end Run_Connect;

   function Reserve_Unreachable_Port
     (Holder : out Socket_Type) return AHT.URL.Port_Number
   is
      Addr : Sock_Addr_Type;
   begin
      --  Hold the number in the UDP namespace while leaving its TCP
      --  namespace closed.  A bound-but-not-listening TCP socket is not a
      --  portable refusal fixture: Darwin lets connect stall until its
      --  kernel timeout instead of rejecting it immediately.
      Create_Socket (Holder, Family_Inet, Socket_Datagram);
      Addr.Addr := Inet_Addr ("127.0.0.1");
      Addr.Port := 0;
      Bind_Socket (Holder, Addr);
      return AHT.URL.Port_Number (Get_Socket_Name (Holder).Port);
   end Reserve_Unreachable_Port;

begin
   --  Case 1: literal path. Inet_Addr parses, single candidate.
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

   --  Case 2: DNS path. Inet_Addr fails, so the name goes to
   --  AHT.DNS.Resolve and its literals become the candidate list.
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
   --  candidate is a closed TCP port (held only in the UDP namespace),
   --  the second is the echo server. Exercises iteration +
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

   --  Case 4: all-candidates-fail. Two closed TCP ports are held in the
   --  UDP namespace so every attempt is refused. Verifies
   --  Connect_Candidates raises Transport_Error with the LAST address's
   --  error in the message:
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
   --  immediately; it does not grant another full budget. HTTP.IO's
   --  line/body loops rely on this, so a slow-drip peer cannot dodge
   --  the deadline by keeping each individual Read under it.
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
   --  still raise Transport_Error, not Timeout_Error: a fast failure
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
   --  second is the echo server; connect + echo must still succeed, so
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

   --  Case 10: an exhausted budget raises Timeout_Error before a connect
   --  is attempted. Connect_Timeout => 0.0 puts the deadline in the past
   --  by the first candidate, so the pre-attempt check trips. A reserved
   --  (refusing) port proves the dial never happens: an attempt would
   --  surface as Transport_Error, which this case rejects. A mid-connect
   --  stall would need an unroutable peer, too environment-dependent.
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

   --  Case 11: Set_Write_Deadline causes a stuck Write to raise
   --  Timeout_Error. The deaf server accepts and never reads, so after
   --  the kernel buffers fill the client's non-blocking partial-send loop
   --  re-parks in Check_Selector and the write deadline trips, proving a
   --  wedged upload is bounded, not hung forever.
   declare
      Srv         : Deaf_Server;
      Port        : AHT.URL.Port_Number;
      Err         : Unbounded_String;
      Runtime_Err : Unbounded_String;
   begin
      Srv.Get_Port (Port, Err);
      if Length (Err) > 0 then
         Fail ("write-timeout: server setup — " & To_String (Err));
         Srv.Release;
      else
         declare
            T   : AHT.Transport.TCP.TCP_Transport;
            Big : Byte_Array_Access :=
              new AHT.Bytes.Byte_Array'(1 .. Big_Write_Len => 65);
         begin
            begin
               T.Connect ("127.0.0.1", Port);
            exception
               when E : others =>
                  Fail ("write-timeout: Connect — "
                        & Ada.Exceptions.Exception_Message (E));
            end;

            if T.Is_Connected then
               T.Set_Write_Deadline (0.3);
               declare
                  T_Start : constant Time := Clock;
                  Elapsed : Duration;
               begin
                  T.Write (Big.all);
                  Fail ("write-timeout: Write returned normally "
                        & "(peer never read — should have blocked)");
               exception
                  when AHT.Transport.Timeout_Error =>
                     Elapsed := Clock - T_Start;
                     if Elapsed < 0.05 then
                        Fail ("write-timeout: fired too early — "
                              & Duration'Image (Elapsed) & "s");
                     end if;
                     if Elapsed > 2.0 then
                        Fail ("write-timeout: took too long — "
                              & Duration'Image (Elapsed) & "s");
                     end if;
                  when E : others =>
                     Fail ("write-timeout: unexpected "
                           & Ada.Exceptions.Exception_Name (E) & " — "
                           & Ada.Exceptions.Exception_Message (E));
               end;

               --  A timeout after a partial send leaves a truncated
               --  message on the wire, so the transport must be
               --  poisoned: Is_Connected goes False and a retry is
               --  rejected instead of appending to the stream.
               if T.Is_Connected then
                  Fail ("write-timeout: still connected after a mid-send "
                        & "timeout (truncated stream left reusable)");
               else
                  begin
                     T.Write (Big.all);
                     Fail ("write-timeout: second Write succeeded on a "
                           & "poisoned transport (should raise)");
                  exception
                     when AHT.Transport.Transport_Error =>
                        null;  --  expected: "TCP write on closed transport"
                     when E : others =>
                        Fail ("write-timeout: second Write raised unexpected "
                              & Ada.Exceptions.Exception_Name (E) & " — "
                              & Ada.Exceptions.Exception_Message (E));
                  end;
               end if;
            end if;

            Srv.Release;
            Close_Quietly (T);
            Free (Big);
         end;
      end if;
      Srv.Wait_Done (Runtime_Err);
      Check_Server_Runtime ("write-timeout (server)", Runtime_Err);
   end;

   --  Case 12: Abort_Pending unblocks a Write wedged on a deaf peer. A
   --  sibling task calls Abort_Pending after a short delay; because each
   --  send is non-blocking and partial, the abort bites at the next
   --  re-park (one selector cycle), proving the cancel is not lost inside
   --  an in-flight syscall. No write deadline is set, so only the abort
   --  can end the Write.
   declare
      Srv         : Deaf_Server;
      Port        : AHT.URL.Port_Number;
      Err         : Unbounded_String;
      Runtime_Err : Unbounded_String;
   begin
      Srv.Get_Port (Port, Err);
      if Length (Err) > 0 then
         Fail ("write-abort: server setup — " & To_String (Err));
         Srv.Release;
      else
         declare
            T   : AHT.Transport.TCP.TCP_Transport;
            Big : Byte_Array_Access :=
              new AHT.Bytes.Byte_Array'(1 .. Big_Write_Len => 65);

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
                  Fail ("write-abort: Connect — "
                        & Ada.Exceptions.Exception_Message (E));
            end;

            if T.Is_Connected then
               declare
                  T_Start : constant Time := Clock;
                  Elapsed : Duration;
               begin
                  T.Write (Big.all);
                  Fail ("write-abort: Write returned normally "
                        & "(peer never read — should have blocked)");
               exception
                  when AHT.Transport.Aborted_Error =>
                     Elapsed := Clock - T_Start;
                     if Elapsed > 1.5 then
                        Fail ("write-abort: took too long — "
                              & Duration'Image (Elapsed) & "s");
                     end if;
                  when E : others =>
                     Fail ("write-abort: unexpected "
                           & Ada.Exceptions.Exception_Name (E) & " — "
                           & Ada.Exceptions.Exception_Message (E));
               end;

               --  Same poisoning contract as the timeout case: an abort
               --  mid-send truncated the message, so the transport is torn
               --  down and a retry must be rejected.
               if T.Is_Connected then
                  Fail ("write-abort: still connected after a mid-send "
                        & "abort (truncated stream left reusable)");
               else
                  begin
                     T.Write (Big.all);
                     Fail ("write-abort: second Write succeeded on a "
                           & "poisoned transport (should raise)");
                  exception
                     when AHT.Transport.Transport_Error =>
                        null;  --  expected: "TCP write on closed transport"
                     when E : others =>
                        Fail ("write-abort: second Write raised unexpected "
                              & Ada.Exceptions.Exception_Name (E) & " — "
                              & Ada.Exceptions.Exception_Message (E));
                  end;
               end if;
            end if;

            Srv.Release;
            Close_Quietly (T);
            Free (Big);
            --  Aborter is declared in this block, so the enclosing end
            --  joins it before we leave the scope.
         end;
      end if;
      Srv.Wait_Done (Runtime_Err);
      Check_Server_Runtime ("write-abort (server)", Runtime_Err);
   end;

   --  Case 13: a peer that closes mid-upload must surface Transport_Error
   --  promptly. The closer server stays deaf after accept, so the write
   --  makes at least one partial send and parks in the selector; the
   --  Closer task then signals Close_Now, which RST-closes the peer and
   --  wakes the parked write. The write deadline is a backstop only:
   --  Timeout_Error is a FAIL, meaning the close was not detected.
   declare
      Srv         : Closer_Server;
      Port        : AHT.URL.Port_Number;
      Err         : Unbounded_String;
      Runtime_Err : Unbounded_String;
   begin
      Srv.Get_Port (Port, Err);
      if Length (Err) > 0 then
         Fail ("write-close: server setup — " & To_String (Err));
      else
         declare
            T   : AHT.Transport.TCP.TCP_Transport;
            Big : Byte_Array_Access :=
              new AHT.Bytes.Byte_Array'(1 .. Big_Write_Len => 65);

            --  Fires the peer close only once the big write below is parked
            --  on the saturated buffer (mirrors Case 12's Aborter). Swallows
            --  any error so a setup hiccup can't crash the test task.
            task Closer;
            task body Closer is
            begin
               delay 0.1;
               Srv.Close_Now;
            exception
               when others => null;
            end Closer;
         begin
            begin
               T.Connect ("127.0.0.1", Port);
            exception
               when E : others =>
                  Fail ("write-close: Connect — "
                        & Ada.Exceptions.Exception_Message (E));
            end;

            if T.Is_Connected then
               T.Set_Write_Deadline (5.0);
               declare
                  T_Start : constant Time := Clock;
                  Elapsed : Duration;
               begin
                  T.Write (Big.all);
                  Fail ("write-close: Write returned normally "
                        & "(peer closed — should have failed)");
               exception
                  when AHT.Transport.Transport_Error =>
                     Elapsed := Clock - T_Start;
                     if Elapsed > 3.0 then
                        Fail ("write-close: took too long — "
                              & Duration'Image (Elapsed) & "s");
                     end if;
                  when AHT.Transport.Timeout_Error =>
                     Fail ("write-close: hit the write deadline — peer "
                           & "close was not detected (write hung)");
                  when E : others =>
                     Fail ("write-close: unexpected "
                           & Ada.Exceptions.Exception_Name (E) & " — "
                           & Ada.Exceptions.Exception_Message (E));
               end;
            end if;

            Close_Quietly (T);
            Free (Big);
         end;
      end if;
      Srv.Wait_Done (Runtime_Err);
      Check_Server_Runtime ("write-close (server)", Runtime_Err);
   end;

   --  Case 14: a peer reset before the first byte is accepted must still
   --  poison the transport (the zero-progress path). The client connects,
   --  signals Reset_Now, lets the RST settle, then writes a tiny payload
   --  so the first send hits a dead endpoint. Write must raise
   --  Transport_Error, Is_Connected must go False, a retry must be
   --  rejected. Gating the reset on Reset_Now keeps it off the connect.
   declare
      Srv         : Resetter_Server;
      Port        : AHT.URL.Port_Number;
      Err         : Unbounded_String;
      Runtime_Err : Unbounded_String;
   begin
      Srv.Get_Port (Port, Err);
      if Length (Err) > 0 then
         Fail ("write-reset: server setup — " & To_String (Err));
         Srv.Reset_Now;
      else
         declare
            T : AHT.Transport.TCP.TCP_Transport;
         begin
            begin
               T.Connect ("127.0.0.1", Port);
            exception
               when E : others =>
                  Fail ("write-reset: Connect — "
                        & Ada.Exceptions.Exception_Message (E));
            end;

            --  The connect handshake is done: tell the server to RST.
            --  Driving the reset here keeps it from racing the
            --  connect-completion check under load.
            Srv.Reset_Now;

            if T.Is_Connected then
               --  Let the server's RST arrive and be processed so the first
               --  send below fails immediately with zero bytes accepted.
               delay 0.3;
               --  Backstop only: a reset socket reports writable-with-error,
               --  so the send should fail at once; if this deadline ever
               --  fired we'd see Timeout_Error and treat it as a FAIL.
               T.Set_Write_Deadline (2.0);
               begin
                  T.Write (Payload);
                  Fail ("write-reset: first Write returned normally "
                        & "(peer reset — should have failed)");
               exception
                  when AHT.Transport.Transport_Error =>
                     null;  --  expected: reset surfaced as Transport_Error
                  when AHT.Transport.Timeout_Error =>
                     Fail ("write-reset: hit the write deadline — the reset "
                           & "was not detected on the first send");
                  when E : others =>
                     Fail ("write-reset: unexpected "
                           & Ada.Exceptions.Exception_Name (E) & " — "
                           & Ada.Exceptions.Exception_Message (E));
               end;

               --  Zero-progress, but the endpoint is gone: the transport
               --  must be poisoned regardless of how many bytes went out.
               if T.Is_Connected then
                  Fail ("write-reset: still connected after a peer reset on "
                        & "the first send (dead socket left reusable)");
               else
                  begin
                     T.Write (Payload);
                     Fail ("write-reset: second Write succeeded on a "
                           & "poisoned transport (should raise)");
                  exception
                     when AHT.Transport.Transport_Error =>
                        null;  --  expected: "TCP write on closed transport"
                     when E : others =>
                        Fail ("write-reset: second Write raised unexpected "
                              & Ada.Exceptions.Exception_Name (E) & " — "
                              & Ada.Exceptions.Exception_Message (E));
                  end;
               end if;
            end if;

            Close_Quietly (T);
         end;
      end if;
      Srv.Wait_Done (Runtime_Err);
      Check_Server_Runtime ("write-reset (server)", Runtime_Err);
   end;

   --  Case 15: Write's failure path must Poison, not Close_Selector,
   --  while a reader is inside Check_Selector on the same transport. The
   --  reader parks in Read on a deaf peer; the writer trips its write
   --  deadline, which poisons. The write must fail bounded, the reader
   --  must return by the poison path (not EOF, abort or its 5 s backstop)
   --  and the transport must end disconnected. Parking itself is not
   --  proven; see the delay below. Case 15b covers the write selector.
   declare
      Srv         : Deaf_Server;
      Port        : AHT.URL.Port_Number;
      Err         : Unbounded_String;
      Runtime_Err : Unbounded_String;
   begin
      Srv.Get_Port (Port, Err);
      if Length (Err) > 0 then
         Fail ("write-vs-read: server setup — " & To_String (Err));
         Srv.Release;
      else
         declare
            T          : AHT.Transport.TCP.TCP_Transport;
            Big        : Byte_Array_Access :=
              new AHT.Bytes.Byte_Array'(1 .. Big_Write_Len => 65);
            Reader_Out : Unbounded_String;
         begin
            begin
               T.Connect ("127.0.0.1", Port);
            exception
               when E : others =>
                  Fail ("write-vs-read: Connect — "
                        & Ada.Exceptions.Exception_Message (E));
            end;

            if T.Is_Connected then
               --  Backstop only: Poison should wake the reader within the
               --  0.3 s write deadline below. If the reader ever falls
               --  through to this 5 s read deadline, the poison failed to
               --  unblock it and we flag the selector race as a FAIL.
               T.Set_Read_Deadline (5.0);

               declare
                  task Reader;
                  task body Reader is
                     Buf  : AHT.Bytes.Byte_Array (1 .. 64);
                     Last : Natural;
                  begin
                     T.Read (Buf, Last);
                     if Last = 0 then
                        Reader_Out := To_Unbounded_String ("eof");
                     else
                        Reader_Out := To_Unbounded_String ("data");
                     end if;
                  exception
                     when AHT.Transport.Timeout_Error =>
                        Reader_Out := To_Unbounded_String ("timeout");
                     when AHT.Transport.Aborted_Error =>
                        Reader_Out := To_Unbounded_String ("aborted");
                     when E : AHT.Transport.Transport_Error =>
                        --  Only "live at the entry check, dead by the
                        --  selector call" is this case's subject; the
                        --  other wording means dead before the check
                        --  (a task can be descheduled between entering
                        --  and looking). Anything else carries its
                        --  message: it says nothing about the poison.
                        declare
                           M : constant String :=
                             Ada.Exceptions.Exception_Message (E);
                           function Says (S : String) return Boolean is
                             (Ada.Strings.Fixed.Index (M, S) > 0);
                        begin
                           Reader_Out := To_Unbounded_String
                             (if Says ("poisoned after its entry check")
                              then "live-at-guard"
                              elsif Says ("TCP read on closed transport")
                              then "dead-at-guard"
                              else "transport:" & M);
                        end;
                     when E : others =>
                        Reader_Out := To_Unbounded_String
                          ("exn:" & Ada.Exceptions.Exception_Name (E));
                  end Reader;
               begin
                  --  Lets the reader reach Check_Selector first; not
                  --  evidence, nor is its message: Abort_Selector
                  --  queues an event the next Check_Selector consumes.
                  --  Proven: live at the entry check, dead after the
                  --  selector call, out by the poison path; nothing
                  --  observes a task inside a selector. Backout:
                  --  without Poison's selector abort this case takes
                  --  the whole 5 s read deadline on Windows; evidence,
                  --  not proof.
                  delay 0.2;

                  T.Set_Write_Deadline (0.3);
                  begin
                     T.Write (Big.all);
                     Fail ("write-vs-read: Write returned normally on a "
                           & "deaf peer (expected a bounded failure)");
                  exception
                     when AHT.Transport.Timeout_Error
                        | AHT.Transport.Transport_Error =>
                        null;  --  expected: bounded write failure → Poison
                     when E : others =>
                        Fail ("write-vs-read: Write raised unexpected "
                              & Ada.Exceptions.Exception_Name (E) & " — "
                              & Ada.Exceptions.Exception_Message (E));
                  end;
                  --  Exiting this block joins Reader: if the poison failed to
                  --  wake it the test stalls only until the 5 s backstop,
                  --  never forever.
               end;

               --  Reader has terminated; its outcome is now safe to read.
               declare
                  Outcome : constant String := To_String (Reader_Out);
               begin
                  --  Exactly Transport_Error. Poison can wake the reader
                  --  two ways (the shutdown makes the socket readable
                  --  on POSIX, the selector abort reports Aborted on
                  --  both) and Read must collapse both into one answer
                  --  by deciding on Is_Connected. "eof" is the specific
                  --  wrong answer: a write teardown is not a peer close.
                  if Outcome = "live-at-guard" then
                     null;  --  came out by the poison path, as required
                  elsif Outcome = "dead-at-guard" then
                     Fail ("write-vs-read: the reader raised the entry "
                           & "guard's Transport_Error, so the transport was "
                           & "already poisoned when its Read looked, and "
                           & "this run says nothing about the poison path");
                  elsif Outcome = "eof" or else Outcome = "aborted" then
                     Fail ("write-vs-read: the reader came out of the poison "
                           & "reporting """ & Outcome & """ — Read must "
                           & "decide on Is_Connected, not on which wake "
                           & "mechanism arrived first");
                  elsif Outcome = "timeout" then
                     Fail ("write-vs-read: the reader ended on its own 5 s "
                           & "read deadline rather than on the poison, so "
                           & "the poison never reached it (the deadline "
                           & "check fires both before and after the park, "
                           & "so this says nothing about where it was)");
                  elsif Outcome = "data" then
                     Fail ("write-vs-read: reader saw data from a deaf peer");
                  else
                     Fail ("write-vs-read: reader raised " & Outcome);
                  end if;
               end;

               if T.Is_Connected then
                  Fail ("write-vs-read: transport still connected after a "
                        & "poisoning write failure");
               end if;
            end if;

            Srv.Release;
            Close_Quietly (T);
            Free (Big);
         end;
      end if;
      Srv.Wait_Done (Runtime_Err);
      Check_Server_Runtime ("write-vs-read (server)", Runtime_Err);
   end;

   --  Case 15b: Poison must wake a parked writer when a third task
   --  poisons (TLS's Drop_Connection fires from read-side fatal paths).
   --  A writer sits in Write on a deaf peer with a far write deadline;
   --  the main task poisons; the writer must report live at its entry
   --  check and poisoned once its selector call returned. An ordering,
   --  not a parking proof, as in case 15.
   --  Validated by: without the write loop's Connected check this fails
   --  with "aborted", the status only the selector abort produces.
   --  Without Abort_Selector (Write_Selector) it still passes on Linux
   --  and wine, where shutdown wakes a parked writer; the abort stays
   --  because on Windows the read side wakes only through the selector.
   declare
      Srv         : Deaf_Server;
      Port        : AHT.URL.Port_Number;
      Err         : Unbounded_String;
      Runtime_Err : Unbounded_String;
   begin
      Srv.Get_Port (Port, Err);
      if Length (Err) > 0 then
         Fail ("poison-vs-write: server setup — " & To_String (Err));
         Srv.Release;
      else
         declare
            T          : AHT.Transport.TCP.TCP_Transport;
            Big        : Byte_Array_Access :=
              new AHT.Bytes.Byte_Array'(1 .. Big_Write_Len => 66);
            Writer_Out : Unbounded_String;
         begin
            begin
               T.Connect ("127.0.0.1", Port);
            exception
               when E : others =>
                  Fail ("poison-vs-write: Connect — "
                        & Ada.Exceptions.Exception_Message (E));
            end;

            if T.Is_Connected then
               --  Backstop only. Poison should return this write long
               --  before here; falling through to it means the writer
               --  was never woken, which is the regression.
               T.Set_Write_Deadline (10.0);

               declare
                  task Writer;
                  task body Writer is
                  begin
                     T.Write (Big.all);
                     Writer_Out := To_Unbounded_String ("returned");
                  exception
                     when AHT.Transport.Timeout_Error =>
                        Writer_Out := To_Unbounded_String ("timeout");
                     when AHT.Transport.Aborted_Error =>
                        Writer_Out := To_Unbounded_String ("aborted");
                     when E : AHT.Transport.Transport_Error =>
                        --  Both matched positively, anything else
                        --  carried through; see case 15's note.
                        declare
                           M : constant String :=
                             Ada.Exceptions.Exception_Message (E);
                           function Says (S : String) return Boolean is
                             (Ada.Strings.Fixed.Index (M, S) > 0);
                        begin
                           Writer_Out := To_Unbounded_String
                             (if Says ("poisoned after its entry check")
                              then "live-at-guard"
                              elsif Says ("TCP write on closed transport")
                              then "dead-at-guard"
                              else "transport:" & M);
                        end;
                     when E : others =>
                        Writer_Out := To_Unbounded_String
                          ("exn:" & Ada.Exceptions.Exception_Name (E));
                  end Writer;
               begin
                  --  As for case 15's delay: it makes the writer likely
                  --  to be parked and proves nothing, and the message
                  --  proves an ordering, not a park.
                  delay 0.5;
                  T.Poison;
                  --  Leaving this block joins Writer; the 10 s write
                  --  deadline bounds the wait if the poison did not
                  --  wake it.
               end;

               declare
                  Outcome : constant String := To_String (Writer_Out);
               begin
                  if Outcome = "live-at-guard" then
                     null;  --  a third party ended the write
                  elsif Outcome = "dead-at-guard" then
                     Fail ("poison-vs-write: the writer raised the entry "
                           & "guard's Transport_Error, so the transport "
                           & "was already poisoned when its Write looked, "
                           & "and this run says nothing about the poison "
                           & "path");
                  elsif Outcome = "timeout" then
                     Fail ("poison-vs-write: the writer ended on its own "
                           & "10 s write deadline rather than on Poison, so "
                           & "Poison never reached it (the deadline check "
                           & "fires both before and after the park, so this "
                           & "says nothing about where it was)");
                  elsif Outcome = "returned" then
                     Fail ("poison-vs-write: the write completed against a "
                           & "peer that never reads, so there was no write "
                           & "still outstanding when Poison ran and this "
                           & "run proves nothing (it may have waited and "
                           & "finished anyway — what failed is the premise, "
                           & "not a claim about where it waited)");
                  else
                     Fail ("poison-vs-write: writer raised " & Outcome);
                  end if;
               end;

               if T.Is_Connected then
                  Fail ("poison-vs-write: transport still connected after "
                        & "Poison");
               end if;
            end if;

            Srv.Release;
            Close_Quietly (T);
            Free (Big);
         end;
      end if;
      Srv.Wait_Done (Runtime_Err);
      Check_Server_Runtime ("poison-vs-write (server)", Runtime_Err);
   end;


   --  Case 16: a transport is single-use. A poisoned transport still owns
   --  its fd/selectors until the single-threaded Close reclaims them, and
   --  Connect must not reclaim them in place: a reader parked on the old
   --  session could wake on a swapped-in fd. Phase 1 poisons T on a deaf
   --  peer; phase 2 asserts an in-place reconnect raises; phase 3 Closes
   --  T and round-trips a fresh transport to the echo server.
   declare
      Deaf        : Deaf_Server;
      Echo        : Echo_Server;
      Deaf_Port   : AHT.URL.Port_Number;
      Echo_Port   : AHT.URL.Port_Number;
      Deaf_Err    : Unbounded_String;
      Echo_Err    : Unbounded_String;
      Deaf_RT     : Unbounded_String;
      Echo_RT     : Unbounded_String;
   begin
      Deaf.Get_Port (Deaf_Port, Deaf_Err);
      Echo.Get_Port (Echo_Port, Echo_Err);
      if Length (Deaf_Err) > 0 then
         Fail ("reconnect: deaf server setup — " & To_String (Deaf_Err));
         Deaf.Release;
      elsif Length (Echo_Err) > 0 then
         Fail ("reconnect: echo server setup — " & To_String (Echo_Err));
         Deaf.Release;
      else
         declare
            T   : AHT.Transport.TCP.TCP_Transport;
            Big : Byte_Array_Access :=
              new AHT.Bytes.Byte_Array'(1 .. Big_Write_Len => 65);
         begin
            --  Phase 1: poison T on the deaf peer (mid-send write timeout).
            begin
               T.Connect ("127.0.0.1", Deaf_Port);
            exception
               when E : others =>
                  Fail ("reconnect: phase-1 Connect — "
                        & Ada.Exceptions.Exception_Message (E));
            end;

            if T.Is_Connected then
               T.Set_Write_Deadline (0.3);
               begin
                  T.Write (Big.all);
                  Fail ("reconnect: phase-1 Write returned normally "
                        & "(deaf peer — expected a bounded failure)");
               exception
                  when AHT.Transport.Timeout_Error =>
                     null;  --  expected: mid-send timeout -> poison
                  when E : others =>
                     Fail ("reconnect: phase-1 Write raised unexpected "
                           & Ada.Exceptions.Exception_Name (E) & " — "
                           & Ada.Exceptions.Exception_Message (E));
               end;
               if T.Is_Connected then
                  Fail ("reconnect: not poisoned after the phase-1 timeout");
               end if;
            end if;
            Deaf.Release;
            Free (Big);

            --  Phase 2: an in-place reconnect of the SAME poisoned (never
            --  Closed) object must be rejected: the fd is still owned, so
            --  recycling it would race a stale reader. No silent reuse/leak.
            begin
               T.Connect ("127.0.0.1", Echo_Port);
               Fail ("reconnect: in-place Connect on a poisoned transport "
                     & "succeeded (must reject; transport is single-use)");
               Close_Quietly (T);
            exception
               when AHT.Transport.Transport_Error =>
                  null;  --  expected: "still owns a connection; Close it ..."
               when E : others =>
                  Fail ("reconnect: in-place Connect raised unexpected "
                        & Ada.Exceptions.Exception_Name (E) & " — "
                        & Ada.Exceptions.Exception_Message (E));
            end;

            --  Phase 3: Close reclaims the poisoned fd/selectors (must not
            --  hang or raise). Single-use is permanent: even after Close, a
            --  Connect on the SAME (already-used) object must still raise;
            --  this is the latch that survives a Close which raced a parked
            --  reader and could only best-effort the selector teardown.
            Close_Quietly (T);
            begin
               T.Connect ("127.0.0.1", Echo_Port);
               Fail ("reconnect: Connect on a closed, already-used transport "
                     & "succeeded (single-use must be permanent)");
               Close_Quietly (T);
            exception
               when AHT.Transport.Transport_Error =>
                  null;  --  expected: "single-use; use a fresh transport"
               when E : others =>
                  Fail ("reconnect: post-Close Connect raised unexpected "
                        & Ada.Exceptions.Exception_Name (E) & " — "
                        & Ada.Exceptions.Exception_Message (E));
            end;

            --  A FRESH transport, by contrast, connects and round-trips
            --  cleanly, proving nothing global was corrupted. Drive_Echo
            --  closes Fresh.
            declare
               Fresh : AHT.Transport.TCP.TCP_Transport;
            begin
               Fresh.Connect ("127.0.0.1", Echo_Port);
               Drive_Echo ("reconnect (fresh)", Fresh);
            exception
               when E : others =>
                  Fail ("reconnect: fresh transport — "
                        & Ada.Exceptions.Exception_Name (E) & " — "
                        & Ada.Exceptions.Exception_Message (E));
            end;
         end;
      end if;
      Deaf.Wait_Done (Deaf_RT);
      Echo.Wait_Done (Echo_RT);
      Check_Server_Runtime ("reconnect (deaf server)", Deaf_RT);
      Check_Server_Runtime ("reconnect (echo server)", Echo_RT);
   end;

   if Failures = 0 then
      Put_Line ("test_tcp: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tcp:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TCP;
