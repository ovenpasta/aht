--  Cross-task cancel via AHT.HTTP.Client.Cancel_Handle.
--
--  The cancel mechanism rides Transport.Abort_Pending, which is
--  already covered at the transport level by test_tcp. This binary
--  exercises the layer above it: the protected Cancel_State that
--  threads the live transport into the handle for the duration of
--  Send, and the pre-cancel short-circuit.
--
--  Four cases:
--    1. Cancel during a blocked Read — silent in-process server
--       accepts but never writes; a sibling task fires Cancel after
--       0.2 s; Send raises Aborted_Error inside the safety window.
--    2. Pre-cancel — Cancel called before Send. Send raises
--       Aborted_Error immediately without dialing.
--    3. Post-Send Cancel is harmless — Send completes against a
--       fast in-process server, then Cancel runs and is a no-op
--       (no exception, no double-close on the closed transport).
--    4. Is_Cancelled reflects state — false initially, true after
--       any Cancel.

with Ada.Calendar; use Ada.Calendar;
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Streams; use Ada.Streams;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;
with GNAT.Sockets; use GNAT.Sockets;

with AHT.HTTP;
with AHT.HTTP.Client;
with AHT.HTTP.Methods;
with AHT.HTTP.Request;
with AHT.HTTP.Response;
with AHT.Transport;
with AHT.URL;

procedure Test_HTTP_Cancel is

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_http_cancel: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Silent HTTP-shaped server: accepts a connection and holds it
   --  for up to Hold_Seconds without ever writing a byte. The
   --  client's Read parks; the only way for Send to return is
   --  Cancel (Aborted_Error) or the client's own read deadline
   --  (Timeout_Error).
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
              (Selector, R_Set, W_Set, Status, Timeout => 3.0);
            Close_Selector (Selector);

            if Status = Completed then
               begin
                  Accept_Socket (Server, Client, Peer);
                  --  Drain the request, then sit on a second
                  --  Receive that blocks until the client tears its
                  --  end down. This is what makes the server
                  --  "silent": once the request is in we never
                  --  write, so the client's Read parks waiting for
                  --  a response that will only ever arrive when
                  --  Cancel (or the read deadline) fires and the
                  --  client closes — at which point our blocked
                  --  Receive returns Last < First (EOF) and we
                  --  proceed to clean up.
                  declare
                     Buf  : Stream_Element_Array (1 .. 4_096);
                     Last : Stream_Element_Offset;
                  begin
                     Receive_Socket (Client, Buf, Last);
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

      select
         accept Wait_Done (Runtime_Err : out Unbounded_String) do
            Runtime_Err := Runtime_Error;
         end Wait_Done;
      or
         terminate;
      end select;
   end Silent_Server;

   --  Fast HTTP server: accepts one connection, reads request,
   --  sends a fixed 200 response, closes. Used for the
   --  post-Send-cancel-is-harmless case.
   task type Fast_Server is
      entry Get_Port
        (P   : out AHT.URL.Port_Number;
         Err : out Unbounded_String);
      entry Wait_Done (Runtime_Err : out Unbounded_String);
   end Fast_Server;

   task body Fast_Server is
      Server        : Socket_Type := No_Socket;
      Client        : Socket_Type;
      Peer          : Sock_Addr_Type;
      Bind_To       : Sock_Addr_Type;
      Bound         : Port_Type := 0;
      Setup_Error   : Unbounded_String;
      Runtime_Error : Unbounded_String;

      Response : constant String :=
        "HTTP/1.1 200 OK" & ASCII.CR & ASCII.LF
        & "Content-Length: 2" & ASCII.CR & ASCII.LF
        & "Connection: close" & ASCII.CR & ASCII.LF
        & ASCII.CR & ASCII.LF
        & "OK";
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
              ("Fast_Server setup: "
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
         begin
            Accept_Socket (Server, Client, Peer);

            --  Drain the request until CRLFCRLF (we don't care
            --  what's in it; just need to consume it so Send isn't
            --  stuck on Write).
            declare
               Buf : Stream_Element_Array (1 .. 4_096);
               Last : Stream_Element_Offset;
               Seen : Unbounded_String;
            begin
               loop
                  Receive_Socket (Client, Buf, Last);
                  exit when Last < Buf'First;
                  for I in Buf'First .. Last loop
                     Append (Seen,
                             Character'Val (Natural (Buf (I))));
                  end loop;
                  exit when Index (Seen,
                                    ASCII.CR & ASCII.LF
                                    & ASCII.CR & ASCII.LF) /= 0;
               end loop;
            end;

            declare
               R : Stream_Element_Array
                 (1 .. Stream_Element_Offset (Response'Length));
               Sent : Stream_Element_Offset;
            begin
               for I in Response'Range loop
                  R (Stream_Element_Offset
                       (I - Response'First + 1)) :=
                    Stream_Element (Character'Pos (Response (I)));
               end loop;
               Send_Socket (Client, R, Sent);
            end;

            Shutdown_Socket (Client, Shut_Write);
            Close_Socket (Client);
         exception
            when E : others =>
               Runtime_Error := To_Unbounded_String
                 ("Fast_Server runtime: "
                  & Ada.Exceptions.Exception_Name (E) & " — "
                  & Ada.Exceptions.Exception_Message (E));
         end;
         begin
            Close_Socket (Server);
         exception
            when others => null;
         end;
      end if;

      select
         accept Wait_Done (Runtime_Err : out Unbounded_String) do
            Runtime_Err := Runtime_Error;
         end Wait_Done;
      or
         terminate;
      end select;
   end Fast_Server;

   --  Build a fresh URL each case so they don't share state.
   function URL_For
     (Port : AHT.URL.Port_Number; Path : String) return String
   is
   begin
      return "http://127.0.0.1:"
        & Ada.Strings.Fixed.Trim
            (AHT.URL.Port_Number'Image (Port), Ada.Strings.Both)
        & Path;
   end URL_For;

begin

   --  Case 1: cancel during a blocked Read.
   declare
      Server   : Silent_Server;
      Port     : AHT.URL.Port_Number;
      Setup_Err, Run_Err : Unbounded_String;
      C        : AHT.HTTP.Client.Client_Type;
      Req      : AHT.HTTP.Request.Request_Type;
      Resp     : AHT.HTTP.Response.Response_Type;
      Handle   : AHT.HTTP.Client.Cancel_Handle;
      Started  : Time;
      Elapsed  : Duration;
      Raised_Aborted : Boolean := False;

      task Canceller is
         entry Go;
      end Canceller;
      task body Canceller is
      begin
         accept Go;
         delay 0.2;
         begin
            AHT.HTTP.Client.Cancel (Handle);
         exception
            when E : others =>
               Put_Line ("test_http_cancel: Canceller raised "
                         & Ada.Exceptions.Exception_Name (E));
         end;
      end Canceller;
   begin
      C.Timeout_Seconds := 3;  -- safety: bail out before any test
                               -- timeout would mask a stuck Send

      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("cancel-during-read: server setup: "
               & To_String (Setup_Err));
         Canceller.Go;  -- still kick it so the task terminates
      else
         Req.Method := AHT.HTTP.Methods.GET;
         Req.Target := AHT.URL.Parse (URL_For (Port, "/hang"));

         Started := Clock;
         Canceller.Go;
         begin
            AHT.HTTP.Client.Send (C, Req, Resp, Handle);
            Fail ("cancel-during-read: Send returned without raising");
         exception
            when AHT.Transport.Aborted_Error =>
               Raised_Aborted := True;
            when E : others =>
               Fail ("cancel-during-read: wrong exception "
                     & Ada.Exceptions.Exception_Name (E) & ": "
                     & Ada.Exceptions.Exception_Message (E));
         end;
         Elapsed := Clock - Started;

         Server.Wait_Done (Run_Err);
         --  An ECONNRESET / EPIPE here is expected: the client's
         --  Abort_Pending tears down the selector and the
         --  subsequent Close hangs up on the server mid-Receive.
         --  We don't fail on Run_Err in this case; only the
         --  client-side Aborted_Error matters.

         if Raised_Aborted then
            if Elapsed > 1.5 then
               Fail ("cancel-during-read: Send took"
                     & Duration'Image (Elapsed)
                     & "s (expected <1.5s after 0.2s cancel)");
            end if;
            if not AHT.HTTP.Client.Is_Cancelled (Handle) then
               Fail ("cancel-during-read: Is_Cancelled false after Cancel");
            end if;
         end if;
      end if;
   end;

   --  Case 2: pre-cancel — Cancel before Send. Must raise
   --  immediately and must not even dial. We give the URL a port
   --  with nothing listening so a "successful" connect would either
   --  raise Transport_Error (visible as the wrong exception) or
   --  hang on Connect's timeout (visible as a long Elapsed).
   declare
      C       : AHT.HTTP.Client.Client_Type;
      Req     : AHT.HTTP.Request.Request_Type;
      Resp    : AHT.HTTP.Response.Response_Type;
      Handle  : AHT.HTTP.Client.Cancel_Handle;
      Started : Time;
      Elapsed : Duration;
   begin
      AHT.HTTP.Client.Cancel (Handle);
      if not AHT.HTTP.Client.Is_Cancelled (Handle) then
         Fail ("pre-cancel: Is_Cancelled false after Cancel");
      end if;

      Req.Method := AHT.HTTP.Methods.GET;
      --  Port 1 is privileged + nothing listens there; if pre-cancel
      --  doesn't short-circuit, the connect raises Transport_Error
      --  (or hangs), and either way the test fails loudly.
      Req.Target := AHT.URL.Parse ("http://127.0.0.1:1/never");

      Started := Clock;
      begin
         AHT.HTTP.Client.Send (C, Req, Resp, Handle);
         Fail ("pre-cancel: Send returned without raising");
      exception
         when AHT.Transport.Aborted_Error => null;
         when E : others =>
            Fail ("pre-cancel: wrong exception "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
      end;
      Elapsed := Clock - Started;
      if Elapsed > 0.5 then
         Fail ("pre-cancel: Send took"
               & Duration'Image (Elapsed)
               & "s (expected <0.5s; pre-cancel should "
               & "short-circuit before any connect attempt)");
      end if;
   end;

   --  Case 3: Cancel after a successful Send is a no-op.
   declare
      Server   : Fast_Server;
      Port     : AHT.URL.Port_Number;
      Setup_Err, Run_Err : Unbounded_String;
      C        : AHT.HTTP.Client.Client_Type;
      Req      : AHT.HTTP.Request.Request_Type;
      Resp     : AHT.HTTP.Response.Response_Type;
      Handle   : AHT.HTTP.Client.Cancel_Handle;
   begin
      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("post-send-cancel: server setup: "
               & To_String (Setup_Err));
      else
         Req.Method := AHT.HTTP.Methods.GET;
         Req.Target := AHT.URL.Parse (URL_For (Port, "/ok"));
         begin
            AHT.HTTP.Client.Send (C, Req, Resp, Handle);
         exception
            when E : others =>
               Fail ("post-send-cancel: Send raised "
                     & Ada.Exceptions.Exception_Name (E) & ": "
                     & Ada.Exceptions.Exception_Message (E));
         end;
         Server.Wait_Done (Run_Err);
         if Length (Run_Err) > 0 then
            Fail ("post-send-cancel: server: "
                  & To_String (Run_Err));
         end if;
         if Resp.Status /= 200 then
            Fail ("post-send-cancel: status =" & Resp.Status'Image);
         end if;

         --  Now fire Cancel. Handle's Bound is null (Send already
         --  unbound). Must be a quiet no-op.
         begin
            AHT.HTTP.Client.Cancel (Handle);
         exception
            when E : others =>
               Fail ("post-send-cancel: Cancel raised "
                     & Ada.Exceptions.Exception_Name (E));
         end;
         if not AHT.HTTP.Client.Is_Cancelled (Handle) then
            Fail ("post-send-cancel: Is_Cancelled false after Cancel");
         end if;
      end if;
   end;

   --  Case 4: Is_Cancelled is false on a fresh handle.
   declare
      Handle : AHT.HTTP.Client.Cancel_Handle;
   begin
      if AHT.HTTP.Client.Is_Cancelled (Handle) then
         Fail ("fresh-handle: Is_Cancelled true on a never-cancelled "
               & "handle");
      end if;
   end;

   if Failures = 0 then
      Put_Line ("test_http_cancel: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_http_cancel:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_HTTP_Cancel;
