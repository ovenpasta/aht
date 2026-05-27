--  Exercises AHT.HTTP.Client.Send_Streaming end-to-end.
--
--  Four cases:
--    1. Chunked body streaming — GET /chunked, sink receives the
--       decoded chunks one at a time, assembled bytes match the
--       fixture's "AHT rocks!\n", and Resp.Body_B is empty after.
--    2. Content-Length streaming — GET /hello, sink delivers the
--       fixed-length body in one or more chunks, total bytes match
--       "hello, world\n", Resp.Body_B is empty.
--    3. Cancel during streaming — silent in-process server holds
--       the connection; sibling task fires Cancel; Send_Streaming
--       raises Aborted_Error and sink was never invoked.
--    4. Sink exception propagates — fast in-process server sends a
--       body; sink raises on the first call; the exception comes
--       out of Send_Streaming and the transport is closed cleanly
--       (a second Send_Streaming on a fresh handle still succeeds,
--       proving the runtime isn't poisoned by the prior failure).

with Ada.Calendar; use Ada.Calendar;
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Streams; use Ada.Streams;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;
with GNAT.Sockets; use GNAT.Sockets;

with AHT.Bytes;
with AHT.HTTP;
with AHT.HTTP.Client;
with AHT.HTTP.Methods;
with AHT.HTTP.Request;
with AHT.HTTP.Response;
with AHT.Transport;
with AHT.URL;

procedure Test_HTTP_Streaming is

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_http_streaming: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Silent server reused from the cancel test's pattern: accept,
   --  drain one Receive worth of bytes, then sit on a second
   --  blocking Receive until the client closes.
   task type Silent_Server is
      entry Get_Port
        (P   : out AHT.URL.Port_Number;
         Err : out Unbounded_String);
      entry Wait_Done (Runtime_Err : out Unbounded_String);
   end Silent_Server;

   task body Silent_Server is
      Server         : Socket_Type := No_Socket;
      Client         : Socket_Type;
      Peer           : Sock_Addr_Type;
      Bind_To        : Sock_Addr_Type;
      Bound          : Port_Type := 0;
      Setup_Error    : Unbounded_String;
      Runtime_Error  : Unbounded_String;
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

   --  Fast HTTP server (canned 200 with Content-Length body), reused
   --  for the sink-raises case.
   task type Fast_Server is
      entry Get_Port
        (P   : out AHT.URL.Port_Number;
         Err : out Unbounded_String);
      entry Wait_Done (Runtime_Err : out Unbounded_String);
   end Fast_Server;

   task body Fast_Server is
      Server         : Socket_Type := No_Socket;
      Client         : Socket_Type;
      Peer           : Sock_Addr_Type;
      Bind_To        : Sock_Addr_Type;
      Bound          : Port_Type := 0;
      Setup_Error    : Unbounded_String;
      Runtime_Error  : Unbounded_String;

      Response : constant String :=
        "HTTP/1.1 200 OK" & ASCII.CR & ASCII.LF
        & "Content-Length: 5" & ASCII.CR & ASCII.LF
        & "Connection: close" & ASCII.CR & ASCII.LF
        & ASCII.CR & ASCII.LF
        & "hello";
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

   function URL_For
     (Port : AHT.URL.Port_Number; Path : String) return String
   is
   begin
      return "http://127.0.0.1:"
        & Ada.Strings.Fixed.Trim
            (AHT.URL.Port_Number'Image (Port), Ada.Strings.Both)
        & Path;
   end URL_For;

   --  Sink helpers built around a per-case Unbounded_String + call
   --  counter. Use file-scope state for the sink-raises case (so
   --  the nested sink can flip a flag) and per-case local state
   --  via outer references for the others.

   Sink_Exception : exception;

begin

   --  Case 1: chunked body via the fixture's /chunked route.
   declare
      C        : AHT.HTTP.Client.Client_Type;
      Req      : AHT.HTTP.Request.Request_Type;
      Resp     : AHT.HTTP.Response.Response_Type;
      Body_S   : Unbounded_String;
      Calls    : Natural := 0;

      procedure Collect (Chunk : AHT.Bytes.Byte_Array) is
      begin
         Calls := Calls + 1;
         for B of Chunk loop
            Append (Body_S, Character'Val (Natural (B)));
         end loop;
      end Collect;
   begin
      Req.Method := AHT.HTTP.Methods.GET;
      Req.Target :=
        AHT.URL.Parse ("http://127.0.0.1:8764/chunked");

      begin
         AHT.HTTP.Client.Send_Streaming
           (C, Req, Resp, Sink => Collect'Access);
      exception
         when E : others =>
            Fail ("chunked: Send_Streaming raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E)
                  & " (is tests/server/server.py running?)");
            Put_Line ("test_http_streaming:" & Failures'Image
                      & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;

      if Resp.Status /= 200 then
         Fail ("chunked: status =" & Resp.Status'Image);
      end if;
      if Natural (Resp.Body_B.Length) /= 0 then
         Fail ("chunked: Body_B not empty after streaming, length ="
               & Natural'Image (Natural (Resp.Body_B.Length)));
      end if;
      if To_String (Body_S) /= "AHT rocks!" & ASCII.LF then
         Fail ("chunked: assembled = """
               & To_String (Body_S) & """");
      end if;
      if Calls = 0 then
         Fail ("chunked: sink never called");
      end if;
   end;

   --  Case 2: Content-Length body via /hello.
   declare
      C        : AHT.HTTP.Client.Client_Type;
      Req      : AHT.HTTP.Request.Request_Type;
      Resp     : AHT.HTTP.Response.Response_Type;
      Body_S   : Unbounded_String;
      Calls    : Natural := 0;

      procedure Collect (Chunk : AHT.Bytes.Byte_Array) is
      begin
         Calls := Calls + 1;
         for B of Chunk loop
            Append (Body_S, Character'Val (Natural (B)));
         end loop;
      end Collect;
   begin
      Req.Method := AHT.HTTP.Methods.GET;
      Req.Target := AHT.URL.Parse ("http://127.0.0.1:8764/hello");

      begin
         AHT.HTTP.Client.Send_Streaming
           (C, Req, Resp, Sink => Collect'Access);
      exception
         when E : others =>
            Fail ("CL: Send_Streaming raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
      end;

      if Resp.Status /= 200 then
         Fail ("CL: status =" & Resp.Status'Image);
      end if;
      if Natural (Resp.Body_B.Length) /= 0 then
         Fail ("CL: Body_B not empty, length ="
               & Natural'Image (Natural (Resp.Body_B.Length)));
      end if;
      if To_String (Body_S) /= "hello, world" & ASCII.LF then
         Fail ("CL: assembled = """ & To_String (Body_S) & """");
      end if;
      if Calls = 0 then
         Fail ("CL: sink never called");
      end if;
   end;

   --  Case 3: cancel during a streaming Send against the silent
   --  server. Sink must never be invoked.
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
      Sink_Calls : Natural := 0;
      Raised_Aborted : Boolean := False;

      procedure Collect (Chunk : AHT.Bytes.Byte_Array) is
         pragma Unreferenced (Chunk);
      begin
         Sink_Calls := Sink_Calls + 1;
      end Collect;

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
            when others => null;
         end;
      end Canceller;
   begin
      C.Timeout_Seconds := 3;
      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("cancel-stream: server setup: "
               & To_String (Setup_Err));
         Canceller.Go;
      else
         Req.Method := AHT.HTTP.Methods.GET;
         Req.Target := AHT.URL.Parse (URL_For (Port, "/hang"));

         Started := Clock;
         Canceller.Go;
         begin
            AHT.HTTP.Client.Send_Streaming
              (C, Req, Resp,
               Sink   => Collect'Access,
               Cancel => Handle);
            Fail ("cancel-stream: Send_Streaming returned without "
                  & "raising");
         exception
            when AHT.Transport.Aborted_Error =>
               Raised_Aborted := True;
            when E : others =>
               Fail ("cancel-stream: wrong exception "
                     & Ada.Exceptions.Exception_Name (E) & ": "
                     & Ada.Exceptions.Exception_Message (E));
         end;
         Elapsed := Clock - Started;

         Server.Wait_Done (Run_Err);

         if Raised_Aborted then
            if Elapsed > 1.5 then
               Fail ("cancel-stream: Send_Streaming took"
                     & Duration'Image (Elapsed) & "s");
            end if;
            if Sink_Calls /= 0 then
               Fail ("cancel-stream: sink was called"
                     & Natural'Image (Sink_Calls) & " times "
                     & "(should be 0 — server never wrote)");
            end if;
            if not AHT.HTTP.Client.Is_Cancelled (Handle) then
               Fail ("cancel-stream: Is_Cancelled false after Cancel");
            end if;
         end if;
      end if;
   end;

   --  Case 4: sink raising propagates out of Send_Streaming, and a
   --  subsequent successful streaming call against a fresh server
   --  proves the runtime is fine.
   declare
      Server   : Fast_Server;
      Port     : AHT.URL.Port_Number;
      Setup_Err, Run_Err : Unbounded_String;
      C        : AHT.HTTP.Client.Client_Type;
      Req      : AHT.HTTP.Request.Request_Type;
      Resp     : AHT.HTTP.Response.Response_Type;

      procedure Raise_On_Chunk (Chunk : AHT.Bytes.Byte_Array) is
         pragma Unreferenced (Chunk);
      begin
         raise Sink_Exception with "sink test exception";
      end Raise_On_Chunk;
   begin
      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("sink-raise: server setup: "
               & To_String (Setup_Err));
      else
         Req.Method := AHT.HTTP.Methods.GET;
         Req.Target := AHT.URL.Parse (URL_For (Port, "/x"));

         begin
            AHT.HTTP.Client.Send_Streaming
              (C, Req, Resp, Sink => Raise_On_Chunk'Access);
            Fail ("sink-raise: Send_Streaming returned without "
                  & "raising");
         exception
            when Sink_Exception => null;  -- expected
            when E : others =>
               Fail ("sink-raise: wrong exception "
                     & Ada.Exceptions.Exception_Name (E));
         end;

         Server.Wait_Done (Run_Err);
         --  ECONNRESET / EPIPE on the server's last write is fine —
         --  the client tore the transport down on the exception
         --  path. Don't fail on Run_Err here.
      end if;
   end;

   --  Sanity follow-up to case 4: a fresh Send_Streaming after the
   --  raise still works. Uses a second Fast_Server because each
   --  task only handles one connection.
   declare
      Server   : Fast_Server;
      Port     : AHT.URL.Port_Number;
      Setup_Err, Run_Err : Unbounded_String;
      C        : AHT.HTTP.Client.Client_Type;
      Req      : AHT.HTTP.Request.Request_Type;
      Resp     : AHT.HTTP.Response.Response_Type;
      Body_S   : Unbounded_String;

      procedure Collect (Chunk : AHT.Bytes.Byte_Array) is
      begin
         for B of Chunk loop
            Append (Body_S, Character'Val (Natural (B)));
         end loop;
      end Collect;
   begin
      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("post-raise: server setup: "
               & To_String (Setup_Err));
      else
         Req.Method := AHT.HTTP.Methods.GET;
         Req.Target := AHT.URL.Parse (URL_For (Port, "/y"));

         begin
            AHT.HTTP.Client.Send_Streaming
              (C, Req, Resp, Sink => Collect'Access);
         exception
            when E : others =>
               Fail ("post-raise: follow-up Send_Streaming raised "
                     & Ada.Exceptions.Exception_Name (E) & ": "
                     & Ada.Exceptions.Exception_Message (E));
         end;
         Server.Wait_Done (Run_Err);
         if Length (Run_Err) > 0 then
            Fail ("post-raise: server: " & To_String (Run_Err));
         end if;
         if Resp.Status /= 200 then
            Fail ("post-raise: status =" & Resp.Status'Image);
         end if;
         if To_String (Body_S) /= "hello" then
            Fail ("post-raise: assembled = """
                  & To_String (Body_S) & """");
         end if;
      end if;
   end;

   if Failures = 0 then
      Put_Line ("test_http_streaming: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_http_streaming:" & Failures'Image
                & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_HTTP_Streaming;
