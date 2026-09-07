--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Exercises AHT.HTTP.Client.Send_Async / Await / Cancel.
--
--  Eight cases:
--    1. Happy path — Send_Async to /hello, Await returns 200 with
--       body "hello, world\n" and Is_Done flips to true.
--    2. Concurrent requests — two handles, two Send_Asyncs to
--       /hello, both Await complete with 200 and matching bodies.
--    3. Cancel before Await — silent in-process server holds the
--       connection; sibling task fires Cancel; Await re-raises
--       Aborted_Error with original identity preserved.
--    4. Double Send_Async raises — calling Send_Async on a handle
--       that's already started raises HTTP_Error.
--    5. Drop without Await — handle is declared inside an inner
--       block and Send_Async'd against /hello; the block ends
--       without Awaiting, and the enclosing master waits for the
--       worker (which is short). Test asserts the wait was bounded.
--    6. Exception identity round-trip — Send_Async against a
--       wss:// URL (rejected by Send) propagates the original
--       HTTP_Error out of Await, not a generic wrapper.
--    7. Await before Send_Async — calling Await on a fresh handle
--       must raise HTTP_Error, not deadlock on the worker's Start
--       rendezvous.
--    8. Double Await returns the same result — a second Await on
--       a Done handle returns the same response without blocking
--       (the worker stashed the result in the protected state and
--       has already terminated, so this only re-reads).

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

procedure Test_HTTP_Async is

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_http_async: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function Body_To_String (V : AHT.Bytes.Buffer) return String is
     (AHT.Bytes.To_String (V));

   --  Silent server reused from the cancel/streaming tests.
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

   --  Case 1: happy path against the Python fixture's /hello.
   declare
      C    : AHT.HTTP.Client.Client_Type;
      Req  : AHT.HTTP.Request.Request_Type;
      Resp : AHT.HTTP.Response.Response_Type;
      H    : AHT.HTTP.Client.Async_Handle;
   begin
      Req.Method := AHT.HTTP.Methods.GET;
      Req.Target := AHT.URL.Parse ("http://127.0.0.1:8764/hello");

      begin
         AHT.HTTP.Client.Send_Async (C, Req, H);
      exception
         when E : others =>
            Fail ("happy: Send_Async raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E)
                  & " (is tests/server/server.py running?)");
            Put_Line ("test_http_async:" & Failures'Image
                      & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;

      begin
         AHT.HTTP.Client.Await (H, Resp);
      exception
         when E : others =>
            Fail ("happy: Await raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
      end;

      if Resp.Status /= 200 then
         Fail ("happy: status =" & Resp.Status'Image);
      end if;
      if Body_To_String (Resp.Body_B) /= "hello, world" & ASCII.LF then
         Fail ("happy: body = """ & Body_To_String (Resp.Body_B) & """");
      end if;
      if not AHT.HTTP.Client.Is_Done (H) then
         Fail ("happy: Is_Done false after successful Await");
      end if;
   end;

   --  Case 2: two concurrent Send_Asyncs against the fixture.
   declare
      C    : AHT.HTTP.Client.Client_Type;
      Req1, Req2  : AHT.HTTP.Request.Request_Type;
      Resp1, Resp2 : AHT.HTTP.Response.Response_Type;
      Ha, Hb : AHT.HTTP.Client.Async_Handle;
   begin
      Req1.Method := AHT.HTTP.Methods.GET;
      Req1.Target := AHT.URL.Parse ("http://127.0.0.1:8764/hello");
      Req2.Method := AHT.HTTP.Methods.GET;
      Req2.Target := AHT.URL.Parse ("http://127.0.0.1:8764/json");

      AHT.HTTP.Client.Send_Async (C, Req1, Ha);
      AHT.HTTP.Client.Send_Async (C, Req2, Hb);

      begin
         AHT.HTTP.Client.Await (Ha, Resp1);
         AHT.HTTP.Client.Await (Hb, Resp2);
      exception
         when E : others =>
            Fail ("concurrent: Await raised "
                  & Ada.Exceptions.Exception_Name (E));
      end;

      if Resp1.Status /= 200 or else Resp2.Status /= 200 then
         Fail ("concurrent: statuses ="
               & Resp1.Status'Image & " /"
               & Resp2.Status'Image);
      end if;
      if Body_To_String (Resp1.Body_B) /= "hello, world" & ASCII.LF then
         Fail ("concurrent: body1 = """
               & Body_To_String (Resp1.Body_B) & """");
      end if;
      if Body_To_String (Resp2.Body_B) /= "{""ok"":true}" & ASCII.LF then
         Fail ("concurrent: body2 = """
               & Body_To_String (Resp2.Body_B) & """");
      end if;
   end;

   --  Case 3: Cancel before Await against a silent server. Await
   --  re-raises Aborted_Error with original identity.
   declare
      Server   : Silent_Server;
      Port     : AHT.URL.Port_Number;
      Setup_Err, Run_Err : Unbounded_String;
      C        : AHT.HTTP.Client.Client_Type;
      Req      : AHT.HTTP.Request.Request_Type;
      Resp     : AHT.HTTP.Response.Response_Type;
      H        : AHT.HTTP.Client.Async_Handle;
      Raised_Aborted : Boolean := False;
      Started, Ended : Time;
   begin
      C.Timeout_Seconds := 3;
      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("cancel-async: server setup: "
               & To_String (Setup_Err));
      else
         Req.Method := AHT.HTTP.Methods.GET;
         Req.Target := AHT.URL.Parse (URL_For (Port, "/hang"));

         Started := Clock;
         AHT.HTTP.Client.Send_Async (C, Req, H);
         delay 0.2;
         AHT.HTTP.Client.Cancel (H);

         begin
            AHT.HTTP.Client.Await (H, Resp);
            Fail ("cancel-async: Await returned without raising");
         exception
            when AHT.Transport.Aborted_Error =>
               Raised_Aborted := True;
            when E : others =>
               Fail ("cancel-async: wrong exception re-raised "
                     & Ada.Exceptions.Exception_Name (E));
         end;
         Ended := Clock;

         Server.Wait_Done (Run_Err);

         if Raised_Aborted then
            if Ended - Started > 1.5 then
               Fail ("cancel-async: Await took"
                     & Duration'Image (Ended - Started) & "s");
            end if;
            if not AHT.HTTP.Client.Is_Cancelled (H) then
               Fail ("cancel-async: Is_Cancelled false after Cancel");
            end if;
            if not AHT.HTTP.Client.Is_Done (H) then
               Fail ("cancel-async: Is_Done false after Await");
            end if;
         end if;
      end if;
   end;

   --  Case 4: Send_Async on an already-started handle raises.
   declare
      C    : AHT.HTTP.Client.Client_Type;
      Req  : AHT.HTTP.Request.Request_Type;
      Resp : AHT.HTTP.Response.Response_Type;
      H    : AHT.HTTP.Client.Async_Handle;
   begin
      Req.Method := AHT.HTTP.Methods.GET;
      Req.Target := AHT.URL.Parse ("http://127.0.0.1:8764/hello");

      AHT.HTTP.Client.Send_Async (C, Req, H);
      begin
         AHT.HTTP.Client.Send_Async (C, Req, H);
         Fail ("double-send: second Send_Async returned without "
               & "raising");
      exception
         when AHT.HTTP.HTTP_Error => null;
         when E : others =>
            Fail ("double-send: wrong exception "
                  & Ada.Exceptions.Exception_Name (E));
      end;

      --  Still need to Await the first call so the worker can
      --  finish and the master doesn't wait at end-of-block.
      AHT.HTTP.Client.Await (H, Resp);
   end;

   --  Case 5: drop without Await — declare handle in inner block,
   --  Send_Async, exit. Master waits for worker; total elapsed
   --  must be bounded (the /hello fetch is fast).
   declare
      C       : AHT.HTTP.Client.Client_Type;
      Started, Ended : Time;
   begin
      Started := Clock;
      declare
         Req  : AHT.HTTP.Request.Request_Type;
         H    : AHT.HTTP.Client.Async_Handle;
      begin
         Req.Method := AHT.HTTP.Methods.GET;
         Req.Target := AHT.URL.Parse ("http://127.0.0.1:8764/hello");
         AHT.HTTP.Client.Send_Async (C, Req, H);
      end;  -- master waits for the worker to finish Run_Request +
            -- collapse via terminate alternative
      Ended := Clock;

      if Ended - Started > 2.0 then
         Fail ("drop-without-await: scope exit took"
               & Duration'Image (Ended - Started) & "s "
               & "(expected fast — /hello is local)");
      end if;
   end;

   --  Case 6: original exception identity is preserved. wss://
   --  goes through Send → HTTP_Error; Await must re-raise that
   --  exact exception, not a wrapped substitute.
   declare
      C    : AHT.HTTP.Client.Client_Type;
      Req  : AHT.HTTP.Request.Request_Type;
      Resp : AHT.HTTP.Response.Response_Type;
      H    : AHT.HTTP.Client.Async_Handle;
      Raised_HTTP : Boolean := False;
   begin
      Req.Method := AHT.HTTP.Methods.GET;
      Req.Target := AHT.URL.Parse ("wss://example.com/sock");
      AHT.HTTP.Client.Send_Async (C, Req, H);
      begin
         AHT.HTTP.Client.Await (H, Resp);
         Fail ("exception-id: Await returned without raising");
      exception
         when AHT.HTTP.HTTP_Error =>
            Raised_HTTP := True;
         when E : others =>
            Fail ("exception-id: wrong exception re-raised "
                  & Ada.Exceptions.Exception_Name (E)
                  & " (expected AHT.HTTP.HTTP_Error)");
      end;
      if Raised_HTTP and then not AHT.HTTP.Client.Is_Done (H) then
         Fail ("exception-id: Is_Done false after Await");
      end if;
   end;

   --  Case 7: Await on a never-Send_Async'd handle must raise
   --  HTTP_Error promptly (not deadlock on the worker's Start
   --  rendezvous, which is what would happen without the guard
   --  in Await).
   declare
      H        : AHT.HTTP.Client.Async_Handle;
      Resp     : AHT.HTTP.Response.Response_Type;
      Started  : Time;
      Elapsed  : Duration;
      Raised_HTTP : Boolean := False;
   begin
      Started := Clock;
      begin
         AHT.HTTP.Client.Await (H, Resp);
         Fail ("no-send: Await returned without raising");
      exception
         when AHT.HTTP.HTTP_Error => Raised_HTTP := True;
         when E : others =>
            Fail ("no-send: wrong exception "
                  & Ada.Exceptions.Exception_Name (E));
      end;
      Elapsed := Clock - Started;
      if Raised_HTTP and then Elapsed > 0.5 then
         Fail ("no-send: Await took"
               & Duration'Image (Elapsed)
               & "s (must reject immediately, not block)");
      end if;
   end;

   --  Case 8: a second Await on a Done handle returns the same
   --  result without blocking. The worker has already terminated
   --  after stashing the result in the protected state, so this
   --  is purely a Read_Result call.
   declare
      C    : AHT.HTTP.Client.Client_Type;
      Req  : AHT.HTTP.Request.Request_Type;
      H    : AHT.HTTP.Client.Async_Handle;
      Resp1, Resp2 : AHT.HTTP.Response.Response_Type;
      Started, Ended : Time;
   begin
      Req.Method := AHT.HTTP.Methods.GET;
      Req.Target := AHT.URL.Parse ("http://127.0.0.1:8764/hello");
      AHT.HTTP.Client.Send_Async (C, Req, H);
      AHT.HTTP.Client.Await (H, Resp1);

      Started := Clock;
      AHT.HTTP.Client.Await (H, Resp2);
      Ended := Clock;

      if Resp2.Status /= Resp1.Status then
         Fail ("double-await: second status differs ="
               & Resp2.Status'Image & " vs"
               & Resp1.Status'Image);
      end if;
      if Body_To_String (Resp2.Body_B) /= Body_To_String (Resp1.Body_B)
      then
         Fail ("double-await: second body differs");
      end if;
      if Ended - Started > 0.1 then
         Fail ("double-await: second Await took"
               & Duration'Image (Ended - Started) & "s (should "
               & "be near-instant)");
      end if;
   end;

   if Failures = 0 then
      Put_Line ("test_http_async: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_http_async:" & Failures'Image
                & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_HTTP_Async;
