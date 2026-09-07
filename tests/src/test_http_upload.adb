--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Streaming request-body upload via AHT.HTTP.Client.Send_Streaming_Body.
--
--  The on-the-wire framing (fixed Content-Length vs chunked, the chunk
--  sizes, the 0\r\n\r\n terminator, the anti-smuggling rejections) is
--  pinned deterministically against the mock transport in test_http_wire
--  (slice 2). This binary exercises the layer above — the *client*
--  surface that threads a Body_Source through Run_Request /
--  Wire_Round_Trip over a real socket, arms the write deadline, and
--  buffers the response — and proves the framing is accepted by a real,
--  third-party HTTP/1.1 server rather than a hand-rolled test peer.
--
--  Interop peer: go-httpbin (mccutchen/go-httpbin), the same fixture
--  test_httpbin uses. Its /post endpoint reads the request body
--  (transparently dechunking a Transfer-Encoding: chunked upload, since
--  it is Go net/http) and echoes it back inside the JSON "data" field.
--  The orchestrator (tests/run_tests.sh) starts it only when a Go
--  toolchain is available and exports AHT_HTTPBIN_URL; when that is
--  unset the two framing cases SKIP cleanly so the suite stays green on
--  machines without Go. The cancel case never needs Go.
--
--  Three cases:
--    1. Fixed framing  — Set_Content_Length + Send_Streaming_Body; the
--       go-httpbin /post echo must contain the sent payload.
--    2. Chunked framing — no Content-Length; the source drives
--       Transfer-Encoding: chunked, dechunked by go-httpbin and echoed.
--    3. Cancel mid-upload — a multi-MB body to an in-process non-reading
--       peer fills the socket buffer so the write parks; a sibling task
--       fires Cancel and Send_Streaming_Body raises Aborted_Error. This
--       case is self-contained and runs with or without Go.

with Ada.Calendar; use Ada.Calendar;
with Ada.Command_Line;
with Ada.Environment_Variables;
with Ada.Exceptions;
with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;
with GNAT.Sockets; use GNAT.Sockets;

with AHT.Bytes;
with AHT.HTTP.Client;
with AHT.HTTP.Methods;
with AHT.HTTP.Request;
with AHT.HTTP.Response;
with AHT.Transport;
with AHT.URL;

procedure Test_HTTP_Upload is

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_http_upload: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   ---------------------------------------------------------------
   --  Test pull sources
   ---------------------------------------------------------------

   --  Array-backed source: hands out its stored bytes in slices of at
   --  most Chunk per Read_Chunk so even a small payload exercises the
   --  multi-window pump (and, when chunked, multiple chunk frames).
   type Array_Source is new AHT.HTTP.Request.Body_Source with record
      Data   : AHT.Bytes.Buffer;
      Cursor : Positive := 1;
      Chunk  : Positive := Positive'Last;
   end record;

   overriding procedure Read_Chunk
     (Self : in out Array_Source;
      Buf  : out AHT.Bytes.Byte_Array;
      Last : out Natural)
   is
      Remaining : constant Natural := Self.Data.Length - (Self.Cursor - 1);
      N         : Natural := Remaining;
   begin
      if Remaining = 0 then
         Last := Buf'First - 1;  --  EOF
         return;
      end if;
      if N > Self.Chunk then N := Self.Chunk; end if;
      if N > Buf'Length then N := Buf'Length; end if;
      for I in 0 .. N - 1 loop
         Buf (Buf'First + I) := Self.Data (Self.Cursor + I);
      end loop;
      Self.Cursor := Self.Cursor + N;
      Last := Buf'First + N - 1;
   end Read_Chunk;

   procedure Load_Source
     (S : in out Array_Source; Str : String; Chunk : Positive)
   is
   begin
      S.Cursor := 1;
      S.Chunk  := Chunk;
      for C of Str loop
         S.Data.Append (Character'Pos (C));
      end loop;
   end Load_Source;

   --  Synthetic source that yields Remaining bytes (all 'x') without
   --  materialising them, for the multi-megabyte cancel payload.
   type Big_Source is new AHT.HTTP.Request.Body_Source with record
      Remaining : Natural := 0;
   end record;

   overriding procedure Read_Chunk
     (Self : in out Big_Source;
      Buf  : out AHT.Bytes.Byte_Array;
      Last : out Natural)
   is
      N : Natural := Self.Remaining;
   begin
      if N = 0 then
         Last := Buf'First - 1;  --  EOF
         return;
      end if;
      if N > Buf'Length then N := Buf'Length; end if;
      for I in 0 .. N - 1 loop
         Buf (Buf'First + I) := Character'Pos ('x');
      end loop;
      Self.Remaining := Self.Remaining - N;
      Last := Buf'First + N - 1;
   end Read_Chunk;

   ---------------------------------------------------------------
   --  Non-reading peer for the cancel case: accepts and holds the
   --  socket without ever draining it, so a large upload fills the
   --  socket buffer and the client's write parks — the only exit is
   --  Cancel (Aborted_Error) or the write deadline.
   ---------------------------------------------------------------
   task type Idle_Server is
      entry Get_Port
        (P   : out AHT.URL.Port_Number;
         Err : out Unbounded_String);
      entry Wait_Done (Runtime_Err : out Unbounded_String);
   end Idle_Server;

   task body Idle_Server is
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
         --  Shrink the receive buffer (accepted sockets inherit it from
         --  the listener) so that, with the peer never reading, the
         --  client's much larger body cannot be swallowed whole by the
         --  kernel: its Write parks once this tiny buffer + the client's
         --  send buffer fill. That makes the cancel hit the *parked
         --  write* deterministically, not the response read (which the
         --  client never reaches because no response is ever sent).
         Set_Socket_Option
           (Server, Socket_Level, (Name => Receive_Buffer, Size => 4096));
         Bind_To.Addr := Inet_Addr ("127.0.0.1");
         Bind_To.Port := 0;
         Bind_Socket (Server, Bind_To);
         Listen_Socket (Server, 1);
         Bound := Get_Socket_Name (Server).Port;
      exception
         when E : others =>
            Setup_Error := To_Unbounded_String
              ("Idle_Server setup: "
               & Ada.Exceptions.Exception_Message (E));
      end;

      accept Get_Port
        (P   : out AHT.URL.Port_Number;
         Err : out Unbounded_String)
      do
         if Length (Setup_Error) > 0 then P := 1;
         else P := AHT.URL.Port_Number (Bound); end if;
         Err := Setup_Error;
      end Get_Port;

      if Length (Setup_Error) = 0 then
         begin
            Accept_Socket (Server, Client, Peer);
            --  Hold without reading; the client cancels and closes.
            delay 3.0;
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
         accept Wait_Done (Runtime_Err : out Unbounded_String) do
            Runtime_Err := Runtime_Error;
         end Wait_Done;
      or
         terminate;
      end select;
   end Idle_Server;

   function URL_For
     (Port : AHT.URL.Port_Number; Path : String) return String is
     ("http://127.0.0.1:"
      & Ada.Strings.Fixed.Trim
          (AHT.URL.Port_Number'Image (Port), Ada.Strings.Both)
      & Path);

   Base : constant String :=
     Ada.Environment_Variables.Value ("AHT_HTTPBIN_URL", "");

   Payload : constant String :=
     "the quick brown fox jumps over the lazy dog 0123456789";

   --  Stream Payload to go-httpbin /post and assert the echoed JSON
   --  "data" field contains it. Fixed = True selects Content-Length
   --  framing; Fixed = False omits it so the encoder emits chunked.
   procedure Check_Upload (Title : String; Fixed : Boolean) is
      C    : AHT.HTTP.Client.Client_Type;
      Req  : AHT.HTTP.Request.Request_Type;
      Resp : AHT.HTTP.Response.Response_Type;
      Src  : Array_Source;
   begin
      C.Timeout_Seconds := 5;
      Req.Method := AHT.HTTP.Methods.POST;
      Req.Target := AHT.URL.Parse (Base & "/post");
      Req.Headers.Set ("content-type", "text/plain");
      if Fixed then
         Req.Set_Content_Length
           (AHT.HTTP.Request.Byte_Count (Payload'Length));
      end if;
      --  Small Chunk so a chunked body spans several chunk frames.
      Load_Source (Src, Payload, Chunk => 8);

      AHT.HTTP.Client.Send_Streaming_Body (C, Req, Resp, Src);

      if Resp.Status /= 200 then
         Fail (Title & ": status =" & Resp.Status'Image);
      elsif Ada.Strings.Fixed.Index
              (AHT.Bytes.To_String (Resp.Body_B), Payload) = 0
      then
         Fail (Title & ": go-httpbin echo did not contain the payload");
      end if;
   exception
      when E : others =>
         Fail (Title & ": raised " & Ada.Exceptions.Exception_Name (E)
               & " — " & Ada.Exceptions.Exception_Message (E));
   end Check_Upload;

begin

   --  Cases 1 & 2: framing interop against go-httpbin (SKIP without Go).
   if Base = "" then
      Put_Line ("test_http_upload: framing cases SKIP "
                & "(AHT_HTTPBIN_URL unset; install Go to enable go-httpbin)");
   else
      Check_Upload ("fixed",   Fixed => True);
      Check_Upload ("chunked", Fixed => False);
   end if;

   --  Case 3: cancel an in-flight upload. A multi-MB chunked body to a
   --  non-reading peer fills the socket buffer; the write parks and a
   --  sibling Cancel breaks it with Aborted_Error. Self-contained — no
   --  Go fixture stalls, so this always runs.
   declare
      Server   : Idle_Server;
      Port     : AHT.URL.Port_Number;
      Setup_Err, Run_Err : Unbounded_String;
      C      : AHT.HTTP.Client.Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : AHT.HTTP.Response.Response_Type;
      Src    : Big_Source := (Remaining => 4_000_000);
      Handle : AHT.HTTP.Client.Cancel_Handle;
      Started : Time;
      Elapsed : Duration;
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
               Put_Line ("test_http_upload: Canceller raised "
                         & Ada.Exceptions.Exception_Name (E));
         end;
      end Canceller;
   begin
      C.Timeout_Seconds := 5;  --  safety net well past the 0.2s cancel
      Server.Get_Port (Port, Setup_Err);
      if Length (Setup_Err) > 0 then
         Fail ("cancel: server setup: " & To_String (Setup_Err));
         Canceller.Go;
      else
         Req.Method := AHT.HTTP.Methods.POST;
         Req.Target := AHT.URL.Parse (URL_For (Port, "/big"));

         Started := Clock;
         Canceller.Go;
         begin
            AHT.HTTP.Client.Send_Streaming_Body (C, Req, Resp, Src, Handle);
            Fail ("cancel: Send_Streaming_Body returned without raising");
         exception
            when AHT.Transport.Aborted_Error =>
               Raised_Aborted := True;
            when E : others =>
               Fail ("cancel: wrong exception "
                     & Ada.Exceptions.Exception_Name (E) & ": "
                     & Ada.Exceptions.Exception_Message (E));
         end;
         Elapsed := Clock - Started;
         Server.Wait_Done (Run_Err);

         if Raised_Aborted then
            if Elapsed > 2.0 then
               Fail ("cancel: upload took"
                     & Duration'Image (Elapsed)
                     & "s (expected <2s after 0.2s cancel)");
            end if;
            if not AHT.HTTP.Client.Is_Cancelled (Handle) then
               Fail ("cancel: Is_Cancelled false after Cancel");
            end if;
         end if;
      end if;
   end;

   if Failures = 0 then
      Put_Line ("test_http_upload: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_http_upload:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_HTTP_Upload;
