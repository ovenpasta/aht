with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.HTTP;
with AHT.HTTP.Headers;
with AHT.HTTP.Methods;
with AHT.HTTP.Request;
with AHT.HTTP.Response;
with AHT.Transport;
with AHT.URL;

procedure Test_HTTP_Wire is

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_http_wire: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Same mock as test_http_io: script-backed Read, buffered Write.
   type Transport is new AHT.Transport.Transport_Type with record
      Script  : AHT.Bytes.Buffer;
      Cursor  : Positive := 1;
      Written : AHT.Bytes.Buffer;
      Open    : Boolean  := True;
   end record;

   overriding procedure Write
     (Self : in out Transport;
      Data : AHT.Bytes.Byte_Array);

   overriding procedure Read
     (Self : in out Transport;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural);

   overriding procedure Close (Self : in out Transport);

   overriding function Is_Connected (Self : Transport) return Boolean;

   overriding procedure Write
     (Self : in out Transport;
      Data : AHT.Bytes.Byte_Array) is
   begin
      for B of Data loop
         Self.Written.Append (B);
      end loop;
   end Write;

   overriding procedure Read
     (Self : in out Transport;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural)
   is
      Remaining : constant Natural :=
        Self.Script.Length - (Self.Cursor - 1);
      N         : Natural := Remaining;
   begin
      if Remaining = 0 then
         Last := 0;
         return;
      end if;
      if N > Data'Length then N := Data'Length; end if;
      for I in 0 .. N - 1 loop
         Data (Data'First + I) := Self.Script (Self.Cursor + I);
      end loop;
      Self.Cursor := Self.Cursor + N;
      Last := Data'First + N - 1;
   end Read;

   overriding procedure Close (Self : in out Transport) is
   begin
      Self.Open := False;
   end Close;

   overriding function Is_Connected (Self : Transport) return Boolean is
     (Self.Open);

   procedure Load (T : in out Transport; S : String) is
   begin
      T.Script.Clear;
      T.Cursor := 1;
      for C of S loop
         T.Script.Append (Character'Pos (C));
      end loop;
   end Load;

   function Written_To_String (T : Transport) return String is
     (AHT.Bytes.To_String (T.Written));

   function Body_To_String (V : AHT.Bytes.Buffer) return String is
     (AHT.Bytes.To_String (V));

   function Contains (Haystack, Needle : String) return Boolean is
     (Ada.Strings.Fixed.Index (Haystack, Needle) /= 0);

begin
   --  Case 1: GET — request line, caller-supplied headers, no body,
   --  no synthesized Content-Length.
   declare
      T   : Transport;
      Req : AHT.HTTP.Request.Request_Type;
   begin
      Req.Method := AHT.HTTP.Methods.GET;
      Req.Target := AHT.URL.Parse ("http://example.com/hello?x=1");
      Req.Headers.Set ("host", "example.com");
      Req.Headers.Set ("user-agent", "AHT-test/0.1");

      Req.Write (T);

      declare
         Wire : constant String := Written_To_String (T);
      begin
         if not Contains (Wire, "GET /hello?x=1 HTTP/1.1" & ASCII.CR & ASCII.LF) then
            Fail ("GET: request line wrong: """ & Wire & """");
         end if;
         if not Contains (Wire, "host: example.com" & ASCII.CR & ASCII.LF) then
            Fail ("GET: host header missing: """ & Wire & """");
         end if;
         if not Contains (Wire, "user-agent: AHT-test/0.1" & ASCII.CR & ASCII.LF) then
            Fail ("GET: user-agent missing: """ & Wire & """");
         end if;
         if Contains (Wire, "content-length") then
            Fail ("GET: unexpected Content-Length on empty body: """
                  & Wire & """");
         end if;
         if Wire (Wire'Last - 3 .. Wire'Last) /=
           ASCII.CR & ASCII.LF & ASCII.CR & ASCII.LF
         then
            Fail ("GET: missing final CRLFCRLF: """ & Wire & """");
         end if;
      end;
   end;

   --  Case 2: POST with body — Content-Length auto-injected, body
   --  bytes emitted verbatim after the blank line.
   declare
      T    : Transport;
      Req  : AHT.HTTP.Request.Request_Type;
      Data : constant AHT.Bytes.Byte_Array := AHT.Bytes.From_String ("ping!");
   begin
      Req.Method := AHT.HTTP.Methods.POST;
      Req.Target := AHT.URL.Parse ("http://example.com/echo");
      Req.Headers.Set ("host", "example.com");
      for B of Data loop
         Req.Body_B.Append (B);
      end loop;

      Req.Write (T);

      declare
         Wire : constant String := Written_To_String (T);
      begin
         if not Contains
           (Wire,
            "POST /echo HTTP/1.1" & ASCII.CR & ASCII.LF)
         then
            Fail ("POST: request line wrong: """ & Wire & """");
         end if;
         if not Contains (Wire, "content-length: 5" & ASCII.CR & ASCII.LF) then
            Fail ("POST: auto Content-Length missing: """ & Wire & """");
         end if;
         --  Body follows the CRLFCRLF separator.
         declare
            Sep : constant String :=
              ASCII.CR & ASCII.LF & ASCII.CR & ASCII.LF & "ping!";
         begin
            if not Contains (Wire, Sep) then
               Fail ("POST: body not after head separator: """ & Wire & """");
            end if;
         end;
      end;
   end;

   --  Case 3: POST where the caller set Transfer-Encoding — v1 does
   --  not chunk-encode request bodies, so Request.Write transcribing
   --  Body_B verbatim would produce malformed wire. Expect a clean
   --  Protocol_Error rather than silently-invalid bytes on the wire.
   declare
      T    : Transport;
      Req  : AHT.HTTP.Request.Request_Type;
   begin
      Req.Method := AHT.HTTP.Methods.POST;
      Req.Target := AHT.URL.Parse ("http://example.com/upload");
      Req.Headers.Set ("transfer-encoding", "chunked");
      Req.Body_B.Append (16#41#);  --  "A"

      begin
         Req.Write (T);
         Fail ("TE-request: Write returned normally");
      exception
         when AHT.HTTP.Protocol_Error => null;
         when E : others =>
            Fail ("TE-request: wrong exception: "
                  & Ada.Exceptions.Exception_Name (E));
      end;
   end;

   --  Case 4: Response.Read with Content-Length.
   declare
      T    : Transport;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Load (T,
            "HTTP/1.1 200 OK" & ASCII.CR & ASCII.LF
            & "Content-Type: text/plain" & ASCII.CR & ASCII.LF
            & "Content-Length: 11" & ASCII.CR & ASCII.LF
            & ASCII.CR & ASCII.LF
            & "hello world");
      Resp.Read (T);

      if Resp.Status /= 200 then
         Fail ("CL: status =" & Resp.Status'Image);
      end if;
      if To_String (Resp.Reason) /= "OK" then
         Fail ("CL: reason = """ & To_String (Resp.Reason) & """");
      end if;
      if Resp.Headers.Get ("content-type") /= "text/plain" then
         Fail ("CL: content-type = """
               & Resp.Headers.Get ("content-type") & """");
      end if;
      if Body_To_String (Resp.Body_B) /= "hello world" then
         Fail ("CL: body = """ & Body_To_String (Resp.Body_B) & """");
      end if;
   end;

   --  Case 5: chunked response. Reuses the decoder from HTTP.IO.
   declare
      T    : Transport;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Load (T,
            "HTTP/1.1 200 OK" & ASCII.CR & ASCII.LF
            & "Transfer-Encoding: chunked" & ASCII.CR & ASCII.LF
            & ASCII.CR & ASCII.LF
            & "5" & ASCII.CR & ASCII.LF & "Hello" & ASCII.CR & ASCII.LF
            & "6" & ASCII.CR & ASCII.LF & " world" & ASCII.CR & ASCII.LF
            & "0" & ASCII.CR & ASCII.LF
            & ASCII.CR & ASCII.LF);
      Resp.Read (T);

      if Resp.Status /= 200 then
         Fail ("chunked: status =" & Resp.Status'Image);
      end if;
      if Body_To_String (Resp.Body_B) /= "Hello world" then
         Fail ("chunked: body = """ & Body_To_String (Resp.Body_B) & """");
      end if;
   end;

   --  Case 6: neither Content-Length nor Transfer-Encoding —
   --  read-until-EOF fallback. The mock ends its script right after
   --  the body so Read returns Last=0 and the loop terminates.
   declare
      T    : Transport;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Load (T,
            "HTTP/1.1 200 OK" & ASCII.CR & ASCII.LF
            & ASCII.CR & ASCII.LF
            & "trailing bytes until eof");
      Resp.Read (T);
      if Body_To_String (Resp.Body_B) /= "trailing bytes until eof" then
         Fail ("EOF: body = """ & Body_To_String (Resp.Body_B) & """");
      end if;
   end;

   --  Case 7: non-numeric Content-Length → Protocol_Error.
   declare
      T    : Transport;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Load (T,
            "HTTP/1.1 200 OK" & ASCII.CR & ASCII.LF
            & "Content-Length: abc" & ASCII.CR & ASCII.LF
            & ASCII.CR & ASCII.LF);
      begin
         Resp.Read (T);
         Fail ("bad-CL: Read returned normally");
      exception
         when AHT.HTTP.Protocol_Error => null;
         when E : others =>
            Fail ("bad-CL: wrong exception: "
                  & Ada.Exceptions.Exception_Name (E));
      end;
   end;

   --  Case 8: status code out of 100..599 range → Protocol_Error.
   declare
      T    : Transport;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Load (T,
            "HTTP/1.1 999 Made Up" & ASCII.CR & ASCII.LF
            & ASCII.CR & ASCII.LF);
      begin
         Resp.Read (T);
         Fail ("bad-status: Read returned normally");
      exception
         when AHT.HTTP.Protocol_Error => null;
         when E : others =>
            Fail ("bad-status: wrong exception: "
                  & Ada.Exceptions.Exception_Name (E));
      end;
   end;

   --  Case 9: malformed header line (no colon) → Protocol_Error.
   declare
      T    : Transport;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Load (T,
            "HTTP/1.1 200 OK" & ASCII.CR & ASCII.LF
            & "not a header" & ASCII.CR & ASCII.LF
            & ASCII.CR & ASCII.LF);
      begin
         Resp.Read (T);
         Fail ("bad-header: Read returned normally");
      exception
         when AHT.HTTP.Protocol_Error => null;
         when E : others =>
            Fail ("bad-header: wrong exception: "
                  & Ada.Exceptions.Exception_Name (E));
      end;
   end;

   --  Case 10: status line without reason phrase is legal
   --  (RFC 7230 §3.1.2 allows an empty reason). Reason is "".
   declare
      T    : Transport;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Load (T,
            "HTTP/1.1 204" & ASCII.CR & ASCII.LF
            & "Content-Length: 0" & ASCII.CR & ASCII.LF
            & ASCII.CR & ASCII.LF);
      Resp.Read (T);
      if Resp.Status /= 204 then
         Fail ("no-reason: status =" & Resp.Status'Image);
      end if;
      if Length (Resp.Reason) /= 0 then
         Fail ("no-reason: reason = """ & To_String (Resp.Reason) & """");
      end if;
      if Resp.Body_B.Length /= 0 then
         Fail ("no-reason: body length ="
               & Natural'Image (Resp.Body_B.Length));
      end if;
   end;

   --  Case 11: 101 Switching Protocols. Body framing must not run:
   --  the bytes after CRLFCRLF belong to the upgraded protocol
   --  (e.g. a WebSocket frame). Load a "frame" after the headers
   --  and verify (a) the response body is empty, (b) the transport
   --  still has those bytes available for the next Read.
   declare
      T    : Transport;
      Resp : AHT.HTTP.Response.Response_Type;
      Leftover : AHT.Bytes.Byte_Array (1 .. 8);
      Last     : Natural;
   begin
      Load (T,
            "HTTP/1.1 101 Switching Protocols" & ASCII.CR & ASCII.LF
            & "Upgrade: websocket" & ASCII.CR & ASCII.LF
            & "Connection: Upgrade" & ASCII.CR & ASCII.LF
            & ASCII.CR & ASCII.LF
            & "FRAME001");
      Resp.Read (T);

      if Resp.Status /= 101 then
         Fail ("101: status =" & Resp.Status'Image);
      end if;
      if Resp.Body_B.Length /= 0 then
         Fail ("101: body not empty, length ="
               & Natural'Image (Resp.Body_B.Length));
      end if;
      T.Read (Leftover, Last);
      if Last /= Leftover'First + 7 then
         Fail ("101: post-header bytes consumed; Last =" & Last'Image);
      else
         declare
            S : String (1 .. 8);
         begin
            for I in S'Range loop
               S (I) := Character'Val
                 (Natural (Leftover (Leftover'First + I - 1)));
            end loop;
            if S /= "FRAME001" then
               Fail ("101: next bytes corrupted: """ & S & """");
            end if;
         end;
      end if;
   end;

   --  Case 12: 204 No Content with no framing headers. Without the
   --  no-body short-circuit, the EOF fallback would consume any
   --  bytes that follow (e.g. the status line of the next response
   --  on a persistent connection). Assert the body is empty and the
   --  trailing bytes stay on the wire.
   declare
      T    : Transport;
      Resp : AHT.HTTP.Response.Response_Type;
      Leftover : AHT.Bytes.Byte_Array (1 .. 8);
      Last     : Natural;
   begin
      Load (T,
            "HTTP/1.1 204 No Content" & ASCII.CR & ASCII.LF
            & ASCII.CR & ASCII.LF
            & "NEXTRESP");
      Resp.Read (T);

      if Resp.Status /= 204 then
         Fail ("204-no-CL: status =" & Resp.Status'Image);
      end if;
      if Resp.Body_B.Length /= 0 then
         Fail ("204-no-CL: body non-empty, length ="
               & Natural'Image (Resp.Body_B.Length));
      end if;
      T.Read (Leftover, Last);
      if Last /= Leftover'First + 7 then
         Fail ("204-no-CL: trailing bytes consumed; Last =" & Last'Image);
      end if;
   end;

   --  Case 13: 204 with an erroneous Content-Length: 5 plus five
   --  "body" bytes. Per RFC 7230 §3.3.3 the CL must be ignored;
   --  those five bytes must remain on the wire for the next parse.
   declare
      T    : Transport;
      Resp : AHT.HTTP.Response.Response_Type;
      Leftover : AHT.Bytes.Byte_Array (1 .. 5);
      Last     : Natural;
   begin
      Load (T,
            "HTTP/1.1 204 No Content" & ASCII.CR & ASCII.LF
            & "Content-Length: 5" & ASCII.CR & ASCII.LF
            & ASCII.CR & ASCII.LF
            & "hello");
      Resp.Read (T);

      if Resp.Status /= 204 then
         Fail ("204-bad-CL: status =" & Resp.Status'Image);
      end if;
      if Resp.Body_B.Length /= 0 then
         Fail ("204-bad-CL: body non-empty, length ="
               & Natural'Image (Resp.Body_B.Length));
      end if;
      T.Read (Leftover, Last);
      if Last /= Leftover'First + 4 then
         Fail ("204-bad-CL: erroneous body consumed; Last =" & Last'Image);
      end if;
   end;

   --  Case 14: 205 Reset Content — same no-body rule as 204. An
   --  erroneous `Content-Length: 4` with four "body" bytes must be
   --  ignored (RFC 9110 §15.3.6 "The 205 response MUST NOT include
   --  content"); those bytes remain on the wire.
   declare
      T    : Transport;
      Resp : AHT.HTTP.Response.Response_Type;
      Leftover : AHT.Bytes.Byte_Array (1 .. 4);
      Last     : Natural;
   begin
      Load (T,
            "HTTP/1.1 205 Reset Content" & ASCII.CR & ASCII.LF
            & "Content-Length: 4" & ASCII.CR & ASCII.LF
            & ASCII.CR & ASCII.LF
            & "keep");
      Resp.Read (T);

      if Resp.Status /= 205 then
         Fail ("205-bad-CL: status =" & Resp.Status'Image);
      end if;
      if Resp.Body_B.Length /= 0 then
         Fail ("205-bad-CL: body non-empty, length ="
               & Natural'Image (Resp.Body_B.Length));
      end if;
      T.Read (Leftover, Last);
      if Last /= Leftover'First + 3 then
         Fail ("205-bad-CL: erroneous body consumed; Last =" & Last'Image);
      end if;
   end;

   --  Case 15: 304 Not Modified with an erroneous Transfer-Encoding:
   --  chunked. Must not invoke the chunked decoder.
   declare
      T    : Transport;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Load (T,
            "HTTP/1.1 304 Not Modified" & ASCII.CR & ASCII.LF
            & "Transfer-Encoding: chunked" & ASCII.CR & ASCII.LF
            & "ETag: ""abc""" & ASCII.CR & ASCII.LF
            & ASCII.CR & ASCII.LF);
      Resp.Read (T);

      if Resp.Status /= 304 then
         Fail ("304: status =" & Resp.Status'Image);
      end if;
      if Resp.Body_B.Length /= 0 then
         Fail ("304: body non-empty, length ="
               & Natural'Image (Resp.Body_B.Length));
      end if;
   end;

   --  Case 16: HEAD response. The peer typically advertises the
   --  GET-equivalent Content-Length but sends no body bytes. With
   --  Method => HEAD, Response.Read must skip body framing entirely;
   --  any bytes after CRLFCRLF (e.g. a next response on a persistent
   --  connection) must stay on the wire. Without the suppression the
   --  Content-Length path would try to Read_N and either hang or
   --  consume the next response's status line.
   declare
      T    : Transport;
      Resp : AHT.HTTP.Response.Response_Type;
      Leftover : AHT.Bytes.Byte_Array (1 .. 8);
      Last     : Natural;
   begin
      Load (T,
            "HTTP/1.1 200 OK" & ASCII.CR & ASCII.LF
            & "Content-Length: 1234" & ASCII.CR & ASCII.LF
            & ASCII.CR & ASCII.LF
            & "NEXTRESP");
      Resp.Read (T, Method => AHT.HTTP.Methods.HEAD);

      if Resp.Status /= 200 then
         Fail ("HEAD: status =" & Resp.Status'Image);
      end if;
      if Resp.Body_B.Length /= 0 then
         Fail ("HEAD: body non-empty, length ="
               & Natural'Image (Resp.Body_B.Length));
      end if;
      T.Read (Leftover, Last);
      if Last /= Leftover'First + 7 then
         Fail ("HEAD: trailing bytes consumed; Last =" & Last'Image);
      end if;
   end;

   if Failures = 0 then
      Put_Line ("test_http_wire: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_http_wire:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_HTTP_Wire;
