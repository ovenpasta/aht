with Ada.Strings.Unbounded;

with AHT.Bytes;
with AHT.HTTP.Headers;
with AHT.HTTP.Methods;
with AHT.HTTP.Status;
with AHT.Transport;

package AHT.HTTP.Response is

   type Response_Type is tagged record
      Status  : AHT.HTTP.Status.Status_Code := 200;
      Reason  : Ada.Strings.Unbounded.Unbounded_String;
      Headers : AHT.HTTP.Headers.Map;
      Body_B  : AHT.Bytes.Byte_Vector;
   end record;

   procedure Read
     (Self   : out Response_Type;
      T      : in out AHT.Transport.Transport_Type'Class;
      Method : AHT.HTTP.Methods.Method_Type := AHT.HTTP.Methods.GET);
   --  Parses an HTTP/1.1 response off `T` into `Self`:
   --
   --     HTTP/1.1 {status} {reason}\r\n
   --     {header: value\r\n}*
   --     \r\n
   --     {body}
   --
   --  Body framing (per RFC 7230 §3.3.3 and RFC 9110 §15.3.6):
   --    0. 1xx / 204 / 205 / 304 ⇒ no body, regardless of any
   --       framing header the peer sent. The message ends at the
   --       empty line. Matters for 101 (next bytes are the upgraded
   --       protocol — e.g. WebSocket frames — not HTTP body) and
   --       for 204/205/304 on `Connection: close` streams (the EOF
   --       fallback would otherwise block until the peer closes).
   --    0a. `Method = HEAD` ⇒ no body either, regardless of status
   --       or framing headers (RFC 7230 §3.3.3 rule 1). The codec
   --       can't infer the request method, so the caller passes it.
   --       Default `GET` keeps existing callers correct.
   --    1. `Transfer-Encoding: chunked` ⇒ chunked-decode via
   --       `AHT.HTTP.IO.Read_Chunked_Body`.
   --    2. else `Content-Length: N` ⇒ read exactly N bytes.
   --    3. else read until the peer closes the connection.
   --
   --  Raises `AHT.HTTP.Protocol_Error` on malformed status line,
   --  malformed header line, `Status` outside 100..599, or a
   --  non-numeric `Content-Length`.

end AHT.HTTP.Response;
