with Ada.Strings.Unbounded;

with AHT.Bytes;
with AHT.HTTP.Headers;
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
     (Self : out Response_Type;
      T    : in out AHT.Transport.Transport_Type'Class);
   --  Parses an HTTP/1.1 response off `T` into `Self`:
   --
   --     HTTP/1.1 {status} {reason}\r\n
   --     {header: value\r\n}*
   --     \r\n
   --     {body}
   --
   --  Body framing (per RFC 7230 §3.3.3):
   --    1. `Transfer-Encoding: chunked` ⇒ chunked-decode via
   --       `AHT.HTTP.IO.Read_Chunked_Body`.
   --    2. else `Content-Length: N` ⇒ read exactly N bytes.
   --    3. else read until the peer closes the connection.
   --
   --  Raises `AHT.HTTP.Protocol_Error` on malformed status line,
   --  malformed header line, `Status` outside 100..599, or a
   --  non-numeric `Content-Length`.

end AHT.HTTP.Response;
