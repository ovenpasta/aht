with AHT.Bytes;
with AHT.HTTP.Headers;
with AHT.HTTP.Methods;
with AHT.Transport;
with AHT.URL;

package AHT.HTTP.Request is

   type Request_Type is tagged record
      Method  : AHT.HTTP.Methods.Method_Type := AHT.HTTP.Methods.GET;
      Target  : AHT.URL.URL_Type;
      Headers : AHT.HTTP.Headers.Map;
      Body_B  : AHT.Bytes.Byte_Vector;
   end record;

   procedure Write
     (Self : Request_Type;
      T    : in out AHT.Transport.Transport_Type'Class);
   --  Writes the HTTP/1.1 wire form of `Self` to `T`:
   --
   --     {METHOD} {request-target} HTTP/1.1\r\n
   --     {header: value\r\n}*
   --     \r\n
   --     {body}
   --
   --  Headers are written in their stored lowercase form (RFC 7230
   --  §3.2 lets us: field names are case-insensitive on the wire).
   --  If `Body_B` is non-empty and `Self.Headers` contains neither
   --  `Content-Length` nor `Transfer-Encoding`, a `Content-Length:
   --  {Body_B'Length}` line is synthesised so the request is not
   --  a framing error.
   --
   --  The caller is responsible for `Host`, `User-Agent`,
   --  `Connection`, `Authorization`, and any other policy headers —
   --  `Write` transcribes what's in the record, it does not invent
   --  routing.

end AHT.HTTP.Request;
