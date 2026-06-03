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

   procedure Set_Body (Self : in out Request_Type; Text : String);
   --  Replaces the request body with the bytes of `Text`, one octet
   --  per Character (raw / Latin-1, no charset encoding) — the inverse
   --  of `Response.Body_Text`, so a String body needn't be walked into
   --  `Body_B` by hand. `Content-Length` is synthesised by `Write`
   --  from the resulting body, so the caller need not set it.

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
   --  If `Body_B` is non-empty and `Self.Headers` does not already
   --  contain `Content-Length`, a `Content-Length: {Body_B'Length}`
   --  line is synthesised so the request is always framed.
   --
   --  Raises `AHT.HTTP.Protocol_Error` if `Self.Headers` contains
   --  `Transfer-Encoding`: v1 does not do chunked request bodies.
   --  `Write` transcribes `Body_B` verbatim, so a TE header with no
   --  matching encoder would emit malformed wire bytes — a clean
   --  refusal beats a plausible-looking request the peer will
   --  reject (or worse, misparse). Streaming upload will be a
   --  separate API.
   --
   --  The caller remains responsible for `Host`, `User-Agent`,
   --  `Connection`, `Authorization`, and any other policy headers —
   --  `Write` transcribes what's in the record, it does not invent
   --  routing.

end AHT.HTTP.Request;
