with Interfaces;

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
      Body_B  : AHT.Bytes.Buffer;
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
   --  Anti-smuggling framing checks (RFC 7230 §3.3.3), all raising
   --  `AHT.HTTP.Protocol_Error`:
   --    * `Transfer-Encoding` in `Self.Headers` is rejected — v1 does
   --      not chunk-encode a buffered body, and `Write` transcribes
   --      `Body_B` verbatim, so a TE header with no matching encoder
   --      would emit malformed wire. Use `Write_Streaming` for chunked
   --      upload.
   --    * A duplicate `Content-Length` (the header map allows repeats)
   --      is rejected — intermediaries can disagree on which wins.
   --    * A caller-supplied single `Content-Length` must equal
   --      `Body_B.Length`; a declared-vs-actual mismatch (e.g.
   --      `Content-Length: 1` over a 4-byte body) would truncate the
   --      upload or hang the peer, so it is refused rather than shipped.
   --
   --  The caller remains responsible for `Host`, `User-Agent`,
   --  `Connection`, `Authorization`, and any other policy headers —
   --  `Write` transcribes what's in the record, it does not invent
   --  routing.

   --  Pull-style request-body source for streaming uploads. The upload
   --  state (file handle, generator cursor, ...) lives in the caller's
   --  own concrete type derived from this interface, so no closure and
   --  no `'Unrestricted_Access` is ever needed: `Write_Streaming` takes
   --  the source by reference and drives the whole upload before it
   --  returns, so the source cannot dangle.
   type Body_Source is limited interface;

   procedure Read_Chunk
     (Self : in out Body_Source;
      Buf  : out AHT.Bytes.Byte_Array;
      Last : out Natural) is abstract;
   --  Fill `Buf (Buf'First .. Last)` with the next run of body bytes and
   --  set `Last` to the index of the last byte written. `Last < Buf'First`
   --  (canonically `Last = 0`) signals end-of-stream; once EOF has been
   --  signalled the source must keep signalling it. Allocation-free and
   --  O(1): `Write_Streaming` hands the same fixed window every call.
   --  Runs synchronously on the caller's task, so there is no
   --  task-safety contract — but it must not block indefinitely, since a
   --  stuck source is bounded only by the transport's write deadline
   --  (see `AHT.Transport.Set_Write_Deadline`).

   subtype Byte_Count is
     Interfaces.Integer_64 range 0 .. Interfaces.Integer_64'Last;

   procedure Set_Content_Length (Self : in out Request_Type; N : Byte_Count);
   --  Sets `content-length` to `N`'s decimal image, selecting fixed
   --  framing for `Write_Streaming`. 64-bit so a multi-GB upload is
   --  expressible (the buffered `Body_B` path stays `Natural`-bounded —
   --  a >2 GB buffered body is a non-use-case).

   procedure Write_Streaming
     (Self        : Request_Type;
      T           : in out AHT.Transport.Transport_Type'Class;
      Source      : in out Body_Source'Class;
      Abort_Check : access function return Boolean := null);
   --  Streams a request body pulled from `Source` to `T`, never
   --  buffering it. The head is built exactly like `Write` (same request
   --  line, same lowercase caller headers, same anti-smuggling checks),
   --  then the body is framed per the headers:
   --    * **fixed** — if `Self.Headers` carries exactly one
   --      `Content-Length`, stream that many bytes. A source that signals
   --      EOF early (**under-run**) or hands over more than declared
   --      (**over-run**) raises `Protocol_Error`; the stream stops at
   --      exactly N. Set it via `Set_Content_Length`.
   --    * **chunked** — otherwise emit `Transfer-Encoding: chunked` and
   --      frame each window as `{hex-size}CRLF {bytes} CRLF`, closing
   --      with `0 CRLF CRLF`. An empty body is just the terminator.
   --  The caller must NOT set `Transfer-Encoding` (the encoder owns it)
   --  nor a duplicate `Content-Length` — both raise `Protocol_Error`.
   --
   --  `Abort_Check`, when non-null, is polled between windows; a True
   --  result raises `AHT.Transport.Aborted_Error` mid-body. It is a
   --  cheap secondary fast-exit — the real bound on a stuck send is the
   --  transport's non-blocking write deadline / `Abort_Pending`. The
   --  hook is only ever called during this synchronous call, so it
   --  carries no cross-task lifetime hazard.
   --
   --  A `Timeout_Error` / `Aborted_Error` can be raised after some body
   --  bytes have reached the peer, so a failed streaming upload is
   --  retry-unsafe for a non-idempotent request — see the partial-send
   --  note on `AHT.Transport.Write`.

end AHT.HTTP.Request;
