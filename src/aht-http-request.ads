--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

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
   --  per Character (raw / Latin-1, no charset encoding), the inverse
   --  of `Response.Body_Text`, so a String body needn't be walked into
   --  `Body_B` by hand. `Content-Length` is synthesised by `Write`
   --  from the resulting body, so the caller need not set it.

   procedure Write
     (Self : Request_Type;
      T    : in out AHT.Transport.Transport_Type'Class);
   --  Writes the HTTP/1.1 wire form of `Self` to `T`: request line,
   --  headers in their stored lowercase form (RFC 7230 sec. 3.2),
   --  empty line, body. If `Body_B` is non-empty and no
   --  `Content-Length` is present, one is synthesised.
   --
   --  Raises `AHT.HTTP.Protocol_Error` (RFC 7230 sec. 3.3.3) on a
   --  `Transfer-Encoding` header, since a buffered body is written
   --  verbatim (use `Write_Streaming` for chunked upload); on a
   --  duplicate `Content-Length`; and on a single `Content-Length`
   --  that does not equal `Body_B.Length`.
   --
   --  `Host`, `User-Agent`, `Connection`, `Authorization` and other
   --  policy headers are the caller's.

   --  Pull-style request-body source for streaming uploads. The
   --  caller's concrete type holds the upload state; `Write_Streaming`
   --  takes the source by reference and drives the whole upload
   --  before returning, so it cannot dangle.
   type Body_Source is limited interface;

   procedure Read_Chunk
     (Self : in out Body_Source;
      Buf  : out AHT.Bytes.Byte_Array;
      Last : out Natural) is abstract;
   --  Fills `Buf (Buf'First .. Last)` with the next body bytes.
   --  `Last < Buf'First` signals end-of-stream, and must keep doing
   --  so once signalled. Runs on the caller's task and must not block
   --  indefinitely: a stuck source is bounded only by the transport's
   --  write deadline.

   subtype Byte_Count is
     Interfaces.Integer_64 range 0 .. Interfaces.Integer_64'Last;

   procedure Set_Content_Length (Self : in out Request_Type; N : Byte_Count);
   --  Sets `content-length` to `N`, selecting fixed framing for
   --  `Write_Streaming`. 64-bit so a multi-GB upload is expressible.

   procedure Write_Streaming
     (Self        : Request_Type;
      T           : in out AHT.Transport.Transport_Type'Class;
      Source      : in out Body_Source'Class;
      Abort_Check : access function return Boolean := null);
   --  Streams a body pulled from `Source` to `T` without buffering.
   --  The head is written as by `Write`, then the body is framed per
   --  the headers: exactly one `Content-Length` selects fixed framing
   --  of that many bytes, and a source that ends early or hands over
   --  more raises `Protocol_Error`; otherwise `Transfer-Encoding:
   --  chunked`, each window as `{hex-size} CRLF {bytes} CRLF`, closed
   --  by `0 CRLF CRLF`. A caller-set `Transfer-Encoding` or a
   --  duplicate `Content-Length` raises `Protocol_Error`.
   --
   --  `Abort_Check`, when non-null, is polled between windows; True
   --  raises `AHT.Transport.Aborted_Error`. It is only called during
   --  this synchronous call. A `Timeout_Error` / `Aborted_Error` can
   --  be raised after some body bytes reached the peer, so a failed
   --  upload is retry-unsafe for a non-idempotent request.

end AHT.HTTP.Request;
