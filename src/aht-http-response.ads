--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Strings.Unbounded;
with Interfaces;

with AHT.Bytes;
with AHT.HTTP.Headers;
with AHT.HTTP.Methods;
with AHT.HTTP.Status;
with AHT.Transport;
with AHT.URL;

package AHT.HTTP.Response is

   type Response_Type is tagged record
      Status    : AHT.HTTP.Status.Status_Code := 200;
      Reason    : Ada.Strings.Unbounded.Unbounded_String;
      Headers   : AHT.HTTP.Headers.Map;
      Body_B    : AHT.Bytes.Buffer;
      Decoded   : Boolean := False;
      --  The body was decompressed (see Max_Decoded below); its
      --  Content-Encoding and Content-Length headers were removed.
      Final_URL : AHT.URL.URL_Type;
      --  Set by AHT.HTTP.Client: the URL this response came from, the
      --  request's target or the last redirect's. Read leaves it at
      --  its default.
   end record;

   subtype Decode_Limit is
     Interfaces.Integer_64 range 0 .. Interfaces.Integer_64'Last;
   --  Whether a coded body is decoded, and to how many bytes at most.
   --  The bound is the switch: asking for decoding means naming one.
   --  There is no value for "unbounded" and no default bound: DEFLATE
   --  expands up to about 1000 to 1, so how much a response may
   --  become is the caller's decision.

   No_Decoding : constant Decode_Limit := 0;

   procedure Read_Streaming
     (Self        : out Response_Type;
      T           : in out AHT.Transport.Transport_Type'Class;
      Sink        : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array);
      Method      : AHT.HTTP.Methods.Method_Type := AHT.HTTP.Methods.GET;
      Max_Decoded : Decode_Limit := No_Decoding);
   --  As Read for the status line, headers and body suppression, but
   --  the body goes to Sink as it is decoded, in non-empty slices of
   --  at most 4 KiB: chunked bodies in windows that do not preserve
   --  chunk boundaries, Content-Length bodies in ceil (N / 4 KiB)
   --  fully-read windows, Connection: close bodies one call per
   --  transport Read until EOF, decompressed bodies as the decoder
   --  produces them. Self.Body_B stays empty. Same Protocol_Error
   --  conditions as Read.
   --
   --  Max_Decoded: when not No_Decoding, a body whose Content-Encoding is exactly one
   --  of gzip, x-gzip or deflate (case-insensitive) is decompressed on
   --  the way to Sink, the content-encoding and content-length
   --  headers are removed from Self before the first Sink call, and
   --  Self.Decoded is set. "deflate" is accepted zlib-wrapped or raw.
   --  Anything else is delivered as received with its headers
   --  untouched: no body, a 206 (a byte range of a coded body is not
   --  decodable on its own), identity, an unknown coding, or a list
   --  of several. A malformed, truncated or checksum-failing coded
   --  body raises Protocol_Error; bytes already delivered stay
   --  delivered. So does a body that decodes to more than Max_Decoded
   --  bytes: at most Max_Decoded bytes reach Sink before the raise.

   procedure Read_Streaming
     (Self        : out Response_Type;
      T           : in out AHT.Transport.Transport_Type'Class;
      Sink        : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array);
      Method      : AHT.HTTP.Methods.Method_Type;
      Max_Decoded : Decode_Limit;
      Persistent  : out Boolean;
      Head_Read   : access Boolean := null);
   --  As above, and reports whether T may carry another response:
   --  True when this message ended where its framing says (no body,
   --  chunked or Content-Length, not read-until-close), it is not a
   --  101, its version is HTTP/1.1, no Connection header lists
   --  "close", and its framing headers are unambiguous: a message
   --  with both Transfer-Encoding and Content-Length, or with
   --  Transfer-Encoding on several lines, is read but not Persistent
   --  (RFC 9112 sec. 6.3). Says nothing about the request side.
   --
   --  Head_Read, when not null, is set to True once a status line has
   --  been parsed. Through an access so the value survives a raise:
   --  it tells a peer that answered badly from one that never
   --  answered.

   function Body_Text (Self : Response_Type) return String;
   --  The response body decoded one Character per byte (raw octets /
   --  Latin-1), so it can be printed or compared as a String. Empty
   --  when there is no body (after a HEAD, or a streaming Read that
   --  drained the body into a Sink). No charset decoding is attempted.

   procedure Read
     (Self   : out Response_Type;
      T      : in out AHT.Transport.Transport_Type'Class;
      Method      : AHT.HTTP.Methods.Method_Type := AHT.HTTP.Methods.GET;
      Max_Decoded : Decode_Limit := No_Decoding);
   --  Parses an HTTP/1.1 response off T into Self: status line,
   --  headers, empty line, body. Body framing (RFC 7230 sec. 3.3.3,
   --  RFC 9110 sec. 15.3.6): 1xx / 204 / 205 / 304, or Method = HEAD,
   --  means no body whatever the framing headers say, so a 101's
   --  following bytes stay on the transport and a 204 on a
   --  Connection: close stream does not wait for EOF; else
   --  Transfer-Encoding: chunked decodes via
   --  AHT.HTTP.IO.Read_Chunked_Body; else Content-Length: N reads N
   --  bytes; else read until the peer closes. Raises
   --  AHT.HTTP.Protocol_Error on a malformed status or header line,
   --  Status outside 100..599, a non-numeric Content-Length, or
   --  Content-Length headers that disagree. Max_Decoded as for
   --  Read_Streaming.

end AHT.HTTP.Response;
