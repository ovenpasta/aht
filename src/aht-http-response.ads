--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

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
      Body_B  : AHT.Bytes.Buffer;
   end record;

   procedure Read_Streaming
     (Self   : out Response_Type;
      T      : in out AHT.Transport.Transport_Type'Class;
      Sink   : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array);
      Method : AHT.HTTP.Methods.Method_Type := AHT.HTTP.Methods.GET);
   --  As Read for the status line, headers and body suppression, but
   --  the body goes to Sink as it is decoded, in non-empty slices of
   --  at most 4 KiB: chunked bodies in windows that do not preserve
   --  chunk boundaries, Content-Length bodies in ceil (N / 4 KiB)
   --  fully-read windows, Connection: close bodies one call per
   --  transport Read until EOF. Self.Body_B stays empty. Same
   --  Protocol_Error conditions as Read.

   function Body_Text (Self : Response_Type) return String;
   --  The response body decoded one Character per byte (raw octets /
   --  Latin-1), so it can be printed or compared as a String. Empty
   --  when there is no body (after a HEAD, or a streaming Read that
   --  drained the body into a Sink). No charset decoding is attempted.

   procedure Read
     (Self   : out Response_Type;
      T      : in out AHT.Transport.Transport_Type'Class;
      Method : AHT.HTTP.Methods.Method_Type := AHT.HTTP.Methods.GET);
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
   --  Status outside 100..599, or a non-numeric Content-Length.

end AHT.HTTP.Response;
