--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with AHT.Bytes;
with AHT.Transport;

package AHT.HTTP.IO is

   procedure Write_All
     (T    : in out AHT.Transport.Transport_Type'Class;
      Data : AHT.Bytes.Byte_Array);

   function Read_Line
     (T           : in out AHT.Transport.Transport_Type'Class;
      Max_Length  : Positive := 8_192) return String;
   --  Reads until CRLF. Raises HTTP.Protocol_Error if no CRLF before
   --  Max_Length bytes have been consumed.

   procedure Read_N
     (T    : in out AHT.Transport.Transport_Type'Class;
      Data : out AHT.Bytes.Byte_Array);

   procedure Read_Chunked_Body
     (T    : in out AHT.Transport.Transport_Type'Class;
      Sink : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array));
   --  Streaming chunked-transfer decoder. Delivers the body to Sink
   --  as ordered, non-empty slices of at most 4 KiB; chunk boundaries
   --  are not preserved and the zero-size terminator is not
   --  delivered. Trailer headers are drained and discarded. Raises
   --  Protocol_Error on a non-hex chunk size, a size overflowing
   --  Natural'Last, or chunk data not followed by a bare CRLF.

   function Read_Chunked_Body
     (T : in out AHT.Transport.Transport_Type'Class)
      return AHT.Bytes.Buffer;
   --  Buffered form: assembles every chunk into one buffer by wrapping
   --  the streaming procedure with an appending sink.

   --  Pull-style reader over one message body, for consumers that
   --  ask for bytes rather than receive them (the content decoders).
   --  The push procedures above are loops over it.
   type Body_Framing is
     (No_Body,      --  the message ends at its header section
      Chunked,      --  Transfer-Encoding: chunked
      Fixed,        --  Content-Length: N
      Until_Close); --  everything until the peer closes

   type Body_Reader is private;

   procedure Start
     (Self    : out Body_Reader;
      Framing : Body_Framing;
      Length  : Natural := 0);
   --  A reader positioned at the first body byte. Length is N for
   --  Fixed and ignored otherwise.

   procedure Read
     (Self : in out Body_Reader;
      T    : in out AHT.Transport.Transport_Type'Class;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural);
   --  The next body bytes into Data (Data'First .. Last), or
   --  Last < Data'First at the end of the body, then on every later
   --  call. Fixed and Chunked fill exactly min (Data'Length, bytes
   --  left in the body or the current chunk), so a read never crosses
   --  a chunk boundary and never reads past the message; Chunked
   --  consumes each chunk's CRLF, and at the end the trailer section,
   --  before reporting the end. Until_Close returns what one
   --  transport Read returns. Same Protocol_Error conditions as the
   --  push readers, and for Fixed a peer close before N bytes.

   function At_End (Self : Body_Reader) return Boolean;
   --  True once Read has reported the end of the body.

private

   type Body_Reader is record
      Framing    : Body_Framing := No_Body;
      Left       : Natural := 0;
      --  Fixed: body bytes left. Chunked: bytes left in this chunk.
      In_Chunk   : Boolean := False;
      --  Chunked: a chunk's data has started and its CRLF is pending.
      Done       : Boolean := True;
   end record;

end AHT.HTTP.IO;
