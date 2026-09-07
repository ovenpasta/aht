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

end AHT.HTTP.IO;
