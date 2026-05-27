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
   --  Streaming chunked-transfer decoder. Calls `Sink` for each
   --  decoded chunk's data bytes; the zero-size terminator chunk
   --  closes the body but is not delivered (`Sink` is never called
   --  with an empty `Chunk`). Trailer headers are still drained and
   --  discarded. Same error conditions as the buffered overload:
   --  non-hex size, overflow past `Natural'Last`, chunk-data not
   --  followed by bare CRLF.

   function Read_Chunked_Body
     (T : in out AHT.Transport.Transport_Type'Class)
      return AHT.Bytes.Byte_Vector;
   --  Buffered convenience: assembles every chunk into one vector
   --  by wrapping the streaming procedure with an appending sink.

end AHT.HTTP.IO;
