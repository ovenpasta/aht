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
   --  Streaming chunked-transfer decoder. Delivers the body to `Sink`
   --  as ordered, non-empty byte slices and never calls `Sink` with an
   --  empty `Chunk`; the zero-size terminator chunk closes the body.
   --  Chunk boundaries are NOT preserved: a single large wire chunk is
   --  delivered as several bounded windows so the decoder's stack
   --  footprint stays O(1) in the chunk size rather than allocating a
   --  size-of-chunk buffer that a multi-MB chunk would overflow. A
   --  `Sink` must therefore treat each call as "more body bytes", not
   --  as an HTTP-chunk boundary — matching `Read_N_Streaming` /
   --  `Read_Until_EOF_Streaming` in AHT.HTTP.Response, which already
   --  window their deliveries. Trailer headers are still drained and
   --  discarded. Same error conditions as the buffered overload:
   --  non-hex size, overflow past `Natural'Last`, chunk-data not
   --  followed by bare CRLF.

   function Read_Chunked_Body
     (T : in out AHT.Transport.Transport_Type'Class)
      return AHT.Bytes.Buffer;
   --  Buffered convenience: assembles every chunk into one buffer
   --  by wrapping the streaming procedure with an appending sink.

end AHT.HTTP.IO;
