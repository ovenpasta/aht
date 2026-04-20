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

   function Read_Chunked_Body
     (T : in out AHT.Transport.Transport_Type'Class)
      return AHT.Bytes.Byte_Vector;

end AHT.HTTP.IO;
