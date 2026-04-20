package body AHT.HTTP.IO is

   procedure Write_All
     (T    : in out AHT.Transport.Transport_Type'Class;
      Data : AHT.Bytes.Byte_Array)
   is
      pragma Unreferenced (T, Data);
   begin
      raise HTTP_Error with "AHT.HTTP.IO.Write_All: not yet implemented";
   end Write_All;

   function Read_Line
     (T          : in out AHT.Transport.Transport_Type'Class;
      Max_Length : Positive := 8_192) return String
   is
      pragma Unreferenced (T, Max_Length);
   begin
      raise HTTP_Error with "AHT.HTTP.IO.Read_Line: not yet implemented";
      return "";
   end Read_Line;

   procedure Read_N
     (T    : in out AHT.Transport.Transport_Type'Class;
      Data : out AHT.Bytes.Byte_Array)
   is
      pragma Unreferenced (T);
   begin
      for I in Data'Range loop
         Data (I) := 0;
      end loop;
      raise HTTP_Error with "AHT.HTTP.IO.Read_N: not yet implemented";
   end Read_N;

   function Read_Chunked_Body
     (T : in out AHT.Transport.Transport_Type'Class)
      return AHT.Bytes.Byte_Vector
   is
      pragma Unreferenced (T);
      Empty : AHT.Bytes.Byte_Vector;
   begin
      raise HTTP_Error with "AHT.HTTP.IO.Read_Chunked_Body: not yet implemented";
      return Empty;
   end Read_Chunked_Body;

end AHT.HTTP.IO;
