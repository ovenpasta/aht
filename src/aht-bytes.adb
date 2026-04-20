package body AHT.Bytes is

   function From_String (S : String) return Byte_Array is
      Result : Byte_Array (1 .. S'Length);
   begin
      for I in S'Range loop
         Result (Result'First + (I - S'First)) := Character'Pos (S (I));
      end loop;
      return Result;
   end From_String;

   function To_String (B : Byte_Array) return String is
      Result : String (1 .. B'Length);
   begin
      for I in B'Range loop
         Result (Result'First + (I - B'First)) := Character'Val (B (I));
      end loop;
      return Result;
   end To_String;

end AHT.Bytes;
