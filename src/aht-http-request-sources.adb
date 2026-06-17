package body AHT.HTTP.Request.Sources is

   function Create
     (Stream : not null access Ada.Streams.Root_Stream_Type'Class)
      return Stream_Source is
   begin
      return S : Stream_Source do
         S.Stream := Stream;
      end return;
   end Create;

   overriding procedure Read_Chunk
     (Self : in out Stream_Source;
      Buf  : out AHT.Bytes.Byte_Array;
      Last : out Natural)
   is
      use type Ada.Streams.Stream_Element_Offset;
      SE      : Ada.Streams.Stream_Element_Array
                  (0 .. Ada.Streams.Stream_Element_Offset (Buf'Length) - 1);
      Last_SE : Ada.Streams.Stream_Element_Offset;
   begin
      if Self.Done then
         Last := Buf'First - 1;  --  sticky EOF
         return;
      end if;

      Self.Stream.Read (SE, Last_SE);

      if Last_SE < SE'First then
         --  Zero elements read => end of stream. Latch so every later
         --  call keeps signalling EOF.
         Self.Done := True;
         Last := Buf'First - 1;
         return;
      end if;

      for I in 0 .. Natural (Last_SE - SE'First) loop
         Buf (Buf'First + I) :=
           AHT.Bytes.Octet
             (SE (SE'First + Ada.Streams.Stream_Element_Offset (I)));
      end loop;
      Last := Buf'First + Natural (Last_SE - SE'First);
   end Read_Chunk;

end AHT.HTTP.Request.Sources;
