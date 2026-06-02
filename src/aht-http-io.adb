with AHT.Log.Tag;

package body AHT.HTTP.IO is

   package Log is new AHT.Log.Tag ("http.io");

   --  Parse a hexadecimal string into a Natural. Used only for the
   --  chunk-size line, which is caller-trimmed to just the HEXDIG run.
   --  Raises Protocol_Error on a non-hex character, an empty input, or
   --  an overflow past Natural'Last.
   function Parse_Hex (S : String) return Natural;

   function Parse_Hex (S : String) return Natural is
      Result : Natural := 0;
      Digit  : Natural;
   begin
      if S'Length = 0 then
         raise Protocol_Error with
           "HTTP.IO.Parse_Hex: empty chunk-size";
      end if;

      for C of S loop
         case C is
            when '0' .. '9' => Digit := Character'Pos (C) - Character'Pos ('0');
            when 'a' .. 'f' => Digit := 10 + Character'Pos (C) - Character'Pos ('a');
            when 'A' .. 'F' => Digit := 10 + Character'Pos (C) - Character'Pos ('A');
            when others =>
               raise Protocol_Error with
                 "HTTP.IO.Parse_Hex: non-hex character '" & C & "'";
         end case;

         --  Pre-check overflow: Natural'Last / 16 is the largest value
         --  that can be safely shifted left by 4 bits without wrapping.
         if Result > (Natural'Last - Digit) / 16 then
            raise Protocol_Error with
              "HTTP.IO.Parse_Hex: chunk size overflows Natural";
         end if;
         Result := Result * 16 + Digit;
      end loop;

      return Result;
   end Parse_Hex;

   procedure Write_All
     (T    : in out AHT.Transport.Transport_Type'Class;
      Data : AHT.Bytes.Byte_Array)
   is
   begin
      --  The Transport contract is "all-or-raise": TCP/TLS Write
      --  either flushes every byte or raises Transport_Error. This is
      --  a thin named entry point for the HTTP layer plus a log call.
      if Data'Length = 0 then
         return;
      end if;
      T.Write (Data);
      if Log.Enabled (AHT.Log.Trace) then
         Log.Trace ("wrote" & Integer'Image (Data'Length) & " bytes");
      end if;
   end Write_All;

   function Read_Line
     (T          : in out AHT.Transport.Transport_Type'Class;
      Max_Length : Positive := 8_192) return String
   is
      Buf  : String (1 .. Max_Length);
      Len  : Natural := 0;
      One  : AHT.Bytes.Byte_Array (1 .. 1);
      Last : Natural;
   begin
      --  Byte-by-byte read so the caller can transition to bulk body
      --  reads without a buffered-reader abstraction: every Read_Line
      --  leaves the transport positioned exactly at the byte after
      --  CRLF, with no overshoot.
      loop
         T.Read (One, Last);
         if Last = 0 then
            raise Protocol_Error with
              "HTTP.IO.Read_Line: peer closed before CRLF";
         end if;

         if Len = Max_Length then
            raise Protocol_Error with
              "HTTP.IO.Read_Line: line exceeds"
              & Positive'Image (Max_Length) & " bytes";
         end if;

         Len := Len + 1;
         Buf (Len) := Character'Val (One (1));

         if Len >= 2
           and then Buf (Len - 1) = ASCII.CR
           and then Buf (Len)     = ASCII.LF
         then
            return Buf (1 .. Len - 2);
         end if;
      end loop;
   end Read_Line;

   procedure Read_N
     (T    : in out AHT.Transport.Transport_Type'Class;
      Data : out AHT.Bytes.Byte_Array)
   is
      Cursor : Positive := Data'First;
      Last   : Natural;
   begin
      if Data'Length = 0 then
         return;
      end if;

      while Cursor <= Data'Last loop
         T.Read (Data (Cursor .. Data'Last), Last);
         if Last = 0 then
            raise Protocol_Error with
              "HTTP.IO.Read_N: peer closed with"
              & Natural'Image (Cursor - Data'First)
              & " of" & Natural'Image (Data'Length) & " bytes read";
         end if;
         Cursor := Last + 1;
      end loop;
   end Read_N;

   procedure Read_Chunked_Body
     (T    : in out AHT.Transport.Transport_Type'Class;
      Sink : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array))
   is
      Total : Natural := 0;

      function Chunk_Size_From_Line (Line : String) return Natural;

      function Chunk_Size_From_Line (Line : String) return Natural is
         Semi : Natural := 0;
      begin
         --  Ignore chunk-ext (anything after the first ';').
         for I in Line'Range loop
            if Line (I) = ';' then
               Semi := I;
               exit;
            end if;
         end loop;
         if Semi = 0 then
            return Parse_Hex (Line);
         else
            return Parse_Hex (Line (Line'First .. Semi - 1));
         end if;
      end Chunk_Size_From_Line;

   begin
      loop
         declare
            Line : constant String := Read_Line (T);
            Size : constant Natural := Chunk_Size_From_Line (Line);
         begin
            exit when Size = 0;

            --  Read the chunk-data in bounded windows rather than into
            --  a single Size-sized array. Size comes straight off the
            --  wire (the chunk-size line) and is unbounded, so a
            --  Size-sized local would be a dynamically-sized *primary*-
            --  stack object that overflows the fixed thread stack on a
            --  multi-MB chunk (and would drive the same overflow into
            --  TCP Read's buffer via Read_N). A fixed window keeps the
            --  stack footprint O(1) in the chunk size; Sink sees the
            --  chunk delivered as ordered slices.
            declare
               Window : constant Positive := 4_096;
               Buf    : AHT.Bytes.Byte_Array (1 .. Window);
               Left   : Natural := Size;
            begin
               while Left > 0 loop
                  declare
                     This  : constant Positive := Natural'Min (Window, Left);
                     Slice : AHT.Bytes.Byte_Array renames Buf (1 .. This);
                  begin
                     Read_N (T, Slice);
                     Sink (Slice);
                     Left := Left - This;
                  end;
               end loop;
               Total := Total + Size;
            end;

            --  RFC 7230: chunk-data is followed by CRLF.
            declare
               Trailing : constant String := Read_Line (T);
            begin
               if Trailing'Length /= 0 then
                  raise Protocol_Error with
                    "HTTP.IO.Read_Chunked_Body: chunk-data not followed "
                    & "by bare CRLF (got """ & Trailing & """)";
               end if;
            end;
         end;
      end loop;

      --  After the last (zero-size) chunk: read trailer lines until an
      --  empty line terminates the chunked body.
      loop
         declare
            Trailer : constant String := Read_Line (T);
         begin
            exit when Trailer'Length = 0;
         end;
      end loop;

      if Log.Enabled (AHT.Log.Debug) then
         Log.Debug
           ("chunked body: " & Natural'Image (Total) & " bytes");
      end if;
   end Read_Chunked_Body;

   function Read_Chunked_Body
     (T : in out AHT.Transport.Transport_Type'Class)
      return AHT.Bytes.Byte_Vector
   is
      Result : AHT.Bytes.Byte_Vector;

      procedure Append_To_Result (Chunk : AHT.Bytes.Byte_Array) is
      begin
         for B of Chunk loop
            Result.Append (B);
         end loop;
      end Append_To_Result;
   begin
      Read_Chunked_Body (T, Append_To_Result'Access);
      return Result;
   end Read_Chunked_Body;

end AHT.HTTP.IO;
