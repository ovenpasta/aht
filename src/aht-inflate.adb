--  Copyright (C) 2007-2025 Gautier de Montmollin
--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: MIT

with Interfaces; use Interfaces;

with AHT.Inflate.Huffman; use AHT.Inflate.Huffman;

package body AHT.Inflate is

   subtype Octet is AHT.Bytes.Octet;

   --  The sliding window: DEFLATE distances reach at most 32 KiB back.
   Window_Size : constant := 16#8000#;

   --  Largest slice handed to Output.
   Max_Slice : constant := 4_096;

   --  Zero bytes the bit reader may borrow past the end of input. A
   --  Huffman lookup reads its full index width even when the code is
   --  shorter, so the last code of a complete stream can need bits
   --  beyond the final byte: up to two bytes, for the widest read (16
   --  bits). The bound is twice that. A stream that borrows more is
   --  truncated. A stream that ends having consumed borrowed bits is
   --  truncated too (checked at its end).
   Max_Pad : constant := 4;

   ---------------------------------------------------------------------
   --  Checksums
   ---------------------------------------------------------------------

   type CRC_Table_Type is array (Unsigned_32 range 0 .. 255) of Unsigned_32;

   function Make_CRC_Table return CRC_Table_Type is
      T : CRC_Table_Type;
      C : Unsigned_32;
   begin
      for N in T'Range loop
         C := N;
         for Bit in 1 .. 8 loop
            if (C and 1) /= 0 then
               C := 16#EDB8_8320# xor Shift_Right (C, 1);
            else
               C := Shift_Right (C, 1);
            end if;
         end loop;
         T (N) := C;
      end loop;
      return T;
   end Make_CRC_Table;

   CRC_Table : constant CRC_Table_Type := Make_CRC_Table;

   --  The register is kept inverted: start at all ones, and the CRC
   --  is the register xor all ones.
   procedure CRC_Update (CRC : in out Unsigned_32; B : Octet) with Inline is
   begin
      CRC := CRC_Table ((CRC xor Unsigned_32 (B)) and 16#FF#)
             xor Shift_Right (CRC, 8);
   end CRC_Update;

   Adler_Base : constant := 65_521;

   ---------------------------------------------------------------------
   --  DEFLATE code tables (RFC 1951 sec. 3.2.5)
   ---------------------------------------------------------------------

   --  Base lengths for literal/length codes 257 .. 285.
   Copy_Lengths_Literal : constant Length_Array (0 .. 30) :=
     [3,  4,  5,  6,  7,  8,  9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
      35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0];

   --  Extra bits for literal/length codes 257 .. 285; 286 and 287
   --  are invalid.
   Extra_Bits_Literal : constant Length_Array (0 .. 30) :=
     [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
      3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, Invalid, Invalid];

   --  Base distances for distance codes 0 .. 29.
   Copy_Offset_Distance : constant Length_Array (0 .. 29) :=
     [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
      257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
      8193, 12289, 16385, 24577];

   Extra_Bits_Distance : constant Length_Array (0 .. 29) :=
     [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
      7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

   Fixed_Literal_Lengths : constant Length_Array (0 .. 287) :=
     [0 .. 143 => 8, 144 .. 255 => 9, 256 .. 279 => 7, 280 .. 287 => 8];

   Fixed_Distance_Lengths : constant Length_Array (0 .. 29) :=
     [others => 5];

   Code_Length_Order : constant array (0 .. 18) of Natural :=
     [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

   ---------------------------------------------------------------------
   --  Decode
   ---------------------------------------------------------------------

   procedure Decode
     (Kind   : Format;
      Input  : not null access procedure
        (Data : out AHT.Bytes.Byte_Array; Last : out Natural);
      Output : not null access procedure (Data : AHT.Bytes.Byte_Array))
   is
      --  Input side: the last buffer Input filled.
      In_Buf  : AHT.Bytes.Byte_Array (1 .. 4_096);
      In_Pos  : Positive := 1;
      In_Last : Natural := 0;
      In_EOF  : Boolean := False;

      --  Bit reader: K bits are buffered in BB, least significant
      --  first. Pad of them, the most significant whole bytes, were
      --  borrowed past the end of input.
      BB  : Unsigned_32 := 0;
      K   : Natural := 0;
      Pad : Natural := 0;

      --  Output side: Slide (Flushed .. Slide_Index - 1) is decoded
      --  but not yet delivered.
      type Slide_Array is array (Natural range 0 .. Window_Size) of Octet;
      Slide       : Slide_Array := [others => 0];
      Slide_Index : Natural := 0;
      Flushed     : Natural := 0;

      --  Bytes decoded in the whole stream, for the distance check.
      Produced : Unsigned_64 := 0;

      --  Per-member checks, over delivered bytes.
      CRC        : Unsigned_32 := 16#FFFF_FFFF#;
      Adler_A    : Unsigned_32 := 1;
      Adler_B    : Unsigned_32 := 0;
      Member_Out : Unsigned_32 := 0;   --  mod 2**32

      procedure Reset_Checks is
      begin
         CRC        := 16#FFFF_FFFF#;
         Adler_A    := 1;
         Adler_B    := 0;
         Member_Out := 0;
      end Reset_Checks;

      ------------------------------------------------------------------
      --  Output
      ------------------------------------------------------------------

      procedure Deliver (First, Last : Natural) is
         P : Natural := First;
      begin
         while P <= Last loop
            declare
               N   : constant Positive :=
                 Natural'Min (Max_Slice, Last - P + 1);
               Tmp : AHT.Bytes.Byte_Array (1 .. N);
            begin
               for I in 1 .. N loop
                  declare
                     B : constant Octet := Slide (P + I - 1);
                  begin
                     Tmp (I) := B;
                     CRC_Update (CRC, B);
                     Adler_A := (Adler_A + Unsigned_32 (B)) mod Adler_Base;
                     Adler_B := (Adler_B + Adler_A) mod Adler_Base;
                  end;
               end loop;
               Member_Out := Member_Out + Unsigned_32 (N);
               Output (Tmp);
               P := P + N;
            end;
         end loop;
      end Deliver;

      procedure Flush_Pending is
      begin
         if Slide_Index > Flushed then
            Deliver (Flushed, Slide_Index - 1);
            Flushed := Slide_Index;
         end if;
      end Flush_Pending;

      procedure Flush_If_Full with Inline is
      begin
         if Slide_Index = Window_Size then
            Flush_Pending;
            Slide_Index := 0;
            Flushed     := 0;
         end if;
      end Flush_If_Full;

      procedure Put_Byte (B : Octet) with Inline is
      begin
         Slide (Slide_Index) := B;
         Slide_Index := Slide_Index + 1;
         Produced    := Produced + 1;
         Flush_If_Full;
      end Put_Byte;

      --  Copy Length bytes from Distance back in the output. The
      --  window arithmetic is Zip-Ada's (Adjust_to_Slide, Copy_range).
      procedure Copy (Distance, Length : Natural) is
         Source : Integer := Slide_Index - Distance;
         Remain : Natural := Length;
         Part   : Integer;
      begin
         if Distance = 0 or else Unsigned_64 (Distance) > Produced then
            raise Data_Error with
              "inflate: distance" & Distance'Image
              & " reaches before the start of the output";
         end if;
         loop
            Source := Source mod Window_Size;
            if Source > Slide_Index then
               Part := Window_Size - Source;
            else
               Part := Window_Size - Slide_Index;
            end if;
            if Part > Remain then
               Part := Remain;
            end if;
            Remain := Remain - Part;

            if abs (Slide_Index - Source) < Part then
               --  Overlapping: byte by byte, so a short distance
               --  replicates the bytes just written.
               for Count in reverse 1 .. Part loop
                  Slide (Slide_Index) := Slide (Source);
                  Slide_Index := Slide_Index + 1;
                  Source      := Source + 1;
               end loop;
            else
               Slide (Slide_Index .. Slide_Index + Part - 1) :=
                 Slide (Source .. Source + Part - 1);
               Slide_Index := Slide_Index + Part;
               Source      := Source + Part;
            end if;
            Produced := Produced + Unsigned_64 (Part);
            Flush_If_Full;
            exit when Remain = 0;
         end loop;
      end Copy;

      ------------------------------------------------------------------
      --  Input
      ------------------------------------------------------------------

      --  True when a real input byte is available at In_Pos, pulling
      --  more input (after delivering pending output) if needed.
      function More_Input return Boolean is
      begin
         if In_Pos <= In_Last then
            return True;
         end if;
         if In_EOF then
            return False;
         end if;
         Flush_Pending;
         Input (In_Buf, In_Last);
         In_Pos := In_Buf'First;
         if In_Last < In_Buf'First then
            In_EOF  := True;
            In_Last := 0;
            return False;
         end if;
         return True;
      end More_Input;

      procedure Need (N : Natural) with Inline is
      begin
         while K < N loop
            if More_Input then
               BB := BB or Shift_Left (Unsigned_32 (In_Buf (In_Pos)), K);
               In_Pos := In_Pos + 1;
            else
               Pad := Pad + 1;
               if Pad > Max_Pad then
                  raise Data_Error with "inflate: truncated stream";
               end if;
            end if;
            K := K + 8;
         end loop;
      end Need;

      procedure Dump (N : Natural) with Inline is
      begin
         BB := Shift_Right (BB, N);
         K  := K - N;
      end Dump;

      function Read (N : Natural) return Natural with Inline is
      begin
         Need (N);
         return Natural (BB and (Shift_Left (Unsigned_32'(1), N) - 1));
      end Read;

      function Read_And_Dump (N : Natural) return Natural is
         R : constant Natural := Read (N);
      begin
         Dump (N);
         return R;
      end Read_And_Dump;

      --  True when the stream has read borrowed bits.
      function Overrun return Boolean is (K < 8 * Pad);

      --  Whole bytes in BB that came from the input.
      function Real_Buffered_Bytes return Integer is (K / 8 - Pad);

      --  The next byte at a byte boundary (K mod 8 = 0): from BB while
      --  it holds real bytes, then from the input.
      function Next_Byte return Octet is
         R : Octet;
      begin
         if K >= 8 then
            if Real_Buffered_Bytes < 1 then
               raise Data_Error with "inflate: truncated stream";
            end if;
            R := Octet (BB and 16#FF#);
            Dump (8);
            return R;
         elsif More_Input then
            R := In_Buf (In_Pos);
            In_Pos := In_Pos + 1;
            return R;
         else
            raise Data_Error with "inflate: truncated stream";
         end if;
      end Next_Byte;

      --  At a byte boundary: True when no input byte remains, buffered
      --  or not.
      function At_End return Boolean is
        (Real_Buffered_Bytes <= 0 and then not More_Input);

      ------------------------------------------------------------------
      --  DEFLATE blocks (Zip-Ada's Inflate_Codes / _Stored / _Fixed /
      --  _Dynamic / _Block)
      ------------------------------------------------------------------

      procedure Inflate_Codes
        (Tl, Td : Table_List; Bl, Bd : Integer)
      is
         CT     : HufT_Table_Access;
         CT_Idx : Natural;
         Length : Natural;
         E      : Integer;
      begin
         if Tl.Head = null then
            raise Data_Error with "inflate: no literal/length codes";
         end if;
         loop
            CT := Tl.Head.Table;
            CT_Idx := Read (Bl);
            loop
               E := CT (CT_Idx).Extra_Bits;
               exit when E <= 16;
               if E = Invalid then
                  raise Data_Error with "inflate: invalid literal/length code";
               end if;
               Dump (CT (CT_Idx).Bits);
               E := E - 16;
               CT := CT (CT_Idx).Next_Table;
               CT_Idx := Read (E);
            end loop;

            Dump (CT (CT_Idx).Bits);

            case E is
               when 16 =>
                  --  A literal byte.
                  Put_Byte (Octet (CT (CT_Idx).N));

               when 15 =>
                  --  End of block.
                  exit;

               when others =>
                  --  A length, then its distance.
                  Length := CT (CT_Idx).N + Read_And_Dump (E);

                  if Td.Head = null then
                     raise Data_Error with "inflate: no distance codes";
                  end if;
                  CT := Td.Head.Table;
                  CT_Idx := Read (Bd);
                  loop
                     E := CT (CT_Idx).Extra_Bits;
                     exit when E <= 16;
                     if E = Invalid then
                        raise Data_Error with
                          "inflate: invalid distance code";
                     end if;
                     Dump (CT (CT_Idx).Bits);
                     E := E - 16;
                     CT := CT (CT_Idx).Next_Table;
                     CT_Idx := Read (E);
                  end loop;
                  if E > 13 then
                     raise Data_Error with "inflate: invalid distance code";
                  end if;
                  Dump (CT (CT_Idx).Bits);
                  Copy (Distance => CT (CT_Idx).N + Read_And_Dump (E),
                        Length   => Length);
            end case;
         end loop;
      end Inflate_Codes;

      procedure Inflate_Stored_Block is
         N : Natural;
      begin
         Dump (K mod 8);
         N := Read_And_Dump (16);
         if N + Read_And_Dump (16) /= 16#FFFF# then
            raise Data_Error with "inflate: stored block length mismatch";
         end if;
         for I in 1 .. N loop
            Put_Byte (Octet (Read_And_Dump (8)));
         end loop;
      end Inflate_Stored_Block;

      procedure Build_Or_Fail
        (B          : Length_Array;
         S          : Integer;
         D, E       : Length_Array;
         Tables     : in out Table_List;
         M          : in out Integer;
         Incomplete : out Boolean;
         What       : String) is
      begin
         Build (B, S, D, E, Tables, M, Incomplete);
      exception
         when Huffman_Error =>
            raise Data_Error with "inflate: bad " & What & " code set";
      end Build_Or_Fail;

      procedure Inflate_Fixed_Block is
         Tl, Td     : Table_List;
         Bl         : Integer := 7;
         Bd         : Integer := 5;
         Incomplete : Boolean;
      begin
         Build_Or_Fail
           (Fixed_Literal_Lengths, 257,
            Copy_Lengths_Literal, Extra_Bits_Literal,
            Tl, Bl, Incomplete, "fixed literal/length");
         Build_Or_Fail
           (Fixed_Distance_Lengths, 0,
            Copy_Offset_Distance, Extra_Bits_Distance,
            Td, Bd, Incomplete, "fixed distance");
         Inflate_Codes (Tl, Td, Bl, Bd);
      end Inflate_Fixed_Block;

      procedure Inflate_Dynamic_Block is
         Lbits : constant := 9;
         Dbits : constant := 6;

         Current_Length    : Natural := 0;
         Defined           : Natural := 0;
         Number_Of_Lengths : Natural;

         Tc, Tl, Td : Table_List;
         CT         : HufT_Table_Access;
         CT_Idx     : Natural;
         Bc, Bl, Bd : Integer;

         Nb : Natural;   --  bit-length codes
         Nl : Natural;   --  literal/length codes
         Nd : Natural;   --  distance codes

         Ll : Length_Array (0 .. 288 + 32 - 1) := [others => 0];

         Incomplete : Boolean;

         procedure Repeat (Amount : Natural) is
         begin
            if Defined + Amount > Number_Of_Lengths then
               raise Data_Error with "inflate: too many code lengths";
            end if;
            for C in 1 .. Amount loop
               Ll (Defined) := Current_Length;
               Defined := Defined + 1;
            end loop;
         end Repeat;
      begin
         Nl := 257 + Read_And_Dump (5);
         Nd :=   1 + Read_And_Dump (5);
         Nb :=   4 + Read_And_Dump (4);

         if Nl > 286 or else Nd > 30 then
            raise Data_Error with
              "inflate: too many length or distance symbols";
         end if;

         for J in 0 .. Nb - 1 loop
            Ll (Code_Length_Order (J)) := Read_And_Dump (3);
         end loop;

         Bc := 7;
         Build_Or_Fail
           (Ll (0 .. 18), 19, Empty, Empty, Tc, Bc, Incomplete,
            "code length");
         if Incomplete or else Tc.Head = null then
            raise Data_Error with "inflate: incomplete code length set";
         end if;

         Number_Of_Lengths := Nl + Nd;
         Ll (0 .. 18) := [others => 0];

         while Defined < Number_Of_Lengths loop
            CT := Tc.Head.Table;
            CT_Idx := Read (Bc);
            if CT (CT_Idx).Extra_Bits = Invalid then
               raise Data_Error with "inflate: invalid code length code";
            end if;
            Dump (CT (CT_Idx).Bits);

            case CT (CT_Idx).N is
               when 0 .. 15 =>
                  Current_Length := CT (CT_Idx).N;
                  Ll (Defined) := Current_Length;
                  Defined := Defined + 1;
               when 16 =>
                  --  Repeat the previous length 3 .. 6 times.
                  if Defined = 0 then
                     raise Data_Error with
                       "inflate: repeat with no previous length";
                  end if;
                  Repeat (3 + Read_And_Dump (2));
               when 17 =>
                  Current_Length := 0;
                  Repeat (3 + Read_And_Dump (3));
               when 18 =>
                  Current_Length := 0;
                  Repeat (11 + Read_And_Dump (7));
               when others =>
                  raise Data_Error with "inflate: invalid code length";
            end case;
         end loop;
         Free (Tc);

         if Ll (256) = 0 then
            raise Data_Error with "inflate: no end-of-block code";
         end if;

         Bl := Lbits;
         Build_Or_Fail
           (Ll (0 .. Nl - 1), 257,
            Copy_Lengths_Literal, Extra_Bits_Literal,
            Tl, Bl, Incomplete, "literal/length");
         if Incomplete then
            raise Data_Error with "inflate: incomplete literal/length set";
         end if;

         Bd := Dbits;
         Build_Or_Fail
           (Ll (Nl .. Nl + Nd - 1), 0,
            Copy_Offset_Distance, Extra_Bits_Distance,
            Td, Bd, Incomplete, "distance");
         if Incomplete then
            raise Data_Error with "inflate: incomplete distance set";
         end if;

         Inflate_Codes (Tl, Td, Bl, Bd);
      end Inflate_Dynamic_Block;

      --  One whole DEFLATE stream; ends at a byte boundary with every
      --  decoded byte delivered.
      procedure Inflate_Stream is
         Last_Block : Boolean;
      begin
         loop
            Last_Block := Read_And_Dump (1) = 1;
            case Read_And_Dump (2) is
               when 0 => Inflate_Stored_Block;
               when 1 => Inflate_Fixed_Block;
               when 2 => Inflate_Dynamic_Block;
               when others =>
                  raise Data_Error with "inflate: invalid block type";
            end case;
            exit when Last_Block;
         end loop;
         if Overrun then
            raise Data_Error with "inflate: truncated stream";
         end if;
         Dump (K mod 8);
         Flush_Pending;
      end Inflate_Stream;

      ------------------------------------------------------------------
      --  Framings
      ------------------------------------------------------------------

      function Next_U32_LE return Unsigned_32 is
         R : Unsigned_32 := 0;
      begin
         for I in 0 .. 3 loop
            R := R or Shift_Left (Unsigned_32 (Next_Byte), 8 * I);
         end loop;
         return R;
      end Next_U32_LE;

      function Next_U32_BE return Unsigned_32 is
         R : Unsigned_32 := 0;
      begin
         for I in 0 .. 3 loop
            R := Shift_Left (R, 8) or Unsigned_32 (Next_Byte);
         end loop;
         return R;
      end Next_U32_BE;

      function Valid_Zlib_Header (CMF, FLG : Octet) return Boolean is
        ((CMF and 16#0F#) = 8
         and then Shift_Right (CMF, 4) <= 7
         and then (Natural (CMF) * 256 + Natural (FLG)) mod 31 = 0);

      --  Zlib after its two header bytes: FDICT, DEFLATE, Adler-32.
      procedure Zlib_Body (FLG : Octet) is
      begin
         if (FLG and 16#20#) /= 0 then
            raise Data_Error with "zlib: preset dictionary not supported";
         end if;
         Reset_Checks;
         Inflate_Stream;
         if Next_U32_BE /= Shift_Left (Adler_B, 16) + Adler_A then
            raise Data_Error with "zlib: Adler-32 mismatch";
         end if;
      end Zlib_Body;

      procedure Zlib_Member is
         CMF : constant Octet := Next_Byte;
         FLG : constant Octet := Next_Byte;
      begin
         if not Valid_Zlib_Header (CMF, FLG) then
            raise Data_Error with "zlib: invalid header";
         end if;
         Zlib_Body (FLG);
      end Zlib_Member;

      procedure Gzip_Member is
         FHCRC    : constant := 16#02#;
         FEXTRA   : constant := 16#04#;
         FNAME    : constant := 16#08#;
         FCOMMENT : constant := 16#10#;

         Header_CRC : Unsigned_32 := 16#FFFF_FFFF#;

         function Header_Byte return Octet is
            B : constant Octet := Next_Byte;
         begin
            CRC_Update (Header_CRC, B);
            return B;
         end Header_Byte;

         procedure Skip_Zero_Terminated is
         begin
            loop
               exit when Header_Byte = 0;
            end loop;
         end Skip_Zero_Terminated;

         FLG : Octet;
      begin
         if Header_Byte /= 16#1F# or else Header_Byte /= 16#8B# then
            raise Data_Error with "gzip: bad magic";
         end if;
         if Header_Byte /= 8 then
            raise Data_Error with "gzip: compression method is not deflate";
         end if;
         FLG := Header_Byte;
         if (FLG and 16#E0#) /= 0 then
            raise Data_Error with "gzip: reserved flag set";
         end if;
         for I in 1 .. 6 loop   --  MTIME, XFL, OS
            declare
               Ignore : constant Octet := Header_Byte;
            begin
               null;
            end;
         end loop;

         if (FLG and FEXTRA) /= 0 then
            declare
               Lo  : constant Octet := Header_Byte;
               Hi  : constant Octet := Header_Byte;
               Len : constant Natural := Natural (Lo) + 256 * Natural (Hi);
            begin
               for I in 1 .. Len loop
                  declare
                     Ignore : constant Octet := Header_Byte;
                  begin
                     null;
                  end;
               end loop;
            end;
         end if;
         if (FLG and FNAME) /= 0 then
            Skip_Zero_Terminated;
         end if;
         if (FLG and FCOMMENT) /= 0 then
            Skip_Zero_Terminated;
         end if;
         if (FLG and FHCRC) /= 0 then
            declare
               Expected : constant Unsigned_32 :=
                 (Header_CRC xor 16#FFFF_FFFF#) and 16#FFFF#;
               Lo       : constant Octet := Next_Byte;
               Hi       : constant Octet := Next_Byte;
            begin
               if Unsigned_32 (Lo) + 256 * Unsigned_32 (Hi) /= Expected then
                  raise Data_Error with "gzip: header CRC mismatch";
               end if;
            end;
         end if;

         Reset_Checks;
         Inflate_Stream;
         if Next_U32_LE /= (CRC xor 16#FFFF_FFFF#) then
            raise Data_Error with "gzip: CRC-32 mismatch";
         end if;
         if Next_U32_LE /= Member_Out then
            raise Data_Error with "gzip: length mismatch";
         end if;
      end Gzip_Member;

   begin
      if not More_Input then
         return;
      end if;

      case Kind is
         when Raw =>
            Inflate_Stream;

         when Zlib =>
            Zlib_Member;

         when Zlib_Or_Raw =>
            --  Look at two bytes without committing: a zlib header
            --  consumes them, a raw stream starts with them.
            Need (16);
            if Pad = 0
              and then Valid_Zlib_Header
                (Octet (BB and 16#FF#), Octet (Shift_Right (BB, 8) and 16#FF#))
            then
               declare
                  FLG : constant Octet := Octet (Shift_Right (BB, 8) and 16#FF#);
               begin
                  Dump (16);
                  Zlib_Body (FLG);
               end;
            else
               Inflate_Stream;
            end if;

         when Gzip =>
            loop
               Gzip_Member;
               exit when At_End;
            end loop;
      end case;

      if not At_End then
         raise Data_Error with "inflate: trailing data after the stream";
      end if;
   exception
      when Data_Error =>
         --  Past the end of the input the decoder reads zeros, so a
         --  stream cut short can fail on whatever those decode to.
         --  The cause is the cut.
         if Pad > 0 then
            raise Data_Error with "inflate: truncated stream";
         end if;
         raise;
   end Decode;

end AHT.Inflate;
