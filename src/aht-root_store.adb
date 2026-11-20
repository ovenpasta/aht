--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Containers.Indefinite_Vectors;
with Ada.Directories;
with Ada.Environment_Variables;
with Ada.IO_Exceptions;
with Ada.Streams.Stream_IO;
with Ada.Strings.Fixed;
with Ada.Unchecked_Deallocation;

with GNAT.OS_Lib;

with AHT.Root_Store.Platform;

package body AHT.Root_Store is

   use type Ada.Directories.File_Kind;
   use type Ada.Directories.File_Size;

   Begin_Line : constant String := "-----BEGIN CERTIFICATE-----";
   End_Line   : constant String := "-----END CERTIFICATE-----";
   Line_Width : constant := 64;

   function Is_Space (Ch : Character) return Boolean is
     (Ch = ' ' or else Ch = ASCII.HT or else Ch = ASCII.LF
      or else Ch = ASCII.CR or else Ch = ASCII.FF or else Ch = ASCII.VT);

   function Is_Base64 (Ch : Character) return Boolean is
     (Ch in 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '+' | '/');

   type String_Access is access String;
   procedure Free is new Ada.Unchecked_Deallocation (String, String_Access);

   --  Raw with whitespace removed, written to Into (1 .. N); N = 0 when
   --  what remains is not base64: a character outside the alphabet,
   --  padding other than one or two trailing '=', or a length not a
   --  multiple of four. Into is at least Raw'Length long.
   procedure Canonical_Body
     (Raw : String; Into : in out String; N : out Natural)
   is
      Pad : Natural := 0;
   begin
      N := 0;
      for Ch of Raw loop
         if Is_Space (Ch) then
            null;
         elsif Ch = '=' then
            Pad := Pad + 1;
            if Pad > 2 then
               N := 0;
               return;
            end if;
            N := N + 1;
            Into (Into'First + N - 1) := Ch;
         elsif Pad = 0 and then Is_Base64 (Ch) then
            N := N + 1;
            Into (Into'First + N - 1) := Ch;
         else
            N := 0;
            return;
         end if;
      end loop;

      if N mod 4 /= 0 then
         N := 0;
      end if;
   end Canonical_Body;

   --  Appends one block for B64 unless it is a duplicate. Reaching
   --  Max_Certificates with a further distinct certificate sets
   --  Truncated. The block is built before anything in C changes, and
   --  a failure to append it takes B64 back out of Seen, so C never
   --  holds half a certificate.
   procedure Take (C : in out Collector; B64 : String; Added : out Natural)
   is
      Block : SU.Unbounded_String;
      First : Positive := B64'First;
      Last  : Positive;
   begin
      Added := 0;
      if Full (C) or else C.Seen.Contains (B64) then
         return;
      end if;
      if C.Result.Count = Max_Certificates then
         C.Result.Truncated := True;
         return;
      end if;

      SU.Append (Block, Begin_Line & ASCII.LF);
      loop
         Last := (if B64'Last - First < Line_Width
                  then B64'Last
                  else First + (Line_Width - 1));
         SU.Append (Block, B64 (First .. Last) & ASCII.LF);
         exit when Last = B64'Last;
         First := Last + 1;
      end loop;
      SU.Append (Block, End_Line & ASCII.LF);

      C.Seen.Insert (B64);
      begin
         SU.Append (C.Result.PEM, Block);
      exception
         when others =>
            C.Seen.Exclude (B64);
            raise;
      end;

      C.Result.Count := C.Result.Count + 1;
      Added := 1;
   end Take;

   ------------------
   -- Add_PEM_Text --
   ------------------

   --  One pass. Each BEGIN is found once, and the END of its block is
   --  searched for only up to the next BEGIN, so every character is
   --  examined a bounded number of times. A block with no END before
   --  the next BEGIN was never closed and is skipped, as is one whose
   --  body exceeds Max_Block_Bytes.
   procedure Add_PEM_Text
     (C : in out Collector; Text : String; Added : out Natural)
   is
      --  Offsets from Text'First, so no index one past Text'Last is
      --  formed; the same discipline as AHT.PEM.
      Len     : constant Natural := Text'Length;
      Next_B  : Natural := Ada.Strings.Fixed.Index (Text, Begin_Line);
      Scratch : String_Access;
      N       : Natural;
      One     : Natural;
   begin
      Added := 0;
      if Next_B = 0 then
         return;
      end if;
      --  On the heap: no local is sized by the input.
      Scratch := new String (1 .. Max_Block_Bytes);

      while Next_B /= 0 and then not Full (C) loop
         declare
            --  Offset of the body, just past this BEGIN.
            S : constant Natural :=
              (Next_B - Text'First) + Begin_Line'Length;
         begin
            exit when S >= Len;

            Next_B := Ada.Strings.Fixed.Index
              (Text (Text'First + S .. Text'Last), Begin_Line);

            declare
               --  Offset one past the last character this block may
               --  use: the next BEGIN, or the end of Text.
               Stop : constant Natural :=
                 (if Next_B = 0 then Len else Next_B - Text'First);
               E    : constant Natural :=
                 Ada.Strings.Fixed.Index
                   (Text (Text'First + S .. Text'First + (Stop - 1)),
                    End_Line);
            begin
               if E /= 0
                 and then E - (Text'First + S) <= Max_Block_Bytes
               then
                  Canonical_Body
                    (Text (Text'First + S .. E - 1), Scratch.all, N);
                  if N > 0 then
                     Take (C, Scratch (1 .. N), One);
                     Added := Added + One;
                  end if;
               end if;
            end;
         end;
      end loop;

      Free (Scratch);
   exception
      when others =>
         Free (Scratch);
         raise;
   end Add_PEM_Text;

   -------------
   -- Add_DER --
   -------------

   procedure Add_DER
     (C     : in out Collector;
      DER   : AHT.Bytes.Byte_Array;
      Added : out Natural) is
   begin
      Added := 0;
      if Full (C) or else DER'Length = 0 then
         return;
      end if;
      if DER'Length > Max_Bytes - C.Bytes_Read then
         C.Result.Truncated := True;
         return;
      end if;
      C.Bytes_Read := C.Bytes_Read + DER'Length;
      Take (C, AHT.Bytes.Base64_Encode (DER), Added);
   end Add_DER;

   procedure Close_Quietly (F : in out Ada.Streams.Stream_IO.File_Type) is
   begin
      if Ada.Streams.Stream_IO.Is_Open (F) then
         Ada.Streams.Stream_IO.Close (F);
      end if;
   exception
      when others =>
         null;
   end Close_Quietly;

   --------------
   -- Add_File --
   --------------

   procedure Add_File
     (C : in out Collector; Path : String; Added : out Natural)
   is
      use Ada.Streams;

      Size : Ada.Directories.File_Size;
      Buf  : String_Access;
      F    : Stream_IO.File_Type;
   begin
      Added := 0;
      if Full (C) then
         return;
      end if;

      --  Kind follows symbolic links. Anything but a regular file (a
      --  directory, a FIFO that would block the open) is skipped.
      if not Ada.Directories.Exists (Path)
        or else Ada.Directories.Kind (Path) /= Ada.Directories.Ordinary_File
      then
         return;
      end if;

      if C.Entries = Max_Entries then
         C.Result.Truncated := True;
         return;
      end if;
      C.Entries := C.Entries + 1;

      Size := Ada.Directories.Size (Path);
      if Size = 0 then
         return;
      end if;
      if Size > Ada.Directories.File_Size (Max_Bytes - C.Bytes_Read) then
         C.Result.Truncated := True;
         return;
      end if;

      --  On the heap: Max_Bytes would not fit a task's stack.
      Buf := new String (1 .. Natural (Size));
      declare
         Data : Stream_Element_Array (1 .. Stream_Element_Offset (Size))
           with Import, Address => Buf.all'Address;
         Last : Stream_Element_Offset;
      begin
         Stream_IO.Open (F, Stream_IO.In_File, Path);
         Stream_IO.Read (F, Data, Last);
         Stream_IO.Close (F);
         C.Bytes_Read := C.Bytes_Read + Natural (Last);
         Add_PEM_Text (C, Buf (1 .. Natural (Last)), Added);
      end;
      Free (Buf);
   exception
      --  Unreadable: removed, permission denied, an I/O error. The
      --  source is skipped, per the contract of Load.
      when Ada.IO_Exceptions.Name_Error
         | Ada.IO_Exceptions.Use_Error
         | Ada.IO_Exceptions.Device_Error
         | Ada.IO_Exceptions.End_Error =>
         Close_Quietly (F);
         Free (Buf);
      --  Anything else (Storage_Error) stops the read: what was taken
      --  so far is whole, but the store was not read to the end.
      when others =>
         Close_Quietly (F);
         Free (Buf);
         C.Result.Truncated := True;
   end Add_File;

   -------------------
   -- Add_Directory --
   -------------------

   procedure Add_Directory
     (C : in out Collector; Dir : String; Added : out Natural)
   is
      use Ada.Directories;

      package Name_Vectors is new Ada.Containers.Indefinite_Vectors
        (Positive, String);
      package Name_Sorting is new Name_Vectors.Generic_Sorting;

      Names : Name_Vectors.Vector;
      S     : Search_Type;
      E     : Directory_Entry_Type;
      One   : Natural;
   begin
      Added := 0;
      if Full (C)
        or else not Exists (Dir)
        or else Kind (Dir) /= Directory
      then
         return;
      end if;

      --  The listing is bounded too: one name past Max_Entries is
      --  enough for Add_File to report the limit.
      Start_Search
        (S, Dir, "",
         [Ordinary_File => True, Directory => False, Special_File => False]);
      while More_Entries (S)
        and then Natural (Names.Length) <= Max_Entries
      loop
         Get_Next_Entry (S, E);
         Names.Append (Full_Name (E));
      end loop;
      End_Search (S);

      Name_Sorting.Sort (Names);
      for Name of Names loop
         exit when Full (C);
         Add_File (C, Name, One);
         Added := Added + One;
      end loop;
   exception
      when Ada.IO_Exceptions.Name_Error | Ada.IO_Exceptions.Use_Error =>
         null;
      --  As in Add_File: the read stops, incomplete.
      when others =>
         C.Result.Truncated := True;
   end Add_Directory;

   -----------------
   -- Admit_Entry --
   -----------------

   function Admit_Entry (C : in out Collector) return Boolean is
   begin
      if Full (C) then
         return False;
      end if;
      if C.Entries = Max_Entries then
         C.Result.Truncated := True;
         return False;
      end if;
      C.Entries := C.Entries + 1;
      return True;
   end Admit_Entry;

   -------------------
   -- Note_Location --
   -------------------

   procedure Note_Location (C : in out Collector; Where : String) is
   begin
      if SU.Length (C.Result.Location) > 0 then
         SU.Append (C.Result.Location, GNAT.OS_Lib.Path_Separator);
      end if;
      SU.Append (C.Result.Location, Where);
   end Note_Location;

   ----------
   -- Load --
   ----------

   function Load return Roots is

      function Env (Name : String) return String is
        (if Ada.Environment_Variables.Exists (Name)
         then Ada.Environment_Variables.Value (Name)
         else "");

      File_Var : constant String := Env ("SSL_CERT_FILE");
      Dir_Var  : constant String := Env ("SSL_CERT_DIR");

      C   : Collector;
      One : Natural;
   begin
      if File_Var /= "" or else Dir_Var /= "" then
         if File_Var /= "" then
            Add_File (C, File_Var, One);
            if One > 0 then
               Note_Location (C, File_Var);
            end if;
         end if;

         --  Each element of the list; empty elements are ignored.
         declare
            First : Positive := Dir_Var'First;
            Sep   : Natural;
         begin
            while First <= Dir_Var'Last loop
               Sep := Ada.Strings.Fixed.Index
                 (Dir_Var (First .. Dir_Var'Last),
                  [1 => GNAT.OS_Lib.Path_Separator]);
               declare
                  Last : constant Natural :=
                    (if Sep = 0 then Dir_Var'Last else Sep - 1);
               begin
                  if Last >= First then
                     Add_Directory (C, Dir_Var (First .. Last), One);
                     if One > 0 then
                        Note_Location (C, Dir_Var (First .. Last));
                     end if;
                  end if;
               end;
               exit when Sep = 0;
               First := Sep + 1;
            end loop;
         end;

         if C.Result.Count > 0 then
            C.Result.Origin := Environment;
         end if;
      else
         AHT.Root_Store.Platform.Collect_Default (C);
      end if;

      if C.Result.Count = 0 then
         C.Result.Origin   := None;
         C.Result.Location := SU.Null_Unbounded_String;
      end if;
      return C.Result;
   exception
      --  A failure outside any one source (Storage_Error copying the
      --  result, say): nothing is returned, and Truncated says the read
      --  did not finish.
      when others =>
         return Failed : Roots do
            Failed.Truncated := True;
         end return;
   end Load;

end AHT.Root_Store;
