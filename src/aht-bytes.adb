with Ada.Unchecked_Deallocation;
with Interfaces; use Interfaces;

package body AHT.Bytes is

   procedure Free is
     new Ada.Unchecked_Deallocation (Byte_Array, Byte_Array_Access);

   --  To_String / To_Buffer (String) reinterpret bytes through a
   --  Byte_Array view overlaid on String storage. That block move is
   --  only sound while Character and Octet are both 8-bit; enforce it
   --  at compile time so an exotic target fails to build instead of
   --  silently corrupting text.
   pragma Compile_Time_Error
     (Standard.Character'Size /= 8 or else Octet'Size /= 8,
      "AHT.Bytes String<->byte overlay requires 8-bit Character and Octet");

   Initial_Capacity : constant := 64;

   function Cap (Self : Buffer) return Natural is
     (if Self.Data = null then 0 else Self.Data'Length);

   --  Grow Data so it can hold at least Needed bytes, preserving the
   --  live bytes. Capacity doubling; no-op when already big enough.
   procedure Ensure_Capacity (Self : in out Buffer; Needed : Natural) is
   begin
      if Needed <= Cap (Self) then
         return;
      end if;

      declare
         New_Cap : Natural :=
           (if Cap (Self) = 0 then Initial_Capacity else Cap (Self));
      begin
         while New_Cap < Needed loop
            New_Cap := New_Cap * 2;
         end loop;

         declare
            Fresh : constant Byte_Array_Access :=
              new Byte_Array (1 .. New_Cap);
         begin
            if Self.Len > 0 then
               Fresh (1 .. Self.Len) := Self.Data (1 .. Self.Len);
            end if;
            Free (Self.Data);
            Self.Data := Fresh;
         end;
      end;
   end Ensure_Capacity;

   overriding procedure Adjust (Self : in out Buffer) is
      Source : constant Byte_Array_Access := Self.Data;
      N      : constant Natural           := Self.Len;
   begin
      --  After the raw record copy, Self.Data still aliases the source's
      --  array. Detach up front: if the allocation below raises (e.g.
      --  Storage_Error on a huge body) Self is left empty, so its later
      --  Finalize frees nothing rather than double-freeing the array the
      --  source still owns.
      Self.Data := null;
      Self.Len  := 0;
      if Source /= null and then N > 0 then
         Self.Data := new Byte_Array (1 .. N);
         Self.Data (1 .. N) := Source (1 .. N);
         Self.Len := N;
      end if;
   end Adjust;

   overriding procedure Finalize (Self : in out Buffer) is
   begin
      Free (Self.Data);  --  no-op when already null; idempotent
      Self.Len := 0;
   end Finalize;

   function Length      (Self : Buffer) return Natural  is (Self.Len);
   function Is_Empty    (Self : Buffer) return Boolean  is (Self.Len = 0);
   function First_Index (Self : Buffer) return Positive is (1);
   function Last_Index  (Self : Buffer) return Natural  is (Self.Len);

   --  Mirrors the Pre at runtime: the release profile drops -gnata so the
   --  contract is inert there, and Data is sized to capacity (>= Len), so
   --  an unchecked Index in Len + 1 .. capacity would read a stale byte
   --  instead of failing. Raising Constraint_Error keeps the fail-on-
   --  out-of-range guarantee live in release too.
   function Element (Self : Buffer; Index : Positive) return Octet is
   begin
      if Index > Self.Len then
         raise Constraint_Error
           with "AHT.Bytes.Buffer.Element: index" & Index'Image
              & " past length" & Self.Len'Image;
      end if;
      return Self.Data (Index);
   end Element;

   --  Release-mode mirror of the Low .. High readers' Pre. Same reason as
   --  Element: the contracts are inert without -gnata and Data spans
   --  capacity, so a High in Len + 1 .. capacity would silently read
   --  stale bytes. Check only on the actual-read path (High >= Low, i.e.
   --  a non-empty span) so the documented empty-slice forms (High < Low,
   --  incl. the Low = Len + 1 boundary) keep returning empty.
   procedure Validate_Span (Self : Buffer; Low : Positive; High : Natural) is
   begin
      if High >= Low and then High > Self.Len then
         raise Constraint_Error
           with "AHT.Bytes.Buffer: slice" & Low'Image & " .." & High'Image
              & " out of range (length" & Self.Len'Image & ")";
      end if;
   end Validate_Span;

   function To_Array (Self : Buffer) return Byte_Array is
   begin
      return Result : Byte_Array (1 .. Self.Len) do
         if Self.Len > 0 then
            Result := Self.Data (1 .. Self.Len);
         end if;
      end return;
   end To_Array;

   --  Byte_Array and String share an 8-bit representation, so a String
   --  result is filled by a single block move through a Byte_Array view
   --  overlaid on its storage — no per-character loop.
   function To_String (Self : Buffer) return String is
   begin
      return Result : String (1 .. Self.Len) do
         if Self.Len > 0 then
            declare
               View : Byte_Array (1 .. Self.Len)
                 with Import, Address => Result'Address;
            begin
               View := Self.Data (1 .. Self.Len);
            end;
         end if;
      end return;
   end To_String;

   function To_Array
     (Self : Buffer; Low : Positive; High : Natural) return Byte_Array
   is
      Span : constant Natural := (if High < Low then 0 else High - Low + 1);
   begin
      Validate_Span (Self, Low, High);
      return Result : Byte_Array (1 .. Span) do
         if Span > 0 then
            Result := Self.Data (Low .. High);
         end if;
      end return;
   end To_Array;

   function To_String
     (Self : Buffer; Low : Positive; High : Natural) return String
   is
      Span : constant Natural := (if High < Low then 0 else High - Low + 1);
   begin
      Validate_Span (Self, Low, High);
      return Result : String (1 .. Span) do
         if Span > 0 then
            declare
               View : Byte_Array (1 .. Span)
                 with Import, Address => Result'Address;
            begin
               View := Self.Data (Low .. High);
            end;
         end if;
      end return;
   end To_String;

   function Slice
     (Self : Buffer; Low : Positive; High : Natural) return Buffer
   is
      Span : constant Natural := (if High < Low then 0 else High - Low + 1);
   begin
      Validate_Span (Self, Low, High);
      return Result : Buffer do
         if Span > 0 then
            Ensure_Capacity (Result, Span);
            Result.Data (1 .. Span) := Self.Data (Low .. High);
            Result.Len := Span;
         end if;
      end return;
   end Slice;

   function To_Buffer (Data : Byte_Array) return Buffer is
   begin
      return Result : Buffer do
         if Data'Length > 0 then
            Ensure_Capacity (Result, Data'Length);
            Result.Data (1 .. Data'Length) := Data;
            Result.Len := Data'Length;
         end if;
      end return;
   end To_Buffer;

   function To_Buffer (S : String) return Buffer is
   begin
      return Result : Buffer do
         if S'Length > 0 then
            Ensure_Capacity (Result, S'Length);
            declare
               View : Byte_Array (1 .. S'Length)
                 with Import, Address => S'Address;
            begin
               Result.Data (1 .. S'Length) := View;
            end;
            Result.Len := S'Length;
         end if;
      end return;
   end To_Buffer;

   procedure Clear (Self : in out Buffer) is
   begin
      Self.Len := 0;  --  keep capacity for reuse
   end Clear;

   procedure Reserve (Self : in out Buffer; Capacity : Natural) is
   begin
      Ensure_Capacity (Self, Capacity);
   end Reserve;

   procedure Append (Self : in out Buffer; Data : Byte_Array) is
   begin
      if Data'Length = 0 then
         return;
      end if;
      Ensure_Capacity (Self, Self.Len + Data'Length);
      Self.Data (Self.Len + 1 .. Self.Len + Data'Length) := Data;
      Self.Len := Self.Len + Data'Length;
   end Append;

   procedure Append (Self : in out Buffer; Datum : Octet) is
   begin
      Ensure_Capacity (Self, Self.Len + 1);
      Self.Data (Self.Len + 1) := Datum;
      Self.Len := Self.Len + 1;
   end Append;

   procedure Append (Self : in out Buffer; Other : Buffer) is
      N : constant Natural := Other.Len;
   begin
      if N > 0 then
         --  Grow first, then one block move. Sound even for Self.Append
         --  (Self): Ensure_Capacity reallocs before the copy, and the
         --  source (1 .. N) and destination (Len + 1 .. Len + N) ranges
         --  never overlap.
         Ensure_Capacity (Self, Self.Len + N);
         Self.Data (Self.Len + 1 .. Self.Len + N) := Other.Data (1 .. N);
         Self.Len := Self.Len + N;
      end if;
   end Append;

   procedure Set (Self : in out Buffer; Data : Byte_Array) is
   begin
      Self.Len := 0;
      Append (Self, Data);
   end Set;

   --  In-place String fill: reuse/grow Self's own array and block-move
   --  the String straight in through a Byte_Array overlay. No temporary
   --  Buffer, no Adjust — one allocation/copy, not the two that
   --  `Self := To_Buffer (S)` would incur.
   procedure Set (Self : in out Buffer; S : String) is
   begin
      Self.Len := 0;
      if S'Length > 0 then
         Ensure_Capacity (Self, S'Length);
         declare
            View : Byte_Array (1 .. S'Length)
              with Import, Address => S'Address;
         begin
            Self.Data (1 .. S'Length) := View;
         end;
         Self.Len := S'Length;
      end if;
   end Set;

   procedure Query
     (Self : Buffer; Process : not null access procedure (Data : Byte_Array))
   is
   begin
      if Self.Len = 0 then
         declare
            Empty : Byte_Array (1 .. 0);
         begin
            Process (Empty);
         end;
      else
         Process (Self.Data (1 .. Self.Len));
      end if;
   end Query;

   --  Extended returns so a large result is built in the caller's
   --  heap-backed secondary-stack return slot, not as a dynamically-sized
   --  primary-stack local that overflows the thread stack on multi-MB
   --  payloads (RFC 6455 §9).
   function From_String (S : String) return Byte_Array is
   begin
      return Result : Byte_Array (1 .. S'Length) do
         for I in S'Range loop
            Result (Result'First + (I - S'First)) := Character'Pos (S (I));
         end loop;
      end return;
   end From_String;

   function To_String (B : Byte_Array) return String is
   begin
      return Result : String (1 .. B'Length) do
         for I in B'Range loop
            Result (Result'First + (I - B'First)) := Character'Val (B (I));
         end loop;
      end return;
   end To_String;

   function Base64_Encode (B : Byte_Array) return String is
      Alphabet : constant String :=
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        & "0123456789+/";
      Pad      : constant Character := '=';

      Length_In   : constant Natural := B'Length;
      Full_Groups : constant Natural := Length_In / 3;
      Remainder   : constant Natural := Length_In mod 3;
      Output_Len  : constant Natural := 4 * ((Length_In + 2) / 3);

      Result : String (1 .. Output_Len);

      --  Take the bottom 6 bits of V (after the requested shift) and
      --  yield the corresponding alphabet character. Folded into a
      --  helper because the same 6-bit-window pick happens up to four
      --  times per group with different shifts.
      function Sextet (V : Unsigned_32; Shift : Natural)
         return Character is
        (Alphabet
           (Natural (Shift_Right (V, Shift) and 16#3F#) + 1));
   begin
      if Length_In = 0 then
         return "";
      end if;

      --  Three input bytes -> 24 bits -> four 6-bit alphabet chars.
      for G in 0 .. Full_Groups - 1 loop
         declare
            A : constant Unsigned_32 :=
              Unsigned_32 (B (B'First + 3 * G));
            C : constant Unsigned_32 :=
              Unsigned_32 (B (B'First + 3 * G + 1));
            D : constant Unsigned_32 :=
              Unsigned_32 (B (B'First + 3 * G + 2));
            V : constant Unsigned_32 :=
              Shift_Left (A, 16) or Shift_Left (C, 8) or D;
         begin
            Result (1 + 4 * G)     := Sextet (V, 18);
            Result (1 + 4 * G + 1) := Sextet (V, 12);
            Result (1 + 4 * G + 2) := Sextet (V,  6);
            Result (1 + 4 * G + 3) := Sextet (V,  0);
         end;
      end loop;

      --  Trailing 1- or 2-byte tail gets padded with '=' so the
      --  output length is always a multiple of 4.
      if Remainder = 1 then
         declare
            A : constant Unsigned_32 :=
              Unsigned_32 (B (B'First + 3 * Full_Groups));
            V : constant Unsigned_32 := Shift_Left (A, 16);
            Off : constant Positive := 1 + 4 * Full_Groups;
         begin
            Result (Off)     := Sextet (V, 18);
            Result (Off + 1) := Sextet (V, 12);
            Result (Off + 2) := Pad;
            Result (Off + 3) := Pad;
         end;
      elsif Remainder = 2 then
         declare
            A : constant Unsigned_32 :=
              Unsigned_32 (B (B'First + 3 * Full_Groups));
            C : constant Unsigned_32 :=
              Unsigned_32 (B (B'First + 3 * Full_Groups + 1));
            V : constant Unsigned_32 :=
              Shift_Left (A, 16) or Shift_Left (C, 8);
            Off : constant Positive := 1 + 4 * Full_Groups;
         begin
            Result (Off)     := Sextet (V, 18);
            Result (Off + 1) := Sextet (V, 12);
            Result (Off + 2) := Sextet (V,  6);
            Result (Off + 3) := Pad;
         end;
      end if;

      return Result;
   end Base64_Encode;

end AHT.Bytes;
