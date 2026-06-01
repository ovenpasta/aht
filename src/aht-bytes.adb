with Interfaces; use Interfaces;

package body AHT.Bytes is

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
