with Ada.Strings.Unbounded;

package body AHT.URL.Encoding is

   subtype Hex_Digit is Character
     with Static_Predicate =>
       Hex_Digit in '0' .. '9' | 'a' .. 'f' | 'A' .. 'F';

   function Hex_Value (C : Hex_Digit) return Natural is
     (case C is
        when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
        when 'a' .. 'f' => Character'Pos (C) - Character'Pos ('a') + 10,
        when 'A' .. 'F' => Character'Pos (C) - Character'Pos ('A') + 10);

   function Hex_Digit_Of (V : Natural) return Character
     with Pre => V < 16;

   function Hex_Digit_Of (V : Natural) return Character is
     (if V < 10 then Character'Val (V + Character'Pos ('0'))
      else Character'Val (V - 10 + Character'Pos ('A')));

   --  RFC 3986 §2.3 unreserved = ASCII ALPHA / DIGIT / '-' / '.' / '_' / '~'.
   --  Deliberately NOT Ada.Characters.Handling.Is_Alphanumeric, which would
   --  let Latin-1 accented letters through and produce non-portable URLs.
   function Is_Unreserved (C : Character) return Boolean is
     (C in '0' .. '9' | 'A' .. 'Z' | 'a' .. 'z'
      or else C = '-' or else C = '.' or else C = '_' or else C = '~');

   function Percent_Encode (S : String) return String is
      use Ada.Strings.Unbounded;
      Out_S : Unbounded_String;
   begin
      for C of S loop
         if Is_Unreserved (C) then
            Append (Out_S, C);
         else
            declare
               Byte : constant Natural := Character'Pos (C);
            begin
               Append (Out_S, '%');
               Append (Out_S, Hex_Digit_Of (Byte / 16));
               Append (Out_S, Hex_Digit_Of (Byte mod 16));
            end;
         end if;
      end loop;
      return To_String (Out_S);
   end Percent_Encode;

   function Percent_Decode (S : String) return String is
      use Ada.Strings.Unbounded;
      Out_S : Unbounded_String;
      I     : Positive := S'First;
   begin
      while I <= S'Last loop
         if S (I) = '%' then
            if I + 2 > S'Last
              or else S (I + 1) not in Hex_Digit
              or else S (I + 2) not in Hex_Digit
            then
               raise Constraint_Error with "invalid percent escape";
            end if;
            Append
              (Out_S,
               Character'Val
                 (Hex_Value (S (I + 1)) * 16 + Hex_Value (S (I + 2))));
            I := I + 3;
         else
            Append (Out_S, S (I));
            I := I + 1;
         end if;
      end loop;
      return To_String (Out_S);
   end Percent_Decode;

   function Form_Encode (S : String) return String is
      use Ada.Strings.Unbounded;
      Out_S : Unbounded_String;
   begin
      for C of S loop
         if C = ' ' then
            Append (Out_S, '+');
         elsif Is_Unreserved (C) then
            Append (Out_S, C);
         else
            declare
               Byte : constant Natural := Character'Pos (C);
            begin
               Append (Out_S, '%');
               Append (Out_S, Hex_Digit_Of (Byte / 16));
               Append (Out_S, Hex_Digit_Of (Byte mod 16));
            end;
         end if;
      end loop;
      return To_String (Out_S);
   end Form_Encode;

   function Form_Decode (S : String) return String is
      Temp : String (S'Range);
   begin
      for I in S'Range loop
         Temp (I) := (if S (I) = '+' then ' ' else S (I));
      end loop;
      return Percent_Decode (Temp);
   end Form_Decode;

end AHT.URL.Encoding;
