--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Strings.Fixed;

package body AHT.PEM is

   Begin_Line : constant String := "-----BEGIN CERTIFICATE-----";
   End_Line   : constant String := "-----END CERTIFICATE-----";

   function Is_Space (C : Character) return Boolean is
     (C = ' ' or else C = ASCII.HT or else C = ASCII.LF
      or else C = ASCII.CR or else C = ASCII.FF or else C = ASCII.VT);

   ---------------------
   -- Bundle_Problem --
   ---------------------

   function Bundle_Problem (Data : String) return String is
      --  Scanned by offset from Data'First, never by absolute index:
      --  "one past the last character" as an absolute position is
      --  Data'Last + 1, which overflows when the bounds sit near
      --  Positive'Last. An offset in 0 .. Len has no such edge.
      Len    : constant Natural := Data'Length;
      O      : Natural := 0;
      Blocks : Natural := 0;

      --  The bound is M'Length <= Len - O: the sum O + M'Length can
      --  overflow while the comparison is false. Not covered by a
      --  test (needs Len near Integer'Last); the other two overflow
      --  guards in this function are. The slice endpoint brackets
      --  (O + M'Length - 1) so Data'Last + 1 is never formed on the
      --  way to Data'Last.
      function At_Marker (M : String) return Boolean is
        (M'Length <= Len - O
         and then Data (Data'First + O
                        .. Data'First + (O + M'Length - 1))
                  = M);

   begin
      loop
         --  Whitespace between blocks is fine and is the only thing
         --  that is.
         while O < Len and then Is_Space (Data (Data'First + O)) loop
            O := O + 1;
         end loop;

         exit when O = Len;

         if not At_Marker (Begin_Line) then
            return
              (if Blocks = 0
               then "the data does not begin with " & Begin_Line
               else "unexpected data after certificate"
                    & Natural'Image (Blocks)
                    & "; only whitespace may separate certificate "
                    & "blocks");
         end if;

         O := O + Begin_Line'Length;

         --  Nothing follows the marker. Checked before the slice
         --  below, because with O = Len the start expression
         --  Data'First + O is itself Data'Last + 1 and overflows,
         --  the same hazard as the endpoint above.
         if O = Len then
            return "certificate" & Natural'Image (Blocks + 1)
              & " has no " & End_Line
              & "; it is truncated or corrupt";
         end if;

         --  The matching END, searched for from here so a stray END
         --  before the next BEGIN cannot be claimed by the wrong block.
         declare
            Tail  : String renames Data (Data'First + O .. Data'Last);
            E_Abs : constant Natural :=
              Ada.Strings.Fixed.Index (Tail, End_Line);
         begin
            if E_Abs = 0 then
               return "certificate" & Natural'Image (Blocks + 1)
                 & " has no " & End_Line
                 & "; it is truncated or corrupt";
            end if;

            --  A BEGIN inside the block means the previous one was
            --  never closed.
            if Ada.Strings.Fixed.Index
                 (Tail (Tail'First .. E_Abs), Begin_Line) /= 0
            then
               return "certificate" & Natural'Image (Blocks + 1)
                 & " contains a nested " & Begin_Line
                 & "; a block was left unclosed";
            end if;

            --  Back to an offset, still without forming an absolute
            --  one-past index.
            O := (E_Abs - Data'First) + End_Line'Length;
         end;

         Blocks := Blocks + 1;
      end loop;

      if Blocks = 0 then
         return "no certificate found";
      end if;

      return "";
   end Bundle_Problem;

end AHT.PEM;
