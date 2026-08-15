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
      --  Scanned by OFFSET from Data'First, never by absolute index.
      --
      --  A String's bounds are arbitrary, and the scan needs to
      --  represent "one past the last character" -- which as an
      --  absolute position is Data'Last + 1 and overflows when the
      --  bounds sit near Positive'Last. The object can be tiny and
      --  still do this; it is the bounds, not the size, that are
      --  extreme. An offset in 0 .. Len has no such edge: Len is a
      --  length, and Data'First + O is only ever formed while
      --  O < Len, so it cannot exceed Data'Last.
      Len    : constant Natural := Data'Length;
      O      : Natural := 0;
      Blocks : Natural := 0;

      --  Both halves are written to keep every intermediate inside
      --  the type.
      --
      --  The bound is M'Length <= Len - O rather than
      --  O + M'Length <= Len: the sum can exceed Integer'Last while
      --  the comparison it feeds is false, so the check meant to
      --  prevent the overrun would itself overflow.
      --
      --  That one is defensive and is NOT covered: reaching it needs
      --  Len itself near Integer'Last, i.e. a genuinely
      --  multi-gigabyte bundle, which no test here allocates. Kept
      --  because it costs nothing and the subtraction is no harder to
      --  read. The other two below are covered, and each fails the
      --  suite on its own when backed out.
      --
      --  The slice endpoint is Data'First + (O + M'Length - 1), not
      --  Data'First + O + M'Length - 1. Ada evaluates the latter
      --  left-to-right, so it forms Data'Last + 1 on the way to
      --  Data'Last -- which overflows for a bundle ending exactly at
      --  Positive'Last. Bracketing keeps the offset arithmetic among
      --  small numbers and adds Data'First exactly once.
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
         --  Data'First + O is itself Data'Last + 1 and overflows --
         --  the same hazard as the endpoint above, reached by a
         --  different route.
         if O = Len then
            return "certificate" & Natural'Image (Blocks + 1)
              & " has no " & End_Line
              & "; it is truncated or corrupt";
         end if;

         --  The matching END, searched for from here rather than
         --  anywhere in the input, so a stray END before the next
         --  BEGIN cannot be claimed by the wrong block.
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
