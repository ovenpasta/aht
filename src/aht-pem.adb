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
      P      : Natural := Data'First;
      Blocks : Natural := 0;

      function At_Marker (M : String) return Boolean is
        (P + M'Length - 1 <= Data'Last
         and then Data (P .. P + M'Length - 1) = M);

   begin
      loop
         --  Whitespace between blocks is fine and is the only thing
         --  that is.
         while P <= Data'Last and then Is_Space (Data (P)) loop
            P := P + 1;
         end loop;

         exit when P > Data'Last;

         if not At_Marker (Begin_Line) then
            return
              (if Blocks = 0
               then "the data does not begin with " & Begin_Line
               else "unexpected data after certificate"
                    & Natural'Image (Blocks)
                    & "; only whitespace may separate certificate "
                    & "blocks");
         end if;

         P := P + Begin_Line'Length;

         --  The matching END, searched for from here rather than
         --  anywhere in the input, so a stray END before the next
         --  BEGIN cannot be claimed by the wrong block.
         declare
            E : constant Natural :=
              Ada.Strings.Fixed.Index (Data (P .. Data'Last), End_Line);
         begin
            if E = 0 then
               return "certificate" & Natural'Image (Blocks + 1)
                 & " has no " & End_Line
                 & "; it is truncated or corrupt";
            end if;

            --  A BEGIN inside the block means the previous one was
            --  never closed.
            declare
               B2 : constant Natural :=
                 Ada.Strings.Fixed.Index (Data (P .. E), Begin_Line);
            begin
               if B2 /= 0 then
                  return "certificate" & Natural'Image (Blocks + 1)
                    & " contains a nested " & Begin_Line
                    & "; a block was left unclosed";
               end if;
            end;

            P := E + End_Line'Length;
         end;

         Blocks := Blocks + 1;
      end loop;

      if Blocks = 0 then
         return "no certificate found";
      end if;

      return "";
   end Bundle_Problem;

end AHT.PEM;
