package body AHT.Openssl.Err is

   use type Interfaces.C.unsigned_long;

   function Drain return String is

      function Render_One (E : Interfaces.C.unsigned_long) return String is
         use type Interfaces.C.char;
         use type Interfaces.C.size_t;
         Buf  : Interfaces.C.char_array (0 .. 255) :=
           [others => Interfaces.C.NUL];
         Last : Interfaces.C.size_t := Buf'First;
      begin
         Error_String_N (E, Buf'Address, Buf'Length);
         while Last <= Buf'Last
           and then Buf (Last) /= Interfaces.C.NUL
         loop
            Last := Last + 1;
         end loop;
         if Last = Buf'First then
            return "";
         end if;
         return Interfaces.C.To_Ada
           (Buf (Buf'First .. Last - 1), Trim_Nul => False);
      end Render_One;

      E : constant Interfaces.C.unsigned_long := Get_Error;
   begin
      if E = 0 then
         return "";
      end if;
      declare
         Rest : constant String := Drain;
      begin
         if Rest = "" then
            return Render_One (E);
         end if;
         return Render_One (E) & "; " & Rest;
      end;
   end Drain;

end AHT.Openssl.Err;
