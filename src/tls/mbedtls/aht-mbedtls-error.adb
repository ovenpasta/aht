with System;

package body AHT.Mbedtls.Error is

   --  C: void mbedtls_strerror(int errnum, char *buffer, size_t buflen).
   --  Buffer is curated to System.Address so we can hand it a stack
   --  char_array via 'Address (cf. AHT.Mbedtls.Version).
   procedure C_Strerror
     (Errnum : Interfaces.C.int;
      Buffer : System.Address;
      Buflen : Interfaces.C.size_t)
     with Import, Convention => C, External_Name => "mbedtls_strerror";

   function Strerror (Code : Interfaces.C.int) return String is
      use type Interfaces.C.char;
      use type Interfaces.C.size_t;
      Buf  : Interfaces.C.char_array (0 .. 159) :=
        [others => Interfaces.C.NUL];
      Last : Interfaces.C.size_t := Buf'First;
   begin
      C_Strerror (Code, Buf'Address, Buf'Length);
      while Last <= Buf'Last and then Buf (Last) /= Interfaces.C.NUL loop
         Last := Last + 1;
      end loop;
      if Last = Buf'First then
         return "";
      end if;
      return Interfaces.C.To_Ada
        (Buf (Buf'First .. Last - 1), Trim_Nul => False);
   end Strerror;

end AHT.Mbedtls.Error;
