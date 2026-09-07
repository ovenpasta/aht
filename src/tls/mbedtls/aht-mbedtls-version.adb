--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Interfaces.C;
with System;

package body AHT.Mbedtls.Version is

   --  C signatures: `void mbedtls_version_get_string(char *)` and
   --  `void mbedtls_version_get_string_full(char *)`. The generator
   --  emits `Interfaces.C.Strings.chars_ptr` for the buffer; we
   --  curate to System.Address so we can pass a stack-allocated
   --  char_array via 'Address without heap allocating a chars_ptr.

   procedure C_Get_String (Buf : System.Address)
     with Import,
          Convention    => C,
          External_Name => "mbedtls_version_get_string";

   procedure C_Get_String_Full (Buf : System.Address)
     with Import,
          Convention    => C,
          External_Name => "mbedtls_version_get_string_full";

   --  Strip the trailing NUL the C side writes and return the
   --  payload as an Ada String. Buf is sized by the caller; we
   --  find the first NUL within Buf's range.
   function Read_C_String
     (Buf : Interfaces.C.char_array) return String
   is
      use type Interfaces.C.char;
      use type Interfaces.C.size_t;
      Last : Interfaces.C.size_t := Buf'First;
   begin
      while Last <= Buf'Last and then Buf (Last) /= Interfaces.C.NUL loop
         Last := Last + 1;
      end loop;
      if Last = Buf'First then
         return "";
      end if;
      return Interfaces.C.To_Ada
        (Buf (Buf'First .. Last - 1), Trim_Nul => False);
   end Read_C_String;

   function Version_String return String is
      --  mbedTLS documents "should be at least 9 bytes" for the
      --  short form. 16 leaves slack without being wasteful.
      Buf : Interfaces.C.char_array (0 .. 15) :=
        [others => Interfaces.C.NUL];
   begin
      C_Get_String (Buf'Address);
      return Read_C_String (Buf);
   end Version_String;

   function Full_Version_String return String is
      --  mbedTLS documents "at most 18 bytes including the
      --  terminating NUL". 32 leaves slack.
      Buf : Interfaces.C.char_array (0 .. 31) :=
        [others => Interfaces.C.NUL];
   begin
      C_Get_String_Full (Buf'Address);
      return Read_C_String (Buf);
   end Full_Version_String;

end AHT.Mbedtls.Version;
