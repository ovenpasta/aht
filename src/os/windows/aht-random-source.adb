--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Interfaces.C;
with System;

--  Windows: RtlGenRandom, exported by advapi32 as SystemFunction036.
--  One call fills the whole buffer or fails; no descriptor, no fork
--  state, no short read. bcrypt.dll is not used: it does not exist
--  before Vista and importing it makes the image unloadable on XP,
--  and every binary reaches this unit (frame masking draws here).
package body AHT.Random.Source is

   --  Named even though GNAT's mingw link spec already has advapi32.
   pragma Linker_Options ("-ladvapi32");

   use type Interfaces.C.unsigned_char;

   --  Stdcall: the Win32 convention; on 32-bit Windows a C import
   --  would corrupt the stack, and the export is decorated
   --  _SystemFunction036@8, which Stdcall produces. BOOLEAN is
   --  unsigned char: on x86 a byte return arrives in AL with the
   --  upper bits of EAX undefined, so a wider declaration could
   --  misread a failing call as success. Only a failing call is
   --  affected, and no probe can make this API fail. ULONG is 32
   --  bits on both 32- and 64-bit Windows.
   function RtlGenRandom
     (RandomBuffer       : System.Address;
      RandomBufferLength : Interfaces.C.unsigned_long)
      return Interfaces.C.unsigned_char
     with Import, Convention => Stdcall,
          External_Name => "SystemFunction036";

   ---------
   -- Get --
   ---------

   procedure Get (B : out AHT.Bytes.Byte_Array) is
      OK : Interfaces.C.unsigned_char;
   begin
      --  Fills the whole buffer or fails: unlike read(2) there is no
      --  short-result case to loop over.
      OK :=
        RtlGenRandom
          (RandomBuffer       => B (B'First)'Address,
           RandomBufferLength => Interfaces.C.unsigned_long (B'Length));

      --  Non-zero is TRUE. The API reports failure and nothing else.
      if OK = 0 then
         raise Entropy_Error
           with "AHT.Random: RtlGenRandom (SystemFunction036) returned"
             & " FALSE; refusing to fall back to a predictable source";
      end if;
   end Get;

end AHT.Random.Source;
