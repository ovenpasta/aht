--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with AHT.Bytes;
with AHT.Random;

package body AHT.Mbedtls.Entropy is

   --  For the unary minus below, which is not directly visible on a
   --  type declared in another package.
   use type Interfaces.C.int;

   --  MBEDTLS_ERR_ENTROPY_SOURCE_FAILED from mbedtls/entropy.h. Error
   --  codes are ABI-stable, struct layouts are not.
   Source_Failed : constant Interfaces.C.int := -16#003C#;

   ----------
   -- Poll --
   ----------

   function Poll
     (Data   : System.Address;
      Output : System.Address;
      Len    : Interfaces.C.size_t;
      Olen   : access Interfaces.C.size_t) return Interfaces.C.int
   is
      pragma Unreferenced (Data);
      use type Interfaces.C.size_t;
   begin
      if Olen = null then
         return Source_Failed;
      end if;

      --  Cleared before any work, so every path that returns an error
      --  below has already reported zero bytes delivered. mbedTLS adds
      --  *olen to its pool accounting, and a stale value there would
      --  credit the pool for entropy it never received.
      Olen.all := 0;

      if Len = 0 then
         return 0;
      end if;

      declare
         --  Overlay on the caller's buffer. Byte_Array is not
         --  controlled, so nothing is finalized when this goes out of
         --  scope.
         B : AHT.Bytes.Byte_Array (1 .. Natural (Len))
           with Address => Output, Import;
      begin
         AHT.Random.Fill (B);
      end;

      Olen.all := Len;
      return 0;

   exception
      when others =>
         --  Entropy_Error is the expected one; anything else means
         --  the binding is wrong. mbedTLS has one code for "this
         --  source produced nothing". Olen stays 0, so a partially
         --  written buffer is never counted as delivered entropy.
         Olen.all := 0;
         return Source_Failed;
   end Poll;

end AHT.Mbedtls.Entropy;
