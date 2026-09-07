--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Interfaces.C;
with System;

--  The entropy source mbedTLS draws from. The vendored library is
--  built MBEDTLS_NO_PLATFORM_ENTROPY, so mbedtls_entropy_init leaves
--  the pool empty and seeding fails unless a source is registered;
--  aht_mbedtls_entropy_new registers Poll. Routing through AHT.Random
--  keeps the platform entropy decision in one place: entropy_poll.c's
--  Windows branch calls BCryptGenRandom, which imports bcrypt.dll and
--  leaves the image unloadable on XP.
package AHT.Mbedtls.Entropy is

   function Poll
     (Data   : System.Address;
      Output : System.Address;
      Len    : Interfaces.C.size_t;
      Olen   : access Interfaces.C.size_t) return Interfaces.C.int
     with Export, Convention => C,
          External_Name => "aht_mbedtls_entropy_poll";
   --  An mbedtls_entropy_f_source_ptr. Fills Output with Len bytes
   --  from AHT.Random, reports Len through Olen and returns 0; on any
   --  failure returns MBEDTLS_ERR_ENTROPY_SOURCE_FAILED with Olen = 0.
   --  Data is the registered context pointer, null here: the source
   --  has no state, so one callback serves every session. Never
   --  propagates an Ada exception; the return code is the only
   --  channel the C caller can read.

end AHT.Mbedtls.Entropy;
