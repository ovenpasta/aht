with Interfaces.C;
with System;

--  The entropy source mbedTLS draws from.
--
--  The vendored library is configured MBEDTLS_NO_PLATFORM_ENTROPY, so
--  it has no source of its own: mbedtls_entropy_init leaves the pool
--  empty and mbedtls_ctr_drbg_seed fails unless something is
--  registered. aht_mbedtls_entropy_new registers the callback below.
--
--  Routing mbedTLS through AHT.Random rather than letting it call the
--  OS itself keeps the platform entropy decision in one place. That is
--  what makes it maintainable on Windows: entropy_poll.c's Windows
--  branch calls BCryptGenRandom, which imports bcrypt.dll and leaves
--  the image unloadable on the XP target. One source, one place to
--  keep XP-clean, one place a mistake can hide.
package AHT.Mbedtls.Entropy is

   function Poll
     (Data   : System.Address;
      Output : System.Address;
      Len    : Interfaces.C.size_t;
      Olen   : access Interfaces.C.size_t) return Interfaces.C.int
     with Export, Convention => C,
          External_Name => "aht_mbedtls_entropy_poll";
   --  An mbedtls_entropy_f_source_ptr. Fills Output with Len bytes
   --  from AHT.Random, reports Len through Olen, and returns 0;
   --  returns MBEDTLS_ERR_ENTROPY_SOURCE_FAILED on any failure.
   --
   --  Data is the context pointer registered alongside the callback.
   --  It is null here, because this source has no state -- which is
   --  also why one callback serves every session concurrently.
   --
   --  Never propagates an Ada exception. AHT.Random.Fill raises
   --  Entropy_Error when the system CSPRNG refuses, and letting that
   --  cross into C would unwind through mbedTLS frames that have no
   --  handler and own heap allocations. The return code is the only
   --  channel the caller can read.

end AHT.Mbedtls.Entropy;
