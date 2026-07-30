with Interfaces.C;
with System;

--  Ada view of the C glue in csrc/aht_mbedtls_glue.c. Each mbedTLS
--  context is an opaque System.Address whose storage is malloc'd (and
--  sized) on the C side, so no struct layout is modelled in Ada. See
--  csrc/aht_mbedtls_glue.c for why the sizing must happen in C.
package AHT.Mbedtls.Glue is

   --  Allocate + init / free + deallocate one context of each kind.
   --  *_New returns System.Null_Address on allocation failure.

   function SSL_New return System.Address
     with Import, Convention => C, External_Name => "aht_mbedtls_ssl_new";
   procedure SSL_Free (Ctx : System.Address)
     with Import, Convention => C, External_Name => "aht_mbedtls_ssl_free";

   function Config_New return System.Address
     with Import, Convention => C, External_Name => "aht_mbedtls_config_new";
   procedure Config_Free (Ctx : System.Address)
     with Import, Convention => C, External_Name => "aht_mbedtls_config_free";

   function CTR_DRBG_New return System.Address
     with Import, Convention => C,
          External_Name => "aht_mbedtls_ctr_drbg_new";
   procedure CTR_DRBG_Free (Ctx : System.Address)
     with Import, Convention => C,
          External_Name => "aht_mbedtls_ctr_drbg_free";

   function Entropy_New return System.Address
     with Import, Convention => C, External_Name => "aht_mbedtls_entropy_new";
   procedure Entropy_Free (Ctx : System.Address)
     with Import, Convention => C, External_Name => "aht_mbedtls_entropy_free";

   function X509_CRT_New return System.Address
     with Import, Convention => C,
          External_Name => "aht_mbedtls_x509_crt_new";
   procedure X509_CRT_Free (Ctx : System.Address)
     with Import, Convention => C,
          External_Name => "aht_mbedtls_x509_crt_free";

   --  Seed CTR_DRBG from the entropy source (returns an mbedTLS int,
   --  0 on success). Wraps the mbedtls_entropy_func plumbing.
   function CTR_DRBG_Seed
     (CTR_DRBG : System.Address;
      Entropy  : System.Address) return Interfaces.C.int
     with Import, Convention => C,
          External_Name => "aht_mbedtls_ctr_drbg_seed";

   --  Point the config's RNG at CTR_DRBG (mbedtls_ctr_drbg_random).
   procedure Conf_RNG
     (Conf     : System.Address;
      CTR_DRBG : System.Address)
     with Import, Convention => C, External_Name => "aht_mbedtls_conf_rng";

end AHT.Mbedtls.Glue;
