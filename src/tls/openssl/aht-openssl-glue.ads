with Interfaces.C;
with System;

--  Ada view of the C glue in csrc/openssl/aht_openssl_glue.c: the few
--  OpenSSL entry points that are macros over *_ctrl calls, wrapped in
--  real C functions so their ctrl numbers come from the installed
--  headers rather than a curated constant.
package AHT.Openssl.Glue is

   function Set_TLSext_Host_Name
     (S    : System.Address;
      Name : System.Address) return Interfaces.C.long
     with Import, Convention => C,
          External_Name => "aht_openssl_set_tlsext_host_name";
   --  SNI for DNS-name hosts. 1 on success.

   function CTX_Set_Min_Proto_Version
     (Ctx     : System.Address;
      Version : Interfaces.C.int) return Interfaces.C.long
     with Import, Convention => C,
          External_Name => "aht_openssl_ctx_set_min_proto_version";
   --  1 on success. Pass AHT.Openssl.SSL.TLS_1_2_VERSION.

   function Set_Mem_EOF_Return
     (B : System.Address;
      V : Interfaces.C.long) return Interfaces.C.long
     with Import, Convention => C,
          External_Name => "aht_openssl_set_mem_eof_return";
   --  V = -1: empty reads are retryable (WANT_READ); V = 0: EOF.

end AHT.Openssl.Glue;
