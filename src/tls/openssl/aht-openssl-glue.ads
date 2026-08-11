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

   function CTX_Load_CA_PEM
     (Ctx : System.Address;
      PEM : System.Address;
      Len : Interfaces.C.int) return Interfaces.C.int
     with Import, Convention => C,
          External_Name => "aht_openssl_ctx_load_ca_pem";
   --  Load one or more concatenated PEM certificates from memory into
   --  Ctx's trust store. Returns the number added (> 0), or a negative
   --  code: -1 allocation / no store, -2 no certificate found,
   --  -3 trailing or malformed data, -4 could not add to the store.
   --
   --  All-or-nothing, which is why this is glue rather than an Ada
   --  loop over PEM_read_bio_X509: classifying "clean end of input"
   --  apart from "malformed tail" needs ERR_GET_REASON and the
   --  PEM_R_/X509_R_ reason codes, whose values and masking drift
   --  across OpenSSL releases.

end AHT.Openssl.Glue;
