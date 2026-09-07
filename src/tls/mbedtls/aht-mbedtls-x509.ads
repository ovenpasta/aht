--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Interfaces.C;
with System;

--  Curated binding for the mbedTLS X.509 certificate-parsing calls
--  AHT.Transport.TLS uses for CA verification. The chain is an opaque
--  System.Address (allocated by AHT.Mbedtls.Glue.X509_CRT_New); Path is
--  a NUL-terminated C string. Both return an mbedTLS int (0 on success).
package AHT.Mbedtls.X509 is

   function CRT_Parse_File
     (Chain : System.Address; Path : System.Address) return Interfaces.C.int
     with Import, Convention => C,
          External_Name => "mbedtls_x509_crt_parse_file";

   function CRT_Parse_Path
     (Chain : System.Address; Path : System.Address) return Interfaces.C.int
     with Import, Convention => C,
          External_Name => "mbedtls_x509_crt_parse_path";

   function CRT_Parse
     (Chain : System.Address;
      Buf   : System.Address;
      Len   : Interfaces.C.size_t) return Interfaces.C.int
     with Import, Convention => C,
          External_Name => "mbedtls_x509_crt_parse";
   --  In-memory form. Len MUST include a terminating NUL when Buf
   --  holds PEM: mbedTLS picks PEM over DER by finding "-----BEGIN"
   --  and requires the NUL inside the counted length; the text length
   --  alone makes it try DER. Returns 0 when every certificate
   --  parsed, a positive count of failed certificates, or a negative
   --  mbedTLS error; only 0 is a clean load.

end AHT.Mbedtls.X509;
