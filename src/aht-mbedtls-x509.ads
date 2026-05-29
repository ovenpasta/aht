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

end AHT.Mbedtls.X509;
