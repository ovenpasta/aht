--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Interfaces.C;
with System;

--  Curated binding for the certificate-verification helpers the
--  OpenSSL backend uses beyond libssl's own surface.
package AHT.Openssl.X509 is

   function Verify_Param_Set1_IP_ASC
     (Param : System.Address;
      IP    : System.Address) return Interfaces.C.int
     with Import, Convention => C,
          External_Name => "X509_VERIFY_PARAM_set1_ip_asc";
   --  1 on success. Arms IP-SAN verification for an IP-literal host
   --  (dotted IPv4 or textual IPv6), on the param borrowed from
   --  AHT.Openssl.SSL.Get0_Param. The DNS counterpart is
   --  SSL.Set1_Host.

   function Verify_Cert_Error_String
     (N : Interfaces.C.long) return System.Address
     with Import, Convention => C,
          External_Name => "X509_verify_cert_error_string";
   --  Static const char* (never freed) describing an X509_V_ERR_*
   --  code from SSL.Get_Verify_Result.

end AHT.Openssl.X509;
