--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Version introspection for the linked OpenSSL. The three numeric
--  functions are new in OpenSSL 3.0, so linking this unit already
--  fails against LibreSSL or OpenSSL 1.1; AHT.Transport.TLS
--  additionally checks Major >= 3 at Connect so the failure is
--  reported as a TLS_Error, and test_tls_version
--  (tests/src/openssl/) asserts it in the suite.
package AHT.Openssl.Version is

   function Major return Natural;
   function Minor return Natural;
   function Patch return Natural;
   --  OPENSSL_version_major / _minor / _patch of the linked library.

   function Version_String return String;
   --  OpenSSL_version(OPENSSL_VERSION), e.g.
   --  "OpenSSL 3.6.1 30 Sep 2025".

end AHT.Openssl.Version;
