--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Envelope validation for PEM certificate bundles, shared by both
--  TLS backends. Neither library reports data left over after the
--  last certificate block: OpenSSL's PEM_R_NO_START_LINE means "no
--  further header", for trailing garbage as for a clean end; mbedTLS
--  returns the count of certificates that failed to parse, zero for
--  trailing garbage. Only the envelope is checked here; whether a
--  block's base64 decodes to a certificate is the library's job.
package AHT.PEM is

   --  "" when Data is one or more complete certificate blocks with
   --  nothing but whitespace between, before and after them;
   --  otherwise a diagnostic naming the problem. Only the
   --  "CERTIFICATE" label is accepted: OpenSSL would also take
   --  "TRUSTED CERTIFICATE" and mbedTLS would not.
   function Bundle_Problem (Data : String) return String;

end AHT.PEM;
