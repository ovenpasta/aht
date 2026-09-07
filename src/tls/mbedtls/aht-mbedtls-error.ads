--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Interfaces.C;

--  Human-readable mbedTLS error strings. Wraps mbedtls_strerror so
--  callers get an Ada String instead of managing a C buffer.
package AHT.Mbedtls.Error is

   function Strerror (Code : Interfaces.C.int) return String;
   --  The message for an mbedTLS error code (e.g. -0x2700). For unknown
   --  codes mbedTLS yields an empty string; callers should fall back to
   --  the numeric code.

end AHT.Mbedtls.Error;
