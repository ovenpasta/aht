--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

package AHT.Mbedtls.Version is

   --  Compile-time constants mirrored from mbedtls/version.h.
   --  These move in lockstep with the pinned mbedTLS release
   --  scripts/fetch_mbedtls.sh downloads; if you bump the pin,
   --  rerun scripts/regen_mbedtls_bindings.sh and update these
   --  numbers from the regenerated spec.
   Major : constant := 3;
   Minor : constant := 6;
   Patch : constant := 7;

   function Version_String return String;
   --  Wraps mbedtls_version_get_string. Returns "x.y.z"
   --  (e.g. "3.6.7"), the short form without leading prefix.

   function Full_Version_String return String;
   --  Wraps mbedtls_version_get_string_full. Returns
   --  "Mbed TLS x.y.z" (e.g. "Mbed TLS 3.6.7"). Used by
   --  test_mbedtls_version as a smoke test that the binding +
   --  linker chain through to libmbedtls.a works end-to-end.

end AHT.Mbedtls.Version;
