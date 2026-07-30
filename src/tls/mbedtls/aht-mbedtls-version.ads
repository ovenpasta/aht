package AHT.Mbedtls.Version is

   --  Compile-time constants mirrored from mbedtls/version.h.
   --  These move in lockstep with the pinned mbedTLS release
   --  scripts/fetch_mbedtls.sh downloads; if you bump the pin,
   --  rerun scripts/regen_mbedtls_bindings.sh and update these
   --  numbers from the regenerated spec.
   Major : constant := 2;
   Minor : constant := 28;
   Patch : constant := 9;

   function Version_String return String;
   --  Wraps mbedtls_version_get_string. Returns "x.y.z"
   --  (e.g. "2.28.9"), the short form without leading prefix.

   function Full_Version_String return String;
   --  Wraps mbedtls_version_get_string_full. Returns
   --  "Mbed TLS x.y.z" (e.g. "Mbed TLS 2.28.9"). Used by
   --  test_mbedtls_version as a smoke test that the binding +
   --  linker chain through to libmbedtls.a works end-to-end.

end AHT.Mbedtls.Version;
