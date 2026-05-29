package AHT.Mbedtls is

   --  Root of the AHT.Mbedtls.* binding tree. Children are curated
   --  hand-edits of the output of `scripts/regen_mbedtls_bindings.sh`
   --  (see docs/mbedtls.md for the why and how).
   --
   --  `pragma Linker_Options` here is the single place we tell the
   --  linker how to find the three static archives that
   --  `scripts/fetch_mbedtls.sh` builds into
   --  `third_party/mbedtls-2.28.9/library/`. The pragma only fires
   --  when a binary transitively `with`s a unit in AHT.Mbedtls.*,
   --  so test binaries that don't touch mbedTLS skip the extra
   --  link step.
   --
   --  Relative paths resolve against the linker's CWD, which
   --  gprbuild sets to the project root. -lpthread is needed
   --  because mbedTLS was built with MBEDTLS_THREADING_PTHREAD.
   pragma Linker_Options
     ("-Lthird_party/mbedtls-2.28.9/library");
   pragma Linker_Options ("-lmbedtls");
   pragma Linker_Options ("-lmbedx509");
   pragma Linker_Options ("-lmbedcrypto");
   pragma Linker_Options ("-lpthread");

end AHT.Mbedtls;
