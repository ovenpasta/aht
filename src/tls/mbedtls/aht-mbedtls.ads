--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

package AHT.Mbedtls is

   --  Root of the AHT.Mbedtls.* binding tree. Children are curated
   --  hand-edits of the output of `scripts/regen_mbedtls_bindings.sh`
   --  (see docs/mbedtls.md for the why and how).
   --
   --  `pragma Linker_Options` here names the three static archives
   --  that `scripts/fetch_mbedtls.sh` builds into
   --  `third_party/mbedtls-2.28.9/library/`. The pragma only fires
   --  when a binary transitively `with`s a unit in AHT.Mbedtls.*,
   --  so test binaries that don't touch mbedTLS skip the extra
   --  link step. The library search path (-L) comes from aht.gpr's
   --  Linker_Options, anchored to Project_Dir so it also resolves
   --  when aht is consumed as a dependency.
   --
   --  These three names are the same for every target. Anything that
   --  is not -- currently just the threading library, which POSIX
   --  needs and Windows does not -- lives in AHT.Mbedtls.Link, whose
   --  body-less spec comes from an OS-selected directory.
   pragma Linker_Options ("-lmbedtls");
   pragma Linker_Options ("-lmbedx509");
   pragma Linker_Options ("-lmbedcrypto");

end AHT.Mbedtls;
