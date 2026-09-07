--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

package AHT.Mbedtls is

   --  Root of the AHT.Mbedtls.* binding tree: curated hand-edits of
   --  the output of scripts/regen_mbedtls_bindings.sh (docs/mbedtls.md).
   --  The Linker_Options name the three archives that
   --  scripts/fetch_mbedtls.sh builds into
   --  third_party/mbedtls-3.6.7/library/ (suffixed with the cross
   --  target for a cross build); they fire only in a binary whose
   --  closure reaches AHT.Mbedtls.*. The -L path comes from aht.gpr.
   --  The OS-dependent part (the threading library, POSIX only) is in
   --  AHT.Mbedtls.Link.
   pragma Linker_Options ("-lmbedtls");
   pragma Linker_Options ("-lmbedx509");
   pragma Linker_Options ("-lmbedcrypto");

end AHT.Mbedtls;
