--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

package AHT.Openssl is

   --  Root of the AHT.Openssl.* binding tree: the system OpenSSL 3.
   --  Children are curated hand-edits of the output of
   --  scripts/regen_openssl_bindings.sh (docs/tls.md). Every handle
   --  is an opaque pointer, so the only C glue is for macro-defined
   --  entry points (AHT.Openssl.Glue). The Linker_Options fire only
   --  in a binary whose closure reaches AHT.Openssl.*; the -L path
   --  comes from aht.gpr (AHT_OPENSSL_DIR, default /usr).
   pragma Linker_Options ("-lssl");
   pragma Linker_Options ("-lcrypto");

end AHT.Openssl;
