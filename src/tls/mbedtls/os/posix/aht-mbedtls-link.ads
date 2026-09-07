--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  The part of the mbedTLS link line that depends on the target OS.
--
--  One body-less spec per OS directory, the same one-unit-per-target
--  shape as AHT.Random.Source; aht.gpr puts exactly one of them on
--  Source_Dirs. The vendored library is not configured identically
--  for every target, and the link line follows that configuration.
--
--  Here, POSIX: scripts/fetch_mbedtls.sh enables
--  MBEDTLS_THREADING_PTHREAD, so the archive calls pthread_mutex_*
--  and something has to supply them. Harmless where the C library
--  already does (glibc 2.34 and later, macOS libSystem); required
--  where it does not.
--
--  The archives themselves stay in the parent spec: they are the same
--  three names everywhere.
package AHT.Mbedtls.Link is

   pragma Linker_Options ("-lpthread");

end AHT.Mbedtls.Link;
