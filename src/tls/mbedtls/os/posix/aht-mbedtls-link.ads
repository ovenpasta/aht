--  The part of the mbedTLS link line that depends on the target OS.
--
--  One body-less spec per OS directory, the same one-unit-per-target
--  shape as AHT.Random.Source; aht.gpr puts exactly one of them on
--  Source_Dirs. It exists because the vendored library is not
--  configured identically for every target, and the link line has to
--  follow that choice rather than restate a guess about it.
--
--  Here, POSIX: scripts/fetch_mbedtls.sh enables
--  MBEDTLS_THREADING_PTHREAD, so the archive calls pthread_mutex_*
--  and something has to supply them. Harmless where the C library
--  already does (glibc 2.34 and later, macOS libSystem); load-bearing
--  where it does not.
--
--  The archives themselves stay in the parent spec: they are the same
--  three names everywhere, and duplicating them per OS would be a
--  drift hazard for no gain.
package AHT.Mbedtls.Link is

   pragma Linker_Options ("-lpthread");

end AHT.Mbedtls.Link;
