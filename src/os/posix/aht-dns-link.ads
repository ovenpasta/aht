--  The part of the resolver shim's link line that depends on the
--  target OS.
--
--  One body-less spec per OS directory, the same shape as
--  AHT.Random.Source and AHT.Mbedtls.Link; aht.gpr puts exactly one
--  of them on Source_Dirs. csrc/dns/aht_dns.c reaches for two
--  different sets of names depending on the target, and the link line
--  has to follow that rather than restate a guess about it.
--
--  Here, POSIX: the shim creates its worker with pthread_create and
--  waits on a pthread condition variable, so something has to supply
--  those. Harmless where the C library already does (glibc 2.34 and
--  later folded libpthread into libc, as does macOS libSystem);
--  load-bearing where it does not. getaddrinfo itself is in libc
--  everywhere and needs nothing named here.
package AHT.DNS.Link is

   pragma Linker_Options ("-lpthread");

end AHT.DNS.Link;
