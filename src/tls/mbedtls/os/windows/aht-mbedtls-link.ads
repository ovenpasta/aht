--  The part of the mbedTLS link line that depends on the target OS.
--  See the POSIX sibling for the shape; this is the Windows one, and
--  it is deliberately empty.
--
--  mbedTLS 2.28 offers pthread or a caller-supplied THREADING_ALT and
--  nothing else, so scripts/fetch_mbedtls.sh builds this target
--  threadless: no MBEDTLS_THREADING_C, hence no mutex calls, hence
--  no threading library to name here.
--
--  That is sound rather than convenient, and the argument is
--  enumerated in docs/tls.md -- every mutex mbedTLS would take is
--  either around a context AHT keeps per session, or in a code path
--  this client does not reach, or in a POSIX-only branch whose _WIN32
--  counterpart is thread-safe without one. It holds only while
--  MBEDTLS_USE_PSA_CRYPTO stays off; the fetch script checks that and
--  fails the build if it ever does not.
--
--  An empty package rather than no package: aht.gpr selects a
--  directory, not a file, so the unit has to exist for both targets.
--  Its emptiness is the point being recorded.
package AHT.Mbedtls.Link is

end AHT.Mbedtls.Link;
