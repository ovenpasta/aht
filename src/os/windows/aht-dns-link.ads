--  The part of the resolver shim's link line that depends on the
--  target OS. See the POSIX sibling for the shape; this is the
--  Windows one.
--
--  getaddrinfo, freeaddrinfo, inet_ntop and WSAStartup are Winsock
--  rather than C library on this target, so ws2_32 has to be named or
--  the link fails on four __imp_ symbols. Nothing is needed for the
--  threading: the shim uses CreateThread and a CONDITION_VARIABLE,
--  both of which come from kernel32, which is always linked.
--
--  This was found by the cross build rather than by reading the
--  manual — which is the argument for keeping that build in the loop.
--  The POSIX side compiles and links without it, so nothing on the
--  native path could have reported the omission.
package AHT.DNS.Link is

   pragma Linker_Options ("-lws2_32");

end AHT.DNS.Link;
