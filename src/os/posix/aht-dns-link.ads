--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  The OS-dependent part of the resolver shim's link line. One
--  body-less spec per OS directory, like AHT.Random.Source and
--  AHT.Mbedtls.Link; aht.gpr puts exactly one on Source_Dirs.
--
--  POSIX: the shim uses pthread_create and a pthread condition
--  variable. Harmless where libc already provides them (glibc 2.34
--  and later, macOS); required elsewhere. getaddrinfo is in libc.
package AHT.DNS.Link is

   pragma Linker_Options ("-lpthread");

end AHT.DNS.Link;
