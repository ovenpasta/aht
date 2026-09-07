--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  The OS-dependent part of the resolver shim's link line; see the
--  POSIX sibling for the shape.
--
--  Windows: getaddrinfo, freeaddrinfo, inet_ntop and WSAStartup are
--  Winsock, so ws2_32 must be named. The threading (CreateThread, a
--  CONDITION_VARIABLE) comes from kernel32, always linked. Windows
--  is not a supported configuration; the suite runs under wine.
package AHT.DNS.Link is

   pragma Linker_Options ("-lws2_32");

end AHT.DNS.Link;
