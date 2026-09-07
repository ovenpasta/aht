--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Strings.Unbounded;

--  Hostname resolution with a bound on the caller's wait. getaddrinfo
--  has no deadline and cannot be cancelled on either platform, so a
--  Resolve that reports Timed_Out has stopped waiting, not stopped
--  the lookup; the worker runs on until the platform resolver's own
--  retry limits end it. A C shim (csrc/dns/aht_dns.c), not an Ada
--  task: a task parked in a blocking C call cannot be aborted on
--  Windows (docs/websocket.md, "Abort safety is structural").
package AHT.DNS is

   package SU renames Ada.Strings.Unbounded;

   --  A ceiling: a name with more addresses is truncated, not
   --  rejected.
   Max_Addresses : constant := 16;

   subtype Address_Count is Natural range 0 .. Max_Addresses;

   type Address_Array is
     array (1 .. Max_Addresses) of SU.Unbounded_String;

   type Resolve_Status is
     (Resolved,        --  Count >= 1 literals in Result
      Timed_Out,       --  the wait expired; the lookup continues
      Failed,          --  the resolver answered, with nothing usable
      Internal_Error); --  no thread, no memory: nothing was attempted

   --  Resolves Host to numeric literals, waiting at most Timeout;
   --  Duration'Last waits indefinitely. Service is the port as a
   --  string, or "". Result holds Count literals, IPv4 or IPv6, in
   --  resolver order, for AHT.Transport.TCP.Connect_Candidates; Count
   --  is 0 unless Status is Resolved. Resolving here keeps Host the
   --  name used for SNI and certificate verification; a literal in
   --  the URL would send no SNI and verify against IP SANs. A
   --  negative Timeout is refused by the precondition: the shim reads
   --  a negative millisecond count as no bound.
   procedure Resolve
     (Host    : String;
      Service : String;
      Timeout : Duration;
      Result  : out Address_Array;
      Count   : out Address_Count;
      Status  : out Resolve_Status)
     with Pre => Timeout >= 0.0;

end AHT.DNS;
