with Ada.Strings.Unbounded;

--  Hostname resolution with a bound on the caller's wait.
--
--  This exists because getaddrinfo has no deadline and cannot be
--  cancelled on either platform, so the transports' Connect_Timeout —
--  which starts counting only once the addresses are known — leaves
--  resolution itself unbounded. A dial to a name is therefore bounded
--  end to end only if the resolution ahead of it is.
--
--  The bound is on the CALLER, and the distinction is the whole
--  contract. A Resolve that reports Timed_Out has stopped waiting; it
--  has not stopped the lookup, because nothing can. The worker
--  carrying it runs until the platform resolver gives up by itself,
--  which it does — bounded in practice by the resolver's own retry
--  limits — so an abandoned lookup is a thread with a bounded life
--  rather than a leak. What the caller gets back is control, on time.
--
--  The implementation is a C shim (csrc/dns/aht_dns.c) rather than an
--  Ada task, because the thing that must be abandoned is a blocking
--  C call: an Ada task parked in it could not be aborted on Windows
--  (see *Abort safety is structural* in docs/websocket.md), which is
--  the platform where this matters most.
package AHT.DNS is

   package SU renames Ada.Strings.Unbounded;

   --  How many addresses one name may yield here. A ceiling rather
   --  than a promise: a name with more is truncated, not rejected,
   --  since a connect walks candidates in order and exhausting
   --  sixteen already means something other than address selection is
   --  wrong.
   Max_Addresses : constant := 16;

   subtype Address_Count is Natural range 0 .. Max_Addresses;

   type Address_Array is
     array (1 .. Max_Addresses) of SU.Unbounded_String;

   type Resolve_Status is
     (Resolved,        --  Count >= 1 literals in Result
      Timed_Out,       --  the wait expired; the lookup continues
      Failed,          --  the resolver answered, with nothing usable
      Internal_Error); --  no thread, no memory: nothing was attempted

   --  Resolve Host to numeric address literals, waiting at most
   --  Timeout. Service is the port as a string (or "" — the
   --  literals are what this is for, not the service lookup).
   --
   --  Duration'Last waits indefinitely, which is the pre-existing
   --  behaviour and the default everywhere in this library.
   --
   --  Result holds Count presentation-form literals — IPv4 or IPv6,
   --  in the order the resolver returned them, ready to be handed to
   --  AHT.Transport.TCP.Connect_Candidates. Count is 0 unless Status
   --  is Resolved.
   --
   --  Passing the literals on while keeping Host for SNI and
   --  certificate verification is the point of resolving separately.
   --  Substituting a literal INTO the URL instead is the trap: an
   --  IP-literal host sends no SNI and is verified against IP SANs,
   --  which ordinary certificates do not carry.
   --  A negative Timeout is a caller error rather than a shorthand,
   --  and is refused here instead of being passed on: the shim reads
   --  any negative millisecond count as "no bound", so an unchecked
   --  -1.0 would produce an unbounded wait — the exact opposite of
   --  what asking for a negative timeout could possibly mean. Same
   --  shape as AHT.Transport's deadline setters, which bound their
   --  own argument the same way.
   procedure Resolve
     (Host    : String;
      Service : String;
      Timeout : Duration;
      Result  : out Address_Array;
      Count   : out Address_Count;
      Status  : out Resolve_Status)
     with Pre => Timeout >= 0.0;

end AHT.DNS;
