--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Interfaces.C;
with System;

--  Pulls the target's link-line requirements into the closure of any
--  binary that resolves, and only those: a program that never touches
--  AHT.DNS does not name ws2_32 either.
with AHT.DNS.Link;
pragma Unreferenced (AHT.DNS.Link);

package body AHT.DNS is

   use type Interfaces.C.int;
   use type Interfaces.C.long;
   use type Interfaces.C.size_t;
   use type Interfaces.C.char;
   use type Interfaces.C.char_array;

   Addr_Len : constant := 46;  --  AHT_DNS_ADDRSTRLEN; INET6_ADDRSTRLEN

   --  Status codes, mirroring the AHT_DNS_* constants in
   --  csrc/dns/aht_dns.c. Anything the shim returns that is not
   --  listed here lands on Internal_Error.
   C_OK       : constant Interfaces.C.int := 0;
   C_Timeout  : constant Interfaces.C.int := 1;
   C_Failed   : constant Interfaces.C.int := 2;

   function C_Resolve
     (Host       : System.Address;
      Svc        : System.Address;
      Timeout_Ms : Interfaces.C.long;
      Out_Buf    : System.Address;
      Max_Addrs  : Interfaces.C.int;
      Count      : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "aht_dns_resolve";

   procedure Resolve
     (Host    : String;
      Service : String;
      Timeout : Duration;
      Result  : out Address_Array;
      Count   : out Address_Count;
      Status  : out Resolve_Status)
   is
      Host_C : constant Interfaces.C.char_array :=
        Interfaces.C.To_C (Host);
      Svc_C  : constant Interfaces.C.char_array :=
        Interfaces.C.To_C (Service);

      --  One flat block of Max_Addresses fixed-width slots, which is
      --  what the shim writes. Fixed width so that a short answer
      --  cannot be read as a long one: every slot starts where Ada
      --  expects it to.
      Buf : Interfaces.C.char_array
              (1 .. Interfaces.C.size_t (Max_Addresses * Addr_Len)) :=
        [others => Interfaces.C.nul];

      N  : aliased Interfaces.C.int := 0;
      RC : Interfaces.C.int;

      --  "No bound" is passed as a negative rather than as a very
      --  large millisecond count, because the multiplication would
      --  overflow C long on a 32-bit target, and an overflowed
      --  deadline is an arbitrarily short one. Anything from a day
      --  upwards is treated the same way: it is already past every
      --  resolver's own retry limits, so it is not distinguishable
      --  from Duration'Last.
      Ms : constant Interfaces.C.long :=
        (if Timeout >= 86_400.0
         then -1
         else Interfaces.C.long (Timeout * 1000.0));
   begin
      Result := [others => SU.Null_Unbounded_String];
      Count  := 0;

      RC := C_Resolve
              (Host       => Host_C'Address,
               Svc        => Svc_C'Address,
               Timeout_Ms => Ms,
               Out_Buf    => Buf'Address,
               Max_Addrs  => Interfaces.C.int (Max_Addresses),
               Count      => N'Address);

      if RC = C_OK then
         Status := Resolved;
      elsif RC = C_Timeout then
         Status := Timed_Out;
         return;
      elsif RC = C_Failed then
         Status := Failed;
         return;
      else
         Status := Internal_Error;
         return;
      end if;

      --  Only reached on Resolved. Clamped so that a shim reporting a
      --  count outside the array cannot index past it; Max_Addresses
      --  already states the ceiling.
      Count := Address_Count (Interfaces.C.int'Min
                                (N, Interfaces.C.int (Max_Addresses)));

      for I in 1 .. Count loop
         declare
            Base : constant Interfaces.C.size_t :=
              Interfaces.C.size_t ((I - 1) * Addr_Len);
            Last : Interfaces.C.size_t := Base;
         begin
            --  Each slot is NUL-terminated by the shim; find the
            --  terminator rather than trusting the whole width.
            while Last < Base + Addr_Len
              and then Buf (Last + 1) /= Interfaces.C.nul
            loop
               Last := Last + 1;
            end loop;

            Result (I) := SU.To_Unbounded_String
              (Interfaces.C.To_Ada
                 (Buf (Base + 1 .. Last) & Interfaces.C.nul));
         end;
      end loop;

      --  A success with nothing in it is not a success. The shim does
      --  not produce this; the check keeps one that did from being
      --  read as an empty candidate list.
      if Count = 0 then
         Status := Failed;
      end if;
   end Resolve;

end AHT.DNS;
