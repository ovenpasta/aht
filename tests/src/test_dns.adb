--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Bounded resolution: AHT.DNS and the shim under it
--  (csrc/dns/aht_dns.c). The bound is on the CALLER, not the lookup.
--  All cases but 1 and 6 run against a fake resolver installed through
--  a C seam that replaces the LOOKUP only: the worker thread, the
--  wait, the deadline and the reference-counted handoff are production.
--
--  Cases:
--    1. the real resolver, reached and answering (localhost)
--    2. values survive the trip: three literals, in order
--    3. a 3 s resolver with a 0.5 s budget returns at 0.5 s
--    4. the abandoned worker finishes later and frees its half
--    5. a fake sleeping inside a generous budget succeeds
--    6. presentation form of IPv6, driven directly
--
--  Covers:
--    - the caller left first: the completion counter has not moved on
--      return, and then moves
--    - case 5 stops a shim that returns Timed_Out unconditionally
--
--  Does not cover:
--    - a real getaddrinfo stall: making one happen means a black-hole
--      nameserver in /etc/resolv.conf, process-global state

with Ada.Real_Time; use Ada.Real_Time;
with Ada.Command_Line;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces;
with Interfaces.C;
with System;

with AHT.DNS;

procedure Test_DNS is

   use type AHT.DNS.Resolve_Status;
   use type Interfaces.C.int;
   use type Interfaces.C.char;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_dns: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  The seam. The library's own API offers no way to reach it, so
   --  installing a fake takes an explicit import of a symbol with
   --  _for_test in its name.
   procedure Install_Fake (Sleep_Ms, N_Addrs : Interfaces.C.int)
     with Import, Convention => C,
          External_Name => "aht_dns_install_fake_for_test";

   procedure Restore_Real
     with Import, Convention => C,
          External_Name => "aht_dns_restore_real_for_test";

   function Fake_Completions return Interfaces.C.int
     with Import, Convention => C,
          External_Name => "aht_dns_fake_completions_for_test";

   --  Family is 4 or 6, not AF_INET/AF_INET6, so this side needs no
   --  platform constant to reach it.
   function Format_Addr
     (Family : Interfaces.C.int;
      Addr   : System.Address;
      Out_Buf : System.Address;
      Cap    : Interfaces.C.int) return Interfaces.C.int
     with Import, Convention => C,
          External_Name => "aht_dns_format_for_test";

   Addr_Len : constant := 46;   --  AHT_DNS_ADDRSTRLEN

   type Octets is array (Natural range <>) of Interfaces.Unsigned_8;

   --  Presentation form of Bytes, or "" if the shim refused.
   function Formatted (Family : Interfaces.C.int; Bytes : Octets)
     return String
   is
      Buf : Interfaces.C.char_array (1 .. Addr_Len) :=
        [others => Interfaces.C.nul];
      B   : Octets := Bytes;
      RC  : Interfaces.C.int;
      Last : Natural := 0;
   begin
      RC := Format_Addr (Family, B'Address, Buf'Address, Addr_Len);
      if RC = 0 then
         return "";
      end if;
      for I in Buf'Range loop
         exit when Buf (I) = Interfaces.C.nul;
         Last := Natural (I);
      end loop;
      return Interfaces.C.To_Ada
        (Buf (1 .. Interfaces.C.size_t (Last)), Trim_Nul => False);
   end Formatted;

   procedure Check_Format
     (Label : String; Family : Interfaces.C.int;
      Bytes : Octets; Expect : String)
   is
      Got : constant String := Formatted (Family, Bytes);
   begin
      if Got /= Expect then
         Fail ("format " & Label & ": got """ & Got
               & """, expected """ & Expect & """");
      end if;
   end Check_Format;

   Result : AHT.DNS.Address_Array;
   Count  : AHT.DNS.Address_Count;
   Status : AHT.DNS.Resolve_Status;

begin
   --  Case 1: the real resolver, reached and answering. This is the
   --  only case that exercises getaddrinfo, and without it the rest
   --  would pass against a shim that never reaches the lookup at all.
   --  localhost resolves from /etc/hosts without a nameserver.
   AHT.DNS.Resolve
     (Host    => "localhost",
      Service => "80",
      Timeout => 10.0,
      Result  => Result,
      Count   => Count,
      Status  => Status);

   if Status /= AHT.DNS.Resolved then
      Fail ("real: localhost gave " & Status'Image);
   elsif Count = 0 then
      Fail ("real: Resolved with no addresses");
   else
      declare
         First : constant String := To_String (Result (1));
      begin
         --  Loopback in either family. Not an equality check: which
         --  of 127.0.0.1 / ::1 comes first is the resolver's choice.
         if Ada.Strings.Fixed.Index (First, "127.") /= 1
           and then First /= "::1"
         then
            Fail ("real: localhost resolved to " & First
                  & ", expected a loopback literal");
         end if;
      end;
   end if;

   --  Case 2: values survive the trip. A fake that answers at once
   --  with three distinct literals must come back Resolved, with
   --  those three, in that order. Catches wrong slot arithmetic in
   --  the binding: a read at the wrong stride returns plausible
   --  garbage.
   Install_Fake (0, 3);
   AHT.DNS.Resolve
     (Host    => "example.invalid",
      Service => "443",
      Timeout => 5.0,
      Result  => Result,
      Count   => Count,
      Status  => Status);

   if Status /= AHT.DNS.Resolved then
      Fail ("fake-immediate: " & Status'Image & " (expected Resolved)");
   elsif Count /= 3 then
      Fail ("fake-immediate: Count =" & Count'Image & " (expected 3)");
   else
      for I in 1 .. 3 loop
         declare
            Want : constant String :=
              "127.0.0." & Ada.Strings.Fixed.Trim
                             (Integer'Image (I), Ada.Strings.Left);
            Got  : constant String := To_String (Result (I));
         begin
            if Want /= Got then
               Fail ("fake-immediate: address" & Integer'Image (I)
                     & " = """ & Got & """ (expected """ & Want & """)");
            end if;
         end;
      end loop;
   end if;

   --  Cases 3 and 4 are one experiment. A resolver that sleeps 3 s,
   --  given a 0.5 s budget, must hand control back at 0.5 s; that is
   --  equally true of "no worker ever ran". So the completion counter
   --  is read on return and must NOT have moved, then is waited on
   --  until it does.
   declare
      Before  : constant Interfaces.C.int := Fake_Completions;
      Started : Ada.Real_Time.Time;
      Took    : Duration;
      At_Exit : Interfaces.C.int;
      Waited  : Duration := 0.0;
   begin
      Install_Fake (3_000, 1);
      Started := Ada.Real_Time.Clock;
      AHT.DNS.Resolve
        (Host    => "example.invalid",
         Service => "443",
         Timeout => 0.5,
         Result  => Result,
         Count   => Count,
         Status  => Status);
      Took    := To_Duration (Ada.Real_Time.Clock - Started);
      At_Exit := Fake_Completions;

      if Status /= AHT.DNS.Timed_Out then
         Fail ("stall: " & Status'Image & " (expected Timed_Out)");
      end if;
      if Count /= 0 then
         Fail ("stall: Count =" & Count'Image
               & " on a timeout (expected 0)");
      end if;
      --  The shim keeps its deadline in whole milliseconds on the
      --  monotonic clock, and takes "now" by truncation, so the wait
      --  can finish up to one tick inside the nominal budget. The
      --  slack covers that quantization only: an early return (the
      --  deadline ignored, the wait not taken) is off by hundreds of
      --  milliseconds, not by two.
      if Took < 0.498 then
         Fail ("stall: returned after" & Duration'Image (Took)
               & "s, before the budget could have expired");
      elsif Took > 2.0 then
         Fail ("stall: took" & Duration'Image (Took)
               & "s for a 0.5s budget against a 3.0s sleep");
      end if;

      --  The premise: the caller got out while the lookup was still
      --  running. Had the worker already finished, this would test a
      --  slow return, not an abandoned one.
      if At_Exit /= Before then
         Fail ("stall: the fake had already completed when Resolve "
               & "returned — the wait was not cut short, so nothing "
               & "was abandoned and case 4 proves nothing");
      end if;

      --  The other half: it does finish, afterwards. Polled, so the
      --  delay is a liveness backstop and the counter is the evidence.
      while Fake_Completions = Before and then Waited < 10.0 loop
         delay 0.1;
         Waited := Waited + 0.1;
      end loop;

      if Fake_Completions = Before then
         Fail ("stall: the abandoned lookup never completed within"
               & Duration'Image (Waited)
               & "s — the worker was lost, not abandoned");
      end if;
   end;

   --  Case 5: the timeout path is not simply always taken. Same fake,
   --  sleeping well inside a generous budget, must succeed. Without
   --  this, a shim that returned Timed_Out unconditionally would pass
   --  case 3.
   Install_Fake (200, 2);
   declare
      Started : constant Ada.Real_Time.Time := Ada.Real_Time.Clock;
      Took    : Duration;
   begin
      AHT.DNS.Resolve
        (Host    => "example.invalid",
         Service => "443",
         Timeout => 5.0,
         Result  => Result,
         Count   => Count,
         Status  => Status);
      Took := To_Duration (Ada.Real_Time.Clock - Started);

      if Status /= AHT.DNS.Resolved then
         Fail ("under-budget: " & Status'Image & " (expected Resolved)");
      elsif Count /= 2 then
         Fail ("under-budget: Count =" & Count'Image & " (expected 2)");
      end if;
      if Took > 3.0 then
         Fail ("under-budget: took" & Duration'Image (Took)
               & "s for a 0.2s lookup — the wait is not being woken "
               & "by the worker, only by the deadline");
      end if;
   end;

   --  Leave the resolver as it was found, so a later test in the same
   --  binary could not silently inherit the fake.
   Restore_Real;

   --  Case 6: presentation form, driven directly, on inputs a resolver
   --  will not produce on request. The zero-run rule: the formatter
   --  must take the LONGEST run, the leftmost of equal runs, and must
   --  leave a single zero group uncompressed.
   declare
      V4  : constant Octets := [127, 0, 0, 1];
      Lo6 : constant Octets := [0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 1];
   begin
      Check_Format ("v4", 4, V4, "127.0.0.1");

      --  The literal case 1 accepts from a live lookup; a regression
      --  here also breaks case 1 on any host whose localhost answers
      --  ::1 first.
      Check_Format ("v6 loopback", 6, Lo6, "::1");

      Check_Format ("v6 unspecified", 6,
                    [0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0], "::");

      Check_Format ("v6 no zeros", 6,
                    [16#20#, 1, 16#0d#, 16#b8#, 0, 1, 0, 2,
                     0, 3, 0, 4, 0, 5, 0, 6],
                    "2001:db8:1:2:3:4:5:6");

      --  Longest run wins: one zero group, then a run of three.
      Check_Format ("v6 longest run", 6,
                    [16#20#, 1, 0, 0, 0, 1, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 1],
                    "2001:0:1::1");

      --  Equal runs of two: the leftmost is the one compressed.
      Check_Format ("v6 leftmost tie", 6,
                    [16#20#, 1, 0, 0, 0, 0, 0, 1,
                     0, 0, 0, 0, 0, 2, 0, 3],
                    "2001::1:0:0:2:3");

      --  A single zero group stays "0"; "::" for one group is no
      --  shorter and reads as an unknown number of groups.
      Check_Format ("v6 single zero", 6,
                    [16#20#, 1, 0, 0, 0, 1, 0, 2,
                     0, 3, 0, 4, 0, 5, 0, 6],
                    "2001:0:1:2:3:4:5:6");

      --  Run at the tail.
      Check_Format ("v6 trailing run", 6,
                    [16#20#, 1, 0, 1, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0],
                    "2001:1::");

      --  v4-mapped: the hex reading of these bytes is correct but
      --  unrecognisable next to a v4 literal.
      Check_Format ("v6 v4-mapped", 6,
                    [0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 16#ff#, 16#ff#, 192, 168, 1, 10],
                    "::ffff:192.168.1.10");

      --  A family the shim does not format is refused, not guessed.
      if Formatted (5, V4) /= "" then
         Fail ("format: family 5 was formatted rather than refused");
      end if;
   end;

   if Failures = 0 then
      Put_Line ("test_dns: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_dns:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_DNS;
