--  Bounded resolution: AHT.DNS and the shim under it
--  (csrc/dns/aht_dns.c).
--
--  The bound here is on the CALLER, not on the lookup, and the two
--  cannot be tested the same way. That the caller stops waiting is
--  observable directly. That the abandoned worker is handled
--  correctly is not — so case 4 makes it observable rather than
--  assuming it, which is the whole reason the fake counts its own
--  completions.
--
--  Everything below runs against a fake resolver installed through a
--  C seam, except case 1. The seam replaces the LOOKUP only: the
--  worker thread, the condition-variable wait, the deadline and the
--  reference-counted handoff are the production ones in every case.
--  A seam any higher — swapping AHT.DNS.Resolve itself — would test
--  none of those, which is to say it would test nothing that can go
--  wrong.
--
--  Why a fake at all: the timeout path needs a resolver that stalls,
--  and the real one stalls only against an unreachable nameserver.
--  That is /etc/resolv.conf, which is process-global and shared with
--  whatever else is running on the machine. A sleeping fake makes the
--  same path deterministic with no network, no configuration, and
--  identical behaviour under wine.
--
--  What is NOT covered: that a real getaddrinfo stall is survived.
--  Case 1 proves the real resolver is reached and answers; no case
--  drives it to its own timeout, because arranging that is exactly
--  the global-state problem above. The gap is narrow — the stall path
--  and the success path differ only in which function the seam holds
--  — but it is a gap.

with Ada.Real_Time; use Ada.Real_Time;
with Ada.Command_Line;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces.C;

with AHT.DNS;

procedure Test_DNS is

   use type AHT.DNS.Resolve_Status;
   use type Interfaces.C.int;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_dns: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  The seam. Imported here rather than bound in AHT.DNS on
   --  purpose: the library's own API offers no way to reach it, so
   --  installing a fake takes a deliberate import of a symbol with
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

   Result : AHT.DNS.Address_Array;
   Count  : AHT.DNS.Address_Count;
   Status : AHT.DNS.Resolve_Status;

begin
   --  Case 1: the real resolver, reached and answering. This is the
   --  only case that exercises getaddrinfo, and it is what stops the
   --  rest passing against a shim that never reaches the lookup at
   --  all. localhost is used because it resolves from /etc/hosts
   --  without a nameserver.
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
   --  those three, in that order. This is what would catch the slot
   --  arithmetic in the binding being wrong — a fixed-width block
   --  read at the wrong stride returns plausible-looking garbage
   --  rather than failing.
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

   --  Case 3 and 4 are one experiment, and case 4 is the half that
   --  makes case 3 mean anything.
   --
   --  A resolver that sleeps 3 s, given a 0.5 s budget, must hand
   --  control back at 0.5 s. That alone is equally consistent with
   --  "the worker was abandoned correctly" and "no worker ever ran"
   --  — the trap CLAUDE.md names. So the completion counter is read
   --  immediately on return and must NOT yet have moved (the worker
   --  is still asleep: the caller really did leave first), and is
   --  then waited on until it does move (the worker really did
   --  finish, late, and freed its half of the job).
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
      --  slack here is for that quantization and nothing else: a
      --  genuine early return — the deadline ignored, the wait not
      --  taken — is off by hundreds of milliseconds, not by two.
      if Took < 0.498 then
         Fail ("stall: returned after" & Duration'Image (Took)
               & "s, before the budget could have expired");
      elsif Took > 2.0 then
         Fail ("stall: took" & Duration'Image (Took)
               & "s for a 0.5s budget against a 3.0s sleep");
      end if;

      --  The premise: the caller got out while the lookup was still
      --  running. Had the worker already finished, this would be a
      --  test of a slow return, not of an abandoned one.
      if At_Exit /= Before then
         Fail ("stall: the fake had already completed when Resolve "
               & "returned — the wait was not cut short, so nothing "
               & "was abandoned and case 4 proves nothing");
      end if;

      --  And the other half: it does finish, afterwards. Polled
      --  rather than slept-through, so the delay is a liveness
      --  backstop and the counter is the evidence.
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

   if Failures = 0 then
      Put_Line ("test_dns: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_dns:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_DNS;
