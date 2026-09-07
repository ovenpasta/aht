--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Bounds on Websocket.Client.Connect: Resolve_Timeout,
--  Connect_Timeout, Handshake_Deadline and Upgrade_Deadline. Before
--  these existed the client dialled with all four at Duration'Last,
--  so a peer that accepted the TCP connection and then went silent
--  parked the caller forever, with no API-level way to bound or
--  cancel it — and a name that would not resolve did the same before
--  a socket ever existed.
--
--  Routing:
--    * ws://127.0.0.1:8767/  — server_stall.py. Accepts TCP, then
--      never speaks a byte. The connect succeeds and the HTTP upgrade
--      is what stalls, so this is the Upgrade_Deadline fixture.
--    * wss://127.0.0.1:8767/ — the same fixture reached over TLS
--      (Insecure). Now the *handshake* stalls and the upgrade is
--      never reached, so this is the Handshake_Deadline fixture.
--    * ws://127.0.0.1:8765/  — the real echo fixture, for the
--      controls and for the deadline-cleared regression.
--
--  What each case proves, and how it would fail:
--
--  Cases 1 and 2 do not assert merely that *a* timeout happened; they
--  assert that the wait tracked the value passed. The fixture never
--  sends anything, so nothing but the deadline can end the wait, and
--  the lower bound (elapsed >= deadline) is therefore exact rather
--  than statistical: the wait cannot come back early, only late.
--
--  Lateness is the only noise, which is why the two cases are checked
--  against constants and never against each other. Their windows —
--  [1.0, 4.0] and [6.0, 12.0] — are disjoint, so no single fixed
--  internal bound can satisfy both, and a build that ignored the
--  parameter fails one of them whatever it hard-coded. Comparing the
--  two elapsed times would test the same thing but through two noisy
--  measurements at once, where a slow 1.0 s case could overtake a
--  prompt 6.0 s one and fail a test that had found nothing wrong.
--
--  The exception identity carries the rest of the premise. Reaching
--  Timeout_Error rather than Transport_Error is itself proof that the
--  TCP connect succeeded, so case 1 cannot pass by failing early for
--  an unrelated reason — a refused or unreachable port surfaces as
--  Transport_Error, which every case here rejects explicitly.
--
--  Case 3 leaves Upgrade_Deadline at its default deliberately. Were
--  the handshake bound not honoured, the dial would hang rather than
--  fall through to a different bound and pass for the wrong reason;
--  run_tests.sh's per-test cap reports that as a TIMEOUT.
--
--  Case 5 is the regression guard for the disarm at the end of
--  Connect. Set_Read_Deadline / Set_Write_Deadline are COMPOUND
--  budgets measured from the setter call, so an Upgrade_Deadline left
--  armed after a successful upgrade does not go on bounding the
--  upgrade — it expires under the receiver mid-session, on a
--  connection that was never in trouble. The case connects with a
--  1.0 s upgrade budget, idles well past it, and then requires a full
--  round trip. Backed out (both Set_*_Deadline (Duration'Last) calls
--  at the end of Connect removed) it fails, and fails in the place
--  the argument predicts: the receiver trips Timeout_Error during the
--  idle, so Is_Open is already False before the send.
--
--  What case 5 does not distinguish: a genuine clear from a disarm
--  that merely re-armed some very large finite budget. Both survive a
--  2.5 s idle. What makes the case sound is the specific pair of
--  numbers — any budget of 1.0 s that leaked is certainly expired by
--  then — not a proof that the deadline was zeroed. That the disarm
--  is a real clear rather than a large value is a property of
--  Set_*_Deadline (Duration'Last), which the transports implement by
--  dropping the flag; it is their contract, tested there, and this
--  case leans on it rather than re-proving it.
--
--  What is NOT covered. A genuine mid-connect stall for
--  Connect_Timeout: that needs an unroutable or firewalled peer, too
--  environment-dependent for CI — the same limitation test_tcp
--  records for its own budget-exhausted case. Case 4 drives the
--  pre-attempt budget check instead, which proves the parameter
--  reaches AHT.Transport.TCP.Connect and no more; it does not prove a
--  stalled connect is interrupted.
--
--  Resolution is covered by cases 7 to 9, through the same C seam
--  test_dns uses. What is not covered there is a stall in the real
--  getaddrinfo, for the reason test_dns records: making one happen
--  means pointing the process at a black-hole nameserver, which is
--  global state shared with the rest of the machine.

with Ada.Calendar; use Ada.Calendar;
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Real_Time;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces.C;

with AHT.Bytes;
with AHT.Transport;
with AHT.Websocket;
with AHT.Websocket.Client;

procedure Test_WS_Connect_Bounds is

   use type AHT.Websocket.Message_Kind;

   --  Ada.Calendar is use'd above and both packages export Time and
   --  Clock, so Ada.Real_Time is named explicitly rather than use'd.
   --  This one operator still has to be made visible for the
   --  subtraction in case 7.
   use type Ada.Real_Time.Time;
   use type Interfaces.C.int;

   Failures : Natural := 0;

   Stall_WS  : constant String := "ws://127.0.0.1:8767/";
   Stall_WSS : constant String := "wss://127.0.0.1:8767/";
   Echo_WS   : constant String := "ws://127.0.0.1:8765/";

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_connect_bounds: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function To_String (V : AHT.Bytes.Buffer) return String is
     (AHT.Bytes.To_String (V));

   --  The resolver seam, as in test_dns: imported deliberately rather
   --  than exposed by AHT.DNS. Used only by cases 7 to 9, and undone
   --  before the run ends.
   procedure Install_Fake (Sleep_Ms, N_Addrs : Interfaces.C.int)
     with Import, Convention => C,
          External_Name => "aht_dns_install_fake_for_test";

   procedure Restore_Real
     with Import, Convention => C,
          External_Name => "aht_dns_restore_real_for_test";

   function Fake_Completions return Interfaces.C.int
     with Import, Convention => C,
          External_Name => "aht_dns_fake_completions_for_test";

   --  Dial the stall fixture with an upgrade budget and report how
   --  long the dial took. Returns 0.0 and records a failure if
   --  anything other than Timeout_Error came back, so the caller can
   --  compare two elapsed times without re-checking the outcome.
   function Stalled_Upgrade_Took (Deadline : Duration) return Duration is
      C       : AHT.Websocket.Client.Client_Type;
      Started : constant Time := Clock;
      Tag     : constant String :=
        "upgrade-deadline" & Duration'Image (Deadline) & "s: ";
   begin
      AHT.Websocket.Client.Connect
        (C, Stall_WS, Upgrade_Deadline => Deadline);
      Fail (Tag & "Connect returned normally against a fixture that "
            & "never sends a byte");
      AHT.Websocket.Client.Close (C);
      return 0.0;
   exception
      when AHT.Transport.Timeout_Error =>
         return Clock - Started;
      when E : others =>
         Fail (Tag & "expected Timeout_Error, got "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E)
               & " (is server_stall.py running on 8767?)");
         return 0.0;
   end Stalled_Upgrade_Took;

   Short_Took : Duration := 0.0;
   Long_Took  : Duration := 0.0;

begin
   --  Case 1: a peer that accepts the connection and never answers
   --  the upgrade must not park the caller. 1.0 s budget, and the
   --  wait must be over well before case 2's budget could have
   --  produced it — see the note there for why 4.0 is the ceiling.
   Short_Took := Stalled_Upgrade_Took (1.0);
   if Short_Took > 0.0 then
      if Short_Took < 1.0 then
         Fail ("upgrade-deadline 1.0s: returned after"
               & Duration'Image (Short_Took)
               & "s, before the budget could have expired");
      elsif Short_Took > 4.0 then
         Fail ("upgrade-deadline 1.0s: took"
               & Duration'Image (Short_Took)
               & "s — bounded, but not by this budget");
      end if;
   end if;

   --  Case 2: the wait tracks the value passed, not some fixed
   --  internal bound. Same fixture, 6x the budget.
   --
   --  The two cases are deliberately checked against CONSTANTS rather
   --  than against each other. Comparing the two elapsed times would
   --  be comparing two measurements that scheduling delay can only
   --  inflate, and on a loaded machine a slow 1.0 s case could
   --  overtake a prompt 6.0 s one and fail a test that had found
   --  nothing wrong. The windows do the same work without that: case
   --  1 must land in [1.0, 4.0] and case 2 in [6.0, 12.0], and no
   --  single fixed bound B satisfies both — it would need B <= 4.0
   --  and B >= 6.0. So an implementation that ignored the parameter
   --  fails one of the two whatever value it hard-coded, and neither
   --  check depends on the other's timing.
   Long_Took := Stalled_Upgrade_Took (6.0);
   if Long_Took > 0.0 then
      if Long_Took < 6.0 then
         Fail ("upgrade-deadline 6.0s: returned after"
               & Duration'Image (Long_Took)
               & "s, before the budget could have expired — the "
               & "parameter is not what bounded the wait");
      elsif Long_Took > 12.0 then
         Fail ("upgrade-deadline 6.0s: took"
               & Duration'Image (Long_Took) & "s");
      end if;
   end if;

   --  Case 3: the TLS handshake against the same silent fixture.
   --  Upgrade_Deadline is deliberately left at Duration'Last: the
   --  upgrade is never reached, so if Handshake_Deadline did not
   --  bound this the dial would hang rather than be rescued by the
   --  other knob.
   declare
      C       : AHT.Websocket.Client.Client_Type;
      Started : constant Time := Clock;
      Took    : Duration;
   begin
      AHT.Websocket.Client.Connect
        (C, Stall_WSS,
         Insecure           => True,
         Handshake_Deadline => 1.0);
      Fail ("handshake-deadline: Connect returned normally against a "
            & "fixture that never sends a ServerHello");
      AHT.Websocket.Client.Close (C);
   exception
      when AHT.Transport.Timeout_Error =>
         Took := Clock - Started;
         if Took < 1.0 then
            Fail ("handshake-deadline: returned after"
                  & Duration'Image (Took)
                  & "s, before the budget could have expired");
         elsif Took > 6.0 then
            Fail ("handshake-deadline: took" & Duration'Image (Took)
                  & "s — bounded, but not by this budget");
         end if;
      when E : others =>
         Fail ("handshake-deadline: expected Timeout_Error, got "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E));
   end;

   --  Case 4: Connect_Timeout reaches AHT.Transport.TCP.Connect. An
   --  exhausted budget trips the pre-attempt check, so the dial never
   --  happens — which is why the target is the LIVE echo fixture. A
   --  build that dropped the parameter connects to it and returns
   --  normally, and that is the failure this case reports.
   declare
      C : AHT.Websocket.Client.Client_Type;
   begin
      AHT.Websocket.Client.Connect
        (C, Echo_WS, Connect_Timeout => 0.0);
      Fail ("connect-timeout: Connect returned normally with an "
            & "exhausted budget");
      AHT.Websocket.Client.Close (C);
   exception
      when AHT.Transport.Timeout_Error =>
         null;  --  expected
      when E : others =>
         Fail ("connect-timeout: expected Timeout_Error, got "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E));
   end;

   --  Case 5: the upgrade budget is disarmed once the upgrade
   --  succeeds. Connect with 1.0 s, idle well past it, then require a
   --  full round trip. See the header: this is the case that fails if
   --  the two Set_*_Deadline (Duration'Last) calls at the end of
   --  Connect are backed out.
   declare
      C       : AHT.Websocket.Client.Client_Type;
      Msg     : AHT.Websocket.Client.Message_Type;
      Started : Time;
      Idled   : Duration;
   begin
      begin
         AHT.Websocket.Client.Connect
           (C, Echo_WS, Upgrade_Deadline => 1.0);
      exception
         when E : others =>
            Fail ("deadline-cleared: Connect raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E)
                  & " (is server_ws.py running on 8765?)");
            Put_Line ("test_ws_connect_bounds:" & Failures'Image
                      & " failure(s)");
            Ada.Command_Line.Set_Exit_Status (1);
            return;
      end;

      --  Idle past the budget. The premise is not the delay itself
      --  but that the elapsed time is confirmed to exceed 1.0 s
      --  before anything is asserted: a budget that had leaked into
      --  the session is expired by this point, so the checks below
      --  are checking something.
      Started := Clock;
      delay 2.5;
      Idled := Clock - Started;
      if Idled <= 1.0 then
         Fail ("deadline-cleared: idled only" & Duration'Image (Idled)
               & "s, which does not outlast the 1.0s budget — the "
               & "case proves nothing as it stands");
      end if;

      if not AHT.Websocket.Client.Is_Open (C) then
         Fail ("deadline-cleared: connection died during a"
               & Duration'Image (Idled)
               & "s idle — the upgrade budget outlived the upgrade");
      else
         begin
            AHT.Websocket.Client.Send_Text (C, "past the deadline");
            AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);
            if Msg.Kind /= AHT.Websocket.Text_Message then
               Fail ("deadline-cleared: Kind = " & Msg.Kind'Image);
            elsif To_String (Msg.Payload) /= "past the deadline" then
               Fail ("deadline-cleared: payload = """
                     & To_String (Msg.Payload) & """");
            end if;
         exception
            when E : others =>
               Fail ("deadline-cleared: round trip after a"
                     & Duration'Image (Idled) & "s idle raised "
                     & Ada.Exceptions.Exception_Name (E) & ": "
                     & Ada.Exceptions.Exception_Message (E));
         end;
      end if;

      AHT.Websocket.Client.Close (C);
   end;

   --  Case 6: a timed-out Connect leaves the client dialable. The
   --  spec claims the attempt releases its admission and closes the
   --  half-built session like any other failure, so the retry below
   --  must be admitted — on the SAME client, which is what makes it a
   --  test of the release rather than of a fresh object.
   declare
      C   : AHT.Websocket.Client.Client_Type;
      Msg : AHT.Websocket.Client.Message_Type;
   begin
      begin
         AHT.Websocket.Client.Connect
           (C, Stall_WS, Upgrade_Deadline => 1.0);
         Fail ("retry-after-timeout: the stalled dial did not time out");
      exception
         when AHT.Transport.Timeout_Error =>
            null;  --  expected
      end;

      if AHT.Websocket.Client.Is_Open (C) then
         Fail ("retry-after-timeout: Is_Open true after a timed-out "
               & "Connect");
      end if;

      begin
         AHT.Websocket.Client.Connect (C, Echo_WS);
         AHT.Websocket.Client.Send_Text (C, "redialled");
         AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);
         if Msg.Kind /= AHT.Websocket.Text_Message then
            Fail ("retry-after-timeout: Kind = " & Msg.Kind'Image);
         elsif To_String (Msg.Payload) /= "redialled" then
            Fail ("retry-after-timeout: payload = """
                  & To_String (Msg.Payload) & """");
         end if;
         AHT.Websocket.Client.Close (C);
      exception
         when E : others =>
            Fail ("retry-after-timeout: redial raised "
                  & Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E)
                  & " — the timed-out attempt did not release its "
                  & "admission");
      end;
   end;

   --  Cases 7 to 9 cover the fourth bound, Resolve_Timeout, which is
   --  the one that cannot be reached with a fixture: the wait it
   --  bounds happens before any socket exists. They drive it through
   --  the same C seam test_dns uses, installed here so the path under
   --  test is the real one — Client.Connect to TCP/TLS.Connect to
   --  AHT.DNS to the resolver — with only the lookup replaced.
   --
   --  The fake answers with 127.0.0.1, which is what makes case 8 an
   --  end-to-end check rather than a mock: the dial names a host that
   --  does not exist, and reaches the echo fixture anyway, because
   --  the address the resolver returned is the address that was used.

   --  Case 7: a resolver that stalls must not park the dial. The host
   --  name is deliberately one that could never resolve for real, so
   --  a build that bypassed the seam fails here rather than passing
   --  against an accidental answer.
   Install_Fake (3_000, 1);
   declare
      C       : AHT.Websocket.Client.Client_Type;
      Started : constant Ada.Real_Time.Time := Ada.Real_Time.Clock;
      Took    : Duration;
   begin
      AHT.Websocket.Client.Connect
        (C, "ws://nonexistent.invalid:8765/", Resolve_Timeout => 0.5);
      Fail ("resolve-deadline: Connect returned normally against a "
            & "resolver that never answers");
      AHT.Websocket.Client.Close (C);
   exception
      when AHT.Transport.Timeout_Error =>
         Took := Ada.Real_Time.To_Duration (Ada.Real_Time.Clock - Started);
         if Took < 0.498 then
            Fail ("resolve-deadline: returned after"
                  & Duration'Image (Took)
                  & "s, before the budget could have expired");
         elsif Took > 3.0 then
            Fail ("resolve-deadline: took" & Duration'Image (Took)
                  & "s — bounded, but not by this budget");
         end if;
      when E : others =>
         Fail ("resolve-deadline: expected Timeout_Error, got "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E));
   end;

   --  That dial left a worker still inside the fake, and the next
   --  case reinstalls it with different settings. Those settings are
   --  plain globals, so writing them while the outgoing worker is
   --  still reading them is a data race — benign in its effect here,
   --  since the worker's answer is already discarded, but a race all
   --  the same and squarely in what dns_asan.sh's UBSan pass looks
   --  for. Waiting for the worker removes it rather than reasoning
   --  about why it would not matter. test_dns waits at the same
   --  point, for the same reason.
   declare
      Before : constant Interfaces.C.int := Fake_Completions;
      Waited : Duration := 0.0;
   begin
      while Fake_Completions = Before and then Waited < 10.0 loop
         delay 0.1;
         Waited := Waited + 0.1;
      end loop;
      if Fake_Completions = Before then
         Fail ("resolve-deadline: the abandoned lookup never completed "
               & "within" & Duration'Image (Waited)
               & "s — the worker was lost, not abandoned");
      end if;
   end;

   --  Case 8: and the addresses it returns are the ones dialled.
   --  Without this, case 7 would pass equally against a client that
   --  always failed to resolve.
   Install_Fake (0, 1);
   declare
      C   : AHT.Websocket.Client.Client_Type;
      Msg : AHT.Websocket.Client.Message_Type;
   begin
      AHT.Websocket.Client.Connect
        (C, "ws://nonexistent.invalid:8765/", Resolve_Timeout => 5.0);
      AHT.Websocket.Client.Send_Text (C, "resolved");
      AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);
      if To_String (Msg.Payload) /= "resolved" then
         Fail ("resolve-used: payload = """
               & To_String (Msg.Payload) & """");
      end if;
      AHT.Websocket.Client.Close (C);
   exception
      when E : others =>
         Fail ("resolve-used: dialling a name that resolves to "
               & "127.0.0.1 raised "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E));
   end;

   --  Case 9: an IP literal is not resolved at all. The stalling fake
   --  from case 7 is reinstalled and would hang any dial that
   --  consulted it; a literal URL must connect regardless, which is
   --  what proves the short-circuit rather than assuming it.
   Install_Fake (30_000, 1);
   declare
      C   : AHT.Websocket.Client.Client_Type;
      Msg : AHT.Websocket.Client.Message_Type;
   begin
      AHT.Websocket.Client.Connect (C, Echo_WS, Resolve_Timeout => 1.0);
      AHT.Websocket.Client.Send_Text (C, "literal");
      AHT.Websocket.Client.Receive (C, Msg, Timeout => 5.0);
      if To_String (Msg.Payload) /= "literal" then
         Fail ("literal-skips-resolve: payload = """
               & To_String (Msg.Payload) & """");
      end if;
      AHT.Websocket.Client.Close (C);
   exception
      when E : others =>
         Fail ("literal-skips-resolve: dialling an IP literal raised "
               & Ada.Exceptions.Exception_Name (E) & ": "
               & Ada.Exceptions.Exception_Message (E)
               & " — the resolver was consulted for an address that "
               & "needed no lookup");
   end;

   Restore_Real;

   if Failures = 0 then
      Put_Line ("test_ws_connect_bounds: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_connect_bounds:" & Failures'Image
                & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Connect_Bounds;
