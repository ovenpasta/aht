--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Bounds on Websocket.Client.Connect: Resolve_Timeout,
--  Connect_Timeout, Handshake_Deadline and Upgrade_Deadline. Fixtures:
--  ws://127.0.0.1:8767/ is server_stall.py, which accepts TCP and
--  never speaks (the upgrade stalls); wss:// on the same port stalls
--  in the TLS handshake; ws://127.0.0.1:8765/ is the live echo fixture.
--
--  Cases:
--    1. Upgrade_Deadline 1.0 s ends the wait, elapsed in [1.0, 4.0]
--    2. Upgrade_Deadline 6.0 s, elapsed in [6.0, 12.0]
--    3. Handshake_Deadline bounds the TLS handshake
--    4. Connect_Timeout reaches TCP.Connect's pre-attempt budget check
--    5. the upgrade budget is disarmed after a successful upgrade
--    6. a timed-out Connect leaves the same client dialable
--    7. Resolve_Timeout ends a stalled resolver
--    8. the addresses the resolver returns are the ones dialled
--    9. an IP literal never consults the resolver
--
--  Covers:
--    - the wait tracks the value passed: the windows of cases 1 and 2
--      are disjoint, so no single fixed bound satisfies both
--    - Timeout_Error, not Transport_Error, proves the TCP connect
--      succeeded before the wait; every case rejects Transport_Error
--    - case 3 hangs (run_tests.sh TIMEOUT) if Handshake_Deadline is
--      not honoured, since Upgrade_Deadline is left at Duration'Last
--
--  Does not cover:
--    - a mid-connect stall for Connect_Timeout: needs an unroutable
--      peer; case 4 proves the parameter arrives, not that a stalled
--      connect is interrupted
--    - case 5 does not distinguish a real clear from a re-arm to a
--      large finite budget; that Set_*_Deadline (Duration'Last) clears
--      is the transports' contract, tested there
--    - a stall in the real getaddrinfo, as test_dns records
--
--  Validated by:
--    case 5 fails with both Set_*_Deadline (Duration'Last) calls at
--    the end of Connect removed: the receiver trips Timeout_Error
--    during the idle, so Is_Open is False before the send.

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
   --  Clock, so Ada.Real_Time is named explicitly. This one operator
   --  still has to be made visible for the subtraction in case 7.
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

   --  The resolver seam, as in test_dns. Used only by cases 7 to 9,
   --  and undone before the run ends.
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
   --  the upgrade must not park the caller. 1.0 s budget; elapsed
   --  must land in [1.0, 4.0].
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

   --  Case 2: the wait tracks the value passed. Same fixture, 6x the
   --  budget; elapsed must land in [6.0, 12.0]. Checked against
   --  constants, not against case 1: no single fixed bound satisfies
   --  both windows.
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
   --  Upgrade_Deadline is left at Duration'Last: the upgrade is never
   --  reached, so only Handshake_Deadline can end this dial.
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
   --  happens, so the target is the LIVE echo fixture. A
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
   --  attempt releases its admission and closes the half-built
   --  session, so the retry below must be admitted on the SAME client.
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

   --  Cases 7 to 9 cover Resolve_Timeout, whose wait happens before
   --  any socket exists. They install the C seam test_dns uses, so the
   --  path under test is the real one with only the lookup replaced.
   --  The fake answers with 127.0.0.1, so case 8 dials a host that
   --  does not exist and reaches the echo fixture anyway.

   --  Case 7: a resolver that stalls must not park the dial. The host
   --  name could never resolve for real, so a build that bypassed the
   --  seam fails here.
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
   --  case reinstalls it with different settings, which are plain
   --  globals: writing them while the worker reads them is a data
   --  race UBSan reports. Wait for the worker first.
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
   --  consulted it; a literal URL must connect regardless, which
   --  proves the short-circuit.
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
