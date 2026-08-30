--  Per-phase timeout bounds on AHT.HTTP.Client.Client_Type.
--
--  Timeout_Seconds is one number applied to five phases separately,
--  so it cannot express "bound the dial tightly, but let the body
--  take as long as it takes". The Phase_Bound fields split it. These
--  cases pin the three properties that split has to have: an explicit
--  bound overrides the coarse one in both directions, and a bound on
--  one phase does not reach another.
--
--  Two fixtures, both required up:
--    * 127.0.0.1:8764 (server.py) — /slow withholds a 200 for
--      SLOW_DELAY = 3 s, so a 1 s read deadline must trip on it and a
--      6 s one must not; /hello answers at once, which is what makes
--      a zero budget the only possible cause of a timeout on it.
--    * 127.0.0.1:8767 (server_stall.py) — accepts TCP, then silence.
--      Over https:// that stalls the handshake.
--
--  Elapsed time is asserted only as a liveness backstop, never as the
--  evidence: every case is decided by the status code or the
--  exception identity, both of which are facts about what the client
--  did rather than about how long it took.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Real_Time; use Ada.Real_Time;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.HTTP.Client;
with AHT.HTTP.Response;
with AHT.Transport;

procedure Test_HTTP_Phase_Bounds is

   Slow_URL  : constant String := "http://127.0.0.1:8764/slow";
   Fast_URL  : constant String := "http://127.0.0.1:8764/hello";
   Stall_URL : constant String := "https://127.0.0.1:8767/hello";

   --  Generous: every case here either answers in about the 3 s
   --  server.py withholds /slow for, or raises well before it.
   --  Anything past this means a bound that should have applied did
   --  not, and the call effectively hung.
   Max_Wait : constant Duration := 30.0;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_http_phase_bounds: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Liveness backstop shared by every case.
   procedure Check_Prompt (Case_Name : String; Started : Time) is
      Elapsed : constant Duration := To_Duration (Clock - Started);
   begin
      if Elapsed > Max_Wait then
         Fail (Case_Name & ": took" & Elapsed'Image & "s (>"
               & Max_Wait'Image & "s) — the bound did not apply");
      end if;
   end Check_Prompt;

   --  Run a GET and assert it completed with 200 and the expected
   --  body. Used where the point is that a bound did NOT fire.
   procedure Expect_OK
     (Case_Name : String;
      C         : in out AHT.HTTP.Client.Client_Type;
      URL       : String;
      Expected  : String)
   is
      Started : constant Time := Clock;
      Resp    : AHT.HTTP.Response.Response_Type;
   begin
      Resp := AHT.HTTP.Client.Get (C, URL);
      Check_Prompt (Case_Name, Started);
      if Resp.Status /= 200 then
         Fail (Case_Name & ": status" & Resp.Status'Image
               & ", expected 200");
      elsif AHT.Bytes.To_String (Resp.Body_B) /= Expected then
         Fail (Case_Name & ": body """
               & AHT.Bytes.To_String (Resp.Body_B) & """");
      end if;
   exception
      when E : others =>
         Check_Prompt (Case_Name, Started);
         Fail (Case_Name & ": expected 200, got "
               & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E));
   end Expect_OK;

   --  Run a GET and assert it raised Timeout_Error. Used where the
   --  point is that a bound DID fire. A returned response is a
   --  failure even when it is a good one: it means nothing bounded
   --  the wait.
   procedure Expect_Timeout
     (Case_Name : String;
      C         : in out AHT.HTTP.Client.Client_Type;
      URL       : String)
   is
      Started : constant Time := Clock;
      Resp    : AHT.HTTP.Response.Response_Type;
   begin
      Resp := AHT.HTTP.Client.Get (C, URL);
      Check_Prompt (Case_Name, Started);
      Fail (Case_Name & ": returned status" & Resp.Status'Image
            & " instead of raising Timeout_Error");
   exception
      when AHT.Transport.Timeout_Error =>
         Check_Prompt (Case_Name, Started);
      when E : others =>
         Check_Prompt (Case_Name, Started);
         Fail (Case_Name & ": expected Timeout_Error, got "
               & Ada.Exceptions.Exception_Name (E) & " — "
               & Ada.Exceptions.Exception_Message (E)
               & " (are the 8764 and 8767 fixtures running?)");
   end Expect_Timeout;

   Expected_Slow : constant String := "slow, world" & ASCII.LF;

begin
   --  Case 1: widening. Timeout_Seconds alone would kill this read at
   --  1 s; Read_Deadline overrides it and the 3 s response arrives.
   declare
      C : AHT.HTTP.Client.Client_Type;
   begin
      C.Timeout_Seconds := 1;
      C.Read_Deadline   := AHT.HTTP.Client.Seconds (6.0);
      Expect_OK ("widen", C, Slow_URL, Expected_Slow);
   end;

   --  Case 2: the back-out of case 1, in the suite rather than by
   --  hand. Same client, same route, Read_Deadline left at Inherit —
   --  and now the 1 s coarse bound must kill it. Without this, case 1
   --  would pass just as well against a client that had no read
   --  deadline at all.
   declare
      C : AHT.HTTP.Client.Client_Type;
   begin
      C.Timeout_Seconds := 1;
      Expect_Timeout ("inherit", C, Slow_URL);
   end;

   --  Case 3: narrowing, and the vacuity check. Timeout_Seconds = 0
   --  arms no read deadline at all, so the only thing that can end
   --  this call is Read_Deadline. A build that ignored the field
   --  would return 200 here rather than fail to compile.
   declare
      C : AHT.HTTP.Client.Client_Type;
   begin
      C.Timeout_Seconds := 0;
      C.Read_Deadline   := AHT.HTTP.Client.Seconds (1.0);
      Expect_Timeout ("narrow", C, Slow_URL);
   end;

   --  Case 4: the case the split exists for. Nothing is bounded
   --  except the TLS handshake, which is the wait a caller who has
   --  disabled Timeout_Seconds to allow a long download still wants
   --  bounded. Against the stall fixture the handshake never
   --  completes, so an unbounded one hangs until the runner's cap
   --  kills the process.
   declare
      C : AHT.HTTP.Client.Client_Type;
   begin
      C.Timeout_Seconds    := 0;
      C.Insecure           := True;
      C.Handshake_Deadline := AHT.HTTP.Client.Seconds (1.0);
      Expect_Timeout ("handshake", C, Stall_URL);
   end;

   --  Case 5: scoping. A 1 s connect bound against a route that takes
   --  3 s to answer — the connect itself is immediate, so the only
   --  way this fails is if the bound leaked into the read.
   declare
      C : AHT.HTTP.Client.Client_Type;
   begin
      C.Timeout_Seconds := 0;
      C.Connect_Timeout := AHT.HTTP.Client.Seconds (1.0);
      Expect_OK ("scope", C, Slow_URL, Expected_Slow);
   end;

   --  Case 6: Seconds (0.0) is a zero budget, not a synonym for
   --  Unbounded — the one place the two knobs deliberately disagree,
   --  since Timeout_Seconds => 0 does mean no bound. The route
   --  answers immediately, so there is nothing slow here for a
   --  deadline to catch: a Timeout_Error can only come from the
   --  budget being zero, and reading Seconds (0.0) as "no bound"
   --  returns 200 instead.
   declare
      C : AHT.HTTP.Client.Client_Type;
   begin
      C.Timeout_Seconds := 0;
      C.Read_Deadline   := AHT.HTTP.Client.Seconds (0.0);
      Expect_Timeout ("zero", C, Fast_URL);
   end;

   if Failures = 0 then
      Put_Line ("test_http_phase_bounds: OK (6 cases)");
   else
      Put_Line ("test_http_phase_bounds:" & Failures'Image
                & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_HTTP_Phase_Bounds;
