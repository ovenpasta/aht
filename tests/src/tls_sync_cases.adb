with Ada.Real_Time; use Ada.Real_Time;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.TLS_Sync;

package body TLS_Sync_Cases is

   use type AHT.TLS_Sync.Epoch_Type;

   function Run (Label : String) return Natural is
      Failures : Natural := 0;

      procedure Fail (Msg : String) is
      begin
         Put_Line (Label & ": FAIL — " & Msg);
         Failures := Failures + 1;
      end Fail;

      Coord   : AHT.TLS_Sync.Coordinator_Type;
      Granted : Boolean;
   begin
      --  A1: the claim is unique; a second claimant arms instead, and
      --  releasing the claim fires the latch.
      Coord.Try_Claim_Or_Arm (Granted);
      if not Granted then
         Fail ("A1: first claim not granted");
      end if;
      Coord.Try_Claim_Or_Arm (Granted);
      if Granted then
         Fail ("A1: second claim granted while held");
      end if;
      Coord.Release_Feeder;
      select
         Coord.Await_Wakeup;
      else
         Fail ("A1: latch not fired by Release_Feeder");
      end select;

      --  A2: Bump_Abort wakes a parked waiter, and the woken task can
      --  see the epoch changed. The claim is taken BEFORE the waiter
      --  task activates, so the waiter deterministically arms.
      Coord.Try_Claim_Or_Arm (Granted);
      if not Granted then
         Fail ("A2: main could not take the claim");
      end if;
      declare
         Epoch0 : constant AHT.TLS_Sync.Epoch_Type := Coord.Abort_Epoch;
         Woke   : Boolean := False with Volatile;
         Timed  : Boolean := False with Volatile;

         task Waiter;
         task body Waiter is
            G : Boolean;
         begin
            Coord.Try_Claim_Or_Arm (G);   --  main holds it: arms
            if G then
               Coord.Release_Feeder;      --  cannot happen; A2 fails
               Timed := True;
            else
               select
                  Coord.Await_Wakeup;
                  Woke := True;
               or
                  delay 5.0;
                  Coord.Disarm;
                  Timed := True;
               end select;
            end if;
         end Waiter;
      begin
         delay 0.2;                       --  let Waiter park
         Coord.Bump_Abort;
         while not (Woke or Timed) loop   --  join via flags
            delay 0.01;
         end loop;
         if not Woke then
            Fail ("A2: abort did not wake the parked waiter");
         end if;
         if Coord.Abort_Epoch = Epoch0 then
            Fail ("A2: abort epoch unchanged after Bump_Abort");
         end if;
         Coord.Release_Feeder;
      end;

      --  A3: a parked waiter that nobody signals must hit its own
      --  deadline rather than wait forever.
      Coord.Try_Claim_Or_Arm (Granted);
      if not Granted then
         Fail ("A3: main could not take the claim");
      end if;
      declare
         Timed : Boolean := False with Volatile;

         task Sleeper;
         task body Sleeper is
            G : Boolean;
         begin
            Coord.Try_Claim_Or_Arm (G);
            if G then
               Coord.Release_Feeder;      --  cannot happen; A3 fails
            else
               select
                  Coord.Await_Wakeup;
               or
                  delay until Clock + To_Time_Span (0.3);
                  Coord.Disarm;
                  Timed := True;
               end select;
            end if;
         end Sleeper;
      begin
         delay 1.0;                       --  past the 0.3 s bound
         if not Timed then
            Fail ("A3: parked waiter did not time out");
         end if;
         Coord.Release_Feeder;
      end;

      --  A4: the wake path the engines actually depend on — a writer
      --  parked while the reader owns the claim is released by the
      --  reader's Release_Feeder and can then claim the socket itself.
      Coord.Try_Claim_Or_Arm (Granted);
      if not Granted then
         Fail ("A4: main could not take the claim");
      end if;
      declare
         Claimed : Boolean := False with Volatile;
         Failed  : Boolean := False with Volatile;

         task Follower;
         task body Follower is
            G : Boolean;
         begin
            Coord.Try_Claim_Or_Arm (G);
            if G then
               Coord.Release_Feeder;      --  cannot happen; A4 fails
               Failed := True;
            else
               select
                  Coord.Await_Wakeup;
                  Coord.Try_Claim_Or_Arm (G);
                  if G then
                     Claimed := True;
                     Coord.Release_Feeder;
                  else
                     Failed := True;
                  end if;
               or
                  delay 5.0;
                  Coord.Disarm;
                  Failed := True;
               end select;
            end if;
         end Follower;
      begin
         delay 0.2;                       --  let Follower park
         Coord.Release_Feeder;            --  hand the socket over
         while not (Claimed or Failed) loop
            delay 0.01;
         end loop;
         if not Claimed then
            Fail ("A4: waiter woken by Release_Feeder could not claim");
         end if;
      end;

      return Failures;
   end Run;

end TLS_Sync_Cases;
