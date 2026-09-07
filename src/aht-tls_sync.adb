--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

package body AHT.TLS_Sync is

   protected body Lock_Type is
      entry Seize when not Locked is
      begin
         Locked := True;
      end Seize;
      procedure Release is
      begin
         Locked := False;
      end Release;
   end Lock_Type;

   protected body Coordinator_Type is

      procedure Try_Claim_Or_Arm (Granted : out Boolean) is
      begin
         if not Feeder_Claimed then
            Feeder_Claimed := True;
            Granted := True;
         else
            Granted := False;
            Armed   := True;
            --  An event that already happened opens the barrier now.
            if Is_EOF or Is_Fatal then
               Fired := True;
            end if;
         end if;
      end Try_Claim_Or_Arm;

      procedure Release_Feeder is
      begin
         Feeder_Claimed := False;
         if Armed then
            Fired := True;
         end if;
      end Release_Feeder;

      entry Await_Wakeup when Fired is
      begin
         Armed := False;
         Fired := False;
      end Await_Wakeup;

      procedure Disarm is
      begin
         Armed := False;
         Fired := False;
      end Disarm;

      procedure Latch_EOF is
      begin
         Is_EOF := True;
         if Armed then
            Fired := True;
         end if;
      end Latch_EOF;

      procedure Latch_Fatal is
      begin
         Is_Fatal := True;
         if Armed then
            Fired := True;
         end if;
      end Latch_Fatal;

      function EOF return Boolean is (Is_EOF);
      function Fatal return Boolean is (Is_Fatal);

      procedure Bump_Abort is
      begin
         Epoch := Epoch + 1;
         if Armed then
            Fired := True;
         end if;
      end Bump_Abort;

      function Abort_Epoch return Epoch_Type is (Epoch);

   end Coordinator_Type;

end AHT.TLS_Sync;
