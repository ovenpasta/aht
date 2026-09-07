--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

package body AHT.Websocket.Send_Guards is

   protected body Send_Guard is

      entry Acquire (Owner : System.Address) when not Busy is
      begin
         Busy    := True;
         Held_By := Owner;
         --  Saturating: a diagnostic counter that wrapped into
         --  Constraint_Error would take every subsequent send on the
         --  connection down with it.
         if Taken < Natural'Last then
            Taken := Taken + 1;
         end if;
      end Acquire;

      procedure Release_If_Owner (Owner : System.Address) is
         use type System.Address;
      begin
         --  Conditional: a caller whose acquisition was cancelled still
         --  runs its release, and must not free a latch somebody else
         --  is holding.
         if Busy and then Held_By = Owner then
            Busy    := False;
            Held_By := System.Null_Address;
         end if;
      end Release_If_Owner;

      procedure Mark_Close_Sent is
      begin
         Close_Sent := True;
      end Mark_Close_Sent;

      function Close_Frame_Sent return Boolean is (Close_Sent);

      function Is_Held return Boolean is (Busy);

      function Waiters return Natural is (Acquire'Count);

      function Acquisitions return Natural is (Taken);

   end Send_Guard;

   procedure Take (T : in out Guard_Token) is
   begin
      T.G.Acquire (T'Address);
   end Take;

   procedure Try_Take
     (T      : in out Guard_Token;
      Within : Duration;
      Taken  : out Boolean) is
   begin
      select
         T.G.Acquire (T'Address);
         Taken := True;
      or
         delay Within;
         Taken := False;
      end select;
   end Try_Take;

   overriding procedure Finalize (T : in out Guard_Token) is
   begin
      T.G.Release_If_Owner (T'Address);
   end Finalize;

end AHT.Websocket.Send_Guards;
