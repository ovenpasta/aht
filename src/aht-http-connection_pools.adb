--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Characters.Handling;
with Ada.Unchecked_Deallocation;

with AHT.Guarded_New;

package body AHT.HTTP.Connection_Pools is

   use Ada.Real_Time;
   use Ada.Strings.Unbounded;
   use type AHT.URL.Scheme_Kind;

   package New_TCP is new AHT.Guarded_New
     (AHT.Transport.TCP.TCP_Transport, TCP_Access);
   package New_TLS is new AHT.Guarded_New
     (AHT.Transport.TLS.TLS_Transport, TLS_Access);

   procedure Free is new Ada.Unchecked_Deallocation
     (AHT.Transport.TCP.TCP_Transport, TCP_Access);
   procedure Free is new Ada.Unchecked_Deallocation
     (AHT.Transport.TLS.TLS_Transport, TLS_Access);
   procedure Free is new Ada.Unchecked_Deallocation
     (Pool_State, Pool_State_Access);

   function Normalized (Where : Endpoint) return Endpoint is
     ((Where with delta
         Host => To_Unbounded_String
           (Ada.Characters.Handling.To_Lower (To_String (Where.Host)))));

   ---------------------------------------------------------------------
   --  Connection
   ---------------------------------------------------------------------

   function Is_Empty (C : Connection) return Boolean is
     (C.TCP = null and then C.TLS = null);

   function Transport
     (C : Connection) return AHT.Transport.Transport_Access is
     (if C.TCP /= null then AHT.Transport.Transport_Access (C.TCP)
      else AHT.Transport.Transport_Access (C.TLS));

   procedure Allocate (C : out Connection; Scheme : AHT.URL.Scheme_Kind) is
   begin
      C := (TCP => null, TLS => null);
      if Scheme = AHT.URL.HTTP then
         declare
            P : aliased TCP_Access;
         begin
            New_TCP.Gate.Allocate (P'Access);
            C.TCP := P;
         end;
      else
         declare
            P : aliased TLS_Access;
         begin
            New_TLS.Gate.Allocate (P'Access);
            C.TLS := P;
         end;
      end if;
   end Allocate;

   procedure Discard (C : in out Connection) is
   begin
      --  Close never raises past its own handler (Transport.Finalize
      --  relies on that too), but a discard must not leak on a
      --  surprise, so guard each step.
      if C.TCP /= null then
         begin
            C.TCP.Close;
         exception
            when others => null;
         end;
         Free (C.TCP);
      end if;
      if C.TLS /= null then
         begin
            C.TLS.Close;
         exception
            when others => null;
         end;
         Free (C.TLS);
      end if;
   end Discard;

   --  Holds one connection taken out of the pool for closing, so an
   --  abort between the pop and the close still closes it.
   type Holder is new Ada.Finalization.Limited_Controlled with record
      C : aliased Connection;
   end record;

   overriding procedure Finalize (Self : in out Holder);

   overriding procedure Finalize (Self : in out Holder) is
   begin
      Discard (Self.C);
   end Finalize;

   ---------------------------------------------------------------------
   --  Pool_State
   ---------------------------------------------------------------------

   protected body Pool_State is

      procedure Set_Timeout (Timeout : Duration) is
      begin
         Pool_State.Timeout := To_Time_Span (Timeout);
      end Set_Timeout;

      --  Doom every entry idle for Timeout or longer.
      procedure Expire is
         Now : constant Time := Clock;
         I   : Positive := 1;
      begin
         while I <= Natural (Idle.Length) loop
            if Now - Idle (I).Since >= Timeout then
               Doomed.Append (Idle (I).Conn);
               Idle.Delete (I);
            else
               I := I + 1;
            end if;
         end loop;
      end Expire;

      procedure Take
        (Where : Endpoint;
         C     : not null access Connection;
         Found : out Boolean) is
      begin
         Expire;
         Found := False;
         --  Newest first: the last connection released is the one
         --  least likely to have been closed by the peer.
         for I in reverse 1 .. Natural (Idle.Length) loop
            if Idle (I).Where = Where then
               C.all := Idle (I).Conn;
               Idle.Delete (I);
               Found := True;
               return;
            end if;
         end loop;
      end Take;

      procedure Put
        (Where : Endpoint;
         C     : not null access Connection)
      is
         Same_Host : Natural := 0;
      begin
         Expire;

         --  Entries are in release order, so the first match is the
         --  longest idle.
         for E of Idle loop
            if E.Where = Where then
               Same_Host := Same_Host + 1;
            end if;
         end loop;
         if Same_Host >= Max_Per_Host then
            for I in 1 .. Natural (Idle.Length) loop
               if Idle (I).Where = Where then
                  Doomed.Append (Idle (I).Conn);
                  Idle.Delete (I);
                  exit;
               end if;
            end loop;
         end if;
         if Natural (Idle.Length) >= Max_Total then
            Doomed.Append (Idle.First_Element.Conn);
            Idle.Delete_First;
         end if;

         Idle.Append
           (Idle_Entry'(Where => Where, Conn => C.all, Since => Clock));
         C.all := (TCP => null, TLS => null);
      end Put;

      procedure Doom_All is
      begin
         for E of Idle loop
            Doomed.Append (E.Conn);
         end loop;
         Idle.Clear;
      end Doom_All;

      procedure Pop_Doomed
        (C   : not null access Connection;
         Got : out Boolean) is
      begin
         Got := not Doomed.Is_Empty;
         if Got then
            C.all := Doomed.Last_Element;
            Doomed.Delete_Last;
         end if;
      end Pop_Doomed;

      function Count return Natural is (Natural (Idle.Length));

      procedure Retain is
      begin
         Refs := Refs + 1;
      end Retain;

      procedure Release_Ref (Last : out Boolean) is
      begin
         Refs := Refs - 1;
         Last := Refs = 0;
      end Release_Ref;

   end Pool_State;

   --  Close everything the pool has pushed out.
   procedure Reap (State : Pool_State_Access) is
      Got : Boolean;
   begin
      loop
         declare
            H : Holder;
         begin
            State.Pop_Doomed (H.C'Access, Got);
         end;
         exit when not Got;
      end loop;
   end Reap;

   ---------------------------------------------------------------------
   --  Pool_Ref
   ---------------------------------------------------------------------

   function Create
     (Max_Idle_Per_Host : Positive := 4;
      Max_Idle          : Positive := 32;
      Idle_Timeout      : Duration := 30.0) return Pool_Ref is
   begin
      return R : Pool_Ref do
         R.State := new Pool_State (Max_Idle_Per_Host, Max_Idle);
         R.State.Set_Timeout (Idle_Timeout);
      end return;
   end Create;

   function Is_Null (Self : Pool_Ref) return Boolean is (Self.State = null);

   function Idle_Count (Self : Pool_Ref) return Natural is
     (Self.State.Count);

   procedure Clear (Self : Pool_Ref) is
   begin
      Self.State.Doom_All;
      Reap (Self.State);
   end Clear;

   procedure Acquire
     (Self  : Pool_Ref;
      Where : Endpoint;
      C     : not null access Connection;
      Found : out Boolean) is
   begin
      Self.State.Take (Normalized (Where), C, Found);
      Reap (Self.State);
   end Acquire;

   procedure Release
     (Self  : Pool_Ref;
      Where : Endpoint;
      C     : not null access Connection) is
   begin
      Self.State.Put (Normalized (Where), C);
      Reap (Self.State);
   end Release;

   overriding procedure Adjust (Self : in out Pool_Ref) is
   begin
      if Self.State /= null then
         Self.State.Retain;
      end if;
   end Adjust;

   overriding procedure Finalize (Self : in out Pool_Ref) is
      State : Pool_State_Access := Self.State;
      Last  : Boolean;
   begin
      --  Cleared first: Finalize may run twice on one object.
      Self.State := null;
      if State = null then
         return;
      end if;
      State.Release_Ref (Last);
      if Last then
         State.Doom_All;
         Reap (State);
         Free (State);
      end if;
   end Finalize;

end AHT.HTTP.Connection_Pools;
