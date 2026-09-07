--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Finalization;
with System;

--  Serialization of frame writes on one connection, plus the scope
--  guard that pairs taking the latch with giving it back. A separate
--  unit so test_ws_send_guard drives these exact types.
package AHT.Websocket.Send_Guards is

   --  Acquire / Release_If_Owner serialize socket writes across
   --  tasks; the Write itself runs outside the lock. Ownership is
   --  recorded inside the protected action that takes the latch and
   --  the release is conditional on it: a pending abort takes effect
   --  at the end of the action, before any assignment the caller
   --  makes, so a cancelled acquisition records nothing and a
   --  completed one is always released. Callers identify themselves
   --  by the address of their scope guard.
   protected type Send_Guard is
      entry     Acquire (Owner : System.Address);
      procedure Release_If_Owner (Owner : System.Address);

      --  Latched when a Close frame is written. Set and checked while
      --  holding the latch, so a Send_* that loses the Acquire race
      --  to a close observes it and raises instead of writing a data
      --  frame after the Close (RFC 6455 sec. 5.5.1).
      procedure Mark_Close_Sent;
      function  Close_Frame_Sent return Boolean;

      --  Diagnostics, not control primitives. Waiters is a snapshot
      --  and must never gate who gets the latch. Acquisitions
      --  saturates at Natural'Last; it lets a test confirm a handover
      --  without looking between the release and the abort.
      function  Is_Held return Boolean;
      function  Waiters return Natural;
      function  Acquisitions return Natural;
   private
      Busy       : Boolean := False;
      Taken      : Natural := 0;
      Held_By    : System.Address := System.Null_Address;
      Close_Sent : Boolean := False;
   end Send_Guard;

   --  Scope guard for one frame write. Take is a plain call, not
   --  Initialize: Initialize is abort-deferred (RM 9.8), and on GNAT
   --  an asynchronous transfer of control cannot interrupt a queued
   --  entry call made from it, so a close under an asynchronous
   --  select would hang behind a stuck writer. Finalize always runs.
   type Guard_Token (G : access Send_Guard) is
     new Ada.Finalization.Limited_Controlled with null record;

   procedure Take (T : in out Guard_Token);

   --  Bounded acquisition. Taken is False if the latch could not be
   --  had within Within, and then the token owns nothing and its
   --  release is a no-op. Within of 0.0 still takes a free latch.
   procedure Try_Take
     (T      : in out Guard_Token;
      Within : Duration;
      Taken  : out Boolean);

   overriding procedure Finalize (T : in out Guard_Token);

end AHT.Websocket.Send_Guards;
