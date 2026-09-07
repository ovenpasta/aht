--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Abort-deferred allocation gate for a single `new`.
--
--  GNAT attaches a heap object to its access type's collection before
--  initializing it, inside the runtime's global task lock
--  (Allocate_Any_Controlled, s-stposu.adb); releasing that lock is an
--  abort completion point (s-tasini.adb). An abort inside `new` leaves
--  an attached, uninitialized, unreachable object that library
--  finalization treats as real. Allocating inside a protected action
--  (abort-deferred throughout) closes the window: nothing allocated,
--  or Into holds a fully initialized object. Into is an access
--  parameter, not `out`: `out` copy-back happens after the action.
--  Generic so a body can instantiate it for a type visible only there.
private generic
   type Object is limited private;
   type Object_Access is access Object;
package AHT.Guarded_New is

   protected Gate is
      procedure Allocate (Into : access Object_Access);
      --  Into.all := new Object, as one abort-deferred action.
   end Gate;

end AHT.Guarded_New;
