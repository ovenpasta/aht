--  Abort-deferred allocation gate for a single `new`.
--
--  GNAT attaches a heap object to its access type's collection BEFORE
--  the object is initialized, from inside the runtime's global task
--  lock (`Allocate_Any_Controlled`, steps 2 to 4 of `s-stposu.adb`),
--  and releasing that lock is an abort completion point
--  (`Task_Lock`/`Task_Unlock`, `s-tasini.adb`). An abort landing
--  anywhere inside a `new` -- the allocator call included -- is
--  therefore delivered with the object attached, wholly
--  uninitialized, and unreachable: the allocator never returned, so
--  no pointer to the object exists and no `Free` can be aimed at it.
--  It survives to library finalization, which finalizes it as though
--  it were real. See the note at
--  `AHT.Websocket.Client.Lifecycle_Controller.Create_Session`, which
--  closes the identical window for a session by the same construct.
--
--  A protected action is abort-deferred for its whole duration, so
--  performing the allocation inside one closes the window: either
--  nothing was allocated, or Into holds a fully-initialized object.
--  Into is an access parameter, never `out` -- an `out` parameter's
--  copy-back happens AFTER the protected action ends, which is
--  exactly where the abort lands, and would leave a complete object
--  that the aborted caller never receives a pointer to.
--
--  Generic over the object type and its access type so any caller
--  facing this hazard can instantiate it rather than hand-rolling the
--  protected wrapper, including one whose object type is not visible
--  outside its own body (as with the TLS backends' Backend_State,
--  Taft-amended and completed differently by each). A private child
--  of AHT because nothing about this utility is meant for consumers
--  of the library.
private generic
   type Object is limited private;
   type Object_Access is access Object;
package AHT.Guarded_New is

   protected Gate is
      procedure Allocate (Into : access Object_Access);
      --  Into.all := new Object, as one abort-deferred action.
   end Gate;

end AHT.Guarded_New;
