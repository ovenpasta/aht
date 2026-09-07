--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Cross-cutting log facade. Silent by default: the library only
--  emits output when the caller installs a sink. See docs/log.md for
--  the design rationale.

package AHT.Log is

   type Level is (Trace, Debug, Info, Warning, Error);

   type Sink_Callback is access procedure
     (Lvl       : Level;
      Subsystem : String;
      Message   : String);

   procedure Set_Sink (Cb : Sink_Callback);
   --  Install the sink that receives every Emit with a level above
   --  the active threshold. Passing null restores the silent state.

   procedure Set_Default_Level (Lvl : Level);
   --  Default minimum level applied to any subsystem that does not
   --  have an explicit override. Initial value: Info.

   procedure Set_Subsystem_Level (Subsystem : String; Lvl : Level);
   --  Per-subsystem override. Wins over the default for that
   --  subsystem only.

   procedure Clear_Subsystem_Level (Subsystem : String);
   --  Drop a per-subsystem override so the subsystem falls back to
   --  the default level again.

   function Is_Enabled
     (Lvl : Level; Subsystem : String) return Boolean;
   --  True if a message at Lvl for Subsystem would reach the sink.
   --  Guard expensive formatting with this.

   procedure Emit
     (Lvl       : Level;
      Subsystem : String;
      Message   : String);
   --  If Is_Enabled (Lvl, Subsystem) and a sink is installed, call
   --  the sink with the three arguments verbatim. No allocation on
   --  the drop path.

   --  Ready-made sinks ------------------------------------------------

   procedure Stderr_Sink
     (Lvl       : Level;
      Subsystem : String;
      Message   : String);
   --  Writes "<LEVEL> [<subsystem>] <message>" to Standard_Error,
   --  one record per call, terminated by a newline.

   function Synchronized_Sink
     (Inner : Sink_Callback) return Sink_Callback;
   --  Thread-safe wrapper around Inner: concurrent Emit calls are
   --  serialized so records do not interleave. Inner need not be
   --  thread-safe. Only one wrap is active at a time: the returned
   --  value is a module-level trampoline delegating to the most
   --  recently wrapped Inner. A second call with a different non-null
   --  Inner while a wrap is active raises Program_Error. Passing null
   --  clears the wrap; the same Inner again returns the same
   --  trampoline.

end AHT.Log;
