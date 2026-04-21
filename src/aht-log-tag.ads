--  Generic shortcut bound to a specific subsystem. Instantiate once
--  per unit body, typically as:
--
--     package Log is new AHT.Log.Tag ("tcp");
--
--  Call sites then read as Log.Debug ("..."), Log.Error ("...") with
--  the subsystem name baked in at the instantiation point.

generic
   Subsystem : String;
package AHT.Log.Tag is

   function Enabled (Lvl : Level) return Boolean with Inline;

   procedure Trace   (Message : String) with Inline;
   procedure Debug   (Message : String) with Inline;
   procedure Info    (Message : String) with Inline;
   procedure Warning (Message : String) with Inline;
   procedure Error   (Message : String) with Inline;

end AHT.Log.Tag;
