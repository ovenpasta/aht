--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

package body AHT.Log.Tag is

   function Enabled (Lvl : Level) return Boolean is
     (Is_Enabled (Lvl, Subsystem));

   procedure Trace (Message : String) is
   begin
      Emit (AHT.Log.Trace, Subsystem, Message);
   end Trace;

   procedure Debug (Message : String) is
   begin
      Emit (AHT.Log.Debug, Subsystem, Message);
   end Debug;

   procedure Info (Message : String) is
   begin
      Emit (AHT.Log.Info, Subsystem, Message);
   end Info;

   procedure Warning (Message : String) is
   begin
      Emit (AHT.Log.Warning, Subsystem, Message);
   end Warning;

   procedure Error (Message : String) is
   begin
      Emit (AHT.Log.Error, Subsystem, Message);
   end Error;

end AHT.Log.Tag;
