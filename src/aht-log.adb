with Ada.Containers.Indefinite_Ordered_Maps;
with Ada.Text_IO;

package body AHT.Log is

   package Override_Maps is new Ada.Containers.Indefinite_Ordered_Maps
     (Key_Type     => String,
      Element_Type => Level);

   protected Config is
      procedure Set_Sink (Cb : Sink_Callback);
      procedure Set_Default_Level (Lvl : Level);
      procedure Set_Subsystem_Level (Subsystem : String; Lvl : Level);
      procedure Clear_Subsystem_Level (Subsystem : String);
      procedure Snapshot
        (Subsystem : String;
         Cb        : out Sink_Callback;
         Min_Lvl   : out Level);
   private
      Sink      : Sink_Callback := null;
      Default   : Level := Info;
      Overrides : Override_Maps.Map;
   end Config;

   protected body Config is

      procedure Set_Sink (Cb : Sink_Callback) is
      begin
         Sink := Cb;
      end Set_Sink;

      procedure Set_Default_Level (Lvl : Level) is
      begin
         Default := Lvl;
      end Set_Default_Level;

      procedure Set_Subsystem_Level (Subsystem : String; Lvl : Level) is
      begin
         Overrides.Include (Subsystem, Lvl);
      end Set_Subsystem_Level;

      procedure Clear_Subsystem_Level (Subsystem : String) is
      begin
         Overrides.Exclude (Subsystem);
      end Clear_Subsystem_Level;

      procedure Snapshot
        (Subsystem : String;
         Cb        : out Sink_Callback;
         Min_Lvl   : out Level)
      is
         C : constant Override_Maps.Cursor := Overrides.Find (Subsystem);
      begin
         Cb := Sink;
         if Override_Maps.Has_Element (C) then
            Min_Lvl := Override_Maps.Element (C);
         else
            Min_Lvl := Default;
         end if;
      end Snapshot;

   end Config;

   --  Synchronized_Sink machinery --------------------------------------
   --
   --  A single module-level Inner pointer (managed by Sync_Holder) plus
   --  a binary-mutex protected object (Sync_Mutex) used as a serializer.
   --  The trampoline reads Inner without holding the mutex, then takes
   --  the mutex only while calling Inner.all — Inner may block on I/O,
   --  and a blocking call inside a protected action would be a bounded
   --  error.

   protected Sync_Holder is
      procedure Set (Cb : Sink_Callback);
      function  Get return Sink_Callback;
   private
      Inner : Sink_Callback := null;
   end Sync_Holder;

   protected body Sync_Holder is
      procedure Set (Cb : Sink_Callback) is
      begin
         Inner := Cb;
      end Set;

      function Get return Sink_Callback is
      begin
         return Inner;
      end Get;
   end Sync_Holder;

   protected Sync_Mutex is
      entry Acquire;
      procedure Release;
   private
      Locked : Boolean := False;
   end Sync_Mutex;

   protected body Sync_Mutex is
      entry Acquire when not Locked is
      begin
         Locked := True;
      end Acquire;

      procedure Release is
      begin
         Locked := False;
      end Release;
   end Sync_Mutex;

   procedure Sync_Trampoline
     (Lvl : Level; Subsystem : String; Message : String);

   procedure Sync_Trampoline
     (Lvl : Level; Subsystem : String; Message : String)
   is
      Inner : constant Sink_Callback := Sync_Holder.Get;
   begin
      if Inner = null then
         return;
      end if;
      Sync_Mutex.Acquire;
      begin
         Inner.all (Lvl, Subsystem, Message);
      exception
         when others =>
            Sync_Mutex.Release;
            raise;
      end;
      Sync_Mutex.Release;
   end Sync_Trampoline;

   --  Public surface ----------------------------------------------------

   procedure Set_Sink (Cb : Sink_Callback) is
   begin
      Config.Set_Sink (Cb);
   end Set_Sink;

   procedure Set_Default_Level (Lvl : Level) is
   begin
      Config.Set_Default_Level (Lvl);
   end Set_Default_Level;

   procedure Set_Subsystem_Level (Subsystem : String; Lvl : Level) is
   begin
      Config.Set_Subsystem_Level (Subsystem, Lvl);
   end Set_Subsystem_Level;

   procedure Clear_Subsystem_Level (Subsystem : String) is
   begin
      Config.Clear_Subsystem_Level (Subsystem);
   end Clear_Subsystem_Level;

   function Is_Enabled (Lvl : Level; Subsystem : String) return Boolean is
      Cb      : Sink_Callback;
      Min_Lvl : Level;
   begin
      Config.Snapshot (Subsystem, Cb, Min_Lvl);
      return Cb /= null and then Lvl >= Min_Lvl;
   end Is_Enabled;

   procedure Emit
     (Lvl       : Level;
      Subsystem : String;
      Message   : String)
   is
      Cb      : Sink_Callback;
      Min_Lvl : Level;
   begin
      Config.Snapshot (Subsystem, Cb, Min_Lvl);
      if Cb /= null and then Lvl >= Min_Lvl then
         Cb.all (Lvl, Subsystem, Message);
      end if;
   end Emit;

   procedure Stderr_Sink
     (Lvl       : Level;
      Subsystem : String;
      Message   : String)
   is
      use Ada.Text_IO;
   begin
      Put_Line
        (Standard_Error,
         Level'Image (Lvl) & " [" & Subsystem & "] " & Message);
   end Stderr_Sink;

   function Synchronized_Sink
     (Inner : Sink_Callback) return Sink_Callback
   is
   begin
      Sync_Holder.Set (Inner);
      return Sync_Trampoline'Access;
   end Synchronized_Sink;

end AHT.Log;
