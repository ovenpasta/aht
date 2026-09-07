--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.HTTP.Headers;

procedure Test_Headers is

   Failures : Natural := 0;

   procedure Check (OK : Boolean; Message : String) is
   begin
      if not OK then
         Put_Line ("FAIL: " & Message);
         Failures := Failures + 1;
      end if;
   end Check;

   procedure Check_Eq (Got, Want, Label : String) is
   begin
      if Got /= Want then
         Put_Line
           ("FAIL " & Label & ": got [" & Got & "] want [" & Want & "]");
         Failures := Failures + 1;
      end if;
   end Check_Eq;

begin
   declare
      H : AHT.HTTP.Headers.Map;
   begin
      H.Set ("Content-Type", "text/plain");
      Check (H.Contains ("content-type"), "case-insensitive contains");
      Check (H.Contains ("CONTENT-TYPE"), "uppercase contains");
      Check_Eq (H.Get ("Content-Type"), "text/plain", "get");

      --  Set replaces prior values.
      H.Set ("Content-Type", "application/json");
      Check_Eq (H.Get ("content-type"), "application/json", "set replaces");
      Check (H.Count = 1, "count after set replace");

      --  Append adds new values; Set-Cookie must NOT be comma-combined.
      H.Append ("Set-Cookie", "a=1");
      H.Append ("set-cookie", "b=2");
      Check (H.Count = 3, "count after 2 appends");
      declare
         Vs : constant AHT.HTTP.Headers.Value_List :=
           H.Values ("Set-Cookie");
      begin
         Check (Natural (Vs.Length) = 2, "Values returns 2 entries");
         Check_Eq (Vs (1), "a=1", "Values[1]");
         Check_Eq (Vs (2), "b=2", "Values[2]");
      end;

      --  Remove.
      H.Remove ("content-type");
      Check (not H.Contains ("Content-Type"), "remove by lowercase");
      Check (H.Count = 2, "count after remove");
   end;

   if Failures = 0 then
      Put_Line ("test_headers: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_headers: " & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_Headers;
