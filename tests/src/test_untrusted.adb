--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.PEM;

package body Test_Untrusted is

   Fixture : constant String := "tests/server/certs/server.crt";

   function Read_File (Path : String) return String is
      F : File_Type;
      R : Unbounded_String;
   begin
      Open (F, In_File, Path);
      while not End_Of_File (F) loop
         Append (R, Get_Line (F));
         Append (R, ASCII.LF);
      end loop;
      Close (F);
      return To_String (R);
   exception
      when others =>
         if Is_Open (F) then
            Close (F);
         end if;
         return "";
   end Read_File;

   function Anchor_Problem return String is
      Other : constant String := Read_File (Other_File);
   begin
      if Other = "" then
         return Other_File & " is missing or empty; run "
           & "scripts/generate_cert.sh from the repo root";
      elsif AHT.PEM.Bundle_Problem (Other) /= "" then
         return Other_File & ": " & AHT.PEM.Bundle_Problem (Other);
      elsif Ada.Strings.Fixed.Count (Other, "-----BEGIN CERTIFICATE-----")
            /= 1
      then
         return Other_File & " holds more than one certificate";
      elsif Other = Read_File (Fixture) then
         return Other_File & " is the fixture's own certificate";
      end if;
      return "";
   end Anchor_Problem;

   --  Both backends prefix every handshake failure with this; trust
   --  loading and choice report "TLS connect".
   function Is_Handshake_Rejection (Msg : String) return Boolean is
     (Ada.Strings.Fixed.Index (Msg, "TLS handshake") /= 0);

   function Count_Dial (Host, Address : String) return Boolean is
      pragma Unreferenced (Host, Address);
   begin
      Dials := Dials + 1;
      return True;
   end Count_Dial;

end Test_Untrusted;
