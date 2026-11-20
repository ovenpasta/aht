--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Environment_Variables;

with AHT.PEM;
with AHT.Root_Store;

package body AHT.Transport.TLS.Anchors is

   function Checked_PEM
     (Insecure         : Boolean;
      CA_Path          : String;
      CA_PEM           : String;
      Use_System_Roots : Boolean) return String
   is
      Chosen : constant Natural :=
        Boolean'Pos (CA_Path /= "") + Boolean'Pos (CA_PEM /= "")
        + Boolean'Pos (Use_System_Roots);
   begin
      if Chosen > 1 then
         raise TLS_Error
           with "TLS connect: CA_Path, CA_PEM and Use_System_Roots are "
             & "mutually exclusive; choose one source of trust anchors";
      end if;

      if CA_PEM /= "" then
         declare
            Problem : constant String := AHT.PEM.Bundle_Problem (CA_PEM);
         begin
            if Problem /= "" then
               raise TLS_Error
                 with "TLS connect (CA_PEM): " & Problem
                   & "; the bundle is rejected whole rather than in "
                   & "part";
            end if;
         end;
         return CA_PEM;
      end if;

      if Chosen = 0 then
         if Insecure then
            return "";
         end if;
         raise TLS_Error
           with "TLS connect: no trust anchors configured; set CA_Path, "
             & "CA_PEM or Use_System_Roots, or Insecure to skip "
             & "certificate verification";
      end if;

      if CA_Path /= "" or else Insecure then
         return "";
      end if;

      declare
         function Env (Name : String) return String is
           (if Ada.Environment_Variables.Exists (Name)
            then Ada.Environment_Variables.Value (Name)
            else "");

         R : constant AHT.Root_Store.Roots := AHT.Root_Store.Load;

         Overridden : constant String :=
           (if Env ("SSL_CERT_FILE") = "" and then Env ("SSL_CERT_DIR") = ""
            then ""
            else " (SSL_CERT_FILE=""" & Env ("SSL_CERT_FILE")
                 & """, SSL_CERT_DIR=""" & Env ("SSL_CERT_DIR")
                 & """ replace the platform default)");
      begin
         if R.Truncated then
            raise TLS_Error
              with "TLS connect (Use_System_Roots): the platform trust "
                & "store exceeds the limits of AHT.Root_Store" & Overridden
                & "; it is rejected whole rather than in part";
         end if;
         if R.Count = 0 then
            raise TLS_Error
              with "TLS connect (Use_System_Roots): no certificate found "
                & "in the platform trust store" & Overridden;
         end if;
         return AHT.Root_Store.SU.To_String (R.PEM);
      end;
   end Checked_PEM;

end AHT.Transport.TLS.Anchors;
