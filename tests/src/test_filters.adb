--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

package body Test_Filters is

   function Refuse_Redirects
     (From, To : AHT.URL.URL_Type;
      Status   : AHT.HTTP.Status.Status_Code;
      Hop      : Positive) return AHT.HTTP.Client.Redirect_Decision
   is
      pragma Unreferenced (From, To, Status, Hop);
   begin
      Redirect_Calls := Redirect_Calls + 1;
      return AHT.HTTP.Client.Refuse;
   end Refuse_Redirects;

   function Refuse_Addresses (Host, Address : String) return Boolean is
      pragma Unreferenced (Host, Address);
   begin
      Address_Calls := Address_Calls + 1;
      return False;
   end Refuse_Addresses;

end Test_Filters;
