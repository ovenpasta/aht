--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Library-level filter functions for the field forms
--  (Client_Type.On_Redirect / On_Address), which cannot designate a
--  function nested in a test's main procedure. Each counts its calls.

with AHT.HTTP.Client;
with AHT.HTTP.Status;
with AHT.URL;

package Test_Filters is

   Redirect_Calls : Natural := 0;
   Address_Calls  : Natural := 0;

   function Refuse_Redirects
     (From, To : AHT.URL.URL_Type;
      Status   : AHT.HTTP.Status.Status_Code;
      Hop      : Positive) return AHT.HTTP.Client.Redirect_Decision;
   --  Refuse, always.

   function Refuse_Addresses (Host, Address : String) return Boolean;
   --  False, always.

end Test_Filters;
