--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

package body AHT.Transport is

   overriding procedure Finalize (Self : in out Transport_Type) is
   begin
      Close (Transport_Type'Class (Self));
   exception
      when others =>
         null;
   end Finalize;

end AHT.Transport;
