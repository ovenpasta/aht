--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

package body AHT.Guarded_New is

   protected body Gate is
      procedure Allocate (Into : access Object_Access) is
      begin
         Into.all := new Object;
      end Allocate;
   end Gate;

end AHT.Guarded_New;
