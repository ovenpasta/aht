--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  The trust choice of one Connect, checked the same way by both
--  backend bodies before anything is dialled.
private package AHT.Transport.TLS.Anchors is

   --  Raises TLS_Error when more than one of CA_Path, CA_PEM and
   --  Use_System_Roots is chosen (even under Insecure), when CA_PEM
   --  fails AHT.PEM.Bundle_Problem (even under Insecure), and when
   --  none is chosen and Insecure is False. Under Use_System_Roots
   --  and not Insecure, reads AHT.Root_Store and raises TLS_Error
   --  when it yields no certificate or was truncated by a limit.
   --
   --  Returns the PEM to install: CA_PEM itself, or the store's
   --  certificates under Use_System_Roots. Returns "" when CA_Path
   --  is the choice, or when Insecure leaves nothing to load.
   function Checked_PEM
     (Insecure         : Boolean;
      CA_Path          : String;
      CA_PEM           : String;
      Use_System_Roots : Boolean) return String;

end AHT.Transport.TLS.Anchors;
