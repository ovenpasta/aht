--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

package body AHT.Websocket.Handoffs is

   protected body Handoff is

      procedure Record_Taken (Gen : Positive) is
      begin
         --  Both updates are inside this action, so a caller aborted
         --  around the call sees either a complete record or none.
         if Gen > Highest then
            Highest := Gen;
         end if;
         if Count < Natural'Last then
            Count := Count + 1;
         end if;
      end Record_Taken;

      function Taken (Gen : Positive) return Boolean is (Highest >= Gen);

      function Records return Natural is (Count);
      function High_Water return Natural is (Highest);

   end Handoff;

end AHT.Websocket.Handoffs;
