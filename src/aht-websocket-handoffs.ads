--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  The record that a generation's session changed hands from the
--  connecting task to the receiver, so the connecting task's cleanup
--  knows not to free it. Recorded inside a protected action: abort is
--  deferred there, so the record is either complete or never began;
--  recorded by the caller afterwards, a pending abort could land
--  between the two and the session would be freed twice. A separate
--  public unit so test_ws_handoff drives this exact type.
package AHT.Websocket.Handoffs is

   protected type Handoff is

      --  Records that generation Gen changed hands. Monotone: an
      --  attempt's cleanup may run after a later attempt has
      --  published, and its question must stay answerable.
      procedure Record_Taken (Gen : Positive);

      --  Whether generation Gen was handed over. True once Gen or any
      --  later generation has been recorded.
      function Taken (Gen : Positive) return Boolean;

      --  Diagnostics, not control primitives; never gate a decision on
      --  them. Records lets a test confirm that a recording it
      --  arranged completed, rather than inferring that from a delay.
      --  Both saturate at Natural'Last rather than overflowing.
      function Records return Natural;
      function High_Water return Natural;

   private
      Highest : Natural := 0;
      Count   : Natural := 0;
   end Handoff;

end AHT.Websocket.Handoffs;
