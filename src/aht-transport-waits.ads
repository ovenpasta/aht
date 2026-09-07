--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with GNAT.Sockets;

--  The one piece of Check_Selector's contract that is easy to get
--  wrong, in its own unit so a test can drive it without a socket.
--
--  GNAT.Sockets.Forever is a SENTINEL, not a duration: it is mapped to
--  a null timeval, i.e. a genuinely unbounded wait ("No timeout or
--  Forever is indicated by a null timeval pointer", g-socket.adb). Its
--  numeric value is only Duration'Last where MAX_tv_sec is enormous;
--  on Windows select takes a 32-bit millisecond timeout, so Forever is
--  2**32/1000 -- about 49.7 days -- and Timeval_Duration ends there.
--
--  Two mistakes follow from that, and this unit exists to make both
--  impossible to make by accident:
--
--    * Passing Duration'Last for "no deadline" raises Constraint_Error
--      wherever Forever is smaller than Duration'Last. It did, on
--      Windows, at the first write.
--    * Clamping a long but FINITE budget up to Forever turns a
--      deadline into an infinite park, and the Expired branch that
--      exists to notice never runs.
--  Public, and deliberately, on the same footing as
--  AHT.Websocket.Send_Guards and AHT.Websocket.Handoffs: test_waits
--  drives this exact function from its own binary, and a private
--  child would need a descendant test to do it. It is therefore
--  supported surface, GNAT.Sockets.Selector_Duration in the profile
--  included -- that type is already unavoidable for anyone calling
--  Check_Selector, which is the only reason to want this.
package AHT.Transport.Waits is

   --  The largest wait that is still finite. A bounded operation must
   --  never be given anything above this.
   Longest_Finite : constant GNAT.Sockets.Selector_Duration :=
     GNAT.Sockets.Selector_Duration'Pred (GNAT.Sockets.Forever);

   --  A wait for an operation that HAS a deadline. Never returns the
   --  sentinel, whatever it is given -- including Duration'Last. A
   --  budget longer than Longest_Finite is served in chunks; the
   --  caller re-parks after rechecking its absolute deadline.
   function Bounded
     (D : Duration) return GNAT.Sockets.Selector_Duration
   is (if D <= GNAT.Sockets.Immediate then GNAT.Sockets.Immediate
       elsif D >= Longest_Finite then Longest_Finite
       else GNAT.Sockets.Selector_Duration (D));

end AHT.Transport.Waits;
