--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with GNAT.Sockets;

--  Bounded waits for Check_Selector; a separate unit so test_waits
--  can drive them without a socket.
--
--  GNAT.Sockets.Forever is a sentinel mapped to a null timeval, an
--  unbounded wait. On Windows select takes a 32-bit millisecond
--  timeout, so Forever is about 49.7 days and Timeval_Duration ends
--  there. Passing Duration'Last there raises Constraint_Error, and
--  clamping a long finite budget up to Forever parks forever.
package AHT.Transport.Waits is

   --  The largest wait that is still finite. A bounded operation must
   --  never be given anything above this.
   Longest_Finite : constant GNAT.Sockets.Selector_Duration :=
     GNAT.Sockets.Selector_Duration'Pred (GNAT.Sockets.Forever);

   --  A wait for an operation that has a deadline. Never returns the
   --  sentinel, whatever it is given, Duration'Last included. A budget
   --  longer than Longest_Finite is served in chunks; the caller
   --  re-parks after rechecking its absolute deadline.
   function Bounded
     (D : Duration) return GNAT.Sockets.Selector_Duration
   is (if D <= GNAT.Sockets.Immediate then GNAT.Sockets.Immediate
       elsif D >= Longest_Finite then Longest_Finite
       else GNAT.Sockets.Selector_Duration (D));

end AHT.Transport.Waits;
