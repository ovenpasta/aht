--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Budget arithmetic for the close handshake.
--
--  Two expressions, kept out of the client so they can be checked
--  directly: what they guard is a difference of fractions of a
--  second, or a sentinel that only misbehaves at conversion time,
--  neither of which a socket test can observe reliably.
package AHT.Websocket.Budgets is

   pragma Pure;

   --  What the close frame's write gets when the caller's budget is
   --  exactly zero, and only then.
   --
   --  To a transport a zero deadline means "fail before parking", so
   --  even a frame going straight into an empty socket buffer would
   --  be refused. A budget of zero says not to wait for the peer's
   --  echo; it does not say to skip sending the Close frame.
   Close_Frame_Grace : constant Duration := 0.25;

   --  What is left of a budget after Spent has gone.
   --
   --  Duration'Last is the "no bound" sentinel the transports
   --  understand and passes through intact: Duration'Last minus a
   --  microsecond is not a sentinel but an enormous finite deadline,
   --  which overflows when converted to a point in time.
   --
   --  An exhausted budget returns zero rather than going negative,
   --  and an overspent one is not treated as credit.
   function Remaining (Budget, Spent : Duration) return Duration
   is (if Budget = Duration'Last then Duration'Last
       elsif Spent >= Budget then 0.0
       else Budget - Spent);

   --  What the close frame's write may spend.
   --
   --  Left is what Remaining says is available. The grace applies to
   --  a budget of exactly zero and nothing else: applied as a floor it
   --  would hand a caller asking for 0.05 a quarter second, and refill
   --  a budget already spent acquiring the send latch.
   function Close_Frame_Budget (Budget, Left : Duration) return Duration
   is (if Budget = 0.0 then Close_Frame_Grace else Left);

end AHT.Websocket.Budgets;
