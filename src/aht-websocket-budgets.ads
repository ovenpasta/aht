--  Budget arithmetic for the close handshake.
--
--  Two expressions, pulled out of the client so they can be checked
--  directly. Both are one line and both were got wrong once: the
--  first degraded the "no bound" sentinel into an enormous finite
--  deadline, and the second was applied as a floor under every budget
--  rather than to the one value that needs it, quietly refilling a
--  budget the caller had already spent.
--
--  Neither is reachable from a socket test at a resolution that would
--  not be flaky -- the differences are fractions of a second, or a
--  sentinel that only misbehaves at conversion time -- so they are
--  pinned here instead, where they are just arithmetic.
package AHT.Websocket.Budgets is

   pragma Pure;

   --  What the close frame's write gets when the caller's budget is
   --  exactly zero, and only then.
   --
   --  A zero deadline does not mean "try once" to a transport; it
   --  means "fail before parking", so even a frame going straight
   --  into an empty socket buffer would be refused. A budget of zero
   --  says not to wait for the PEER's echo -- it does not say to skip
   --  saying goodbye.
   Close_Frame_Grace : constant Duration := 0.25;

   --  What is left of a budget after `Spent` has gone.
   --
   --  Duration'Last is the "no bound" sentinel the transports
   --  understand, and it has to come through intact: Duration'Last
   --  minus a microsecond is not a sentinel any more, it is an
   --  enormous finite deadline that overflows when turned into a
   --  point in time.
   --
   --  An exhausted budget returns zero rather than going negative,
   --  and an overspent one is not treated as credit.
   function Remaining (Budget, Spent : Duration) return Duration
   is (if Budget = Duration'Last then Duration'Last
       elsif Spent >= Budget then 0.0
       else Budget - Spent);

   --  What the close frame's write may spend.
   --
   --  `Left` is what Remaining says is available. The grace applies
   --  to a budget of exactly zero and nothing else: used as a floor
   --  it would hand a caller asking for 0.05 a quarter second, and
   --  refill a budget already spent acquiring the send latch, which
   --  is the per-phase renewal a compound budget exists to prevent.
   function Close_Frame_Budget (Budget, Left : Duration) return Duration
   is (if Budget = 0.0 then Close_Frame_Grace else Left);

end AHT.Websocket.Budgets;
