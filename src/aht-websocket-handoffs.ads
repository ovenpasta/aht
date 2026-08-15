--  The record that a generation's session changed hands.
--
--  This lives in its own unit for the reason `Send_Guards` does: its
--  correctness argument is about abort, and an abort-safety claim
--  tested against a hand-written replica is not tested at all -- the
--  replica can stay correct while the original rots. Here
--  `test_ws_handoff` drives this exact type.
--
--  What it guards. A connecting task builds a session and hands it to
--  the receiver; from that moment the receiver owns it and will
--  reclaim it, and the connecting task's cleanup must not also free
--  it. The cleanup decides by asking whether the handover happened,
--  so the answer has to be recorded somewhere an abort of the
--  connecting task cannot lose.
--
--  A protected action is that somewhere. Abort is deferred inside one
--  and takes effect at its end, so a record made *by this operation*
--  is either complete or never began. The failure it rules out is
--  recording in the CALLER after the call returns: a pending abort
--  lands exactly between the two, leaving the receiver owning a
--  session whose giver still believes it owns it too -- a double
--  free, and one that no ordinary run would show.
--  Public, and deliberately: `test_ws_handoff` drives these exact
--  types from its own binary, which is the point of the split, and a
--  private child would need a descendant test to do it. Same standing
--  as `AHT.Websocket.Send_Guards`, which is public for the same
--  reason. So this is supported surface, diagnostics included -- not
--  an internal detail that happens to be reachable. Callers have no
--  reason to construct one, but nothing breaks if they do.
package AHT.Websocket.Handoffs is

   protected type Handoff is

      --  Record that generation Gen changed hands. Recorded inside
      --  this action, which is the whole point; see above.
      --
      --  Monotone: recording a generation never un-records an earlier
      --  one. Generations are handed out in order and an attempt's
      --  cleanup may run long after a later attempt has published, so
      --  "was mine taken?" has to stay answerable for a generation the
      --  world has moved past.
      procedure Record_Taken (Gen : Positive);

      --  Whether generation Gen was handed over. True once Gen or any
      --  later generation has been recorded.
      function Taken (Gen : Positive) return Boolean;

      --  Diagnostics, not control primitives -- the same role
      --  Send_Guard.Acquisitions plays, and with the same caveat:
      --  never gate a decision on them.
      --
      --  Records exists so a test can confirm that a recording it
      --  arranged really completed, rather than inferring it from a
      --  delay. Both saturate at Natural'Last rather than overflowing.
      function Records return Natural;
      function High_Water return Natural;

   private
      Highest : Natural := 0;
      Count   : Natural := 0;
   end Handoff;

end AHT.Websocket.Handoffs;
