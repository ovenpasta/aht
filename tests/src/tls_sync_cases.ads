--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  White-box cases for AHT.TLS_Sync.Coordinator_Type, the arbiter
--  both TLS engines rely on. Shared by the per-backend
--  test_tls_keyupdate mains because the coordinator itself is shared:
--  the claim/arm atomicity, wake-on-release, abort-wakes-parked-waiter
--  and deadline-expiry-while-parked behaviors are the same code on
--  either backend, and end-to-end traffic cannot force them
--  deterministically.
package TLS_Sync_Cases is

   function Run (Label : String) return Natural;
   --  Runs every case, printing "<Label>: FAIL — ..." for each
   --  failure. Returns the number of failures (0 = all good).

end TLS_Sync_Cases;
