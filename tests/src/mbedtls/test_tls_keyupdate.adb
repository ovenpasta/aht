--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Coordinator coverage, mbedtls backend. The shared white-box
--  TLS_Sync_Cases run here: the mbedtls engine arbitrates its single
--  socket read through the same AHT.TLS_Sync coordinator.
--
--  Cases:
--    A. TLS_Sync_Cases
--
--  Does not cover:
--    - KeyUpdate: this backend is built with MBEDTLS_SSL_PROTO_TLS1_3
--      compiled out (scripts/fetch_mbedtls.sh) and negotiates TLS 1.2
--    - the skip is unconditional; nothing asks the session what it
--      negotiated, so if the protocol ceiling moves this main keeps
--      skipping coverage that had become reachable

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;

with TLS_Sync_Cases;

procedure Test_TLS_Keyupdate is
   Failures : constant Natural :=
     TLS_Sync_Cases.Run ("test_tls_keyupdate");
begin
   Put_Line ("test_tls_keyupdate: SKIP end-to-end half (mbedtls "
             & "backend is TLS 1.2; no KeyUpdate to trigger)");

   if Failures = 0 then
      Put_Line ("test_tls_keyupdate: OK (coordinator cases)");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_tls_keyupdate:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_TLS_Keyupdate;
