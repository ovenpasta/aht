--  Coordinator coverage, mbedtls backend.
--
--  The KeyUpdate half of this main is openssl-only: mbedTLS 2.28
--  negotiates TLS 1.2 at most, which has no post-handshake KeyUpdate
--  to drive. The coordinator half applies to BOTH backends, though —
--  since the mbedtls engine became a buffered, non-blocking engine it
--  arbitrates its single socket read through the very same
--  AHT.TLS_Sync coordinator — so the shared white-box cases run here.

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
