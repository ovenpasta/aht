--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  The platform default of AHT.Root_Store.Load: one body per OS,
--  selected by the AHT_OS scenario variable in aht.gpr. The parent
--  body consults it only when SSL_CERT_FILE and SSL_CERT_DIR are
--  both unset or empty.
private package AHT.Root_Store.Platform is

   --  Adds the platform's default trust anchors to C and sets
   --  C.Result.Origin to the source they came from; leaves Origin at
   --  None when nothing yielded a certificate.
   procedure Collect_Default (C : in out Collector);

end AHT.Root_Store.Platform;
