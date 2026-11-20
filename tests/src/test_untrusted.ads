--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Support for the "untrusted chain" cases of test_tls, test_http_tls,
--  test_ws_tls and test_tls_retry: the fixture is verified against an
--  unrelated certificate and the handshake must reject it. Such a case
--  passes vacuously when the anchor cannot be loaded, since that too
--  raises TLS_Error; these establish that the refusal came from the
--  handshake.

package Test_Untrusted is

   --  Written by scripts/generate_cert.sh: self-signed, the fixture's
   --  subject and SANs, a different key.
   Other_File : constant String := "tests/server/certs/other.crt";

   --  "" when Other_File holds exactly one well-formed certificate
   --  block that is not the fixture's; otherwise what is wrong.
   function Anchor_Problem return String;

   --  True when Msg reports a rejection by the TLS handshake, on
   --  either backend, rather than a failure to load or choose trust.
   function Is_Handshake_Rejection (Msg : String) return Boolean;

   --  Dials seen by Count_Dial since it was last reset. Written only by
   --  the connecting task.
   Dials : Natural := 0;

   --  An address filter (AHT.Transport.TLS.Connect's Address_Filter,
   --  Client_Type.On_Address) that counts and allows every address.
   function Count_Dial (Host, Address : String) return Boolean;

end Test_Untrusted;
