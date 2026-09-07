--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Interfaces.C;
with System;

--  Curated binding for the libssl surface AHT.Transport.TLS uses. Only
--  *function* symbols are bound — every handle is an opaque
--  System.Address — plus the API constants we branch on, which are
--  plain header-defined integers (not ABI-dependent). Macro-defined
--  entry points live in AHT.Openssl.Glue instead.
package AHT.Openssl.SSL is

   use type Interfaces.C.int;

   --  SSL_get_error classifications (openssl/ssl.h).
   ERROR_NONE        : constant Interfaces.C.int := 0;
   ERROR_SSL         : constant Interfaces.C.int := 1;
   ERROR_WANT_READ   : constant Interfaces.C.int := 2;
   ERROR_WANT_WRITE  : constant Interfaces.C.int := 3;
   ERROR_SYSCALL     : constant Interfaces.C.int := 5;
   ERROR_ZERO_RETURN : constant Interfaces.C.int := 6;

   --  SSL_CTX_set_verify modes.
   VERIFY_NONE : constant Interfaces.C.int := 16#00#;
   VERIFY_PEER : constant Interfaces.C.int := 16#01#;

   --  Protocol version for SSL_CTX_set_min_proto_version (via Glue).
   TLS_1_2_VERSION : constant Interfaces.C.int := 16#0303#;

   --  SSL_CTX_set_options bits (uint64_t since 3.0). Curated subset:
   --  NO_RENEGOTIATION hardens the client against server-initiated
   --  TLS 1.2 renegotiation, which would complicate the concurrency
   --  reasoning for no benefit. (SSL_OP_IGNORE_UNEXPECTED_EOF is
   --  deliberately NOT bound: truncation must fail — see docs/tls.md.)
   OP_NO_RENEGOTIATION : constant Interfaces.Unsigned_64 :=
     16#4000_0000#;  --  SSL_OP_BIT(30)

   ------------------------------------------------------------------
   --  SSL_CTX (per-connection here; the transport is single-use)
   ------------------------------------------------------------------

   function TLS_Client_Method return System.Address
     with Import, Convention => C, External_Name => "TLS_client_method";

   function CTX_New (Method : System.Address) return System.Address
     with Import, Convention => C, External_Name => "SSL_CTX_new";
   --  Returns Null_Address on failure.

   procedure CTX_Free (Ctx : System.Address)
     with Import, Convention => C, External_Name => "SSL_CTX_free";

   procedure CTX_Set_Verify
     (Ctx      : System.Address;
      Mode     : Interfaces.C.int;
      Callback : System.Address)
     with Import, Convention => C, External_Name => "SSL_CTX_set_verify";
   --  Callback is always Null_Address here (default verification).

   function CTX_Set_Default_Verify_Paths
     (Ctx : System.Address) return Interfaces.C.int
     with Import, Convention => C,
          External_Name => "SSL_CTX_set_default_verify_paths";
   --  1 on success. Loads the platform trust store (honours
   --  SSL_CERT_FILE / SSL_CERT_DIR).

   function CTX_Load_Verify_Locations
     (Ctx    : System.Address;
      CAfile : System.Address;
      CApath : System.Address) return Interfaces.C.int
     with Import, Convention => C,
          External_Name => "SSL_CTX_load_verify_locations";
   --  1 on success. Exactly one of CAfile/CApath is non-null per call
   --  (a CApath directory must use c_rehash hashed names).

   function CTX_Set_Options
     (Ctx : System.Address;
      Op  : Interfaces.Unsigned_64) return Interfaces.Unsigned_64
     with Import, Convention => C, External_Name => "SSL_CTX_set_options";
   --  Real function taking uint64_t since OpenSSL 3.0. Returns the new
   --  option mask.

   ------------------------------------------------------------------
   --  SSL connection object
   ------------------------------------------------------------------

   function New_SSL (Ctx : System.Address) return System.Address
     with Import, Convention => C, External_Name => "SSL_new";
   --  Returns Null_Address on failure.

   procedure Free (S : System.Address)
     with Import, Convention => C, External_Name => "SSL_free";
   --  Also frees BIOs whose ownership was transferred via Set_Bio.

   procedure Set_Bio
     (S    : System.Address;
      RBio : System.Address;
      WBio : System.Address)
     with Import, Convention => C, External_Name => "SSL_set_bio";
   --  Transfers ownership of both BIOs to the SSL (they are freed by
   --  Free above) — after this call, never BIO_free them directly.

   procedure Set_Connect_State (S : System.Address)
     with Import, Convention => C, External_Name => "SSL_set_connect_state";

   function Set1_Host
     (S : System.Address; Host : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "SSL_set1_host";
   --  1 on success. Arms hostname verification (DNS names) via the
   --  X509_VERIFY_PARAM machinery.

   function Get0_Param (S : System.Address) return System.Address
     with Import, Convention => C, External_Name => "SSL_get0_param";
   --  Borrowed X509_VERIFY_PARAM* (do not free); used for the
   --  IP-literal verification path (AHT.Openssl.X509).

   function Do_Handshake (S : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "SSL_do_handshake";

   function Read
     (S   : System.Address;
      Buf : System.Address;
      Num : Interfaces.C.int) return Interfaces.C.int
     with Import, Convention => C, External_Name => "SSL_read";

   function Write
     (S   : System.Address;
      Buf : System.Address;
      Num : Interfaces.C.int) return Interfaces.C.int
     with Import, Convention => C, External_Name => "SSL_write";

   function Get_Error
     (S : System.Address; Ret : Interfaces.C.int) return Interfaces.C.int
     with Import, Convention => C, External_Name => "SSL_get_error";
   --  Must be called immediately after the SSL_* call it classifies,
   --  with no intervening OpenSSL call and an ERR queue that was clear
   --  going in (AHT.Openssl.Err.Clear_Error).

   function Shutdown (S : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "SSL_shutdown";
   --  Special result protocol — NOT followed by Get_Error on >= 0:
   --  0 = close_notify sent (ours queued to the BIO), 1 = bidirectional
   --  shutdown complete, < 0 = error.

   function Get_Verify_Result (S : System.Address) return Interfaces.C.long
     with Import, Convention => C, External_Name => "SSL_get_verify_result";
   --  X509_V_OK (0) or a X509_V_ERR_* code; render with
   --  AHT.Openssl.X509.Verify_Error_String.

end AHT.Openssl.SSL;
