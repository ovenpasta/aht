--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Interfaces.C;
with System;

--  Curated binding for the mbedTLS SSL/TLS surface AHT.Transport.TLS
--  uses. Only *function* signatures are bound here — every context is an
--  opaque System.Address (allocated by AHT.Mbedtls.Glue), so no
--  ABI-dependent struct layout is modelled. The API/protocol constants
--  below are plain ints fixed by the headers (not ABI-dependent), so
--  curating them as Ada constants is safe across platforms.
package AHT.Mbedtls.SSL is

   use type Interfaces.C.int;

   --  mbedtls_ssl_config_defaults endpoint / transport / preset.
   IS_CLIENT        : constant Interfaces.C.int := 0;
   TRANSPORT_STREAM : constant Interfaces.C.int := 0;
   PRESET_DEFAULT   : constant Interfaces.C.int := 0;

   --  mbedtls_ssl_conf_authmode values.
   VERIFY_NONE      : constant Interfaces.C.int := 0;
   VERIFY_OPTIONAL  : constant Interfaces.C.int := 1;
   VERIFY_REQUIRED  : constant Interfaces.C.int := 2;

   --  Negative return codes we branch on. -0xNNNN in the headers.
   ERR_WANT_READ         : constant Interfaces.C.int := -16#6900#;
   ERR_WANT_WRITE        : constant Interfaces.C.int := -16#6880#;
   ERR_TIMEOUT           : constant Interfaces.C.int := -16#6800#;
   ERR_PEER_CLOSE_NOTIFY : constant Interfaces.C.int := -16#7880#;
   ERR_CONN_EOF          : constant Interfaces.C.int := -16#7280#;
   --  What a recv callback returning 0 (end of stream) surfaces as.
   ERR_NET_RECV_FAILED   : constant Interfaces.C.int := -16#004C#;
   ERR_NET_SEND_FAILED   : constant Interfaces.C.int := -16#004E#;

   --  BIO callbacks. C profiles:
   --    int f_send(void *ctx, const unsigned char *buf, size_t len);
   --    int f_recv(void *ctx,       unsigned char *buf, size_t len);
   --  Return bytes transferred, or a negative MBEDTLS_ERR_* code. The
   --  implementations live in AHT.Transport.TLS and bridge to the inner
   --  TCP transport.
   type Send_Fn is access function
     (Ctx : System.Address;
      Buf : System.Address;
      Len : Interfaces.C.size_t) return Interfaces.C.int
     with Convention => C;

   type Recv_Fn is access function
     (Ctx : System.Address;
      Buf : System.Address;
      Len : Interfaces.C.size_t) return Interfaces.C.int
     with Convention => C;

   function Config_Defaults
     (Conf      : System.Address;
      Endpoint  : Interfaces.C.int;
      Transport : Interfaces.C.int;
      Preset    : Interfaces.C.int) return Interfaces.C.int
     with Import, Convention => C,
          External_Name => "mbedtls_ssl_config_defaults";

   procedure Conf_Authmode
     (Conf : System.Address; Authmode : Interfaces.C.int)
     with Import, Convention => C,
          External_Name => "mbedtls_ssl_conf_authmode";

   procedure Conf_CA_Chain
     (Conf     : System.Address;
      CA_Chain : System.Address;
      CA_CRL   : System.Address)
     with Import, Convention => C,
          External_Name => "mbedtls_ssl_conf_ca_chain";

   function Setup
     (SSL : System.Address; Conf : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "mbedtls_ssl_setup";

   --  Hostname is a NUL-terminated C string (address of a char_array).
   function Set_Hostname
     (SSL : System.Address; Hostname : System.Address) return Interfaces.C.int
     with Import, Convention => C,
          External_Name => "mbedtls_ssl_set_hostname";

   procedure Set_Bio
     (SSL            : System.Address;
      P_Bio          : System.Address;
      F_Send         : Send_Fn;
      F_Recv         : Recv_Fn;
      F_Recv_Timeout : System.Address)
     with Import, Convention => C, External_Name => "mbedtls_ssl_set_bio";

   function Handshake (SSL : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "mbedtls_ssl_handshake";

   function Read
     (SSL : System.Address;
      Buf : System.Address;
      Len : Interfaces.C.size_t) return Interfaces.C.int
     with Import, Convention => C, External_Name => "mbedtls_ssl_read";

   function Write
     (SSL : System.Address;
      Buf : System.Address;
      Len : Interfaces.C.size_t) return Interfaces.C.int
     with Import, Convention => C, External_Name => "mbedtls_ssl_write";

   function Close_Notify (SSL : System.Address) return Interfaces.C.int
     with Import, Convention => C,
          External_Name => "mbedtls_ssl_close_notify";

end AHT.Mbedtls.SSL;
