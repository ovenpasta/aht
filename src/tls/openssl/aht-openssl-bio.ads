--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Interfaces.C;
with System;

--  Curated binding for the memory-BIO surface the OpenSSL backend
--  uses. The engine gives the SSL two BIO_s_mem BIOs (SSL_set_bio) and
--  moves ciphertext between them and the TCP transport itself, so no
--  custom BIO_METHOD and no C callbacks are needed.
package AHT.Openssl.BIO is

   function S_Mem return System.Address
     with Import, Convention => C, External_Name => "BIO_s_mem";
   --  The memory BIO method (borrowed; never freed).

   function New_BIO (Method : System.Address) return System.Address
     with Import, Convention => C, External_Name => "BIO_new";
   --  Returns Null_Address on failure. Ownership passes to the SSL at
   --  SSL_set_bio; only a BIO never handed over is freed directly.

   function Free (B : System.Address) return Interfaces.C.int
     with Import, Convention => C, External_Name => "BIO_free";
   --  Only for BIOs NOT yet transferred to an SSL (partial-allocation
   --  cleanup in Connect).

   function Read
     (B   : System.Address;
      Buf : System.Address;
      Len : Interfaces.C.int) return Interfaces.C.int
     with Import, Convention => C, External_Name => "BIO_read";
   --  Drain ciphertext OpenSSL queued in the write-side memory BIO.

   function Write
     (B   : System.Address;
      Buf : System.Address;
      Len : Interfaces.C.int) return Interfaces.C.int
     with Import, Convention => C, External_Name => "BIO_write";
   --  Feed network bytes into the read-side memory BIO (it grows; a
   --  short write only happens on allocation failure).

   function Ctrl_Pending (B : System.Address) return Interfaces.C.size_t
     with Import, Convention => C, External_Name => "BIO_ctrl_pending";
   --  Bytes currently buffered in the BIO (how much WBIO ciphertext
   --  there is to drain).

end AHT.Openssl.BIO;
