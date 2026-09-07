--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Interfaces.C;
with System;

--  Curated binding for the libcrypto error queue. Discipline (see
--  docs/tls.md): the queue is thread-local; clear it before every
--  SSL_* call, classify with SSL_get_error immediately after, and
--  drain the queue into the exception message on failure.
package AHT.Openssl.Err is

   procedure Clear_Error
     with Import, Convention => C, External_Name => "ERR_clear_error";

   function Get_Error return Interfaces.C.unsigned_long
     with Import, Convention => C, External_Name => "ERR_get_error";
   --  Pops the oldest error (0 when the queue is empty).

   procedure Error_String_N
     (E   : Interfaces.C.unsigned_long;
      Buf : System.Address;
      Len : Interfaces.C.size_t)
     with Import, Convention => C, External_Name => "ERR_error_string_n";
   --  Renders E as "error:......:lib:reason" into Buf (NUL-terminated).

   function Drain return String;
   --  Pop and render every queued error into one human-readable
   --  string ("" when the queue is empty). Leaves the queue clear.

end AHT.Openssl.Err;
