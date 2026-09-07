--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

package AHT.URL.Encoding is

   pragma Preelaborate;

   --  All functions in this package operate on bytes. The input `String`
   --  is treated as an opaque sequence of octets (Character'Pos gives the
   --  byte value). For URLs carrying non-ASCII text, the caller is
   --  expected to pre-encode the text as UTF-8 before passing it in.
   --
   --  The "unreserved" set used below is exactly RFC 3986 §2.3
   --  ("ALPHA / DIGIT / '-' / '.' / '_' / '~'"), where ALPHA and DIGIT
   --  mean strictly ASCII letters and digits. Every other byte is
   --  percent-encoded as "%HH" (uppercase hex). This is deliberately
   --  stricter than Ada.Characters.Handling.Is_Alphanumeric, which would
   --  classify accented Latin-1 letters as unreserved and emit
   --  non-portable URLs.

   function Percent_Encode (S : String) return String;
   function Percent_Decode (S : String) return String;

   --  "application/x-www-form-urlencoded" variant: space → '+', and
   --  on decode '+' → space. Everything else follows percent encoding.
   function Form_Encode (S : String) return String;
   function Form_Decode (S : String) return String;

end AHT.URL.Encoding;
