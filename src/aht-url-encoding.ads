--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

package AHT.URL.Encoding is

   pragma Preelaborate;

   --  Every function here operates on bytes: the input String is an
   --  opaque octet sequence (Character'Pos is the byte value). Text
   --  carrying non-ASCII must be UTF-8 encoded by the caller.
   --  The unreserved set is exactly RFC 3986 2.3 (ASCII ALPHA / DIGIT
   --  / '-' / '.' / '_' / '~'); every other byte becomes "%HH" in
   --  uppercase hex. Ada.Characters.Handling.Is_Alphanumeric would
   --  admit Latin-1 letters and emit non-portable URLs.

   function Percent_Encode (S : String) return String;
   function Percent_Decode (S : String) return String;

   --  "application/x-www-form-urlencoded" variant: space => '+', and
   --  on decode '+' => space. Everything else follows percent encoding.
   function Form_Encode (S : String) return String;
   function Form_Decode (S : String) return String;

end AHT.URL.Encoding;
