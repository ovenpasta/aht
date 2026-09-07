--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with AHT.Bytes;

package AHT.Websocket.UTF8 is

   pragma Preelaborate;

   --  RFC 3629 well-formedness check for UTF-8, as required of text
   --  messages and Close reasons (RFC 6455 sec. 8.1; violations close
   --  with 1007). The complete sequence must be well-formed, so a
   --  truncated multi-byte sequence is invalid. Strict: 1..4-byte
   --  sequences only, no overlongs, no surrogates, nothing above
   --  U+10FFFF, as Autobahn section 6 enforces.

   function Is_Valid (Data : AHT.Bytes.Byte_Array) return Boolean;
   function Is_Valid (Data : AHT.Bytes.Buffer)     return Boolean;

end AHT.Websocket.UTF8;
