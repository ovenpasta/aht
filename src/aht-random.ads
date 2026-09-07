--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with AHT.Bytes;

--  Cryptographically secure random bytes from the OS CSPRNG.
--
--  RFC 6455 5.3: the frame masking key MUST come from a strong source
--  of entropy. RFC 6455 4.1: Sec-WebSocket-Key MUST be a nonce
--  selected randomly for each connection.
--
--  The system call lives in AHT.Random.Source, one body per OS,
--  selected by the AHT_OS scenario variable:
--    POSIX    /dev/urandom, one descriptor, close-on-exec, unbuffered.
--    Windows  RtlGenRandom (advapi32's SystemFunction036); no bcrypt.
--  Fails closed: no fallback to a weaker source. Windows is not a
--  supported configuration; the suite runs under wine.
package AHT.Random is

   --  A request to the system CSPRNG failed; the message says which
   --  call. No fallback to a weaker source.
   Entropy_Error : exception;

   --  Fills every byte of `B` from the system CSPRNG. A null range is
   --  a no-op.
   procedure Fill (B : out AHT.Bytes.Byte_Array);

   --  Fill calls so far, counted on entry (a Fill that raises counts),
   --  saturating at Natural'Last. Diagnostic; a test that watches only
   --  the wire cannot see this. test_ws_masking states the limit.
   function Draws return Natural;

   --  Bytes requested so far, counted like Draws. Diagnostic; a test
   --  that watches only the wire cannot see this. With Draws it
   --  recovers requests per width (4 for a mask, 16 for a nonce).
   function Bytes_Requested return Natural;

end AHT.Random;
