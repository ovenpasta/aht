--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with AHT.Bytes;

--  The OS entropy call itself, and nothing else.
--
--  Split out so that the counting, the zero-length case and the
--  fail-closed contract live once in the parent body rather than
--  being reimplemented — and quietly diverging — per platform. A
--  platform body has exactly one job: fill the buffer from the
--  system CSPRNG, or raise.
--
--  One body per OS, selected by the AHT_OS scenario variable in
--  aht.gpr, the same way the TLS backend picks its own directory.
private package AHT.Random.Source is

   --  Fills every byte of B from the operating system's CSPRNG.
   --
   --  B is never null-ranged here; the parent handles that before
   --  calling, so a body may assume there is work to do.
   --
   --  Raises AHT.Random.Entropy_Error on any failure. Raising rather
   --  than reporting is deliberate and is the whole contract: there
   --  is no weaker source to fall back to, and a caller that silently
   --  got predictable bytes would have no way to notice.
   procedure Get (B : out AHT.Bytes.Byte_Array);

end AHT.Random.Source;
