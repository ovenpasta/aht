--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with AHT.Bytes;

--  The OS entropy call. Counting, the zero-length case and the
--  fail-closed contract live in the parent body; a platform body
--  fills the buffer from the system CSPRNG or raises. One body per
--  OS, selected by the AHT_OS scenario variable in aht.gpr.
private package AHT.Random.Source is

   --  Fills every byte of B from the OS CSPRNG. B is never
   --  null-ranged here. Raises AHT.Random.Entropy_Error on any
   --  failure; no fallback to a weaker source.
   procedure Get (B : out AHT.Bytes.Byte_Array);

end AHT.Random.Source;
