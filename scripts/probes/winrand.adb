--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  Cross-build probe for the Windows entropy body (AHT.Random.Source),
--  built by hand with the recipes in src/os/README.md and run under
--  wine; not in any Source_Dirs. It checks that the Stdcall import
--  binds, RtlGenRandom reports success, both buffers were written, the
--  draws differ and the parent's counters saw both requests. Each
--  check sets the exit status.
--
--  Does not cover:
--  * Whether the image loads on Windows XP; wine loads any DLL it is
--    asked for. The import-table check in src/os/README.md covers it.
--  * A too-wide return declaration on RtlGenRandom: BOOLEAN arrives in
--    AL with the upper EAX bits undefined, and only a failing call,
--    which nothing here can provoke, would misread.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

--  use type for /=, which is not directly visible on Octet here.
with AHT.Bytes; use type AHT.Bytes.Octet;
with AHT.Random;

procedure Winrand is

   --  Nonce width, the size the handshake draws.
   Width  : constant := 16;
   Calls  : constant := 2;

   --  The buffers hold a sentinel before the draw. Left uninitialised,
   --  a Get that writes nothing would leave two patches of stack
   --  garbage, which differ, and the differ check would pass. The
   --  parent's counters count requests, not bytes delivered.
   Sentinel : constant AHT.Bytes.Octet := 16#A5#;

   A, B : AHT.Bytes.Byte_Array (1 .. Width) := (others => Sentinel);

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("winrand: FAIL - " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Checked per buffer: a body that filled the first draw and not
   --  the second would still pass the differ check. A working CSPRNG
   --  returns all-Sentinel for 16 bytes with probability 2**(-128).
   procedure Check_Written (X : AHT.Bytes.Byte_Array; Which : String) is
      Untouched : Boolean := True;
   begin
      for I in X'Range loop
         if X (I) /= Sentinel then
            Untouched := False;
         end if;
      end loop;

      if Untouched then
         Fail (Which & " is still entirely the sentinel byte - the"
               & " source wrote nothing and reported no error");
      end if;
   end Check_Written;

   function Hex (X : AHT.Bytes.Byte_Array) return String is
      Digits_Lower : constant String := "0123456789abcdef";
      R : String (1 .. 2 * X'Length);
      P : Positive := 1;
   begin
      for I in X'Range loop
         R (P)     := Digits_Lower (Integer (X (I)) / 16 + 1);
         R (P + 1) := Digits_Lower (Integer (X (I)) mod 16 + 1);
         P := P + 2;
      end loop;
      return R;
   end Hex;

   Identical : Boolean := True;

begin
   begin
      AHT.Random.Fill (A);
      AHT.Random.Fill (B);
   exception
      when E : others =>
         --  Reported in full: Entropy_Error means RtlGenRandom returned
         --  FALSE, while Program_Error or Storage_Error from the same
         --  call means the binding itself is wrong (convention or
         --  parameter width).
         Fail ("Fill raised: "
               & Ada.Exceptions.Exception_Information (E));
         Put_Line ("winrand:" & Failures'Image & " failure(s)");
         Ada.Command_Line.Set_Exit_Status (1);
         return;
   end;

   Put_Line ("draw1 = " & Hex (A));
   Put_Line ("draw2 = " & Hex (B));

   Check_Written (A, "draw1");
   Check_Written (B, "draw2");

   for I in A'Range loop
      if A (I) /= B (I) then
         Identical := False;
      end if;
   end loop;

   --  Two 16-byte draws from a working CSPRNG are distinct with
   --  probability 1 - 2**(-128); equal means the source is stuck.
   if Identical then
      Fail ("the two draws were identical - the source is stuck");
   end if;

   --  The counters show the parent's shared accounting is reached
   --  through the platform body.
   if AHT.Random.Draws /= Calls then
      Fail ("Draws =" & Natural'Image (AHT.Random.Draws)
            & ", expected" & Natural'Image (Calls));
   end if;

   if AHT.Random.Bytes_Requested /= Calls * Width then
      Fail ("Bytes_Requested ="
            & Natural'Image (AHT.Random.Bytes_Requested)
            & ", expected" & Natural'Image (Calls * Width));
   end if;

   if Failures = 0 then
      Put_Line ("winrand: OK (draws =" & Natural'Image (AHT.Random.Draws)
                & ", bytes =" & Natural'Image (AHT.Random.Bytes_Requested)
                & ")");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("winrand:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Winrand;
