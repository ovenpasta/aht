--  Cross-build probe for the Windows entropy body.
--
--  Deliberately NOT in any Source_Dirs: src/os itself is not a source
--  directory (only src/os/posix and src/os/windows are), so this main
--  never joins the library. It is built by hand, with the commands in
--  src/os/README.md, when the Windows body changes.
--
--  It exists because AHT.Random.Source's Windows body cannot be
--  exercised by the ordinary suite from a POSIX host, and "it
--  compiles" is not the interesting claim. What this checks is the
--  whole path: that the Stdcall import binds, that
--  pragma Linker_Options pulls in bcrypt, that BCryptGenRandom
--  actually returns STATUS_SUCCESS, that two calls differ, and that
--  the parent's shared counters see the requests.

with Ada.Text_IO; use Ada.Text_IO;

--  use type for /=, which is not directly visible on Octet here.
with AHT.Bytes; use type AHT.Bytes.Octet;
with AHT.Random;

procedure Winrand is

   --  Nonce width, so this exercises the same size the handshake
   --  draws rather than a convenient one.
   A, B : AHT.Bytes.Byte_Array (1 .. 16);

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
   AHT.Random.Fill (A);
   AHT.Random.Fill (B);

   Put_Line ("draw1 = " & Hex (A));
   Put_Line ("draw2 = " & Hex (B));

   for I in A'Range loop
      if A (I) /= B (I) then
         Identical := False;
      end if;
   end loop;

   --  Two 16-byte draws from a working CSPRNG are distinct with
   --  probability 1 - 2**(-128). Equal means the source is stuck, not
   --  that this was an unlucky run.
   Put_Line ("distinct = " & Boolean'Image (not Identical));

   --  Expect draws = 2, bytes = 32. Any other reading means the
   --  parent's counting did not survive the platform split.
   Put_Line ("draws =" & Natural'Image (AHT.Random.Draws)
             & "  bytes =" & Natural'Image (AHT.Random.Bytes_Requested));

   if Identical then
      Put_Line ("FAIL: the two draws were identical");
   else
      Put_Line ("OK");
   end if;
end Winrand;
