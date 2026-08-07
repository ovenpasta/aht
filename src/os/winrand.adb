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
--  the parent's shared counters saw both requests.
--
--  Every check sets the exit status, so this is usable from a script
--  and cannot pass by printing reassuring text. An earlier version
--  could: it announced a failure and still exited 0, and it never
--  looked at the counters at all, so deleting the parent's counting
--  entirely would have left it green.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;

--  use type for /=, which is not directly visible on Octet here.
with AHT.Bytes; use type AHT.Bytes.Octet;
with AHT.Random;

procedure Winrand is

   --  Nonce width, so this exercises the same size the handshake
   --  draws rather than a convenient one.
   Width  : constant := 16;
   Calls  : constant := 2;

   A, B : AHT.Bytes.Byte_Array (1 .. Width);

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("winrand: FAIL - " & Msg);
      Failures := Failures + 1;
   end Fail;

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
      when others =>
         Fail ("Fill raised - the OS entropy call did not succeed");
         Put_Line ("winrand:" & Failures'Image & " failure(s)");
         Ada.Command_Line.Set_Exit_Status (1);
         return;
   end;

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
   if Identical then
      Fail ("the two draws were identical - the source is stuck");
   end if;

   --  The counters are checked, not merely printed. They are the only
   --  evidence that the parent's shared accounting survived the
   --  platform split, and a probe that printed them without asserting
   --  would stay green if it were deleted.
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
