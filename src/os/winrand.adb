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
--  whole path: that the Stdcall import binds, that RtlGenRandom
--  reports success, that the buffers were written at all, that two
--  draws differ, and that the parent's shared counters saw both
--  requests.
--
--  Every check sets the exit status, so this is usable from a script
--  and cannot pass by printing reassuring text. An earlier version
--  could: it announced a failure and still exited 0, and it never
--  looked at the counters at all, so deleting the parent's counting
--  entirely would have left it green.
--
--  ---------------------------------------------------------------
--  Two things this probe cannot see. Both measured, not reasoned.
--
--  It cannot see whether the image would load on Windows XP. It runs
--  under wine, and wine implements every DLL it is asked for, so a
--  body importing a Vista-only DLL passes here while being unloadable
--  on the target. The complementary check is the import-table
--  assertion in
--  src/os/README.md: it never executes a byte, but it does see the
--  DLL names. Neither half is sufficient alone, and neither is
--  redundant with the other. Do not delete one because the other is
--  green.
--
--  It cannot see a too-wide return declaration on RtlGenRandom.
--  BOOLEAN is one byte, arriving in AL with the upper EAX bits
--  undefined; a body that declares it wider misreads only a *failing*
--  call, and nothing here can make this API fail. The declaration in
--  the body is the entire defence against that, and it says so.
--  ---------------------------------------------------------------

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;

--  use type for /=, which is not directly visible on Octet here.
with AHT.Bytes; use type AHT.Bytes.Octet;
with AHT.Random;

procedure Winrand is

   --  Nonce width, so this exercises the same size the handshake
   --  draws rather than a convenient one.
   Width  : constant := 16;
   Calls  : constant := 2;

   --  Sentinelling the buffers before the draw is load-bearing, not
   --  tidiness. Left uninitialised they hold stack garbage, and the
   --  "two draws differ" check below then compares two different
   --  patches of garbage -- which do differ, so it passes.
   --
   --  Measured, not feared: against a Get that writes nothing at all,
   --  a probe without this sentinel prints two plausible hex lines,
   --  reports "OK (draws = 2, bytes = 32)" and exits 0. The counters
   --  do not help, because the parent counts requests rather than
   --  bytes delivered. The sentinel turns "wrote nothing" from a coin
   --  flip on stack contents into a determinate failure.
   Sentinel : constant AHT.Bytes.Octet := 16#A5#;

   A, B : AHT.Bytes.Byte_Array (1 .. Width) := (others => Sentinel);

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("winrand: FAIL - " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Per buffer rather than once over both: a body that filled the
   --  first draw and not the second would pass the differ check, for
   --  the wrong reason.
   --
   --  A working CSPRNG returning all-Sentinel for 16 bytes sits at
   --  2**(-128), the same order as the collision this shares the file
   --  with. That is not a statistical threshold in the sense the
   --  testing standard warns about; it is an impossibility with a
   --  number attached.
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
         --  Reported in full, because the distinctions matter here and
         --  a generic message erases them: Entropy_Error means
         --  RtlGenRandom returned FALSE, while Program_Error or
         --  Storage_Error from the same call means the binding itself
         --  is wrong -- a bad convention, a bad parameter width --
         --  which is a different bug with a different fix.
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
