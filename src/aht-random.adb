with GNAT.OS_Lib;

package body AHT.Random is

   Source_Path : constant String := "/dev/urandom";

   --  Opened once, then read from directly by any number of tasks.
   --
   --  Concurrent `read` on one descriptor is safe here: this is a
   --  character device, so there is no shared file offset to race,
   --  and the kernel hands each reader its own bytes. That is why the
   --  reads below are NOT inside a protected action — doing I/O
   --  inside one would serialise every sender behind it and make a
   --  syscall part of a protected operation, which is exactly what
   --  protected objects are meant not to contain.
   FD : GNAT.OS_Lib.File_Descriptor := GNAT.OS_Lib.Invalid_FD;

   --  Only the open is serialised, and only once. A protected
   --  procedure is the cheapest way to make "open it if nobody has"
   --  atomic without a race in which two tasks each open a descriptor
   --  and one leaks.
   protected Opener is
      procedure Ensure (OK : out Boolean);
   private
      Tried : Boolean := False;
   end Opener;

   protected body Opener is
      procedure Ensure (OK : out Boolean) is
         use type GNAT.OS_Lib.File_Descriptor;
      begin
         if not Tried then
            Tried := True;
            FD := GNAT.OS_Lib.Open_Read (Source_Path, GNAT.OS_Lib.Binary);
         end if;
         OK := FD /= GNAT.OS_Lib.Invalid_FD;
      end Ensure;
   end Opener;

   ----------
   -- Fill --
   ----------

   procedure Fill (B : out AHT.Bytes.Byte_Array) is
      OK   : Boolean;
      Got  : Integer;
      Pos  : Natural;
      Left : Natural;
   begin
      if B'Length = 0 then
         return;
      end if;

      Opener.Ensure (OK);
      if not OK then
         raise Entropy_Error
           with "AHT.Random: cannot open " & Source_Path
             & "; refusing to fall back to a predictable source";
      end if;

      --  Looped, because a short read is legal even here. Asking for
      --  four bytes and using whatever arrived would leave the tail
      --  of the mask at whatever the caller's buffer happened to hold.
      Pos  := B'First;
      Left := B'Length;
      while Left > 0 loop
         Got := GNAT.OS_Lib.Read (FD, B (Pos)'Address, Left);
         if Got <= 0 then
            raise Entropy_Error
              with "AHT.Random: read from " & Source_Path
                & " returned" & Integer'Image (Got);
         end if;
         Pos  := Pos + Got;
         Left := Left - Got;
      end loop;
   end Fill;

end AHT.Random;
