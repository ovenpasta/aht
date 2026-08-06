with GNAT.OS_Lib;
with Interfaces.C;

package body AHT.Random is

   Source_Path : constant String := "/dev/urandom";

   --  Opened once, then read from directly by any number of tasks.
   --
   --  Concurrent `read` on one descriptor is safe here: this is a
   --  character device, so there is no shared file offset to race,
   --  and the kernel hands each reader its own bytes. That is why the
   --  reads below are NOT inside a protected action -- doing I/O
   --  inside one would serialise every sender behind it and make a
   --  syscall part of a protected operation, which is exactly what
   --  protected objects are meant not to contain.
   FD : GNAT.OS_Lib.File_Descriptor := GNAT.OS_Lib.Invalid_FD;

   --  POSIX-standard values, identical on Linux and the BSDs
   --  including macOS, so no per-platform branch is needed.
   F_SETFD    : constant := 2;
   FD_CLOEXEC : constant := 1;

   function C_Fcntl
     (FD : Interfaces.C.int; Cmd : Interfaces.C.int; Arg : Interfaces.C.int)
      return Interfaces.C.int
     with Import, Convention => C, External_Name => "fcntl";

   --  Only the open is serialised. Retried on every call until it
   --  succeeds rather than latched after one attempt: the first open
   --  can fail for reasons that pass -- EMFILE under momentary
   --  descriptor pressure, an interrupted call -- and latching would
   --  turn a transient condition into a process-lifetime outage in
   --  which every later Fill raises even though the source is fine.
   --  Fail-closed is preserved either way; this only decides whether
   --  the failure is permanent.
   protected Opener is
      procedure Ensure (OK : out Boolean);
      procedure Count;
      function  Total return Natural;
   private
      N : Natural := 0;
   end Opener;

   protected body Opener is
      procedure Ensure (OK : out Boolean) is
         use type GNAT.OS_Lib.File_Descriptor;
         Ignored : Interfaces.C.int;
      begin
         if FD = GNAT.OS_Lib.Invalid_FD then
            FD := GNAT.OS_Lib.Open_Read (Source_Path, GNAT.OS_Lib.Binary);

            --  Close-on-exec. Without it every subprocess this
            --  program ever spawns inherits an open descriptor on the
            --  entropy source, which is a descriptor leak into
            --  processes that never asked for one. It does NOT affect
            --  the deliberate fork behaviour -- a fork keeps the
            --  descriptor, which is what makes reading through it
            --  safe across one; only exec drops it.
            if FD /= GNAT.OS_Lib.Invalid_FD then
               Ignored :=
                 C_Fcntl (Interfaces.C.int (FD), F_SETFD, FD_CLOEXEC);
            end if;
         end if;
         OK := FD /= GNAT.OS_Lib.Invalid_FD;
      end Ensure;

      procedure Count is
      begin
         if N < Natural'Last then
            N := N + 1;
         end if;
      end Count;

      function Total return Natural is (N);
   end Opener;

   function Draws return Natural is (Opener.Total);

   ----------
   -- Fill --
   ----------

   procedure Fill (B : out AHT.Bytes.Byte_Array) is
      --  A read can be interrupted by a signal and return -1 with
      --  EINTR, which is not a failure of the source. GNAT.OS_Lib
      --  does not surface errno, so this cannot distinguish that case
      --  from a real error; instead it retries a bounded number of
      --  times and only then gives up. A genuine failure costs a few
      --  wasted syscalls, an interrupted one is survived, and neither
      --  can loop forever.
      Max_Retries : constant := 8;

      OK      : Boolean;
      Got     : Integer;
      Pos     : Natural;
      Left    : Natural;
      Retries : Natural := 0;
   begin
      if B'Length = 0 then
         return;
      end if;

      Opener.Count;
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
            Retries := Retries + 1;
            if Retries > Max_Retries then
               raise Entropy_Error
                 with "AHT.Random: read from " & Source_Path
                   & " returned" & Integer'Image (Got)
                   & " after" & Natural'Image (Max_Retries)
                   & " retries";
            end if;
         else
            --  Left is decremented FIRST, and Pos advanced only while
            --  bytes remain. Advancing unconditionally would compute
            --  one-past-the-end after the final read, which raises
            --  Constraint_Error for a buffer that legitimately ends
            --  at Positive'Last.
            Left := Left - Got;
            if Left > 0 then
               Pos := Pos + Got;
            end if;
         end if;
      end loop;
   end Fill;

end AHT.Random;
