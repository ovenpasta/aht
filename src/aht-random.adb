with GNAT.OS_Lib;

--  System.OS_Constants is an internal GNAT unit, and GNAT says so.
--  It is used deliberately and narrowly, for one target-generated
--  errno value: the alternative is hard-coding 4, which is correct on
--  Linux and the BSDs today and is implementation-defined rather than
--  fixed by POSIX, so it would stop being correct silently. A
--  version-dependent dependency that fails at compile time is a
--  better trade than a portable-looking constant that fails at run
--  time.
pragma Warnings (Off, "*internal GNAT unit*");
pragma Warnings (Off, "*non-portable and version-dependent*");
with System.OS_Constants;
pragma Warnings (On, "*non-portable and version-dependent*");
pragma Warnings (On, "*internal GNAT unit*");

package body AHT.Random is

   Source_Path : constant String := "/dev/urandom";

   --  Target-generated rather than hard-coded. The value is
   --  implementation-defined, not fixed by POSIX, so writing 4 was
   --  correct for the platforms currently supported and would quietly
   --  stop being correct on one that is not.
   EINTR : constant := System.OS_Constants.EINTR;

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
      procedure Count (Bytes : Natural);
      function  Total return Natural;
      function  Total_Bytes return Natural;
   private
      N : Natural := 0;
      B : Natural := 0;
   end Opener;

   protected body Opener is
      procedure Ensure (OK : out Boolean) is
         use type GNAT.OS_Lib.File_Descriptor;
         Set_OK : Boolean;
      begin
         if FD = GNAT.OS_Lib.Invalid_FD then
            FD := GNAT.OS_Lib.Open_Read (Source_Path, GNAT.OS_Lib.Binary);

            if FD /= GNAT.OS_Lib.Invalid_FD then
               --  Close-on-exec, so subprocesses do not inherit a
               --  descriptor on the entropy source. Fork still keeps
               --  it, which is what makes reading through it safe
               --  across one; only exec drops it.
               --
               --  The status is checked and a failure is fatal to
               --  this descriptor. Keeping a descriptor that is NOT
               --  close-on-exec would quietly break the guarantee
               --  above, and the next Ensure re-opens rather than
               --  handing out a weaker one.
               GNAT.OS_Lib.Set_Close_On_Exec (FD, True, Set_OK);
               if not Set_OK then
                  GNAT.OS_Lib.Close (FD);
                  FD := GNAT.OS_Lib.Invalid_FD;
               end if;
            end if;
         end if;
         OK := FD /= GNAT.OS_Lib.Invalid_FD;
      end Ensure;

      procedure Count (Bytes : Natural) is
      begin
         if N < Natural'Last then
            N := N + 1;
         end if;
         if B <= Natural'Last - Bytes then
            B := B + Bytes;
         else
            B := Natural'Last;
         end if;
      end Count;

      function Total return Natural is (N);
      function Total_Bytes return Natural is (B);
   end Opener;

   function Draws return Natural is (Opener.Total);
   function Bytes_Requested return Natural is (Opener.Total_Bytes);

   ----------
   -- Fill --
   ----------

   procedure Fill (B : out AHT.Bytes.Byte_Array) is
      OK   : Boolean;
      Got  : Integer;
      Err  : Integer;
      Pos  : Natural;
      Left : Natural;
   begin
      if B'Length = 0 then
         return;
      end if;

      Opener.Count (B'Length);
      Opener.Ensure (OK);
      if not OK then
         raise Entropy_Error
           with "AHT.Random: cannot open " & Source_Path
             & " with close-on-exec; refusing to fall back to a "
             & "predictable source";
      end if;

      --  Looped, because a short read is legal even here. Asking for
      --  four bytes and using whatever arrived would leave the tail
      --  of the mask at whatever the caller's buffer happened to hold.
      Pos  := B'First;
      Left := B'Length;
      while Left > 0 loop
         Got := GNAT.OS_Lib.Read (FD, B (Pos)'Address, Left);

         if Got < 0 then
            --  Read immediately, before anything else can disturb it.
            Err := GNAT.OS_Lib.Errno;

            --  Only EINTR is retried. A signal arriving mid-read is
            --  not a failure of the source and says nothing about it.
            --  Everything else -- EIO, EBADF, EFAULT -- means the
            --  descriptor or the request is broken, and retrying it
            --  eight times only delays a diagnosis that is already
            --  certain.
            if Err /= EINTR then
               declare
                  --  Named, because Errno_Message returning String is
                  --  ambiguous with indexing it at the call site.
                  Why : constant String := GNAT.OS_Lib.Errno_Message (Err);
               begin
                  raise Entropy_Error
                    with "AHT.Random: read from " & Source_Path
                      & " failed:" & Integer'Image (Err) & " " & Why;
               end;
            end if;

         elsif Got = 0 then
            --  End of file on a character device that is supposed to
            --  be inexhaustible. Not retryable in any useful sense.
            raise Entropy_Error
              with "AHT.Random: read from " & Source_Path
                & " returned 0 bytes; the source is not behaving as "
                & "a character device";

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
