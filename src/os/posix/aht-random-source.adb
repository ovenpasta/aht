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

--  POSIX: /dev/urandom.
--
--  The OS pool is itself a CSPRNG, so there is no generator state
--  here to seed, share between tasks, reseed after a fork, or get
--  wrong.
package body AHT.Random.Source is

   Source_Path : constant String := "/dev/urandom";

   --  Target-generated rather than hard-coded, because the value is
   --  implementation-defined rather than fixed by POSIX.
   EINTR : constant := System.OS_Constants.EINTR;

   --  Opened once, kept for the life of the process, and read by any
   --  number of tasks.
   --
   --  Concurrent `read` on one descriptor is safe here: this is a
   --  character device, so there is no shared file offset to race,
   --  and the kernel hands each reader its own bytes. That is why the
   --  reads below are NOT inside a protected action -- doing I/O
   --  inside one would serialise every caller behind it and make a
   --  syscall part of a protected operation, which is exactly what
   --  protected objects are meant not to contain.
   --
   --  Read unbuffered, deliberately. Buffering would amortise the
   --  syscall but would hand the same pending bytes to both sides of
   --  a fork, whereas reading through a retained descriptor stays
   --  correct across one.
   FD : GNAT.OS_Lib.File_Descriptor := GNAT.OS_Lib.Invalid_FD;

   --  Only the open is serialised. Retried whenever the descriptor is
   --  invalid rather than latched after one attempt: the first open
   --  can fail for reasons that pass -- EMFILE under momentary
   --  descriptor pressure, an interrupted call -- and latching would
   --  turn a transient condition into a process-lifetime outage in
   --  which every later Get raises even though the source is fine.
   --  Fail-closed is preserved either way; this only decides whether
   --  the failure is permanent.
   protected Opener is
      procedure Ensure (OK : out Boolean);
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
               --  this descriptor: keeping one that is NOT
               --  close-on-exec would quietly break the guarantee
               --  above, so the next Ensure re-opens rather than
               --  handing out a weaker one.
               --
               --  Narrow caveat, stated rather than papered over: the
               --  flag is set just after the open, not atomically
               --  with it, so a fork+exec by another task in exactly
               --  that window could still inherit the descriptor.
               --  Closing that needs O_CLOEXEC on the open itself,
               --  which GNAT.OS_Lib does not reach and whose value
               --  differs across POSIX platforms. The exposure is one
               --  descriptor on a world-readable device.
               GNAT.OS_Lib.Set_Close_On_Exec (FD, True, Set_OK);
               if not Set_OK then
                  GNAT.OS_Lib.Close (FD);
                  FD := GNAT.OS_Lib.Invalid_FD;
               end if;
            end if;
         end if;
         OK := FD /= GNAT.OS_Lib.Invalid_FD;
      end Ensure;
   end Opener;

   ---------
   -- Get --
   ---------

   procedure Get (B : out AHT.Bytes.Byte_Array) is
      OK   : Boolean;
      Got  : Integer;
      Err  : Integer;
      Pos  : Natural;
      Left : Natural;
   begin
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
            --  only delays a diagnosis that is already certain.
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
   end Get;

end AHT.Random.Source;
