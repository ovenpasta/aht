--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with GNAT.OS_Lib;

--  System.OS_Constants is an internal GNAT unit, used for one
--  target-generated errno value: EINTR is implementation-defined,
--  and a hard-coded 4 would fail at run time on a target where it
--  differs.
pragma Warnings (Off, "*internal GNAT unit*");
pragma Warnings (Off, "*non-portable and version-dependent*");
with System.OS_Constants;
pragma Warnings (On, "*non-portable and version-dependent*");
pragma Warnings (On, "*internal GNAT unit*");

--  POSIX: /dev/urandom.
package body AHT.Random.Source is

   Source_Path : constant String := "/dev/urandom";

   --  Target-generated: the value is implementation-defined.
   EINTR : constant := System.OS_Constants.EINTR;

   --  Opened once, kept for the life of the process, read by any
   --  number of tasks without a protected action: a character device
   --  has no shared offset to race. Read unbuffered, so a fork does
   --  not hand the same pending bytes to both sides.
   FD : GNAT.OS_Lib.File_Descriptor := GNAT.OS_Lib.Invalid_FD;

   --  Only the open is serialised. Retried whenever the descriptor is
   --  invalid: the first open can fail transiently (EMFILE, EINTR),
   --  and latching would turn that into a process-lifetime outage.
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
               --  Close-on-exec, so subprocesses do not inherit the
               --  descriptor; fork keeps it. A failure to set the
               --  flag discards the descriptor; the next Ensure
               --  re-opens. The flag is set after the open, not with
               --  it (GNAT.OS_Lib has no O_CLOEXEC), so a fork+exec
               --  in that window can still inherit one descriptor.
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

            --  Only EINTR is retried; everything else (EIO, EBADF,
            --  EFAULT) means the descriptor or the request is broken.
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
            --  Pos advances only while bytes remain: advancing after
            --  the final read would form one-past-the-end, which
            --  raises for a buffer ending at Positive'Last.
            Left := Left - Got;
            if Left > 0 then
               Pos := Pos + Got;
            end if;
         end if;
      end loop;
   end Get;

end AHT.Random.Source;
