with Interfaces.C;
with System;

--  Windows: RtlGenRandom, the system CSPRNG that advapi32 has exported
--  since XP.
--
--  Much shorter than the POSIX body, and not because it cuts corners.
--  Every complication there comes from owning a file descriptor --
--  opening it, retrying a transient open, keeping it off exec'd
--  children, surviving a short read, surviving EINTR. This API owns
--  nothing: one call fills the whole buffer or fails, so there is no
--  descriptor to leak across exec, no state to inherit across a fork,
--  and no partial-result case to loop over.
--
--  Not BCryptGenRandom, which this body called until the XP floor was
--  noticed. It lives in bcrypt.dll, which does not exist before Vista,
--  and the pragma below puts that DLL in the PE import table of every
--  binary whose closure reaches this unit -- so XP fails at image load,
--  before main, rather than at the draw. The closure is wider than it
--  looks: RFC 6455 client frame masking draws from AHT.Random on every
--  frame sent, so plain ws:// reaches here too, and the TLS backend
--  choice is irrelevant because this unit is selected by AHT_OS.
--
--  CryptGenRandom is equally XP-safe and is what mbedTLS's own
--  entropy_poll.c calls, which would be the more consistent choice on
--  its face. It needs CryptAcquireContext and CryptReleaseContext
--  bracketing every draw, which puts a handle lifetime and two further
--  failure modes into a body whose entire shape is the paragraph above.
--  The consistency argument also expires: once mbedTLS is configured
--  MBEDTLS_NO_PLATFORM_ENTROPY and fed from this unit, entropy_poll.c
--  is not compiled at all and there is nothing left to be consistent
--  with.
--
--  RtlGenRandom has no import library entry under that name; advapi32
--  exports it as SystemFunction036, which is the documented way to
--  reach it.
package body AHT.Random.Source is

   --  Explicit rather than load-bearing, and that is a real difference
   --  from the bcrypt pragma this replaces -- do not read the old
   --  rationale onto it. bcrypt is not in GNAT's mingw link spec, so
   --  "-lbcrypt" was what made that import resolve, and was therefore
   --  also what put bcrypt.dll in the import table of every binary
   --  reaching this unit. advapi32 *is* in the spec: verified by
   --  deleting this line, relinking the probe, and finding
   --  SystemFunction036 still bound and ADVAPI32.dll still imported.
   --
   --  It stays because the dependency is genuine and should not rest on
   --  a toolchain default that is free to change. It is not the reason
   --  the link succeeds, and a test that removed it would not go red.
   pragma Linker_Options ("-ladvapi32");

   use type Interfaces.C.unsigned_char;

   --  BOOLEAN is unsigned char. That width is load-bearing, not
   --  pedantry, and it is the one thing here no test can catch.
   --
   --  On x86 stdcall a byte-wide return arrives in AL with the upper
   --  bits of EAX undefined. Declare this wider and the comparison
   --  reads those bits, which are usually non-zero whatever the callee
   --  did. Under the predicate this body used to have -- NTSTATUS,
   --  where non-zero meant failure -- that bug was noisy: it raised on
   --  perfectly good draws and was found at once. Under this one, where
   --  non-zero means success, the identical bug is silent and passes.
   --  This is a CSPRNG; a silent pass means shipping entropy that
   --  nothing ever validated.
   --
   --  src/os/winrand.adb cannot detect it either -- see the note there
   --  -- because a width-bugged status test only misreads a *failing*
   --  call, and the probe has no way to make this API fail. The
   --  declaration below is the whole defence. Widen it and nothing goes
   --  red.
   --
   --  ULONG is 32 bits on both 32- and 64-bit Windows, so
   --  Interfaces.C.unsigned_long is right on either.
   --
   --  Convention Stdcall rather than C: it is the calling convention
   --  for the Win32 API, and although the two coincide on x86-64 they
   --  differ on 32-bit Windows, where a C-convention import would
   --  corrupt the stack. advapi32 exports the entry point decorated
   --  _SystemFunction036@8 -- two 4-byte arguments -- which is what
   --  Stdcall produces and a C import would not.
   function RtlGenRandom
     (RandomBuffer       : System.Address;
      RandomBufferLength : Interfaces.C.unsigned_long)
      return Interfaces.C.unsigned_char
     with Import, Convention => Stdcall,
          External_Name => "SystemFunction036";

   ---------
   -- Get --
   ---------

   procedure Get (B : out AHT.Bytes.Byte_Array) is
      OK : Interfaces.C.unsigned_char;
   begin
      --  Fills the whole buffer or fails: unlike read(2) there is no
      --  short-result case to loop over.
      OK :=
        RtlGenRandom
          (RandomBuffer       => B (B'First)'Address,
           RandomBufferLength => Interfaces.C.unsigned_long (B'Length));

      --  Non-zero is TRUE. Unlike the NTSTATUS this replaced there is
      --  no code to report: the API returns the boolean and nothing
      --  else, so a failure here can say that the call was refused and
      --  cannot say why.
      if OK = 0 then
         raise Entropy_Error
           with "AHT.Random: RtlGenRandom (SystemFunction036) returned"
             & " FALSE; refusing to fall back to a predictable source";
      end if;
   end Get;

end AHT.Random.Source;
