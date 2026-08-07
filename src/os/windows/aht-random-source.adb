with Interfaces.C;
with System;

--  Windows: BCryptGenRandom, with the system-preferred RNG.
--
--  Much shorter than the POSIX body, and not because it cuts corners.
--  Every complication there comes from owning a file descriptor --
--  opening it, retrying a transient open, keeping it off exec'd
--  children, surviving a short read, surviving EINTR. This API owns
--  nothing: one call fills the whole buffer or fails, so there is no
--  descriptor to leak across exec, no state to inherit across a fork,
--  and no partial-result case to loop over.
--
--  BCRYPT_USE_SYSTEM_PREFERRED_RNG lets the algorithm handle be null
--  and asks the OS for its current preferred CSPRNG, so this does not
--  pin a named algorithm that a later Windows deprecates. It is
--  available from Vista / Server 2008 onward.
package body AHT.Random.Source is

   --  Joins the link only when a binary's closure actually uses this
   --  package -- the same idiom the TLS bindings use for their
   --  backend libraries, so a program that never draws entropy does
   --  not acquire a bcrypt dependency.
   pragma Linker_Options ("-lbcrypt");

   use type Interfaces.C.long;

   BCRYPT_USE_SYSTEM_PREFERRED_RNG : constant := 16#0000_0002#;

   --  NTSTATUS is a 32-bit signed value and ULONG a 32-bit unsigned
   --  one; on Windows (LLP64) C long is 32 bits for both 32- and
   --  64-bit builds, so Interfaces.C.long / unsigned_long are the
   --  right widths on either.
   --
   --  Convention Stdcall rather than C: it is the calling convention
   --  for the Win32 API, and although the two coincide on x86-64 they
   --  differ on 32-bit Windows, where a C-convention import would
   --  corrupt the stack.
   function BCryptGenRandom
     (hAlgorithm : System.Address;
      pbBuffer   : System.Address;
      cbBuffer   : Interfaces.C.unsigned_long;
      dwFlags    : Interfaces.C.unsigned_long) return Interfaces.C.long
     with Import, Convention => Stdcall, External_Name => "BCryptGenRandom";

   ---------
   -- Get --
   ---------

   procedure Get (B : out AHT.Bytes.Byte_Array) is
      Status : Interfaces.C.long;
   begin
      --  Fills the whole buffer or fails: unlike read(2) there is no
      --  short-result case to loop over.
      Status :=
        BCryptGenRandom
          (hAlgorithm => System.Null_Address,
           pbBuffer   => B (B'First)'Address,
           cbBuffer   => Interfaces.C.unsigned_long (B'Length),
           dwFlags    => BCRYPT_USE_SYSTEM_PREFERRED_RNG);

      --  STATUS_SUCCESS is 0; every NTSTATUS failure is negative or a
      --  non-zero informational code, and none of them means the
      --  buffer was filled.
      if Status /= 0 then
         raise Entropy_Error
           with "AHT.Random: BCryptGenRandom failed with NTSTATUS"
             & Interfaces.C.long'Image (Status)
             & "; refusing to fall back to a predictable source";
      end if;
   end Get;

end AHT.Random.Source;
