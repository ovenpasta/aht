with AHT.Bytes;

--  Cryptographically secure random bytes, from the operating system.
--
--  This exists because RFC 6455 asks for more than a plain PRNG can
--  give, in two places, and both were previously served by a
--  clock-seeded `Ada.Numerics.Discrete_Random`:
--
--    * §5.3 — the frame masking key "MUST be derived from a strong
--      source of entropy", and a given frame's key must not make the
--      next one predictable. Masking is not confidentiality: it exists
--      so that a client cannot be coerced into emitting bytes that a
--      caching proxy would parse as a second, attacker-chosen HTTP
--      request. That defence is worth exactly as much as the mask is
--      unpredictable, so a PRNG an observer can track defeats the
--      entire point of masking rather than merely weakening it.
--    * §4.1 — `Sec-WebSocket-Key` "MUST be a nonce ... selected
--      randomly for each connection".
--
--  Bytes come straight from the OS pool (`/dev/urandom`), which is
--  itself a CSPRNG, so there is no generator state here to seed, to
--  share between tasks, or to get wrong. The descriptor is opened
--  once and kept; the read is a syscall per call, deliberately not
--  buffered. Buffering would amortise the syscall but would hand the
--  same pending bytes to both sides of a `fork`, and reading through
--  a retained descriptor is safe across one.
--
--  POSIX-only, which matches what this library already claims to
--  support.
package AHT.Random is

   --  The OS entropy source could not be opened or read. Deliberately
   --  fatal rather than falling back to a weaker source: a silent
   --  downgrade to predictable masks is the failure this package
   --  exists to prevent, and it would be invisible on the wire.
   Entropy_Error : exception;

   --  Fills every byte of `B` from the OS pool. A null range is a
   --  no-op.
   procedure Fill (B : out AHT.Bytes.Byte_Array);

   --  How many times Fill has been asked for bytes. Saturates at
   --  Natural'Last rather than overflowing.
   --
   --  A diagnostic, not a control primitive -- the same role
   --  Send_Guard.Acquisitions plays. It exists because the property
   --  that matters here cannot be tested any other way: no amount of
   --  sampling the bytes on the wire distinguishes this source from a
   --  well-behaved PRNG, so a test that watched only the output would
   --  stay green with the production call sites reverted. Counting
   --  the calls pins the wiring itself, which is the part that can
   --  actually regress silently.
   function Draws return Natural;

end AHT.Random;
