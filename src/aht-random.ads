with AHT.Bytes;

--  Cryptographically secure random bytes, from the operating system.
--
--  This exists because RFC 6455 asks, in two places, for randomness
--  that a *predictable* generator cannot supply — and both were
--  previously served by a clock-seeded
--  `Ada.Numerics.Discrete_Random`. The distinction is not
--  PRNG-versus-not: `/dev/urandom` is itself a CSPRNG. It is
--  cryptographically secure versus predictable.
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
--  Bytes come straight from the OS pool (`/dev/urandom`), so there is
--  no generator state here to seed, to share between tasks, to
--  reseed after a fork, or to get wrong. That is the whole reason for
--  going to the OS rather than to a crypto library's DRBG: the OS
--  pool is what those DRBGs are seeded from anyway, and owning one of
--  them would add initialization, finalization and post-fork
--  reseeding to obtain the same 4- and 16-byte public values.
--
--  The descriptor is opened once, kept for the life of the process,
--  and read unbuffered — a syscall per call. Buffering would amortise
--  that but would hand the same pending bytes to both sides of a
--  `fork`, whereas reading through a retained descriptor stays
--  correct across one.
--
--  It is set close-on-exec, so subprocesses do not inherit it. One
--  narrow caveat, stated rather than papered over: the flag is set
--  just after the open, not atomically with it, so a `fork`+`exec`
--  performed by another task in exactly that window could still
--  inherit the descriptor. Closing that window needs `O_CLOEXEC` on
--  the open itself, which is not reachable through `GNAT.OS_Lib` and
--  whose value differs across POSIX platforms. The exposure is one
--  descriptor on a world-readable device, so the guarantee is
--  documented as the narrower one rather than bought with C glue and
--  a per-platform constant.
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
