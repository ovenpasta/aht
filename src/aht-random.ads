with AHT.Bytes;

--  Cryptographically secure random bytes, from the operating system.
--
--  This exists because RFC 6455 asks, in two places, for randomness
--  that a *predictable* generator cannot supply — and both were
--  previously served by a clock-seeded
--  `Ada.Numerics.Discrete_Random`. The distinction is not
--  PRNG-versus-not — every system source here is itself a CSPRNG. It
--  is cryptographically secure versus predictable.
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
--  Bytes come straight from the system CSPRNG, so there is no
--  generator state here to seed, to share between tasks, to reseed
--  after a fork, or to get wrong. That is the whole reason for going
--  to the OS rather than to a crypto library's DRBG: the system
--  source is what those DRBGs are seeded from anyway, and owning one
--  of them would add initialization, finalization and post-fork
--  reseeding to obtain the same 4- and 16-byte public values.
--
--  Which system call that is, and the handling it needs, is the one
--  part that cannot be written portably, so it lives in
--  `AHT.Random.Source` with one body per OS — selected by the
--  `AHT_OS` scenario variable, exactly as the TLS backend picks its
--  own directory. Everything else, including the counters below, is
--  shared, so the two platforms cannot drift in what they report.
--
--    POSIX    `/dev/urandom`. The descriptor is opened once, kept for
--             the life of the process, and read unbuffered — a
--             syscall per call. Buffering would amortise that but
--             would hand the same pending bytes to both sides of a
--             `fork`, whereas reading through a retained descriptor
--             stays correct across one. It is set close-on-exec so
--             subprocesses do not inherit it; see the body for the
--             narrow window that leaves open.
--
--    Windows  `RtlGenRandom`, which advapi32 exports as
--             `SystemFunction036`. One call fills the buffer or
--             fails, so there is no descriptor to leak across `exec`,
--             no state to inherit across a `fork`, and no partial
--             result to loop over — the whole family of concerns
--             above simply does not arise. bcrypt.dll is avoided on
--             purpose: it does not exist before Vista, and importing
--             it makes the image unloadable on the XP target.
--
--  Adding a platform means implementing one procedure. It does NOT
--  mean the rest of the library builds there: this unit is portable,
--  the transports and the test harness have not been verified
--  anywhere but POSIX.
package AHT.Random is

   --  A request to the system CSPRNG failed. What that means is
   --  platform-specific -- a device that would not open or read, an
   --  API returning a failure status -- and the message says which;
   --  what matters to a caller is the same either way.
   --
   --  Deliberately fatal rather than falling back to a weaker source:
   --  a silent downgrade to predictable masks is the failure this
   --  package exists to prevent, and it would be invisible on the
   --  wire.
   Entropy_Error : exception;

   --  Fills every byte of `B` from the system CSPRNG. A null range is
   --  a no-op.
   procedure Fill (B : out AHT.Bytes.Byte_Array);

   --  How many times Fill has been ASKED for bytes. Saturates at
   --  Natural'Last rather than overflowing.
   --
   --  Requests, not deliveries: the count is taken on entry, so a
   --  Fill that goes on to raise still increments it. That is the
   --  useful reading for the callers -- "did this path ask?" -- and
   --  the alternative would report nothing at all for the failure
   --  case, which is when one most wants to know.
   --
   --  A diagnostic, not a control primitive -- the same role
   --  Send_Guard.Acquisitions plays. It exists because no amount of
   --  sampling the bytes on the wire distinguishes this source from a
   --  well-behaved PRNG, so a test that watched only the output would
   --  stay green with the production call sites reverted.
   --
   --  What counting establishes is that a path REQUESTED entropy, and
   --  of what width. It does not trace the returned bytes to the
   --  value that shipped: a caller that drew and discarded, then used
   --  something else, would count identically. That is a deliberate
   --  limit, not an oversight -- see test_ws_masking, which states it
   --  and the construction that defeats it.
   function Draws return Natural;

   --  Total bytes REQUESTED. Saturates likewise, and like Draws it
   --  counts on entry, so bytes a failed Fill never delivered are
   --  included. Named for what it measures rather than for what a
   --  reader might hope it measures.
   --
   --  Draws alone cannot separate requests of different sizes: a
   --  missing call and a compensating extra call balance. Paired with
   --  this they can, because the two callers ask for different widths
   --  — 4 bytes for a frame mask, 16 for a handshake nonce — so calls
   --  and bytes form two equations in two unknowns and a test can
   --  recover how many requests of each WIDTH were made.
   --
   --  Width populations, not caller identity. A missing 4-byte
   --  request and an unrelated extra 4-byte request still balance;
   --  what the pair rules out is a deficit in one width being paid
   --  for by a surplus in the other.
   function Bytes_Requested return Natural;

end AHT.Random;
