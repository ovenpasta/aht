# AHT.Bytes.Buffer — design & migration

Replacing `AHT.Bytes.Byte_Vector` with a purpose-built, array-backed
byte buffer that supports **bulk (block-move) operations**. Tracks the
design and the slice-by-slice migration.

Last updated: 2026-06-03 (Slice D landed: `Byte_Vector` deleted from
`AHT.Bytes`; `Buffer` is now the sole byte-buffer type. Migration complete).

## Why

`AHT.Bytes.Byte_Vector` is `Ada.Containers.Vectors (Octet)`, and it is
the pervasive byte-buffer type across the library: HTTP request/response
bodies, WebSocket payloads/frames, `AHT.HTTP.IO`, UTF-8 validation.

The standard `Vectors` API has **no bulk array fill** — the only way to
put bytes in is one `Append` (or `Replace_Element`) per element. So
every conversion in the codebase is a per-byte loop:

- `Set_Body (String)` walks the String into the vector byte-by-byte.
- `Response.Body_Text` walks the vector into a String byte-by-byte.
- `Request.Write` rebuilds a `Byte_Array` from the vector element-by-
  element (`aht-http-request.adb`) only to hand it to the transport.
- `AHT.HTTP.IO.Read_Chunked_Body` accumulates with per-byte `Append`.

Meanwhile the transport / IO boundary already speaks `Byte_Array`
(`Write_All (T, Byte_Array)`, `From_String : Byte_Array`). So the vector
is the **outlier**: on the HTTP body path we convert vector↔array in
both directions for no benefit. Bodies and WS payloads are fill-once /
read-once (or append-as-frames-arrive) blobs — not random-access
growable structures that justify a general vector.

The limitation is the *container choice*, not Ada: array slice
assignment `Dst (A .. B) := Src` compiles to a block move, and
`String` / `Byte_Array` are representationally identical (8-bit
elements), so conversions can be single block copies.

**Goal:** one array-backed, capacity-doubling buffer with bulk ops and
**value (copy) semantics**, replacing `Byte_Vector` everywhere.

## Public API (in `AHT.Bytes`)

```ada
type Buffer is tagged private
  with Default_Initial_Condition => Is_Empty (Buffer),
       Constant_Indexing         => Element;  -- B (I) reads Element (B, I)

--  State / size: the length/index surface the codebase + tests query.
function Length      (Self : Buffer) return Natural;
function Is_Empty    (Self : Buffer) return Boolean;
function First_Index (Self : Buffer) return Positive;   -- always 1
function Last_Index  (Self : Buffer) return Natural;    -- = Length
function Element     (Self : Buffer; Index : Positive) return Octet
  with Pre => Index <= Length (Self);   -- mirrored by a body check (below)

--  Whole-buffer conversions — one block copy each.
function To_Array  (Self : Buffer) return Byte_Array;
function To_String (Self : Buffer) return String;

--  Slice extraction — one block copy of Self (Low .. High). Empty when
--  High < Low (use High => Low - 1), matching Ada slice conventions. A
--  non-empty span with High > Length fails (Pre / body check).
function To_Array  (Self : Buffer; Low : Positive; High : Natural) return Byte_Array
  with Pre => Low <= Length (Self) + 1 and then High <= Length (Self);
function To_String (Self : Buffer; Low : Positive; High : Natural) return String
  with Pre => Low <= Length (Self) + 1 and then High <= Length (Self);
function Slice     (Self : Buffer; Low : Positive; High : Natural) return Buffer
  with Pre => Low <= Length (Self) + 1 and then High <= Length (Self);

--  Construction — one block copy.
function To_Buffer (Data : Byte_Array) return Buffer;
function To_Buffer (S    : String)     return Buffer;

--  Mutation.
procedure Clear   (Self : in out Buffer);
procedure Reserve (Self : in out Buffer; Capacity : Natural);
procedure Append  (Self : in out Buffer; Data  : Byte_Array);  -- bulk slice move
procedure Append  (Self : in out Buffer; Datum : Octet);       -- single, compat
procedure Append  (Self : in out Buffer; Other : Buffer);      -- buffer concat
procedure Set     (Self : in out Buffer; Data  : Byte_Array);  -- replace
procedure Set     (Self : in out Buffer; S     : String);      -- replace, in place

--  Zero-copy read for the wire path: Process is called once with a view
--  of the live bytes (Self is not copied). Used by Request.Write so a
--  body goes straight from the buffer to the socket.
procedure Query
  (Self : Buffer; Process : not null access procedure (Data : Byte_Array));
```

API notes:

- No result-type overloading: constructors are `To_Buffer` (not a second
  `From_String`); `To_String (Buffer)` / `To_Array (Buffer)` overload by
  parameter type, the slice forms by arity.
- `First_Index`/`Last_Index`/`Element`/`Length`/`Append (Octet)`/`Clear`
  exist so the existing prefixed-call sites (incl. ~96 in tests) need
  minimal changes. `Length` returns `Natural` (was `Count_Type`); the
  two `Reserve_Capacity (Count_Type ...)` sites become `Reserve (...)`.
- `Append (Buffer)` and `Constant_Indexing => Element` were **added in
  Slice C**, when the migration surfaced two genuine gaps rather than
  contorting call sites around them (per the "examples reveal API gaps —
  fix the library" rule):
  - **`Append (Buffer)`** concatenates one buffer onto another in a
    single block move. Without it, reassembling fragmented WebSocket
    frames (`Reassembly_Buf.Append (Payload)`) needed a `Query` closure
    to reach the inner array, or a temporary `To_Array` round-trip. It
    is self-append-safe: `Ensure_Capacity` reallocates *before* the copy
    and the source/destination ranges never overlap.
  - **`Constant_Indexing => Element`** restores the `B (I)` read sugar
    `Byte_Vector` offered (e.g. the `test_http_io` mock transport indexes
    its script buffer). Read-only by design: there is no
    `Variable_Indexing`, so `B (I) := X` stays unsupported — no call site
    needs it, and mutation goes through `Append`/`Set`.
- **Bounds are guarded by `Pre` *and* a body check** (`Element` and the
  `Low .. High` readers). The `Pre` states the caller obligation — useful
  as documentation, enforced at the call boundary in debug, and what a
  future SPARK adoption would discharge. But the `release` profile in
  `aht.gpr` compiles without `-gnata`, so the `Pre` is **compiled out**
  there; and because `Data` is sized to *capacity* (≥ `Len`) and capacity
  survives `Clear`/reuse, an unchecked index in `Len + 1 .. capacity`
  would silently read a **stale byte** rather than fail — a data-
  disclosure regression versus `Byte_Vector.Element`, which always
  checked. So the bodies *mirror* the `Pre` with an explicit runtime
  check that raises `Constraint_Error`, keeping the guarantee live in
  release. Cost: the exception differs by build mode (`Assertion_Error`
  from the `Pre` in debug, `Constraint_Error` from the body in release) —
  cosmetic, as neither is meant to be caught in normal flow. The slice
  readers check only the actual-read path (a non-empty span), so the
  documented empty-slice forms (`High < Low`, incl. the `Low = Length + 1`
  boundary) still return empty. Verified by building `test_bytes_buffer`
  under `BUILD_MODE=release` (no `-gnata`) and confirming the out-of-range
  cases still raise. (The release-mode gap was found by Codex adversarial
  review of Slice C; keeping the `Pre` alongside the check was a
  follow-up call to preserve SPARK-readiness.)

## Semantics — the critical part

`Byte_Vector` has **value semantics** (assignment deep-copies), and the
codebase relies on it: the async worker snapshots a whole `Request_Type`
into a task entry; `Response_Type` is returned/`out`-copied by value. A
naive access-wrapper would alias and double-free.

So `Buffer` is an `Ada.Finalization.Controlled` type:

```ada
private
   type Byte_Array_Access is access Byte_Array;
   type Buffer is new Ada.Finalization.Controlled with record
      Data : Byte_Array_Access := null;  -- null iff capacity = 0
      Len  : Natural := 0;               -- live bytes = Data (1 .. Len)
   end record;
   overriding procedure Adjust   (Self : in out Buffer);  -- deep copy
   overriding procedure Finalize (Self : in out Buffer);  -- free, idempotent
```

- **Invariants:** `Data = null` iff capacity 0; `Len <= capacity`; live
  bytes are `Data (1 .. Len)`.
- **Adjust** (post-assignment): the raw record copy leaves `Data`
  aliasing the source's array, so Adjust *detaches first* (null out
  `Data`/`Len`), then allocates a fresh `Byte_Array (1 .. Len)` and
  block-copies the source's live bytes. Detaching up front makes it
  exception-safe: if the allocation raises (e.g. `Storage_Error`), the
  target is left empty and its `Finalize` frees nothing — no
  double-free of the array the source still owns. (GNAT's controlled
  assignment guards literal *and* runtime self-assignment, confirmed by
  test, so `B := B` is a no-op rather than a free-then-read.)
- **Finalize:** `Unchecked_Deallocation` of `Data`, then `null` / `0`.
  Idempotent (the runtime may finalize more than once).
- **Growth:** capacity doubling (start small, e.g. 64). `Reserve` ensures
  capacity ≥ requested without shrinking.
- **Block moves:** `Append (Byte_Array)`, `Set`, `To_Buffer`, the
  `To_Array`/`To_String` family, and `Adjust` all use slice assignment
  (`Dst (lo .. hi) := Src`) — the compiler emits a block move, no loop.
- **String overlay:** `To_String` / `To_Buffer (String)` get their
  block move by overlaying a `Byte_Array` view on the `String` storage
  (`with Import, Address => …`). That reinterpretation is sound only
  while `Character` and `Octet` are 8-bit, so a `pragma
  Compile_Time_Error` enforces it — an exotic target fails to build
  instead of silently corrupting text.

## Migration slices

Each slice: build clean + **full test suite green** + Codex adversarial
review + **explicit go-ahead before commit**. Docs (this file) updated in
the same commit as the code.

- [x] **A. Introduce `Buffer` + `test_bytes_buffer`.** `Byte_Vector`
      stays for now (zero risk to existing code). Unit test covers:
      copy-then-mutate independence (value semantics, both init and
      assignment paths), runtime-forced self-assignment, bulk `Append`,
      `To_Buffer`/`To_String` round trips, slice extraction (array /
      string / sub-buffer, incl. empty `High < Low` and the
      `Low = Length + 1` boundary), large append (1 MB) stays correct,
      `Clear`/`Reserve`/`Set`/`Is_Empty`, `Query` view matches contents.
      Wired into `tests.gpr`.
- [x] **B. HTTP bodies → `Buffer`.** `Request.Body_B` / `Response.Body_B`
      are now `Buffer`. `Set_Body` is `Self.Body_B.Set (Text)` — an
      **in-place** String fill (one allocation/copy). `:= To_Buffer (Text)`
      was rejected: assigning a function result drives controlled
      `Adjust`, which allocates and copies the payload a *second* time
      before the temporary is finalized — a transient 2× peak that could
      turn a large upload into `Storage_Error`. `Body_Text` is
      `To_String (Self.Body_B)`; `Write` streams the body through `Query`
      (zero-copy view → socket); the response and three client body sinks
      each collapse to a single bulk `Append (Chunk)`. The eight
      `test_http_*` `Body_To_String` helpers collapse to `To_String (V)`.
      Full suite green (28).
- [x] **C. `http-io` + WebSocket → `Buffer`.** `Read_Chunked_Body`
      returns `Buffer` (sink does bulk `Result.Append (Chunk)`);
      `Websocket.Frames` `Decode`/`Validate_Close_Decode`/
      `Classify_Inbound_Close`, `Websocket.Client` (`Message_Type.Payload`,
      reassembly, ping/pong, close-reason), and `Websocket.UTF8.Is_Valid`
      all take/return `Buffer`. The frames close-reason byte-loop is now a
      `To_Array` slice; unmasked decode (the hot path — server→client
      frames are never masked) is a single `Set` block move, the masked
      path stays a per-byte XOR. WS test sweep done; full suite (28) green,
      WS suite included to guard the close-race fix. Added `Append (Buffer)`
      + `Constant_Indexing` (see API notes) with coverage in
      `test_bytes_buffer`.
- [x] **D. Retire `Byte_Vector`.** Deleted `Byte_Vectors` / `Byte_Vector`
      (and the now-unused `with Ada.Containers.Vectors`) from `AHT.Bytes`.
      Migrated the last three holdouts off the vector: the `test_http_wire`
      mock transport (`Script` / `Written` → `Buffer`), the
      `test_ws_handshake` fake server's post-handshake byte store (`Post`),
      and the Autobahn driver's echo helpers (which now call `Buffer`'s own
      `To_String` / `To_Array` primitives — the extended-return block move
      keeps the 8M/16M §9 payloads off the primary stack, same as the
      hand-rolled helpers did). No `Byte_Vector` references remain in
      `src`/`tests`. Library, `tests.gpr`, and the standalone `autobahn.gpr`
      all build warning-free; full suite (28) green.

## Status

**Migration complete (Slices A–D landed).** `Buffer` is the sole
byte-buffer type in `AHT.Bytes`; `Byte_Vector` / `Byte_Vectors` are gone,
and no references remain in `src` or `tests`. `To_String`/`To_Buffer
(String)` use a `Byte_Array`-over-`String` address overlay so the
conversion is a single block move, not a per-character loop. HTTP
request/response bodies, `AHT.HTTP.IO.Read_Chunked_Body`, and the whole
WebSocket payload path (frames, client, UTF-8) are `Buffer`. The full
suite (28 tests) is green, and the standalone `autobahn.gpr` driver
builds and links clean against the new API.

`Buffer`'s **partial** view is `tagged private` (the full view extends
`Ada.Finalization.Controlled`, so it is tagged anyway). This is
deliberate: the call sites use prefix notation (`Resp.Body_B.Length`,
`Req.Body_B.Append (X)`), which is only available when the partial view
is tagged — `Byte_Vector`'s was, so the migration kept those calls
verbatim. The unit test calls the same ops in non-prefix form, so it
compiled even before the partial view was tagged.
