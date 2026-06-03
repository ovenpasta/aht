# AHT.Bytes.Buffer — design & migration

Replacing `AHT.Bytes.Byte_Vector` with a purpose-built, array-backed
byte buffer that supports **bulk (block-move) operations**. Tracks the
design and the slice-by-slice migration.

Last updated: 2026-06-03 (Slice B landed: HTTP bodies on `Buffer`).

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
type Buffer is private with Default_Initial_Condition => Is_Empty (Buffer);

--  State / size (mirrors the Byte_Vector surface the codebase + tests use)
function Length      (Self : Buffer) return Natural;
function Is_Empty    (Self : Buffer) return Boolean;
function First_Index (Self : Buffer) return Positive;   -- always 1
function Last_Index  (Self : Buffer) return Natural;    -- = Length
function Element     (Self : Buffer; Index : Positive) return Octet
  with Pre => Index <= Length (Self);

--  Whole-buffer conversions — one block copy each.
function To_Array  (Self : Buffer) return Byte_Array;
function To_String (Self : Buffer) return String;

--  Slice extraction — one block copy of Self (Low .. High). Empty when
--  High < Low (use High => Low - 1), matching Ada slice conventions.
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
- [ ] **C. `http-io` + WebSocket → `Buffer`.** `Read_Chunked_Body`
      return; `Websocket.Frames` / `Websocket.Client` / `Websocket.UTF8`
      payloads. Replace the frames close-reason byte-loop with a slice.
      Sweep WS tests; run the **full WS suite** to guard the close-race
      fix.
- [ ] **D. Retire `Byte_Vector`.** Delete `Byte_Vectors` / `Byte_Vector`
      from `AHT.Bytes`; confirm no references remain; full suite green.

## Status

Slices A–B landed. `Buffer` lives in `AHT.Bytes` alongside `Byte_Vector`,
with `test_bytes_buffer` green. `To_String`/`To_Buffer (String)` use a
`Byte_Array`-over-`String` address overlay so the conversion is a single
block move, not a per-character loop. The HTTP request/response bodies
are now `Buffer`; the full suite (28 tests) is green.

`Buffer`'s **partial** view is `tagged private` (the full view extends
`Ada.Finalization.Controlled`, so it is tagged anyway). This is
deliberate: the call sites use prefix notation (`Resp.Body_B.Length`,
`Req.Body_B.Append (X)`), which is only available when the partial view
is tagged — `Byte_Vector`'s was, so the migration keeps those calls
verbatim. The unit test calls the same ops in non-prefix form, so it
compiled even before the partial view was tagged.

Slices C–D pending.
