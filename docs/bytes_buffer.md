# AHT.Bytes.Buffer

An array-backed, capacity-doubling byte buffer with bulk (block-move)
operations and **value (copy) semantics**. It is the byte-buffer type
across the library: HTTP request/response bodies, WebSocket
payloads/frames, `AHT.HTTP.IO`, UTF-8 validation. `String` and
`Byte_Array` are representationally identical (8-bit elements), so
conversions between them and the buffer are single block copies.

## Public API (in `AHT.Bytes`)

```ada
type Buffer is tagged private
  with Default_Initial_Condition => Is_Empty (Buffer),
       Constant_Indexing         => Element;  -- B (I) reads Element (B, I)

--  State / size.
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
procedure Append  (Self : in out Buffer; Datum : Octet);       -- single byte
procedure Append  (Self : in out Buffer; Other : Buffer);      -- buffer concat
procedure Set     (Self : in out Buffer; Data  : Byte_Array);  -- replace
procedure Set     (Self : in out Buffer; S     : String);      -- replace, in place
procedure Query
  (Self : Buffer; Process : not null access procedure (Data : Byte_Array));
```

API notes:

- **`Query`** is the zero-copy read for the wire path: `Process` is
  called once with a view of the live bytes (`Self` is not copied).
  `Request.Write` uses it so a body goes straight from the buffer to the
  socket.
- **`Set (String)`** fills the buffer in place with one
  allocation/copy — the way to load a body from text
  (`Self.Body_B.Set (Text)`).
- **`Append (Buffer)`** concatenates one buffer onto another in a single
  block move — this is how fragmented WebSocket frames are reassembled
  (`Reassembly_Buf.Append (Payload)`). It is self-append-safe: capacity
  is ensured *before* the copy and the source/destination ranges never
  overlap.
- **`Constant_Indexing => Element`** gives the `B (I)` read sugar.
  Reads only — mutation goes through `Append`/`Set`.
- **Bounds checks are live in every build mode.** `Element` and the
  `Low .. High` readers have both the `Pre` and an explicit body check
  that raises `Constraint_Error`, so out-of-range access fails even in
  the `release` profile, which compiles without `-gnata`. In debug the
  `Pre` raises `Assertion_Error` first; the difference is cosmetic, as
  neither is meant to be caught in normal flow. The empty-slice forms
  (`High < Low`, incl. the `Low = Length + 1` boundary) return empty.

## Semantics

`Buffer` has **value semantics**: assignment deep-copies, so buffers
(and the records that embed them, like `Request_Type` and
`Response_Type`) can be passed, returned, and snapshotted into task
entries safely. It is an `Ada.Finalization.Controlled` type:

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
- **Adjust** (post-assignment): detaches first (null out `Data`/`Len`),
  then allocates a fresh `Byte_Array (1 .. Len)` and block-copies the
  source's live bytes. Detaching up front makes it exception-safe: if
  the allocation raises (e.g. `Storage_Error`), the target is left empty
  and its `Finalize` frees nothing. `B := B` is a no-op.
- **Finalize:** `Unchecked_Deallocation` of `Data`, then `null` / `0`.
  Idempotent (the runtime may finalize more than once).
- **Growth:** capacity doubling (starting at 64). `Reserve` ensures
  capacity ≥ requested without shrinking.
- **Block moves:** `Append (Byte_Array)`, `Set`, `To_Buffer`, the
  `To_Array`/`To_String` family, and `Adjust` all use slice assignment
  (`Dst (lo .. hi) := Src`) — the compiler emits a block move.
- **String overlay:** `To_String` / `To_Buffer (String)` get their
  block move by overlaying a `Byte_Array` view on the `String` storage
  (`with Import, Address => …`). A `pragma Compile_Time_Error` requires
  `Character` and `Octet` to be 8-bit, so an exotic target fails to
  build instead of silently corrupting text.

`Buffer`'s partial view is `tagged private`, so call sites can use
prefix notation (`Resp.Body_B.Length`, `Req.Body_B.Append (X)`).
