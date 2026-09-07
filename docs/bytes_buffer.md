<!--
SPDX-FileCopyrightText: 2026 Aldo Nicolas Bruno
SPDX-License-Identifier: Apache-2.0
-->

# AHT.Bytes

`AHT.Bytes` holds the byte types used across the library: `Octet`,
`Byte_Array`, the growable `Buffer`, conversions between them and
`String`, and a Base64 encoder.

## Byte_Array and String

```ada
subtype Octet is Interfaces.Unsigned_8;
type Byte_Array is array (Positive range <>) of Octet;

function From_String   (S : String)     return Byte_Array;
function To_String     (B : Byte_Array) return String;
function Base64_Encode (B : Byte_Array) return String;
```

`String` and `Byte_Array` are representationally identical (8-bit
elements), so `From_String` and `To_String` are single block copies,
one `Character` per `Octet` with no charset handling. A
`pragma Compile_Time_Error` requires `Character` and `Octet` to be
8-bit, so an exotic target fails to build instead of corrupting text.

`Base64_Encode` is standard Base64 per RFC 4648 §4 (`+` / `/`
alphabet, `=` padding), not the URL-safe variant. The WebSocket
handshake uses it for `Sec-WebSocket-Key` and to verify
`Sec-WebSocket-Accept`.

## Buffer

An array-backed, capacity-doubling byte buffer with bulk (block-move)
operations and value (copy) semantics. It is the byte-buffer type
across the library: HTTP request and response bodies, WebSocket
payloads and frames, `AHT.HTTP.IO`, UTF-8 validation.

```ada
type Buffer is tagged private
  with Default_Initial_Condition => Is_Empty (Buffer),
       Constant_Indexing         => Element;  -- B (I) is Element (B, I)

--  State / size.
function Length      (Self : Buffer) return Natural;
function Is_Empty    (Self : Buffer) return Boolean;
function First_Index (Self : Buffer) return Positive;   -- always 1
function Last_Index  (Self : Buffer) return Natural;    -- = Length
function Element     (Self : Buffer; Index : Positive) return Octet
  with Pre => Index <= Length (Self);

--  Whole-buffer conversions, one block copy each.
function To_Array  (Self : Buffer) return Byte_Array;
function To_String (Self : Buffer) return String;

--  Slice extraction, one block copy of Self (Low .. High). Empty when
--  High < Low (use High => Low - 1), matching Ada slice conventions.
function To_Array
  (Self : Buffer; Low : Positive; High : Natural) return Byte_Array
  with Pre => Low <= Length (Self) + 1 and then High <= Length (Self);
function To_String
  (Self : Buffer; Low : Positive; High : Natural) return String
  with Pre => Low <= Length (Self) + 1 and then High <= Length (Self);
function Slice
  (Self : Buffer; Low : Positive; High : Natural) return Buffer
  with Pre => Low <= Length (Self) + 1 and then High <= Length (Self);

--  Construction, one block copy.
function To_Buffer (Data : Byte_Array) return Buffer;
function To_Buffer (S    : String)     return Buffer;

--  Mutation.
procedure Clear   (Self : in out Buffer);
procedure Reserve (Self : in out Buffer; Capacity : Natural);
procedure Append  (Self : in out Buffer; Data  : Byte_Array);
procedure Append  (Self : in out Buffer; Datum : Octet);
procedure Append  (Self : in out Buffer; Other : Buffer);
procedure Set     (Self : in out Buffer; Data  : Byte_Array);  -- replace
procedure Set     (Self : in out Buffer; S     : String);      -- replace
procedure Query
  (Self : Buffer; Process : not null access procedure (Data : Byte_Array));
```

API notes:

- `Query` is the zero-copy read for the wire path: `Process` is
  called once with a view of the live bytes (`Self` is not copied).
  `Request.Write` uses it so a body goes straight from the buffer to
  the socket.
- `Set (String)` fills the buffer in place with one allocation and
  copy; `Request.Set_Body` uses it to load a body from text.
- `Append (Buffer)` concatenates one buffer onto another in a single
  block move; fragmented WebSocket frames are reassembled this way.
  It is self-append-safe: capacity is ensured before the copy and the
  source and destination ranges never overlap.
- `Constant_Indexing => Element` gives the `B (I)` read sugar. Reads
  only; mutation goes through `Append` and `Set`.
- Bounds checks are live in every build mode. `Element` and the
  `Low .. High` readers have both a `Pre` and a body check raising
  `Constraint_Error`, so out-of-range access fails in the `release`
  profile too, which compiles without `-gnata`. The empty-slice forms
  (`High < Low`, including the `Low = Length + 1` boundary) return
  empty.

### Semantics

`Buffer` has value semantics: assignment deep-copies, so buffers (and
the records that embed them, such as `Request_Type` and
`Response_Type`) can be passed, returned and snapshotted into task
entries safely. It is an `Ada.Finalization.Controlled` type:

```ada
private
   type Byte_Array_Access is access Byte_Array;
   type Buffer is new Ada.Finalization.Controlled with record
      Data : Byte_Array_Access := null;  -- null iff capacity = 0
      Len  : Natural := 0;               -- live bytes: Data (1 .. Len)
   end record;
   overriding procedure Adjust   (Self : in out Buffer);  -- deep copy
   overriding procedure Finalize (Self : in out Buffer);  -- free
```

- Invariants: `Data = null` iff capacity 0; `Len <= capacity`; live
  bytes are `Data (1 .. Len)`.
- `Adjust` (post-assignment) detaches first (nulls `Data` and `Len`),
  then allocates a fresh `Byte_Array (1 .. Len)` and block-copies the
  source's live bytes. Detaching first makes it exception-safe: if
  the allocation raises (`Storage_Error`), the target is left empty
  and its `Finalize` frees nothing. `B := B` is a no-op.
- `Finalize`: `Unchecked_Deallocation` of `Data`, then `null` / `0`.
  Idempotent, since the runtime may finalize more than once.
- Growth: capacity doubling, starting at 64. `Reserve` ensures
  capacity at least the requested value without shrinking.
- Block moves: `Append (Byte_Array)`, `Set`, `To_Buffer`, the
  `To_Array` / `To_String` family and `Adjust` all use slice
  assignment (`Dst (lo .. hi) := Src`), which the compiler emits as a
  block move. The `String` forms overlay a `Byte_Array` view on the
  `String` storage (`with Import, Address => ...`).

`Buffer`'s partial view is `tagged private`, so call sites can use
prefix notation (`Resp.Body_B.Length`, `Req.Body_B.Append (X)`).
