with Ada.Containers.Vectors;
with Ada.Finalization;
with Interfaces;

package AHT.Bytes is

   pragma Preelaborate;

   use type Interfaces.Unsigned_8;

   subtype Octet is Interfaces.Unsigned_8;

   type Byte_Array is array (Positive range <>) of Octet;

   package Byte_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Positive,
      Element_Type => Octet);

   subtype Byte_Vector is Byte_Vectors.Vector;

   --  Array-backed byte buffer with value (copy) semantics. Bulk ops
   --  move whole slices: `Dst (Lo .. Hi) := Src` compiles to a single
   --  block move, no per-element loop. Tagged so the prefix-call style
   --  (`B.Length`, `B.Append (X)`) the call sites use is available, not
   --  for inheritance.
   type Buffer is tagged private
     with Default_Initial_Condition => Is_Empty (Buffer);

   --  State / size (mirrors the Byte_Vector surface call sites use).
   function Length      (Self : Buffer) return Natural;
   function Is_Empty    (Self : Buffer) return Boolean;
   function First_Index (Self : Buffer) return Positive;   --  always 1
   function Last_Index  (Self : Buffer) return Natural;     --  = Length
   function Element     (Self : Buffer; Index : Positive) return Octet
     with Pre => Index <= Length (Self);

   --  Whole-buffer conversions — one block copy each.
   function To_Array  (Self : Buffer) return Byte_Array;
   function To_String (Self : Buffer) return String;

   --  Slice extraction — one block copy of Self (Low .. High). Empty
   --  when High < Low (use High => Low - 1), matching Ada slice rules.
   function To_Array
     (Self : Buffer; Low : Positive; High : Natural) return Byte_Array
     with Pre => Low <= Length (Self) + 1 and then High <= Length (Self);
   function To_String
     (Self : Buffer; Low : Positive; High : Natural) return String
     with Pre => Low <= Length (Self) + 1 and then High <= Length (Self);
   function Slice
     (Self : Buffer; Low : Positive; High : Natural) return Buffer
     with Pre => Low <= Length (Self) + 1 and then High <= Length (Self);

   --  Construction — one block copy.
   function To_Buffer (Data : Byte_Array) return Buffer;
   function To_Buffer (S    : String)     return Buffer;

   --  Mutation.
   procedure Clear   (Self : in out Buffer);
   procedure Reserve (Self : in out Buffer; Capacity : Natural);
   procedure Append  (Self : in out Buffer; Data  : Byte_Array);
   procedure Append  (Self : in out Buffer; Datum : Octet);
   procedure Set     (Self : in out Buffer; Data  : Byte_Array);
   procedure Set     (Self : in out Buffer; S     : String);
   --  Replace the contents in place — Len := 0 then one block move into
   --  Self's own (reused/grown) storage. Unlike `Self := To_Buffer (S)`,
   --  there is no temporary buffer and no controlled `Adjust` copy, so a
   --  large body costs one allocation/copy, not two.

   --  Zero-copy read for the wire path: Process is called once with a
   --  view of the live bytes (Self is not copied). Used by Request.Write
   --  so a body goes straight from the buffer to the socket.
   procedure Query
     (Self : Buffer; Process : not null access procedure (Data : Byte_Array));

   function From_String (S : String) return Byte_Array;
   function To_String   (B : Byte_Array) return String;

   function Base64_Encode (B : Byte_Array) return String;
   --  Standard Base64 per RFC 4648 §4 — `+` / `/` alphabet, `=`
   --  padding. Used by the WebSocket handshake to build the
   --  `Sec-WebSocket-Key` header value and to verify the server's
   --  `Sec-WebSocket-Accept` echo. Not URL-safe; if URL-safe
   --  Base64 is needed later, add a separate routine.

private

   type Byte_Array_Access is access Byte_Array;

   --  Controlled so a heap-backed Buffer keeps value (copy) semantics:
   --  assignment must deep-copy, not alias, else two buffers would free
   --  the same array. Invariants: Data = null iff capacity 0; live bytes
   --  are Data (1 .. Len); Len <= (if Data = null then 0 else Data'Length).
   type Buffer is new Ada.Finalization.Controlled with record
      Data : Byte_Array_Access := null;
      Len  : Natural           := 0;
   end record;

   overriding procedure Adjust   (Self : in out Buffer);  --  deep copy
   overriding procedure Finalize (Self : in out Buffer);  --  free, idempotent

end AHT.Bytes;
