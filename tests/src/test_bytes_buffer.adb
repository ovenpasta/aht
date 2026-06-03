with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;

with Interfaces; use type Interfaces.Unsigned_8;

with AHT.Bytes; use AHT.Bytes;

procedure Test_Bytes_Buffer is

   Failures : Natural := 0;

   procedure Check (Cond : Boolean; Msg : String) is
   begin
      if not Cond then
         Put_Line ("test_bytes_buffer: FAIL — " & Msg);
         Failures := Failures + 1;
      end if;
   end Check;

begin
   --  Construction + whole-buffer round trips.
   declare
      B : constant Buffer := To_Buffer ("hello");
   begin
      Check (Length (B) = 5,          "To_Buffer(String) length");
      Check (not Is_Empty (B),        "To_Buffer(String) not empty");
      Check (To_String (B) = "hello", "To_String round trip");
      Check (First_Index (B) = 1,     "First_Index = 1");
      Check (Last_Index (B) = 5,      "Last_Index = Length");
      Check (Element (B, 1) = Character'Pos ('h'), "Element 1");
      Check (Element (B, 5) = Character'Pos ('o'), "Element Last");
   end;

   declare
      Data : constant Byte_Array := [10, 20, 30, 40];
      B    : constant Buffer := To_Buffer (Data);
   begin
      Check (Length (B) = 4,        "To_Buffer(Byte_Array) length");
      Check (To_Array (B) = Data,   "To_Array round trip");
   end;

   --  Default-initialized buffer is empty (Default_Initial_Condition).
   declare
      B : Buffer;
   begin
      Check (Is_Empty (B),           "default empty");
      Check (Length (B) = 0,         "default length 0");
      Check (To_String (B) = "",     "default To_String empty");
      Check (To_Array (B)'Length = 0, "default To_Array empty");
   end;

   --  Value semantics on initialization: copy then mutate is independent.
   declare
      A : Buffer := To_Buffer ("abc");
      C : Buffer := A;                       --  Adjust: deep copy
   begin
      Append (C, From_String ("XYZ"));
      Check (To_String (A) = "abc",    "init-copy: source unchanged");
      Check (To_String (C) = "abcXYZ", "init-copy: copy mutated");
      Append (A, 33);                        --  '!', octet overload
      Check (To_String (A) = "abc!",   "source mutated independently");
      Check (To_String (C) = "abcXYZ", "copy unaffected by source");
   end;

   --  Value semantics on assignment (Finalize old, copy, Adjust).
   declare
      A : constant Buffer := To_Buffer ("one");
      C : Buffer := To_Buffer ("two-original");
   begin
      C := A;
      Check (To_String (C) = "one", "assignment copies value");
      Append (C, 88);                        --  'X'
      Check (To_String (A) = "one", "assignment deep-copy independence");
   end;

   --  Self-assignment must preserve contents. Index by a runtime value
   --  (Argument_Count is 0 here, so I = J = 1) so GNAT cannot prove the
   --  two sides denote the same object and elide the assignment — this
   --  exercises the real Finalize-then-Adjust path on one object.
   declare
      Arr : array (1 .. 1) of Buffer;
      I   : constant Positive := Ada.Command_Line.Argument_Count + 1;
      J   : constant Positive := Ada.Command_Line.Argument_Count + 1;
   begin
      Arr (1) := To_Buffer ("self-assign-me");
      Arr (I) := Arr (J);
      Check (To_String (Arr (1)) = "self-assign-me",
             "self-assignment preserved");
      Append (Arr (1), 33);
      Check (To_String (Arr (1)) = "self-assign-me!",
             "usable after self-assign");
   end;

   --  Bulk Append concatenation + single-octet Append.
   declare
      B : Buffer;
   begin
      Append (B, From_String ("foo"));
      Append (B, From_String ("bar"));
      Check (To_String (B) = "foobar",  "bulk append concatenation");
      Append (B, 33);
      Check (To_String (B) = "foobar!", "octet append after bulk");
      --  Empty bulk append is a no-op.
      Append (B, From_String (""));
      Check (To_String (B) = "foobar!", "empty append is no-op");
   end;

   --  Set replaces wholesale.
   declare
      B : Buffer := To_Buffer ("discard this");
   begin
      Set (B, From_String ("kept"));
      Check (To_String (B) = "kept", "Set replaces contents");
   end;

   --  Slice extraction: array / string / sub-buffer + empty (High < Low).
   declare
      B : constant Buffer := To_Buffer ("0123456789");
   begin
      Check (To_String (B, 3, 5) = "234",          "To_String slice 3..5");
      Check (To_Array (B, 1, 2) = From_String ("01"), "To_Array slice 1..2");

      declare
         Sub : Buffer := Slice (B, 4, 6);
      begin
         Check (To_String (Sub) = "345", "Slice sub-buffer contents");
         Append (Sub, 88);                  --  'X'
         Check (To_String (Sub) = "345X",       "sub-buffer mutated");
         Check (To_String (B) = "0123456789",   "Slice source unchanged");
      end;

      --  Empty: High < Low yields empty in every form.
      Check (To_String (B, 5, 4) = "",        "empty To_String slice");
      Check (To_Array (B, 1, 0)'Length = 0,   "empty To_Array slice");
      Check (Is_Empty (Slice (B, 3, 2)),      "empty Slice");
      --  Boundary: Low = Length + 1 with High = Length is empty, legal.
      Check (Is_Empty (Slice (B, Length (B) + 1, Length (B))),
             "boundary empty slice (Low = Length + 1)");
      --  Whole-buffer slice.
      Check (To_String (B, 1, Length (B)) = "0123456789", "full slice");
   end;

   --  Clear / Reserve / Is_Empty + reuse after clear.
   declare
      B : Buffer;
   begin
      Reserve (B, 1000);
      Check (Is_Empty (B), "reserve keeps buffer empty");
      Append (B, From_String ("data"));
      Check (Length (B) = 4, "append after reserve");
      Clear (B);
      Check (Is_Empty (B) and Length (B) = 0, "clear empties");
      Append (B, From_String ("again"));
      Check (To_String (B) = "again", "reuse after clear");
   end;

   --  Large append: many bulk appends grow without losing bytes; the
   --  whole-buffer copy stays a single block move.
   declare
      B     : Buffer;
      Chunk : constant Byte_Array (1 .. 1000) := [others => 7];
      Total : constant Natural := 1000 * 1000;
   begin
      for I in 1 .. 1000 loop
         Append (B, Chunk);
      end loop;
      Check (Length (B) = Total,      "large append total length");
      Check (Element (B, 1) = 7,      "large append first byte");
      Check (Element (B, Total) = 7,  "large append last byte");
      declare
         A : constant Byte_Array := To_Array (B);
      begin
         Check (A'Length = Total,                  "large To_Array length");
         Check (A (A'First) = 7 and A (A'Last) = 7, "large To_Array bytes");
      end;
   end;

   --  Query: Process sees a view of the live bytes, no copy.
   declare
      B        : constant Buffer := To_Buffer ("query-me");
      Query_OK : Boolean := False;
      procedure Capture (Data : Byte_Array) is
      begin
         Query_OK := To_String (Data) = "query-me";
      end Capture;
   begin
      Query (B, Capture'Access);
      Check (Query_OK, "Query view matches contents");
   end;

   declare
      B       : Buffer;
      Got_Len : Natural := 99;
      procedure Capture (Data : Byte_Array) is
      begin
         Got_Len := Data'Length;
      end Capture;
   begin
      Query (B, Capture'Access);
      Check (Got_Len = 0, "Query empty view has length 0");
   end;

   if Failures = 0 then
      Put_Line ("test_bytes_buffer: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_bytes_buffer:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_Bytes_Buffer;
