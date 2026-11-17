--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

--  AHT.Inflate against Python's zlib. The HTTP fixture serves each
--  /coded/<variant> body compressed by zlib and, with ?plain, the bytes
--  it was compressed from; the client fetches both with decompression
--  off, so the wire bytes reach this test untouched. Each variant is
--  decoded with input windows of 1, 13 and 4 096 bytes, which moves
--  every refill to a different point of the bit stream, and compared
--  byte for byte with the plain body.
--
--  The variants reach every block type (stored, fixed, dynamic), a
--  back-reference near the 32 KiB window limit, an overlapping copy,
--  every gzip header field, and a two-member gzip stream; the fixture
--  documents which body exercises which. Corruption is applied here,
--  to bytes zlib wrote: a flipped CRC, length or Adler byte, a cut
--  short stream, trailing bytes, and a hand-built back-reference to
--  before the start of the output.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes; use AHT.Bytes;
with AHT.HTTP.Client;
with AHT.HTTP.Response;
with AHT.Inflate;

procedure Test_Inflate is

   use type AHT.Bytes.Octet;
   use type AHT.Inflate.Format;

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_inflate: FAIL - " & Msg);
      Failures := Failures + 1;
   end Fail;

   Base : constant String := "http://127.0.0.1:8764/coded/";

   function Fetch (Path : String) return Byte_Array is
      C    : AHT.HTTP.Client.Client_Type;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Resp := AHT.HTTP.Client.Get (C, Base & Path);
      if Resp.Status /= 200 then
         raise Program_Error with Path & ": status" & Resp.Status'Image;
      end if;
      return Resp.Body_B.To_Array;
   end Fetch;

   --  Outcome of one Decode run.
   type Run_Result is record
      Output        : Buffer;
      Raised        : Boolean := False;
      Name          : Buffer;   --  exception name, when Raised
      Message       : Buffer;
      Bad_Slice     : Boolean := False;  --  empty or over 4 KiB
      Input_Calls   : Natural := 0;
      Output_Before_Last_Input : Boolean := False;
      Input_Before_Output : Natural := 0;
      --  Input bytes handed over before the first Output call.
   end record;

   --  Decode Wire with input windows of at most Window bytes.
   function Run
     (Kind   : AHT.Inflate.Format;
      Wire   : Byte_Array;
      Window : Positive) return Run_Result
   is
      R      : Run_Result;
      Cursor : Natural := Wire'First;
      Calls_With_Output : Natural := 0;   --  first such Input call

      procedure Input (Data : out Byte_Array; Last : out Natural) is
         N : constant Natural :=
           Natural'Min (Natural'Min (Window, Data'Length),
                        Wire'Last - Cursor + 1);
      begin
         R.Input_Calls := R.Input_Calls + 1;
         if R.Output.Length > 0 and then Calls_With_Output = 0 then
            Calls_With_Output := R.Input_Calls;
         end if;
         if N = 0 then
            Last := Data'First - 1;
            return;
         end if;
         Data (Data'First .. Data'First + N - 1) :=
           Wire (Cursor .. Cursor + N - 1);
         Last := Data'First + N - 1;
         Cursor := Cursor + N;
      end Input;

      procedure Output (Data : Byte_Array) is
      begin
         if R.Output.Length = 0 then
            R.Input_Before_Output := Cursor - Wire'First;
         end if;
         if Data'Length = 0 or else Data'Length > 4_096 then
            R.Bad_Slice := True;
         end if;
         R.Output.Append (Data);
      end Output;
   begin
      begin
         AHT.Inflate.Decode (Kind, Input'Access, Output'Access);
      exception
         when E : others =>
            R.Raised := True;
            R.Name.Set (Ada.Exceptions.Exception_Name (E));
            R.Message.Set (Ada.Exceptions.Exception_Message (E));
      end;
      --  Output was seen before the final Input call (the one that
      --  reported the end), so decoding did not wait for all input.
      R.Output_Before_Last_Input :=
        Calls_With_Output > 0 and then Calls_With_Output < R.Input_Calls;
      return R;
   end Run;

   procedure Expect_OK
     (Label  : String;
      Kind   : AHT.Inflate.Format;
      Wire   : Byte_Array;
      Plain  : Byte_Array;
      Window : Positive)
   is
      R : constant Run_Result := Run (Kind, Wire, Window);
      Tag : constant String :=
        Label & " (" & Kind'Image & ", window" & Window'Image & ")";
   begin
      if R.Raised then
         Fail (Tag & ": raised " & R.Name.To_String & ": "
               & R.Message.To_String);
         return;
      end if;
      if R.Bad_Slice then
         Fail (Tag & ": Output got an empty or over-4 KiB slice");
      end if;
      if R.Output.Length /= Plain'Length then
         Fail (Tag & ": decoded" & R.Output.Length'Image
               & " bytes, expected" & Plain'Length'Image);
      elsif R.Output.To_Array /= Plain then
         Fail (Tag & ": decoded bytes differ from the plain body");
      end if;
   end Expect_OK;

   procedure Expect_Data_Error
     (Label    : String;
      Kind     : AHT.Inflate.Format;
      Wire     : Byte_Array;
      Contains : String)
   is
      R : constant Run_Result := Run (Kind, Wire, 4_096);
   begin
      if not R.Raised then
         Fail (Label & ": decoded without error");
      elsif R.Name.To_String /= "AHT.INFLATE.DATA_ERROR" then
         Fail (Label & ": raised " & R.Name.To_String & ", not Data_Error");
      elsif Ada.Strings.Fixed.Index (R.Message.To_String, Contains) = 0 then
         Fail (Label & ": message """ & R.Message.To_String
               & """ lacks """ & Contains & """");
      end if;
   end Expect_Data_Error;

   function Kind_For (Variant : String) return AHT.Inflate.Format is
     (if Variant'Length >= 4
        and then Variant (Variant'First .. Variant'First + 3) = "gzip"
      then AHT.Inflate.Gzip
      else AHT.Inflate.Zlib_Or_Raw);

   function "+" (S : String) return Unbounded_String
     renames To_Unbounded_String;

   Variants : constant array (Positive range <>) of Unbounded_String :=
     [+"gzip-text",  +"gzip-random", +"gzip-small",  +"gzip-mixed",
      +"gzip-empty", +"gzip-fields", +"gzip-multi",  +"gzip-level0",
      +"zlib-text",  +"zlib-mixed",  +"raw-text",    +"raw-mixed",
      +"raw-level0"];

   type Window_List is array (Positive range <>) of Positive;
   Windows : constant Window_List := [1, 13, 4_096];

begin
   ------------------------------------------------------------------
   --  Every variant, every window size.
   ------------------------------------------------------------------
   for Name of Variants loop
      declare
         V : constant String := To_String (Name);
      begin
         declare
            Wire  : constant Byte_Array := Fetch (V);
            Plain : constant Byte_Array := Fetch (V & "?plain");
         begin
            for Window of Windows loop
               Expect_OK (V, Kind_For (V), Wire, Plain, Window);
            end loop;
         end;
      exception
         when E : others =>
            Fail (V & ": fetch raised "
                  & Ada.Exceptions.Exception_Information (E));
      end;
   end loop;

   ------------------------------------------------------------------
   --  Explicit formats: Zlib and Raw accept their own streams, and
   --  each refuses the other's.
   ------------------------------------------------------------------
   declare
      Z     : constant Byte_Array := Fetch ("zlib-text");
      Raw   : constant Byte_Array := Fetch ("raw-text");
      Plain : constant Byte_Array := Fetch ("raw-text?plain");
   begin
      Expect_OK ("zlib-text", AHT.Inflate.Zlib, Z, Plain, 4_096);
      Expect_OK ("raw-text", AHT.Inflate.Raw, Raw, Plain, 4_096);
      Expect_Data_Error ("raw stream as zlib", AHT.Inflate.Zlib, Raw,
                         "zlib: invalid header");
      --  Raw over a zlib stream reads the zlib header as block bits;
      --  whatever it decodes, the Adler-32 left over is trailing data
      --  or a broken block, never a clean end.
      declare
         R : constant Run_Result := Run (AHT.Inflate.Raw, Z, 4_096);
      begin
         if not R.Raised then
            Fail ("zlib stream as raw: decoded without error");
         end if;
      end;
   end;

   ------------------------------------------------------------------
   --  Streaming: decoded bytes are delivered before more input is
   --  pulled, not held until the 32 KiB window fills. gzip-text
   --  compresses about 14:1, so a decoder that waited for a full
   --  window would first deliver after roughly 2.3 KiB of input; one
   --  that flushes before each pull delivers within the first block,
   --  well inside 1 KiB.
   ------------------------------------------------------------------
   declare
      Wire : constant Byte_Array := Fetch ("gzip-text");
      R    : constant Run_Result := Run (AHT.Inflate.Gzip, Wire, 13);
   begin
      if not R.Output_Before_Last_Input then
         Fail ("gzip-text: no output was delivered before the last "
               & "Input call");
      end if;
      if R.Input_Before_Output >= 1_024 then
         Fail ("gzip-text: first output only after"
               & R.Input_Before_Output'Image & " input bytes");
      end if;
   end;

   ------------------------------------------------------------------
   --  Corruption.
   ------------------------------------------------------------------
   declare
      G : constant Byte_Array := Fetch ("gzip-text");
      Z : constant Byte_Array := Fetch ("zlib-text");
      W : Byte_Array (G'Range);
   begin
      --  Last 8 bytes: CRC-32 then ISIZE, little-endian.
      W := G;
      W (W'Last - 7) := W (W'Last - 7) xor 16#01#;
      Expect_Data_Error ("gzip CRC flipped", AHT.Inflate.Gzip, W,
                         "CRC-32 mismatch");
      W := G;
      W (W'Last) := W (W'Last) xor 16#80#;
      Expect_Data_Error ("gzip ISIZE flipped", AHT.Inflate.Gzip, W,
                         "length mismatch");
      W := G;
      W (W'First) := 16#1E#;
      Expect_Data_Error ("gzip magic", AHT.Inflate.Gzip, W, "bad magic");

      Expect_Data_Error ("gzip cut in the trailer", AHT.Inflate.Gzip,
                         G (G'First .. G'Last - 1), "truncated");
      Expect_Data_Error ("gzip cut mid-stream", AHT.Inflate.Gzip,
                         G (G'First .. G'First + G'Length / 2),
                         "truncated");
      Expect_Data_Error ("gzip header only", AHT.Inflate.Gzip,
                         G (G'First .. G'First + 9), "truncated");
      --  A byte past the member is read as the next member's header.
      Expect_Data_Error ("gzip trailing magic byte", AHT.Inflate.Gzip,
                         G & Byte_Array'[1 => 16#1F#], "truncated");
      Expect_Data_Error ("gzip trailing junk", AHT.Inflate.Gzip,
                         G & From_String ("junk!!!!!!!!"), "bad magic");

      declare
         ZW : Byte_Array := Z;
      begin
         ZW (ZW'Last) := ZW (ZW'Last) xor 16#01#;
         Expect_Data_Error ("zlib Adler flipped", AHT.Inflate.Zlib, ZW,
                            "Adler-32 mismatch");
      end;
      Expect_Data_Error ("zlib trailing byte", AHT.Inflate.Zlib,
                         Z & Byte_Array'[1 => 0], "trailing data");
      Expect_Data_Error ("zlib cut mid-stream", AHT.Inflate.Zlib,
                         Z (Z'First .. Z'First + Z'Length / 3),
                         "truncated");
   end;

   declare
      Raw : constant Byte_Array := Fetch ("raw-text");
   begin
      Expect_Data_Error ("raw cut mid-stream", AHT.Inflate.Raw,
                         Raw (Raw'First .. Raw'First + Raw'Length / 2),
                         "truncated");
      Expect_Data_Error ("raw trailing byte", AHT.Inflate.Raw,
                         Raw & Byte_Array'[1 => 16#42#], "trailing data");
   end;

   --  A fixed block whose first code is a length/distance pair
   --  (length 3, distance 1) with nothing decoded yet; zlib says
   --  "invalid distance too far back".
   Expect_Data_Error ("distance before the output", AHT.Inflate.Raw,
                      [16#03#, 16#02#, 16#00#], "reaches before");

   --  A fixed block holding only its end-of-block code: valid, empty.
   Expect_OK ("empty fixed block", AHT.Inflate.Raw,
              [16#03#, 16#00#], Byte_Array'(1 .. 0 => 0), 1);

   --  The same block cut after its first byte: the end-of-block code
   --  can only be completed from bits past the end of the input.
   Expect_Data_Error ("end of block from past the input", AHT.Inflate.Raw,
                      [1 => 16#03#], "truncated");

   --  A stream cut where the decoder's guesses past the end decode to
   --  something invalid still reports the cut: the 206 body the HTTP
   --  fixture serves is gzip-text's first 100 bytes.
   declare
      G : constant Byte_Array := Fetch ("gzip-text");
   begin
      Expect_Data_Error ("gzip cut at 100", AHT.Inflate.Gzip,
                         G (G'First .. G'First + 99), "truncated");
   end;

   --  Block type 3 is reserved.
   Expect_Data_Error ("reserved block type", AHT.Inflate.Raw,
                      [16#07#, 16#00#], "invalid block type");

   --  No input at all is no output, whatever the format.
   for Kind in AHT.Inflate.Format loop
      Expect_OK ("empty input", Kind, Byte_Array'(1 .. 0 => 0),
                 Byte_Array'(1 .. 0 => 0), 1);
   end loop;

   ------------------------------------------------------------------
   --  An exception from Input propagates as itself, not Data_Error.
   ------------------------------------------------------------------
   declare
      Wire   : constant Byte_Array := Fetch ("gzip-text");
      Cursor : Natural := Wire'First;
      Got    : Boolean := False;

      procedure Input (Data : out Byte_Array; Last : out Natural) is
      begin
         if Cursor > Wire'First + 100 then
            raise Constraint_Error with "input failed";
         end if;
         Data (Data'First) := Wire (Cursor);
         Last := Data'First;
         Cursor := Cursor + 1;
      end Input;

      procedure Output (Data : Byte_Array) is null;
   begin
      AHT.Inflate.Decode (AHT.Inflate.Gzip, Input'Access, Output'Access);
      Fail ("raising Input: Decode returned");
   exception
      when E : Constraint_Error =>
         Got := Ada.Exceptions.Exception_Message (E) = "input failed";
         if not Got then
            Fail ("raising Input: Constraint_Error with message """
                  & Ada.Exceptions.Exception_Message (E) & """");
         end if;
      when E : others =>
         Fail ("raising Input: got "
               & Ada.Exceptions.Exception_Name (E));
   end;

   if Failures = 0 then
      Put_Line ("test_inflate: OK");
   else
      Put_Line ("test_inflate:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_Inflate;
