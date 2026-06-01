--  RFC 3629 UTF-8 validation — the check a WebSocket endpoint applies
--  to inbound text-message payloads (and Close-frame reasons) before
--  accepting them, failing the connection with code 1007 on ill-formed
--  input (RFC 6455 §8.1).
--
--  No sockets: AHT.Websocket.UTF8.Is_Valid is a pure predicate over a
--  byte sequence. Vectors are drawn from the Autobahn|Testsuite §6
--  cases and Markus Kuhn's UTF-8 stress suite, so a regression here
--  maps straight to an Autobahn §6 failure.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;

with AHT.Bytes;
with AHT.Websocket.UTF8;

procedure Test_WS_UTF8 is

   Failures : Natural := 0;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_utf8: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   --  Hex string ("cebae1..." ) -> Byte_Array. Two hex chars per byte.
   function From_Hex (Hex : String) return AHT.Bytes.Byte_Array is
      function Val (C : Character) return Natural is
        (case C is
           when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
           when 'a' .. 'f' => 10 + Character'Pos (C) - Character'Pos ('a'),
           when 'A' .. 'F' => 10 + Character'Pos (C) - Character'Pos ('A'),
           when others     => raise Program_Error with "bad hex");
      B : AHT.Bytes.Byte_Array (1 .. Hex'Length / 2);
   begin
      for I in 0 .. B'Length - 1 loop
         B (B'First + I) :=
           AHT.Bytes.Octet
             (16 * Val (Hex (Hex'First + 2 * I))
              +    Val (Hex (Hex'First + 2 * I + 1)));
      end loop;
      return B;
   end From_Hex;

   function To_Vector (B : AHT.Bytes.Byte_Array) return AHT.Bytes.Byte_Vector
   is
      V : AHT.Bytes.Byte_Vector;
   begin
      for X of B loop
         V.Append (X);
      end loop;
      return V;
   end To_Vector;

   --  Assert Is_Valid (both overloads) on the given hex vector.
   procedure Expect (Name : String; Hex : String; Want : Boolean) is
      B : constant AHT.Bytes.Byte_Array := From_Hex (Hex);
   begin
      if AHT.Websocket.UTF8.Is_Valid (B) /= Want then
         Fail (Name & " (Byte_Array): expected "
               & (if Want then "valid" else "invalid"));
      end if;
      if AHT.Websocket.UTF8.Is_Valid (To_Vector (B)) /= Want then
         Fail (Name & " (Byte_Vector): expected "
               & (if Want then "valid" else "invalid"));
      end if;
   end Expect;

begin
   --  ---- valid ----------------------------------------------------
   Expect ("empty",            "",          True);
   Expect ("ascii-hello",      "48656c6c6f", True);   -- "Hello"
   Expect ("nul",              "00",        True);    -- U+0000
   --  Greek "κόσμε" — the canonical Autobahn §6 valid sequence.
   Expect ("kosme",           "cebae1bdb9cf83cebcceb5", True);
   --  Code-point boundaries (RFC 3629 Table 3-7).
   Expect ("U+007F",           "7f",        True);
   Expect ("U+0080",           "c280",      True);
   Expect ("U+07FF",           "dfbf",      True);
   Expect ("U+0800",           "e0a080",    True);
   Expect ("U+FFFF",           "efbfbf",    True);
   Expect ("U+10000",          "f0908080",  True);
   Expect ("U+10FFFF-max",     "f48fbfbf",  True);    -- last valid

   --  ---- invalid: stray / truncated -------------------------------
   Expect ("lone-cont-80",     "80",        False);
   Expect ("lone-cont-bf",     "bf",        False);
   Expect ("trunc-2byte",      "c2",        False);   -- needs 1 cont
   Expect ("trunc-3byte",      "e282",      False);   -- needs 1 more
   Expect ("trunc-4byte",      "f0908d",    False);   -- needs 1 more
   Expect ("cont-where-start", "c280bf",    False);   -- extra cont byte

   --  ---- invalid: overlong ----------------------------------------
   Expect ("overlong-nul-2",   "c080",      False);   -- U+0000 as 2 bytes
   Expect ("overlong-slash",   "c0af",      False);   -- '/' overlong
   Expect ("overlong-nul-3",   "e08080",    False);
   Expect ("overlong-nul-4",   "f0808080",  False);

   --  ---- invalid: surrogates (U+D800 .. U+DFFF) -------------------
   Expect ("surrogate-D800",   "eda080",    False);
   Expect ("surrogate-DFFF",   "edbfbf",    False);

   --  ---- invalid: out of range / illegal start bytes -------------
   Expect ("above-10FFFF",     "f4908080",  False);   -- U+110000
   Expect ("start-f5",         "f5808080",  False);
   Expect ("start-c0",         "c0",        False);
   Expect ("start-c1",         "c1",        False);
   Expect ("start-ff",         "ff",        False);
   Expect ("five-byte-form",   "f888808080", False);  -- forbidden 5-byte

   --  ---- invalid: the exact Autobahn 6.3.1 payload ---------------
   --  κόσμε + ED A0 80 (a surrogate) + "edited".
   Expect ("autobahn-6.3.1",
           "cebae1bdb9cf83cebcceb5eda080656469746564", False);

   if Failures = 0 then
      Put_Line ("test_ws_utf8: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_utf8:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_UTF8;
