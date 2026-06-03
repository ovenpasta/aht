--  RFC 6455 frame codec — encode/decode round-trips plus the
--  validation cases the Decode contract calls out. No sockets; the
--  codec works entirely over Byte_Array / Buffer.
--
--  Test vectors come from RFC 6455 §5.7 where applicable so
--  byte-exact comparisons stay honest.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces;  use Interfaces;

with AHT.Bytes;
with AHT.Websocket;
with AHT.Websocket.Frames;

procedure Test_WS_Frames is

   use type AHT.Websocket.Opcode;
   use all type AHT.Websocket.Frames.Inbound_Close_Status;

   Failures : Natural := 0;

   function To_Buf (A : AHT.Bytes.Byte_Array) return AHT.Bytes.Buffer is
     (AHT.Bytes.To_Buffer (A));

   procedure Fail (Msg : String) is
   begin
      Put_Line ("test_ws_frames: FAIL — " & Msg);
      Failures := Failures + 1;
   end Fail;

   function Buf_To_String (V : AHT.Bytes.Buffer) return String is
     (AHT.Bytes.To_String (V));

   function Bytes_Equal
     (A : AHT.Bytes.Byte_Array; B : AHT.Bytes.Byte_Array)
      return Boolean
   is
   begin
      if A'Length /= B'Length then
         return False;
      end if;
      for I in 0 .. A'Length - 1 loop
         if A (A'First + I) /= B (B'First + I) then
            return False;
         end if;
      end loop;
      return True;
   end Bytes_Equal;

   function Hex (B : AHT.Bytes.Byte_Array) return String is
      Digits_S : constant String := "0123456789ABCDEF";
      R : String (1 .. 2 * B'Length);
      K : Positive := 1;
   begin
      for I in B'Range loop
         R (K)     := Digits_S
           (Integer (Unsigned_8 (B (I)) / 16) + 1);
         R (K + 1) := Digits_S
           (Integer (Unsigned_8 (B (I)) mod 16) + 1);
         K := K + 2;
      end loop;
      return R;
   end Hex;

begin

   --  Case 1: encode unmasked text "Hello" — RFC 6455 §5.7 first
   --  example. Expected wire: 81 05 48 65 6C 6C 6F.
   declare
      Hdr : constant AHT.Websocket.Frames.Frame_Header :=
        (FIN    => True, Op => AHT.Websocket.Text, Masked => False,
         others => <>);
      Payload : constant AHT.Bytes.Byte_Array :=
        AHT.Bytes.From_String ("Hello");
      Expected : constant AHT.Bytes.Byte_Array :=
        [16#81#, 16#05#, 16#48#, 16#65#, 16#6C#, 16#6C#, 16#6F#];
      Got : constant AHT.Bytes.Byte_Array :=
        AHT.Websocket.Frames.Encode (Hdr, Payload);
   begin
      if not Bytes_Equal (Got, Expected) then
         Fail ("rfc-unmasked: got " & Hex (Got)
               & " expected " & Hex (Expected));
      end if;
   end;

   --  Case 2: encode masked text "Hello" with mask 37 FA 21 3D —
   --  RFC 6455 §5.7 second example. Expected wire:
   --  81 85 37 FA 21 3D 7F 9F 4D 51 58.
   declare
      Hdr : constant AHT.Websocket.Frames.Frame_Header :=
        (FIN    => True, Op => AHT.Websocket.Text, Masked => True,
         Mask_Key => [16#37#, 16#FA#, 16#21#, 16#3D#],
         others => <>);
      Payload : constant AHT.Bytes.Byte_Array :=
        AHT.Bytes.From_String ("Hello");
      Expected : constant AHT.Bytes.Byte_Array :=
        [16#81#, 16#85#,
         16#37#, 16#FA#, 16#21#, 16#3D#,
         16#7F#, 16#9F#, 16#4D#, 16#51#, 16#58#];
      Got : constant AHT.Bytes.Byte_Array :=
        AHT.Websocket.Frames.Encode (Hdr, Payload);
   begin
      if not Bytes_Equal (Got, Expected) then
         Fail ("rfc-masked: got " & Hex (Got)
               & " expected " & Hex (Expected));
      end if;
   end;

   --  Case 3: decode unmasked "Hello" (RFC 6455 §5.7 first vector).
   declare
      Wire : constant AHT.Bytes.Byte_Array :=
        [16#81#, 16#05#, 16#48#, 16#65#, 16#6C#, 16#6C#, 16#6F#];
      Hdr  : AHT.Websocket.Frames.Frame_Header;
      Pay  : AHT.Bytes.Buffer;
      Last : Natural;
   begin
      AHT.Websocket.Frames.Decode (Wire, Hdr, Pay, Last);
      if Last /= 7 then
         Fail ("decode-unmasked: Last =" & Last'Image);
      end if;
      if not Hdr.FIN or else Hdr.Op /= AHT.Websocket.Text
        or else Hdr.Masked
      then
         Fail ("decode-unmasked: header wrong");
      end if;
      if Buf_To_String (Pay) /= "Hello" then
         Fail ("decode-unmasked: payload = """
               & Buf_To_String (Pay) & """");
      end if;
   end;

   --  Case 4: decode masked "Hello" (RFC 6455 §5.7 second vector)
   --  — verifies unmasking applies the right xor.
   declare
      Wire : constant AHT.Bytes.Byte_Array :=
        [16#81#, 16#85#,
         16#37#, 16#FA#, 16#21#, 16#3D#,
         16#7F#, 16#9F#, 16#4D#, 16#51#, 16#58#];
      Hdr  : AHT.Websocket.Frames.Frame_Header;
      Pay  : AHT.Bytes.Buffer;
      Last : Natural;
   begin
      AHT.Websocket.Frames.Decode (Wire, Hdr, Pay, Last);
      if Last /= 11 then
         Fail ("decode-masked: Last =" & Last'Image);
      end if;
      if not Hdr.Masked then
         Fail ("decode-masked: Masked false");
      end if;
      if Buf_To_String (Pay) /= "Hello" then
         Fail ("decode-masked: payload = """
               & Buf_To_String (Pay) & """");
      end if;
   end;

   --  Case 5: round-trip a 200-byte binary masked frame —
   --  exercises the 2-byte extended-length path (126 .. 65535).
   declare
      Hdr : constant AHT.Websocket.Frames.Frame_Header :=
        (FIN    => True, Op => AHT.Websocket.Binary, Masked => True,
         Mask_Key => [16#AA#, 16#BB#, 16#CC#, 16#DD#],
         others => <>);
      Payload : AHT.Bytes.Byte_Array (1 .. 200);
      Wire : AHT.Bytes.Byte_Array (1 .. 200 + 8) := [others => 0];
      Wire_Len : Natural;
      Dec_Hdr : AHT.Websocket.Frames.Frame_Header;
      Dec_Pay : AHT.Bytes.Buffer;
      Dec_Last : Natural;
   begin
      for I in Payload'Range loop
         Payload (I) := AHT.Bytes.Octet (I mod 256);
      end loop;

      declare
         Got : constant AHT.Bytes.Byte_Array :=
           AHT.Websocket.Frames.Encode (Hdr, Payload);
      begin
         Wire_Len := Got'Length;
         Wire (1 .. Wire_Len) := Got;
      end;

      --  Header(2) + ext(2) + mask(4) + payload(200) = 208
      if Wire_Len /= 208 then
         Fail ("mid-len: wire size =" & Wire_Len'Image);
      end if;

      AHT.Websocket.Frames.Decode
        (Wire (1 .. Wire_Len), Dec_Hdr, Dec_Pay, Dec_Last);
      if Dec_Last /= Wire_Len then
         Fail ("mid-len: Decode Last =" & Dec_Last'Image);
      end if;
      if Dec_Hdr.Payload_Length /= 200 then
         Fail ("mid-len: decoded length ="
               & Dec_Hdr.Payload_Length'Image);
      end if;
      --  Body matches the input pre-mask.
      for I in 1 .. 200 loop
         if Dec_Pay.Element (I) /= Payload (I) then
            Fail ("mid-len: payload mismatch at" & I'Image);
            exit;
         end if;
      end loop;
   end;

   --  Case 6: round-trip a 70_000-byte binary masked frame —
   --  exercises the 8-byte extended-length path (> 65535).
   declare
      N : constant Natural := 70_000;
      Hdr : constant AHT.Websocket.Frames.Frame_Header :=
        (FIN    => True, Op => AHT.Websocket.Binary, Masked => True,
         Mask_Key => [16#01#, 16#02#, 16#03#, 16#04#],
         others => <>);
      Payload : AHT.Bytes.Byte_Array (1 .. N);
      Dec_Hdr : AHT.Websocket.Frames.Frame_Header;
      Dec_Pay : AHT.Bytes.Buffer;
      Dec_Last : Natural;
   begin
      for I in Payload'Range loop
         Payload (I) := AHT.Bytes.Octet ((I * 31) mod 256);
      end loop;
      declare
         Wire : constant AHT.Bytes.Byte_Array :=
           AHT.Websocket.Frames.Encode (Hdr, Payload);
      begin
         --  Header(2) + ext(8) + mask(4) + payload(N) = N + 14
         if Wire'Length /= N + 14 then
            Fail ("big-len: wire size =" & Wire'Length'Image);
         end if;
         AHT.Websocket.Frames.Decode (Wire, Dec_Hdr, Dec_Pay, Dec_Last);
         if Dec_Last /= Wire'Last then
            Fail ("big-len: Decode Last =" & Dec_Last'Image);
         end if;
         if Dec_Hdr.Payload_Length /= N then
            Fail ("big-len: decoded length ="
                  & Dec_Hdr.Payload_Length'Image);
         end if;
         for I in 1 .. N loop
            if Dec_Pay.Element (I) /= Payload (I) then
               Fail ("big-len: payload mismatch at" & I'Image);
               exit;
            end if;
         end loop;
      end;
   end;

   --  Case 7: encode a zero-payload ping.
   declare
      Hdr : constant AHT.Websocket.Frames.Frame_Header :=
        (FIN    => True, Op => AHT.Websocket.Ping_Op, Masked => True,
         Mask_Key => [16#11#, 16#22#, 16#33#, 16#44#],
         others => <>);
      Empty : constant AHT.Bytes.Byte_Array (1 .. 0) := [];
      Expected : constant AHT.Bytes.Byte_Array :=
        [16#89#, 16#80#, 16#11#, 16#22#, 16#33#, 16#44#];
      Got : constant AHT.Bytes.Byte_Array :=
        AHT.Websocket.Frames.Encode (Hdr, Empty);
   begin
      if not Bytes_Equal (Got, Expected) then
         Fail ("ping: got " & Hex (Got)
               & " expected " & Hex (Expected));
      end if;
   end;

   --  Case 8: decode two frames back-to-back — fragmented text
   --  "Hel" + "lo" (unmasked, server style). First call returns
   --  Last at byte 5; caller resumes from byte 6 for the second.
   declare
      Wire : constant AHT.Bytes.Byte_Array :=
        [16#01#, 16#03#, 16#48#, 16#65#, 16#6C#,   --  FIN=0 Text "Hel"
         16#80#, 16#02#, 16#6C#, 16#6F#];          --  FIN=1 Cont "lo"
      Hdr  : AHT.Websocket.Frames.Frame_Header;
      Pay  : AHT.Bytes.Buffer;
      Last : Natural;
   begin
      AHT.Websocket.Frames.Decode (Wire, Hdr, Pay, Last);
      if Last /= 5 then
         Fail ("frag-1: Last =" & Last'Image);
      end if;
      if Hdr.FIN or else Hdr.Op /= AHT.Websocket.Text then
         Fail ("frag-1: header wrong");
      end if;
      if Buf_To_String (Pay) /= "Hel" then
         Fail ("frag-1: payload = """ & Buf_To_String (Pay) & """");
      end if;

      AHT.Websocket.Frames.Decode (Wire (6 .. Wire'Last), Hdr, Pay, Last);
      if Last /= 9 then
         Fail ("frag-2: Last =" & Last'Image);
      end if;
      if not Hdr.FIN or else Hdr.Op /= AHT.Websocket.Continuation then
         Fail ("frag-2: header wrong");
      end if;
      if Buf_To_String (Pay) /= "lo" then
         Fail ("frag-2: payload = """ & Buf_To_String (Pay) & """");
      end if;
   end;

   --  Case 9: incomplete frames return Last=0 without raising, at
   --  each "need more bytes" boundary.
   declare
      --  One header byte only.
      Just_One : constant AHT.Bytes.Byte_Array := [16#81#];
      --  Two-byte header announcing 16-bit ext length, ext absent.
      Short_Ext : constant AHT.Bytes.Byte_Array := [16#82#, 16#7E#];
      --  Two-byte header announcing 64-bit ext length, ext absent.
      Short_Big : constant AHT.Bytes.Byte_Array := [16#82#, 16#7F#];
      --  Header + announce 5 mask, mask absent.
      Need_Mask : constant AHT.Bytes.Byte_Array := [16#81#, 16#85#];
      --  Header + 5-byte payload announced + 2 payload bytes.
      Short_Pay : constant AHT.Bytes.Byte_Array :=
        [16#81#, 16#05#, 16#48#, 16#65#];
      Hdr  : AHT.Websocket.Frames.Frame_Header;
      Pay  : AHT.Bytes.Buffer;
      Last : Natural;
   begin
      AHT.Websocket.Frames.Decode (Just_One, Hdr, Pay, Last);
      if Last /= 0 then
         Fail ("inc-1: Last =" & Last'Image);
      end if;
      AHT.Websocket.Frames.Decode (Short_Ext, Hdr, Pay, Last);
      if Last /= 0 then
         Fail ("inc-ext16: Last =" & Last'Image);
      end if;
      AHT.Websocket.Frames.Decode (Short_Big, Hdr, Pay, Last);
      if Last /= 0 then
         Fail ("inc-ext64: Last =" & Last'Image);
      end if;
      AHT.Websocket.Frames.Decode (Need_Mask, Hdr, Pay, Last);
      if Last /= 0 then
         Fail ("inc-mask: Last =" & Last'Image);
      end if;
      AHT.Websocket.Frames.Decode (Short_Pay, Hdr, Pay, Last);
      if Last /= 0 then
         Fail ("inc-pay: Last =" & Last'Image);
      end if;
   end;

   --  Case 10: opcode 0x3 is reserved/unassigned → Protocol_Error.
   declare
      Wire : constant AHT.Bytes.Byte_Array := [16#83#, 16#00#];
      Hdr  : AHT.Websocket.Frames.Frame_Header;
      Pay  : AHT.Bytes.Buffer;
      Last : Natural;
   begin
      AHT.Websocket.Frames.Decode (Wire, Hdr, Pay, Last);
      Fail ("bad-op: Decode returned without raising");
   exception
      when AHT.Websocket.Protocol_Error => null;
      when E : others =>
         Fail ("bad-op: wrong exception "
               & Ada.Exceptions.Exception_Name (E));
   end;

   --  Case 11: control frame (Close) with FIN=0 → Protocol_Error.
   declare
      Wire : constant AHT.Bytes.Byte_Array := [16#08#, 16#00#];
      Hdr  : AHT.Websocket.Frames.Frame_Header;
      Pay  : AHT.Bytes.Buffer;
      Last : Natural;
   begin
      AHT.Websocket.Frames.Decode (Wire, Hdr, Pay, Last);
      Fail ("frag-control: Decode returned without raising");
   exception
      when AHT.Websocket.Protocol_Error => null;
      when E : others =>
         Fail ("frag-control: wrong exception "
               & Ada.Exceptions.Exception_Name (E));
   end;

   --  Case 12: control frame with announced length 126 →
   --  Protocol_Error (and the 126 itself is non-minimal too; the
   --  control-length-overflow check catches it).
   declare
      Wire : constant AHT.Bytes.Byte_Array :=
        [16#89#, 16#7E#, 16#00#, 16#7E#];  -- ping ext-len=126
      Hdr  : AHT.Websocket.Frames.Frame_Header;
      Pay  : AHT.Bytes.Buffer;
      Last : Natural;
   begin
      AHT.Websocket.Frames.Decode (Wire, Hdr, Pay, Last);
      Fail ("big-control: Decode returned without raising");
   exception
      when AHT.Websocket.Protocol_Error => null;
      when E : others =>
         Fail ("big-control: wrong exception "
               & Ada.Exceptions.Exception_Name (E));
   end;

   --  Case 13: non-minimal length — 16-bit ext used for value 100,
   --  which fits in the 7-bit field. Must raise.
   declare
      Wire : constant AHT.Bytes.Byte_Array :=
        [16#82#, 16#7E#, 16#00#, 16#64#];  -- ext-len 0x0064 = 100
      Hdr  : AHT.Websocket.Frames.Frame_Header;
      Pay  : AHT.Bytes.Buffer;
      Last : Natural;
   begin
      AHT.Websocket.Frames.Decode (Wire, Hdr, Pay, Last);
      Fail ("non-min: Decode returned without raising");
   exception
      when AHT.Websocket.Protocol_Error => null;
      when E : others =>
         Fail ("non-min: wrong exception "
               & Ada.Exceptions.Exception_Name (E));
   end;

   --  Case 14: RSV1 set without negotiated extension → Protocol_Error.
   declare
      Wire : constant AHT.Bytes.Byte_Array := [16#C1#, 16#00#];
      --  C1 = FIN|RSV1|Text, length 0
      Hdr  : AHT.Websocket.Frames.Frame_Header;
      Pay  : AHT.Bytes.Buffer;
      Last : Natural;
   begin
      AHT.Websocket.Frames.Decode (Wire, Hdr, Pay, Last);
      Fail ("rsv: Decode returned without raising");
   exception
      when AHT.Websocket.Protocol_Error => null;
      when E : others =>
         Fail ("rsv: wrong exception "
               & Ada.Exceptions.Exception_Name (E));
   end;

   --  Case 15: outbound (Encode) control-frame validation —
   --  Encode with FIN=False on a Close opcode raises.
   declare
      Hdr : constant AHT.Websocket.Frames.Frame_Header :=
        (FIN    => False, Op => AHT.Websocket.Close_Op,
         Masked => True,
         Mask_Key => [16#00#, 16#00#, 16#00#, 16#00#],
         others => <>);
      Empty : constant AHT.Bytes.Byte_Array (1 .. 0) := [];
   begin
      declare
         Unused : constant AHT.Bytes.Byte_Array :=
           AHT.Websocket.Frames.Encode (Hdr, Empty);
      begin
         Fail ("encode-frag-control: Encode returned without raising");
      end;
   exception
      when AHT.Websocket.Protocol_Error => null;
      when E : others =>
         Fail ("encode-frag-control: wrong exception "
               & Ada.Exceptions.Exception_Name (E));
   end;

   --  Case 16: Encode a Close with no payload and a Close with a
   --  valid 2-byte code+reason both succeed.
   declare
      Hdr : constant AHT.Websocket.Frames.Frame_Header :=
        (FIN    => True, Op => AHT.Websocket.Close_Op,
         Masked => True,
         Mask_Key => [16#01#, 16#02#, 16#03#, 16#04#],
         others => <>);
      Empty : constant AHT.Bytes.Byte_Array (1 .. 0) := [];
      With_Code : constant AHT.Bytes.Byte_Array :=
        [16#03#, 16#E8#,  -- 1000 = Normal Closure
         Character'Pos ('b'), Character'Pos ('y'),
         Character'Pos ('e')];
   begin
      declare
         R1 : constant AHT.Bytes.Byte_Array :=
           AHT.Websocket.Frames.Encode (Hdr, Empty);
         R2 : constant AHT.Bytes.Byte_Array :=
           AHT.Websocket.Frames.Encode (Hdr, With_Code);
      begin
         if R1'Length /= 6 then
            Fail ("close-empty: wire length =" & R1'Length'Image);
         end if;
         if R2'Length /= 11 then
            Fail ("close-code: wire length =" & R2'Length'Image);
         end if;
      end;
   exception
      when E : others =>
         Fail ("close-good: unexpected exception "
               & Ada.Exceptions.Exception_Name (E));
   end;

   --  Case 17: Encode Close with a 1-byte payload → Protocol_Error
   --  (RFC §5.5.1 — must be 0 or >= 2 bytes).
   declare
      Hdr : constant AHT.Websocket.Frames.Frame_Header :=
        (FIN    => True, Op => AHT.Websocket.Close_Op,
         Masked => True,
         Mask_Key => [16#00#, 16#00#, 16#00#, 16#00#],
         others => <>);
      One : constant AHT.Bytes.Byte_Array (1 .. 1) := [16#03#];
   begin
      declare
         Unused : constant AHT.Bytes.Byte_Array :=
           AHT.Websocket.Frames.Encode (Hdr, One);
      begin
         Fail ("close-1byte: Encode returned without raising");
      end;
   exception
      when AHT.Websocket.Protocol_Error => null;
      when E : others =>
         Fail ("close-1byte: wrong exception "
               & Ada.Exceptions.Exception_Name (E));
   end;

   --  Case 18: Encode Close with synthetic code 1005 →
   --  Protocol_Error (must never appear on the wire).
   declare
      Hdr : constant AHT.Websocket.Frames.Frame_Header :=
        (FIN    => True, Op => AHT.Websocket.Close_Op,
         Masked => True,
         Mask_Key => [16#00#, 16#00#, 16#00#, 16#00#],
         others => <>);
      Payload : constant AHT.Bytes.Byte_Array :=
        [16#03#, 16#ED#];  -- 1005
   begin
      declare
         Unused : constant AHT.Bytes.Byte_Array :=
           AHT.Websocket.Frames.Encode (Hdr, Payload);
      begin
         Fail ("close-1005: Encode returned without raising");
      end;
   exception
      when AHT.Websocket.Protocol_Error => null;
      when E : others =>
         Fail ("close-1005: wrong exception "
               & Ada.Exceptions.Exception_Name (E));
   end;

   --  Case 19: Encode Close with out-of-range code 999 →
   --  Protocol_Error.
   declare
      Hdr : constant AHT.Websocket.Frames.Frame_Header :=
        (FIN    => True, Op => AHT.Websocket.Close_Op,
         Masked => True,
         Mask_Key => [16#00#, 16#00#, 16#00#, 16#00#],
         others => <>);
      Payload : constant AHT.Bytes.Byte_Array :=
        [16#03#, 16#E7#];  -- 999
   begin
      declare
         Unused : constant AHT.Bytes.Byte_Array :=
           AHT.Websocket.Frames.Encode (Hdr, Payload);
      begin
         Fail ("close-999: Encode returned without raising");
      end;
   exception
      when AHT.Websocket.Protocol_Error => null;
      when E : others =>
         Fail ("close-999: wrong exception "
               & Ada.Exceptions.Exception_Name (E));
   end;

   --  Case 20: Decode a server Close (unmasked) with normal code
   --  1000 → succeeds. Verifies the inbound validator accepts a
   --  good close.
   declare
      Wire : constant AHT.Bytes.Byte_Array :=
        [16#88#, 16#02#, 16#03#, 16#E8#];  -- FIN|Close, len 2, 1000
      Hdr  : AHT.Websocket.Frames.Frame_Header;
      Pay  : AHT.Bytes.Buffer;
      Last : Natural;
   begin
      AHT.Websocket.Frames.Decode (Wire, Hdr, Pay, Last);
      if Last /= 4 then
         Fail ("decode-close-good: Last =" & Last'Image);
      end if;
      if Hdr.Op /= AHT.Websocket.Close_Op then
         Fail ("decode-close-good: opcode wrong");
      end if;
   end;

   --  Case 21: Decode a server Close with a 1-byte payload →
   --  Protocol_Error.
   declare
      Wire : constant AHT.Bytes.Byte_Array :=
        [16#88#, 16#01#, 16#03#];  -- FIN|Close, len 1
      Hdr  : AHT.Websocket.Frames.Frame_Header;
      Pay  : AHT.Bytes.Buffer;
      Last : Natural;
   begin
      AHT.Websocket.Frames.Decode (Wire, Hdr, Pay, Last);
      Fail ("decode-close-1byte: Decode returned without raising");
   exception
      when AHT.Websocket.Protocol_Error => null;
      when E : others =>
         Fail ("decode-close-1byte: wrong exception "
               & Ada.Exceptions.Exception_Name (E));
   end;

   --  Case 22: Decode a server Close with out-of-range code 999 →
   --  Protocol_Error.
   declare
      Wire : constant AHT.Bytes.Byte_Array :=
        [16#88#, 16#02#, 16#03#, 16#E7#];  -- 999
      Hdr  : AHT.Websocket.Frames.Frame_Header;
      Pay  : AHT.Bytes.Buffer;
      Last : Natural;
   begin
      AHT.Websocket.Frames.Decode (Wire, Hdr, Pay, Last);
      Fail ("decode-close-999: Decode returned without raising");
   exception
      when AHT.Websocket.Protocol_Error => null;
      when E : others =>
         Fail ("decode-close-999: wrong exception "
               & Ada.Exceptions.Exception_Name (E));
   end;

   --  Case 23: Decode accepts a Close with code 1006 — the
   --  synthetic codes are valid as inbound observations
   --  (Any_Close_Code), even though the spec says peers SHOULD
   --  NOT send them. Decode trusts the wire and surfaces them;
   --  the WebSocket Client layer decides what to do with such
   --  an oddity.
   declare
      Wire : constant AHT.Bytes.Byte_Array :=
        [16#88#, 16#02#, 16#03#, 16#EE#];  -- 1006
      Hdr  : AHT.Websocket.Frames.Frame_Header;
      Pay  : AHT.Bytes.Buffer;
      Last : Natural;
   begin
      AHT.Websocket.Frames.Decode (Wire, Hdr, Pay, Last);
      if Last /= 4 then
         Fail ("decode-close-1006: Last =" & Last'Image);
      end if;
      if Pay.Length /= 2 then
         Fail ("decode-close-1006: payload length ="
               & Pay.Length'Image);
      end if;
   end;

   --  Case 24: Encode Close with reserved code 1004 → Protocol_Error.
   --  1004 has no defined meaning and MUST NOT be sent (RFC §7.4.1), so
   --  Valid_Close_Code excludes it just like the synthetic 1005/1006/1015.
   declare
      Hdr : constant AHT.Websocket.Frames.Frame_Header :=
        (FIN    => True, Op => AHT.Websocket.Close_Op,
         Masked => True,
         Mask_Key => [16#00#, 16#00#, 16#00#, 16#00#],
         others => <>);
      Payload : constant AHT.Bytes.Byte_Array :=
        [16#03#, 16#EC#];  -- 1004
   begin
      declare
         Unused : constant AHT.Bytes.Byte_Array :=
           AHT.Websocket.Frames.Encode (Hdr, Payload);
      begin
         Fail ("close-1004: Encode returned without raising");
      end;
   exception
      when AHT.Websocket.Protocol_Error => null;
      when E : others =>
         Fail ("close-1004: wrong exception "
               & Ada.Exceptions.Exception_Name (E));
   end;

   --  Case 25: Classify_Inbound_Close on an empty payload → Accept_Close.
   --  A bodiless Close is the normal "no status" signal (RFC §5.5.1).
   declare
      Empty : constant AHT.Bytes.Buffer := To_Buf ([]);
   begin
      if AHT.Websocket.Frames.Classify_Inbound_Close (Empty)
        /= Accept_Close
      then
         Fail ("classify-empty: not Accept_Close");
      end if;
   end;

   --  Case 26: code 1000 + ASCII reason "bye" → Accept_Close.
   declare
      Pay : constant AHT.Bytes.Buffer :=
        To_Buf ([16#03#, 16#E8#,  -- 1000
                 Character'Pos ('b'), Character'Pos ('y'),
                 Character'Pos ('e')]);
   begin
      if AHT.Websocket.Frames.Classify_Inbound_Close (Pay)
        /= Accept_Close
      then
         Fail ("classify-good-reason: not Accept_Close");
      end if;
   end;

   --  Case 27: each reserved-on-wire code 1004/1005/1006/1015 a peer
   --  MUST NOT send (RFC §7.4.1) → Reserved_Code.
   declare
      type Code_Pair is array (1 .. 2) of AHT.Bytes.Octet;
      Reserved : constant array (1 .. 4) of Code_Pair :=
        [[16#03#, 16#EC#],   -- 1004
         [16#03#, 16#ED#],   -- 1005
         [16#03#, 16#EE#],   -- 1006
         [16#03#, 16#F7#]];  -- 1015
   begin
      for P of Reserved loop
         declare
            Pay : constant AHT.Bytes.Buffer :=
              To_Buf ([P (1), P (2)]);
         begin
            if AHT.Websocket.Frames.Classify_Inbound_Close (Pay)
              /= Reserved_Code
            then
               Fail ("classify-reserved: code "
                     & Hex ([P (1), P (2)]) & " not Reserved_Code");
            end if;
         end;
      end loop;
   end;

   --  Case 28: acceptable code 1000 + ill-formed UTF-8 reason (a lone
   --  continuation byte 0x80) → Bad_Reason (RFC §8.1).
   declare
      Pay : constant AHT.Bytes.Buffer :=
        To_Buf ([16#03#, 16#E8#, 16#80#]);  -- 1000 + 0x80
   begin
      if AHT.Websocket.Frames.Classify_Inbound_Close (Pay)
        /= Bad_Reason
      then
         Fail ("classify-bad-reason: not Bad_Reason");
      end if;
   end;

   --  Case 29: code 1000 + valid multi-byte reason "é" (C3 A9) →
   --  Accept_Close. Positive control that the reason check is not
   --  over-eager on legitimate non-ASCII text.
   declare
      Pay : constant AHT.Bytes.Buffer :=
        To_Buf ([16#03#, 16#E8#, 16#C3#, 16#A9#]);  -- 1000 + U+00E9
   begin
      if AHT.Websocket.Frames.Classify_Inbound_Close (Pay)
        /= Accept_Close
      then
         Fail ("classify-utf8-reason: not Accept_Close");
      end if;
   end;

   if Failures = 0 then
      Put_Line ("test_ws_frames: OK");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Put_Line ("test_ws_frames:" & Failures'Image & " failure(s)");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_WS_Frames;
