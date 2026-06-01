with Ada.Containers;
with Interfaces; use Interfaces;

with AHT.Websocket.UTF8;

package body AHT.Websocket.Frames is

   --  Wire opcode <-> Opcode enum. The Opcode type uses a
   --  representation clause (Continuation => 0, Text => 1, ...,
   --  Close_Op => 8, ...), so 'Enum_Rep / 'Enum_Val (Ada 2022) map
   --  between Opcode and its 4-bit wire value.
   function Op_To_Wire (Op : Opcode) return Unsigned_8 is
     (Unsigned_8 (Opcode'Enum_Rep (Op)));

   function Op_From_Wire (Bits : Unsigned_8) return Opcode is
   begin
      case Bits is
         when 16#0# | 16#1# | 16#2# | 16#8# | 16#9# | 16#A# =>
            return Opcode'Enum_Val (Integer (Bits));
         when others =>
            raise Protocol_Error
              with "Frames: reserved/unknown opcode" & Bits'Image;
      end case;
   end Op_From_Wire;

   function Is_Control (Op : Opcode) return Boolean is
     (Op = Close_Op or else Op = Ping_Op or else Op = Pong_Op);

   --  Read the 2-byte big-endian close code at the start of a
   --  Close-frame payload. Caller must have already checked the
   --  buffer is at least 2 bytes long.
   function Close_Code_At
     (B : AHT.Bytes.Byte_Array; First : Positive) return Natural is
     (Natural (Shift_Left (Unsigned_16 (B (First)), 8)
                 or Unsigned_16 (B (First + 1))));

   --  RFC 6455 §5.5.1: a Close frame's payload is either empty or
   --  carries a 2-byte status code (optionally followed by a
   --  UTF-8 reason). A 1-byte payload is malformed; a present
   --  code must be in range.
   --
   --  Inbound (Decode) accepts any code in `Any_Close_Code`
   --  (1000..1015 ∪ 3000..4999, including the synthetic 1005 /
   --  1006 / 1015 that a misbehaving peer might wrongly send and
   --  we want to flag explicitly rather than silently coerce).
   --  Outbound (Encode) requires `Valid_Close_Code` — the
   --  synthetic codes must never leave us.
   procedure Validate_Close_Encode
     (Payload : AHT.Bytes.Byte_Array)
   is
      Code : Natural;
   begin
      if Payload'Length = 0 then
         return;
      end if;
      if Payload'Length = 1 then
         raise Protocol_Error
           with "Frames.Encode: Close payload of 1 byte is illegal "
             & "(must be 0 or >= 2 per RFC 6455 §5.5.1)";
      end if;
      Code := Close_Code_At (Payload, Payload'First);
      if Code not in Valid_Close_Code then
         raise Protocol_Error
           with "Frames.Encode: outbound Close code" & Code'Image
             & " is not a Valid_Close_Code (must be in "
             & "1000..1015 ∪ 3000..4999 and not 1005/1006/1015)";
      end if;
   end Validate_Close_Encode;

   procedure Validate_Close_Decode
     (Payload : AHT.Bytes.Byte_Vector)
   is
      Len  : constant Natural := Natural (Payload.Length);
      Code : Natural;
   begin
      if Len = 0 then
         return;
      end if;
      if Len = 1 then
         raise Protocol_Error
           with "Frames.Decode: Close payload of 1 byte is illegal "
             & "(must be 0 or >= 2 per RFC 6455 §5.5.1)";
      end if;
      Code :=
        Natural
          (Shift_Left (Unsigned_16 (Payload.Element
             (Payload.First_Index)), 8)
           or Unsigned_16 (Payload.Element
             (Payload.First_Index + 1)));
      if Code not in Any_Close_Code then
         raise Protocol_Error
           with "Frames.Decode: received Close code" & Code'Image
             & " is outside 1000..1015 ∪ 3000..4999";
      end if;
   end Validate_Close_Decode;

   function Classify_Inbound_Close
     (Payload : AHT.Bytes.Byte_Vector) return Inbound_Close_Status
   is
      Len  : constant Natural := Natural (Payload.Length);
      Code : Natural;
   begin
      if Len = 0 then
         return Accept_Close;
      end if;

      --  Len >= 2 here: Decode rejects a 1-byte Close payload before
      --  this is reached, so the 2-byte code is always present.
      Code :=
        Natural
          (Shift_Left (Unsigned_16 (Payload.Element
             (Payload.First_Index)), 8)
           or Unsigned_16 (Payload.Element
             (Payload.First_Index + 1)));
      if Code in 1004 | 1005 | 1006 | 1015 then
         return Reserved_Code;
      end if;

      --  Bytes after the 2-byte code are the reason text, which MUST
      --  be valid UTF-8 (RFC 6455 §8.1).
      if Len > 2 then
         declare
            Reason : AHT.Bytes.Byte_Vector;
         begin
            for I in Payload.First_Index + 2 .. Payload.Last_Index loop
               Reason.Append (Payload.Element (I));
            end loop;
            if not AHT.Websocket.UTF8.Is_Valid (Reason) then
               return Bad_Reason;
            end if;
         end;
      end if;

      return Accept_Close;
   end Classify_Inbound_Close;

   ---------------------------------------------------------------------
   --  Encode
   ---------------------------------------------------------------------

   function Encode
     (Hdr     : Frame_Header;
      Payload : AHT.Bytes.Byte_Array) return AHT.Bytes.Byte_Array
   is
      Len : constant Natural := Payload'Length;

      Header_Bytes : constant Natural :=
        (if Len <= 125     then 2
         elsif Len <= 65_535 then 4
         else                  10);
      Mask_Bytes : constant Natural := (if Hdr.Masked then 4 else 0);
      Total      : constant Natural := Header_Bytes + Mask_Bytes + Len;

      Result : AHT.Bytes.Byte_Array (1 .. Total);
      Idx    : Positive := 1;

      B0, B1 : Unsigned_8 := 0;
   begin
      --  Control frames per RFC 6455 §5.5: must not fragment
      --  (FIN=1) and payload <= 125 bytes. Outbound side reject
      --  so we never hand the wire a malformed frame.
      if Is_Control (Hdr.Op) then
         if not Hdr.FIN then
            raise Protocol_Error
              with "Frames.Encode: control frame must have FIN=1";
         end if;
         if Len > 125 then
            raise Protocol_Error
              with "Frames.Encode: control frame payload"
                & Natural'Image (Len) & " exceeds 125 bytes";
         end if;
         if Hdr.Op = Close_Op then
            Validate_Close_Encode (Payload);
         end if;
      end if;

      --  Byte 0: FIN | RSV1 | RSV2 | RSV3 | Opcode(4)
      if Hdr.FIN  then B0 := B0 or 16#80#; end if;
      if Hdr.RSV1 then B0 := B0 or 16#40#; end if;
      if Hdr.RSV2 then B0 := B0 or 16#20#; end if;
      if Hdr.RSV3 then B0 := B0 or 16#10#; end if;
      B0 := B0 or (Op_To_Wire (Hdr.Op) and 16#0F#);
      Result (Idx) := AHT.Bytes.Octet (B0);
      Idx := Idx + 1;

      --  Byte 1: MASK | Payload-length (7-bit code)
      B1 :=
        (if Len <= 125         then Unsigned_8 (Len)
         elsif Len <= 65_535   then 126
         else                       127);
      if Hdr.Masked then B1 := B1 or 16#80#; end if;
      Result (Idx) := AHT.Bytes.Octet (B1);
      Idx := Idx + 1;

      --  Extended length (big-endian).
      if Len > 125 and then Len <= 65_535 then
         declare
            V : constant Unsigned_16 := Unsigned_16 (Len);
         begin
            Result (Idx)     := AHT.Bytes.Octet (Shift_Right (V, 8));
            Result (Idx + 1) := AHT.Bytes.Octet (V and 16#FF#);
         end;
         Idx := Idx + 2;
      elsif Len > 65_535 then
         declare
            V : constant Unsigned_64 := Unsigned_64 (Len);
         begin
            for I in 0 .. 7 loop
               Result (Idx + I) :=
                 AHT.Bytes.Octet
                   (Shift_Right (V, 56 - 8 * I) and 16#FF#);
            end loop;
         end;
         Idx := Idx + 8;
      end if;

      --  Mask key (4 bytes) + payload (XOR-masked per RFC §5.3 if
      --  Hdr.Masked, raw otherwise).
      if Hdr.Masked then
         for I in 0 .. 3 loop
            Result (Idx + I) := Hdr.Mask_Key (Hdr.Mask_Key'First + I);
         end loop;
         Idx := Idx + 4;
         for I in 0 .. Len - 1 loop
            Result (Idx + I) :=
              Payload (Payload'First + I)
              xor Hdr.Mask_Key (Hdr.Mask_Key'First + (I mod 4));
         end loop;
      else
         for I in 0 .. Len - 1 loop
            Result (Idx + I) := Payload (Payload'First + I);
         end loop;
      end if;

      return Result;
   end Encode;

   ---------------------------------------------------------------------
   --  Decode
   ---------------------------------------------------------------------

   procedure Decode
     (Input   : AHT.Bytes.Byte_Array;
      Hdr     : out Frame_Header;
      Payload : out AHT.Bytes.Byte_Vector;
      Last    : out Natural)
   is
      Idx       : Positive;
      Available : Natural;
      B0, B1    : Unsigned_8;
      Short_Len : Unsigned_8;
      Len       : Natural;
   begin
      Hdr := (others => <>);
      Payload.Clear;
      Last := 0;

      if Input'Length < 2 then
         return;  -- need at least the two header bytes
      end if;

      Idx := Input'First;
      B0  := Unsigned_8 (Input (Idx));
      B1  := Unsigned_8 (Input (Idx + 1));
      Idx := Idx + 2;

      Hdr.FIN  := (B0 and 16#80#) /= 0;
      Hdr.RSV1 := (B0 and 16#40#) /= 0;
      Hdr.RSV2 := (B0 and 16#20#) /= 0;
      Hdr.RSV3 := (B0 and 16#10#) /= 0;

      --  RFC 6455 §5.2: RSV bits MUST be 0 unless an extension
      --  negotiated their use. v1 doesn't negotiate extensions, so
      --  any RSV bit set is a protocol error.
      if Hdr.RSV1 or else Hdr.RSV2 or else Hdr.RSV3 then
         raise Protocol_Error
           with "Frames.Decode: RSV bit set without negotiated extension";
      end if;

      Hdr.Op := Op_From_Wire (B0 and 16#0F#);

      Hdr.Masked := (B1 and 16#80#) /= 0;
      Short_Len  := B1 and 16#7F#;

      --  Determine the actual length, possibly reading extended
      --  length bytes. "incomplete" returns Last=0 without raising;
      --  "non-minimal encoding" or "MSB set on 127" raises.
      if Short_Len <= 125 then
         Len := Natural (Short_Len);
      elsif Short_Len = 126 then
         Available := Input'Last - Idx + 1;
         if Available < 2 then
            Last := 0; Payload.Clear; return;
         end if;
         declare
            V : constant Unsigned_16 :=
              Shift_Left (Unsigned_16 (Input (Idx)), 8)
                or Unsigned_16 (Input (Idx + 1));
         begin
            if V <= 125 then
               raise Protocol_Error
                 with "Frames.Decode: non-minimal length"
                   & " (16-bit used for value" & V'Image & ")";
            end if;
            Len := Natural (V);
         end;
         Idx := Idx + 2;
      else
         --  Short_Len = 127
         Available := Input'Last - Idx + 1;
         if Available < 8 then
            Last := 0; Payload.Clear; return;
         end if;
         declare
            V : Unsigned_64 := 0;
         begin
            for I in 0 .. 7 loop
               V := Shift_Left (V, 8) or Unsigned_64 (Input (Idx + I));
            end loop;
            if (V and 16#8000_0000_0000_0000#) /= 0 then
               raise Protocol_Error
                 with "Frames.Decode: 64-bit length has MSB set";
            end if;
            if V <= 65_535 then
               raise Protocol_Error
                 with "Frames.Decode: non-minimal length"
                   & " (64-bit used for value" & V'Image & ")";
            end if;
            if V > Unsigned_64 (Natural'Last) then
               raise Protocol_Error
                 with "Frames.Decode: payload length"
                   & V'Image & " exceeds Natural'Last";
            end if;
            Len := Natural (V);
         end;
         Idx := Idx + 8;
      end if;

      --  Control-frame structural checks (RFC §5.5): FIN must be
      --  set and length <= 125. We check after computing Len so
      --  the error message can reference the actual length.
      if Is_Control (Hdr.Op) then
         if not Hdr.FIN then
            raise Protocol_Error
              with "Frames.Decode: control frame must have FIN=1";
         end if;
         if Len > 125 then
            raise Protocol_Error
              with "Frames.Decode: control frame payload"
                & Natural'Image (Len) & " exceeds 125 bytes";
         end if;
      end if;

      --  Mask key (4 bytes) if MASK was set.
      if Hdr.Masked then
         Available := Input'Last - Idx + 1;
         if Available < 4 then
            Last := 0; Payload.Clear; return;
         end if;
         for I in 0 .. 3 loop
            Hdr.Mask_Key (Hdr.Mask_Key'First + I) := Input (Idx + I);
         end loop;
         Idx := Idx + 4;
      end if;

      --  Payload bytes. If the caller's buffer doesn't have the
      --  full payload yet, signal incomplete (Last=0) without
      --  consuming the partial header — re-decode on the next
      --  call with the extended buffer.
      Available := Input'Last - Idx + 1;
      if Available < Len then
         Last := 0; Payload.Clear; return;
      end if;

      Hdr.Payload_Length := Len;
      Payload.Reserve_Capacity (Ada.Containers.Count_Type (Len));
      if Hdr.Masked then
         for I in 0 .. Len - 1 loop
            Payload.Append
              (Input (Idx + I)
                 xor Hdr.Mask_Key (Hdr.Mask_Key'First + (I mod 4)));
         end loop;
      else
         for I in 0 .. Len - 1 loop
            Payload.Append (Input (Idx + I));
         end loop;
      end if;

      --  Close-payload structural + code-range validation. Done
      --  after assembly so the check operates on the unmasked
      --  bytes the application would see.
      if Hdr.Op = Close_Op then
         Validate_Close_Decode (Payload);
      end if;

      Last := Idx + Len - 1;
   end Decode;

end AHT.Websocket.Frames;
