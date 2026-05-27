with AHT.Bytes;

package AHT.Websocket.Frames is

   pragma Preelaborate;

   type Frame_Header is record
      FIN           : Boolean := True;
      RSV1          : Boolean := False;
      RSV2          : Boolean := False;
      RSV3          : Boolean := False;
      Op            : Opcode  := Text;
      Masked        : Boolean := True;
      Payload_Length : Natural := 0;
      Mask_Key       : AHT.Bytes.Byte_Array (1 .. 4) := [others => 0];
   end record;

   function Encode
     (Hdr     : Frame_Header;
      Payload : AHT.Bytes.Byte_Array) return AHT.Bytes.Byte_Array
     with Post => Encode'Result'Length >= 2;
   --  Serializes one frame per RFC 6455 §5.2. The codec is
   --  *direction-neutral* on masking: it emits the frame exactly
   --  as `Hdr.Masked` and `Hdr.Mask_Key` describe (masked with
   --  `Mask_Key` if `Masked = True`, raw otherwise). The
   --  WebSocket Client layer is what enforces "clients MUST mask
   --  outbound" (RFC §5.3) — Frames itself just realises whatever
   --  the caller asks for, which keeps the codec round-trip-
   --  testable without bouncing through a real peer.
   --
   --  Validations that ARE protocol-level (not direction-specific)
   --  and so live here:
   --    * Control frames (Close / Ping / Pong) must have FIN = 1
   --      and payload <= 125 bytes (RFC §5.5).
   --    * Close frames carrying a payload must use 2+ bytes — a
   --      1-byte payload is illegal (RFC §5.5.1) — and the first
   --      2 bytes must be a `Valid_Close_Code` (i.e. in the wire
   --      range and not one of the synthetic 1005 / 1006 / 1015,
   --      which must never appear on outbound wire).
   --  Each violation raises `AHT.Websocket.Protocol_Error`.

   procedure Decode
     (Input   : AHT.Bytes.Byte_Array;
      Hdr     : out Frame_Header;
      Payload : out AHT.Bytes.Byte_Vector;
      Last    : out Natural);
   --  Parses one frame off `Input`. On success `Last` is the
   --  index of the last consumed byte; on "need more bytes" the
   --  outputs are cleared and `Last := 0`. Same direction-neutral
   --  philosophy: a masked frame is parsed and unmasked
   --  regardless of who supposedly sent it, with the
   --  "servers MUST NOT mask" rule (RFC §5.1) deferred to the
   --  Client layer above.
   --
   --  Raises `AHT.Websocket.Protocol_Error` on malformed wire:
   --    * Reserved or unknown opcode (RFC §5.2).
   --    * RSV1 / RSV2 / RSV3 set without negotiated extension
   --      (v1 negotiates none).
   --    * Control frame fragmented (FIN = 0) or with payload
   --      length > 125 (RFC §5.5).
   --    * Close payload of exactly 1 byte (RFC §5.5.1).
   --    * Close payload with a 2-byte code outside the
   --      `Any_Close_Code` range (1000..1015 ∪ 3000..4999).
   --    * Non-minimal length encoding (16-bit ext for a value
   --      that fits in 7 bits, 64-bit ext for a value that fits
   --      in 16 bits, RFC §5.2).
   --    * 64-bit length with the top bit set (RFC §5.2) or a
   --      length overflowing `Natural`.

end AHT.Websocket.Frames;
