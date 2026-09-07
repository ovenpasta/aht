--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

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
   --  Serializes one frame per RFC 6455 sec. 5.2, exactly as
   --  Hdr.Masked and Hdr.Mask_Key describe; the Client layer enforces
   --  "clients MUST mask outbound" (sec. 5.3). Raises
   --  AHT.Websocket.Protocol_Error when a control frame has FIN = 0
   --  or a payload over 125 bytes (sec. 5.5), or a Close payload is
   --  1 byte or its code is not a Valid_Close_Code (sec. 5.5.1).

   --  Where the caller is in a fragment sequence, so Decode can apply
   --  RFC 6455 sec. 5.4 opcode sequencing. Unchecked, the default,
   --  decodes any single frame in isolation; a receiver that tracks
   --  the sequence passes the real state.
   type Fragment_State is (Unchecked, No_Message, In_Message);

   procedure Decode
     (Input     : AHT.Bytes.Byte_Array;
      Hdr       : out Frame_Header;
      Payload   : out AHT.Bytes.Buffer;
      Last      : out Natural;
      Allowance : Natural        := Natural'Last;
      Fragment  : Fragment_State := Unchecked);
   --  Parses one frame off Input. On success Last is the index of the
   --  last consumed byte; on "need more bytes" the outputs are
   --  cleared and Last is 0. When Decode raises no out parameter is
   --  meaningful. A masked frame is unmasked whoever sent it; the
   --  "servers MUST NOT mask" rule (sec. 5.1) is the Client layer's.
   --  Raises AHT.Websocket.Protocol_Error on: a reserved or unknown
   --  opcode; RSV1 / RSV2 / RSV3 set; a control frame with FIN = 0 or
   --  a payload over 125 bytes (sec. 5.5); a 1-byte Close payload, or
   --  a code outside Any_Close_Code (sec. 5.5.1); a non-minimal
   --  length encoding, a 64-bit length with the top bit set, or one
   --  overflowing Natural (sec. 5.2); a data frame whose opcode
   --  contradicts Fragment (sec. 5.4; control frames are exempt).
   --  Raises AHT.Websocket.Message_Too_Big when a data frame declares
   --  more than Allowance bytes, checked as soon as the length field
   --  is parsed, before the body is waited for; sequencing is checked
   --  first, so a misplaced frame is 1002, not 1009. For a fragmented
   --  message Allowance is what remains for the whole message.

   --  Inbound policy verdict for a Close payload already past Decode,
   --  applied by the Client layer.
   --    Reserved_Code  a code a peer MUST NOT send (RFC 6455
   --                   sec. 7.4.1): 1004, 1005, 1006, 1015. The
   --                   Client fails the connection with 1002.
   --    Bad_Reason     the reason is not valid UTF-8 (sec. 8.1). The
   --                   Client fails with 1007.
   --    Accept_Close   empty, or a non-reserved code and a
   --                   well-formed or absent reason.
   type Inbound_Close_Status is (Accept_Close, Reserved_Code, Bad_Reason);

   function Classify_Inbound_Close
     (Payload : AHT.Bytes.Buffer) return Inbound_Close_Status;

end AHT.Websocket.Frames;
