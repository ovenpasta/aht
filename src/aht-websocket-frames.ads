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

   --  Where the caller is in a fragment sequence, so Decode can apply
   --  RFC 6455 §5.4 opcode sequencing at header-parse time.
   --
   --  Unchecked is the default, and has to be: Decode's contract is
   --  that it decodes any single frame in isolation, and callers that
   --  hold no message state -- the codec tests among them -- decode a
   --  standalone Continuation and expect it to succeed. A receiver
   --  that does track the sequence passes the real state.
   type Fragment_State is (Unchecked, No_Message, In_Message);

   procedure Decode
     (Input     : AHT.Bytes.Byte_Array;
      Hdr       : out Frame_Header;
      Payload   : out AHT.Bytes.Buffer;
      Last      : out Natural;
      Allowance : Natural        := Natural'Last;
      Fragment  : Fragment_State := Unchecked);
   --  Parses one frame off `Input`. On success `Last` is the
   --  index of the last consumed byte; on "need more bytes" the
   --  outputs are cleared and `Last := 0`. Both are *normal* returns:
   --  when Decode raises, none of the out parameters is meaningful,
   --  since copy-back of a scalar out parameter is not guaranteed on
   --  a propagating call. Callers distinguish "incomplete" from
   --  "rejected" by the exception, never by inspecting `Last`. Same direction-neutral
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
   --    * A data frame whose opcode contradicts `Fragment`: a
   --      `Continuation` with `No_Message`, or a `Text`/`Binary` with
   --      `In_Message` (RFC §5.4). Control frames interleave legally
   --      and are exempt.
   --
   --  Raises `AHT.Websocket.Message_Too_Big` when a *data* frame
   --  declares more than `Allowance` bytes. The check is at
   --  header-parse time, before the body is waited for, which is the
   --  entire point: Decode signals "incomplete" until the whole
   --  declared payload is buffered, so a ceiling applied to the
   --  returned frame would have to accumulate the bytes it exists to
   --  refuse. Rejection happens as soon as the length field itself is
   --  parsed — ten bytes for the 64-bit form, four for the 16-bit one
   --  — rather than after the declared payload has arrived.
   --
   --  Sequencing is checked BEFORE size. A data frame arriving where a
   --  `Continuation` was required is a 1002, and reporting 1009 for it
   --  because the remaining allowance happened to be smaller would
   --  hide the real fault.
   --
   --  For a fragmented message the receiver passes the allowance
   --  remaining for the whole logical message, so the ceiling bounds
   --  the message rather than each frame independently.
   --
   --  Both defaults reproduce the previous behaviour exactly.

   --  Inbound policy verdict for a *received* Close-frame payload,
   --  applied by the Client layer above Decode.
   --
   --  Decode is direction-neutral: it deliberately accepts every code
   --  in `Any_Close_Code` (so a peer/round-trip can carry even the
   --  synthetic 1005/1006/1015 — see the Decode contract) and does not
   --  inspect the reason text. The two rules below are inbound *policy*,
   --  not wire structure, so they live here rather than inside Decode:
   --
   --    * Reserved_Code — the 2-byte code is one a peer MUST NOT send
   --      (RFC 6455 §7.4.1): 1004 (reserved) and the synthetic,
   --      local-only 1005 / 1006 / 1015. The Client fails the
   --      connection with 1002 (protocol error).
   --    * Bad_Reason — the code is acceptable but the reason text after
   --      it is not valid UTF-8 (RFC 6455 §8.1). The Client fails with
   --      1007.
   --    * Accept_Close — empty payload, or a non-reserved code followed
   --      by a well-formed (or absent) reason. Normal close handling.
   --
   --  The payload is assumed already past Decode, so the illegal 1-byte
   --  case and any code outside `Any_Close_Code` have already raised and
   --  never reach here.
   type Inbound_Close_Status is (Accept_Close, Reserved_Code, Bad_Reason);

   function Classify_Inbound_Close
     (Payload : AHT.Bytes.Buffer) return Inbound_Close_Status;

end AHT.Websocket.Frames;
