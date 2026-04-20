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
   --  Serializes a client frame: payload is masked with Hdr.Mask_Key on output.

   procedure Decode
     (Input   : AHT.Bytes.Byte_Array;
      Hdr     : out Frame_Header;
      Payload : out AHT.Bytes.Byte_Vector;
      Last    : out Natural);
   --  Parses a frame from Input [Input'First .. Last]. Sets Last = 0 if
   --  Input is incomplete; raises Protocol_Error on malformed data.

end AHT.Websocket.Frames;
