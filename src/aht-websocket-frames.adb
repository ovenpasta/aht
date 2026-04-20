package body AHT.Websocket.Frames is

   function Encode
     (Hdr     : Frame_Header;
      Payload : AHT.Bytes.Byte_Array) return AHT.Bytes.Byte_Array
   is
      pragma Unreferenced (Hdr, Payload);
      Stub : AHT.Bytes.Byte_Array (1 .. 2) := [others => 0];
   begin
      raise Protocol_Error with "AHT.Websocket.Frames.Encode: not yet implemented";
      return Stub;
   end Encode;

   procedure Decode
     (Input   : AHT.Bytes.Byte_Array;
      Hdr     : out Frame_Header;
      Payload : out AHT.Bytes.Byte_Vector;
      Last    : out Natural)
   is
      pragma Unreferenced (Input);
   begin
      Hdr := (others => <>);
      Payload.Clear;
      Last := 0;
      raise Protocol_Error with "AHT.Websocket.Frames.Decode: not yet implemented";
   end Decode;

end AHT.Websocket.Frames;
