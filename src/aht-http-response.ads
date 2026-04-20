with Ada.Strings.Unbounded;

with AHT.Bytes;
with AHT.HTTP.Headers;
with AHT.HTTP.Status;

package AHT.HTTP.Response is

   pragma Preelaborate;

   type Response_Type is tagged record
      Status  : AHT.HTTP.Status.Status_Code := 200;
      Reason  : Ada.Strings.Unbounded.Unbounded_String;
      Headers : AHT.HTTP.Headers.Map;
      Body_B  : AHT.Bytes.Byte_Vector;
   end record;

end AHT.HTTP.Response;
