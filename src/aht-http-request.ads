with AHT.Bytes;
with AHT.HTTP.Headers;
with AHT.HTTP.Methods;
with AHT.URL;

package AHT.HTTP.Request is

   pragma Preelaborate;

   type Request_Type is tagged record
      Method  : AHT.HTTP.Methods.Method_Type := AHT.HTTP.Methods.GET;
      Target  : AHT.URL.URL_Type;
      Headers : AHT.HTTP.Headers.Map;
      Body_B  : AHT.Bytes.Byte_Vector;
   end record;

end AHT.HTTP.Request;
