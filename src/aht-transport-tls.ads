with AHT.Bytes;
with AHT.URL;

package AHT.Transport.TLS is

   type TLS_Transport is new Transport_Type with private;
   type TLS_Transport_Access is access all TLS_Transport;

   TLS_Error : exception;

   procedure Connect
     (Self     : in out TLS_Transport;
      Host     : String;
      Port     : AHT.URL.Port_Number;
      Insecure : Boolean := False;
      CA_Path  : String  := "");

   overriding procedure Write
     (Self : in out TLS_Transport;
      Data : AHT.Bytes.Byte_Array);

   overriding procedure Read
     (Self : in out TLS_Transport;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural);

   overriding procedure Close (Self : in out TLS_Transport);

   overriding function Is_Connected (Self : TLS_Transport) return Boolean;

private

   type TLS_Transport is new Transport_Type with record
      Connected : Boolean := False;
   end record;

end AHT.Transport.TLS;
