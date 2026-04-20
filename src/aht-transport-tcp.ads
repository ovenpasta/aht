with AHT.Bytes;
with AHT.URL;

private with GNAT.Sockets;

package AHT.Transport.TCP is

   type TCP_Transport is new Transport_Type with private;
   type TCP_Transport_Access is access all TCP_Transport;

   procedure Connect
     (Self : in out TCP_Transport;
      Host : String;
      Port : AHT.URL.Port_Number);

   overriding procedure Write
     (Self : in out TCP_Transport;
      Data : AHT.Bytes.Byte_Array);

   overriding procedure Read
     (Self : in out TCP_Transport;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural);

   overriding procedure Close (Self : in out TCP_Transport);

   overriding function Is_Connected (Self : TCP_Transport) return Boolean;

private

   type TCP_Transport is new Transport_Type with record
      Socket    : GNAT.Sockets.Socket_Type := GNAT.Sockets.No_Socket;
      Channel   : GNAT.Sockets.Stream_Access := null;
      Connected : Boolean := False;
   end record;

end AHT.Transport.TCP;
