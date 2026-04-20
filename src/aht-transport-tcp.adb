package body AHT.Transport.TCP is

   procedure Connect
     (Self : in out TCP_Transport;
      Host : String;
      Port : AHT.URL.Port_Number)
   is
      pragma Unreferenced (Self, Host, Port);
   begin
      raise Transport_Error with "AHT.Transport.TCP.Connect: not yet implemented";
   end Connect;

   overriding procedure Write
     (Self : in out TCP_Transport;
      Data : AHT.Bytes.Byte_Array)
   is
      pragma Unreferenced (Self, Data);
   begin
      raise Transport_Error with "AHT.Transport.TCP.Write: not yet implemented";
   end Write;

   overriding procedure Read
     (Self : in out TCP_Transport;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural)
   is
      pragma Unreferenced (Self);
   begin
      Last := 0;
      for I in Data'Range loop
         Data (I) := 0;
      end loop;
      raise Transport_Error with "AHT.Transport.TCP.Read: not yet implemented";
   end Read;

   overriding procedure Close (Self : in out TCP_Transport) is
   begin
      Self.Connected := False;
   end Close;

   overriding function Is_Connected (Self : TCP_Transport) return Boolean is
     (Self.Connected);

end AHT.Transport.TCP;
