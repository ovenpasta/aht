package body AHT.Transport.TLS is

   procedure Connect
     (Self     : in out TLS_Transport;
      Host     : String;
      Port     : AHT.URL.Port_Number;
      Insecure : Boolean := False;
      CA_Path  : String  := "")
   is
      pragma Unreferenced (Self, Host, Port, Insecure, CA_Path);
   begin
      raise TLS_Error with "AHT.Transport.TLS.Connect: not yet implemented";
   end Connect;

   overriding procedure Write
     (Self : in out TLS_Transport;
      Data : AHT.Bytes.Byte_Array)
   is
      pragma Unreferenced (Self, Data);
   begin
      raise TLS_Error with "AHT.Transport.TLS.Write: not yet implemented";
   end Write;

   overriding procedure Read
     (Self : in out TLS_Transport;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural)
   is
      pragma Unreferenced (Self);
   begin
      Last := 0;
      for I in Data'Range loop
         Data (I) := 0;
      end loop;
      raise TLS_Error with "AHT.Transport.TLS.Read: not yet implemented";
   end Read;

   overriding procedure Close (Self : in out TLS_Transport) is
   begin
      Self.Connected := False;
   end Close;

   overriding function Is_Connected (Self : TLS_Transport) return Boolean is
     (Self.Connected);

end AHT.Transport.TLS;
