package body AHT.Transport is

   overriding procedure Finalize (Self : in out Transport_Type) is
   begin
      Close (Transport_Type'Class (Self));
   exception
      when others =>
         null;
   end Finalize;

end AHT.Transport;
