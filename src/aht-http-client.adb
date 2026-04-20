package body AHT.HTTP.Client is

   procedure Send
     (Self : in out Client_Type;
      Req  : AHT.HTTP.Request.Request_Type;
      Resp : out AHT.HTTP.Response.Response_Type)
   is
      pragma Unreferenced (Self, Req);
   begin
      Resp := (others => <>);
      raise HTTP_Error with "AHT.HTTP.Client.Send: not yet implemented";
   end Send;

   function Get
     (Self : in out Client_Type;
      URL  : String) return AHT.HTTP.Response.Response_Type
   is
      pragma Unreferenced (Self, URL);
      Empty : AHT.HTTP.Response.Response_Type;
   begin
      raise HTTP_Error with "AHT.HTTP.Client.Get: not yet implemented";
      return Empty;
   end Get;

end AHT.HTTP.Client;
