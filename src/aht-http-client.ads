with Ada.Strings.Unbounded;

with AHT.HTTP.Headers;
with AHT.HTTP.Request;
with AHT.HTTP.Response;

package AHT.HTTP.Client is

   type Client_Type is tagged record
      User_Agent      : Ada.Strings.Unbounded.Unbounded_String :=
        Ada.Strings.Unbounded.To_Unbounded_String ("AHT/0.1");
      Default_Headers : AHT.HTTP.Headers.Map;
      CA_Path         : Ada.Strings.Unbounded.Unbounded_String;
      Insecure        : Boolean := False;
      Timeout_Seconds : Natural := 30;
   end record;

   procedure Send
     (Self : in out Client_Type;
      Req  : AHT.HTTP.Request.Request_Type;
      Resp : out AHT.HTTP.Response.Response_Type);

   function Get
     (Self : in out Client_Type;
      URL  : String) return AHT.HTTP.Response.Response_Type;

end AHT.HTTP.Client;
