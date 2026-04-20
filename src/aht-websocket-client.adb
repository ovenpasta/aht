package body AHT.Websocket.Client is

   procedure Connect
     (Self          : in out Client_Type;
      URL           : String;
      Extra_Headers : AHT.HTTP.Headers.Map;
      Subprotocols  : String := "";
      Origin        : String := "";
      Insecure      : Boolean := False;
      CA_Path       : String := "")
   is
      pragma Unreferenced (Self, URL, Extra_Headers, Subprotocols, Origin, Insecure, CA_Path);
   begin
      raise Handshake_Error with "AHT.Websocket.Client.Connect: not yet implemented";
   end Connect;

   procedure Connect
     (Self     : in out Client_Type;
      URL      : String;
      Insecure : Boolean := False;
      CA_Path  : String := "")
   is
      Empty : AHT.HTTP.Headers.Map;
   begin
      Connect (Self, URL, Empty, "", "", Insecure, CA_Path);
   end Connect;

   function Is_Open (Self : Client_Type) return Boolean is (Self.Open);

   procedure Send_Text
     (Self : in out Client_Type;
      Text : String)
   is
      pragma Unreferenced (Self, Text);
   begin
      raise Closed_Error with "AHT.Websocket.Client.Send_Text: not yet implemented";
   end Send_Text;

   procedure Send_Binary
     (Self : in out Client_Type;
      Data : AHT.Bytes.Byte_Array)
   is
      pragma Unreferenced (Self, Data);
   begin
      raise Closed_Error with "AHT.Websocket.Client.Send_Binary: not yet implemented";
   end Send_Binary;

   procedure Send_Ping
     (Self    : in out Client_Type;
      Payload : AHT.Bytes.Byte_Array := [])
   is
      pragma Unreferenced (Self, Payload);
   begin
      raise Closed_Error with "AHT.Websocket.Client.Send_Ping: not yet implemented";
   end Send_Ping;

   procedure Close
     (Self   : in out Client_Type;
      Code   : Valid_Close_Code := 1000;
      Reason : String := "")
   is
      pragma Unreferenced (Code, Reason);
   begin
      Self.Open := False;
   end Close;

   procedure Receive
     (Self    : in out Client_Type;
      Msg     : out Message_Type;
      Timeout : Duration := Duration'Last)
   is
      pragma Unreferenced (Self, Timeout);
   begin
      Msg := (Kind => Binary_Message, Payload => <>);
      raise Closed_Error with "AHT.Websocket.Client.Receive: not yet implemented";
   end Receive;

   procedure Set_On_Message (Self : in out Client_Type; CB : On_Message_Callback) is
   begin
      Self.On_Message := CB;
   end Set_On_Message;

   procedure Set_On_Close (Self : in out Client_Type; CB : On_Close_Callback) is
   begin
      Self.On_Close := CB;
   end Set_On_Close;

   procedure Set_On_Error (Self : in out Client_Type; CB : On_Error_Callback) is
   begin
      Self.On_Error := CB;
   end Set_On_Error;

   function Selected_Subprotocol (Self : Client_Type) return String is
     (Ada.Strings.Unbounded.To_String (Self.Selected_Protocol));

end AHT.Websocket.Client;
