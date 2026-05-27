with Ada.Strings.Unbounded;

with AHT.Bytes;
with AHT.HTTP.Headers;
with AHT.Transport.TCP;

package AHT.Websocket.Client is

   type Client_Type is tagged limited private;
   type Client_Access is access all Client_Type;

   type Message_Type (Kind : Message_Kind := Binary_Message) is record
      Payload : AHT.Bytes.Byte_Vector;
   end record;

   type On_Message_Callback is access procedure (Msg : Message_Type);
   type On_Close_Callback   is access procedure
     (Info : Close_Info; Reason : String);
   type On_Error_Callback   is access procedure (Message : String);

   procedure Connect
     (Self          : in out Client_Type;
      URL           : String;
      Extra_Headers : AHT.HTTP.Headers.Map;
      Subprotocols  : String := "";
      Origin        : String := "";
      Insecure      : Boolean := False;
      CA_Path       : String := "");

   procedure Connect
     (Self     : in out Client_Type;
      URL      : String;
      Insecure : Boolean := False;
      CA_Path  : String := "");

   function Is_Open (Self : Client_Type) return Boolean;

   procedure Send_Text
     (Self : in out Client_Type;
      Text : String)
     with Pre => Is_Open (Self);

   procedure Send_Binary
     (Self : in out Client_Type;
      Data : AHT.Bytes.Byte_Array)
     with Pre => Is_Open (Self);

   procedure Send_Ping
     (Self    : in out Client_Type;
      Payload : AHT.Bytes.Byte_Array := [])
     with Pre => Is_Open (Self);

   procedure Close
     (Self   : in out Client_Type;
      Code   : Valid_Close_Code := 1000;
      Reason : String := "");
   --  The synthetic codes 1005/1006/1015 are ruled out by the subtype
   --  so they cannot be sent on the wire.

   --  Blocking pull API: blocks up to Timeout for the next decoded message.
   --  Raises Closed_Error if the connection has been closed.
   procedure Receive
     (Self    : in out Client_Type;
      Msg     : out Message_Type;
      Timeout : Duration := Duration'Last);

   --  Push API: callbacks invoked from the internal receiver task.
   procedure Set_On_Message (Self : in out Client_Type; CB : On_Message_Callback);
   procedure Set_On_Close   (Self : in out Client_Type; CB : On_Close_Callback);
   procedure Set_On_Error   (Self : in out Client_Type; CB : On_Error_Callback);

   function Selected_Subprotocol (Self : Client_Type) return String;

private

   type Client_Type is tagged limited record
      --  v1 plain only — wss:// will replace this with a TLS
      --  transport once mbedTLS is wired. Inline (not heap) so the
      --  Client owns its transport for its full lifetime; Connect
      --  populates it on success, Close tears it down.
      Transport          : AHT.Transport.TCP.TCP_Transport;
      Open               : Boolean := False;
      Selected_Protocol  : Ada.Strings.Unbounded.Unbounded_String;
      On_Message         : On_Message_Callback := null;
      On_Close           : On_Close_Callback   := null;
      On_Error           : On_Error_Callback   := null;
   end record;

end AHT.Websocket.Client;
