with Ada.Strings.Unbounded;

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

   type Endpoint is record
      Host : Ada.Strings.Unbounded.Unbounded_String;
      Port : AHT.URL.Port_Number := 1;
   end record;

   type Endpoint_List is array (Positive range <>) of Endpoint;

   procedure Connect_Candidates
     (Self      : in out TCP_Transport;
      Endpoints : Endpoint_List)
     with Pre => Endpoints'Length > 0;
   --  Each `Host` must already be a numeric IP literal (IPv4 or IPv6);
   --  this entry point skips DNS resolution. Tries each endpoint in
   --  order — on `Socket_Error` from an attempt, closes that socket
   --  and moves on. First success wins. If every attempt fails, raises
   --  `Transport_Error` with the last error message.
   --
   --  Public so tests can drive the multi-address fallback with an
   --  explicit `[bad, good]` list; `Connect (Host, Port)` above
   --  delegates to this after DNS lookup.

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
      Connected : Boolean := False;
   end record;

end AHT.Transport.TCP;
