with Ada.Exceptions;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Streams; use Ada.Streams;
with GNAT.Sockets; use GNAT.Sockets;

with AHT.Log.Tag;

package body AHT.Transport.TCP is

   package Log is new AHT.Log.Tag ("tcp");

   procedure To_SEA
     (Source : AHT.Bytes.Byte_Array;
      Target : out Stream_Element_Array);

   procedure From_SEA
     (Source : Stream_Element_Array;
      First  : Stream_Element_Offset;
      Last   : Stream_Element_Offset;
      Target : out AHT.Bytes.Byte_Array;
      Count  : out Natural);

   procedure To_SEA
     (Source : AHT.Bytes.Byte_Array;
      Target : out Stream_Element_Array)
   is
      J : Stream_Element_Offset := Target'First;
   begin
      for I in Source'Range loop
         Target (J) := Stream_Element (Source (I));
         J := J + 1;
      end loop;
   end To_SEA;

   procedure From_SEA
     (Source : Stream_Element_Array;
      First  : Stream_Element_Offset;
      Last   : Stream_Element_Offset;
      Target : out AHT.Bytes.Byte_Array;
      Count  : out Natural)
   is
      J : Positive := Target'First;
   begin
      Count := 0;
      for I in First .. Last loop
         Target (J) := AHT.Bytes.Octet (Source (I));
         J := J + 1;
         Count := Count + 1;
      end loop;
   end From_SEA;

   procedure Connect_Candidates
     (Self      : in out TCP_Transport;
      Endpoints : Endpoint_List)
   is
      Last_Error : Unbounded_String;
      Success    : Boolean := False;

      procedure Try (E : Endpoint) is
         Sock : Socket_Type := No_Socket;
         Addr : Inet_Addr_Type;
      begin
         Addr := Inet_Addr (To_String (E.Host));
         declare
            Peer : constant Sock_Addr_Type :=
              (Family => Addr.Family,
               Port   => Port_Type (E.Port),
               Addr   => Addr);
         begin
            Create_Socket (Sock, Addr.Family, Socket_Stream);
            Log.Debug
              ("try " & To_String (E.Host)
               & ":" & AHT.URL.Port_Number'Image (E.Port));
            Connect_Socket (Sock, Peer);
            Self.Socket := Sock;
            Self.Connected := True;
            Success := True;
            Log.Info
              ("connected " & To_String (E.Host)
               & ":" & AHT.URL.Port_Number'Image (E.Port));
         end;
      exception
         when Ex : Socket_Error =>
            Last_Error := To_Unbounded_String
              ("[" & To_String (E.Host) & ":"
               & AHT.URL.Port_Number'Image (E.Port) & "] "
               & Ada.Exceptions.Exception_Message (Ex));
            Log.Debug
              ("connect refused " & To_String (E.Host)
               & ":" & AHT.URL.Port_Number'Image (E.Port)
               & " — " & Ada.Exceptions.Exception_Message (Ex));
            if Sock /= No_Socket then
               begin
                  Close_Socket (Sock);
               exception
                  when Socket_Error => null;
               end;
            end if;
      end Try;

   begin
      if Self.Connected then
         raise Transport_Error with "TCP transport already connected";
      end if;

      for E of Endpoints loop
         Try (E);
         exit when Success;
      end loop;

      if not Success then
         Log.Warning
           ("all candidates refused — " & To_String (Last_Error));
         raise Transport_Error with
           "TCP connect: all candidates failed: " & To_String (Last_Error);
      end if;
   end Connect_Candidates;

   function Is_IP_Literal (Host : String) return Boolean is
      Ignored : Inet_Addr_Type;
   begin
      Ignored := Inet_Addr (Host);
      return True;
   exception
      when Socket_Error => return False;
   end Is_IP_Literal;

   procedure Connect
     (Self : in out TCP_Transport;
      Host : String;
      Port : AHT.URL.Port_Number)
   is
   begin
      if Is_IP_Literal (Host) then
         Connect_Candidates
           (Self,
            [1 => (Host => To_Unbounded_String (Host), Port => Port)]);
      else
         declare
            Entry_Info : constant Host_Entry_Type := Get_Host_By_Name (Host);
            N          : constant Natural := Addresses_Length (Entry_Info);
            List       : Endpoint_List (1 .. Positive'Max (1, N));
         begin
            if N = 0 then
               raise Transport_Error with
                 "TCP connect to " & Host & ": no addresses resolved";
            end if;
            for I in 1 .. N loop
               List (I) :=
                 (Host => To_Unbounded_String
                            (Image (Addresses (Entry_Info, I))),
                  Port => Port);
            end loop;
            Connect_Candidates (Self, List (1 .. N));
         exception
            when E : Host_Error =>
               raise Transport_Error with
                 "TCP connect to " & Host & ": DNS lookup failed: "
                 & Ada.Exceptions.Exception_Message (E);
         end;
      end if;
   end Connect;

   overriding procedure Write
     (Self : in out TCP_Transport;
      Data : AHT.Bytes.Byte_Array)
   is
      Buffer : Stream_Element_Array (1 .. Stream_Element_Offset (Data'Length));
      Sent   : Stream_Element_Offset;
      Cursor : Stream_Element_Offset := Buffer'First;
   begin
      if not Self.Connected then
         raise Transport_Error with "TCP write on closed transport";
      end if;
      if Data'Length = 0 then
         return;
      end if;

      To_SEA (Data, Buffer);

      while Cursor <= Buffer'Last loop
         Send_Socket (Self.Socket, Buffer (Cursor .. Buffer'Last), Sent);
         exit when Sent < Cursor;
         Cursor := Sent + 1;
      end loop;

      if Cursor <= Buffer'Last then
         raise Transport_Error with "TCP write: short send (peer closed?)";
      end if;
   exception
      when E : Socket_Error =>
         raise Transport_Error with
           "TCP write failed: " & Ada.Exceptions.Exception_Message (E);
   end Write;

   overriding procedure Read
     (Self : in out TCP_Transport;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural)
   is
      Buffer   : Stream_Element_Array (1 .. Stream_Element_Offset (Data'Length));
      Got_Last : Stream_Element_Offset;
      Count    : Natural;
   begin
      Last := 0;
      if Data'Length = 0 then
         return;
      end if;
      if not Self.Connected then
         raise Transport_Error with "TCP read on closed transport";
      end if;

      Receive_Socket (Self.Socket, Buffer, Got_Last);

      if Got_Last < Buffer'First then
         Last := 0;
         return;
      end if;

      From_SEA (Buffer, Buffer'First, Got_Last, Data, Count);
      Last := Data'First + Count - 1;
   exception
      when E : Socket_Error =>
         raise Transport_Error with
           "TCP read failed: " & Ada.Exceptions.Exception_Message (E);
   end Read;

   overriding procedure Close (Self : in out TCP_Transport) is
   begin
      if not Self.Connected then
         return;
      end if;
      Self.Connected := False;
      Log.Debug ("close");

      begin
         Shutdown_Socket (Self.Socket, Shut_Read_Write);
      exception
         when Socket_Error => null;
      end;
      begin
         Close_Socket (Self.Socket);
      exception
         when Socket_Error => null;
      end;
      Self.Socket := No_Socket;
   end Close;

   overriding function Is_Connected (Self : TCP_Transport) return Boolean is
     (Self.Connected);

end AHT.Transport.TCP;
