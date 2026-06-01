with Ada.Exceptions;
with Ada.Real_Time; use Ada.Real_Time;
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
     (Self            : in out TCP_Transport;
      Endpoints       : Endpoint_List;
      Connect_Timeout : Duration := Duration'Last)
   is
      Last_Error : Unbounded_String;
      Success    : Boolean := False;
      Timed_Out  : Boolean := False;

      Budgeted : constant Boolean := Connect_Timeout /= Duration'Last;
      --  A single absolute instant the whole connect phase must finish
      --  by, computed once so every candidate draws from the same
      --  budget rather than each getting a fresh Connect_Timeout.
      Deadline : constant Time :=
        (if Budgeted then Clock + To_Time_Span (Connect_Timeout) else Clock);

      procedure Close_Quietly (S : in out Socket_Type) is
      begin
         if S /= No_Socket then
            begin
               Close_Socket (S);
            exception
               when Socket_Error => null;
            end;
            S := No_Socket;
         end if;
      end Close_Quietly;

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

            if Budgeted then
               declare
                  Remaining : constant Time_Span := Deadline - Clock;
                  Status    : Selector_Status;
               begin
                  if Remaining <= Time_Span_Zero then
                     Timed_Out := True;
                     Last_Error := To_Unbounded_String
                       ("connect budget exhausted before ["
                        & To_String (E.Host) & ":"
                        & AHT.URL.Port_Number'Image (E.Port) & "]");
                     Close_Quietly (Sock);
                     return;
                  end if;
                  Connect_Socket
                    (Socket  => Sock,
                     Server  => Peer,
                     Timeout => Selector_Duration (To_Duration (Remaining)),
                     Status  => Status);
                  if Status /= Completed then
                     --  Expired: this attempt ate the rest of the
                     --  budget. Treat as a timeout, not a refusal.
                     Timed_Out := True;
                     Last_Error := To_Unbounded_String
                       ("connect timed out ["
                        & To_String (E.Host) & ":"
                        & AHT.URL.Port_Number'Image (E.Port) & "]");
                     Log.Debug ("connect timed out " & To_String (E.Host));
                     Close_Quietly (Sock);
                     return;
                  end if;
               end;
            else
               Connect_Socket (Sock, Peer);
            end if;

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
            Close_Quietly (Sock);
      end Try;

   begin
      if Self.Connected then
         raise Transport_Error with "TCP transport already connected";
      end if;

      for E of Endpoints loop
         Try (E);
         exit when Success;
         --  Once the shared budget is gone, stop: every remaining
         --  candidate would just trip the pre-connect exhaustion check.
         exit when Timed_Out;
      end loop;

      if not Success then
         if Timed_Out then
            Log.Warning ("connect timed out — " & To_String (Last_Error));
            raise Timeout_Error with
              "TCP connect timed out: " & To_String (Last_Error);
         else
            Log.Warning
              ("all candidates refused — " & To_String (Last_Error));
            raise Transport_Error with
              "TCP connect: all candidates failed: "
              & To_String (Last_Error);
         end if;
      end if;

      --  Socket is connected. Now create the selector Read/Abort_Pending
      --  need. Deferred until here so that a failed connect path (every
      --  candidate refused, DNS lookup failure, etc.) never leaves the
      --  transport holding an open selector that only a later Close
      --  would have released. If Create_Selector itself fails we unwind
      --  the just-opened socket too, keeping the object reusable.
      if not Self.Selector_Open then
         begin
            Create_Selector (Self.Selector);
            Self.Selector_Open := True;
         exception
            when E : Socket_Error =>
               Self.Connected := False;
               begin
                  Close_Socket (Self.Socket);
               exception
                  when Socket_Error => null;
               end;
               Self.Socket := No_Socket;
               raise Transport_Error with
                 "TCP connect: Create_Selector failed: "
                 & Ada.Exceptions.Exception_Message (E);
         end;
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
     (Self            : in out TCP_Transport;
      Host            : String;
      Port            : AHT.URL.Port_Number;
      Connect_Timeout : Duration := Duration'Last)
   is
   begin
      if Is_IP_Literal (Host) then
         Connect_Candidates
           (Self,
            [1 => (Host => To_Unbounded_String (Host), Port => Port)],
            Connect_Timeout => Connect_Timeout);
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
            Connect_Candidates
              (Self, List (1 .. N), Connect_Timeout => Connect_Timeout);
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
      --  Send in bounded windows. A Data'Length-sized Stream_Element_Array
      --  would be a dynamically-sized *primary*-stack object that overflows
      --  the fixed thread stack on multi-MB frames (RFC 6455 §9 8M/16M);
      --  a fixed window keeps the stack footprint O(1) in the payload size.
      Window_Max : constant := 65_536;
      Buffer     : Stream_Element_Array (1 .. Window_Max);
      Sent       : Stream_Element_Offset;
      Pos        : Natural := Data'First;
   begin
      if not Self.Connected then
         raise Transport_Error with "TCP write on closed transport";
      end if;

      while Pos <= Data'Last loop
         declare
            Window : constant Natural :=
              Natural'Min (Window_Max, Data'Last - Pos + 1);
            Slice  : Stream_Element_Array renames
              Buffer (1 .. Stream_Element_Offset (Window));
            Cursor : Stream_Element_Offset := Slice'First;
         begin
            To_SEA (Data (Pos .. Pos + Window - 1), Slice);
            while Cursor <= Slice'Last loop
               Send_Socket (Self.Socket, Slice (Cursor .. Slice'Last), Sent);
               exit when Sent < Cursor;
               Cursor := Sent + 1;
            end loop;
            if Cursor <= Slice'Last then
               raise Transport_Error
                 with "TCP write: short send (peer closed?)";
            end if;
            Pos := Pos + Window;
         end;
      end loop;
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
      R_Set    : Socket_Set_Type;
      W_Set    : Socket_Set_Type;
      Status   : Selector_Status;
      Timeout  : Duration := Duration'Last;
   begin
      Last := 0;
      if Data'Length = 0 then
         return;
      end if;
      if not Self.Connected then
         raise Transport_Error with "TCP read on closed transport";
      end if;

      --  Resolve the compound deadline. Subtracting the stored
      --  absolute instant from now gives *remaining* budget; if it's
      --  gone (or just about to go), fail without even parking.
      if Self.Has_Deadline then
         declare
            Remaining : constant Time_Span :=
              Self.Deadline_At - Clock;
         begin
            if Remaining <= Time_Span_Zero then
               Log.Debug ("read deadline expired (pre-park)");
               raise Timeout_Error with "TCP read deadline expired";
            end if;
            Timeout := To_Duration (Remaining);
         end;
      end if;

      --  Park in Check_Selector first so the read honours the
      --  deadline (via Timeout) and stays interruptible by
      --  Abort_Pending (via Abort_Selector on the same selector).
      Set (R_Set, Self.Socket);
      Check_Selector
        (Selector     => Self.Selector,
         R_Socket_Set => R_Set,
         W_Socket_Set => W_Set,
         Status       => Status,
         Timeout      => Timeout);

      case Status is
         when Completed =>
            null;
         when Expired =>
            Log.Debug ("read deadline expired");
            raise Timeout_Error with "TCP read deadline expired";
         when Aborted =>
            Log.Debug ("read aborted");
            raise Aborted_Error with "TCP read aborted";
      end case;

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
      if Self.Connected then
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
      end if;

      --  Selector is per-transport, not per-connection. Drop it here
      --  so Close pairs 1:1 with the Connect that created it; a fresh
      --  Connect creates a new selector.
      if Self.Selector_Open then
         begin
            Close_Selector (Self.Selector);
         exception
            when Socket_Error => null;
         end;
         Self.Selector_Open := False;
      end if;

      Self.Has_Deadline := False;
   end Close;

   overriding function Is_Connected (Self : TCP_Transport) return Boolean is
     (Self.Connected);

   overriding procedure Set_Read_Deadline
     (Self     : in out TCP_Transport;
      Deadline : Duration)
   is
   begin
      if Deadline = Duration'Last then
         Self.Has_Deadline := False;
      else
         Self.Has_Deadline := True;
         Self.Deadline_At := Clock + To_Time_Span (Deadline);
      end if;
   end Set_Read_Deadline;

   overriding procedure Abort_Pending (Self : in out TCP_Transport) is
   begin
      if Self.Selector_Open then
         begin
            Abort_Selector (Self.Selector);
            Log.Debug ("abort pending");
         exception
            when Socket_Error => null;
         end;
      end if;
   end Abort_Pending;

end AHT.Transport.TCP;
