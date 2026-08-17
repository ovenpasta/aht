with Ada.Exceptions;
with Ada.Real_Time; use Ada.Real_Time;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Streams; use Ada.Streams;
with GNAT.Sockets; use GNAT.Sockets;
with AHT.Transport.Waits;

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
      --  A transport is permanently single-use. `Used` latches True at the
      --  first fully-successful Connect and is never cleared, so a reused
      --  object is rejected even after Close — crucially even if that Close
      --  raced a parked reader and could only best-effort the selector
      --  teardown (leaving the ownership bits looking clean). The
      --  Socket/Selector checks additionally reject any object that still
      --  owns OS resources before a first success completes (live or
      --  poisoned). We must NOT reclaim in place: a reader parked in Read on
      --  the old session could wake after this swaps in a new fd and then
      --  Receive_Socket against the wrong generation. The caller must Close
      --  (single-threaded, after every read/write task has quiesced) and
      --  connect a *fresh* object instead.
      if Self.Used
        or else Self.Socket /= No_Socket
        or else Self.Selector_Open
      then
         raise Transport_Error with
           "TCP transport is single-use; use a fresh transport to connect "
           & "(this one has already been connected — Close it and discard)";
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
            Create_Selector (Self.Write_Selector);
            Self.Selector_Open := True;
         exception
            when E : Socket_Error =>
               Self.Connected := False;
               begin
                  Close_Selector (Self.Selector);
               exception
                  when Socket_Error => null;
               end;
               begin
                  Close_Selector (Self.Write_Selector);
               exception
                  when Socket_Error => null;
               end;
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

      --  Switch to non-blocking IO so neither Send_Socket nor
      --  Receive_Socket can block in the kernel: the per-connection
      --  Selector becomes the *only* place Read/Write park, which is what
      --  lets the read/write deadlines and Abort_Pending bite at every
      --  re-park instead of being stuck inside an in-flight syscall.
      declare
         Nonblock : Request_Type (Name => Non_Blocking_IO) :=
           (Name => Non_Blocking_IO, Enabled => True);
      begin
         Control_Socket (Self.Socket, Nonblock);
      exception
         when E : Socket_Error =>
            Self.Connected := False;
            begin
               Close_Selector (Self.Selector);
            exception
               when Socket_Error => null;
            end;
            begin
               Close_Selector (Self.Write_Selector);
            exception
               when Socket_Error => null;
            end;
            Self.Selector_Open := False;
            begin
               Close_Socket (Self.Socket);
            exception
               when Socket_Error => null;
            end;
            Self.Socket := No_Socket;
            raise Transport_Error with
              "TCP connect: set non-blocking failed: "
              & Ada.Exceptions.Exception_Message (E);
      end;

      --  Fully connected: socket up, both selectors open, non-blocking set.
      --  Latch single-use here (the definite-success point) so every later
      --  Connect is rejected even after a Close — see the guard above.
      Self.Used := True;
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

   --  Common Write implementation: the deadline is a parameter so the
   --  overriding Write can pass the compound Set_Write_Deadline state
   --  and the deadline-explicit overload can pass its own bound.
   procedure Write_Bounded
     (Self         : in out TCP_Transport;
      Data         : AHT.Bytes.Byte_Array;
      Has_Deadline : Boolean;
      Deadline_At  : Ada.Real_Time.Time)
   is
      --  Send in bounded windows. A Data'Length-sized Stream_Element_Array
      --  would be a dynamically-sized *primary*-stack object that overflows
      --  the fixed thread stack on multi-MB frames (RFC 6455 §9 8M/16M);
      --  a fixed window keeps the stack footprint O(1) in the payload size.
      Window_Max : constant := 65_536;
      Buffer     : Stream_Element_Array (1 .. Window_Max);
      Sent       : Stream_Element_Offset;
      Pos        : Natural := Data'First;
      R_Set      : Socket_Set_Type;
      W_Set      : Socket_Set_Type;
      Status     : Selector_Status;

      --  True once any byte of this Write has been accepted by the kernel.
      --  If a later park then fails (deadline, abort, peer close, socket
      --  error), the application message on the wire is truncated and the
      --  connection must not be reused — see the exception handler.
      Progress   : Boolean := False;
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

            --  The socket is non-blocking, so a single Send_Socket only
            --  accepts whatever the kernel buffer has room for. Park in
            --  Check_Selector until the socket is writable, send the
            --  partial count, advance, re-park — so the write deadline
            --  and Abort_Pending bite at every park, never inside an
            --  in-flight syscall.
            while Cursor <= Slice'Last loop
               declare
                  Timeout : Duration := Duration'Last;
               begin
                  if Has_Deadline then
                     declare
                        Remaining : constant Time_Span :=
                          Deadline_At - Clock;
                     begin
                        if Remaining <= Time_Span_Zero then
                           Log.Debug ("write deadline expired (pre-park)");
                           raise Timeout_Error
                             with "TCP write deadline expired";
                        end if;
                        Timeout := To_Duration (Remaining);
                     end;
                  end if;

                  Empty (W_Set);
                  Set (W_Set, Self.Socket);
                  Check_Selector
                    (Selector     => Self.Write_Selector,
                     R_Socket_Set => R_Set,
                     W_Socket_Set => W_Set,
                     Status       => Status,
                     Timeout      =>
                       (if Has_Deadline
                        then AHT.Transport.Waits.Bounded (Timeout)
                        else GNAT.Sockets.Forever));

                  case Status is
                     when Completed =>
                        begin
                           Send_Socket
                             (Self.Socket, Slice (Cursor .. Slice'Last), Sent);
                           if Sent >= Cursor then
                              Cursor := Sent + 1;
                              Progress := True;
                           else
                              --  Selector reported writable but the send
                              --  accepted zero bytes (Last < First). On a
                              --  non-blocking socket a transient can't-send is
                              --  EAGAIN (the Socket_Error path below), so a
                              --  zero-length send on a ready socket is GNAT's
                              --  closed-peer signal (cf. Stream_Write's
                              --  "exit when Index < First"). Re-parking would
                              --  busy-spin on the still-writable socket, so
                              --  fail fast instead.
                              raise Transport_Error
                                with "TCP write: peer closed connection";
                           end if;
                        exception
                           when Ex : Socket_Error =>
                              if Resolve_Exception (Ex)
                                /= Resource_Temporarily_Unavailable
                              then
                                 raise;
                              end if;
                              --  would-block: re-park
                        end;
                     when Expired =>
                        --  The chunk ran out, which is not necessarily
                        --  the deadline: a budget longer than
                        --  Longest_Finite is served in pieces. Only
                        --  the absolute deadline decides.
                        if Has_Deadline
                          and then Clock < Deadline_At
                        then
                           goto Continue_Write;
                        end if;
                        Log.Debug ("write deadline expired");
                        raise Timeout_Error with "TCP write deadline expired";
                     when Aborted =>
                        Log.Debug ("write aborted");
                        raise Aborted_Error with "TCP write aborted";
                  end case;
               end;
               <<Continue_Write>>
            end loop;
            Pos := Pos + Window;
         end;
      end loop;
   exception
      --  Poison the connection on any fatal write so a desynchronised or
      --  dead socket is never reused (the TCP analogue of TLS's
      --  Drop_Connection): Is_Connected then reads False and a retry raises
      --  "TCP write on closed transport". The decision is by *cause*, not
      --  just by how many bytes went out:
      when E : Socket_Error =>
         --  Non-EAGAIN socket error = the endpoint is gone (reset, broken
         --  pipe, ...). Dead regardless of progress, so always poison. We
         --  poison rather than Close because a concurrent reader may still
         --  be parked in Check_Selector and Close would race its selector.
         Poison (Self);
         raise Transport_Error with
           "TCP write failed: " & Ada.Exceptions.Exception_Message (E);
      when Transport_Error =>
         --  Peer-closed-mid-write (the zero-byte send signal) — the endpoint
         --  is gone, so always poison. (The pre-loop "closed transport"
         --  guard also lands here; Poison is then a harmless no-op.)
         Poison (Self);
         raise;
      when others =>
         --  A *local* interruption (Timeout_Error / Aborted_Error). With no
         --  byte accepted the byte stream is intact and the connection stays
         --  reusable; only a partial send (Progress) truncated a message and
         --  forces a teardown.
         if Progress then
            Poison (Self);
         end if;
         raise;
   end Write_Bounded;

   overriding procedure Write
     (Self : in out TCP_Transport;
      Data : AHT.Bytes.Byte_Array) is
   begin
      Write_Bounded
        (Self, Data, Self.Has_Write_Deadline, Self.Write_Deadline_At);
   end Write;

   procedure Write
     (Self     : in out TCP_Transport;
      Data     : AHT.Bytes.Byte_Array;
      Deadline : Ada.Real_Time.Time) is
   begin
      Write_Bounded (Self, Data, True, Deadline);
   end Write;

   --  Common Read implementation, deadline-parameterized like
   --  Write_Bounded above.
   procedure Read_Bounded
     (Self         : in out TCP_Transport;
      Data         : out AHT.Bytes.Byte_Array;
      Last         : out Natural;
      Has_Deadline : Boolean;
      Deadline_At  : Ada.Real_Time.Time)
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

      loop
         Timeout := Duration'Last;

         --  Resolve the compound deadline. Subtracting the stored
         --  absolute instant from now gives *remaining* budget; if it's
         --  gone (or just about to go), fail without even parking.
         if Has_Deadline then
            declare
               Remaining : constant Time_Span :=
                 Deadline_At - Clock;
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
         Empty (R_Set);
         Set (R_Set, Self.Socket);
         Check_Selector
           (Selector     => Self.Selector,
            R_Socket_Set => R_Set,
            W_Socket_Set => W_Set,
            Status       => Status,
            Timeout      =>
              (if Has_Deadline
               then AHT.Transport.Waits.Bounded (Timeout)
               else GNAT.Sockets.Forever));

         case Status is
            when Completed =>
               null;
            when Expired =>
               --  As in Write: an expired chunk is only the deadline
               --  if the absolute deadline has actually arrived.
               if Has_Deadline and then Clock < Deadline_At then
                  goto Continue_Read;
               end if;
               Log.Debug ("read deadline expired");
               raise Timeout_Error with "TCP read deadline expired";
            when Aborted =>
               Log.Debug ("read aborted");
               raise Aborted_Error with "TCP read aborted";
         end case;

         --  The socket is non-blocking: a Completed wake only means the
         --  selector saw readiness, which can be spurious. If the receive
         --  would block, re-park rather than erroring.
         declare
            Would_Block : Boolean := False;
         begin
            begin
               Receive_Socket (Self.Socket, Buffer, Got_Last);
            exception
               when Ex : Socket_Error =>
                  if Resolve_Exception (Ex)
                    = Resource_Temporarily_Unavailable
                  then
                     Would_Block := True;
                  else
                     raise;
                  end if;
            end;

            if not Would_Block then
               if Got_Last < Buffer'First then
                  Last := 0;
               else
                  From_SEA (Buffer, Buffer'First, Got_Last, Data, Count);
                  Last := Data'First + Count - 1;
               end if;
               return;
            end if;
         end;
         <<Continue_Read>>
      end loop;
   exception
      when E : Socket_Error =>
         raise Transport_Error with
           "TCP read failed: " & Ada.Exceptions.Exception_Message (E);
   end Read_Bounded;

   overriding procedure Read
     (Self : in out TCP_Transport;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural) is
   begin
      Read_Bounded (Self, Data, Last, Self.Has_Deadline, Self.Deadline_At);
   end Read;

   procedure Read
     (Self     : in out TCP_Transport;
      Data     : out AHT.Bytes.Byte_Array;
      Last     : out Natural;
      Deadline : Ada.Real_Time.Time) is
   begin
      Read_Bounded (Self, Data, Last, True, Deadline);
   end Read;

   overriding procedure Close (Self : in out TCP_Transport) is
   begin
      --  Guard on the FD, not Connected: a poisoned transport has already
      --  set Connected False but still owns the socket (Poison defers the
      --  reclaim to here), so this single-threaded lifecycle Close must
      --  still free it. Double-Close is a no-op once Socket is No_Socket.
      if Self.Socket /= No_Socket then
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
         begin
            Close_Selector (Self.Write_Selector);
         exception
            when Socket_Error => null;
         end;
         Self.Selector_Open := False;
      end if;

      Self.Has_Deadline := False;
      Self.Has_Write_Deadline := False;
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
         --  Same ordering as the write side: compute first, so an
         --  absurd Deadline cannot leave the flag set over a value
         --  that was never assigned.
         declare
            At_Time : constant Time := Clock + To_Time_Span (Deadline);
         begin
            Self.Deadline_At  := At_Time;
            Self.Has_Deadline := True;
         end;
      end if;
   end Set_Read_Deadline;

   overriding procedure Set_Write_Deadline
     (Self     : in out TCP_Transport;
      Deadline : Duration)
   is
   begin
      if Deadline = Duration'Last then
         Self.Has_Write_Deadline := False;
      else
         --  Compute before assigning either field. Converting an
         --  absurd Deadline raises, and doing it after setting the
         --  flag would leave the transport claiming a deadline it
         --  never computed -- whose stale value is in the past, so
         --  every later write would fail instantly.
         declare
            At_Time : constant Time := Clock + To_Time_Span (Deadline);
         begin
            Self.Write_Deadline_At  := At_Time;
            Self.Has_Write_Deadline := True;
         end;
      end if;
   end Set_Write_Deadline;

   overriding procedure Abort_Pending (Self : in out TCP_Transport) is
   begin
      if Self.Selector_Open then
         --  Wake whichever direction is parked: the read selector for a
         --  blocked Read, the write selector for a blocked Write. Both
         --  aborts are idempotent, so signalling the idle one is harmless.
         begin
            Abort_Selector (Self.Selector);
         exception
            when Socket_Error => null;
         end;
         begin
            Abort_Selector (Self.Write_Selector);
         exception
            when Socket_Error => null;
         end;
         Log.Debug ("abort pending");
      end if;
   end Abort_Pending;

   procedure Poison (Self : in out TCP_Transport) is
   begin
      if not Self.Connected then
         return;  --  already poisoned or closed
      end if;
      Self.Connected := False;
      Log.Debug ("poison");

      --  Shutdown (not close) the data socket. This wakes a reader parked
      --  in Check_Selector on Self.Selector — the socket goes readable and
      --  Receive_Socket then returns 0 (EOF) — and a parked writer with
      --  EPIPE, all without freeing the FD or selectors. Closing the
      --  selectors here would race that concurrent reader (GNAT forbids
      --  Close_Selector while a task is in Check_Selector); reclamation is
      --  left to the single-threaded Close, which the Socket /= No_Socket
      --  guard lets run even though Connected is already False.
      if Self.Socket /= No_Socket then
         begin
            Shutdown_Socket (Self.Socket, Shut_Read_Write);
         exception
            when Socket_Error => null;
         end;
      end if;
   end Poison;

end AHT.Transport.TCP;
