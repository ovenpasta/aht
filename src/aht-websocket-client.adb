with Ada.Characters.Handling;
with Ada.Exceptions;
with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Unchecked_Deallocation;

with GNAT.SHA1;

with AHT.HTTP.Methods;
with AHT.HTTP.Request;
with AHT.HTTP.Response;
with AHT.URL;
with AHT.Websocket.Frames;
with AHT.Websocket.UTF8;

package body AHT.Websocket.Client is

   ---------------------------------------------------------------
   --  Local helpers
   ---------------------------------------------------------------

   WS_GUID : constant String := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

   function To_Lower (S : String) return String renames
     Ada.Characters.Handling.To_Lower;

   function Strip_OWS (S : String) return String is
      First : Natural := S'First;
      Last  : Integer := S'Last;
   begin
      while First <= Last
        and then (S (First) = ' ' or else S (First) = ASCII.HT)
      loop
         First := First + 1;
      end loop;
      while Last >= First
        and then (S (Last) = ' ' or else S (Last) = ASCII.HT)
      loop
         Last := Last - 1;
      end loop;
      return S (First .. Last);
   end Strip_OWS;

   function Contains_Token (Haystack, Needle : String) return Boolean is
      Lower_Hay  : constant String := To_Lower (Haystack);
      Lower_Need : constant String := To_Lower (Needle);
      First      : Positive := Lower_Hay'First;
   begin
      if Lower_Hay'Length = 0 then
         return False;
      end if;
      loop
         declare
            Comma : constant Natural :=
              Ada.Strings.Fixed.Index
                (Lower_Hay (First .. Lower_Hay'Last), ",");
            Token_Last : constant Natural :=
              (if Comma = 0 then Lower_Hay'Last else Comma - 1);
            T : constant String :=
              Strip_OWS (Lower_Hay (First .. Token_Last));
         begin
            if T = Lower_Need then
               return True;
            end if;
            exit when Comma = 0;
            First := Comma + 1;
         end;
      end loop;
      return False;
   end Contains_Token;

   function Is_Offered_Subprotocol
     (Wanted : String; Subprotocols : String) return Boolean
   is
      First : Positive := Subprotocols'First;
   begin
      if Subprotocols'Length = 0 then
         return False;
      end if;
      loop
         declare
            Comma : constant Natural :=
              Ada.Strings.Fixed.Index
                (Subprotocols (First .. Subprotocols'Last), ",");
            End_Idx : constant Natural :=
              (if Comma = 0 then Subprotocols'Last else Comma - 1);
            T : constant String :=
              Strip_OWS (Subprotocols (First .. End_Idx));
         begin
            if T = Wanted then
               return True;
            end if;
            exit when Comma = 0;
            First := Comma + 1;
         end;
      end loop;
      return False;
   end Is_Offered_Subprotocol;

   function Hex_To_Bytes (Hex : String) return AHT.Bytes.Byte_Array is
      function Val (C : Character) return Natural is
        (case C is
           when '0' .. '9' =>
             Character'Pos (C) - Character'Pos ('0'),
           when 'a' .. 'f' =>
             10 + Character'Pos (C) - Character'Pos ('a'),
           when 'A' .. 'F' =>
             10 + Character'Pos (C) - Character'Pos ('A'),
           when others =>
             raise Program_Error
               with "Hex_To_Bytes: non-hex character '" & C & "'");
      B : AHT.Bytes.Byte_Array (1 .. Hex'Length / 2);
   begin
      for I in 0 .. B'Length - 1 loop
         B (B'First + I) :=
           AHT.Bytes.Octet
             (16 * Val (Hex (Hex'First + 2 * I))
              +    Val (Hex (Hex'First + 2 * I + 1)));
      end loop;
      return B;
   end Hex_To_Bytes;

   function Expected_Accept (Key : String) return String is
      Hex : constant String := GNAT.SHA1.Digest (Key & WS_GUID);
   begin
      return AHT.Bytes.Base64_Encode (Hex_To_Bytes (Hex));
   end Expected_Accept;

   function Host_Header (U : AHT.URL.URL_Type) return String is
      Default : constant AHT.URL.Port_Number :=
        AHT.URL.Default_Port (U.Scheme);
      Host_S  : constant String := AHT.URL.Host_Literal (U);
   begin
      if U.Port = Default then
         return Host_S;
      end if;
      return Host_S & ":"
        & Ada.Strings.Fixed.Trim
            (AHT.URL.Port_Number'Image (U.Port), Ada.Strings.Both);
   end Host_Header;

   procedure Fill_Random (B : out AHT.Bytes.Byte_Array) is
      Gen : Random_Bytes.Generator;
   begin
      Random_Bytes.Reset (Gen);
      for I in B'Range loop
         B (I) := Random_Bytes.Random (Gen);
      end loop;
   end Fill_Random;

   --  Build + send one masked frame on the active transport.
   --  Caller MUST hold the Send_Guard (Acquire / Release wrap this).
   --  The mask is drawn from the guard's PRNG; the encode happens
   --  inside the lock; the transport Write happens *outside* the
   --  lock so a slow socket can't block other tasks' Acquires.
   procedure Send_Frame
     (Transport : in out AHT.Transport.Transport_Type'Class;
      Guard     : in out Send_Guard;
      Op        : AHT.Websocket.Opcode;
      FIN       : Boolean;
      Payload   : AHT.Bytes.Byte_Array)
   is
      Hdr : AHT.Websocket.Frames.Frame_Header :=
        (FIN    => FIN,
         Op     => Op,
         Masked => True,
         others => <>);
   begin
      Guard.Random_Mask (Hdr.Mask_Key);
      declare
         Wire : constant AHT.Bytes.Byte_Array :=
           AHT.Websocket.Frames.Encode (Hdr, Payload);
      begin
         Transport.Write (Wire);
      end;
   end Send_Frame;

   --  Build the 2-byte Close-frame payload (code + optional reason).
   --  Caller must pass a Valid_Close_Code; the Frames layer
   --  re-validates on Encode.
   function Build_Close_Payload
     (Code : AHT.Websocket.Valid_Close_Code; Reason : String)
      return AHT.Bytes.Byte_Array
   is
      Total : constant Natural := 2 + Reason'Length;
      P     : AHT.Bytes.Byte_Array (1 .. Total);
   begin
      P (1) := AHT.Bytes.Octet (Code / 256);
      P (2) := AHT.Bytes.Octet (Code mod 256);
      for I in 0 .. Reason'Length - 1 loop
         P (3 + I) := AHT.Bytes.Octet
           (Character'Pos (Reason (Reason'First + I)));
      end loop;
      return P;
   end Build_Close_Payload;

   ---------------------------------------------------------------
   --  Protected bodies
   ---------------------------------------------------------------

   protected body State_PO is

      procedure Set (S : State_Kind) is
      begin
         Current := S;
      end Set;

      function Get return State_Kind is (Current);

      entry Wait_Closed when Current = Closed is
      begin
         null;
      end Wait_Closed;

      procedure Begin_Closing (Already_Closed : out Boolean) is
      begin
         if Current = Closed then
            Already_Closed := True;
         else
            Current        := Closing;
            Already_Closed := False;
         end if;
      end Begin_Closing;

      procedure Try_Mark_Local_Close (Should_Send : out Boolean) is
      begin
         if Local_Closed then
            Should_Send := False;
         else
            Local_Closed := True;
            Should_Send  := True;
         end if;
      end Try_Mark_Local_Close;

      function Local_Close_Sent return Boolean is (Local_Closed);

   end State_PO;

   protected body Send_Guard is

      entry Acquire when not Busy is
      begin
         Busy := True;
      end Acquire;

      procedure Release is
      begin
         Busy := False;
      end Release;

      procedure Mark_Close_Sent is
      begin
         Close_Sent := True;
      end Mark_Close_Sent;

      function Close_Frame_Sent return Boolean is (Close_Sent);

      procedure Random_Mask (Mask : out AHT.Bytes.Byte_Array) is
      begin
         if not Seeded then
            Random_Bytes.Reset (Gen);
            Seeded := True;
         end if;
         for I in Mask'Range loop
            Mask (I) := Random_Bytes.Random (Gen);
         end loop;
      end Random_Mask;

   end Send_Guard;

   protected body Inbox_PO is

      entry Receive (Msg : out Message_Type)
        when Closed_F or else not Q.Is_Empty
      is
      begin
         if Q.Is_Empty then
            --  Closed_F is the only other thing that could open
            --  the barrier — raise so the caller observes the
            --  closed connection.
            raise AHT.Websocket.Closed_Error
              with "Websocket.Client.Receive: connection closed";
         end if;
         Msg := Q.First_Element;
         Q.Delete_First;
      end Receive;

      procedure Push (Msg : Message_Type) is
      begin
         Q.Append (Msg);
      end Push;

      procedure Mark_Closed is
      begin
         Closed_F := True;
      end Mark_Closed;

      function Count return Natural is (Natural (Q.Length));

      function Is_Closed return Boolean is (Closed_F);

   end Inbox_PO;

   ---------------------------------------------------------------
   --  Receive accumulator
   ---------------------------------------------------------------

   --  Bytes read off the wire but not yet consumed by a successful
   --  Frames.Decode live here. A growable heap Byte_Array plus a
   --  consumed-prefix cursor (Head) keeps the receive path linear
   --  for large payloads (RFC 6455 §9):
   --
   --    * consuming a decoded frame is an O(1) bump of Head, not an
   --      element-by-element Delete_First (which shifted the whole
   --      tail down per byte → O(N²) for one big frame);
   --    * feeding Decode is the slice Data (Head .. Tail), passed by
   --      reference, not a fresh full-buffer copy on every loop turn;
   --    * appending a read is one block move, and the consumed prefix
   --      is reclaimed by lazy compaction (move-to-front) only when
   --      a read won't otherwise fit.
   --
   --  Live bytes are Data (Head .. Tail); the buffer is empty when
   --  Tail < Head (kept normalised to Head = 1, Tail = 0 when drained).
   --  Data is allocated lazily on the first read (Ensure_Room) and the
   --  owning Receiver_Task frees it as it shuts down, so its lifetime is
   --  bounded by the task's.
   type Byte_Array_Access is access AHT.Bytes.Byte_Array;

   procedure Free is new Ada.Unchecked_Deallocation
     (AHT.Bytes.Byte_Array, Byte_Array_Access);

   type Recv_Buffer is record
      Data : Byte_Array_Access;
      Head : Positive := 1;
      Tail : Natural  := 0;
   end record;

   function Live (B : Recv_Buffer) return Natural is (B.Tail - B.Head + 1);

   --  Guarantee at least Extra free bytes past Tail, compacting the
   --  consumed prefix first and only growing (doubling) when that is
   --  still not enough.
   procedure Ensure_Room (B : in out Recv_Buffer; Extra : Natural) is
      Used : constant Natural := Live (B);
   begin
      if B.Data = null then
         --  First read: allocate lazily here, inside the receiver
         --  loop's exception coverage, rather than eagerly at task
         --  start. A failed allocation then propagates to the loop's
         --  handler and drives orderly shutdown, instead of killing
         --  the task before it can mark the connection Closed.
         B.Data :=
           new AHT.Bytes.Byte_Array (1 .. Positive'Max (8_192, Extra));
         return;
      end if;

      if B.Data'Last - B.Tail >= Extra then
         return;  -- already fits at the tail
      end if;

      if Used + Extra <= B.Data'Last then
         --  Compaction alone reclaims enough room.
         if Used > 0 and then B.Head > 1 then
            B.Data (1 .. Used) := B.Data (B.Head .. B.Tail);
         end if;
         B.Head := 1;
         B.Tail := Used;
         return;
      end if;

      declare
         New_Cap  : constant Positive :=
           Positive'Max (B.Data'Last * 2, Used + Extra);
         New_Data : constant Byte_Array_Access :=
           new AHT.Bytes.Byte_Array (1 .. New_Cap);
      begin
         if Used > 0 then
            New_Data (1 .. Used) := B.Data (B.Head .. B.Tail);
         end if;
         Free (B.Data);
         B.Data := New_Data;
         B.Head := 1;
         B.Tail := Used;
      end;
   end Ensure_Room;

   --  Append the first N bytes of Chunk to the buffer (one block move).
   procedure Push
     (B : in out Recv_Buffer; Chunk : AHT.Bytes.Byte_Array; N : Natural)
   is
   begin
      if N = 0 then
         return;
      end if;
      Ensure_Room (B, N);
      B.Data (B.Tail + 1 .. B.Tail + N) :=
        Chunk (Chunk'First .. Chunk'First + N - 1);
      B.Tail := B.Tail + N;
   end Push;

   --  Drop the consumed prefix up to and including index Last (the
   --  last byte a successful Decode reported). Reset to the front
   --  when the buffer drains so it doesn't creep toward capacity.
   procedure Consume (B : in out Recv_Buffer; Last : Natural) is
   begin
      B.Head := Last + 1;
      if B.Head > B.Tail then
         B.Head := 1;
         B.Tail := 0;
      end if;
   end Consume;

   ---------------------------------------------------------------
   --  Receiver task
   ---------------------------------------------------------------

   task body Receiver_Task is
      --  Cached pointer to the Client_Type that owns this task.
      --  Named Conn to avoid shadowing the entry parameter Owner.
      Conn : Client_Access := null;

      --  Frame-decoding accumulator: bytes read from the transport
      --  but not yet consumed by a successful Frames.Decode.
      Buf : Recv_Buffer;

      --  Reassembly state for fragmented messages (RFC 6455 §5.4).
      --  A Text/Binary frame with FIN=0 starts a reassembly; later
      --  Continuation frames append; FIN=1 closes it.
      In_Reassembly   : Boolean        := False;
      Reassembly_Kind : Message_Kind   := Binary_Message;
      Reassembly_Buf  : AHT.Bytes.Buffer;

      Stop_Loop : Boolean := False;

      --  Fire a user-installed callback inside a guard so the
      --  receiver task keeps draining the wire if the callback
      --  raises. Documented contract.
      procedure Fire_On_Message (Msg : Message_Type) is
      begin
         if Conn.On_Message /= null then
            begin
               Conn.On_Message (Msg);
            exception
               when others => null;
            end;
         end if;
      end Fire_On_Message;

      procedure Fire_On_Close (Info : Close_Info; Reason : String) is
      begin
         if Conn.On_Close /= null then
            begin
               Conn.On_Close (Info, Reason);
            exception
               when others => null;
            end;
         end if;
      end Fire_On_Close;

      procedure Fire_On_Error (Message : String) is
      begin
         if Conn.On_Error /= null then
            begin
               Conn.On_Error (Message);
            exception
               when others => null;
            end;
         end if;
      end Fire_On_Error;

      procedure Read_More is
         Chunk : AHT.Bytes.Byte_Array (1 .. 4_096);
         Last  : Natural;
      begin
         Conn.Sess.Active.Read (Chunk, Last);
         if Last = 0 then
            --  Peer closed without a Close frame. Surface as a
            --  connection-closed event; users in Receive wake and
            --  see Closed_Error.
            Fire_On_Close ((Has_Code => False), "");
            Stop_Loop := True;
            return;
         end if;
         Push (Buf, Chunk, Last);
      end Read_More;

      --  Send a Close echo (or initial Close) if we haven't yet.
      --  Acquires the Send_Guard around the actual Write.
      procedure Maybe_Send_Close_Echo
        (Code : AHT.Websocket.Valid_Close_Code := 1000)
      is
         Should_Send : Boolean;
      begin
         Conn.Sess.State.Try_Mark_Local_Close (Should_Send);
         if not Should_Send then
            return;
         end if;
         Conn.Sess.Guard.Acquire;
         begin
            Send_Frame
              (Conn.Sess.Active.all, Conn.Sess.Guard,
               Op      => AHT.Websocket.Close_Op,
               FIN     => True,
               Payload => Build_Close_Payload (Code, ""));
         exception
            when others =>
               --  If the echo can't go out (peer already torn the
               --  transport down, etc.), we still want to release
               --  the guard and exit cleanly. Latch anyway: the
               --  connection is finished, no data frame may follow.
               Conn.Sess.Guard.Mark_Close_Sent;
               Conn.Sess.Guard.Release;
               return;
         end;
         --  Latch under the guard so a Send_* racing this echo sees
         --  Close_Frame_Sent and raises instead of writing behind it.
         Conn.Sess.Guard.Mark_Close_Sent;
         Conn.Sess.Guard.Release;
      end Maybe_Send_Close_Echo;

      procedure Send_Pong (Payload : AHT.Bytes.Byte_Array) is
      begin
         Conn.Sess.Guard.Acquire;
         begin
            Send_Frame
              (Conn.Sess.Active.all, Conn.Sess.Guard,
               Op      => AHT.Websocket.Pong_Op,
               FIN     => True,
               Payload => Payload);
         exception
            when others =>
               Conn.Sess.Guard.Release;
               return;
         end;
         Conn.Sess.Guard.Release;
      end Send_Pong;

      procedure Deliver
        (Kind : Message_Kind; Payload : AHT.Bytes.Buffer)
      is
      begin
         --  RFC 6455 §8.1: a text message (the complete, reassembled
         --  payload) MUST be valid UTF-8. On an ill-formed one we fail
         --  the connection with close code 1007 rather than delivering
         --  the bad bytes. Binary messages carry no such constraint.
         if Kind = Text_Message
           and then not AHT.Websocket.UTF8.Is_Valid (Payload)
         then
            Maybe_Send_Close_Echo (Code => 1007);
            Fire_On_Error
              ("Receiver: invalid UTF-8 in text message "
               & "(RFC 6455 §8.1) — failing connection with 1007");
            Conn.Sess.State.Set (Closed);
            Stop_Loop := True;
            return;
         end if;

         declare
            Msg : constant Message_Type :=
              (Kind => Kind, Payload => Payload);
         begin
            --  Inbox first so a pull-mode Receive doesn't starve if
            --  the push callback runs slow.
            Conn.Sess.Inbox.Push (Msg);
            Fire_On_Message (Msg);
         end;
      end Deliver;

      procedure Handle_Close_Frame
        (Payload : AHT.Bytes.Buffer)
      is
         Len    : constant Natural := Payload.Length;
         Info   : Close_Info;
         Reason : Unbounded_String;
      begin
         --  Inbound close policy that Decode defers (it accepts the
         --  full Any_Close_Code range and ignores the reason text).
         --  RFC 6455 §7.4.1: 1004/1005/1006/1015 must never be sent
         --  by a peer → fail with 1002. §8.1: a Close reason must be
         --  valid UTF-8 → fail with 1007. Either way we don't deliver
         --  an On_Close for a malformed close, we report On_Error.
         case AHT.Websocket.Frames.Classify_Inbound_Close (Payload) is
            when AHT.Websocket.Frames.Reserved_Code =>
               Maybe_Send_Close_Echo (Code => 1002);
               Fire_On_Error
                 ("Receiver: peer sent a reserved Close code "
                  & "(RFC 6455 §7.4.1) — failing connection with 1002");
               Conn.Sess.State.Set (Closed);
               Stop_Loop := True;
               return;
            when AHT.Websocket.Frames.Bad_Reason =>
               Maybe_Send_Close_Echo (Code => 1007);
               Fire_On_Error
                 ("Receiver: invalid UTF-8 in Close reason "
                  & "(RFC 6455 §8.1) — failing connection with 1007");
               Conn.Sess.State.Set (Closed);
               Stop_Loop := True;
               return;
            when AHT.Websocket.Frames.Accept_Close =>
               null;
         end case;

         --  Frames.Decode has already validated len /= 1 and
         --  the code range, so this is structural extraction.
         if Len = 0 then
            Info := (Has_Code => False);
         else
            declare
               Hi : constant Natural :=
                 Natural (Payload.Element (Payload.First_Index));
               Lo : constant Natural :=
                 Natural (Payload.Element (Payload.First_Index + 1));
            begin
               Info := (Has_Code => True, Code => 256 * Hi + Lo);
            end;
            --  Reason text is the bytes past the 2-byte code: one
            --  block-copy slice (empty when Len = 2).
            Append
              (Reason,
               Payload.To_String (Payload.First_Index + 2,
                                  Payload.Last_Index));
         end if;

         Maybe_Send_Close_Echo;
         Fire_On_Close (Info, To_String (Reason));
         Conn.Sess.State.Set (Closed);
         Stop_Loop := True;
      end Handle_Close_Frame;

      procedure Handle_Frame
        (Hdr : AHT.Websocket.Frames.Frame_Header;
         Payload : AHT.Bytes.Buffer)
      is
      begin
         --  RFC 6455 §5.1: a client MUST NOT accept a masked
         --  frame from the server. The Frames codec is
         --  direction-neutral (it'll happily unmask), so the
         --  direction-specific check is ours.
         if Hdr.Masked then
            raise AHT.Websocket.Protocol_Error
              with "Receiver: server sent a masked frame "
                & "(RFC 6455 §5.1 forbids server-side masking)";
         end if;

         case Hdr.Op is
            when AHT.Websocket.Text | AHT.Websocket.Binary =>
               if In_Reassembly then
                  raise AHT.Websocket.Protocol_Error
                    with "Receiver: data frame received while a "
                      & "fragmented message was in progress";
               end if;
               if Hdr.FIN then
                  --  Single-frame message.
                  Deliver
                    ((if Hdr.Op = AHT.Websocket.Text
                      then Text_Message else Binary_Message),
                     Payload);
               else
                  --  Start a reassembly.
                  In_Reassembly := True;
                  Reassembly_Kind :=
                    (if Hdr.Op = AHT.Websocket.Text
                     then Text_Message else Binary_Message);
                  Reassembly_Buf := Payload;
               end if;

            when AHT.Websocket.Continuation =>
               if not In_Reassembly then
                  raise AHT.Websocket.Protocol_Error
                    with "Receiver: Continuation frame without "
                      & "a preceding fragmented data frame";
               end if;
               --  Append the fragment's bytes in one block move.
               Reassembly_Buf.Append (Payload);
               if Hdr.FIN then
                  Deliver (Reassembly_Kind, Reassembly_Buf);
                  In_Reassembly := False;
                  Reassembly_Buf.Clear;
               end if;

            when AHT.Websocket.Ping_Op =>
               Send_Pong (Payload.To_Array);

            when AHT.Websocket.Pong_Op =>
               --  Unsolicited Pong → drop (v1 doesn't track Pings).
               null;

            when AHT.Websocket.Close_Op =>
               Handle_Close_Frame (Payload);
         end case;
      end Handle_Frame;

   begin
      select
         accept Start (Owner : Client_Access) do
            Conn := Owner;
         end Start;
      or
         terminate;
      end select;

      Main_Loop :
      loop
         exit Main_Loop when Stop_Loop;

         declare
            Hdr  : AHT.Websocket.Frames.Frame_Header;
            Payload : AHT.Bytes.Buffer;
            Last : Natural;
         begin
            if Live (Buf) = 0 then
               Read_More;
            else
               AHT.Websocket.Frames.Decode
                 (Buf.Data (Buf.Head .. Buf.Tail), Hdr, Payload, Last);
               if Last = 0 then
                  Read_More;
               else
                  Consume (Buf, Last);
                  Handle_Frame (Hdr, Payload);
               end if;
            end if;
         exception
            when E : AHT.Websocket.Protocol_Error
               | AHT.HTTP.Protocol_Error
               | AHT.Transport.Transport_Error
               | AHT.Transport.Aborted_Error
            =>
               --  Any of these means the connection is unusable.
               --  Fire On_Error, mark Closed, exit; Inbox.Mark_Closed
               --  below wakes any parked Receive caller with
               --  Closed_Error.
               Fire_On_Error
                 (Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
               Stop_Loop := True;
            when E : others =>
               Fire_On_Error
                 (Ada.Exceptions.Exception_Name (E) & ": "
                  & Ada.Exceptions.Exception_Message (E));
               Stop_Loop := True;
         end;
      end loop Main_Loop;

      Free (Buf.Data);
      Conn.Sess.State.Set (Closed);
      Conn.Sess.Inbox.Mark_Closed;
   end Receiver_Task;

   ---------------------------------------------------------------
   --  Public surface
   ---------------------------------------------------------------

   procedure Connect
     (Self          : in out Client_Type;
      URL           : String;
      Extra_Headers : AHT.HTTP.Headers.Map;
      Subprotocols  : String := "";
      Origin        : String := "";
      Insecure      : Boolean := False;
      CA_Path       : String := "")
   is
      Parsed    : constant AHT.URL.URL_Type := AHT.URL.Parse (URL);
      Key_Bytes : AHT.Bytes.Byte_Array (1 .. 16);

      Req  : AHT.HTTP.Request.Request_Type;
      Resp : AHT.HTTP.Response.Response_Type;

      procedure Add_Extra (Name, Value : String) is
      begin
         if Name = "host"
           or else Name = "upgrade"
           or else Name = "connection"
           or else Name = "sec-websocket-version"
           or else Name = "sec-websocket-key"
         then
            return;
         end if;
         Req.Headers.Append (Name, Value);
      end Add_Extra;

   begin
      --  Single-use lifecycle. A Client_Type owns a one-shot
      --  Receiver_Task; after the first successful Connect the
      --  task is past its `accept Start` and either running or
      --  already terminated. Reusing the same Client_Type would
      --  surface as a wrapped Handshake_Error when we try to
      --  call Start again — reject upfront instead so the user
      --  gets a clear lifecycle error before we dial. A
      --  *failed* Connect leaves State = Connecting, so retries
      --  on a fresh URL still work.
      if Self.Sess.State.Get /= Connecting then
         raise AHT.Websocket.Handshake_Error
           with "Websocket.Client.Connect: Client_Type has "
             & "already been Connect'd (state = "
             & State_Kind'Image (Self.Sess.State.Get)
             & "); declare a fresh Client per connection";
      end if;

      case Parsed.Scheme is
         when AHT.URL.WS | AHT.URL.WSS =>
            null;
         when AHT.URL.HTTP | AHT.URL.HTTPS =>
            raise AHT.Websocket.Handshake_Error
              with "Websocket.Client.Connect: URL must be ws:// "
                & "(or wss://); got " & URL;
      end case;

      Fill_Random (Key_Bytes);
      declare
         Key_B64 : constant String :=
           AHT.Bytes.Base64_Encode (Key_Bytes);
      begin
         Req.Method := AHT.HTTP.Methods.GET;
         Req.Target := Parsed;
         Req.Headers.Set ("host", Host_Header (Parsed));
         Req.Headers.Set ("upgrade", "websocket");
         Req.Headers.Set ("connection", "Upgrade");
         Req.Headers.Set ("sec-websocket-version", "13");
         Req.Headers.Set ("sec-websocket-key", Key_B64);
         if Subprotocols /= "" then
            Req.Headers.Set ("sec-websocket-protocol", Subprotocols);
         end if;
         if Origin /= "" then
            Req.Headers.Set ("origin", Origin);
         end if;
         Extra_Headers.Iterate (Add_Extra'Access);

         --  Dial exactly one transport per scheme and point Active at
         --  it. Scheme is already narrowed to WS | WSS above. Active
         --  is set only after the dial returns, so a connect failure
         --  leaves it null and the teardown paths below never run on a
         --  half-open transport (each transport's own Connect closes
         --  its socket on failure).
         case Parsed.Scheme is
            when AHT.URL.WSS =>
               AHT.Transport.TLS.Connect
                 (Self.Sess.Secure,
                  Host     => To_String (Parsed.Host),
                  Port     => Parsed.Port,
                  Insecure => Insecure,
                  CA_Path  => CA_Path);
               Self.Sess.Active := Self.Sess.Secure'Unchecked_Access;
            when others =>
               --  WS (HTTP/HTTPS already rejected above).
               AHT.Transport.TCP.Connect
                 (Self.Sess.Plain,
                  Host => To_String (Parsed.Host),
                  Port => Parsed.Port);
               Self.Sess.Active := Self.Sess.Plain'Unchecked_Access;
         end case;

         begin
            AHT.HTTP.Request.Write (Req, Self.Sess.Active.all);
            AHT.HTTP.Response.Read
              (Resp, Self.Sess.Active.all,
               Method => AHT.HTTP.Methods.GET);

            if Resp.Status /= 101 then
               raise AHT.Websocket.Handshake_Error
                 with "Websocket.Client.Connect: server returned "
                   & Resp.Status'Image & " "
                   & To_String (Resp.Reason)
                   & " (expected 101 Switching Protocols)";
            end if;

            if To_Lower (Resp.Headers.Get ("upgrade")) /= "websocket"
            then
               raise AHT.Websocket.Handshake_Error
                 with "Websocket.Client.Connect: Upgrade header "
                   & "should be 'websocket', got '"
                   & Resp.Headers.Get ("upgrade") & "'";
            end if;

            if not Contains_Token
                     (Resp.Headers.Get ("connection"), "upgrade")
            then
               raise AHT.Websocket.Handshake_Error
                 with "Websocket.Client.Connect: Connection header "
                   & "must contain 'Upgrade' token (got '"
                   & Resp.Headers.Get ("connection") & "')";
            end if;

            declare
               Want : constant String := Expected_Accept (Key_B64);
               Got  : constant String :=
                 Resp.Headers.Get ("sec-websocket-accept");
            begin
               if Want /= Got then
                  raise AHT.Websocket.Handshake_Error
                    with "Websocket.Client.Connect: "
                      & "Sec-WebSocket-Accept mismatch; expected '"
                      & Want & "', got '" & Got & "'";
               end if;
            end;

            declare
               Values : constant AHT.HTTP.Headers.Value_List :=
                 Resp.Headers.Values ("sec-websocket-protocol");
               Got : constant String :=
                 Resp.Headers.Get ("sec-websocket-protocol");
            begin
               if Natural (Values.Length) > 1 then
                  raise AHT.Websocket.Handshake_Error
                    with "Websocket.Client.Connect: server returned"
                      & Natural'Image (Natural (Values.Length))
                      & " Sec-WebSocket-Protocol header values "
                      & "(spec allows at most one)";
               end if;

               if Got /= "" then
                  if Subprotocols = "" then
                     raise AHT.Websocket.Handshake_Error
                       with "Websocket.Client.Connect: server "
                         & "returned Sec-WebSocket-Protocol '"
                         & Got & "' but the client offered none";
                  end if;
                  if not Is_Offered_Subprotocol (Got, Subprotocols)
                  then
                     raise AHT.Websocket.Handshake_Error
                       with "Websocket.Client.Connect: server "
                         & "selected subprotocol '" & Got
                         & "', not in the client-offered list '"
                         & Subprotocols & "'";
                  end if;
               end if;

               Self.Sess.Selected_Protocol := To_Unbounded_String (Got);
            end;

            --  Handshake good — flip the state machine, hand the
            --  open transport to the receiver task, mark Open.
            Self.Sess.State.Set (Open);
            Self.Open := True;
            --  'Unchecked_Access is safe by the same argument as
            --  Async_Handle: the Receiver task is itself a
            --  component of Self, so the parent master waits for
            --  the task before finalizing the other components
            --  (RM 9.3). The Client_Access never outlives Self.
            Self.Receiver.Start (Owner => Self'Unchecked_Access);
         exception
            when AHT.Websocket.Handshake_Error =>
               Self.Sess.Active.Close;
               raise;
            when E : others =>
               Self.Sess.Active.Close;
               raise AHT.Websocket.Handshake_Error
                 with "Websocket.Client.Connect: "
                   & Ada.Exceptions.Exception_Name (E) & ": "
                   & Ada.Exceptions.Exception_Message (E);
         end;
      end;
   end Connect;

   procedure Connect
     (Self     : in out Client_Type;
      URL      : String;
      Insecure : Boolean := False;
      CA_Path  : String := "")
   is
      No_Extras : AHT.HTTP.Headers.Map;
   begin
      Connect
        (Self,
         URL           => URL,
         Extra_Headers => No_Extras,
         Insecure      => Insecure,
         CA_Path       => CA_Path);
   end Connect;

   function Is_Open (Self : Client_Type) return Boolean is
     (Self.Open and then Self.Sess.State.Get = Open);

   function Selected_Subprotocol (Self : Client_Type) return String is
     (To_String (Self.Sess.Selected_Protocol));

   procedure Send_Text
     (Self : in out Client_Type;
      Text : String) is
   begin
      Self.Sess.Guard.Acquire;
      begin
         if not Is_Open (Self) or else Self.Sess.Guard.Close_Frame_Sent then
            raise AHT.Websocket.Closed_Error with
              "Send_Text: connection is not open";
         end if;
         Send_Frame
           (Self.Sess.Active.all, Self.Sess.Guard,
            Op      => AHT.Websocket.Text,
            FIN     => True,
            Payload => AHT.Bytes.From_String (Text));
      exception
         when others =>
            Self.Sess.Guard.Release;
            raise;
      end;
      Self.Sess.Guard.Release;
   end Send_Text;

   procedure Send_Binary
     (Self : in out Client_Type;
      Data : AHT.Bytes.Byte_Array) is
   begin
      Self.Sess.Guard.Acquire;
      begin
         if not Is_Open (Self) or else Self.Sess.Guard.Close_Frame_Sent then
            raise AHT.Websocket.Closed_Error with
              "Send_Binary: connection is not open";
         end if;
         Send_Frame
           (Self.Sess.Active.all, Self.Sess.Guard,
            Op      => AHT.Websocket.Binary,
            FIN     => True,
            Payload => Data);
      exception
         when others =>
            Self.Sess.Guard.Release;
            raise;
      end;
      Self.Sess.Guard.Release;
   end Send_Binary;

   procedure Send_Ping
     (Self    : in out Client_Type;
      Payload : AHT.Bytes.Byte_Array := []) is
   begin
      Self.Sess.Guard.Acquire;
      begin
         if not Is_Open (Self) or else Self.Sess.Guard.Close_Frame_Sent then
            raise AHT.Websocket.Closed_Error with
              "Send_Ping: connection is not open";
         end if;
         Send_Frame
           (Self.Sess.Active.all, Self.Sess.Guard,
            Op      => AHT.Websocket.Ping_Op,
            FIN     => True,
            Payload => Payload);
      exception
         when others =>
            Self.Sess.Guard.Release;
            raise;
      end;
      Self.Sess.Guard.Release;
   end Send_Ping;

   procedure Close
     (Self    : in out Client_Type;
      Code    : AHT.Websocket.Valid_Close_Code := 1000;
      Reason  : String := "";
      Timeout : Duration := 5.0)
   is
      Should_Send    : Boolean;
      Already_Closed : Boolean;
   begin
      if Self.Sess.State.Get = Connecting then
         --  Never handshook; nothing to do.
         return;
      end if;

      if Self.Sess.State.Get not in Open | Closing then
         --  Already Closed (receiver wound up first). Just make
         --  sure the transport is down.
         if Self.Sess.Active.Is_Connected then
            Self.Sess.Active.Close;
         end if;
         Self.Open := False;
         return;
      end if;

      --  RFC 6455 §1.4 close: send our Close (if we haven't yet),
      --  then wait for the receiver to see the peer's echo before
      --  tearing the TCP transport down. Abort_Pending guarantees
      --  Wait_Closed doesn't hang forever if the peer goes silent.
      Self.Sess.State.Try_Mark_Local_Close (Should_Send);
      if Should_Send then
         Self.Sess.Guard.Acquire;
         begin
            Send_Frame
              (Self.Sess.Active.all, Self.Sess.Guard,
               Op      => AHT.Websocket.Close_Op,
               FIN     => True,
               Payload => Build_Close_Payload (Code, Reason));
         exception
            when others =>
               --  Best effort. Continue with the local teardown
               --  regardless.
               null;
         end;
         --  Latch under the guard before releasing: a Send_* blocked
         --  on Acquire will now observe Close_Frame_Sent and raise
         --  rather than writing a data frame after our Close.
         Self.Sess.Guard.Mark_Close_Sent;
         Self.Sess.Guard.Release;
      end if;

      --  Move to Closing, but never clobber a Closed the receiver may
      --  have published while we were sending our Close frame (the
      --  peer can EOF or echo Close mid-handshake, run the receiver's
      --  exit path, and terminate). If that already happened there is
      --  no receiver left to ever re-publish Closed, so an
      --  unconditional Set (Closing) here would make Wait_Closed hang
      --  forever -- detect it and tear down directly instead.
      Self.Sess.State.Begin_Closing (Already_Closed);
      if Already_Closed then
         Self.Open := False;
         Self.Sess.Active.Close;
         return;
      end if;

      --  Bounded wait: if the peer never echoes our Close in
      --  `Timeout` seconds, kick the receiver out via
      --  Abort_Pending so we eventually finalize. Duration'Last
      --  effectively disables the bound; 0.0 fires the abort
      --  path immediately without waiting at all.
      select
         Self.Sess.State.Wait_Closed;
      or
         delay Timeout;
         Self.Sess.Active.Abort_Pending;
         Self.Sess.State.Wait_Closed;
      end select;

      Self.Open := False;
      Self.Sess.Active.Close;
   end Close;

   procedure Receive
     (Self    : in out Client_Type;
      Msg     : out Message_Type;
      Timeout : Duration := Duration'Last) is
   begin
      select
         Self.Sess.Inbox.Receive (Msg);
      or
         delay Timeout;
         Msg := (Kind => Binary_Message, Payload => <>);
         raise AHT.Transport.Timeout_Error
           with "Websocket.Client.Receive: timeout after"
             & Duration'Image (Timeout) & "s";
      end select;
   end Receive;

   procedure Set_On_Message
     (Self : in out Client_Type;
      CB   : On_Message_Callback) is
   begin
      Self.On_Message := CB;
   end Set_On_Message;

   procedure Set_On_Close
     (Self : in out Client_Type;
      CB   : On_Close_Callback) is
   begin
      Self.On_Close := CB;
   end Set_On_Close;

   procedure Set_On_Error
     (Self : in out Client_Type;
      CB   : On_Error_Callback) is
   begin
      Self.On_Error := CB;
   end Set_On_Error;

end AHT.Websocket.Client;
