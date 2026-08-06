with Ada.Characters.Handling;
with Ada.Real_Time;
with Ada.Exceptions;
with Ada.Finalization;
with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Unchecked_Deallocation;

with GNAT.SHA1;

with AHT.HTTP.Methods;
with AHT.HTTP.Request;
with AHT.HTTP.Response;
with AHT.Random;
with AHT.URL;
with AHT.Websocket.Budgets;
with AHT.Websocket.Frames;
with AHT.Websocket.UTF8;

package body AHT.Websocket.Client is

   package Guards renames AHT.Websocket.Send_Guards;

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

   --  Sec-WebSocket-Key must be a nonce selected randomly per
   --  connection (RFC 6455 4.1). The previous implementation reset a
   --  clock-seeded generator on every call, so two connections made
   --  in the same tick could draw the same key.
   procedure Fill_Random (B : out AHT.Bytes.Byte_Array)
     renames AHT.Random.Fill;

   ---------------------------------------------------------------
   --  Session plumbing
   ---------------------------------------------------------------

   --  The transport this session actually dialed. Computed from the
   --  discriminant rather than stored, so there is no field that can
   --  dangle or go stale when the session is replaced.
   function Active
     (S : Session_Access) return AHT.Transport.Transport_Access
   is (case S.Kind is
          when Plain_Transport  => S.Plain'Unchecked_Access,
          when Secure_Transport => S.Secure'Unchecked_Access);

   procedure Free is new Ada.Unchecked_Deallocation
     (Session_Type, Session_Access);

   --  Build + send one masked frame on a transport. Caller MUST hold
   --  the Send_Guard (Acquire / Release wrap this). The transport
   --  Write happens *outside* the guard's own lock so a slow socket
   --  can't block other tasks' Acquires.
   --
   --  The mask comes from the OS entropy pool rather than from state
   --  the guard has to protect, so drawing it needs no lock of its
   --  own -- see AHT.Random for why a PRNG will not do here.
   procedure Send_Frame
     (Transport : in out AHT.Transport.Transport_Type'Class;
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
      AHT.Random.Fill (Hdr.Mask_Key);
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
         --  Exact, deliberately. The counter is only ever incremented
         --  after an insertion succeeded, so it cannot drift; clamping
         --  here would hide an accounting bug rather than fix one.
         Queued_Bytes := Queued_Bytes - Msg.Payload.Length;
      end Receive;

      procedure Try_Push (Msg : Message_Type; Accepted : out Boolean) is
         use type Ada.Containers.Count_Type;
         Len : constant Natural := Msg.Payload.Length;
      begin
         --  Subtraction, not addition: Queued_Bytes + Len could
         --  overflow the very comparison meant to reject it. Written
         --  this way the arithmetic stays in Natural's base type, and
         --  a message larger than the whole budget makes the
         --  right-hand side negative — which refuses, as it should.
         if Closed_F
           or else Q.Length >= Capacity
           or else Queued_Bytes > Max_Bytes - Len
         then
            Accepted := False;
            return;
         end if;

         Q.Append (Msg);
         --  Only now: the count must never claim bytes the queue does
         --  not hold.
         Queued_Bytes := Queued_Bytes + Len;
         Accepted     := True;
      end Try_Push;

      procedure Mark_Closed is
      begin
         Closed_F := True;
      end Mark_Closed;

      function Count return Natural is (Natural (Q.Length));

      function Byte_Count return Natural is (Queued_Bytes);

      function Is_Closed return Boolean is (Closed_F);

   end Inbox_PO;

   protected body Lifecycle_Controller is

      procedure Begin_Connect
        (P         : Connect_Params;
         Owner_Gen : access Natural;
         Gen       : out Natural;
         L         : out Limits;
         Result    : out Admission_Result) is
      begin
         --  Every refusal leaves the object exactly as it was. A
         --  rejected Connect must not burn a generation number, move
         --  the state machine, or commit a delivery mode.
         --
         --  Disconnected is admitted alongside Idle: a client whose
         --  connection has been fully reclaimed is as ready to dial as
         --  one that never has. What stays refused is Connecting (an
         --  attempt is already in flight) and Open or Closing — a live
         --  connection is never silently dropped to make room for a
         --  new one; the caller closes it first, or asks for the
         --  drain-and-redial that Reconnect will provide.
         if St not in Idle | Disconnected then
            Gen    := 0;
            L      := Pending;
            Result := Wrong_State;
            return;
         end if;

         if Pending.Delivery = Callback_Only
           and then CBs.On_Message = null
         then
            Gen    := 0;
            L      := Pending;
            Result := No_Callback;
            return;
         end if;

         --  The one allocating step goes first. Copying the
         --  parameters can raise, and it must not be able to do so
         --  after the state machine has moved: the owner is only
         --  made responsible for the admission below, so a failure
         --  past that point would strand the client in Connecting
         --  with nobody to clear it.
         Pending_Conn := P;

         --  Nothing below can fail.
         Next_Gen     := Next_Gen + 1;

         --  The owner becomes responsible for this admission in the
         --  same protected action that grants it, and before the
         --  state moves. Both orderings matter: recording it after
         --  St := Connecting would leave a state change no owner had
         --  accepted yet, and recording it outside this action at all
         --  would leave the gap an abort slips through.
         Owner_Gen.all := Next_Gen;

         Gen          := Next_Gen;
         St           := Connecting;
         L            := Pending;
         Active_Mode  := Pending.Delivery;
         Result       := Admitted;
      end Begin_Connect;

      procedure Saved_Params (P : out Connect_Params; OK : out Boolean) is
      begin
         P  := Saved_Conn;
         OK := Has_Saved;
      end Saved_Params;

      procedure Set_Pending_Limits (L : Limits; OK : out Boolean) is
      begin
         --  Only while fully disconnected. Anywhere else an attempt is
         --  either in flight or winding down, and the session it
         --  belongs to has already frozen its ceilings.
         if St in Idle | Disconnected then
            Pending := L;
            OK      := True;
         else
            OK := False;
         end if;
      end Set_Pending_Limits;

      procedure Abandon_Connect (Gen : Positive) is
      begin
         --  Only the attempt that is actually in flight may release
         --  admission: a later Connect may already have been admitted
         --  by the time an earlier attempt's cleanup runs, and
         --  Next_Gen is what tells them apart.
         if St = Connecting and then Next_Gen = Gen then
            --  Unpublished by definition, so the client goes back to
            --  where admission found it and stays retryable. Which
            --  state that was is not a matter of memory: admission
            --  only accepts Idle and Disconnected, and those are
            --  exactly "nothing has ever connected" and "something
            --  has". Collapsing both to Idle would erase the fact
            --  that this client has a past — which is what a later
            --  Reconnect needs in order to know it has parameters
            --  worth replaying.
            St   := (if Published_Gen > 0 then Disconnected else Idle);
            Done := True;
         end if;
      end Abandon_Connect;

      procedure Publish (S : Session_Access) is
      begin
         --  Both allocating copies happen before ANY marker moves.
         --  If either raises, publication simply has not happened:
         --  the connecting task's owner still sees the session as
         --  un-handed-off and frees it, and the receiver treats the
         --  failed rendezvous as no session at all. Doing this after
         --  setting Cur or Handed_Off_Gen would leave the two sides
         --  disagreeing about who owns the session, and nobody
         --  reclaiming it.
         Proto      := S.Selected_Protocol;
         --  Promoted here and nowhere else, so what Reconnect repeats
         --  is the last connect that actually worked rather than the
         --  last one attempted.
         Saved_Conn := Pending_Conn;

         --  Nothing below can fail.
         Has_Saved     := True;
         Cur           := S;
         --  Counted, not copied from the session's reserved number.
         --  Those two are different things: reservations are handed
         --  out per ATTEMPT and have gaps where attempts failed,
         --  which is exactly what makes them useful for identifying
         --  an attempt's cleanup. Exposing them would mean a client
         --  whose first dial was refused reports "generation 2" for
         --  its first connection, which is not what the number is
         --  for.
         Published_Gen := Published_Gen + 1;
         Admitting     := True;
         Forced        := False;
         Done          := False;
         Handed_Off_Gen := S.Generation;
         St            := Open;
      end Publish;

      function Attempt_Handed_Off (Gen : Positive) return Boolean is
        (Handed_Off_Gen >= Gen);

      procedure Acquire (S : out Session_Access; OK : out Boolean) is
      begin
         if Admitting and then Cur /= null then
            Leases := Leases + 1;
            S      := Cur;
            OK     := True;
         else
            S  := null;
            OK := False;
         end if;
      end Acquire;

      procedure Release is
      begin
         if Leases > 0 then
            Leases := Leases - 1;
         end if;
      end Release;

      procedure Begin_Teardown
        (S         : out Session_Access;
         Result    : out Teardown_Result;
         By_Caller : Boolean) is
      begin
         if Admitting and then Cur /= null then
            --  Winner. Stopping admission and taking the borrow in
            --  the SAME protected action is what pins the session:
            --  the receiver's Wait_No_Borrowers cannot pass while we
            --  hold it, so S stays valid for the close handshake.
            Admitting := False;
            Forced    := Forced or else By_Caller;
            St        := Closing;
            Leases    := Leases + 1;
            S         := Cur;
            Result    := Won_Teardown;
         elsif not Done then
            --  Teardown already under way — possibly already past
            --  Wait_No_Borrowers, so the session must not be touched.
            S      := null;
            Result := Join_Teardown;
         else
            S      := null;
            Result := No_Session;
         end if;
      end Begin_Teardown;

      procedure Stop_Admission is
      begin
         if Admitting then
            Admitting := False;
            St        := Closing;
         end if;
      end Stop_Admission;

      function Draining_Forced return Boolean is (Forced);

      entry Wait_No_Borrowers when Leases = 0 is
      begin
         null;
      end Wait_No_Borrowers;

      procedure Clear_Published is
      begin
         Cur := null;
         --  The subprotocol was this connection's, not the client's.
         --  Leaving it behind would have Selected_Subprotocol answer
         --  for a session that no longer exists, and keep answering
         --  until some later connection happened to overwrite it.
         Proto := Ada.Strings.Unbounded.Null_Unbounded_String;
      end Clear_Published;

      procedure Signal_Generation_Done is
      begin
         Done   := True;
         Forced := False;
         St     := Disconnected;
      end Signal_Generation_Done;

      entry Wait_Generation_Done when Done is
      begin
         null;
      end Wait_Generation_Done;

      procedure Set_On_Message
        (CB : On_Message_Callback; OK : out Boolean) is
      begin
         --  Refused only when it would leave a Callback_Only
         --  connection with no consumer at all. Connecting counts:
         --  that is the gap between admission and publication, where
         --  the session is already committed to callback delivery.
         --  Closing counts too: a message may be decoded and waiting
         --  to be dispatched right now.
         if CB = null
           and then Active_Mode = Callback_Only
           and then St in Connecting | Open | Closing
         then
            OK := False;
            return;
         end if;
         CBs.On_Message := CB;
         OK             := True;
      end Set_On_Message;

      procedure Set_On_Close (CB : On_Close_Callback) is
      begin
         CBs.On_Close := CB;
      end Set_On_Close;

      procedure Set_On_Error (CB : On_Error_Callback) is
      begin
         CBs.On_Error := CB;
      end Set_On_Error;

      function Current_Callbacks return Callbacks is (CBs);

      function Is_Open return Boolean is (St = Open);

      function State return Client_State is (St);

      function Generation return Natural is (Published_Gen);

      --  Answers only while there is a connection to answer for. The
      --  value is staged by Publish, and Publish stages before it
      --  moves any marker, so without this guard a client could
      --  briefly report the subprotocol of a connection that had not
      --  been established yet.
      function Protocol return String is
        (if St in Open | Closing then To_String (Proto) else "");

      procedure Set_Receiver_Id (Id : Ada.Task_Identification.Task_Id) is
      begin
         Rx := Id;
      end Set_Receiver_Id;

      function Is_Receiver
        (Id : Ada.Task_Identification.Task_Id) return Boolean
      is
         use type Ada.Task_Identification.Task_Id;
      begin
         return Rx /= Ada.Task_Identification.Null_Task_Id
           and then Id = Rx;
      end Is_Receiver;

   end Lifecycle_Controller;

   ---------------------------------------------------------------
   --  Borrow scope guard
   ---------------------------------------------------------------

   --  Every public operation that touches a session takes its borrow
   --  through one of these, so every exit path — a raise, the Receive
   --  timeout branch, an ordinary return — releases exactly once.
   --  Mirrors the feeder scope guard in the TLS engines.
   type Lease (Ctl : access Lifecycle_Controller) is
     new Ada.Finalization.Limited_Controlled with record
        Sess : Session_Access := null;
        Held : Boolean        := False;
     end record;

   overriding procedure Initialize (L : in out Lease);
   overriding procedure Finalize   (L : in out Lease);

   overriding procedure Initialize (L : in out Lease) is
   begin
      L.Ctl.Acquire (L.Sess, L.Held);
   end Initialize;

   overriding procedure Finalize (L : in out Lease) is
   begin
      if L.Held then
         L.Held := False;
         L.Sess := null;
         L.Ctl.Release;
      end if;
   end Finalize;

   --  Owns an admitted, still-UNPUBLISHED connection attempt. Every
   --  exit that did not hand the session to the receiver -- a raise,
   --  or an abort of the connecting task -- drops the transport, frees
   --  the session and releases admission, so the client is never
   --  stranded in Connecting with a leaked transport.
   --
   --  Whether the handoff happened is asked of the CONTROLLER, keyed
   --  by this attempt's generation. Two simpler answers are both
   --  wrong:
   --
   --    * A local flag set after Start returns leaves a window where
   --      an abort makes this Finalize free a session the receiver
   --      already owns -- trading a leak for a double free.
   --    * Clearing the caller's pointer through an `in out` entry
   --      parameter looks like it closes that window, but does not:
   --      GNAT does not deliver the copy-back when the caller is
   --      aborted during the rendezvous, so the pointer stays set and
   --      the double free is back. Measured, not assumed -- and the
   --      handoff sweep in test_ws_abort is what caught it.
   --
   --  Publish records the generation from inside a protected action,
   --  which IS abort-deferred, so the record cannot be lost. Gen also
   --  qualifies the admission release: by the time an early
   --  generation's frame finalizes, its session may already have been
   --  published, reclaimed AND a fresh Connect admitted, and this
   --  cleanup must not release an admission belonging to that newer
   --  attempt.
   --  Gen is a mutable component and NOT a discriminant, which is
   --  what lets this object exist before admission is asked for.
   --
   --  As a discriminant it could only be elaborated once
   --  Begin_Connect had returned the generation — so between the end
   --  of that protected action and the elaboration of the owner there
   --  was a window with the client already in Connecting and nobody
   --  able to take it back out. A pending abort takes effect at
   --  exactly that point (the end of a protected action, before the
   --  statement that follows), and one landing there stranded the
   --  client in Connecting permanently: no owner, so no
   --  Abandon_Connect, so no later Connect ever admitted again.
   --
   --  Now the owner is declared first and Begin_Connect records the
   --  generation into it from INSIDE its own protected action, which
   --  is abort-deferred. There is no window: either the record was
   --  made and Finalize releases the admission, or it was not and
   --  Gen is still 0, meaning this owner never held one. Same shape
   --  as Send_Guard.Acquire, and for the same reason.
   type Attempt_Owner
     (Ctl : access Lifecycle_Controller) is
     new Ada.Finalization.Limited_Controlled with record
        Sess : Session_Access  := null;
        Gen  : aliased Natural := 0;
     end record;

   overriding procedure Finalize (A : in out Attempt_Owner);

   overriding procedure Finalize (A : in out Attempt_Owner) is
   begin
      --  Admission was never granted — the state check refused, the
      --  parameter copy raised, or an abort landed before the record
      --  could be made. In every one of those the client was left
      --  exactly as admission found it, so there is nothing to
      --  release and releasing anyway would clear an admission
      --  belonging to somebody else.
      if A.Gen = 0 then
         return;
      end if;

      if A.Ctl.Attempt_Handed_Off (Positive (A.Gen)) then
         --  The receiver owns it now and will reclaim it.
         A.Sess := null;
         return;
      end if;

      if A.Sess /= null then
         --  Never handed over, so it is still ours to dispose of.
         begin
            Active (A.Sess).Close;
         exception
            when others => null;
         end;
         begin
            Free (A.Sess);
         exception
            when others => A.Sess := null;
         end;
      end if;
      --  A no-op unless THIS attempt is the one still in flight.
      A.Ctl.Abandon_Connect (Positive (A.Gen));
   end Finalize;

   --  Holds the teardown borrow for whoever wins it. Taking the borrow
   --  in Initialize and returning it in Finalize is what makes the win
   --  survive an abort of the closing task: a manual release skipped
   --  that way would leave the borrow count above zero and the
   --  receiver waiting on it forever.
   type Teardown_Pin (Ctl : access Lifecycle_Controller) is
     new Ada.Finalization.Limited_Controlled with record
        Sess   : Session_Access  := null;
        Result : Teardown_Result := No_Session;
        Held   : Boolean         := False;
     end record;

   overriding procedure Initialize (P : in out Teardown_Pin);
   overriding procedure Finalize   (P : in out Teardown_Pin);

   overriding procedure Initialize (P : in out Teardown_Pin) is
   begin
      P.Ctl.Begin_Teardown (P.Sess, P.Result, By_Caller => True);
      P.Held := P.Result = Won_Teardown;
   end Initialize;

   --  Winning the teardown makes this task the ONLY one that can wake
   --  the receiver: admission is already stopped, so no later Close
   --  will win and every one of them joins and waits. Leaving without
   --  waking it -- because the close handshake raised, or because this
   --  task was aborted mid-handshake -- would park the receiver in
   --  Read forever and hang every joiner behind it. So the wake gates
   --  live here, ahead of the release, where no exit path can skip
   --  them; they are idempotent with the receiver's own reclamation.
   overriding procedure Finalize (P : in out Teardown_Pin) is
   begin
      if not P.Held then
         return;
      end if;
      P.Held := False;

      if P.Sess /= null then
         begin
            P.Sess.State.Set (Closed);
            P.Sess.Inbox.Mark_Closed;
         exception
            when others => null;
         end;
         begin
            Active (P.Sess).Abort_Pending;
         exception
            when others => null;
         end;
      end if;

      P.Sess := null;
      P.Ctl.Release;
   end Finalize;

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
   --  Data is allocated lazily on the first read (Ensure_Room). The
   --  buffer is controlled so that ANY exit from the per-connection
   --  receive loop — normal, protocol error, abort, or an unexpected
   --  exception — reclaims it; an explicit Free on the normal path
   --  would leak on every other one.
   type Byte_Array_Access is access AHT.Bytes.Byte_Array;

   procedure Free is new Ada.Unchecked_Deallocation
     (AHT.Bytes.Byte_Array, Byte_Array_Access);

   type Recv_Buffer is new Ada.Finalization.Limited_Controlled with record
      Data : Byte_Array_Access := null;
      Head : Positive := 1;
      Tail : Natural  := 0;
   end record;

   overriding procedure Finalize (B : in out Recv_Buffer);

   overriding procedure Finalize (B : in out Recv_Buffer) is
   begin
      Free (B.Data);
   end Finalize;

   function Live (B : Recv_Buffer) return Natural is (B.Tail - B.Head + 1);

   --  Guarantee at least Extra free bytes past Tail, compacting the
   --  consumed prefix first and only growing (doubling) when that is
   --  still not enough.
   procedure Ensure_Room (B : in out Recv_Buffer; Extra : Natural) is
      Used : constant Natural := Live (B);
   begin
      if B.Data = null then
         --  First read: allocate lazily here, inside the receive
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
      --  This is the ONLY receiver state that spans generations:
      --  everything per-connection is local to Run_Session, so a
      --  second generation cannot inherit the first one's terminal
      --  Stop_Loop or a half-assembled fragment.
      Conn         : Client_Access  := null;
      Cur_Sess     : Session_Access := null;
      Took_Session : Boolean        := False;

      --  Fire a user-installed callback inside a guard so the
      --  receiver task keeps draining the wire if the callback
      --  raises. The registry is read afresh per event, so a setter
      --  called at runtime takes effect from the next event on; the
      --  snapshot exists only so user code never runs under the
      --  controller lock.
      procedure Fire_On_Message (Msg : Message_Type) is
         CB : constant Callbacks := Conn.Ctl.Current_Callbacks;
      begin
         if CB.On_Message /= null then
            begin
               CB.On_Message (Msg);
            exception
               when others => null;
            end;
         end if;
      end Fire_On_Message;

      procedure Fire_On_Close (Info : Close_Info; Reason : String) is
         CB : constant Callbacks := Conn.Ctl.Current_Callbacks;
      begin
         if CB.On_Close /= null then
            begin
               CB.On_Close (Info, Reason);
            exception
               when others => null;
            end;
         end if;
      end Fire_On_Close;

      procedure Fire_On_Error (Message : String) is
         CB : constant Callbacks := Conn.Ctl.Current_Callbacks;
      begin
         if CB.On_Error /= null then
            begin
               CB.On_Error (Message);
            exception
               when others => null;
            end;
         end if;
      end Fire_On_Error;

      ------------------------------------------------------------
      --  One connection, start to finish
      ------------------------------------------------------------

      procedure Run_Session (S : Session_Access) is
         --  Frame-decoding accumulator: bytes read from the transport
         --  but not yet consumed by a successful Frames.Decode.
         Buf : Recv_Buffer;

         --  Reassembly state for fragmented messages (RFC 6455 §5.4).
         --  A Text/Binary frame with FIN=0 starts a reassembly; later
         --  Continuation frames append; FIN=1 closes it.
         In_Reassembly   : Boolean      := False;
         Reassembly_Kind : Message_Kind := Binary_Message;
         Reassembly_Buf  : AHT.Bytes.Buffer;

         Stop_Loop : Boolean := False;

         procedure Read_More is
            Chunk : AHT.Bytes.Byte_Array (1 .. 4_096);
            Last  : Natural;
         begin
            Active (S).Read (Chunk, Last);
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
            Token       : Guards.Guard_Token (S.Guard'Unchecked_Access);
         begin
            Token.Take;
            --  A forced teardown may already have fired Abort_Pending,
            --  which wakes only the waiters that existed at the time.
            --  Starting a write now would park with nothing left to
            --  cancel it, and the reclaimer's borrow drain would never
            --  reach zero. The check must come BEFORE
            --  Try_Mark_Local_Close, or we would consume the "someone
            --  will send the Close" token and then decline to send it.
            if Conn.Ctl.Draining_Forced then
               return;
            end if;

            S.State.Try_Mark_Local_Close (Should_Send);
            if not Should_Send then
               return;
            end if;

            begin
               Send_Frame
                 (Active (S).all,
                  Op      => AHT.Websocket.Close_Op,
                  FIN     => True,
                  Payload => Build_Close_Payload (Code, ""));
            exception
               when others =>
                  --  If the echo can't go out (peer already torn the
                  --  transport down, etc.), latch anyway: the
                  --  connection is finished, no data frame may follow.
                  null;
            end;
            --  Latch under the guard so a Send_* racing this echo sees
            --  Close_Frame_Sent and raises instead of writing behind it.
            S.Guard.Mark_Close_Sent;
         end Maybe_Send_Close_Echo;

         procedure Send_Pong (Payload : AHT.Bytes.Byte_Array) is
            Token : Guards.Guard_Token (S.Guard'Unchecked_Access);
         begin
            Token.Take;
            --  Same forced-teardown gate as the Close echo above.
            if Conn.Ctl.Draining_Forced then
               return;
            end if;
            begin
               Send_Frame
                 (Active (S).all,
                  Op      => AHT.Websocket.Pong_Op,
                  FIN     => True,
                  Payload => Payload);
            exception
               when others => null;
            end;
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
               S.State.Set (Closed);
               Stop_Loop := True;
               return;
            end if;

            declare
               Msg      : constant Message_Type :=
                 (Kind => Kind, Payload => Payload);
               Accepted : Boolean := True;
            begin
               --  Callback_Only never enqueues, which is what removes
               --  the inbox as a growth path rather than merely
               --  bounding it.
               if S.Delivery /= Callback_Only then
                  --  Inbox first so a pull-mode Receive doesn't starve
                  --  if the push callback runs slow.
                  S.Inbox.Try_Push (Msg, Accepted);
               end if;

               if not Accepted then
                  --  The peer is outrunning the application. That is a
                  --  different failure from an oversized message: the
                  --  frame was legal and within its ceiling, we simply
                  --  cannot hold it. Dropping it silently would corrupt
                  --  stream semantics the caller has no way to detect,
                  --  so the connection goes down with 1008 instead.
                  Maybe_Send_Close_Echo (Code => 1008);
                  Fire_On_Error
                    ("Receiver: inbox full ("
                     & Natural'Image (S.Inbox.Count) & " messages,"
                     & Natural'Image (S.Inbox.Byte_Count)
                     & " bytes queued) — failing connection with 1008");
                  S.State.Set (Closed);
                  Stop_Loop := True;
                  return;
               end if;

               --  Not reached for a refused push: pull and push
               --  consumers must observe the same accepted set.
               --
               --  Pull_Only means what it says. A callback installed
               --  before the mode was chosen -- or left installed
               --  across a reconfiguration -- must not start firing
               --  again behind the application's back.
               if S.Delivery /= Pull_Only then
                  Fire_On_Message (Msg);
               end if;
            end;
         end Deliver;

         procedure Handle_Close_Frame (Payload : AHT.Bytes.Buffer) is
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
                  S.State.Set (Closed);
                  Stop_Loop := True;
                  return;
               when AHT.Websocket.Frames.Bad_Reason =>
                  Maybe_Send_Close_Echo (Code => 1007);
                  Fire_On_Error
                    ("Receiver: invalid UTF-8 in Close reason "
                     & "(RFC 6455 §8.1) — failing connection with 1007");
                  S.State.Set (Closed);
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
            S.State.Set (Closed);
            Stop_Loop := True;
         end Handle_Close_Frame;

         procedure Handle_Frame
           (Hdr     : AHT.Websocket.Frames.Frame_Header;
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
         Main_Loop :
         loop
            exit Main_Loop when Stop_Loop;

            declare
               Hdr     : AHT.Websocket.Frames.Frame_Header;
               Payload : AHT.Bytes.Buffer;
               Last    : Natural;
            begin
               if Live (Buf) = 0 then
                  Read_More;
               else
                  --  What is left of the ceiling for the message being
                  --  assembled, so it bounds the logical message
                  --  rather than each frame separately. Computed by
                  --  comparison rather than by subtracting and hoping:
                  --  Used can only exceed the ceiling if something has
                  --  already gone wrong, and an underflow here would
                  --  turn that into a wildly permissive allowance.
                  declare
                     Used : constant Natural :=
                       (if In_Reassembly then Reassembly_Buf.Length else 0);
                     Allowance : constant Natural :=
                       (if Used >= S.Max_Message_Bytes
                        then 0 else S.Max_Message_Bytes - Used);
                     Frag : constant AHT.Websocket.Frames.Fragment_State :=
                       (if In_Reassembly
                        then AHT.Websocket.Frames.In_Message
                        else AHT.Websocket.Frames.No_Message);
                  begin
                     AHT.Websocket.Frames.Decode
                       (Buf.Data (Buf.Head .. Buf.Tail), Hdr, Payload, Last,
                        Allowance => Allowance,
                        Fragment  => Frag);
                  end;
                  if Last = 0 then
                     Read_More;
                  else
                     Consume (Buf, Last);
                     Handle_Frame (Hdr, Payload);
                  end if;
               end if;
            exception
               when AHT.Transport.Aborted_Error =>
                  --  Split out from the others on purpose. An abort is
                  --  how a Close or Reconnect stops us, so when the
                  --  application asked for the teardown this is the
                  --  mechanism working, not a fault to report. A
                  --  peer-driven abort still reaches On_Error.
                  if not Conn.Ctl.Draining_Forced then
                     Fire_On_Error
                       ("AHT.TRANSPORT.ABORTED_ERROR: transport I/O "
                        & "cancelled");
                  end if;
                  Stop_Loop := True;
               when E : AHT.Websocket.Message_Too_Big =>
                  --  The peer declared more than this endpoint will
                  --  hold. Nothing malformed happened, so it gets its
                  --  own close code rather than the protocol one.
                  Maybe_Send_Close_Echo (Code => 1009);
                  Fire_On_Error
                    (Ada.Exceptions.Exception_Name (E) & ": "
                     & Ada.Exceptions.Exception_Message (E));
                  S.State.Set (Closed);
                  Stop_Loop := True;
               when E : AHT.Websocket.Protocol_Error
                  | AHT.HTTP.Protocol_Error
                  | AHT.Transport.Transport_Error
               =>
                  --  Any of these means the connection is unusable.
                  --  Fire On_Error and exit; reclamation below wakes
                  --  any parked Receive caller with Closed_Error.
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
      end Run_Session;

      ------------------------------------------------------------
      --  Reclamation — receiver only
      ------------------------------------------------------------

      --  Steps 2, 3 and 7 are hard safety gates and carry no local
      --  handler: if admission did not stop, a fresh borrow could be
      --  granted after the zero-borrower check; if the published
      --  pointer were not cleared, it would dangle past the Free. A
      --  surprise there must propagate, not be masked. Only the
      --  genuinely best-effort steps — the abort, the transport close
      --  and the deallocation — swallow exceptions, and the signal
      --  runs regardless so nobody waits forever on a completion that
      --  never comes.
      procedure Reclaim (S : in out Session_Access) is
      begin
         --  2. GATE: no new borrows. Before marking anything closed,
         --     or a lease could be granted against a session whose
         --     teardown has already begun. Idempotent — a Close that
         --     won the teardown already did it.
         Conn.Ctl.Stop_Admission;

         --  3. GATE: wake every borrower parked on this session.
         S.State.Set (Closed);
         S.Inbox.Mark_Closed;

         --  4. Best effort: release a borrower parked in Read/Write.
         --     Required even on receiver-initiated reclamation — a
         --     Send parked on a dead socket holds a borrow, and
         --     without this step 5 would wait out its write deadline.
         begin
            Active (S).Abort_Pending;
         exception
            when others => null;
         end;

         --  5. The memory-safety gate, deliberately unbounded.
         Conn.Ctl.Wait_No_Borrowers;

         --  6. Best effort.
         begin
            Active (S).Close;
         exception
            when others => null;
         end;

         --  7. GATE: drop the published pointer before the free.
         Conn.Ctl.Clear_Published;

         --  8. Best effort. Every nested resource — transports,
         --     protected objects, buffers, strings — finalizes here.
         begin
            Free (S);
         exception
            when others => S := null;
         end;

         --  9.
         Conn.Ctl.Signal_Generation_Done;
      end Reclaim;

   begin
      loop
         Took_Session := False;

         begin
            select
               accept Start
                 (Owner : Client_Access; Sess : Session_Access)
               do
                  Conn     := Owner;
                  Cur_Sess := Sess;
                  --  Publishing inside the rendezvous makes it atomic
                  --  with taking ownership, so a receiver that hits
                  --  instant EOF cannot start reclaiming a session the
                  --  controller has not published yet. It is also what
                  --  records the handoff for the connecting task's
                  --  cleanup -- see Attempt_Owner.
                  Conn.Ctl.Publish (Sess);
                  --  Current_Task inside an accept body is the
                  --  ACCEPTING task, so this is the receiver naming
                  --  itself.
                  Conn.Ctl.Set_Receiver_Id
                    (Ada.Task_Identification.Current_Task);
               end Start;
               Took_Session := True;
            or
               terminate;
            end select;
         exception
            when others =>
               --  The rendezvous body failed, so publication did not
               --  happen -- Publish does everything that can raise
               --  before it moves a single marker. The session is
               --  therefore still the connecting task's, and its
               --  cleanup will free it; touching it here would be a
               --  double free. Drop it and wait for the next Start
               --  rather than letting one bad handoff end the task.
               Cur_Sess     := null;
               Took_Session := False;
         end;

         if Took_Session then
            begin
               Run_Session (Cur_Sess);
            exception
               when others =>
                  --  Never let a generation kill the task: the client
                  --  outlives its connections.
                  null;
            end;

            Reclaim (Cur_Sess);
            Cur_Sess := null;
         end if;
      end loop;
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
      Parsed : constant AHT.URL.URL_Type := AHT.URL.Parse (URL);

      Gen : Natural;
      Adm : Admission_Result;
      Lim : Limits;

      --  Deep copies by construction: Unbounded_String and the header
      --  map both own their storage, so a caller reusing its buffers
      --  after this cannot change what a later Reconnect dials.
      Params : constant Connect_Params :=
        (URL          => To_Unbounded_String (URL),
         Extra        => Extra_Headers,
         Subprotocols => To_Unbounded_String (Subprotocols),
         Origin       => To_Unbounded_String (Origin),
         Insecure     => Insecure,
         CA_Path      => To_Unbounded_String (CA_Path));

      --  Declared BEFORE admission is asked for, so that there is no
      --  instant at which the client is Connecting and no object is
      --  responsible for taking it back out. It holds nothing until
      --  Begin_Connect records a generation into it, so a refused
      --  Connect still cannot release an admission it never took.
      Attempt : Attempt_Owner (Self.Ctl'Unchecked_Access);
   begin
      --  Admission. One protected action decides whether an attempt
      --  may start, reserves its generation number and takes the
      --  snapshot the session will be built from. Idle and
      --  Disconnected are admitted; Connecting, Open and Closing are
      --  not, so a live connection is never displaced by a bare
      --  Connect. A failed attempt returns the client to where
      --  admission found it, and that retry genuinely works because
      --  it builds a fresh session with fresh transports rather than
      --  re-dialing one whose single-use latch is already set.
      Self.Ctl.Begin_Connect
        (Params, Attempt.Gen'Unchecked_Access, Gen, Lim, Adm);
      case Adm is
         when Admitted =>
            null;
         when No_Callback =>
            raise AHT.Websocket.Mode_Error
              with "Websocket.Client.Connect: delivery is "
                & "Callback_Only but no On_Message callback is "
                & "installed; every message would be discarded";
         when Wrong_State =>
            raise AHT.Websocket.Handshake_Error
              with "Websocket.Client.Connect: refused in state "
                & Client_State'Image (Self.Ctl.State)
                & ". Connect dials only from Idle or Disconnected; a "
                & "live connection is never displaced silently — "
                & "Close it first, or use Reconnect, which drains it "
                & "and redials";
      end case;

      --  From here the attempt owns the session outright: nothing
      --  else can reach it, and its cleanup runs on every exit. The
      --  owner itself is declared further up, before admission — see
      --  the note there.
      declare
         Key_Bytes : AHT.Bytes.Byte_Array (1 .. 16);
         Req       : AHT.HTTP.Request.Request_Type;
         Resp      : AHT.HTTP.Response.Response_Type;

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

            --  One session, holding exactly the transport this scheme
            --  needs. Scheme is already narrowed to WS | WSS above.
            declare
               --  Callback_Only gets no queue at all rather than an
               --  unused one, so "does not enqueue" is a property of
               --  the allocation and not merely of the code path.
               Cap : constant Ada.Containers.Count_Type :=
                 (if Lim.Delivery = Callback_Only
                  then 0 else Lim.Max_Inbox_Messages);
            begin
               case Parsed.Scheme is
                  when AHT.URL.WSS =>
                     Attempt.Sess := new Session_Type
                       (Kind              => Secure_Transport,
                        Inbox_Capacity    => Cap,
                        Max_Message_Bytes => Lim.Max_Message_Bytes,
                        Max_Inbox_Bytes   => Lim.Max_Inbox_Bytes,
                        Delivery          => Lim.Delivery);
                  when others =>
                     --  WS (HTTP/HTTPS already rejected above).
                     Attempt.Sess := new Session_Type
                       (Kind              => Plain_Transport,
                        Inbox_Capacity    => Cap,
                        Max_Message_Bytes => Lim.Max_Message_Bytes,
                        Max_Inbox_Bytes   => Lim.Max_Inbox_Bytes,
                        Delivery          => Lim.Delivery);
               end case;
            end;
            Attempt.Sess.Generation := Positive (Gen);

            case Attempt.Sess.Kind is
               when Secure_Transport =>
                  AHT.Transport.TLS.Connect
                    (Attempt.Sess.Secure,
                     Host     => To_String (Parsed.Host),
                     Port     => Parsed.Port,
                     Insecure => Insecure,
                     CA_Path  => CA_Path);
               when Plain_Transport =>
                  AHT.Transport.TCP.Connect
                    (Attempt.Sess.Plain,
                     Host => To_String (Parsed.Host),
                     Port => Parsed.Port);
            end case;

            begin
               AHT.HTTP.Request.Write (Req, Active (Attempt.Sess).all);
               AHT.HTTP.Response.Read
                 (Resp, Active (Attempt.Sess).all,
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

                  Attempt.Sess.Selected_Protocol := To_Unbounded_String (Got);
               end;

               --  Handshake good — flip the connection's own state
               --  machine and hand the session to the receiver. The
               --  controller publishes it inside the rendezvous, so
               --  ownership transfer and visibility are one step.
               Attempt.Sess.State.Set (Open);
               --  'Unchecked_Access is safe by the same argument as
               --  Async_Handle: the Receiver task is itself a
               --  component of Self, so the parent master waits for
               --  the task before finalizing the other components
               --  (RM 9.3). The Client_Access never outlives Self.
               --
               --  Publish runs inside this rendezvous, so by the time
               --  Start returns the transfer is already recorded in
               --  the controller and Attempt's cleanup stands down.
               Self.Receiver.Start
                 (Owner => Self'Unchecked_Access,
                  Sess  => Attempt.Sess);
            exception
               when AHT.Websocket.Handshake_Error =>
                  --  The transport teardown, the free and the
                  --  admission release all happen in Attempt's
                  --  Finalize, so no exit path can skip them.
                  raise;
               when E : others =>
                  raise AHT.Websocket.Handshake_Error
                    with "Websocket.Client.Connect: "
                      & Ada.Exceptions.Exception_Name (E) & ": "
                      & Ada.Exceptions.Exception_Message (E);
            end;
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

   --  Called by every operation that would wait on the receiver.
   --  From anywhere else this is free; from a callback it is the
   --  difference between an exception and a deadlock, since the task
   --  being waited on is the one making the call.
   procedure Refuse_If_Receiver (Self : Client_Type; Op : String) is
   begin
      if Self.Ctl.Is_Receiver (Ada.Task_Identification.Current_Task) then
         raise AHT.Websocket.Reentrant_Error
           with "Websocket.Client." & Op & ": called from inside a "
             & "callback, which runs on the receiver task — it would "
             & "be waiting for itself. Send_* are safe here; anything "
             & "that waits is not";
      end if;
   end Refuse_If_Receiver;

   procedure Configure (Self : in out Client_Type; L : Limits) is
      OK : Boolean;
   begin
      Self.Ctl.Set_Pending_Limits (L, OK);
      if not OK then
         raise AHT.Websocket.Mode_Error
           with "Websocket.Client.Configure: limits can only be set "
             & "while fully disconnected (state = "
             & Client_State'Image (Self.Ctl.State)
             & "); a session freezes its ceilings when it is created";
      end if;
   end Configure;

   procedure Reconnect
     (Self          : in out Client_Type;
      Timeout       : Duration := 5.0;
      Drain_Timeout : Duration := Default_Drain_Timeout)
   is
      P  : Connect_Params;
      OK : Boolean;
   begin
      Refuse_If_Receiver (Self, "Reconnect");

      Self.Ctl.Saved_Params (P, OK);
      if not OK then
         raise AHT.Websocket.Handshake_Error
           with "Websocket.Client.Reconnect: this client has never "
             & "connected, so there is nothing to repeat; use Connect";
      end if;

      --  Drain whatever is in place first. Close is the whole of that
      --  step: it already picks a winner, lets everyone else join, and
      --  bounds both halves. With nothing in place it returns at once,
      --  which is exactly right for a redial from Disconnected.
      --
      --  If it raises, the redial does NOT happen. A teardown that has
      --  not finished still owns the session, and dialing a second one
      --  over it is the one thing this must never do.
      Close (Self, Timeout => Timeout, Drain_Timeout => Drain_Timeout);

      Connect
        (Self          => Self,
         URL           => To_String (P.URL),
         Extra_Headers => P.Extra,
         Subprotocols  => To_String (P.Subprotocols),
         Origin        => To_String (P.Origin),
         Insecure      => P.Insecure,
         CA_Path       => To_String (P.CA_Path));
   end Reconnect;

   function Is_Open (Self : Client_Type) return Boolean is
     (Self.Ctl.Is_Open);

   function Selected_Subprotocol (Self : Client_Type) return String is
     (Self.Ctl.Protocol);

   function Generation (Self : Client_Type) return Natural is
     (Self.Ctl.Generation);

   procedure Send_Text
     (Self : in out Client_Type;
      Text : String)
   is
      L : Lease (Self.Ctl'Unchecked_Access);
   begin
      if not L.Held then
         raise AHT.Websocket.Closed_Error with
           "Send_Text: connection is not open";
      end if;
      declare
         Token : Guards.Guard_Token (L.Sess.Guard'Unchecked_Access);
      begin
         Token.Take;
         --  Re-check under the guard, not just at borrow time.
         --  We may have queued here for a long time behind
         --  another writer, and teardown may have started --
         --  and fired its one-shot Abort_Pending -- while we
         --  waited. Starting a write now would park with
         --  nothing left to cancel it, and the reclaimer would
         --  wait on our borrow forever. This is the sender-side
         --  form of the rule the receiver echo paths follow.
         --  Close_Frame_Sent alone does not cover it: a
         --  peer-initiated teardown never latches it.
         if not L.Ctl.Is_Open
           or else L.Sess.Guard.Close_Frame_Sent
         then
            raise AHT.Websocket.Closed_Error with
              "Send_Text: connection is not open";
         end if;
         Send_Frame
           (Active (L.Sess).all,
            Op      => AHT.Websocket.Text,
            FIN     => True,
            Payload => AHT.Bytes.From_String (Text));
      end;
   end Send_Text;

   procedure Send_Binary
     (Self : in out Client_Type;
      Data : AHT.Bytes.Byte_Array)
   is
      L : Lease (Self.Ctl'Unchecked_Access);
   begin
      if not L.Held then
         raise AHT.Websocket.Closed_Error with
           "Send_Binary: connection is not open";
      end if;
      declare
         Token : Guards.Guard_Token (L.Sess.Guard'Unchecked_Access);
      begin
         Token.Take;
         --  Re-check under the guard, not just at borrow time.
         --  We may have queued here for a long time behind
         --  another writer, and teardown may have started --
         --  and fired its one-shot Abort_Pending -- while we
         --  waited. Starting a write now would park with
         --  nothing left to cancel it, and the reclaimer would
         --  wait on our borrow forever. This is the sender-side
         --  form of the rule the receiver echo paths follow.
         --  Close_Frame_Sent alone does not cover it: a
         --  peer-initiated teardown never latches it.
         if not L.Ctl.Is_Open
           or else L.Sess.Guard.Close_Frame_Sent
         then
            raise AHT.Websocket.Closed_Error with
              "Send_Binary: connection is not open";
         end if;
         Send_Frame
           (Active (L.Sess).all,
            Op      => AHT.Websocket.Binary,
            FIN     => True,
            Payload => Data);
      end;
   end Send_Binary;

   procedure Send_Ping
     (Self    : in out Client_Type;
      Payload : AHT.Bytes.Byte_Array := [])
   is
      L : Lease (Self.Ctl'Unchecked_Access);
   begin
      if not L.Held then
         raise AHT.Websocket.Closed_Error with
           "Send_Ping: connection is not open";
      end if;
      declare
         Token : Guards.Guard_Token (L.Sess.Guard'Unchecked_Access);
      begin
         Token.Take;
         --  Re-check under the guard, not just at borrow time.
         --  We may have queued here for a long time behind
         --  another writer, and teardown may have started --
         --  and fired its one-shot Abort_Pending -- while we
         --  waited. Starting a write now would park with
         --  nothing left to cancel it, and the reclaimer would
         --  wait on our borrow forever. This is the sender-side
         --  form of the rule the receiver echo paths follow.
         --  Close_Frame_Sent alone does not cover it: a
         --  peer-initiated teardown never latches it.
         if not L.Ctl.Is_Open
           or else L.Sess.Guard.Close_Frame_Sent
         then
            raise AHT.Websocket.Closed_Error with
              "Send_Ping: connection is not open";
         end if;
         Send_Frame
           (Active (L.Sess).all,
            Op      => AHT.Websocket.Ping_Op,
            FIN     => True,
            Payload => Payload);
      end;
   end Send_Ping;

   procedure Close
     (Self          : in out Client_Type;
      Code          : AHT.Websocket.Valid_Close_Code := 1000;
      Reason        : String := "";
      Timeout       : Duration := 5.0;
      Drain_Timeout : Duration := Default_Drain_Timeout)
   is
      --  Runs only for the caller that won the teardown, on the
      --  session its borrow pins, so S cannot be freed under it.
      --  Everything here is best effort -- the borrow has to come
      --  back whatever happens, or the receiver never reclaims.
      procedure Close_Handshake (S : Session_Access) is
         Should_Send    : Boolean;
         Already_Closed : Boolean;

         Phase_Start : constant Ada.Real_Time.Time := Ada.Real_Time.Clock;

         --  Timeout is a budget for the whole handshake, not an
         --  allowance renewed per phase. Both phases are "waiting for
         --  somebody else" -- another writer to put the latch down,
         --  then the peer to echo -- and a caller that asked for T
         --  must not be able to spend 2T because the first phase
         --  nearly exhausted it and the second started afresh.
         --
         --  Computed by subtracting elapsed rather than from an
         --  absolute deadline, so Duration'Last stays usable: adding
         --  it to a clock reading would overflow, while subtracting a
         --  small elapsed span from it does not.
         function Remaining return Duration is
            use type Ada.Real_Time.Time;
            Spent : constant Duration :=
              Ada.Real_Time.To_Duration
                (Ada.Real_Time.Clock - Phase_Start);
         begin
            return AHT.Websocket.Budgets.Remaining (Timeout, Spent);
         end Remaining;
      begin
         --  RFC 6455 §1.4 close: send our Close (if we haven't yet),
         --  then wait for the receiver to see the peer's echo.
         --  Abort_Pending guarantees Wait_Closed doesn't hang forever
         --  if the peer goes silent.
         S.State.Try_Mark_Local_Close (Should_Send);
         if Should_Send then
            declare
               Token : Guards.Guard_Token (S.Guard'Unchecked_Access);
               Got   : Boolean;
            begin
               --  Bounded, because this is reached BEFORE the timed
               --  wait below. Taking the latch unconditionally would
               --  let a writer parked in the transport outwait
               --  Timeout without Timeout ever being consulted --
               --  WebSocket writes carry no deadline of their own, so
               --  a peer that stops reading is enough to arrange it.
               Token.Try_Take (Remaining, Got);

               if Got then
                  --  The write needs bounding too, or the budget only
                  --  ever bounded the WAITING. A writer that completes
                  --  while leaving the socket buffer full puts the
                  --  latch down on a healthy transport, and this write
                  --  would then park with neither Remaining nor
                  --  Drain_Timeout able to reach it, since both are
                  --  already behind us.
                  --
                  --  See AHT.Websocket.Budgets for why a budget of
                  --  exactly zero is the only one that gets a grace,
                  --  and why every positive one gets what is left of
                  --  it and no more.
                  begin
                     Active (S).Set_Write_Deadline
                       (AHT.Websocket.Budgets.Close_Frame_Budget
                          (Timeout, Remaining));
                  exception
                     when others => null;
                  end;

                  begin
                     Send_Frame
                       (Active (S).all,
                        Op      => AHT.Websocket.Close_Op,
                        FIN     => True,
                        Payload => Build_Close_Payload (Code, Reason));
                  exception
                     when others =>
                        --  Best effort. Continue with the local
                        --  teardown regardless.
                        null;
                  end;

                  --  Put it back: reclamation still has a transport
                  --  Close to do, and it should not inherit a
                  --  deadline that belonged to this frame.
                  begin
                     Active (S).Set_Write_Deadline (Duration'Last);
                  exception
                     when others => null;
                  end;
                  --  Latch under the guard: a Send_* blocked on
                  --  Acquire will now observe Close_Frame_Sent and
                  --  raise rather than writing a data frame after our
                  --  Close.
                  S.Guard.Mark_Close_Sent;
               else
                  --  Somebody else is mid-write and stuck. Cancel
                  --  their I/O so the teardown can proceed, and send
                  --  no Close at all: a writer interrupted part-way
                  --  has left a partial frame on the wire, and
                  --  RFC 6455 §5.5.1 admits nothing after a Close --
                  --  including the rest of the frame it would be
                  --  following. A truncated stream with no Close is
                  --  the honest signal here.
                  begin
                     Active (S).Abort_Pending;
                  exception
                     when others => null;
                  end;
               end if;
            end;
         end if;

         --  Move to Closing, but never clobber a Closed the receiver
         --  may have published while we were sending our Close frame
         --  (the peer can EOF or echo Close mid-handshake). If that
         --  already happened, Wait_Closed is open and there is nothing
         --  left to wait for.
         S.State.Begin_Closing (Already_Closed);
         if not Already_Closed then
            select
               S.State.Wait_Closed;
            or
               delay Remaining;
               --  The bound fired; kick the receiver out now rather
               --  than waiting for the pin's Finalize to do it, so a
               --  silent peer costs exactly Timeout.
               begin
                  Active (S).Abort_Pending;
               exception
                  when others => null;
               end;
            end select;
         end if;
      exception
         when others =>
            --  Best effort, and safe to swallow precisely because the
            --  wake gates are NOT here: they run from the pin's
            --  Finalize, which no exit path can skip.
            null;
      end Close_Handshake;

   begin
      Refuse_If_Receiver (Self, "Close");

      --  The pin takes the teardown borrow on declaration and gives it
      --  back on scope exit, so no exit -- not a raise, not an abort of
      --  this task mid-handshake -- can leave the borrow count above
      --  zero with the receiver waiting on it.
      declare
         Pin : Teardown_Pin (Self.Ctl'Unchecked_Access);
      begin
         case Pin.Result is
            when No_Session =>
               --  Never connected, or the receiver already finished
               --  reclaiming -- including closing the transport.
               return;

            when Join_Teardown =>
               --  Someone else is driving it, possibly already past the
               --  point where the session may be touched. Fall through
               --  to the shared wait without touching anything.
               null;

            when Won_Teardown =>
               Close_Handshake (Pin.Sess);
         end case;
      end;
      --  Out of the pin's scope, so the borrow is back and the
      --  receiver's drain can pass. Waiting inside it would deadlock
      --  the two against each other.

      --  Synchronous with respect to receiver exit and callbacks: the
      --  transport is closed and the session freed by the time this
      --  returns normally. Bounded, and the joiner path above lands
      --  here too, so joining a stalled teardown reports rather than
      --  blocks.
      select
         Self.Ctl.Wait_Generation_Done;
      or
         delay Drain_Timeout;
         --  Nothing is abandoned here and nothing leaks. The receiver
         --  still owns the session and is still reclaiming it; what
         --  has run out is this caller's patience, and a later Close
         --  or Reconnect joins the very same completion. The usual
         --  cause is a callback that has not returned, which no
         --  receiver-side mechanism can detect -- Abort_Pending
         --  cancels transport I/O, not user code.
         raise AHT.Transport.Timeout_Error
           with "Websocket.Client.Close: the connection was not "
             & "reclaimed within" & Duration'Image (Drain_Timeout)
             & "s; teardown continues in the background (is a "
             & "callback still running?)";
      end select;
   end Close;

   procedure Receive
     (Self    : in out Client_Type;
      Msg     : out Message_Type;
      Timeout : Duration := Duration'Last)
   is
      L : Lease (Self.Ctl'Unchecked_Access);
   begin
      Refuse_If_Receiver (Self, "Receive");

      if not L.Held then
         Msg := (Kind => Binary_Message, Payload => <>);
         raise AHT.Websocket.Closed_Error
           with "Websocket.Client.Receive: connection closed";
      end if;

      if L.Sess.Delivery = Callback_Only then
         --  Nothing is ever enqueued in this mode, so blocking here
         --  would wait on an inbox no one will fill.
         Msg := (Kind => Binary_Message, Payload => <>);
         raise AHT.Websocket.Mode_Error
           with "Websocket.Client.Receive: delivery is Callback_Only; "
             & "messages are delivered to On_Message, not queued";
      end if;
      --  Blocked on THIS session's inbox: when it is reclaimed,
      --  Mark_Closed wakes us with Closed_Error, and we can never
      --  observe a later generation's messages.
      select
         L.Sess.Inbox.Receive (Msg);
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
      CB   : On_Message_Callback)
   is
      OK : Boolean;
   begin
      Self.Ctl.Set_On_Message (CB, OK);
      if not OK then
         raise AHT.Websocket.Mode_Error
           with "Websocket.Client.Set_On_Message: cannot clear the "
             & "callback while a Callback_Only connection is in "
             & "force; it is that connection's only consumer";
      end if;
   end Set_On_Message;

   procedure Set_On_Close
     (Self : in out Client_Type;
      CB   : On_Close_Callback) is
   begin
      Self.Ctl.Set_On_Close (CB);
   end Set_On_Close;

   procedure Set_On_Error
     (Self : in out Client_Type;
      CB   : On_Error_Callback) is
   begin
      Self.Ctl.Set_On_Error (CB);
   end Set_On_Error;

end AHT.Websocket.Client;
