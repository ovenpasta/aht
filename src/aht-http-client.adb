--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;

with AHT.HTTP.Methods;
with AHT.Transport.TCP;
with AHT.Transport.TLS;
with AHT.URL;

package body AHT.HTTP.Client is

   use type AHT.Transport.Transport_Access;

   function Seconds (S : Duration) return Phase_Bound is
     ((Inherited => False, Limit => S));

   --  Collapse one phase's field to the Duration the transport
   --  layer wants: the field's own limit, or Timeout_Seconds when
   --  the field was left at Inherit. Duration'Last is "no bound"
   --  either way, which is what both Connect and the deadline
   --  setters already take it to mean.
   function Resolve_Bound
     (Self : Client_Type; B : Phase_Bound) return Duration is
     (if not B.Inherited then B.Limit
      elsif Self.Timeout_Seconds > 0 then Duration (Self.Timeout_Seconds)
      else Duration'Last);

   --  "host" or "host:port": the port is emitted only when it differs
   --  from the URL scheme's default, matching how browsers and curl
   --  format the Host header.
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

   --  Merges Self.Default_Headers and the auto-set Host / User-Agent
   --  / Connection onto Working: request beats defaults, defaults
   --  beat auto. A default name absent from Req.Headers is copied
   --  with all its values; Host, User-Agent and Connection are set
   --  only if still absent, so a request's Connection: Upgrade is
   --  preserved.
   procedure Merge_Headers
     (Self    : Client_Type;
      Req     : AHT.HTTP.Request.Request_Type;
      Working : in out AHT.HTTP.Request.Request_Type)
   is
      procedure Add_If_Req_Absent (Name, Value : String) is
      begin
         if not Req.Headers.Contains (Name) then
            Working.Headers.Append (Name, Value);
         end if;
      end Add_If_Req_Absent;
   begin
      Self.Default_Headers.Iterate (Add_If_Req_Absent'Access);

      if not Working.Headers.Contains ("host") then
         Working.Headers.Set ("host", Host_Header (Req.Target));
      end if;
      if not Working.Headers.Contains ("user-agent") then
         Working.Headers.Set ("user-agent", To_String (Self.User_Agent));
      end if;
      if not Working.Headers.Contains ("connection") then
         Working.Headers.Set ("connection", "close");
      end if;
   end Merge_Headers;

   --  Round trip on a connected transport: write the request, then
   --  loop over Response.Read_Streaming until the status is not 1xx.
   --  101 is terminal, leaving post-header bytes buffered for the
   --  next layer. Source, when non-null, streams the request body via
   --  Write_Streaming with Cancel as the between-window abort check.
   procedure Wire_Round_Trip
     (Self    : Client_Type;
      Working : AHT.HTTP.Request.Request_Type;
      Method  : AHT.HTTP.Methods.Method_Type;
      T       : in out AHT.Transport.Transport_Type'Class;
      Resp    : out AHT.HTTP.Response.Response_Type;
      Sink    : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array);
      Source  : access AHT.HTTP.Request.Body_Source'Class := null;
      Cancel  : access Cancel_State := null)
   is
      function Aborted return Boolean is
        (Cancel /= null and then Cancel.Was_Cancelled);
   begin
      if Source /= null then
         --  Streaming upload only: a parked Write raises
         --  Timeout_Error instead of hanging. The deadline bites only
         --  inside Transport.Write; a blocked Read_Chunk is the
         --  caller's. A buffered body drains in one shot and arms
         --  none.
         declare
            Bound : constant Duration :=
              Resolve_Bound (Self, Self.Write_Deadline);
         begin
            if Bound /= Duration'Last then
               T.Set_Write_Deadline (Bound);
            end if;
         end;
         AHT.HTTP.Request.Write_Streaming
           (Working, T, Source.all, Aborted'Access);
      else
         AHT.HTTP.Request.Write (Working, T);
      end if;

      --  Arm the read deadline only *after* the body is fully on the
      --  wire. Set_Read_Deadline is a compound budget measured from when
      --  it is armed, so arming it up front would let a slow/large upload
      --  burn the response-read budget and surface a spurious
      --  Timeout_Error the instant the upload completes.
      declare
         Bound : constant Duration :=
           Resolve_Bound (Self, Self.Read_Deadline);
      begin
         if Bound /= Duration'Last then
            T.Set_Read_Deadline (Bound);
         end if;
      end;

      loop
         AHT.HTTP.Response.Read_Streaming
           (Resp, T, Sink => Sink, Method => Method);
         exit when Resp.Status not in 100 .. 199
           or else Resp.Status = 101;
      end loop;
   end Wire_Round_Trip;

   --  Single core for every Send overload. Sink receives body chunks;
   --  the buffered overloads pass one that appends to Resp.Body_B.
   --  Source, when non-null, streams the request body; otherwise
   --  Req.Body_B is written. Cancel, when non-null, is bound to the
   --  live transport so a concurrent Cancel can Abort_Pending it,
   --  and a pre-cancelled handle does not dial.
   procedure Run_Request
     (Self   : Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Sink   : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array);
      Cancel : access Cancel_State;
      Source : access AHT.HTTP.Request.Body_Source'Class := null)
   is
      Working : AHT.HTTP.Request.Request_Type := Req;

      --  One resolved bound per dial phase. Each is the matching
      --  Client_Type field, or Timeout_Seconds where that field was
      --  left at Inherit -- so these are independent budgets, not
      --  slices of a shared one, and a request's wall clock can run
      --  to their sum. The write and read deadlines resolve the same
      --  way inside Wire_Round_Trip, where they are armed.
      Resolve_B   : constant Duration :=
        Resolve_Bound (Self, Self.Resolve_Timeout);
      Connect_B   : constant Duration :=
        Resolve_Bound (Self, Self.Connect_Timeout);
      Handshake_B : constant Duration :=
        Resolve_Bound (Self, Self.Handshake_Deadline);
   begin
      Merge_Headers (Self, Req, Working);

      if Cancel /= null and then Cancel.Was_Cancelled then
         raise AHT.Transport.Aborted_Error
           with "HTTP.Client.Send: Cancel_Handle was triggered "
             & "before the request started";
      end if;

      case Req.Target.Scheme is
         when AHT.URL.HTTP =>
            declare
               T : aliased AHT.Transport.TCP.TCP_Transport;
            begin
               AHT.Transport.TCP.Connect
                 (T,
                  Host            => To_String (Req.Target.Host),
                  Port            => Req.Target.Port,
                  Connect_Timeout => Connect_B,
                  Resolve_Timeout => Resolve_B);

               --  Race window: Cancel could fire between Connect
               --  returning and Bind running. Bind itself re-checks
               --  Cancelled under the protected lock and triggers
               --  Abort_Pending on the freshly bound transport, so a
               --  Cancel landing here still takes effect on the next
               --  Read.
               if Cancel /= null then
                  Cancel.Bind (T'Unchecked_Access);
               end if;

               begin
                  Wire_Round_Trip
                    (Self, Working, Req.Method, T, Resp, Sink,
                     Source, Cancel);
               exception
                  when others =>
                     if Cancel /= null then
                        Cancel.Unbind;
                     end if;
                     T.Close;
                     raise;
               end;

               if Cancel /= null then
                  Cancel.Unbind;
               end if;
               T.Close;
            end;

         when AHT.URL.HTTPS =>
            declare
               T : aliased AHT.Transport.TLS.TLS_Transport;
            begin
               AHT.Transport.TLS.Connect
                 (T,
                  Host               => To_String (Req.Target.Host),
                  Port               => Req.Target.Port,
                  Insecure           => Self.Insecure,
                  CA_Path            => To_String (Self.CA_Path),
                  Connect_Timeout    => Connect_B,
                  Handshake_Deadline => Handshake_B,
                  Resolve_Timeout    => Resolve_B,
                  CA_PEM             => To_String (Self.CA_PEM));

               --  Same Cancel bind/unbind discipline as the HTTP
               --  branch: Bind re-checks Cancelled under the lock and
               --  fires Abort_Pending on the freshly-bound TLS
               --  transport, which forwards to the underlying TCP.
               if Cancel /= null then
                  Cancel.Bind (T'Unchecked_Access);
               end if;

               begin
                  Wire_Round_Trip
                    (Self, Working, Req.Method, T, Resp, Sink,
                     Source, Cancel);
               exception
                  when others =>
                     if Cancel /= null then
                        Cancel.Unbind;
                     end if;
                     T.Close;
                     raise;
               end;

               if Cancel /= null then
                  Cancel.Unbind;
               end if;
               T.Close;
            end;

         when AHT.URL.WS | AHT.URL.WSS =>
            raise HTTP_Error
              with "ws/wss URL passed to HTTP.Client.Send; "
                & "use AHT.Websocket.Client for WebSocket connections";
      end case;
   end Run_Request;

   procedure Send
     (Self : in out Client_Type;
      Req  : AHT.HTTP.Request.Request_Type;
      Resp : out AHT.HTTP.Response.Response_Type)
   is
      --  Body sink that appends every delivered chunk to Resp.Body_B.
      --  Read_Streaming clears Self before any sink call (via its
      --  inner Parse_Head), so this builds up a fresh body.
      procedure Append_To_Body (Chunk : AHT.Bytes.Byte_Array) is
      begin
         Resp.Body_B.Append (Chunk);
      end Append_To_Body;
   begin
      Run_Request (Self, Req, Resp,
                   Sink   => Append_To_Body'Access,
                   Cancel => null);
   end Send;

   procedure Send
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Cancel : in out Cancel_Handle)
   is
      procedure Append_To_Body (Chunk : AHT.Bytes.Byte_Array) is
      begin
         Resp.Body_B.Append (Chunk);
      end Append_To_Body;
   begin
      Run_Request (Self, Req, Resp,
                   Sink   => Append_To_Body'Access,
                   Cancel => Cancel.State'Access);
   end Send;

   procedure Send_Streaming
     (Self : in out Client_Type;
      Req  : AHT.HTTP.Request.Request_Type;
      Resp : out AHT.HTTP.Response.Response_Type;
      Sink : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array)) is
   begin
      Run_Request (Self, Req, Resp, Sink => Sink, Cancel => null);
   end Send_Streaming;

   procedure Send_Streaming
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Sink   : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array);
      Cancel : in out Cancel_Handle) is
   begin
      Run_Request (Self, Req, Resp,
                   Sink   => Sink,
                   Cancel => Cancel.State'Access);
   end Send_Streaming;

   --  Body sink that writes every delivered chunk straight to an Ada
   --  stream. Block-copies Byte_Array -> Stream_Element_Array (the
   --  download mirror of Stream_Source.Read_Chunk's copy;
   --  Stream_Element'Size = Octet'Size = 8 on every supported target),
   --  then dispatches to the stream's Write. A raising Write propagates
   --  out through Run_Request, which closes the transport.
   procedure Send_Streaming
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Target : not null access Ada.Streams.Root_Stream_Type'Class)
   is
      procedure Write_To_Stream (Chunk : AHT.Bytes.Byte_Array) is
         use type Ada.Streams.Stream_Element_Offset;
         SE : Ada.Streams.Stream_Element_Array
                (0 .. Ada.Streams.Stream_Element_Offset (Chunk'Length) - 1);
      begin
         for I in 0 .. Chunk'Length - 1 loop
            SE (Ada.Streams.Stream_Element_Offset (I)) :=
              Ada.Streams.Stream_Element (Chunk (Chunk'First + I));
         end loop;
         Target.Write (SE);
      end Write_To_Stream;
   begin
      Run_Request (Self, Req, Resp,
                   Sink   => Write_To_Stream'Access,
                   Cancel => null);
   end Send_Streaming;

   procedure Send_Streaming
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Target : not null access Ada.Streams.Root_Stream_Type'Class;
      Cancel : in out Cancel_Handle)
   is
      procedure Write_To_Stream (Chunk : AHT.Bytes.Byte_Array) is
         use type Ada.Streams.Stream_Element_Offset;
         SE : Ada.Streams.Stream_Element_Array
                (0 .. Ada.Streams.Stream_Element_Offset (Chunk'Length) - 1);
      begin
         for I in 0 .. Chunk'Length - 1 loop
            SE (Ada.Streams.Stream_Element_Offset (I)) :=
              Ada.Streams.Stream_Element (Chunk (Chunk'First + I));
         end loop;
         Target.Write (SE);
      end Write_To_Stream;
   begin
      Run_Request (Self, Req, Resp,
                   Sink   => Write_To_Stream'Access,
                   Cancel => Cancel.State'Access);
   end Send_Streaming;

   procedure Send_Streaming_Body
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Source : in out AHT.HTTP.Request.Body_Source'Class)
   is
      procedure Append_To_Body (Chunk : AHT.Bytes.Byte_Array) is
      begin
         Resp.Body_B.Append (Chunk);
      end Append_To_Body;
   begin
      Run_Request (Self, Req, Resp,
                   Sink   => Append_To_Body'Access,
                   Cancel => null,
                   Source => Source'Access);
   end Send_Streaming_Body;

   procedure Send_Streaming_Body
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Source : in out AHT.HTTP.Request.Body_Source'Class;
      Cancel : in out Cancel_Handle)
   is
      procedure Append_To_Body (Chunk : AHT.Bytes.Byte_Array) is
      begin
         Resp.Body_B.Append (Chunk);
      end Append_To_Body;
   begin
      Run_Request (Self, Req, Resp,
                   Sink   => Append_To_Body'Access,
                   Cancel => Cancel.State'Access,
                   Source => Source'Access);
   end Send_Streaming_Body;

   function Get
     (Self : in out Client_Type;
      URL  : String) return AHT.HTTP.Response.Response_Type
   is
      Req  : AHT.HTTP.Request.Request_Type;
      Resp : AHT.HTTP.Response.Response_Type;
   begin
      Req.Method := AHT.HTTP.Methods.GET;
      Req.Target := AHT.URL.Parse (URL);
      Send (Self, Req, Resp);
      return Resp;
   end Get;

   procedure Cancel (Self : in out Cancel_Handle) is
   begin
      Self.State.Cancel_Internal;
   end Cancel;

   function Is_Cancelled (Self : Cancel_Handle) return Boolean is
     (Self.State.Was_Cancelled);

   protected body Cancel_State is

      procedure Cancel_Internal is
      begin
         Cancelled := True;
         if Bound /= null then
            --  Dispatching call into the bound transport's
            --  Abort_Pending. Idempotent on the transport side; safe
            --  if called multiple times.
            Bound.Abort_Pending;
         end if;
      end Cancel_Internal;

      procedure Bind (T : AHT.Transport.Transport_Access) is
      begin
         Bound := T;
         --  If Cancel landed before Bind (between Connect and here),
         --  fire Abort_Pending now so the very first Read on this
         --  transport raises Aborted_Error instead of blocking.
         if Cancelled and then T /= null then
            T.Abort_Pending;
         end if;
      end Bind;

      procedure Unbind is
      begin
         Bound := null;
      end Unbind;

      procedure Mark_Done_OK
        (R : AHT.HTTP.Response.Response_Type) is
      begin
         Result_Resp := R;
         Result_OK   := True;
         Done_Flag   := True;
      end Mark_Done_OK;

      procedure Mark_Done_Err
        (E : Ada.Exceptions.Exception_Occurrence) is
      begin
         Ada.Exceptions.Save_Occurrence (Result_Caught, E);
         Result_OK := False;
         Done_Flag := True;
      end Mark_Done_Err;

      entry Wait_Until_Done when Done_Flag is
      begin
         null;
         --  Caller wakes when the worker has stored a result.
         --  Multiple callers all proceed because the barrier
         --  stays open once Done_Flag is True.
      end Wait_Until_Done;

      procedure Read_Result
        (Out_Resp   : out AHT.HTTP.Response.Response_Type;
         Out_OK     : out Boolean;
         Out_Caught : out Ada.Exceptions.Exception_Occurrence) is
      begin
         Out_Resp := Result_Resp;
         Out_OK   := Result_OK;
         Ada.Exceptions.Save_Occurrence (Out_Caught, Result_Caught);
      end Read_Result;

      function Was_Cancelled return Boolean is (Cancelled);

      function Is_Done_Flag return Boolean is (Done_Flag);

   end Cancel_State;

   ---------------------------------------------------------------------
   --  Async
   ---------------------------------------------------------------------

   task body Worker_Task is
      Client_Snap : Client_Type;
      Req_Snap    : AHT.HTTP.Request.Request_Type;
      State       : Cancel_State_Access := null;
      Resp        : AHT.HTTP.Response.Response_Type;

      procedure Append_To_Resp (Chunk : AHT.Bytes.Byte_Array) is
      begin
         Resp.Body_B.Append (Chunk);
      end Append_To_Resp;
   begin
      --  Wait for Send_Async to fire Start. If the handle goes out
      --  of scope without ever calling Send_Async, the terminate
      --  alternative fires when the master finalizes us and we
      --  collapse cleanly.
      select
         accept Start
           (Client_Snapshot  : Client_Type;
            Request_Snapshot : AHT.HTTP.Request.Request_Type;
            State_Ref        : Cancel_State_Access)
         do
            Client_Snap := Client_Snapshot;
            Req_Snap    := Request_Snapshot;
            State       := State_Ref;
         end Start;
      or
         terminate;
      end select;

      --  Run the request, stash the result in the shared state,
      --  and terminate. Await reads from the protected state, so
      --  there is no second rendezvous; multiple Awaits and "drop
      --  without Await" both work.
      begin
         Run_Request (Client_Snap, Req_Snap, Resp,
                      Sink   => Append_To_Resp'Access,
                      Cancel => State);
         if State /= null then
            State.Mark_Done_OK (Resp);
         end if;
      exception
         when E : others =>
            if State /= null then
               State.Mark_Done_Err (E);
            end if;
      end;
   end Worker_Task;

   procedure Send_Async
     (Self  : in out Client_Type;
      Req   : AHT.HTTP.Request.Request_Type;
      Async : in out Async_Handle) is
   begin
      if Async.Started then
         raise HTTP_Error
           with "HTTP.Client.Send_Async: Async_Handle already "
             & "started; declare a fresh handle per request";
      end if;
      Async.Started := True;
      --  'Unchecked_Access bypasses the static accessibility check
      --  because the named Cancel_State_Access type has library-level
      --  accessibility but Async.State is on the caller's stack. The
      --  check guards against the access outliving the designated
      --  object, which cannot happen here: the only holder of
      --  State_Ref is Async.Worker, itself a component of
      --  Async_Handle, finalized together with Async.State when the
      --  handle goes out of scope (the master waits for the task
      --  before component finalization, RM 9.3).
      Async.Worker.Start
        (Client_Snapshot  => Self,
         Request_Snapshot => Req,
         State_Ref        => Async.State'Unchecked_Access);
   end Send_Async;

   procedure Await
     (Self : in out Async_Handle;
      Resp : out AHT.HTTP.Response.Response_Type)
   is
      OK         : Boolean;
      Caught_Exn : Ada.Exceptions.Exception_Occurrence;
   begin
      --  Reject a never-started handle: the worker is parked at
      --  its Start rendezvous and Wait_Until_Done would block
      --  forever (Done_Flag stays False until Run_Request runs).
      if not Self.Started then
         raise HTTP_Error
           with "HTTP.Client.Await: Async_Handle has not been "
             & "Send_Async'd";
      end if;

      Self.State.Wait_Until_Done;
      Self.State.Read_Result (Resp, OK, Caught_Exn);
      if not OK then
         Ada.Exceptions.Reraise_Occurrence (Caught_Exn);
      end if;
   end Await;

   procedure Cancel (Self : in out Async_Handle) is
   begin
      Self.State.Cancel_Internal;
   end Cancel;

   function Is_Done (Self : Async_Handle) return Boolean is
     (Self.State.Is_Done_Flag);

   function Is_Cancelled (Self : Async_Handle) return Boolean is
     (Self.State.Was_Cancelled);

end AHT.HTTP.Client;
