--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Characters.Handling;
with Ada.Finalization;
with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;

with GNAT.SHA256;

with AHT.HTTP.Methods;
with AHT.Transport.TCP;
with AHT.Transport.TLS;

package body AHT.HTTP.Client is

   use type AHT.Transport.Transport_Access;
   use type AHT.HTTP.Methods.Method_Type;
   use type AHT.URL.Scheme_Kind;

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

   function Lower (S : String) return String
     renames Ada.Characters.Handling.To_Lower;

   --  True when some value of header Name lists Token among its
   --  comma-separated elements (case-insensitive).
   function Lists_Token
     (H : AHT.HTTP.Headers.Map; Name, Token : String) return Boolean is
   begin
      for V of H.Values (Name) loop
         declare
            L     : constant String := Lower (V);
            First : Positive := L'First;
         begin
            loop
               declare
                  Comma : constant Natural :=
                    Ada.Strings.Fixed.Index (L (First .. L'Last), ",");
                  Stop  : constant Natural :=
                    (if Comma = 0 then L'Last else Comma - 1);
               begin
                  if Ada.Strings.Fixed.Trim
                       (L (First .. Stop), Ada.Strings.Both) = Token
                  then
                     return True;
                  end if;
                  exit when Comma = 0;
                  First := Comma + 1;
               end;
            end loop;
         end;
      end loop;
      return False;
   end Lists_Token;

   function Same_Origin (A, B : AHT.URL.URL_Type) return Boolean is
     (A.Scheme = B.Scheme
      and then Lower (To_String (A.Host)) = Lower (To_String (B.Host))
      and then A.Port = B.Port);

   --  Merges Self.Default_Headers and the auto-set headers onto
   --  Working: request beats defaults, defaults beat auto. A default
   --  name absent from Req.Headers is copied with all its values;
   --  Host, User-Agent, Connection and (when decoding)
   --  Accept-Encoding are set only if still absent, so a request's
   --  Connection: Upgrade is preserved. Strip_Credentials then
   --  removes what must not follow a redirect to another origin,
   --  whichever source set it.
   procedure Merge_Headers
     (Self              : Client_Type;
      Req               : AHT.HTTP.Request.Request_Type;
      Working           : in out AHT.HTTP.Request.Request_Type;
      Strip_Credentials : Boolean)
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
         Working.Headers.Set
           ("connection",
            (if AHT.HTTP.Connection_Pools.Is_Null (Self.Pool)
             then "close" else "keep-alive"));
      end if;
      if Self.Max_Decoded_Bytes not in AHT.HTTP.Response.No_Decoding
        and then not Working.Headers.Contains ("accept-encoding")
      then
         Working.Headers.Set ("accept-encoding", "gzip, deflate");
      end if;

      if Strip_Credentials then
         Working.Headers.Remove ("authorization");
         Working.Headers.Remove ("proxy-authorization");
         Working.Headers.Remove ("cookie");
      end if;
   end Merge_Headers;

   --  Round trip on a connected transport: write the request, then
   --  loop over Response.Read_Streaming until the status is not 1xx.
   --  101 is terminal, leaving post-header bytes buffered for the
   --  next layer. Source, when non-null, streams the request body via
   --  Write_Streaming with Cancel as the between-window abort check.
   --  Persistent is the final response's.
   procedure Wire_Round_Trip
     (Self       : Client_Type;
      Working    : AHT.HTTP.Request.Request_Type;
      Method     : AHT.HTTP.Methods.Method_Type;
      T          : in out AHT.Transport.Transport_Type'Class;
      Resp       : out AHT.HTTP.Response.Response_Type;
      Sink       : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array);
      Source     : access AHT.HTTP.Request.Body_Source'Class;
      Cancel     : access Cancel_State;
      Persistent : out Boolean;
      Head_Read  : access Boolean)
   is
      function Aborted return Boolean is
        (Cancel /= null and then Cancel.Was_Cancelled);
   begin
      --  A pooled transport carries the previous exchange's deadlines;
      --  start from none. Duration'Last clears.
      T.Set_Read_Deadline (Duration'Last);
      T.Set_Write_Deadline (Duration'Last);

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
           (Resp, T, Sink,
            Method     => Method,
            Max_Decoded => Self.Max_Decoded_Bytes,
            Persistent  => Persistent,
            Head_Read   => Head_Read);
         exit when Resp.Status not in 100 .. 199
           or else Resp.Status = 101;
      end loop;
   end Wire_Round_Trip;

   --  Unbinds a Cancel_State when it goes out of scope, so that every
   --  way out of Exchange, an abort included, leaves the state bound
   --  to nothing: the transport it pointed at is about to be closed
   --  or freed, and a later Cancel must not reach it.
   type Binding is new Ada.Finalization.Limited_Controlled with record
      State : Cancel_State_Access;
   end record;

   overriding procedure Finalize (Self : in out Binding) is
   begin
      if Self.State /= null then
         Self.State.Unbind;
         Self.State := null;
      end if;
   end Finalize;

   procedure Arm (Self : in out Binding; State : Cancel_State_Access) is
   begin
      Self.State := State;
   end Arm;

   --  Wire_Round_Trip with T bound to Cancel for its duration. A
   --  Cancel that landed while bound may have fired Abort_Pending at
   --  T, which can still be pending, so such a transport is reported
   --  not Persistent. Unbind (the Binding's finalization) and the
   --  Was_Cancelled check are ordered under the Cancel_State lock: a
   --  Cancel after Unbind fires at nothing.
   procedure Exchange
     (Self       : Client_Type;
      Working    : AHT.HTTP.Request.Request_Type;
      Method     : AHT.HTTP.Methods.Method_Type;
      T          : in out AHT.Transport.Transport_Type'Class;
      Resp       : out AHT.HTTP.Response.Response_Type;
      Sink       : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array);
      Source     : access AHT.HTTP.Request.Body_Source'Class;
      Cancel     : access Cancel_State;
      Persistent : out Boolean;
      Head_Read  : access Boolean) is
   begin
      declare
         B : Binding;
      begin
         --  Race window: Cancel could fire between Connect returning
         --  and Bind running. Bind itself re-checks Cancelled under
         --  the protected lock and triggers Abort_Pending on the
         --  freshly bound transport, so a Cancel landing here still
         --  takes effect on the next Read.
         if Cancel /= null then
            --  'Unchecked_Access: B cannot outlive this block, and
            --  the state outlives the Send that was handed it.
            Arm (B, Cancel.all'Unchecked_Access);
            Cancel.Bind (T'Unchecked_Access);
         end if;

         Wire_Round_Trip
           (Self, Working, Method, T, Resp, Sink, Source, Cancel,
            Persistent, Head_Read);
      end;

      if Cancel /= null and then Cancel.Was_Cancelled then
         Persistent := False;
      end if;
   end Exchange;

   --  Owns one pooled connection for the duration of a hop, so every
   --  exit, an abort included, closes and frees what was not handed
   --  back to the pool.
   type Lease is new Ada.Finalization.Limited_Controlled with record
      C : aliased AHT.HTTP.Connection_Pools.Connection;
   end record;

   overriding procedure Finalize (Self : in out Lease) is
   begin
      AHT.HTTP.Connection_Pools.Discard (Self.C);
   end Finalize;

   --  SHA-256 of PEM in hex, or "" for an empty PEM. Fed in slices,
   --  so the bundle is never copied whole.
   function PEM_Digest (PEM : Unbounded_String) return String is
      Chunk : constant := 4096;
      Last  : constant Natural := Length (PEM);
      Ctx   : GNAT.SHA256.Context := GNAT.SHA256.Initial_Context;
      First : Positive := 1;
      Stop  : Natural;
   begin
      if Last = 0 then
         return "";
      end if;
      loop
         Stop := (if Last - First < Chunk then Last else First + Chunk - 1);
         GNAT.SHA256.Update (Ctx, Slice (PEM, First, Stop));
         exit when Stop = Last;
         First := Stop + 1;
      end loop;
      return GNAT.SHA256.Digest (Ctx);
   end PEM_Digest;

   --  For https the profile holds CA_PEM's digest rather than CA_PEM,
   --  which may be a whole system store: the key kept per idle
   --  connection is the same size whatever the bundle's, and building
   --  it on each hop hashes the bundle without copying it.
   function Endpoint_Of
     (Self : Client_Type;
      U    : AHT.URL.URL_Type) return AHT.HTTP.Connection_Pools.Endpoint is
     (Scheme      => U.Scheme,
      Host        => U.Host,
      Port        => U.Port,
      TLS_Profile =>
        (if U.Scheme = AHT.URL.HTTPS
         then To_Unbounded_String
                ((if Self.Insecure then "insecure" else "verify")
                 & (if Self.Use_System_Roots then "+system" else "")
                 & ASCII.NUL & To_String (Self.CA_Path)
                 & ASCII.NUL & PEM_Digest (Self.CA_PEM))
         else Null_Unbounded_String));

   function Pool_Endpoint
     (Self : Client_Type;
      URL  : AHT.URL.URL_Type) return AHT.HTTP.Connection_Pools.Endpoint
     renames Endpoint_Of;

   function Idempotent (M : AHT.HTTP.Methods.Method_Type) return Boolean is
     (M in AHT.HTTP.Methods.GET | AHT.HTTP.Methods.HEAD
         | AHT.HTTP.Methods.PUT | AHT.HTTP.Methods.DELETE
         | AHT.HTTP.Methods.OPTIONS);

   --  One request/response exchange for Req (a hop of a Send). Sink
   --  receives body chunks. Source, when non-null, streams the
   --  request body; otherwise Req.Body_B is written. Cancel, when
   --  non-null, is bound to the live transport so a concurrent Cancel
   --  can Abort_Pending it, and a pre-cancelled handle does not dial.
   procedure Run_Hop
     (Self              : Client_Type;
      Req               : AHT.HTTP.Request.Request_Type;
      Resp              : out AHT.HTTP.Response.Response_Type;
      Sink              : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array);
      Cancel            : access Cancel_State;
      Source            : access AHT.HTTP.Request.Body_Source'Class;
      On_Address        : access function
        (Host, Address : String) return Boolean;
      Strip_Credentials : Boolean)
   is
      Working : AHT.HTTP.Request.Request_Type := Req;

      Filtering : constant Boolean :=
        Self.On_Address /= null or else On_Address /= null;

      --  The field's filter and the request's: both must accept.
      function Address_OK (Host, Address : String) return Boolean is
        ((Self.On_Address = null or else Self.On_Address (Host, Address))
         and then (On_Address = null or else On_Address (Host, Address)));

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

      Persistent : Boolean;

      --  Whether a status line came back in this hop. Written through
      --  an access by the response reader, so it is right after a
      --  raise.
      Answered : aliased Boolean := False;

      procedure Connect_TCP (T : in out AHT.Transport.TCP.TCP_Transport) is
      begin
         AHT.Transport.TCP.Connect
           (T,
            Host            => To_String (Req.Target.Host),
            Port            => Req.Target.Port,
            Connect_Timeout => Connect_B,
            Resolve_Timeout => Resolve_B,
            Address_Filter  =>
              (if Filtering then Address_OK'Access else null));
      end Connect_TCP;

      procedure Connect_TLS (T : in out AHT.Transport.TLS.TLS_Transport) is
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
            CA_PEM             => To_String (Self.CA_PEM),
            Address_Filter     =>
              (if Filtering then Address_OK'Access else null),
            Use_System_Roots   => Self.Use_System_Roots);
      end Connect_TLS;

      --  The pooled path. A hop on a connection from the pool that
      --  fails before the caller saw a body byte is retried once on a
      --  fresh connection when that is safe (see Send in the spec).
      procedure Run_Pooled is
         use AHT.HTTP.Connection_Pools;

         function View (C : Connection) return AHT.Transport.Transport_Access
           renames AHT.HTTP.Connection_Pools.Transport;

         Where     : constant Endpoint := Endpoint_Of (Self, Req.Target);
         function Retry_Safe return Boolean is
           (Idempotent (Req.Method)
            and then Source = null
            and then not Answered
            and then not (Cancel /= null and then Cancel.Was_Cancelled));

         --  Set by Attempt as soon as it has a pooled connection. Not an
         --  out parameter: a scalar out is not copied back when the
         --  call propagates, and propagating is when it is needed.
         Reused : Boolean := False;

         procedure Attempt (Reuse : Boolean) is
            L     : Lease;
            Found : Boolean := False;
         begin
            Reused := False;
            if Reuse then
               --  Skip connections the peer has spoken on since they
               --  were parked; that is almost always its close. Skip
               --  too any whose address this request's filter refuses:
               --  it was dialled under another request's rules.
               loop
                  Acquire (Self.Pool, Where, L.C'Access, Found);
                  exit when not Found
                    or else
                      (View (L.C).Peer_Quiet
                       and then
                         (not Filtering
                          or else Address_OK
                            (To_String (Req.Target.Host),
                             View (L.C).Peer_Address)));
                  Discard (L.C);
               end loop;
            end if;

            if Found then
               Reused := True;
            else
               Allocate (L.C, Req.Target.Scheme);
               if Req.Target.Scheme = AHT.URL.HTTP then
                  Connect_TCP
                    (AHT.Transport.TCP.TCP_Transport (View (L.C).all));
               else
                  Connect_TLS
                    (AHT.Transport.TLS.TLS_Transport (View (L.C).all));
               end if;
            end if;

            Exchange
              (Self, Working, Req.Method, View (L.C).all, Resp,
               Sink, Source, Cancel, Persistent, Answered'Access);

            if Persistent
              and then not Lists_Token (Working.Headers, "connection", "close")
            then
               Release (Self.Pool, Where, L.C'Access);
            end if;
            --  Otherwise L's finalization closes it.
         end Attempt;
      begin
         begin
            Attempt (Reuse => True);
         exception
            when AHT.Transport.Transport_Error
               | Protocol_Error
               | AHT.Transport.TLS.TLS_Error =>
               if not (Reused and then Retry_Safe) then
                  raise;
               end if;
               Attempt (Reuse => False);
         end;
      end Run_Pooled;

   begin
      Merge_Headers (Self, Req, Working, Strip_Credentials);

      if Cancel /= null and then Cancel.Was_Cancelled then
         raise AHT.Transport.Aborted_Error
           with "HTTP.Client.Send: Cancel_Handle was triggered "
             & "before the request started";
      end if;

      if Req.Target.Scheme in AHT.URL.WS | AHT.URL.WSS then
         raise HTTP_Error
           with "ws/wss URL passed to HTTP.Client.Send; "
             & "use AHT.Websocket.Client for WebSocket connections";
      end if;

      if not AHT.HTTP.Connection_Pools.Is_Null (Self.Pool) then
         Run_Pooled;
         return;
      end if;

      case Req.Target.Scheme is
         when AHT.URL.HTTP =>
            declare
               T : aliased AHT.Transport.TCP.TCP_Transport;
            begin
               Connect_TCP (T);
               begin
                  Exchange
                    (Self, Working, Req.Method, T, Resp, Sink,
                     Source, Cancel, Persistent, Answered'Access);
               exception
                  when others =>
                     T.Close;
                     raise;
               end;
               T.Close;
            end;

         when AHT.URL.HTTPS =>
            declare
               T : aliased AHT.Transport.TLS.TLS_Transport;
            begin
               Connect_TLS (T);
               begin
                  Exchange
                    (Self, Working, Req.Method, T, Resp, Sink,
                     Source, Cancel, Persistent, Answered'Access);
               exception
                  when others =>
                     T.Close;
                     raise;
               end;
               T.Close;
            end;

         when AHT.URL.WS | AHT.URL.WSS =>
            null;   --  refused above
      end case;
   end Run_Hop;

   --  How much of a followed redirect's body is read before the
   --  connection is given up instead: enough for any honest "moved"
   --  page, too little for a server to hold the client with.
   Redirect_Body_Limit : constant := 65_536;

   --  A 303, or a 301 / 302 answering a POST, continues as a GET (a
   --  HEAD stays a HEAD) without the request body (RFC 9110 sec.
   --  15.4); 307 and 308, and 301 / 302 for other methods, repeat the
   --  request as it was.
   function Drops_Body
     (Status : AHT.HTTP.Status.Status_Code;
      Method : AHT.HTTP.Methods.Method_Type) return Boolean is
     (Status = 303
      or else (Status in 301 | 302 and then Method = AHT.HTTP.Methods.POST));

   --  Single core for every Send overload: Run_Hop per hop, following
   --  redirects as Self.Max_Redirects allows. Sink receives the body
   --  of the response returned; a followed redirect's body is read
   --  and dropped.
   procedure Run_Request
     (Self   : Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      On_Redirect : access function
        (From, To : AHT.URL.URL_Type;
         Status   : AHT.HTTP.Status.Status_Code;
         Hop      : Positive) return Redirect_Decision;
      On_Address  : access function
        (Host, Address : String) return Boolean;
      Sink   : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array);
      Cancel : access Cancel_State;
      Source : access AHT.HTTP.Request.Body_Source'Class := null)
   is
      Hop        : AHT.HTTP.Request.Request_Type := Req;
      Hop_Source : access AHT.HTTP.Request.Body_Source'Class := Source;
      Hops       : Natural := 0;

      --  Bytes of the current followed redirect's body dropped so far.
      Dropped : Natural := 0;

      --  Raised by Forward to stop reading a redirect body past
      --  Redirect_Body_Limit. It unwinds the hop like any exception,
      --  which closes the transport instead of pooling it; the head
      --  already parsed into Resp is all the redirect needs.
      Redirect_Body_Too_Long : exception;

      --  Whether the response being read is a redirect this Send
      --  follows. Decided from the status line and headers alone, so
      --  it holds from the first body byte; the checks that refuse a
      --  redirect (hop count, Location, scheme) raise after the body
      --  is drained. A redirect that needs a streamed body replayed is
      --  not followed.
      function Following return Boolean is
        (Self.Max_Redirects > 0
         and then Resp.Status in 301 | 302 | 303 | 307 | 308
         and then Resp.Headers.Contains ("location")
         and then (Hop_Source = null
                   or else Drops_Body (Resp.Status, Hop.Method)));

      procedure Forward (Chunk : AHT.Bytes.Byte_Array) is
      begin
         if not Following then
            Sink (Chunk);
         else
            Dropped := Dropped + Chunk'Length;
            if Dropped > Redirect_Body_Limit then
               raise Redirect_Body_Too_Long;
            end if;
         end if;
      end Forward;

      --  The field's filter, then the request's.
      function Vet
        (To : AHT.URL.URL_Type) return Redirect_Decision
      is
         D : Redirect_Decision := Follow;
      begin
         if Self.On_Redirect /= null then
            D := Self.On_Redirect (Hop.Target, To, Resp.Status, Hops);
         end if;
         if D = Follow and then On_Redirect /= null then
            D := On_Redirect (Hop.Target, To, Resp.Status, Hops);
         end if;
         return D;
      end Vet;
   begin
      --  Checked for every scheme, before anything is dialled, as the
      --  WebSocket client does for ws://: an http:// request does not
      --  reach the TLS transport, and a redirect could take it to
      --  https:// with the contradiction still in place.
      if Boolean'Pos (Length (Self.CA_Path) > 0)
           + Boolean'Pos (Length (Self.CA_PEM) > 0)
           + Boolean'Pos (Self.Use_System_Roots) > 1
      then
         raise AHT.Transport.TLS.TLS_Error
           with "HTTP.Client.Send: CA_Path, CA_PEM and Use_System_Roots "
             & "are mutually exclusive; choose one source of trust "
             & "anchors";
      end if;

      loop
         Dropped := 0;
         begin
            Run_Hop
              (Self, Hop, Resp, Forward'Access, Cancel, Hop_Source,
               On_Address,
               Strip_Credentials =>
                 not Same_Origin (Hop.Target, Req.Target));
         exception
            when Redirect_Body_Too_Long =>
               null;
         end;
         Resp.Final_URL := Hop.Target;

         exit when not Following;

         if Hops = Self.Max_Redirects then
            raise Redirect_Error with
              "HTTP.Client.Send: more than" & Self.Max_Redirects'Image
              & " redirects, last to " & Resp.Headers.Get ("location");
         end if;
         Hops := Hops + 1;

         declare
            Location : constant String := Resp.Headers.Get ("location");
            Next     : AHT.URL.URL_Type;
         begin
            begin
               Next := AHT.URL.Resolve (Hop.Target, Location);
            exception
               when E : AHT.URL.Parse_Error =>
                  raise Redirect_Error with
                    "HTTP.Client.Send: unusable Location """ & Location
                    & """: " & Ada.Exceptions.Exception_Message (E);
            end;

            if Next.Scheme not in AHT.URL.HTTP | AHT.URL.HTTPS then
               raise Redirect_Error with
                 "HTTP.Client.Send: redirect to a non-HTTP URL: "
                 & Location;
            end if;
            if Hop.Target.Scheme = AHT.URL.HTTPS
              and then Next.Scheme = AHT.URL.HTTP
              and then not Self.Allow_Redirect_Downgrade
            then
               raise Redirect_Error with
                 "HTTP.Client.Send: refusing https to http redirect to "
                 & Location;
            end if;

            --  The caller's say comes last, so it can only narrow
            --  what the rules above allow.
            case Vet (Next) is
               when Follow =>
                  null;
               when Stop =>
                  exit;
               when Refuse =>
                  raise Redirect_Error with
                    "HTTP.Client.Send: redirect to "
                    & AHT.URL.To_String (Next)
                    & " refused by the redirect filter";
            end case;

            --  RFC 9110 sec. 10.2.2: a Location without a fragment
            --  inherits the request's.
            if Length (Next.Fragment) = 0 then
               Next.Fragment := Hop.Target.Fragment;
            end if;

            if Drops_Body (Resp.Status, Hop.Method) then
               if Hop.Method /= AHT.HTTP.Methods.HEAD then
                  Hop.Method := AHT.HTTP.Methods.GET;
               end if;
               Hop.Body_B.Clear;
               Hop.Headers.Remove ("content-length");
               Hop.Headers.Remove ("content-type");
               Hop.Headers.Remove ("content-encoding");
               Hop.Headers.Remove ("transfer-encoding");
               Hop_Source := null;
            end if;

            --  Host is the new target's, whatever the caller set.
            Hop.Headers.Remove ("host");
            Hop.Target := Next;
         end;
      end loop;
   end Run_Request;

   procedure Send
     (Self : in out Client_Type;
      Req  : AHT.HTTP.Request.Request_Type;
      Resp : out AHT.HTTP.Response.Response_Type;
      On_Redirect : access function
        (From, To : AHT.URL.URL_Type;
         Status   : AHT.HTTP.Status.Status_Code;
         Hop      : Positive) return Redirect_Decision := null;
      On_Address  : access function
        (Host, Address : String) return Boolean := null)
   is
      --  Body sink that appends every delivered chunk to Resp.Body_B.
      --  Read_Streaming clears Self before any sink call (via its
      --  inner Parse_Head), so this builds up a fresh body.
      procedure Append_To_Body (Chunk : AHT.Bytes.Byte_Array) is
      begin
         Resp.Body_B.Append (Chunk);
      end Append_To_Body;
   begin
      Run_Request (Self, Req, Resp, On_Redirect, On_Address,
                   Sink   => Append_To_Body'Access,
                   Cancel => null);
   end Send;

   procedure Send
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Cancel : in out Cancel_Handle;
      On_Redirect : access function
        (From, To : AHT.URL.URL_Type;
         Status   : AHT.HTTP.Status.Status_Code;
         Hop      : Positive) return Redirect_Decision := null;
      On_Address  : access function
        (Host, Address : String) return Boolean := null)
   is
      procedure Append_To_Body (Chunk : AHT.Bytes.Byte_Array) is
      begin
         Resp.Body_B.Append (Chunk);
      end Append_To_Body;
   begin
      Run_Request (Self, Req, Resp, On_Redirect, On_Address,
                   Sink   => Append_To_Body'Access,
                   Cancel => Cancel.State'Access);
   end Send;

   procedure Send_Streaming
     (Self : in out Client_Type;
      Req  : AHT.HTTP.Request.Request_Type;
      Resp : out AHT.HTTP.Response.Response_Type;
      Sink : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array);
      On_Redirect : access function
        (From, To : AHT.URL.URL_Type;
         Status   : AHT.HTTP.Status.Status_Code;
         Hop      : Positive) return Redirect_Decision := null;
      On_Address  : access function
        (Host, Address : String) return Boolean := null) is
   begin
      Run_Request (Self, Req, Resp, On_Redirect, On_Address, Sink => Sink, Cancel => null);
   end Send_Streaming;

   procedure Send_Streaming
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Sink   : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array);
      Cancel : in out Cancel_Handle;
      On_Redirect : access function
        (From, To : AHT.URL.URL_Type;
         Status   : AHT.HTTP.Status.Status_Code;
         Hop      : Positive) return Redirect_Decision := null;
      On_Address  : access function
        (Host, Address : String) return Boolean := null) is
   begin
      Run_Request (Self, Req, Resp, On_Redirect, On_Address,
                   Sink   => Sink,
                   Cancel => Cancel.State'Access);
   end Send_Streaming;

   --  Body sink that writes every delivered chunk straight to an Ada
   --  stream. Block-copies Byte_Array -> Stream_Element_Array (the
   --  download mirror of Stream_Source.Read_Chunk's copy;
   --  Stream_Element'Size = Octet'Size = 8 on every supported target),
   --  then dispatches to the stream's Write. A raising Write propagates
   --  out through Run_Request; the hop that owned the transport closes
   --  it on the way.
   procedure Send_Streaming
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Target : not null access Ada.Streams.Root_Stream_Type'Class;
      On_Redirect : access function
        (From, To : AHT.URL.URL_Type;
         Status   : AHT.HTTP.Status.Status_Code;
         Hop      : Positive) return Redirect_Decision := null;
      On_Address  : access function
        (Host, Address : String) return Boolean := null)
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
      Run_Request (Self, Req, Resp, On_Redirect, On_Address,
                   Sink   => Write_To_Stream'Access,
                   Cancel => null);
   end Send_Streaming;

   procedure Send_Streaming
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Target : not null access Ada.Streams.Root_Stream_Type'Class;
      Cancel : in out Cancel_Handle;
      On_Redirect : access function
        (From, To : AHT.URL.URL_Type;
         Status   : AHT.HTTP.Status.Status_Code;
         Hop      : Positive) return Redirect_Decision := null;
      On_Address  : access function
        (Host, Address : String) return Boolean := null)
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
      Run_Request (Self, Req, Resp, On_Redirect, On_Address,
                   Sink   => Write_To_Stream'Access,
                   Cancel => Cancel.State'Access);
   end Send_Streaming;

   procedure Send_Streaming_Body
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Source : in out AHT.HTTP.Request.Body_Source'Class;
      On_Redirect : access function
        (From, To : AHT.URL.URL_Type;
         Status   : AHT.HTTP.Status.Status_Code;
         Hop      : Positive) return Redirect_Decision := null;
      On_Address  : access function
        (Host, Address : String) return Boolean := null)
   is
      procedure Append_To_Body (Chunk : AHT.Bytes.Byte_Array) is
      begin
         Resp.Body_B.Append (Chunk);
      end Append_To_Body;
   begin
      Run_Request (Self, Req, Resp, On_Redirect, On_Address,
                   Sink   => Append_To_Body'Access,
                   Cancel => null,
                   Source => Source'Access);
   end Send_Streaming_Body;

   procedure Send_Streaming_Body
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Source : in out AHT.HTTP.Request.Body_Source'Class;
      Cancel : in out Cancel_Handle;
      On_Redirect : access function
        (From, To : AHT.URL.URL_Type;
         Status   : AHT.HTTP.Status.Status_Code;
         Hop      : Positive) return Redirect_Decision := null;
      On_Address  : access function
        (Host, Address : String) return Boolean := null)
   is
      procedure Append_To_Body (Chunk : AHT.Bytes.Byte_Array) is
      begin
         Resp.Body_B.Append (Chunk);
      end Append_To_Body;
   begin
      Run_Request (Self, Req, Resp, On_Redirect, On_Address,
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
         Run_Request (Client_Snap, Req_Snap, Resp, null, null,
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
