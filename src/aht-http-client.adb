with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;

with AHT.HTTP.Methods;
with AHT.Transport.TCP;
with AHT.URL;

package body AHT.HTTP.Client is

   use type AHT.Transport.Transport_Access;

   --  "host" or "host:port" — only emits the port when it differs
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

   --  Merge `Self.Default_Headers` and the auto-set Host /
   --  User-Agent / Connection onto `Working`, with the rule
   --  "request beats defaults, defaults beat auto":
   --    1. For each Name in Default_Headers, if Req.Headers does
   --       not contain Name, copy *all* of Default_Headers's entries
   --       for that Name across (preserves multi-valued defaults
   --       like repeated Accept).
   --    2. Then for Host / User-Agent / Connection, set them only
   --       if Working still doesn't contain them — so a default of
   --       `User-Agent: my-app/1` overrides `Self.User_Agent`, and
   --       an explicit `Connection: Upgrade` on the request (e.g.
   --       from the WebSocket layer) is preserved.
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

   --  Wire round-trip on an already-connected transport: optional
   --  read deadline, write the request, then loop over Response.Read
   --  until the status is not 1xx. 101 Switching Protocols is
   --  terminal — exit with the response so post-header bytes (e.g.
   --  WebSocket frames) stay buffered on the transport for the next
   --  layer.
   procedure Wire_Round_Trip
     (Self    : Client_Type;
      Working : AHT.HTTP.Request.Request_Type;
      Method  : AHT.HTTP.Methods.Method_Type;
      T       : in out AHT.Transport.Transport_Type'Class;
      Resp    : out AHT.HTTP.Response.Response_Type) is
   begin
      if Self.Timeout_Seconds > 0 then
         T.Set_Read_Deadline (Duration (Self.Timeout_Seconds));
      end if;

      AHT.HTTP.Request.Write (Working, T);

      loop
         AHT.HTTP.Response.Read (Resp, T, Method => Method);
         exit when Resp.Status not in 100 .. 199
           or else Resp.Status = 101;
      end loop;
   end Wire_Round_Trip;

   --  Single core for both Send overloads. When `Cancel` is null,
   --  behaves exactly like the no-cancel path. When `Cancel` is
   --  non-null, threads the live transport into the protected state
   --  so a concurrent Cancel can Abort_Pending on it.
   --
   --  Pre-cancel is honoured *before* connect — a handle that was
   --  Cancelled before Send started must not even dial.
   procedure Run_Request
     (Self   : Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Cancel : access Cancel_State)
   is
      Working : AHT.HTTP.Request.Request_Type := Req;
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
                  Host => To_String (Req.Target.Host),
                  Port => Req.Target.Port);

               --  Race window: Cancel could fire between Connect
                --  returning and Bind running. Bind itself
                --  re-checks Cancelled under the protected lock and
                --  triggers Abort_Pending on the freshly-bound
                --  transport, so a Cancel landing here still takes
                --  effect on the next Read.
               if Cancel /= null then
                  Cancel.Bind (T'Unchecked_Access);
               end if;

               begin
                  Wire_Round_Trip (Self, Working, Req.Method, T, Resp);
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
            raise HTTP_Error
              with "HTTPS is not yet wired in HTTP.Client.Send "
                & "(AHT.Transport.TLS pending mbedTLS integration)";

         when AHT.URL.WS | AHT.URL.WSS =>
            raise HTTP_Error
              with "ws/wss URL passed to HTTP.Client.Send; "
                & "use AHT.Websocket.Client for WebSocket connections";
      end case;
   end Run_Request;

   procedure Send
     (Self : in out Client_Type;
      Req  : AHT.HTTP.Request.Request_Type;
      Resp : out AHT.HTTP.Response.Response_Type) is
   begin
      Run_Request (Self, Req, Resp, Cancel => null);
   end Send;

   procedure Send
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Cancel : in out Cancel_Handle) is
   begin
      Run_Request (Self, Req, Resp, Cancel => Cancel.State'Access);
   end Send;

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

      function Was_Cancelled return Boolean is (Cancelled);

      function Is_Bound return Boolean is (Bound /= null);

   end Cancel_State;

end AHT.HTTP.Client;
