with Ada.Strings.Unbounded;

with AHT.Bytes;
with AHT.HTTP.Headers;
with AHT.HTTP.Request;
with AHT.HTTP.Response;
with AHT.Transport;

package AHT.HTTP.Client is

   type Client_Type is tagged record
      User_Agent      : Ada.Strings.Unbounded.Unbounded_String :=
        Ada.Strings.Unbounded.To_Unbounded_String ("AHT/0.1");
      Default_Headers : AHT.HTTP.Headers.Map;
      CA_Path         : Ada.Strings.Unbounded.Unbounded_String;
      Insecure        : Boolean := False;
      Timeout_Seconds : Natural := 30;
   end record;

   --  Cross-task cancel for an in-flight Send. Owned by the caller,
   --  passed by reference to the cancellable Send overload below.
   --
   --  Lifecycle:
   --    * `Cancel` from any task aborts a Send currently running with
   --      this handle (Send raises `AHT.Transport.Aborted_Error`).
   --    * `Cancel` before Send starts arms the handle: the next Send
   --      raises `Aborted_Error` immediately without dialing.
   --    * `Cancel` after Send returns is a harmless no-op.
   --    * `Is_Cancelled` reflects whether `Cancel` has ever been
   --      called on this handle.
   --
   --  v1 caveats:
   --    * Cancel takes effect during the response Read; it does not
   --      interrupt the TCP connect (`Abort_Pending` is a Read-side
   --      hook). A pre-cancelled handle short-circuits before connect.
   --    * Single-use: once `Cancel` has been called, every subsequent
   --      Send with this handle aborts immediately. Declare a fresh
   --      handle per cancellable operation.
   --    * Single-Send-at-a-time: sharing one handle across two
   --      concurrent Sends races on the bound-transport slot — Cancel
   --      will only abort one of them, unpredictably.
   type Cancel_Handle is limited private;

   procedure Cancel (Self : in out Cancel_Handle);
   function  Is_Cancelled (Self : Cancel_Handle) return Boolean;

   procedure Send
     (Self : in out Client_Type;
      Req  : AHT.HTTP.Request.Request_Type;
      Resp : out AHT.HTTP.Response.Response_Type);
   --  Synchronous, single-request HTTP round trip. Owns a fresh
   --  transport for the call (no keep-alive in v1), so multiple
   --  tasks can share one `Client_Type` without external locking.
   --
   --  Scheme dispatch on `Req.Target.Scheme`:
   --    * HTTP  → `AHT.Transport.TCP`.
   --    * HTTPS → not yet wired (raises `HTTP_Error`; pending TLS).
   --    * WS / WSS → raises `HTTP_Error`; use `AHT.Websocket.Client`.
   --
   --  Headers are merged onto a working copy of `Req` (request wins
   --  over defaults), only filling in what the caller did not set:
   --    * `Host` — `Host_Literal[:port]` from the URL.
   --    * `User-Agent` — `Self.User_Agent`.
   --    * `Connection: close` — no keep-alive in v1.
   --    * Each entry in `Self.Default_Headers` whose name is absent
   --      from `Req.Headers`. Multi-valued defaults are added in
   --      full or not at all (per-name decision, not per-entry).
   --
   --  Interim 1xx responses (100 Continue, 103 Early Hints, ...)
   --  are read and discarded; the loop returns the first non-1xx
   --  response. `101 Switching Protocols` is **terminal** — it is
   --  returned as-is with any post-header bytes still buffered on
   --  the transport, so a WebSocket layer above can consume them.
   --
   --  `Req.Method = HEAD` is threaded into `Response.Read` so the
   --  body framing is suppressed regardless of the peer's
   --  Content-Length / Transfer-Encoding.
   --
   --  Non-2xx status is **not** an exception — `Resp` carries the
   --  status verbatim. `HTTP_Error` / `Protocol_Error` /
   --  `Transport_Error` / `Timeout_Error` / `Aborted_Error` are
   --  raised for malformed wire, transport failure, deadline
   --  expiry, or external cancel. The transport is closed in every
   --  exit path.

   procedure Send
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Cancel : in out Cancel_Handle);
   --  Same as the 3-argument Send, plus cross-task cancellation via
   --  `Cancel` (see `Cancel_Handle` above for the lifecycle rules).
   --  Raises `AHT.Transport.Aborted_Error` if cancelled before or
   --  during the request; the transport is closed on the abort path
   --  just like any other exception exit.

   procedure Send_Streaming
     (Self : in out Client_Type;
      Req  : AHT.HTTP.Request.Request_Type;
      Resp : out AHT.HTTP.Response.Response_Type;
      Sink : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array));
   --  Streaming variant of Send: every body byte is delivered to
   --  `Sink` as it arrives instead of being accumulated in
   --  `Resp.Body_B`. `Resp.Status`, `Resp.Reason`, and
   --  `Resp.Headers` are populated as usual; `Resp.Body_B` is
   --  empty when the call returns.
   --
   --  Chunk granularity (none of these are stable contract; tests
   --  should treat them as hints, not guarantees):
   --    * `Transfer-Encoding: chunked` — one `Sink` call per
   --      decoded chunk.
   --    * `Content-Length: N` — `Sink` is called with up to 4 KiB
   --      chunks (one call when `N` ≤ 4 KiB).
   --    * neither header (`Connection: close`) — `Sink` is called
   --      with whatever the transport returns per `Read` (typically
   --      up to one TCP segment).
   --
   --  `Sink` may raise; the exception propagates out of `Send` and
   --  the transport is closed on that path just like any other
   --  exception. Sink must not invoke `Send` recursively against
   --  the same `Client_Type` (the transport is in mid-call).
   --
   --  Interim 1xx responses are looped past the same way as the
   --  buffered Send; `Sink` is never called for a 1xx (no body).
   --  `101 Switching Protocols` is the terminal 1xx and returns
   --  without calling `Sink`.

   procedure Send_Streaming
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Sink   : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array);
      Cancel : in out Cancel_Handle);
   --  Streaming Send with cross-task cancel. Same Cancel_Handle
   --  semantics as the buffered overload.

   function Get
     (Self : in out Client_Type;
      URL  : String) return AHT.HTTP.Response.Response_Type;
   --  Convenience wrapper: parses `URL`, builds a GET request with
   --  no body, and calls `Send`. Raises `AHT.URL.Parse_Error` on a
   --  malformed URL.

private

   --  Holds the transport currently bound to a Send and the sticky
   --  Cancelled flag. All access is serialized by the protected
   --  object so Cancel / Bind / Unbind are race-free across tasks.
   --
   --  Bind passes a stack-local transport pointer (via
   --  'Unchecked_Access) into the protected state for the duration
   --  of the Send call; Unbind clears it before Send returns.
   --  The Bound pointer is therefore always either null or pointing
   --  at a live transport on the active Send's stack — never
   --  dangling.
   protected type Cancel_State is
      procedure Cancel_Internal;
      procedure Bind (T : AHT.Transport.Transport_Access);
      procedure Unbind;
      function  Was_Cancelled return Boolean;
      function  Is_Bound return Boolean;
   private
      Bound     : AHT.Transport.Transport_Access := null;
      Cancelled : Boolean := False;
   end Cancel_State;

   type Cancel_Handle is limited record
      State : aliased Cancel_State;
   end record;

end AHT.HTTP.Client;
