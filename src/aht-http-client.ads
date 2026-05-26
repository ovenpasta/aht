with Ada.Strings.Unbounded;

with AHT.HTTP.Headers;
with AHT.HTTP.Request;
with AHT.HTTP.Response;

package AHT.HTTP.Client is

   type Client_Type is tagged record
      User_Agent      : Ada.Strings.Unbounded.Unbounded_String :=
        Ada.Strings.Unbounded.To_Unbounded_String ("AHT/0.1");
      Default_Headers : AHT.HTTP.Headers.Map;
      CA_Path         : Ada.Strings.Unbounded.Unbounded_String;
      Insecure        : Boolean := False;
      Timeout_Seconds : Natural := 30;
   end record;

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

   function Get
     (Self : in out Client_Type;
      URL  : String) return AHT.HTTP.Response.Response_Type;
   --  Convenience wrapper: parses `URL`, builds a GET request with
   --  no body, and calls `Send`. Raises `AHT.URL.Parse_Error` on a
   --  malformed URL.

end AHT.HTTP.Client;
