with Ada.Exceptions;
with Ada.Streams;
with Ada.Strings.Unbounded;

with AHT.Bytes;
with AHT.HTTP.Headers;
with AHT.HTTP.Request;
with AHT.HTTP.Response;
with AHT.Transport;

package AHT.HTTP.Client is

   --  One phase's bound, for the per-phase fields on Client_Type.
   --
   --  A request walks five phases -- DNS, TCP connect, TLS handshake,
   --  request write, response read -- and Timeout_Seconds is one
   --  number spent on each of them separately. That couples bounds
   --  that have nothing to do with each other: a caller who must
   --  allow a long download can only do it by widening the one knob,
   --  which widens the dial along with it, and a peer that stalls
   --  mid-handshake then gets the download's patience. These fields
   --  split the knob apart.
   type Phase_Bound is private;

   function Seconds (S : Duration) return Phase_Bound
     with Pre => S >= 0.0;
   --  Bound this phase at S seconds.
   --
   --  Seconds (0.0) is a *zero* budget -- the phase expires at once
   --  -- and is deliberately not a synonym for "no bound", which
   --  Timeout_Seconds => 0 does mean. The two knobs disagree because
   --  the failure modes are not symmetric: a caller who writes
   --  Seconds (0.0) expecting no bound gets an immediate
   --  Timeout_Error, while the reverse reading would hang. Spell no
   --  bound as Unbounded.

   Inherit : constant Phase_Bound;
   --  Take this phase's bound from Timeout_Seconds. The default for
   --  every field below, so a client that sets none of them behaves
   --  exactly as it did before they existed.

   Unbounded : constant Phase_Bound;
   --  No bound on this phase, whatever Timeout_Seconds says.

   type Client_Type is tagged record
      User_Agent      : Ada.Strings.Unbounded.Unbounded_String :=
        Ada.Strings.Unbounded.To_Unbounded_String ("AHT/0.1");
      Default_Headers : AHT.HTTP.Headers.Map;
      CA_Path         : Ada.Strings.Unbounded.Unbounded_String;
      --  Trust anchors held in memory rather than on disk -- one or
      --  more concatenated PEM certificates, for anchors compiled
      --  into the binary. Setting BOTH this and CA_Path raises
      --  TLS_Error on the next HTTPS request, before anything is
      --  dialled; there is no precedence rule, and the refusal stands
      --  even under Insecure.
      CA_PEM          : Ada.Strings.Unbounded.Unbounded_String;
      Insecure        : Boolean := False;

      --  The coarse bound, applied to every phase left at Inherit.
      --  0 means no bound. It is not an end-to-end deadline: each
      --  phase gets the full value as its own budget, so the wall
      --  clock a request may occupy is a multiple of it.
      Timeout_Seconds : Natural := 30;

      --  Per-phase overrides of Timeout_Seconds. Each covers exactly
      --  one wait, and they are separate knobs for the same reason
      --  AHT.Websocket.Client.Connect's four are: a caller willing to
      --  wait out a slow body may still refuse to wait on a peer that
      --  never finishes the handshake.
      --
      --    Resolve_Timeout     the DNS lookup, which runs before any
      --                        of the others and so cannot be bounded
      --                        by them. Nothing to bound when the URL
      --                        carries an IP literal.
      --
      --    Connect_Timeout     the TCP connect, as ONE total budget
      --                        across every address DNS resolved to,
      --                        not a per-candidate one.
      --
      --    Handshake_Deadline  the TLS handshake alone, and so only
      --                        on https://; an http:// request runs
      --                        none and ignores it.
      --
      --    Write_Deadline      the request write, and only on the
      --                        streaming-upload path
      --                        (Send_Streaming_Body). A buffered body
      --                        is already in RAM and drains in one
      --                        shot, so the other overloads arm no
      --                        write deadline and ignore this.
      --
      --    Read_Deadline       the response read, armed once the
      --                        request is fully on the wire, as one
      --                        compound budget over status line,
      --                        headers and body together.
      --
      --  Exhaustion of any of them raises Timeout_Error, exactly as
      --  Timeout_Seconds does; these change which wait is bounded and
      --  by how much, never what a breach looks like.
      Resolve_Timeout    : Phase_Bound := Inherit;
      Connect_Timeout    : Phase_Bound := Inherit;
      Handshake_Deadline : Phase_Bound := Inherit;
      Write_Deadline     : Phase_Bound := Inherit;
      Read_Deadline      : Phase_Bound := Inherit;
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
   --      interrupt the connect dial (`Abort_Pending` is a Read-side
   --      hook). For `https://` that uninterruptible phase covers the
   --      TLS handshake too — only a deadline can bound
   --      connect/handshake, never `Cancel`: `Connect_Timeout` and
   --      `Handshake_Deadline`, or `Timeout_Seconds` where those are
   --      left at `Inherit`. A caller who has set `Timeout_Seconds`
   --      to 0 to allow an unbounded body still wants those two set,
   --      or the dial has nothing bounding it at all. A pre-cancelled
   --      handle short-circuits before connect; a Cancel arriving
   --      during connect/handshake takes effect on the first response
   --      Read.
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
   --    * HTTPS → `AHT.Transport.TLS`, honouring `Self.CA_Path`,
   --      `Self.CA_PEM` /
   --      `Self.Insecure`.
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
   --  expiry, or external cancel. `https://` additionally raises
   --  `AHT.Transport.TLS.TLS_Error` on a TLS failure such as an
   --  untrusted/invalid certificate chain. The transport is closed
   --  in every exit path.
   --
   --  Retry-safety: once a write deadline is armed (from
   --  `Self.Write_Deadline`, or `Self.Timeout_Seconds` where that is
   --  `Inherit`), or a `Cancel` fires, a `Timeout_Error` / `Aborted_Error`
   --  can be raised *while the request is mid-flight on the wire* — some
   --  request bytes may already have reached the peer (see the partial-send
   --  note on `AHT.Transport.Write`). Such a failure is therefore
   --  **retry-unsafe** for a non-idempotent request: the library cannot tell
   --  "never sent" from "partially sent", so a blind retry could duplicate a
   --  side effect. The fresh-per-request transport is closed on the exit
   --  path, so the partially-written connection is never silently reused;
   --  whether to retry is the caller's call (safe for idempotent methods,
   --  unsafe otherwise).

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

   procedure Send_Streaming
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Target : not null access Ada.Streams.Root_Stream_Type'Class);
   --  Streaming download straight to an Ada stream: every response body
   --  byte is written to `Target` as it arrives instead of being
   --  accumulated in `Resp.Body_B` or pushed through a `Sink` callback.
   --  The download mirror of `Send_Streaming_Body`'s `Stream_Source` --
   --  because `Root_Stream_Type'Class` subsumes files (via
   --  `Ada.Streams.Stream_IO.Stream`), sockets, and generators, saving a
   --  response straight to a file/socket is a one-liner with no
   --  hand-rolled `Sink`.
   --
   --  Resolves against the `Sink` overloads by the fourth parameter:
   --  pass `Sink => ...` for the callback form, `Target => ...` for the
   --  stream form. `Resp.Status`, `Resp.Reason`, and `Resp.Headers` are
   --  populated as usual; `Resp.Body_B` is empty on return (the bytes
   --  went to the stream). Chunk granularity, the 1xx loop, and HEAD
   --  suppression are identical to the `Sink` overload.
   --
   --  Lifetime / framing parity with `Stream_Source`: the call is
   --  synchronous and *borrows* `Target` -- the caller owns its
   --  open/close lifetime, which outlives the call by construction. A
   --  stream `Write` that raises propagates out of `Send_Streaming` and
   --  the transport is closed on that path, exactly like a raising
   --  `Sink`.

   procedure Send_Streaming
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Target : not null access Ada.Streams.Root_Stream_Type'Class;
      Cancel : in out Cancel_Handle);
   --  Stream-target download with cross-task cancel. Same `Cancel_Handle`
   --  semantics as the other cancellable overloads.

   procedure Send_Streaming_Body
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Source : in out AHT.HTTP.Request.Body_Source'Class);
   --  Streaming *upload*: pull the request body from `Source`
   --  (Source.Read_Chunk) and frame it on the wire without ever
   --  buffering it — the mirror of Send_Streaming, which streams the
   --  *download*. Framing is header-driven (see
   --  `AHT.HTTP.Request.Write_Streaming`): a single `Content-Length`
   --  set on `Req` (e.g. via `Request.Set_Content_Length`) selects
   --  fixed framing of exactly that many bytes; otherwise the body is
   --  sent `Transfer-Encoding: chunked`. A `Content-Length` under- or
   --  over-run, a caller-set `Transfer-Encoding`, or a duplicate
   --  `Content-Length` raises `Protocol_Error` before/while writing.
   --
   --  The *response* is buffered into `Resp.Body_B` exactly like the
   --  plain `Send` — only the upload streams. Header merging, scheme
   --  dispatch, the 1xx loop, and HEAD suppression are identical to
   --  `Send`. The call is synchronous: it runs the whole upload and
   --  reads the response before returning, so `Source` need only
   --  outlive the call. `Source.Read_Chunk` runs on the caller's task
   --  and **must not block indefinitely**: `Self.Write_Deadline` (or
   --  `Self.Timeout_Seconds`, where it is left at `Inherit`) arms
   --  a write deadline that bounds a stalled *transmit* (a peer that
   --  stops reading), but it only bites once control is inside the
   --  transport write -- it does *not* interrupt a `Read_Chunk` that is
   --  itself blocked, so a source that can stall must enforce its own
   --  timeout.
   --
   --  Same retry-safety caveat as `Send`: a `Timeout_Error` /
   --  `Aborted_Error` can be raised mid-upload with some bytes already
   --  on the wire, so a failed streaming upload of a non-idempotent
   --  request is retry-unsafe.
   --
   --  Streaming upload on the *async* surface is not offered yet
   --  (`Send_Async` stays buffered); it is a deferred follow-up.

   procedure Send_Streaming_Body
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Source : in out AHT.HTTP.Request.Body_Source'Class;
      Cancel : in out Cancel_Handle);
   --  Streaming upload with cross-task cancel. Same `Cancel_Handle`
   --  semantics as the other cancellable overloads: a `Cancel` from
   --  another task aborts the in-flight upload with `Aborted_Error`.
   --  Cancel bites at the transport (a parked write is broken via
   --  `Abort_Pending`) and between source windows (the upload polls the
   --  handle before each `Read_Chunk`), so a long upload or a peer that
   --  stalls the send is interruptible, not just the response read. A
   --  `Read_Chunk` already in progress is *not* interrupted -- cancel is
   --  observed before the next window, not during a blocked read.

   function Get
     (Self : in out Client_Type;
      URL  : String) return AHT.HTTP.Response.Response_Type;
   --  Convenience wrapper: parses `URL`, builds a GET request with
   --  no body, and calls `Send`. Raises `AHT.URL.Parse_Error` on a
   --  malformed URL.

   --  Async surface: kick off a buffered Send in a worker task and
   --  collect the response later via Await. Same wire behaviour as
   --  the sync Send (header merging, 1xx loop, HEAD suppression,
   --  scheme dispatch); the worker just runs on its own task so the
   --  caller can do other work in the meantime.
   --
   --  Lifecycle:
   --    * Declare an Async_Handle. The worker task auto-starts and
   --      waits at an internal `accept Start or terminate`.
   --    * Send_Async snapshots Self + Req into the worker and kicks
   --      off the request. Returns immediately.
   --    * Await blocks until the worker is done; returns the
   --      response or re-raises the worker's exception (with
   --      original identity preserved via Save_Occurrence).
   --    * Cancel from any task aborts the in-flight request the
   --      same way Cancel_Handle.Cancel does (Transport.Abort_Pending
   --      on the bound transport, with the same pre-cancel and
   --      bind-race semantics).
   --
   --  Caveats:
   --    * Single-use. Each handle services exactly one Send_Async.
   --      A second call raises HTTP_Error. Declare a fresh handle.
   --    * Self and Req are snapshotted into the worker at Start;
   --      mutating them in the caller after Send_Async has no
   --      effect on the in-flight call.
   --    * If the handle goes out of scope before Await, the
   --      enclosing master waits for the worker to finish
   --      Run_Request (the natural Ada behaviour). Cancel + Await
   --      if you want to abandon a request without blocking on it.
   type Async_Handle is limited private;

   procedure Send_Async
     (Self  : in out Client_Type;
      Req   : AHT.HTTP.Request.Request_Type;
      Async : in out Async_Handle);

   procedure Await
     (Self : in out Async_Handle;
      Resp : out AHT.HTTP.Response.Response_Type);
   --  Blocks until the worker finishes. On success returns the
   --  response; on failure re-raises whatever Run_Request raised
   --  (Aborted_Error / Transport_Error / HTTP_Error / etc.) with
   --  the original exception identity intact.
   --
   --  Raises `HTTP_Error` if the handle has not been `Send_Async`'d
   --  yet — otherwise the worker is still parked at its Start
   --  rendezvous and Await would deadlock.
   --
   --  Safe to call any number of times. The worker stashes the
   --  result in the handle's protected state before terminating,
   --  so subsequent calls just re-read it without blocking
   --  (success returns the same response; failure re-raises the
   --  same exception).

   procedure Cancel (Self : in out Async_Handle);
   --  Same semantics as Cancel_Handle.Cancel.

   function Is_Done       (Self : Async_Handle) return Boolean;
   --  True once the worker has returned from Run_Request (success
   --  or exception). Await on a Done handle returns without
   --  blocking.

   function Is_Cancelled  (Self : Async_Handle) return Boolean;

private

   --  Inherited is the state a bare Duration cannot carry. "No
   --  bound" is Duration'Last and "n seconds" is n, but "whatever
   --  Timeout_Seconds says" is neither -- and it has to be the
   --  default, or adding these fields would silently change what
   --  every existing client does.
   type Phase_Bound is record
      Inherited : Boolean  := True;
      Limit     : Duration := 0.0;
   end record;

   Inherit   : constant Phase_Bound :=
     (Inherited => True, Limit => 0.0);
   Unbounded : constant Phase_Bound :=
     (Inherited => False, Limit => Duration'Last);

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

      --  Cancel-side (used by both sync Cancel_Handle and async
      --  Async_Handle).
      procedure Cancel_Internal;
      procedure Bind (T : AHT.Transport.Transport_Access);
      procedure Unbind;
      function  Was_Cancelled return Boolean;
      function  Is_Bound return Boolean;

      --  Async-only (sync Cancel_Handle never invokes these). The
      --  worker stores its result here and then terminates; Await
      --  waits on the entry barrier and reads the stored state, so
      --  multiple Awaits all see the same outcome.
      procedure Mark_Done_OK  (R : AHT.HTTP.Response.Response_Type);
      procedure Mark_Done_Err
        (E : Ada.Exceptions.Exception_Occurrence);
      entry     Wait_Until_Done;
      procedure Read_Result
        (Out_Resp   : out AHT.HTTP.Response.Response_Type;
         Out_OK     : out Boolean;
         Out_Caught : out Ada.Exceptions.Exception_Occurrence);
      function  Is_Done_Flag return Boolean;

   private
      Bound         : AHT.Transport.Transport_Access := null;
      Cancelled     : Boolean := False;
      Done_Flag     : Boolean := False;
      Result_OK     : Boolean := False;
      Result_Resp   : AHT.HTTP.Response.Response_Type;
      Result_Caught : Ada.Exceptions.Exception_Occurrence;
   end Cancel_State;

   type Cancel_State_Access is access all Cancel_State;
   --  Named access so a pointer to Cancel_State can appear in task
   --  entry parameter lists (RM 9.5.2: anonymous access parameters
   --  are forbidden on entries).

   type Cancel_Handle is limited record
      State : aliased Cancel_State;
   end record;

   --  Worker task that owns one in-flight Send for an Async_Handle.
   --  Auto-started on Async_Handle elaboration; blocks at Start
   --  until Send_Async kicks the request off, then runs
   --  Run_Request, stashes the result (response or exception) in
   --  the shared Cancel_State via Mark_Done_OK / Mark_Done_Err,
   --  and terminates. The result lives in the protected state, so
   --  Await reads it from there instead of through a second
   --  rendezvous — multiple Awaits and "drop without Await" both
   --  work cleanly. The terminate alternative on Start lets a
   --  never-Send_Async'd handle collapse when its master ends.
   task type Worker_Task is
      entry Start
        (Client_Snapshot  : Client_Type;
         Request_Snapshot : AHT.HTTP.Request.Request_Type;
         State_Ref        : Cancel_State_Access);
   end Worker_Task;

   type Async_Handle is limited record
      State   : aliased Cancel_State;
      Worker  : Worker_Task;
      Started : Boolean := False;
   end record;

end AHT.HTTP.Client;
