--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

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
   --  Timeout_Seconds is one number spent on each of five phases
   --  separately; these fields split it apart.
   type Phase_Bound is private;

   function Seconds (S : Duration) return Phase_Bound
     with Pre => S >= 0.0;
   --  Bound this phase at S seconds.
   --
   --  Seconds (0.0) is a zero budget: the phase expires at once. It is
   --  not a synonym for "no bound", which Timeout_Seconds => 0 does
   --  mean; spell no bound as Unbounded.

   Inherit : constant Phase_Bound;
   --  Take this phase's bound from Timeout_Seconds. The default for
   --  every field below.

   Unbounded : constant Phase_Bound;
   --  No bound on this phase, whatever Timeout_Seconds says.

   type Client_Type is tagged record
      User_Agent      : Ada.Strings.Unbounded.Unbounded_String :=
        Ada.Strings.Unbounded.To_Unbounded_String ("AHT/0.1");
      Default_Headers : AHT.HTTP.Headers.Map;
      CA_Path         : Ada.Strings.Unbounded.Unbounded_String;
      --  Trust anchors in memory: concatenated PEM certificates.
      --  Supplying both this and CA_Path raises
      --  AHT.Transport.TLS.TLS_Error before dialling; there is no
      --  precedence, and the refusal stands even under Insecure.
      CA_PEM          : Ada.Strings.Unbounded.Unbounded_String;
      Insecure        : Boolean := False;

      --  The coarse bound, applied to every phase left at Inherit.
      --  0 means no bound. It is not an end-to-end deadline: each
      --  phase gets the full value as its own budget, so the wall
      --  clock a request may occupy is a multiple of it.
      Timeout_Seconds : Natural := 30;

      --  Per-phase overrides of Timeout_Seconds, each on one wait:
      --    Resolve_Timeout     the DNS lookup; unused for an IP
      --                        literal.
      --    Connect_Timeout     the TCP connect, one budget across
      --                        every resolved address.
      --    Handshake_Deadline  the TLS handshake; ignored on http://.
      --    Write_Deadline      the request write, on the streaming
      --                        upload path only; a buffered body
      --                        arms none.
      --    Read_Deadline       the response read, armed once the
      --                        request is on the wire, one budget
      --                        over status line, headers and body.
      --  Exhaustion of any raises Timeout_Error, as Timeout_Seconds
      --  does.
      Resolve_Timeout    : Phase_Bound := Inherit;
      Connect_Timeout    : Phase_Bound := Inherit;
      Handshake_Deadline : Phase_Bound := Inherit;
      Write_Deadline     : Phase_Bound := Inherit;
      Read_Deadline      : Phase_Bound := Inherit;
   end record;

   --  Cross-task cancel for an in-flight Send. Cancel from any task
   --  makes the Send raise AHT.Transport.Aborted_Error; before Send
   --  it arms the handle so the next Send raises without dialling;
   --  after Send it is a no-op. Is_Cancelled reports whether Cancel
   --  has ever been called. Cancel takes effect during the response
   --  Read; it does not interrupt the connect or TLS handshake, which
   --  only Connect_Timeout and Handshake_Deadline bound. Single-use:
   --  once cancelled, every later Send with this handle aborts. One
   --  Send at a time: concurrent Sends on one handle race on the
   --  bound-transport slot.
   type Cancel_Handle is limited private;

   procedure Cancel (Self : in out Cancel_Handle);
   function  Is_Cancelled (Self : Cancel_Handle) return Boolean;

   procedure Send
     (Self : in out Client_Type;
      Req  : AHT.HTTP.Request.Request_Type;
      Resp : out AHT.HTTP.Response.Response_Type);
   --  Synchronous single-request round trip on a fresh transport (no
   --  keep-alive), so tasks may share one Client_Type without
   --  locking. HTTP dials AHT.Transport.TCP; HTTPS dials
   --  AHT.Transport.TLS with Self.CA_Path, Self.CA_PEM and
   --  Self.Insecure; WS / WSS raise HTTP_Error.
   --
   --  Headers the caller did not set are filled in: Host from the
   --  URL, User-Agent from Self.User_Agent, Connection: close, and
   --  each Self.Default_Headers name absent from Req.Headers.
   --
   --  Interim 1xx responses are discarded; the first non-1xx is
   --  returned. 101 is terminal and returned as-is with post-header
   --  bytes still buffered on the transport. Req.Method = HEAD
   --  suppresses body framing. Non-2xx status is not an exception.
   --
   --  Raises HTTP_Error, Protocol_Error, Transport_Error,
   --  Timeout_Error or Aborted_Error for malformed wire, transport
   --  failure, deadline expiry or cancel; https:// also raises
   --  AHT.Transport.TLS.TLS_Error on a TLS failure. The transport is
   --  closed on every exit path.
   --
   --  Retry safety: with a write deadline armed or a Cancel fired,
   --  Timeout_Error / Aborted_Error can be raised with some request
   --  bytes already at the peer; a blind retry of a non-idempotent
   --  request may duplicate a side effect.

   procedure Send
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Cancel : in out Cancel_Handle);
   --  Same as the 3-argument Send, plus cross-task cancellation via
   --  Cancel (see Cancel_Handle above for the lifecycle rules).
   --  Raises AHT.Transport.Aborted_Error if cancelled before or
   --  during the request; the transport is closed on the abort path
   --  like any other exception exit.

   procedure Send_Streaming
     (Self : in out Client_Type;
      Req  : AHT.HTTP.Request.Request_Type;
      Resp : out AHT.HTTP.Response.Response_Type;
      Sink : not null access
        procedure (Chunk : AHT.Bytes.Byte_Array));
   --  Streaming variant of Send: every body byte goes to Sink as it
   --  arrives; Resp.Body_B stays empty. Slices are at most 4 KiB and
   --  wire chunk boundaries are not preserved (not a stable
   --  contract). Sink may raise; the exception propagates and the
   --  transport is closed. Sink must not call Send on the same
   --  Client_Type. Sink is never called for a 1xx, including the
   --  terminal 101.

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
   --  Download straight to an Ada stream: every body byte is written
   --  to Target as it arrives; Resp.Body_B stays empty. Selected with
   --  Target => ...; otherwise as the Sink overload. Target is
   --  borrowed for the call; a stream Write that raises propagates
   --  and the transport is closed.

   procedure Send_Streaming
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Target : not null access Ada.Streams.Root_Stream_Type'Class;
      Cancel : in out Cancel_Handle);
   --  Stream-target download with cross-task cancel. Same
   --  Cancel_Handle semantics as the other cancellable overloads.

   procedure Send_Streaming_Body
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Source : in out AHT.HTTP.Request.Body_Source'Class);
   --  Streaming upload: the body is pulled from Source.Read_Chunk and
   --  framed without buffering. A single Content-Length on Req
   --  selects fixed framing of exactly that many bytes; otherwise
   --  Transfer-Encoding: chunked. A Content-Length under- or
   --  over-run, a caller-set Transfer-Encoding or a duplicate
   --  Content-Length raises Protocol_Error. The response is buffered
   --  into Resp.Body_B as in Send; header merging, scheme dispatch,
   --  the 1xx loop and HEAD suppression are the same. Synchronous:
   --  Source need only outlive the call. Read_Chunk runs on the
   --  caller's task; Write_Deadline bounds a stalled transmit, not a
   --  blocked Read_Chunk. Same retry-safety rule as Send. Send_Async
   --  has no streaming upload.

   procedure Send_Streaming_Body
     (Self   : in out Client_Type;
      Req    : AHT.HTTP.Request.Request_Type;
      Resp   : out AHT.HTTP.Response.Response_Type;
      Source : in out AHT.HTTP.Request.Body_Source'Class;
      Cancel : in out Cancel_Handle);
   --  Streaming upload with cross-task cancel. Cancel is observed at
   --  the transport (a parked write is broken via Abort_Pending) and
   --  before each Read_Chunk, never during one.

   function Get
     (Self : in out Client_Type;
      URL  : String) return AHT.HTTP.Response.Response_Type;
   --  Convenience wrapper: parses URL, builds a GET request with no
   --  body, and calls Send. Raises AHT.URL.Parse_Error on a malformed
   --  URL.

   --  Async surface: Send_Async runs a buffered Send in a worker
   --  task, Await collects the result. Same wire behaviour as Send.
   --  Send_Async snapshots Self and Req into the worker and returns
   --  at once; later mutation has no effect. Await blocks until the
   --  worker is done and returns the response or re-raises the
   --  worker's exception with its identity preserved. Cancel aborts
   --  the request as Cancel_Handle.Cancel does. Single-use: a second
   --  Send_Async raises HTTP_Error. If the handle goes out of scope
   --  before Await, the master waits for the worker; Cancel + Await
   --  abandons a request without blocking on it.
   type Async_Handle is limited private;

   procedure Send_Async
     (Self  : in out Client_Type;
      Req   : AHT.HTTP.Request.Request_Type;
      Async : in out Async_Handle);

   procedure Await
     (Self : in out Async_Handle;
      Resp : out AHT.HTTP.Response.Response_Type);
   --  Blocks until the worker finishes; returns the response or
   --  re-raises what Run_Request raised. Raises HTTP_Error if the
   --  handle has not been Send_Async'd, since the worker is still
   --  parked at Start and Await would deadlock. Safe to call any
   --  number of times: the result is stored in the handle.

   procedure Cancel (Self : in out Async_Handle);
   --  Same semantics as Cancel_Handle.Cancel.

   function Is_Done       (Self : Async_Handle) return Boolean;
   --  True once the worker has returned from Run_Request (success
   --  or exception). Await on a Done handle returns without
   --  blocking.

   function Is_Cancelled  (Self : Async_Handle) return Boolean;

private

   --  Inherited is the state a bare Duration cannot carry: "no bound"
   --  is Duration'Last and "n seconds" is n, but "whatever
   --  Timeout_Seconds says" is neither, and it is the default.
   type Phase_Bound is record
      Inherited : Boolean  := True;
      Limit     : Duration := 0.0;
   end record;

   Inherit   : constant Phase_Bound :=
     (Inherited => True, Limit => 0.0);
   Unbounded : constant Phase_Bound :=
     (Inherited => False, Limit => Duration'Last);

   --  Holds the transport bound to a Send and the sticky Cancelled
   --  flag. Bind installs a pointer to the active Send's stack-local
   --  transport; Unbind clears it before Send returns, so Bound is
   --  null or live, never dangling.
   protected type Cancel_State is

      --  Cancel-side (used by both sync Cancel_Handle and async
      --  Async_Handle).
      procedure Cancel_Internal;
      procedure Bind (T : AHT.Transport.Transport_Access);
      procedure Unbind;
      function  Was_Cancelled return Boolean;

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

   --  Owns one in-flight Send for an Async_Handle. Blocks at Start
   --  until Send_Async, runs Run_Request, stores the result in the
   --  shared Cancel_State and terminates. The terminate alternative
   --  lets a never-started handle collapse with its master.
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
