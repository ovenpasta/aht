--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with AHT.Bytes;
with AHT.URL;

private with Ada.Real_Time;

--  TLS transport, layered over the TCP transport so HTTPS/WSS inherit
--  its DNS multi-candidate fallback, compound read/write deadlines and
--  Abort_Pending. This spec is backend-neutral: two interchangeable
--  bodies implement it, selected at build time by the AHT_TLS_BACKEND
--  gpr external (see docs/tls.md):
--    * openssl: system OpenSSL 3 (libssl/libcrypto).
--    * mbedtls: vendored mbedTLS 3.6, fetched and built on demand.
package AHT.Transport.TLS is

   type TLS_Transport is new Transport_Type with private;

   TLS_Error : exception;

   procedure Connect
     (Self               : in out TLS_Transport;
      Host               : String;
      Port               : AHT.URL.Port_Number;
      Insecure           : Boolean := False;
      CA_Path            : String  := "";
      Connect_Timeout    : Duration := Duration'Last;
      Handshake_Deadline : Duration := Duration'Last;
      CA_PEM             : String  := "";
      Resolve_Timeout    : Duration := Duration'Last);
   --  TCP-connect to Host:Port, then run the TLS handshake. A DNS name
   --  gets SNI = Host and certificate verification against Host; an
   --  IP literal gets no SNI and is checked against its IP SANs. Host
   --  stays the name for SNI; see AHT.DNS. Insecure skips
   --  verification; otherwise a failure raises TLS_Error.
   --  CA_Path: a PEM bundle file or a directory of certificates. With
   --  CA_Path = "": openssl uses the platform trust store; mbedtls has
   --  no default trust and the handshake fails. A directory needs
   --  c_rehash names on openssl; mbedtls loads every file in it.
   --  CA_PEM: the same trust material as concatenated PEM in memory; a
   --  malformed bundle raises TLS_Error with nothing of it installed.
   --  Both CA_Path and CA_PEM supplied: raises TLS_Error before
   --  dialling; no precedence.
   --  Resolve_Timeout bounds the DNS lookup; Timeout_Error.
   --  Connect_Timeout bounds the TCP connect across all candidates
   --  (AHT.Transport.TCP.Connect); Timeout_Error.
   --  Handshake_Deadline bounds the handshake only (Set_*_Deadline do
   --  not apply to it); Timeout_Error. Duration'Last is unbounded.
   --  Single-use: after a successful Connect, further Connect calls
   --  raise TLS_Error. A failed Connect leaves the object retryable.

   overriding procedure Write
     (Self : in out TLS_Transport;
      Data : AHT.Bytes.Byte_Array);

   overriding procedure Read
     (Self : in out TLS_Transport;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural);
   --  Concurrency contract (both backends): a TLS transport supports at
   --  most one task in Read and one task in Write concurrently, the
   --  WSS receiver-task-plus-sender shape. Two concurrent readers or
   --  two concurrent writers are not supported (the same restriction
   --  the TCP transport's single-waiter selectors impose).

   type Try_Read_Status is (Would_Block, Data_Ready, Peer_Closed);

   procedure Try_Read
     (Self   : in out TLS_Transport;
      Data   : out AHT.Bytes.Byte_Array;
      Last   : out Natural;
      Status : out Try_Read_Status);
   --  Read without waiting for the network, for callers that multiplex
   --  the connection in their own event loop. Decrypts what the engine
   --  already holds, taking at most one non-blocking receive from the
   --  socket when it needs more ciphertext, and returns:
   --    Data_Ready   plaintext stored in Data, Last its last index;
   --    Would_Block  no complete record yet (Last = 0); a partial
   --                 record stays buffered for the next call;
   --    Peer_Closed  the peer's close_notify (Last = 0); repeats on
   --                 every later call.
   --  A TCP EOF without close_notify raises TLS_Error on both
   --  backends: Peer_Closed is only ever an authenticated close (the
   --  mbedtls blocking Read is laxer; see docs/tls.md). Errors poison
   --  the session as they do in Read. Empty Data: Would_Block.
   --  One receive may carry several records while one call returns
   --  one, so call again until Would_Block before waiting for socket
   --  readiness. Ciphertext the engine queues while reading (a
   --  KeyUpdate reply, an alert) is not sent here; the next Write,
   --  Read or Close drains it, which is as soon as the protocol
   --  requires. Set_Read_Deadline and Abort_Pending do not apply:
   --  there is no wait to bound. Takes the reader role of the
   --  concurrency contract above: it may run alongside one Write, not
   --  alongside Read or another Try_Read.

   procedure Abortive_Close (Self : in out TLS_Transport);
   --  Drops the session without a close_notify: frees the backend
   --  contexts and closes the inner TCP transport, never writing to
   --  the socket, so it cannot wait on a peer that has stopped
   --  reading. The peer sees a truncated stream; use Close where it
   --  must see an authenticated end. Idempotent, also after a fatal
   --  error and on a never-connected object. Same precondition as
   --  Close. Does not change Close or the inherited Finalize.

   overriding procedure Close (Self : in out TLS_Transport);
   --  Closes: best-effort close_notify (skipped after a fatal error),
   --  then the inner TCP transport, then frees the backend contexts.
   --  Idempotent.
   --  Precondition: no other task is inside any operation on this
   --  transport, Is_Connected and the deadline setters included; they
   --  dereference the state Close frees. Not enforced. For the
   --  concurrent fatal-write case the inner TCP is Poison'ed and this
   --  reclaim waits until the reader has exited.

   overriding function Is_Connected (Self : TLS_Transport) return Boolean;
   --  True after a successful Connect until Close, except that a
   --  session poisoned by a fatal Read/Write reports False (via a
   --  task-safe latch, so a reader may query it while a writer fails).

   overriding procedure Set_Read_Deadline
     (Self     : in out TLS_Transport;
      Deadline : Duration);

   overriding procedure Set_Write_Deadline
     (Self     : in out TLS_Transport;
      Deadline : Duration);
   --  Compound budgets measured from the call, per the base contract.
   --  Mirrored here as absolute times and forwarded to the inner TCP
   --  transport; every internal wait, including one performed for the
   --  other direction's traffic, is bounded by the deadline of the
   --  operation performing it. Callable before Connect: the deadline
   --  then applies to Read/Write on the future connection, not to the
   --  handshake.

   overriding procedure Abort_Pending (Self : in out TLS_Transport);
   --  Unblocks a Read/Write in progress with Aborted_Error. No-op when
   --  the transport has no connection state.

private

   --  All backend-specific state (crypto contexts, the inner TCP
   --  transport, synchronization) lives behind this deferred-to-body
   --  ("Taft") type, so the two backend bodies can complete it
   --  differently while sharing this spec verbatim.
   type Backend_State;
   type Backend_State_Access is access Backend_State;

   type TLS_Transport is new Transport_Type with record
      State              : aliased Backend_State_Access := null;
      --  aliased so AHT.Guarded_New can be handed State'Access at the
      --  allocation site in each backend body.
      Used               : Boolean := False;
      --  Latched by a successful handshake only, so a failed Connect
      --  leaves the object retryable while a completed session makes
      --  the transport single-use.
      Connected          : Boolean := False;
      --  Lifecycle-owned: written only by Connect/Close under their
      --  single-threaded preconditions. Fatal mid-session errors latch
      --  a protected flag inside Backend_State instead (RM 9.10).
      Has_Read_Deadline  : Boolean := False;
      Read_Deadline      : Ada.Real_Time.Time := Ada.Real_Time.Time_First;
      Has_Write_Deadline : Boolean := False;
      Write_Deadline     : Ada.Real_Time.Time := Ada.Real_Time.Time_First;
      --  Absolute deadline mirrors, computed once in the setters (the
      --  budget is measured from the setter call). Kept outside
      --  Backend_State: the setters must work with State = null.
   end record;

end AHT.Transport.TLS;
