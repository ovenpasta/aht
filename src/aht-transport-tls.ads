with AHT.Bytes;
with AHT.URL;

private with Ada.Real_Time;

--  TLS transport, layered over the TCP transport so HTTPS/WSS inherit
--  its DNS multi-candidate fallback, compound read/write deadlines and
--  Abort_Pending. This spec is backend-neutral: two interchangeable
--  bodies implement it, selected at build time by the AHT_TLS_BACKEND
--  gpr external (see docs/tls.md):
--    * openssl — system OpenSSL 3 (libssl/libcrypto).
--    * mbedtls — vendored mbedTLS 2.28, fetched and built on demand.
package AHT.Transport.TLS is

   type TLS_Transport is new Transport_Type with private;
   type TLS_Transport_Access is access all TLS_Transport;

   TLS_Error : exception;

   procedure Connect
     (Self               : in out TLS_Transport;
      Host               : String;
      Port               : AHT.URL.Port_Number;
      Insecure           : Boolean := False;
      CA_Path            : String  := "";
      Connect_Timeout    : Duration := Duration'Last;
      Handshake_Deadline : Duration := Duration'Last;
      CA_PEM             : String  := "");
   --  TCP-connect to Host:Port, then run the TLS handshake. For a DNS
   --  name the handshake sends SNI = Host and verifies the peer
   --  certificate against Host; for an IP-literal Host the certificate
   --  is checked against its IP SANs (no SNI). Insecure => the peer
   --  certificate is not verified; otherwise a verification failure
   --  raises TLS_Error.
   --
   --  CA_Path names the trust anchors: a PEM bundle file or a directory
   --  of certs. With CA_Path = "" the backends differ:
   --    * openssl verifies against the platform's default trust store,
   --      so public https:// endpoints work out of the box;
   --    * mbedtls configures no default trust, so the handshake rejects
   --      — pass a CA bundle or set Insecure.
   --  (A CA *directory* is also backend-specific: openssl requires
   --  c_rehash-style hashed names, mbedtls loads every file. Prefer a
   --  bundle file for portability.)
   --
   --  CA_PEM is the same trust material held in memory rather than on
   --  disk -- one or more concatenated PEM certificates, for anchors
   --  compiled into the binary. Empty means "not supplied" and leaves
   --  the backend-specific default above untouched.
   --
   --  It is appended to the parameter list rather than placed beside
   --  CA_Path so that existing positional callers passing
   --  Connect_Timeout and Handshake_Deadline keep compiling and keep
   --  meaning what they meant.
   --
   --  Supplying BOTH CA_Path and CA_PEM raises TLS_Error before
   --  anything is dialled. There is deliberately no precedence rule,
   --  and the refusal stands even under Insecure: a caller who gave
   --  two sets of trust anchors has a mistaken belief about which one
   --  is in force, and silently honouring one of them leaves that
   --  belief intact. Under Insecure neither is used, which makes
   --  quietly accepting the contradiction more misleading rather than
   --  less.
   --
   --  Parsing is all-or-nothing. A bundle whose tail is truncated or
   --  corrupt is rejected outright rather than installing the
   --  certificates that parsed before the damage -- trusting a prefix
   --  of what the caller meant to trust is worse than trusting
   --  nothing, because nobody finds out.
   --
   --  Connect_Timeout is forwarded to the underlying TCP connect as its
   --  total budget across resolved candidates (see
   --  AHT.Transport.TCP.Connect); exhaustion raises Timeout_Error.
   --  Duration'Last leaves the TCP connect unbounded.
   --
   --  Handshake_Deadline bounds the **TLS handshake only**: a peer that
   --  stalls mid-handshake raises Timeout_Error instead of blocking
   --  forever. It does **not** bound DNS resolution or the TCP connect
   --  (those run before it is armed). Deadlines installed earlier via
   --  Set_Read_Deadline / Set_Write_Deadline do not apply to the
   --  handshake either — they govern subsequent Read/Write calls and
   --  are installed on the connection only after the handshake
   --  succeeds. Duration'Last (the default) leaves the handshake
   --  unbounded.
   --
   --  A TLS transport is **single-use after success**: once a Connect
   --  has completed, further Connect calls raise TLS_Error — even after
   --  a fatal Write poisoned the session (close the object and use a
   --  fresh transport to reconnect). A **failed** Connect, however —
   --  TCP failure, handshake timeout, certificate rejection — releases
   --  everything it allocated and leaves the object ready for another
   --  Connect attempt.

   overriding procedure Write
     (Self : in out TLS_Transport;
      Data : AHT.Bytes.Byte_Array);

   overriding procedure Read
     (Self : in out TLS_Transport;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural);
   --  Concurrency contract (both backends): a TLS transport supports at
   --  most ONE task in Read and ONE task in Write concurrently — the
   --  WSS receiver-task-plus-sender shape. Two concurrent readers or
   --  two concurrent writers are not supported (the same restriction
   --  the TCP transport's single-waiter selectors impose).

   overriding procedure Close (Self : in out TLS_Transport);
   --  Single-threaded lifecycle reclaim: best-effort close_notify (
   --  skipped when the session died of a fatal error), then closes the
   --  inner TCP transport and unconditionally frees the backend
   --  contexts. Idempotent.
   --
   --  Precondition (caller's responsibility, not enforceable here): no
   --  other task may be inside ANY operation on this transport while
   --  Close runs.
   --
   --  Not just Read and Write. Close nulls and frees the backend state,
   --  and every other primitive dereferences it — Is_Connected, the
   --  deadline setters, Abort_Pending — so any of them racing Close is
   --  a use-after-free, not merely a stale answer. Enumerating the
   --  operations invites the list to fall behind the body; the rule is
   --  the whole object, and the caller must quiesce every task using it
   --  before calling this.
   --
   --  Websocket.Client keeps that rule two different ways, depending on
   --  whether the session ever became reachable by a second task:
   --
   --    * Published sessions are closed by the RECEIVER, in Reclaim,
   --      after Stop_Admission has shut the door and Wait_No_Borrowers
   --      has seen the last borrow returned. Exclusivity comes from
   --      that borrow protocol.
   --    * An attempt that never published -- a failed or aborted
   --      Connect -- is closed by Attempt_Owner.Finalize, on the
   --      connecting task itself. Exclusivity holds because the session
   --      was never handed over: the receiver task exists (it is a
   --      component of the client and outlives any one connection) but
   --      never accepted this session and has no way to reach it, so
   --      the connecting task is its only owner. Which is why the owner
   --      checks Attempt_Handed_Off first and does nothing if it fired.
   --
   --  Wait_Closed is NOT that point, and cannot be. It is a protected
   --  entry that opens when the connection state reaches Closed, which
   --  Reclaim publishes *before* it drains borrowers — and the caller
   --  waits on it while still holding its own teardown borrow, so a
   --  Wait_Closed that meant "reclaimed" would deadlock against the
   --  drain it is part of. The caller learns that the transport is
   --  closed and the session freed from Wait_Generation_Done, which it
   --  reaches only after leaving the pin's scope and giving that borrow
   --  back.
   --
   --  For the concurrent fatal-write case the inner TCP is Poison'ed
   --  (reader-safe), deferring this reclaim until the reader has
   --  exited.

   overriding function Is_Connected (Self : TLS_Transport) return Boolean;
   --  True after a successful Connect until Close — except that a
   --  session poisoned by a fatal Read/Write reports False (via a
   --  task-safe latch, so a reader may query it while a writer fails).

   overriding procedure Set_Read_Deadline
     (Self     : in out TLS_Transport;
      Deadline : Duration);

   overriding procedure Set_Write_Deadline
     (Self     : in out TLS_Transport;
      Deadline : Duration);
   --  Compound budgets measured from the call, per the base contract.
   --  Both are mirrored here (as absolute times computed once) and
   --  forwarded to the inner TCP transport; the mirrors let the
   --  backends bound every internal wait — including waits performed on
   --  behalf of the *other* direction's protocol traffic — by the
   --  deadline of the operation that performs them. Callable before
   --  Connect: the deadline then applies to Read/Write on the future
   --  connection (not to the handshake).

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
      State              : Backend_State_Access := null;
      Used               : Boolean := False;
      --  Latched by a SUCCESSFUL handshake only, so a failed Connect
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
      --  Absolute deadline mirrors, computed ONCE in the setters (the
      --  budget is measured from the setter call; recomputing later
      --  would silently refresh it). Out here rather than in
      --  Backend_State because the setters must work with State = null.
   end record;

end AHT.Transport.TLS;
