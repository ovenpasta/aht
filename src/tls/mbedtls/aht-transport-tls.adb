--  Copyright (C) 2026 Aldo Nicolas Bruno
--  SPDX-License-Identifier: Apache-2.0

with Ada.Directories;
with Ada.Exceptions;
with Ada.Unchecked_Conversion;
with Ada.Unchecked_Deallocation;
with Interfaces.C;
with System;

with AHT.Mbedtls.Error;
--  Withed so the callback aht_mbedtls_entropy_new registers is in the
--  closure. Nothing on this side calls it -- the caller is C, through
--  a function pointer -- so without a with the symbol is undefined at
--  link and the entropy pool has no source.
with AHT.Mbedtls.Entropy;
pragma Unreferenced (AHT.Mbedtls.Entropy);
with AHT.Mbedtls.Glue;
--  Withed for its pragma Linker_Options and nothing else -- the unit
--  declares no entities, so there is nothing here to reference. It has
--  to be in some binary's closure for the pragma to fire, and this
--  body is the one unit every mbedTLS-using binary pulls in.
with AHT.Mbedtls.Link;
with AHT.Mbedtls.SSL;
with AHT.Mbedtls.X509;
with AHT.TLS_Sync;
with AHT.Guarded_New;
with AHT.PEM;
with AHT.Transport.TCP;

--  mbedTLS backend, structured as a buffered engine.
--
--  mbedTLS does the crypto; the bytes travel over an
--  AHT.Transport.TCP instance held in Backend_State. The BIO callbacks
--  do NOT touch the socket: they move bytes to and from two in-memory
--  queues, so every mbedtls_ssl_* call returns promptly (WANT_READ
--  when the inbound queue is dry) and all network waiting happens in
--  plain Ada outside the library.
--
--  That structure exists for concurrency. An mbedtls_ssl_context is
--  NOT safe for two tasks at once — the library's own mutexes, where
--  the build has any, guard its shared internals and never one
--  session's state — and mbedtls_ssl_read may itself write (alerts),
--  yet the WebSocket client runs a receiver task in Read while
--  senders call Write. So every mbedtls_ssl_* call is serialized under
--  SSL_Lock and
--  is non-blocking; wire output is serialized and kept in order by
--  Drain_Lock (strict order: Drain_Lock outer, SSL_Lock inner); and a
--  shared coordinator (AHT.TLS_Sync) arbitrates which task performs
--  the single TCP.Read while the other parks on a single-waiter latch.
--  Sound because the transport contract allows at most one reader and
--  one writer task.
--
--  Every blocking step (lock seize, latch wait, TCP read/write) is
--  bounded by the deadline of the OPERATION performing it (the
--  absolute mirrors in the outer record) and re-checks the abort epoch
--  afterwards. This mirrors the openssl backend; see docs/tls.md.
package body AHT.Transport.TLS is

   use type System.Address;
   use type Interfaces.C.int;
   use type Ada.Real_Time.Time;
   use type Ada.Directories.File_Kind;
   use type AHT.TLS_Sync.Epoch_Type;

   package C renames Interfaces.C;
   package M renames AHT.Mbedtls.SSL;

   Chunk_Max : constant := 65_536;

   type TCP_Access is access AHT.Transport.TCP.TCP_Transport;

   subtype Epoch_Type is AHT.TLS_Sync.Epoch_Type;
   subtype Lock_Type is AHT.TLS_Sync.Lock_Type;

   ---------------------------------------------------------------
   --  Engine I/O queues (the BIO callbacks' whole world)
   ---------------------------------------------------------------

   --  Passed to mbedtls_ssl_set_bio as the opaque p_bio. Only ever
   --  touched from inside an mbedtls_ssl_* call (so, under SSL_Lock)
   --  or by Feed/Drain while they hold SSL_Lock.
   type Engine_IO is record
      In_Data  : AHT.Bytes.Buffer;   --  inbound ciphertext queue
      In_Pos   : Positive := 1;      --  next unread index in In_Data
      In_EOF   : Boolean := False;   --  peer's stream ended
      Out_Data : AHT.Bytes.Buffer;   --  outbound ciphertext queue
   end record;
   type Engine_IO_Access is access all Engine_IO;

   function To_IO is new Ada.Unchecked_Conversion
     (System.Address, Engine_IO_Access);
   --  Recover the context in a callback. An access conversion rather
   --  than an address overlay on purpose: Engine_IO holds controlled
   --  Buffers, and an imported overlay object would be finalized when
   --  the callback returns, freeing storage the session still owns.

   --  Every mbedTLS context this backend owns is per transport object,
   --  including the entropy source and the DRBG. Nothing is shared
   --  between sessions, and therefore nothing is shared between tasks
   --  beyond what SSL_Lock already serializes.
   --
   --  That is worth stating because a whole build configuration rests
   --  on it: the Windows archive is built without MBEDTLS_THREADING_C,
   --  which is sound precisely because the mutexes it would add all
   --  guard state this backend does not have. Making CTR_DRBG or
   --  Entropy a library-level singleton — a tempting optimisation,
   --  since seeding is the expensive part of connecting — would
   --  invalidate that argument silently. See docs/tls.md.
   type Backend_State is record
      TCP      : aliased TCP_Access;
      --  aliased so AHT.Guarded_New can be handed
      --  State.TCP'Access at the allocation site below.
      IO       : aliased Engine_IO;
      SSL      : System.Address := System.Null_Address;  --  ssl_context*
      Conf     : System.Address := System.Null_Address;  --  ssl_config*
      CTR_DRBG : System.Address := System.Null_Address;
      Entropy  : System.Address := System.Null_Address;
      CA_Cert  : System.Address := System.Null_Address;  --  x509_crt*

      SSL_Lock   : Lock_Type;
      Drain_Lock : Lock_Type;
      Coord      : AHT.TLS_Sync.Coordinator_Type;

      Engine_Dead  : Boolean := False;
      Death_Reason : AHT.Bytes.Buffer;
      --  Guarded by SSL_Lock. Latched when a session-fatal error is
      --  seen, with the reason, so the operations rejected afterwards
      --  report what actually killed the session (the task that hit
      --  the original failure is often not the one the caller sees
      --  fail).
   end record;

   procedure Free_TCP is new Ada.Unchecked_Deallocation
     (AHT.Transport.TCP.TCP_Transport, TCP_Access);
   procedure Free_State is new Ada.Unchecked_Deallocation
     (Backend_State, Backend_State_Access);

   --  See AHT.Guarded_New: each instantiation's Gate is
   --  elaborated once, at library level, and closes the
   --  Allocate_Any_Controlled abort window around its one `new`.
   package New_State is new AHT.Guarded_New
     (Backend_State, Backend_State_Access);
   package New_TCP is new AHT.Guarded_New
     (AHT.Transport.TCP.TCP_Transport, TCP_Access);

   ---------------------------------------------------------------
   --  BIO callbacks — memory only, never the socket
   ---------------------------------------------------------------

   function Send_CB
     (Ctx : System.Address;
      Buf : System.Address;
      Len : C.size_t) return C.int
     with Convention => C;

   function Recv_CB
     (Ctx : System.Address;
      Buf : System.Address;
      Len : C.size_t) return C.int
     with Convention => C;

   function Send_CB
     (Ctx : System.Address;
      Buf : System.Address;
      Len : C.size_t) return C.int
   is
      IO : constant Engine_IO_Access := To_IO (Ctx);
      N  : constant Natural := Natural (Len);
   begin
      if N = 0 then
         return 0;
      end if;
      declare
         Data : AHT.Bytes.Byte_Array (1 .. N)
           with Import, Address => Buf;
      begin
         IO.Out_Data.Append (Data);
      end;
      return C.int (N);
   exception
      when others =>
         --  Ada exceptions must never cross the C frame. The only way
         --  here is an allocation failure growing the queue.
         return M.ERR_NET_SEND_FAILED;
   end Send_CB;

   function Recv_CB
     (Ctx : System.Address;
      Buf : System.Address;
      Len : C.size_t) return C.int
   is
      IO    : constant Engine_IO_Access := To_IO (Ctx);
      Want  : constant Natural := Natural (Len);
      Avail : constant Integer := IO.In_Data.Length - IO.In_Pos + 1;
   begin
      if Want = 0 then
         return 0;
      end if;
      if Avail <= 0 then
         --  Nothing buffered: EOF once the stream has ended, else ask
         --  the engine loop to feed us (it does the socket read).
         return (if IO.In_EOF then 0 else M.ERR_WANT_READ);
      end if;

      declare
         N   : constant Positive := Natural'Min (Want, Avail);
         Src : constant AHT.Bytes.Byte_Array :=
           IO.In_Data.To_Array (IO.In_Pos, IO.In_Pos + N - 1);
         Dst : AHT.Bytes.Byte_Array (1 .. N)
           with Import, Address => Buf;
      begin
         Dst := Src;
         IO.In_Pos := IO.In_Pos + N;
         if IO.In_Pos > IO.In_Data.Length then
            IO.In_Data.Clear;      --  fully consumed: reclaim and rewind
            IO.In_Pos := 1;
         end if;
         return C.int (N);
      end;
   exception
      when others =>
         return M.ERR_NET_RECV_FAILED;
   end Recv_CB;

   ---------------------------------------------------------------
   --  Small helpers
   ---------------------------------------------------------------

   function Bound
     (Has : Boolean; At_Time : Ada.Real_Time.Time)
      return Ada.Real_Time.Time
   is (if Has then At_Time else Ada.Real_Time.Time_Last);

   procedure Check_Abort
     (St     : Backend_State_Access;
      Epoch0 : Epoch_Type;
      Where  : String) is
   begin
      if St.Coord.Abort_Epoch /= Epoch0 then
         raise AHT.Transport.Aborted_Error with Where & ": aborted";
      end if;
   end Check_Abort;

   procedure Seize
     (L      : in out Lock_Type;
      St     : Backend_State_Access;
      DL     : Ada.Real_Time.Time;
      Epoch0 : Epoch_Type;
      Where  : String;
      What   : String) is
   begin
      select
         L.Seize;
      or
         delay until DL;
         raise AHT.Transport.Timeout_Error
           with Where & ": deadline expired (" & What & ")";
      end select;
      begin
         Check_Abort (St, Epoch0, Where);
      exception
         when others =>
            L.Release;
            raise;
      end;
   end Seize;

   --  Tear a desynchronised session down hard. A write that failed
   --  partway through a TLS record may already have put some bytes on
   --  the wire while mbedTLS believes none were sent — the outbound
   --  record stream is corrupt and must never be reused. Latch Fatal
   --  (so further Read/Write raise and Is_Connected reports False) and
   --  poison the TCP *without* a close_notify, which would only push
   --  another record onto the broken stream. Poison rather than Close
   --  because a WSS receiver task may still be parked on the socket;
   --  Close would race its selector. The contexts are left for the
   --  eventual Close/finalization.
   procedure Drop_Connection (St : Backend_State_Access) is
   begin
      St.Coord.Latch_Fatal;
      begin
         St.TCP.Poison;
      exception
         when others => null;
      end;
   end Drop_Connection;

   procedure Latch_Engine_Dead
     (St : Backend_State_Access; Reason : String) is
   begin
      St.SSL_Lock.Seize;
      if not St.Engine_Dead then
         St.Engine_Dead := True;
         St.Death_Reason.Set (Reason);
      end if;
      St.SSL_Lock.Release;
   end Latch_Engine_Dead;

   function Live (Self : TLS_Transport) return Boolean is
     (Self.Connected
      and then Self.State /= null
      and then not Self.State.Coord.Fatal);

   --  Map a fatal mbedTLS code to an exception. Takes the code by
   --  value so callers can capture it before tearing state down.
   procedure Raise_From_Code (Code : C.int; Where : String)
     with No_Return;

   procedure Raise_From_Code (Code : C.int; Where : String) is
   begin
      raise TLS_Error
        with Where & ": mbedTLS error" & C.int'Image (Code)
          & " (" & AHT.Mbedtls.Error.Strerror (Code) & ")";
   end Raise_From_Code;

   ---------------------------------------------------------------
   --  Phase B — drain queued ciphertext to the wire
   ---------------------------------------------------------------

   procedure Drain_Output
     (St     : Backend_State_Access;
      DL     : Ada.Real_Time.Time;
      Epoch0 : Epoch_Type;
      Where  : String) is
   begin
      Seize (St.Drain_Lock, St, DL, Epoch0, Where, "output drain lock");
      begin
         loop
            Seize (St.SSL_Lock, St, DL, Epoch0, Where, "engine lock");
            declare
               Pending : constant Natural := St.IO.Out_Data.Length;
               N       : constant Natural :=
                 Natural'Min (Pending, Chunk_Max);
            begin
               if N = 0 then
                  St.SSL_Lock.Release;
                  exit;
               end if;
               declare
                  --  Extract under the engine lock so wire order
                  --  matches queue order; send it with the lock free.
                  Slice : constant AHT.Bytes.Byte_Array :=
                    St.IO.Out_Data.To_Array (1, N);
               begin
                  if N = Pending then
                     St.IO.Out_Data.Clear;
                  else
                     St.IO.Out_Data.Set
                       (St.IO.Out_Data.To_Array (N + 1, Pending));
                  end if;
                  St.SSL_Lock.Release;
                  St.TCP.Write (Slice, Deadline => DL);
               end;
            end;
         end loop;
      exception
         when E : others =>
            St.Drain_Lock.Release;
            Latch_Engine_Dead
              (St, Where & " drain failed: "
               & Ada.Exceptions.Exception_Name (E) & " - "
               & Ada.Exceptions.Exception_Message (E));
            Drop_Connection (St);
            raise;
      end;
      St.Drain_Lock.Release;
   end Drain_Output;

   ---------------------------------------------------------------
   --  Feed — more inbound ciphertext, or wait for the other task's
   ---------------------------------------------------------------

   procedure Feed
     (St     : Backend_State_Access;
      DL     : Ada.Real_Time.Time;
      Epoch0 : Epoch_Type;
      Where  : String)
   is
      Granted : Boolean;
   begin
      St.Coord.Try_Claim_Or_Arm (Granted);

      if not Granted then
         --  The other direction's task owns the socket read; park
         --  until it feeds, releases, or something ends the session.
         select
            St.Coord.Await_Wakeup;
         or
            delay until DL;
            St.Coord.Disarm;
            raise AHT.Transport.Timeout_Error
              with Where & ": deadline expired (waiting for TLS input)";
         end select;
         Check_Abort (St, Epoch0, Where);
         return;
      end if;

      begin
         declare
            Buf  : AHT.Bytes.Byte_Array (1 .. Chunk_Max);
            Last : Natural;
         begin
            St.TCP.Read (Buf, Last, Deadline => DL);
            Seize (St.SSL_Lock, St, DL, Epoch0, Where, "engine lock");
            if Last = 0 then
               St.IO.In_EOF := True;
               St.SSL_Lock.Release;
               St.Coord.Latch_EOF;
            else
               St.IO.In_Data.Append (Buf (1 .. Last));
               St.SSL_Lock.Release;
            end if;
         end;
      exception
         when others =>
            St.Coord.Release_Feeder;
            raise;
      end;
      St.Coord.Release_Feeder;
      Check_Abort (St, Epoch0, Where);
   end Feed;

   ---------------------------------------------------------------
   --  Phase A — one engine call under SSL_Lock
   ---------------------------------------------------------------

   type Engine_Op is (Op_Read, Op_Write);

   procedure Engine_Call
     (St      : Backend_State_Access;
      Op      : Engine_Op;
      Buf     : System.Address;
      Len     : C.size_t;
      DL      : Ada.Real_Time.Time;
      Epoch0  : Epoch_Type;
      Where   : String;
      Ret     : out C.int;
      Pending : out Natural)
   is
      Is_Fatal : Boolean := False;
      Fatal_Ret : C.int := 0;
   begin
      Seize (St.SSL_Lock, St, DL, Epoch0, Where, "engine lock");

      if St.Engine_Dead then
         declare
            Reason : constant String := St.Death_Reason.To_String;
         begin
            St.SSL_Lock.Release;
            raise TLS_Error
              with Where & ": session already failed"
                & (if Reason = "" then "" else " (" & Reason & ")");
         end;
      end if;

      case Op is
         when Op_Read  => Ret := M.Read  (St.SSL, Buf, Len);
         when Op_Write => Ret := M.Write (St.SSL, Buf, Len);
      end case;

      --  A negative code that is not one of the "call me again" or
      --  clean-shutdown ones ends the session for good.
      if Ret < 0
        and then Ret /= M.ERR_WANT_READ
        and then Ret /= M.ERR_WANT_WRITE
        and then Ret /= M.ERR_PEER_CLOSE_NOTIFY
        and then Ret /= M.ERR_CONN_EOF
      then
         Is_Fatal  := True;
         Fatal_Ret := Ret;
         St.Engine_Dead := True;
         St.Death_Reason.Set
           (Where & ": mbedTLS error" & C.int'Image (Ret)
            & " (" & AHT.Mbedtls.Error.Strerror (Ret) & ")");
      end if;

      Pending := St.IO.Out_Data.Length;
      St.SSL_Lock.Release;

      --  Poison and raise HERE, so a session-fatal error reaches the
      --  caller the same way whichever direction hit it. Latching
      --  Engine_Dead alone is not enough: Is_Connected reads the
      --  coordinator's Fatal latch, so leaving it unset let a session
      --  killed by e.g. a bad record MAC keep reporting Is_Connected
      --  True (the read path raised without dropping, and only the
      --  write path had a fail-closed handler).
      if Is_Fatal then
         Drop_Connection (St);
         Raise_From_Code (Fatal_Ret, Where);
      end if;
   end Engine_Call;

   ---------------------------------------------------------------
   --  Connect
   ---------------------------------------------------------------

   --  Release everything a failed Connect allocated, leaving the
   --  object retryable. Single-task: no reader exists before Connect
   --  returns. Idempotent (it nulls Self.State).
   procedure Release_State (Self : in out TLS_Transport) is
      St : Backend_State_Access renames Self.State;
   begin
      if St = null then
         return;
      end if;
      if St.SSL /= System.Null_Address then
         AHT.Mbedtls.Glue.SSL_Free (St.SSL);
         St.SSL := System.Null_Address;
      end if;
      if St.Conf /= System.Null_Address then
         AHT.Mbedtls.Glue.Config_Free (St.Conf);
         St.Conf := System.Null_Address;
      end if;
      if St.CA_Cert /= System.Null_Address then
         AHT.Mbedtls.Glue.X509_CRT_Free (St.CA_Cert);
         St.CA_Cert := System.Null_Address;
      end if;
      if St.CTR_DRBG /= System.Null_Address then
         AHT.Mbedtls.Glue.CTR_DRBG_Free (St.CTR_DRBG);
         St.CTR_DRBG := System.Null_Address;
      end if;
      if St.Entropy /= System.Null_Address then
         AHT.Mbedtls.Glue.Entropy_Free (St.Entropy);
         St.Entropy := System.Null_Address;
      end if;
      if St.TCP /= null then
         begin
            St.TCP.Close;
         exception
            when others => null;
         end;
         Free_TCP (St.TCP);
      end if;
      Free_State (St);
   end Release_State;

   procedure Connect
     (Self               : in out TLS_Transport;
      Host               : String;
      Port               : AHT.URL.Port_Number;
      Insecure           : Boolean := False;
      CA_Path            : String  := "";
      Connect_Timeout    : Duration := Duration'Last;
      Handshake_Deadline : Duration := Duration'Last;
      CA_PEM             : String  := "";
      Resolve_Timeout    : Duration := Duration'Last)
   is
      use Ada.Real_Time;

      Ret : C.int;

      procedure Fail (Code : C.int; Where : String) with No_Return is
      begin
         Release_State (Self);
         Raise_From_Code (Code, Where);
      end Fail;

      HS_Bound : constant Ada.Real_Time.Time :=
        (if Handshake_Deadline = Duration'Last
         then Ada.Real_Time.Time_Last
         else Clock + To_Time_Span (Handshake_Deadline));

      --  Move whatever the handshake queued to the wire.
      procedure Pump_Out is
         St : constant Backend_State_Access := Self.State;
      begin
         while St.IO.Out_Data.Length > 0 loop
            declare
               Pending : constant Natural := St.IO.Out_Data.Length;
               N       : constant Natural :=
                 Natural'Min (Pending, Chunk_Max);
               Slice   : constant AHT.Bytes.Byte_Array :=
                 St.IO.Out_Data.To_Array (1, N);
            begin
               if N = Pending then
                  St.IO.Out_Data.Clear;
               else
                  St.IO.Out_Data.Set
                    (St.IO.Out_Data.To_Array (N + 1, Pending));
               end if;
               St.TCP.Write (Slice, Deadline => HS_Bound);
            end;
         end loop;
      end Pump_Out;

   begin
      if Self.Used or else Self.Connected then
         --  Single-use after success (see the spec): a completed
         --  session — live or poisoned — is never reconnected in
         --  place; a WSS receiver may still be unwinding through Read.
         raise TLS_Error with "TLS transport already connected";
      end if;

      --  Backend_State carries two Lock_Type and a Coordinator_Type,
      --  both protected types with entries (AHT.TLS_Sync), so a
      --  stranded, zero-filled one is not inert: a zeroed
      --  CRITICAL_SECTION reads as contended -- LockCount 0, where an
      --  initialized and unheld one is -1 -- and finalizing it hangs.
      --  Measured for this shape of object, on this target, by the
      --  Session_Type case New_State's construct mirrors (see
      --  AHT.Websocket.Client.Lifecycle_Controller.Create_Session)
      --  and by a standalone zero-fill probe; whether an abort
      --  actually lands inside this particular `new` in a live run
      --  has not been separately observed. See AHT.Guarded_New for
      --  why the bracket is a protected action taking Into by access
      --  rather than a plain `new` or an `out` parameter.
      New_State.Gate.Allocate (Self.State'Access);

      --  Everything from here on runs inside a cleanup block: ANY
      --  exception — the expected Fail paths, but equally an
      --  allocation failure or a filesystem error from the CA-kind
      --  classification — must release the state so the object stays
      --  retryable. Release_State is idempotent, so the inner Fail
      --  paths that already released are unaffected.
      begin

      --  Refused before anything is dialled, and refused even under
      --  Insecure. A caller who supplied two sets of trust anchors
      --  holds a mistaken belief about which one is in force;
      --  honouring one silently leaves that belief intact. Under
      --  Insecure neither is used, which makes accepting the
      --  contradiction more misleading rather than less.
      if CA_Path /= "" and then CA_PEM /= "" then
         raise TLS_Error
           with "TLS connect: CA_Path and CA_PEM are mutually "
             & "exclusive; supply the trust anchors either as a path "
             & "or as PEM data, not both";
      end if;

      --  Validated here, before anything is dialled and regardless of
      --  Insecure.
      --
      --  Regardless of Insecure, because the two backends disagreed
      --  otherwise: OpenSSL skips CA loading entirely when
      --  verification is off, mbedTLS parsed it anyway, so the same
      --  malformed bundle was accepted by one and rejected by the
      --  other. Checking the shape unconditionally makes supplying
      --  broken trust material an error the caller hears about even
      --  when this particular dial would not have used it -- which is
      --  the fail-closed reading, and the one that does not depend on
      --  which backend is linked.
      if CA_PEM /= "" then
         declare
            Problem : constant String := AHT.PEM.Bundle_Problem (CA_PEM);
         begin
            if Problem /= "" then
               raise TLS_Error
                 with "TLS connect (CA_PEM): " & Problem
                   & "; the bundle is rejected whole rather than in "
                   & "part";
            end if;
         end;
      end if;

      --  1. Plain TCP first (fresh per attempt, so a failed handshake
      --     leaves this object retryable): DNS multi-candidate
      --     fallback, the selectors, deadlines and Abort_Pending all
      --     come from AHT.Transport.TCP unchanged.
      --
      --  AHT.Transport.TCP.TCP_Transport is limited-controlled too,
      --  so it is stranded by the same window, but the consequence
      --  differs: it holds no CRITICAL_SECTION, and
      --  Transport_Type.Finalize (src/aht-transport.adb) dispatches
      --  on the object's tag before touching anything else -- on
      --  zero-filled memory that tag is null, so the dispatch faults
      --  and Finalize's own blanket handler swallows it. A stranded
      --  one is a leak and a swallowed fault, not a hang -- reasoned
      --  from that code, not measured -- and closing the same window
      --  here costs nothing.
      New_TCP.Gate.Allocate (Self.State.TCP'Access);
      AHT.Transport.TCP.Connect
        (Self.State.TCP.all, Host, Port,
         Connect_Timeout => Connect_Timeout,
         Resolve_Timeout => Resolve_Timeout);

      --  2. Allocate the mbedTLS contexts (sized by the C glue).
      Self.State.Entropy  := AHT.Mbedtls.Glue.Entropy_New;
      Self.State.CTR_DRBG := AHT.Mbedtls.Glue.CTR_DRBG_New;
      Self.State.Conf     := AHT.Mbedtls.Glue.Config_New;
      Self.State.SSL      := AHT.Mbedtls.Glue.SSL_New;
      if Self.State.Entropy = System.Null_Address
        or else Self.State.CTR_DRBG = System.Null_Address
        or else Self.State.Conf = System.Null_Address
        or else Self.State.SSL = System.Null_Address
      then
         raise TLS_Error with "TLS connect: context allocation failed";
      end if;

      --  3. Seed the RNG from the entropy source.
      Ret := AHT.Mbedtls.Glue.CTR_DRBG_Seed
        (Self.State.CTR_DRBG, Self.State.Entropy);
      if Ret /= 0 then
         Fail (Ret, "TLS connect (ctr_drbg_seed)");
      end if;

      --  4. Client/stream/default config.
      Ret := M.Config_Defaults
        (Self.State.Conf, M.IS_CLIENT, M.TRANSPORT_STREAM, M.PRESET_DEFAULT);
      if Ret /= 0 then
         Fail (Ret, "TLS connect (config_defaults)");
      end if;

      --  5. Verification mode + optional CA chain.
      if Insecure then
         M.Conf_Authmode (Self.State.Conf, M.VERIFY_NONE);
      else
         M.Conf_Authmode (Self.State.Conf, M.VERIFY_REQUIRED);
      end if;

      if CA_Path /= "" or else CA_PEM /= "" then
         Self.State.CA_Cert := AHT.Mbedtls.Glue.X509_CRT_New;
         if Self.State.CA_Cert = System.Null_Address then
            Fail (0, "TLS connect (x509 alloc)");
         end if;

         if CA_PEM /= "" then
            declare
               --  To_C with Append_Nul, and the NUL is COUNTED in the
               --  length. mbedTLS picks PEM over DER by finding
               --  "-----BEGIN", and its PEM branch requires the
               --  terminator inside the counted length; passing the
               --  text length alone makes it try DER and fail
               --  obscurely.
               Buf : aliased C.char_array := C.To_C (CA_PEM, True);
            begin
               Ret := AHT.Mbedtls.X509.CRT_Parse
                 (Self.State.CA_Cert, Buf'Address, Buf'Length);
            end;
            --  0 only. A positive result counts certificates that
            --  failed to parse, which is exactly the partial success
            --  this must refuse: installing the ones that did parse
            --  would trust a prefix of what the caller supplied and
            --  say nothing about the rest.
            if Ret /= 0 then
               Fail (Ret,
                     "TLS connect (CA_PEM parse; the bundle is "
                     & "rejected whole rather than in part)");
            end if;
         else
            declare
               Path_C : aliased C.char_array := C.To_C (CA_Path);
               Is_Dir : constant Boolean :=
                 Ada.Directories.Exists (CA_Path)
                   and then Ada.Directories.Kind (CA_Path)
                            = Ada.Directories.Directory;
            begin
               if Is_Dir then
                  Ret := AHT.Mbedtls.X509.CRT_Parse_Path
                    (Self.State.CA_Cert, Path_C'Address);
               else
                  Ret := AHT.Mbedtls.X509.CRT_Parse_File
                    (Self.State.CA_Cert, Path_C'Address);
               end if;
            end;
            --  parse_* returns 0 on full success, >0 if some certs in
            --  the file failed, <0 on hard error. Require a clean
            --  parse.
            if Ret /= 0 then
               Fail (Ret, "TLS connect (CA parse " & CA_Path & ")");
            end if;
         end if;
         M.Conf_CA_Chain
           (Self.State.Conf, Self.State.CA_Cert, System.Null_Address);
      end if;

      --  6. Point config RNG at CTR_DRBG, build ssl from config.
      AHT.Mbedtls.Glue.Conf_RNG (Self.State.Conf, Self.State.CTR_DRBG);
      Ret := M.Setup (Self.State.SSL, Self.State.Conf);
      if Ret /= 0 then
         Fail (Ret, "TLS connect (ssl_setup)");
      end if;

      --  7. SNI / cert-name hostname. mbedTLS matches dNSName SANs,
      --     the CN, and iPAddress SANs, so an IP-literal host verifies
      --     here as it does on the openssl backend; see docs/tls.md.
      declare
         Host_C : aliased C.char_array := C.To_C (Host);
      begin
         Ret := M.Set_Hostname (Self.State.SSL, Host_C'Address);
         if Ret /= 0 then
            Fail (Ret, "TLS connect (set_hostname)");
         end if;
      end;

      --  8. Wire the BIO to the in-memory queues. No recv-timeout
      --     callback: nothing here blocks, and the deadlines live on
      --     the engine's own TCP calls.
      M.Set_Bio
        (Self.State.SSL, Self.State.IO'Address,
         Send_CB'Access, Recv_CB'Access, System.Null_Address);

      --  9. Handshake pump: run the engine, push what it produced,
      --     pull what it asked for — all bounded by HS_Bound. Single
      --     task, so no locks are needed yet.
      Handshake :
      loop
         Ret := M.Handshake (Self.State.SSL);
         Pump_Out;
         exit Handshake when Ret = 0;

         if Ret = M.ERR_WANT_READ then
            if Self.State.IO.In_EOF then
               --  The peer's stream already ended and mbedTLS still
               --  wants input. It normally reports that itself (a recv
               --  callback returning 0 becomes CONN_EOF, handled
               --  below), but relying on that would make the loop spin
               --  on an at-EOF socket if it ever didn't — and with no
               --  Handshake_Deadline that spin would be unbounded.
               Fail (M.ERR_CONN_EOF, "TLS handshake (peer closed)");
            end if;
            declare
               Buf  : AHT.Bytes.Byte_Array (1 .. Chunk_Max);
               Last : Natural;
            begin
               Self.State.TCP.Read (Buf, Last, Deadline => HS_Bound);
               if Last = 0 then
                  Self.State.IO.In_EOF := True;
               else
                  Self.State.IO.In_Data.Append (Buf (1 .. Last));
               end if;
            end;
         elsif Ret /= M.ERR_WANT_WRITE then
            Fail (Ret, "TLS handshake");
         end if;
      end loop Handshake;

      --  Install the application deadlines mirrored before Connect
      --  onto the fresh TCP as REMAINING budgets (the engine passes
      --  explicit deadlines per call, but forwarding keeps the inner
      --  transport's own view consistent for anything that reads it).
      declare
         Now : constant Ada.Real_Time.Time := Clock;
         function Remaining (D : Ada.Real_Time.Time) return Duration is
           (if D > Now then To_Duration (D - Now) else 0.0);
      begin
         if Self.Has_Read_Deadline then
            Self.State.TCP.Set_Read_Deadline
              (Remaining (Self.Read_Deadline));
         end if;
         if Self.Has_Write_Deadline then
            Self.State.TCP.Set_Write_Deadline
              (Remaining (Self.Write_Deadline));
         end if;
      end;

      Self.Connected := True;
      Self.Used      := True;

      exception
         when others =>
            Release_State (Self);
            raise;
      end;
   end Connect;

   ---------------------------------------------------------------
   --  Read / Write
   ---------------------------------------------------------------

   overriding procedure Read
     (Self : in out TLS_Transport;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural)
   is
      St : Backend_State_Access;
   begin
      Last := 0;
      if Data'Length = 0 then
         return;
      end if;
      if not Live (Self) then
         raise AHT.Transport.Transport_Error
           with "TLS read on closed transport";
      end if;
      St := Self.State;

      declare
         DL      : constant Ada.Real_Time.Time :=
           Bound (Self.Has_Read_Deadline, Self.Read_Deadline);
         Epoch0  : constant Epoch_Type := St.Coord.Abort_Epoch;
         Ret     : C.int;
         Pending : Natural;
      begin
         loop
            Engine_Call
              (St, Op_Read, Data'Address, C.size_t (Data'Length),
               DL, Epoch0, "TLS read", Ret, Pending);

            --  Phase B: ship anything the engine produced (an alert,
            --  a renegotiation refusal) before deciding.
            if Pending > 0 then
               Drain_Output (St, DL, Epoch0, "TLS read");
            end if;

            if Ret > 0 then
               --  Phase C: a fatal latched by the OTHER task (whose
               --  drain may have carried our record) forbids success.
               if St.Coord.Fatal then
                  raise TLS_Error
                    with "TLS read: session failed concurrently";
               end if;
               Last := Data'First + Natural (Ret) - 1;
               return;
            elsif Ret = 0
              or else Ret = M.ERR_PEER_CLOSE_NOTIFY
              or else Ret = M.ERR_CONN_EOF
            then
               --  Clean TLS shutdown, or the peer's stream simply
               --  ending: both mirror the TCP transport's "Last = 0
               --  means peer closed" contract. (Unlike the openssl
               --  backend, an abrupt EOF is NOT an error here — a
               --  documented backend difference, see docs/tls.md.)
               Last := 0;
               return;
            elsif Ret = M.ERR_WANT_READ then
               Feed (St, DL, Epoch0, "TLS read");
            elsif Ret = M.ERR_WANT_WRITE then
               null;  --  output already drained above; call again
            else
               --  Defensive: Engine_Call classifies and poisons every
               --  fatal code, so nothing should reach here — but an
               --  unclassifiable state means the stream's integrity is
               --  unknown, so fail closed rather than stay usable.
               Drop_Connection (St);
               Raise_From_Code (Ret, "TLS read");
            end if;
         end loop;
      end;
   end Read;

   overriding procedure Write
     (Self : in out TLS_Transport;
      Data : AHT.Bytes.Byte_Array)
   is
      St : Backend_State_Access;
   begin
      if not Live (Self) then
         raise AHT.Transport.Transport_Error
           with "TLS write on closed transport";
      end if;
      if Data'Length = 0 then
         return;
      end if;
      St := Self.State;

      declare
         DL      : constant Ada.Real_Time.Time :=
           Bound (Self.Has_Write_Deadline, Self.Write_Deadline);
         Epoch0  : constant Epoch_Type := St.Coord.Abort_Epoch;
         Cursor  : Natural := Data'First;
         Ret     : C.int;
         Pending : Natural;
      begin
         while Cursor <= Data'Last loop
            Engine_Call
              (St, Op_Write, Data (Cursor)'Address,
               C.size_t (Data'Last - Cursor + 1),
               DL, Epoch0, "TLS write", Ret, Pending);

            begin
               if Pending > 0 then
                  Drain_Output (St, DL, Epoch0, "TLS write");
               end if;

               if Ret > 0 then
                  if St.Coord.Fatal then
                     raise TLS_Error
                       with "TLS write: session failed concurrently";
                  end if;
                  Cursor := Cursor + Natural (Ret);
               elsif Ret = M.ERR_WANT_WRITE then
                  null;  --  output drained above; call again
               elsif Ret = M.ERR_WANT_READ then
                  --  mbedTLS needs a record from the peer mid-write.
                  --  Get it ourselves, or wait for the reader task —
                  --  bounded by OUR (write) deadline either way.
                  Feed (St, DL, Epoch0, "TLS write");
                  if St.Coord.EOF then
                     raise TLS_Error
                       with "TLS write: peer closed mid-record";
                  end if;
               else
                  Raise_From_Code (Ret, "TLS write");
               end if;
            exception
               when E : TLS_Error | AHT.Transport.Timeout_Error
                  | AHT.Transport.Aborted_Error
                  | AHT.Transport.Transport_Error =>
                  --  Fail-closed: the record stream may be half-
                  --  written and irrecoverable, so the session is
                  --  dropped before the exception propagates — a retry
                  --  then raises rather than emitting onto a
                  --  desynchronised stream.
                  Latch_Engine_Dead
                    (St, "TLS write failed: "
                     & Ada.Exceptions.Exception_Name (E) & " - "
                     & Ada.Exceptions.Exception_Message (E));
                  Drop_Connection (St);
                  raise;
            end;
         end loop;
      end;
   end Write;

   ---------------------------------------------------------------
   --  Lifecycle / hooks
   ---------------------------------------------------------------

   overriding procedure Close (Self : in out TLS_Transport) is
      St     : Backend_State_Access := Self.State;
      Ignore : C.int;
   begin
      if St = null then
         Self.Connected := False;
         return;
      end if;
      Self.State := null;

      --  Block 1 (best-effort): close_notify + its drain, skipped for
      --  a session that died fatally (another record on a
      --  desynchronised stream helps nobody). Close is documented
      --  single-threaded, so plain state reads are fine here.
      begin
         if Self.Connected
           and then not St.Coord.Fatal
           and then not St.Engine_Dead
           and then St.SSL /= System.Null_Address
         then
            Ignore := M.Close_Notify (St.SSL);
            while St.IO.Out_Data.Length > 0 loop
               declare
                  Pending : constant Natural := St.IO.Out_Data.Length;
                  N       : constant Natural :=
                    Natural'Min (Pending, Chunk_Max);
                  Slice   : constant AHT.Bytes.Byte_Array :=
                    St.IO.Out_Data.To_Array (1, N);
               begin
                  if N = Pending then
                     St.IO.Out_Data.Clear;
                  else
                     St.IO.Out_Data.Set
                       (St.IO.Out_Data.To_Array (N + 1, Pending));
                  end if;
                  St.TCP.Write (Slice);
               end;
            end loop;
         end if;
      exception
         when others => null;
      end;
      Self.Connected := False;

      --  Block 2 (best-effort): the socket.
      begin
         St.TCP.Close;
      exception
         when others => null;
      end;

      --  Block 3 (unconditional): every free runs even if the blocks
      --  above failed — Finalize only swallows exceptions after Close
      --  has unwound, so Close itself must never skip cleanup.
      if St.SSL /= System.Null_Address then
         AHT.Mbedtls.Glue.SSL_Free (St.SSL);
         St.SSL := System.Null_Address;
      end if;
      if St.Conf /= System.Null_Address then
         AHT.Mbedtls.Glue.Config_Free (St.Conf);
         St.Conf := System.Null_Address;
      end if;
      if St.CA_Cert /= System.Null_Address then
         AHT.Mbedtls.Glue.X509_CRT_Free (St.CA_Cert);
         St.CA_Cert := System.Null_Address;
      end if;
      if St.CTR_DRBG /= System.Null_Address then
         AHT.Mbedtls.Glue.CTR_DRBG_Free (St.CTR_DRBG);
         St.CTR_DRBG := System.Null_Address;
      end if;
      if St.Entropy /= System.Null_Address then
         AHT.Mbedtls.Glue.Entropy_Free (St.Entropy);
         St.Entropy := System.Null_Address;
      end if;
      Free_TCP (St.TCP);
      Free_State (St);
   end Close;

   overriding function Is_Connected (Self : TLS_Transport) return Boolean is
     (Live (Self));

   overriding procedure Set_Read_Deadline
     (Self     : in out TLS_Transport;
      Deadline : Duration)
   is
      use Ada.Real_Time;
   begin
      --  Mirrored as an absolute computed ONCE here (the budget is
      --  measured from this call); the engine bounds every read-side
      --  wait by it. Forwarded to the inner TCP too, so its own view
      --  stays consistent.
      if Deadline = Duration'Last then
         Self.Has_Read_Deadline := False;
      else
         declare
            At_Time : constant Time := Clock + To_Time_Span (Deadline);
         begin
            Self.Read_Deadline     := At_Time;
            Self.Has_Read_Deadline := True;
         end;
      end if;
      if Self.State /= null and then Self.State.TCP /= null then
         Self.State.TCP.Set_Read_Deadline (Deadline);
      end if;
   end Set_Read_Deadline;

   overriding procedure Set_Write_Deadline
     (Self     : in out TLS_Transport;
      Deadline : Duration)
   is
      use Ada.Real_Time;
   begin
      if Deadline = Duration'Last then
         Self.Has_Write_Deadline := False;
      else
         declare
            At_Time : constant Time := Clock + To_Time_Span (Deadline);
         begin
            Self.Write_Deadline     := At_Time;
            Self.Has_Write_Deadline := True;
         end;
      end if;
      if Self.State /= null and then Self.State.TCP /= null then
         Self.State.TCP.Set_Write_Deadline (Deadline);
      end if;
   end Set_Write_Deadline;

   overriding procedure Abort_Pending (Self : in out TLS_Transport) is
   begin
      if Self.State = null then
         return;
      end if;
      --  Wake selector waiters (a feeder in TCP.Read, a drain in
      --  TCP.Write) AND the latch waiter; the epoch makes the woken
      --  operation raise Aborted_Error. Non-sticky: operations started
      --  after this call snapshot the new epoch.
      Self.State.Coord.Bump_Abort;
      begin
         Self.State.TCP.Abort_Pending;
      exception
         when others => null;
      end;
   end Abort_Pending;

end AHT.Transport.TLS;
