with Ada.Directories;
with Ada.Exceptions;
with Ada.Unchecked_Conversion;
with Ada.Unchecked_Deallocation;
with Interfaces.C.Strings;
with System;

with GNAT.Sockets;

with AHT.Openssl.BIO;
with AHT.Openssl.Err;
with AHT.Openssl.Glue;
with AHT.Openssl.SSL;
with AHT.TLS_Sync;
with AHT.Openssl.Version;
with AHT.Openssl.X509;
with AHT.PEM;
with AHT.Transport.TCP;

--  OpenSSL backend: a memory-BIO engine. The SSL object owns two
--  BIO_s_mem BIOs (RBIO for inbound ciphertext, WBIO for outbound);
--  OpenSSL never touches the socket. Plain Ada code moves bytes
--  between the BIOs and the inner TCP transport, so network
--  exceptions (Timeout/Aborted/Transport) propagate natively and no
--  Ada exception ever crosses a C frame.
--
--  Concurrency (see docs/tls.md for the full design): OpenSSL 3 does
--  NOT permit two tasks inside SSL_read/SSL_write on one SSL* (TLS 1.3
--  KeyUpdate/tickets mutate shared state), so every SSL_* call runs
--  under SSL_Lock and is non-blocking (memory BIOs); all waiting
--  happens outside the lock. Wire output is serialized by Drain_Lock
--  (strict order: Drain_Lock outer, SSL_Lock inner). The Coordinator
--  arbitrates which task performs the single TCP.Read (feeder claim)
--  and parks the other on a single-waiter latch — sound because the
--  transport contract allows at most one reader + one writer task.
--
--  Every blocking step (lock seize, latch wait, TCP read/write) is
--  bounded by the deadline of the OPERATION performing it (the
--  absolute mirrors in the outer record) and re-checks the abort
--  epoch afterwards.
package body AHT.Transport.TLS is

   use type System.Address;
   use type Interfaces.C.int;
   use type Interfaces.C.long;
   use type Interfaces.C.size_t;
   use type Ada.Real_Time.Time;
   use type Ada.Directories.File_Kind;

   package C renames Interfaces.C;
   package OSSL renames AHT.Openssl.SSL;
   package OBIO renames AHT.Openssl.BIO;

   Chunk_Max : constant := 65_536;

   type TCP_Access is access AHT.Transport.TCP.TCP_Transport;

   --  Locks, coordinator and abort epoch live in AHT.Openssl.Sync so
   --  their claim/arm/wake semantics are unit-testable on their own.
   subtype Epoch_Type is AHT.TLS_Sync.Epoch_Type;
   subtype Lock_Type is AHT.TLS_Sync.Lock_Type;
   use type AHT.TLS_Sync.Epoch_Type;

   ---------------------------------------------------------------
   --  Backend state
   ---------------------------------------------------------------

   type Backend_State is record
      TCP  : TCP_Access;
      Ctx  : System.Address := System.Null_Address;  --  SSL_CTX*
      SSL  : System.Address := System.Null_Address;  --  SSL*
      RBio : System.Address := System.Null_Address;  --  inbound mem BIO
      WBio : System.Address := System.Null_Address;  --  outbound mem BIO
      Bios_Transferred : Boolean := False;
      --  True once SSL_set_bio ran: ownership of both BIOs passed to
      --  the SSL (SSL_free frees them; BIO_free would double-free).

      SSL_Lock   : Lock_Type;
      Drain_Lock : Lock_Type;
      Coord      : AHT.TLS_Sync.Coordinator_Type;

      Engine_Dead : Boolean := False;
      Death_Reason : AHT.Bytes.Buffer;
      --  Guarded by SSL_Lock. Set (before the lock is released) when
      --  SSL_get_error reports SSL_ERROR_SSL/SSL_ERROR_SYSCALL or a
      --  drain fails — OpenSSL forbids further I/O on the SSL after a
      --  fatal result, so every engine call checks this first. The
      --  reason is kept so the operations rejected AFTERWARDS can
      --  report what actually killed the session rather than a bare
      --  "engine is dead" (the task that hit the original failure is
      --  often not the one the caller sees fail).
   end record;

   procedure Free_TCP is new Ada.Unchecked_Deallocation
     (AHT.Transport.TCP.TCP_Transport, TCP_Access);
   procedure Free_State is new Ada.Unchecked_Deallocation
     (Backend_State, Backend_State_Access);

   ---------------------------------------------------------------
   --  Small helpers
   ---------------------------------------------------------------

   --  Effective absolute bound for the operation: its mirrored
   --  deadline, or effectively-never when none is set (Time_Last works
   --  in both `delay until` and the TCP deadline-explicit calls).
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

   --  Timed lock seize, then abort re-check. What names the wait in
   --  the timeout message.
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

   --  Poison the session after a fatal error: latch Fatal (waking a
   --  parked waiter), poison the inner TCP (waking selector waiters
   --  with EOF/EPIPE) — the openssl analogue of the mbedtls backend's
   --  Drop_Connection. Engine_Dead is latched separately, under
   --  SSL_Lock, by the code that discovered the fatality.
   procedure Drop_Connection (St : Backend_State_Access) is
   begin
      St.Coord.Latch_Fatal;
      begin
         St.TCP.Poison;
      exception
         when others => null;
      end;
   end Drop_Connection;

   --  Mark the engine dead from a context that does NOT hold SSL_Lock
   --  (drain failures). Unconditional seize: lock holds are bounded by
   --  in-memory work, never a network wait.
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

   ---------------------------------------------------------------
   --  Phase B — drain WBIO ciphertext to the wire
   ---------------------------------------------------------------

   --  Drain everything pending in WBIO to the TCP transport, in wire
   --  order (extraction happens under Drain_Lock). Bounded by the
   --  calling operation's deadline. Any failure here is fail-closed:
   --  ciphertext may be half-sent, so the engine is dead and the
   --  session poisoned before the exception propagates.
   procedure Drain_Output
     (St     : Backend_State_Access;
      DL     : Ada.Real_Time.Time;
      Epoch0 : Epoch_Type;
      Where  : String)
   is
      Buf : AHT.Bytes.Byte_Array (1 .. Chunk_Max);
      Got : C.int;
   begin
      Seize (St.Drain_Lock, St, DL, Epoch0, Where, "output drain lock");
      begin
         loop
            Seize (St.SSL_Lock, St, DL, Epoch0, Where, "engine lock");
            declare
               Pending : constant C.size_t :=
                 OBIO.Ctrl_Pending (St.WBio);
            begin
               if Pending = 0 then
                  St.SSL_Lock.Release;
                  exit;
               end if;
               Got := OBIO.Read
                 (St.WBio, Buf'Address,
                  C.int (C.size_t'Min (Pending, Chunk_Max)));
            end;
            St.SSL_Lock.Release;
            if Got <= 0 then
               raise TLS_Error
                 with Where & ": BIO_read from output BIO failed";
            end if;
            St.TCP.Write (Buf (1 .. Natural (Got)), Deadline => DL);
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
   --  Feed — get more inbound ciphertext into RBIO (or wait for it)
   ---------------------------------------------------------------

   --  Called when an engine call returned WANT_READ. Claims the feeder
   --  role and performs the single TCP.Read itself, or — when the
   --  other direction's task owns the claim — parks on the latch until
   --  something changes. Either way the caller re-checks abort/EOF/
   --  Fatal and retries its engine call. The feeder claim is released
   --  on EVERY exit path.
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
         --  The other task is feeding (or EOF/Fatal already latched —
         --  Try_Claim_Or_Arm pre-fires the latch then). Park bounded.
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

      --  We are the feeder.
      begin
         declare
            Buf  : AHT.Bytes.Byte_Array (1 .. Chunk_Max);
            Last : Natural;
         begin
            St.TCP.Read (Buf, Last, Deadline => DL);
            if Last = 0 then
               --  TCP EOF: flip RBIO to hard-EOF so the next engine
               --  call classifies it (truncation error or clean
               --  ZERO_RETURN) instead of spinning on WANT_READ.
               Seize (St.SSL_Lock, St, DL, Epoch0, Where, "engine lock");
               declare
                  Ignore : C.long;
               begin
                  Ignore := AHT.Openssl.Glue.Set_Mem_EOF_Return
                    (St.RBio, 0);
               end;
               St.SSL_Lock.Release;
               St.Coord.Latch_EOF;
            else
               Seize (St.SSL_Lock, St, DL, Epoch0, Where, "engine lock");
               declare
                  Wrote : constant C.int :=
                    OBIO.Write (St.RBio, Buf'Address, C.int (Last));
               begin
                  St.SSL_Lock.Release;
                  if Wrote /= C.int (Last) then
                     raise TLS_Error
                       with Where & ": BIO_write to input BIO failed";
                  end if;
               end;
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

   --  Runs exactly one SSL_read/SSL_write under SSL_Lock with the
   --  documented discipline: Engine_Dead check, ERR_clear_error, the
   --  call, SSL_get_error immediately, error-queue capture on a fatal
   --  result (latching Engine_Dead before the lock is released), and
   --  a WBIO-pending sample. On a fatal result the session is poisoned
   --  and TLS_Error raised; otherwise Err_Class tells the caller what
   --  to do next.
   procedure Engine_Call
     (St        : Backend_State_Access;
      Op        : Engine_Op;
      Buf       : System.Address;
      Len       : C.int;
      DL        : Ada.Real_Time.Time;
      Epoch0    : Epoch_Type;
      Where     : String;
      Ret       : out C.int;
      Err_Class : out C.int;
      Pending   : out Natural)
   is
      Fatal_Msg : AHT.Bytes.Buffer;  --  built only on the fatal path
      Is_Fatal  : Boolean := False;
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

      AHT.Openssl.Err.Clear_Error;
      case Op is
         when Op_Read  => Ret := OSSL.Read  (St.SSL, Buf, Len);
         when Op_Write => Ret := OSSL.Write (St.SSL, Buf, Len);
      end case;

      if Ret > 0 then
         Err_Class := OSSL.ERROR_NONE;
      else
         Err_Class := OSSL.Get_Error (St.SSL, Ret);
      end if;

      if Err_Class = OSSL.ERROR_SSL
        or else Err_Class = OSSL.ERROR_SYSCALL
      then
         Is_Fatal := True;
         St.Engine_Dead := True;
         Fatal_Msg.Set (AHT.Openssl.Err.Drain);
         St.Death_Reason.Set
           (Where & " class" & C.int'Image (Err_Class) & ": "
            & (if Fatal_Msg.Is_Empty then "no detail queued"
               else Fatal_Msg.To_String));
      end if;

      Pending := Natural (OBIO.Ctrl_Pending (St.WBio));
      St.SSL_Lock.Release;

      if Is_Fatal then
         Drop_Connection (St);
         raise TLS_Error
           with Where & ": OpenSSL error (class"
             & C.int'Image (Err_Class) & "): "
             & (if Fatal_Msg.Is_Empty then "no detail queued"
                else Fatal_Msg.To_String);
      end if;
   end Engine_Call;

   ---------------------------------------------------------------
   --  Connect
   ---------------------------------------------------------------

   --  Release everything a failed Connect allocated, leaving the
   --  object retryable. Single-task: no reader exists before Connect
   --  returns.
   procedure Release_State (Self : in out TLS_Transport) is
      St     : Backend_State_Access renames Self.State;
      Ignore : C.int;
   begin
      if St = null then
         return;
      end if;
      if St.SSL /= System.Null_Address then
         OSSL.Free (St.SSL);          --  frees both BIOs if transferred
         St.SSL := System.Null_Address;
      end if;
      if not St.Bios_Transferred then
         if St.RBio /= System.Null_Address then
            Ignore := OBIO.Free (St.RBio);
         end if;
         if St.WBio /= System.Null_Address then
            Ignore := OBIO.Free (St.WBio);
         end if;
      end if;
      St.RBio := System.Null_Address;
      St.WBio := System.Null_Address;
      if St.Ctx /= System.Null_Address then
         OSSL.CTX_Free (St.Ctx);
         St.Ctx := System.Null_Address;
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

      procedure Fail (Where : String; Extra : String := "")
        with No_Return;

      procedure Fail (Where : String; Extra : String := "") is
         Queue : constant String := AHT.Openssl.Err.Drain;
      begin
         Release_State (Self);
         raise TLS_Error
           with Where
             & (if Extra = "" then "" else ": " & Extra)
             & (if Queue = "" then "" else " [" & Queue & "]");
      end Fail;

      function Is_IP_Literal (H : String) return Boolean is
         Ignore : GNAT.Sockets.Inet_Addr_Type;
      begin
         Ignore := GNAT.Sockets.Inet_Addr (H);
         return True;
      exception
         when GNAT.Sockets.Socket_Error => return False;
      end Is_IP_Literal;

      HS_Bound : constant Ada.Real_Time.Time :=
        (if Handshake_Deadline = Duration'Last
         then Ada.Real_Time.Time_Last
         else Clock + To_Time_Span (Handshake_Deadline));

      Ret : C.int;
   begin
      if Self.Used or else Self.Connected then
         --  Single-use after success (see the spec): a completed
         --  session — live or poisoned — is never reconnected in
         --  place; a WSS receiver may still be unwinding through Read.
         raise TLS_Error with "TLS transport already connected";
      end if;

      --  Consumer-facing LibreSSL/1.1 guard (the 3.0-only version
      --  symbols also make the LINK fail, but a runtime check reports
      --  it as a proper TLS_Error instead of a linker mystery).
      if AHT.Openssl.Version.Major < 3 then
         raise TLS_Error
           with "TLS connect: linked library is not OpenSSL 3 ("
             & AHT.Openssl.Version.Version_String & ")";
      end if;

      Self.State := new Backend_State;

      --  Everything from here on runs inside a cleanup block: ANY
      --  exception — the expected Fail/TLS paths, but equally an
      --  allocation failure, a filesystem error from the CA-kind
      --  classification, or Storage_Error — must release the state so
      --  the object stays retryable. Release_State is idempotent
      --  (it nulls Self.State), so the inner Fail paths that already
      --  released are unaffected.
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

      --  1. Plain TCP first (fresh per attempt — failed Connect frees
      --     it and the object stays retryable).
      Self.State.TCP := new AHT.Transport.TCP.TCP_Transport;
      AHT.Transport.TCP.Connect
        (Self.State.TCP.all, Host, Port,
         Connect_Timeout => Connect_Timeout,
         Resolve_Timeout => Resolve_Timeout);

      --  2. SSL_CTX: TLS client, min TLS 1.2, no renegotiation,
      --     verification per Insecure/CA_Path.
      Self.State.Ctx := OSSL.CTX_New (OSSL.TLS_Client_Method);
      if Self.State.Ctx = System.Null_Address then
         Fail ("TLS connect (SSL_CTX_new)");
      end if;

      if AHT.Openssl.Glue.CTX_Set_Min_Proto_Version
           (Self.State.Ctx, OSSL.TLS_1_2_VERSION) /= 1
      then
         Fail ("TLS connect (set_min_proto_version)");
      end if;

      declare
         Ignore : Interfaces.Unsigned_64;
      begin
         Ignore := OSSL.CTX_Set_Options
           (Self.State.Ctx, OSSL.OP_NO_RENEGOTIATION);
      end;

      if Insecure then
         OSSL.CTX_Set_Verify
           (Self.State.Ctx, OSSL.VERIFY_NONE, System.Null_Address);
      else
         OSSL.CTX_Set_Verify
           (Self.State.Ctx, OSSL.VERIFY_PEER, System.Null_Address);
         if CA_Path = "" and then CA_PEM = "" then
            --  Platform trust store (deliberate difference from the
            --  mbedtls backend, which configures no default trust).
            if OSSL.CTX_Set_Default_Verify_Paths (Self.State.Ctx) /= 1
            then
               Fail ("TLS connect (set_default_verify_paths)");
            end if;
         elsif CA_PEM /= "" then
            declare
               --  Copied so the bytes handed to OpenSSL are
               --  contiguous and outlive the call; BIO_new_mem_buf
               --  does not take ownership, and the glue frees its BIO
               --  before returning, so this may be a local.
               Buf : aliased C.char_array := C.To_C (CA_PEM, False);
               N   : constant C.int :=
                 AHT.Openssl.Glue.CTX_Load_CA_PEM
                   (Self.State.Ctx, Buf'Address, Buf'Length);
            begin
               if N <= 0 then
                  Fail ("TLS connect (CA_PEM load)",
                        (case N is
                            when -1 => "allocation failed",
                            when -2 =>
                              "no certificate found in the supplied PEM",
                            when -3 =>
                              "trailing or malformed data after the last "
                              & "certificate; the bundle is rejected "
                              & "whole rather than in part",
                            when -4 =>
                              "certificate could not be added to the "
                              & "trust store",
                            when others => "code" & C.int'Image (N)));
               end if;
            end;
         else
            declare
               Path_C : aliased C.char_array := C.To_C (CA_Path);
               Is_Dir : constant Boolean :=
                 Ada.Directories.Exists (CA_Path)
                   and then Ada.Directories.Kind (CA_Path)
                            = Ada.Directories.Directory;
            begin
               if Is_Dir then
                  Ret := OSSL.CTX_Load_Verify_Locations
                    (Self.State.Ctx,
                     CAfile => System.Null_Address,
                     CApath => Path_C'Address);
               else
                  Ret := OSSL.CTX_Load_Verify_Locations
                    (Self.State.Ctx,
                     CAfile => Path_C'Address,
                     CApath => System.Null_Address);
               end if;
            end;
            if Ret /= 1 then
               Fail ("TLS connect (CA load """ & CA_Path & """)");
            end if;
         end if;
      end if;

      --  3. SSL + the two memory BIOs. RBIO starts retryable-on-empty
      --     (eof_return -1); Feed flips it to hard-EOF at TCP EOF.
      Self.State.SSL := OSSL.New_SSL (Self.State.Ctx);
      if Self.State.SSL = System.Null_Address then
         Fail ("TLS connect (SSL_new)");
      end if;

      Self.State.RBio := OBIO.New_BIO (OBIO.S_Mem);
      Self.State.WBio := OBIO.New_BIO (OBIO.S_Mem);
      if Self.State.RBio = System.Null_Address
        or else Self.State.WBio = System.Null_Address
      then
         Fail ("TLS connect (BIO_new)");
      end if;
      declare
         Ignore : C.long;
      begin
         Ignore := AHT.Openssl.Glue.Set_Mem_EOF_Return
           (Self.State.RBio, -1);
      end;

      OSSL.Set_Bio (Self.State.SSL, Self.State.RBio, Self.State.WBio);
      Self.State.Bios_Transferred := True;

      --  4. Identity: DNS names get SNI + hostname verification;
      --     IP literals get IP-SAN verification and no SNI.
      declare
         Host_C : aliased C.char_array := C.To_C (Host);
      begin
         if Is_IP_Literal (Host) then
            if not Insecure
              and then AHT.Openssl.X509.Verify_Param_Set1_IP_ASC
                (OSSL.Get0_Param (Self.State.SSL), Host_C'Address) /= 1
            then
               Fail ("TLS connect (set1_ip """ & Host & """)");
            end if;
         else
            if AHT.Openssl.Glue.Set_TLSext_Host_Name
                 (Self.State.SSL, Host_C'Address) /= 1
            then
               Fail ("TLS connect (SNI """ & Host & """)");
            end if;
            if not Insecure
              and then OSSL.Set1_Host
                (Self.State.SSL, Host_C'Address) /= 1
            then
               Fail ("TLS connect (set1_host """ & Host & """)");
            end if;
         end if;
      end;

      OSSL.Set_Connect_State (Self.State.SSL);

      --  5. Handshake pump. Single-task, so no locks: run the engine,
      --     drain WBIO to the wire, feed RBIO from the wire on
      --     WANT_READ — every network step bounded by HS_Bound.
      Handshake :
      loop
         AHT.Openssl.Err.Clear_Error;
         Ret := OSSL.Do_Handshake (Self.State.SSL);

         declare
            Class : constant C.int :=
              (if Ret = 1 then OSSL.ERROR_NONE
               else OSSL.Get_Error (Self.State.SSL, Ret));
            Buf   : AHT.Bytes.Byte_Array (1 .. Chunk_Max);
            Got   : C.int;
            Last  : Natural;
         begin
            --  Drain whatever this step produced (ClientHello, ...).
            loop
               declare
                  Pending : constant C.size_t :=
                    OBIO.Ctrl_Pending (Self.State.WBio);
               begin
                  exit when Pending = 0;
                  Got := OBIO.Read
                    (Self.State.WBio, Buf'Address,
                     C.int (C.size_t'Min (Pending, Chunk_Max)));
               end;
               if Got <= 0 then
                  Fail ("TLS handshake (drain)");
               end if;
               Self.State.TCP.Write
                 (Buf (1 .. Natural (Got)), Deadline => HS_Bound);
            end loop;

            exit Handshake when Ret = 1;

            if Class = OSSL.ERROR_WANT_READ then
               Self.State.TCP.Read (Buf, Last, Deadline => HS_Bound);
               if Last = 0 then
                  Fail ("TLS handshake",
                        "peer closed during handshake");
               end if;
               if OBIO.Write (Self.State.RBio, Buf'Address, C.int (Last))
                 /= C.int (Last)
               then
                  Fail ("TLS handshake (feed)");
               end if;
            else
               --  Fatal handshake failure; enrich certificate
               --  verification errors with the X509 reason.
               declare
                  V : constant C.long :=
                    OSSL.Get_Verify_Result (Self.State.SSL);

                  function Verify_Text return String is
                     use Interfaces.C.Strings;
                     P : constant System.Address :=
                       AHT.Openssl.X509.Verify_Cert_Error_String (V);
                     function To_Ptr is new Ada.Unchecked_Conversion
                       (System.Address, chars_ptr);
                  begin
                     return Value (To_Ptr (P));
                  end Verify_Text;
               begin
                  if V /= 0 then
                     Fail ("TLS handshake",
                           "certificate verify failed: " & Verify_Text);
                  else
                     Fail ("TLS handshake",
                           "error class" & C.int'Image (Class));
                  end if;
               end;
            end if;
         end;
      end loop Handshake;

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
         DL     : constant Ada.Real_Time.Time :=
           Bound (Self.Has_Read_Deadline, Self.Read_Deadline);
         Epoch0 : constant Epoch_Type := St.Coord.Abort_Epoch;
         Ret     : C.int;
         Class   : C.int;
         Pending : Natural;
      begin
         loop
            Engine_Call
              (St, Op_Read, Data'Address, C.int (Data'Length),
               DL, Epoch0, "TLS read", Ret, Class, Pending);

            --  Phase B: ship anything the engine produced (KeyUpdate
            --  replies, ticket acks) before deciding.
            if Pending > 0 then
               Drain_Output (St, DL, Epoch0, "TLS read");
            end if;

            if Ret > 0 then
               --  Phase C: a fatal latched by the OTHER task (its
               --  drain may have carried our traffic) forbids success.
               if St.Coord.Fatal then
                  raise TLS_Error
                    with "TLS read: session failed concurrently";
               end if;
               Last := Data'First + Natural (Ret) - 1;
               return;
            elsif Class = OSSL.ERROR_ZERO_RETURN then
               --  Proper close_notify — clean EOF, mirroring the TCP
               --  "Last = 0" contract. (An abrupt TCP EOF surfaces as
               --  SSL_ERROR_SSL/unexpected-EOF inside Engine_Call and
               --  raises TLS_Error: truncation is never a clean EOF
               --  on this backend.)
               Last := 0;
               return;
            elsif Class = OSSL.ERROR_WANT_READ then
               Feed (St, DL, Epoch0, "TLS read");
            else
               --  Defensive: Engine_Call already poisons the fatal
               --  classes, so nothing should reach here — but an
               --  unclassifiable state means the stream's integrity is
               --  unknown, so fail closed rather than stay usable.
               Latch_Engine_Dead
                 (St, "TLS read: unexpected engine state (class"
                  & C.int'Image (Class) & ")");
               Drop_Connection (St);
               raise TLS_Error
                 with "TLS read: unexpected engine state (class"
                   & C.int'Image (Class) & ")";
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
         DL     : constant Ada.Real_Time.Time :=
           Bound (Self.Has_Write_Deadline, Self.Write_Deadline);
         Epoch0 : constant Epoch_Type := St.Coord.Abort_Epoch;
         Cursor  : Natural := Data'First;
         Ret     : C.int;
         Class   : C.int;
         Pending : Natural;
      begin
         while Cursor <= Data'Last loop
            Engine_Call
              (St, Op_Write, Data (Cursor)'Address,
               C.int (Data'Last - Cursor + 1),
               DL, Epoch0, "TLS write", Ret, Class, Pending);

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
               elsif Class = OSSL.ERROR_WANT_READ then
                  --  Mid-write post-handshake message: get input, by
                  --  self-feeding or waiting on the reader — bounded
                  --  by OUR (write) deadline either way.
                  Feed (St, DL, Epoch0, "TLS write");
                  if St.Coord.EOF then
                     raise TLS_Error
                       with "TLS write: peer closed mid-record";
                  end if;
               else
                  --  WANT_WRITE cannot happen against a growing
                  --  memory BIO; anything else is unclassifiable.
                  raise TLS_Error
                    with "TLS write: unexpected engine state (class"
                      & C.int'Image (Class) & ")";
               end if;
            exception
               when E : TLS_Error | AHT.Transport.Timeout_Error
                  | AHT.Transport.Aborted_Error
                  | AHT.Transport.Transport_Error =>
                  --  Fail-closed: SSL_write may already have consumed
                  --  plaintext / queued ciphertext, so any failure
                  --  past Phase A poisons the session (the mid-record
                  --  write-timeout rule of the transport contract).
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

      --  Block 1 (best-effort): SSL_shutdown + final drain — skipped
      --  entirely for a session that died fatally (OpenSSL forbids
      --  shutdown after SSL_ERROR_SSL/SYSCALL, and another record on
      --  a desynchronised stream helps nobody). Close is documented
      --  single-threaded, so plain reads of Engine_Dead are fine.
      begin
         if Self.Connected
           and then not St.Coord.Fatal
           and then not St.Engine_Dead
           and then St.SSL /= System.Null_Address
         then
            --  SSL_shutdown has its OWN result protocol: 0 = our
            --  close_notify queued (do NOT consult SSL_get_error),
            --  1 = already complete, < 0 = give up (best-effort; no
            --  second call, WANT_* abandoned).
            Ignore := OSSL.Shutdown (St.SSL);
            if Ignore >= 0 then
               declare
                  Buf : AHT.Bytes.Byte_Array (1 .. Chunk_Max);
                  Got : C.int;
               begin
                  loop
                     declare
                        Pending : constant C.size_t :=
                          OBIO.Ctrl_Pending (St.WBio);
                     begin
                        exit when Pending = 0;
                        Got := OBIO.Read
                          (St.WBio, Buf'Address,
                           C.int (C.size_t'Min (Pending, Chunk_Max)));
                     end;
                     exit when Got <= 0;
                     St.TCP.Write (Buf (1 .. Natural (Got)));
                  end loop;
               end;
            end if;
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
         OSSL.Free (St.SSL);          --  frees both transferred BIOs
         St.SSL := System.Null_Address;
      end if;
      if St.Ctx /= System.Null_Address then
         OSSL.CTX_Free (St.Ctx);
         St.Ctx := System.Null_Address;
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
      --  Mirror only: the engine bounds every read-side wait by this
      --  absolute (computed once here — the budget is measured from
      --  this call). The TCP compound deadlines are never consulted:
      --  all engine TCP calls pass their bound explicitly.
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
   end Set_Write_Deadline;

   overriding procedure Abort_Pending (Self : in out TLS_Transport) is
   begin
      if Self.State = null then
         return;
      end if;
      --  Wake selector waiters (a feeder inside TCP.Read, a drain
      --  inside TCP.Write) AND the latch waiter; the epoch makes the
      --  woken operation raise Aborted_Error. Non-sticky: operations
      --  started after this call snapshot the new epoch.
      Self.State.Coord.Bump_Abort;
      begin
         Self.State.TCP.Abort_Pending;
      exception
         when others => null;
      end;
   end Abort_Pending;

end AHT.Transport.TLS;
