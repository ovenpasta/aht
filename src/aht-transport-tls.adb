with Ada.Directories;
with Interfaces.C;

with AHT.Mbedtls.Error;
with AHT.Mbedtls.Glue;
with AHT.Mbedtls.SSL;
with AHT.Mbedtls.X509;

package body AHT.Transport.TLS is

   use type System.Address;
   use type Interfaces.C.int;
   use type Ada.Directories.File_Kind;

   package C renames Interfaces.C;
   package M renames AHT.Mbedtls.SSL;

   ---------------------------------------------------------------
   --  BIO callbacks
   ---------------------------------------------------------------
   --  mbedTLS calls these to move bytes; they bridge to the inner TCP
   --  transport recovered from the opaque p_bio (Ctx) by address
   --  overlay. An Ada exception must NEVER propagate through the C
   --  frame, so each callback catches it, records which kind it was in
   --  the BIO_Context, and returns a negative MBEDTLS_ERR_* code. The
   --  Ada side (Connect / Read / Write) inspects Last_Error after the
   --  mbedTLS call returns and re-raises the right exception.

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
      BC : BIO_Context with Import, Address => Ctx;
      N  : constant Natural := Natural (Len);
   begin
      if N = 0 then
         return 0;
      end if;
      declare
         Data : AHT.Bytes.Byte_Array (1 .. N)
           with Import, Address => Buf;
      begin
         --  TCP.Write sends all bytes or raises; no partial return.
         BC.TCP.Write (Data);
         return C.int (N);
      end;
   exception
      when AHT.Transport.Timeout_Error =>
         BC.Last_Error := BIO_Timeout;
         return M.ERR_NET_SEND_FAILED;
      when AHT.Transport.Aborted_Error =>
         BC.Last_Error := BIO_Aborted;
         return M.ERR_NET_SEND_FAILED;
      when others =>
         BC.Last_Error := BIO_Transport;
         return M.ERR_NET_SEND_FAILED;
   end Send_CB;

   function Recv_CB
     (Ctx : System.Address;
      Buf : System.Address;
      Len : C.size_t) return C.int
   is
      BC : BIO_Context with Import, Address => Ctx;
      N  : constant Natural := Natural (Len);
   begin
      if N = 0 then
         return 0;
      end if;
      declare
         Data : AHT.Bytes.Byte_Array (1 .. N)
           with Import, Address => Buf;
         Last : Natural;
      begin
         BC.TCP.Read (Data, Last);
         --  Last counts bytes read into Data (Data'First = 1). Last = 0
         --  is a clean peer close → return 0 so mbedTLS sees EOF.
         return C.int (Last);
      end;
   exception
      when AHT.Transport.Timeout_Error =>
         BC.Last_Error := BIO_Timeout;
         return M.ERR_NET_RECV_FAILED;
      when AHT.Transport.Aborted_Error =>
         BC.Last_Error := BIO_Aborted;
         return M.ERR_NET_RECV_FAILED;
      when others =>
         BC.Last_Error := BIO_Transport;
         return M.ERR_NET_RECV_FAILED;
   end Recv_CB;

   ---------------------------------------------------------------
   --  Error mapping + context teardown
   ---------------------------------------------------------------

   --  Turn a negative mbedTLS return into an Ada exception. A BIO
   --  callback error (deadline/abort/transport) takes precedence over
   --  the raw mbedTLS code so callers see Timeout_Error / Aborted_Error
   --  / Transport_Error exactly as the TCP transport would raise them.
   procedure Raise_From_Code
     (Self : in out TLS_Transport; Code : C.int; Where : String)
     with No_Return;

   procedure Raise_From_Code
     (Self : in out TLS_Transport; Code : C.int; Where : String)
   is
      Kind : constant BIO_Error_Kind := Self.BIO.Last_Error;
   begin
      Self.BIO.Last_Error := BIO_None;
      case Kind is
         when BIO_Timeout =>
            raise AHT.Transport.Timeout_Error
              with Where & ": deadline expired";
         when BIO_Aborted =>
            raise AHT.Transport.Aborted_Error
              with Where & ": aborted";
         when BIO_Transport =>
            raise AHT.Transport.Transport_Error
              with Where & ": underlying transport failed";
         when BIO_None =>
            raise TLS_Error
              with Where & ": mbedTLS error" & C.int'Image (Code)
                & " (" & AHT.Mbedtls.Error.Strerror (Code) & ")";
      end case;
   end Raise_From_Code;

   procedure Free_Contexts (Self : in out TLS_Transport) is
   begin
      --  Free ssl before config/ca (it references them during use, not
      --  during free, but this keeps the order least-surprising).
      if Self.SSL /= System.Null_Address then
         AHT.Mbedtls.Glue.SSL_Free (Self.SSL);
         Self.SSL := System.Null_Address;
      end if;
      if Self.Conf /= System.Null_Address then
         AHT.Mbedtls.Glue.Config_Free (Self.Conf);
         Self.Conf := System.Null_Address;
      end if;
      if Self.CA_Cert /= System.Null_Address then
         AHT.Mbedtls.Glue.X509_CRT_Free (Self.CA_Cert);
         Self.CA_Cert := System.Null_Address;
      end if;
      if Self.CTR_DRBG /= System.Null_Address then
         AHT.Mbedtls.Glue.CTR_DRBG_Free (Self.CTR_DRBG);
         Self.CTR_DRBG := System.Null_Address;
      end if;
      if Self.Entropy /= System.Null_Address then
         AHT.Mbedtls.Glue.Entropy_Free (Self.Entropy);
         Self.Entropy := System.Null_Address;
      end if;
   end Free_Contexts;

   --  Tear a desynchronised session down hard. A write that fails partway
   --  through a TLS record (timeout/abort/transport error reported by
   --  Send_CB) may already have put some bytes of that record on the wire
   --  while mbedTLS believes none were sent — the outbound record stream
   --  is now corrupt and the session must never be reused. Mark it closed
   --  (so any further Read/Write raises) and poison the underlying TCP
   --  *without* a close_notify, which would only push another record onto
   --  the broken stream. We Poison rather than Close the inner TCP because
   --  a WSS receiver task may still be parked in Check_Selector on it; Close
   --  would race that selector (GNAT forbids Close_Selector while a task
   --  waits on it). Poison just shuts the socket down (waking the reader
   --  with EOF) and leaves the FD/selector reclaim to the eventual Close.
   --  The mbedTLS contexts are left for the eventual Close/finalization to
   --  free; Last_Error is preserved so the caller's Raise_From_Code still
   --  reports the originating exception.
   procedure Drop_Connection (Self : in out TLS_Transport) is
   begin
      Self.Connected := False;
      begin
         Self.TCP.Poison;
      exception
         when others => null;
      end;
   end Drop_Connection;

   ---------------------------------------------------------------
   --  Connect
   ---------------------------------------------------------------

   procedure Connect
     (Self               : in out TLS_Transport;
      Host               : String;
      Port               : AHT.URL.Port_Number;
      Insecure           : Boolean := False;
      CA_Path            : String  := "";
      Connect_Timeout    : Duration := Duration'Last;
      Handshake_Deadline : Duration := Duration'Last)
   is
      Ret : C.int;

      procedure Fail (Code : C.int; Where : String) with No_Return is
      begin
         Free_Contexts (Self);
         begin
            Self.TCP.Close;
         exception
            when others => null;
         end;
         Raise_From_Code (Self, Code, Where);
      end Fail;

   begin
      if Self.Connected then
         raise TLS_Error with "TLS transport already connected";
      end if;

      --  A TLS transport is single-use. We must NOT free/reinitialize the
      --  mbedTLS contexts in place to "recycle" a dropped session: a WSS
      --  receiver task may still be unwinding through TLS.Read / the BIO
      --  callbacks, so freeing SSL/config/CA/RNG here would be a
      --  use-after-free. A poisoned object (Drop_Connection flipped
      --  Connected False but left the inner TCP poisoned and the contexts
      --  live for Close/finalization) is therefore rejected by the inner
      --  AHT.Transport.TCP.Connect guard below — its socket is still owned,
      --  so TCP.Connect raises before any TLS state is touched. The caller
      --  must Close (after every read/write task has quiesced) and use a
      --  fresh transport to reconnect.

      --  1. Plain TCP first: DNS multi-candidate fallback, the
      --     selector, the compound deadline and Abort_Pending all come
      --     from AHT.Transport.TCP and are reused unchanged.
      AHT.Transport.TCP.Connect
        (Self.TCP, Host, Port, Connect_Timeout => Connect_Timeout);
      Self.BIO.TCP := Self.TCP'Unchecked_Access;
      Self.BIO.Last_Error := BIO_None;

      --  2. Allocate the mbedTLS contexts (sized by the C glue).
      Self.Entropy  := AHT.Mbedtls.Glue.Entropy_New;
      Self.CTR_DRBG := AHT.Mbedtls.Glue.CTR_DRBG_New;
      Self.Conf     := AHT.Mbedtls.Glue.Config_New;
      Self.SSL      := AHT.Mbedtls.Glue.SSL_New;
      if Self.Entropy = System.Null_Address
        or else Self.CTR_DRBG = System.Null_Address
        or else Self.Conf = System.Null_Address
        or else Self.SSL = System.Null_Address
      then
         Free_Contexts (Self);
         begin
            Self.TCP.Close;
         exception
            when others => null;
         end;
         raise TLS_Error with "TLS connect: context allocation failed";
      end if;

      --  3. Seed the RNG from the entropy source.
      Ret := AHT.Mbedtls.Glue.CTR_DRBG_Seed (Self.CTR_DRBG, Self.Entropy);
      if Ret /= 0 then
         Fail (Ret, "TLS connect (ctr_drbg_seed)");
      end if;

      --  4. Client/stream/default config.
      Ret := M.Config_Defaults
        (Self.Conf, M.IS_CLIENT, M.TRANSPORT_STREAM, M.PRESET_DEFAULT);
      if Ret /= 0 then
         Fail (Ret, "TLS connect (config_defaults)");
      end if;

      --  5. Verification mode + optional CA chain.
      if Insecure then
         M.Conf_Authmode (Self.Conf, M.VERIFY_NONE);
      else
         M.Conf_Authmode (Self.Conf, M.VERIFY_REQUIRED);
      end if;

      if CA_Path /= "" then
         Self.CA_Cert := AHT.Mbedtls.Glue.X509_CRT_New;
         if Self.CA_Cert = System.Null_Address then
            Fail (0, "TLS connect (x509 alloc)");
         end if;
         declare
            Path_C : aliased C.char_array := C.To_C (CA_Path);
            Is_Dir : constant Boolean :=
              Ada.Directories.Exists (CA_Path)
                and then Ada.Directories.Kind (CA_Path)
                         = Ada.Directories.Directory;
         begin
            if Is_Dir then
               Ret := AHT.Mbedtls.X509.CRT_Parse_Path
                 (Self.CA_Cert, Path_C'Address);
            else
               Ret := AHT.Mbedtls.X509.CRT_Parse_File
                 (Self.CA_Cert, Path_C'Address);
            end if;
         end;
         --  parse_* returns 0 on full success, >0 if some certs in the
         --  file failed, <0 on hard error. Require a clean parse.
         if Ret /= 0 then
            Fail (Ret, "TLS connect (CA parse """ & CA_Path & """)");
         end if;
         M.Conf_CA_Chain (Self.Conf, Self.CA_Cert, System.Null_Address);
      end if;

      --  6. Point config RNG at CTR_DRBG, build ssl from config.
      AHT.Mbedtls.Glue.Conf_RNG (Self.Conf, Self.CTR_DRBG);
      Ret := M.Setup (Self.SSL, Self.Conf);
      if Ret /= 0 then
         Fail (Ret, "TLS connect (ssl_setup)");
      end if;

      --  7. SNI / cert-name hostname.
      declare
         Host_C : aliased C.char_array := C.To_C (Host);
      begin
         Ret := M.Set_Hostname (Self.SSL, Host_C'Address);
         if Ret /= 0 then
            Fail (Ret, "TLS connect (set_hostname)");
         end if;
      end;

      --  8. Wire BIO to our callbacks (blocking; no recv-timeout cb —
      --     the deadline lives in the TCP transport).
      M.Set_Bio
        (Self.SSL, Self.BIO'Address,
         Send_CB'Access, Recv_CB'Access, System.Null_Address);

      --  9. Handshake, optionally bounded by Handshake_Deadline. The
      --     budget is armed on the TCP transport so the BIO recv reads
      --     can't block forever on a stalled peer; a trip surfaces as
      --     Timeout_Error via the Recv_CB → BIO_Timeout → Fail path.
      --     BIO is blocking, but mbedTLS may still hand back
      --     WANT_READ/WANT_WRITE mid-flight; just call again.
      if Handshake_Deadline /= Duration'Last then
         Self.TCP.Set_Read_Deadline (Handshake_Deadline);
      end if;
      loop
         Ret := M.Handshake (Self.SSL);
         exit when Ret = 0;
         if Ret /= M.ERR_WANT_READ and then Ret /= M.ERR_WANT_WRITE then
            Fail (Ret, "TLS handshake");
         end if;
      end loop;

      --  Clear the handshake budget so post-handshake reads start with
      --  no deadline — the caller owns Read deadlines from here on
      --  (HTTP.Client re-arms one per response in Wire_Round_Trip).
      if Handshake_Deadline /= Duration'Last then
         Self.TCP.Set_Read_Deadline (Duration'Last);
      end if;

      Self.Connected := True;
   end Connect;

   ---------------------------------------------------------------
   --  Read / Write
   ---------------------------------------------------------------

   overriding procedure Read
     (Self : in out TLS_Transport;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural)
   is
      Ret : C.int;
   begin
      Last := 0;
      if Data'Length = 0 then
         return;
      end if;
      if not Self.Connected then
         raise AHT.Transport.Transport_Error
           with "TLS read on closed transport";
      end if;

      Self.BIO.Last_Error := BIO_None;
      loop
         Ret := M.Read (Self.SSL, Data'Address, C.size_t (Data'Length));
         exit when Ret /= M.ERR_WANT_READ
           and then Ret /= M.ERR_WANT_WRITE;
      end loop;

      if Ret = M.ERR_PEER_CLOSE_NOTIFY or else Ret = 0 then
         --  Clean TLS shutdown / EOF — mirror the TCP transport's
         --  "Last = 0 means peer closed" contract.
         Last := 0;
         return;
      elsif Ret < 0 then
         Raise_From_Code (Self, Ret, "TLS read");
      end if;

      Last := Data'First + Natural (Ret) - 1;
   end Read;

   overriding procedure Write
     (Self : in out TLS_Transport;
      Data : AHT.Bytes.Byte_Array)
   is
      Cursor : Natural := Data'First;
      Ret    : C.int;
   begin
      if not Self.Connected then
         raise AHT.Transport.Transport_Error
           with "TLS write on closed transport";
      end if;
      if Data'Length = 0 then
         return;
      end if;

      Self.BIO.Last_Error := BIO_None;
      while Cursor <= Data'Last loop
         Ret := M.Write
           (Self.SSL, Data (Cursor)'Address,
            C.size_t (Data'Last - Cursor + 1));
         if Ret = M.ERR_WANT_READ or else Ret = M.ERR_WANT_WRITE then
            null;  --  retry the same cursor
         elsif Ret < 0 then
            --  Any fatal write error means the TLS record stream may be
            --  half-written and irrecoverable, so the session is dropped
            --  before the exception propagates (Codex F1): the transport
            --  reports Is_Connected = False and a retry raises rather than
            --  emitting onto a desynchronised stream.
            Drop_Connection (Self);
            Raise_From_Code (Self, Ret, "TLS write");
         else
            Cursor := Cursor + Natural (Ret);
         end if;
      end loop;
   end Write;

   ---------------------------------------------------------------
   --  Lifecycle / hooks
   ---------------------------------------------------------------

   overriding procedure Close (Self : in out TLS_Transport) is
      Ignore : C.int;
   begin
      if Self.Connected then
         if Self.SSL /= System.Null_Address then
            begin
               --  Best-effort close_notify; drives Send_CB on the way
               --  out. If the peer is already gone the callback simply
               --  records an error and we move on.
               Ignore := M.Close_Notify (Self.SSL);
            exception
               when others => null;
            end;
         end if;
         Self.Connected := False;
      end if;

      begin
         Self.TCP.Close;
      exception
         when others => null;
      end;

      Free_Contexts (Self);
   end Close;

   overriding function Is_Connected (Self : TLS_Transport) return Boolean is
     (Self.Connected);

   overriding procedure Set_Read_Deadline
     (Self     : in out TLS_Transport;
      Deadline : Duration) is
   begin
      Self.TCP.Set_Read_Deadline (Deadline);
   end Set_Read_Deadline;

   overriding procedure Set_Write_Deadline
     (Self     : in out TLS_Transport;
      Deadline : Duration) is
   begin
      Self.TCP.Set_Write_Deadline (Deadline);
   end Set_Write_Deadline;

   overriding procedure Abort_Pending (Self : in out TLS_Transport) is
   begin
      Self.TCP.Abort_Pending;
   end Abort_Pending;

end AHT.Transport.TLS;
