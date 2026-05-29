with AHT.Bytes;
with AHT.URL;

private with System;
private with AHT.Transport.TCP;

--  TLS transport: mbedTLS does the crypto, layered over the existing
--  GNAT.Sockets TCP transport via custom BIO callbacks
--  (mbedtls_ssl_set_bio). Because the byte I/O still goes through
--  AHT.Transport.TCP, HTTPS/WSS inherit its DNS multi-candidate
--  fallback, compound read deadline, and Abort_Pending for free —
--  Set_Read_Deadline and Abort_Pending below just forward to it.
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
      Handshake_Deadline : Duration := Duration'Last);
   --  TCP-connect to Host:Port, then run the TLS handshake with SNI =
   --  Host. Insecure => peer certificate is not verified (authmode
   --  NONE); otherwise the chain is verified against CA_Path (a PEM
   --  bundle file or a directory of certs) and a verification failure
   --  raises TLS_Error. With CA_Path = "" and not Insecure, only the
   --  platform-default trust applies (none is configured here), so the
   --  handshake will reject — pass a CA bundle or set Insecure.
   --
   --  Connect_Timeout is forwarded to the underlying TCP connect as its
   --  total budget across resolved candidates (see
   --  AHT.Transport.TCP.Connect); exhaustion raises Timeout_Error.
   --  Duration'Last leaves the TCP connect unbounded.
   --
   --  Handshake_Deadline bounds the **TLS handshake only**: it is armed
   --  as a read deadline on the underlying TCP transport just for the
   --  handshake exchange, so a peer that stalls mid-handshake raises
   --  Timeout_Error instead of blocking forever. It does **not** bound
   --  DNS resolution or the TCP connect (those run before the deadline
   --  is armed). The deadline is cleared once the handshake completes,
   --  so post-handshake Read deadlines remain entirely the caller's to
   --  set via Set_Read_Deadline. Duration'Last (the default) leaves the
   --  handshake unbounded.

   overriding procedure Write
     (Self : in out TLS_Transport;
      Data : AHT.Bytes.Byte_Array);

   overriding procedure Read
     (Self : in out TLS_Transport;
      Data : out AHT.Bytes.Byte_Array;
      Last : out Natural);

   overriding procedure Close (Self : in out TLS_Transport);

   overriding function Is_Connected (Self : TLS_Transport) return Boolean;

   overriding procedure Set_Read_Deadline
     (Self     : in out TLS_Transport;
      Deadline : Duration);

   overriding procedure Abort_Pending (Self : in out TLS_Transport);

private

   --  Which Ada exception a BIO callback swallowed, if any. Set by the
   --  send/recv callbacks (Ada exceptions must not cross the C frame),
   --  read back by Connect/Read/Write to re-raise the right exception
   --  after mbedTLS surfaces the corresponding negative return code.
   type BIO_Error_Kind is
     (BIO_None, BIO_Timeout, BIO_Aborted, BIO_Transport);

   --  Passed to mbedtls_ssl_set_bio as the opaque p_bio. The callbacks
   --  recover it from the void* ctx by address overlay.
   type BIO_Context is record
      TCP        : access AHT.Transport.TCP.TCP_Transport;
      Last_Error : BIO_Error_Kind := BIO_None;
   end record;

   type TLS_Transport is new Transport_Type with record
      TCP       : aliased AHT.Transport.TCP.TCP_Transport;
      BIO       : aliased BIO_Context;
      SSL       : System.Address := System.Null_Address;  --  ssl_context*
      Conf      : System.Address := System.Null_Address;  --  ssl_config*
      CTR_DRBG  : System.Address := System.Null_Address;
      Entropy   : System.Address := System.Null_Address;
      CA_Cert   : System.Address := System.Null_Address;  --  x509_crt*
      Connected : Boolean := False;
   end record;

end AHT.Transport.TLS;
