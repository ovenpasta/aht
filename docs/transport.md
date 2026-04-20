# Transport

Packages:

| Unit | Status |
|---|---|
| `AHT.Transport` (abstract) | spec implemented |
| `AHT.Transport.TCP` | stubbed |
| `AHT.Transport.TLS` | stubbed |

## Abstraction

```ada
type Transport_Type is abstract tagged limited null record;

procedure Write (Self, Data : Byte_Array) is abstract;
procedure Read  (Self; Data : out Byte_Array; Last : out Natural) is abstract;
procedure Close (Self) is abstract;
function  Is_Connected (Self) return Boolean is abstract;
```

### Read semantics

`Read` fills `Data` up to its bound, blocking until either:

- some bytes arrive (sets `Last` to the last filled index), or
- the peer closes cleanly (sets `Last := 0`).

It does **not** guarantee filling the entire slice — callers that need
exact byte counts (e.g. `AHT.HTTP.IO.Read_N`) loop until `Last = 0`
(error) or the expected total is reached.

### Shared exception

`AHT.Transport.Transport_Error` is raised by either implementation for
OS-level I/O failures or protocol-level socket errors. TLS adds
`AHT.Transport.TLS.TLS_Error` for mbedTLS-specific failures (invalid
cert chain, handshake failure, bad record, …).

## `AHT.Transport.TCP` — to be implemented

Thin wrapper over `GNAT.Sockets`. Connects by `(Host, Port)`, resolves
the hostname, opens a stream-mode IPv4/IPv6 socket, keeps a
`Stream_Access` for reads/writes. `Close` shuts down gracefully and
releases the socket.

Interaction with `AHT.URL`: `Connect` takes a plain string host, not a
`URL_Type`. The caller passes `URL.Host` (already IPv6-bracketless)
and `URL.Port`. IPv6 literals don't need any bracket handling at the
socket layer — `GNAT.Sockets` accepts the raw address.

## `AHT.Transport.TLS` — to be implemented

Wraps a TCP transport with an mbedTLS SSL context. Lifecycle per
connection:

1. Initialise `mbedtls_{ssl, ssl_config, x509_crt, ctr_drbg, entropy,
   net}` contexts.
2. Seed the DRBG (`mbedtls_ctr_drbg_seed`).
3. Load CA chain — `CA_Path` if supplied, else `/etc/ssl/certs` — via
   `mbedtls_x509_crt_parse_file` / `_path`.
4. `mbedtls_ssl_config_defaults` with client preset, TLS 1.2+
   profile.
5. `mbedtls_ssl_conf_authmode`:
   - `MBEDTLS_SSL_VERIFY_REQUIRED` by default;
   - `MBEDTLS_SSL_VERIFY_NONE` when `Insecure => True` (for self-
     signed test certs).
6. `mbedtls_net_connect` + `mbedtls_ssl_set_bio` binding.
7. `mbedtls_ssl_set_hostname` for SNI.
8. Loop `mbedtls_ssl_handshake` until it returns 0 or an error.
9. `Read` / `Write` delegate to `mbedtls_ssl_read` / `_write`,
   re-entering on `MBEDTLS_ERR_SSL_WANT_READ` / `_WANT_WRITE`.
10. `Close` calls `mbedtls_ssl_close_notify` then frees every context.

Concurrency: each transport instance owns its own mbedTLS state, so
two tasks using separate `TLS_Transport` objects do not interfere.
mbedTLS itself is compiled with `MBEDTLS_THREADING_C +
MBEDTLS_THREADING_PTHREAD` so its internal shared structures are safe
under parallel use.
