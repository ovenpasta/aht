#!/usr/bin/env python3
"""AHT deaf-TLS test fixture.

Completes the TLS handshake on 127.0.0.1:8769 and then never reads a
single byte of application data. The listening socket is given a tiny
SO_RCVBUF (inherited by every accepted socket) so a client streaming a
large body fills the kernel buffers and parks almost immediately — which
is exactly what test_tls_timeout's write-poison case needs: the client
arms a short write deadline, the deadline fires mid-record, and the TLS
transport must drop the (now record-desynchronised) session instead of
leaving it reusable.

Unlike server_stall.py (which never sends a ServerHello, so it stalls the
*handshake*), this fixture lets the handshake succeed and only stalls the
post-handshake *write* path. The cert/key are the self-signed pair from
scripts/generate_cert.sh; clients connect with Insecure => True.

Prints `READY tlsdeaf 127.0.0.1:8769` once listening so
tests/run_tests.sh can wait for it instead of racing.
"""

from __future__ import annotations

import os
import socket
import ssl
import sys

HOST = "127.0.0.1"
PORT = 8769

HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "certs", "server.crt")
KEY = os.path.join(HERE, "certs", "server.key")


def main() -> int:
    if not (os.path.exists(CERT) and os.path.exists(KEY)):
        print(
            f"FATAL: missing cert/key ({CERT}, {KEY}); "
            "run scripts/generate_cert.sh first",
            file=sys.stderr,
            flush=True,
        )
        return 2

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT, keyfile=KEY)

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #  Tiny receive buffer (inherited by accepted sockets) so the peer's
    #  large write fills the buffers and parks past its first partial send.
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
    lsock.bind((HOST, PORT))
    lsock.listen(8)

    print(f"READY tlsdeaf {HOST}:{PORT}", flush=True)

    #  Keep every accepted (and handshaked) connection alive, never reading
    #  from it, so the client's write wedges on flow control.
    held: list[ssl.SSLSocket] = []
    try:
        while True:
            conn, _ = lsock.accept()
            try:
                #  do_handshake_on_connect=True (default) drives the TLS
                #  handshake to completion here, so the client reaches the
                #  application-data phase before it starts the big write.
                tls = ctx.wrap_socket(conn, server_side=True)
                held.append(tls)
            except (ssl.SSLError, OSError):
                #  A client that aborts/handshake-fails is fine; keep serving.
                try:
                    conn.close()
                except OSError:
                    pass
    except KeyboardInterrupt:
        pass
    finally:
        for s in held:
            try:
                s.close()
            except OSError:
                pass
        lsock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
