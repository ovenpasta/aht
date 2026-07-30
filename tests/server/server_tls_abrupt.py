#!/usr/bin/env python3
"""Abrupt-close TLS fixture for the truncation-policy test.

Listens on 127.0.0.1:8771. For every connection: TLS handshake, send a
short banner, then close the TCP socket WITHOUT the SSL shutdown
handshake — no close_notify ever goes out (the fd is detached and
closed raw, so the ssl module cannot add one). Clients see exactly
what a truncation attack looks like:

    OpenSSL backend  -> TLS_Error (strict-EOF policy)
    mbedTLS backend  -> clean EOF (documented backend difference)

Prints `READY tlsabrupt 127.0.0.1:8771` once listening.
"""

from __future__ import annotations

import os
import socket
import ssl
import sys

HOST = "127.0.0.1"
PORT = 8771
BANNER = b"HELLO-THEN-TRUNCATE"

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

    lsock = socket.create_server((HOST, PORT), reuse_port=False)
    lsock.listen(8)
    print(f"READY tlsabrupt {HOST}:{PORT}", flush=True)

    while True:
        conn, _ = lsock.accept()
        try:
            tls = ctx.wrap_socket(conn, server_side=True)
            tls.sendall(BANNER)
            # Abrupt close: detach the fd from the SSL object and close
            # it raw — nothing can send a close_notify on the way out.
            os.close(tls.detach())
        except (OSError, ssl.SSLError):
            try:
                conn.close()
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
