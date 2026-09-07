#!/usr/bin/env python3
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
"""AHT deaf-TLS test fixture.

Completes the TLS handshake on 127.0.0.1:8769 and then never reads
application data. The listening socket has a tiny SO_RCVBUF, inherited
by every accepted socket, so a client streaming a large body parks
almost at once. test_tls_timeout's write-poison case arms a short
write deadline, which fires mid-record, and the TLS transport must
drop the record-desynchronised session. server_stall.py stalls the
handshake; this fixture stalls the post-handshake write path. Cert and
key are the pair from scripts/generate_cert.sh; clients connect with
Insecure => True.

Prints `READY tlsdeaf 127.0.0.1:8769` once listening.
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
    #  Tiny receive buffer, inherited by accepted sockets, so the peer's
    #  large write parks past its first partial send.
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
    lsock.bind((HOST, PORT))
    lsock.listen(8)

    print(f"READY tlsdeaf {HOST}:{PORT}", flush=True)

    #  Keep every handshaked connection alive and unread, so the
    #  client's write wedges on flow control.
    held: list[ssl.SSLSocket] = []
    try:
        while True:
            conn, _ = lsock.accept()
            try:
                #  wrap_socket completes the handshake here, so the
                #  client reaches application data before the big write.
                tls = ctx.wrap_socket(conn, server_side=True)
                held.append(tls)
            except (ssl.SSLError, OSError):
                #  A client that aborts or fails the handshake is fine.
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
