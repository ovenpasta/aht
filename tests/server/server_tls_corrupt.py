#!/usr/bin/env python3
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
"""Corrupted-record TLS fixture.

Listens on 127.0.0.1:8773. Per connection: TLS handshake, send a valid
banner record, then write a bogus application-data record straight to
the file descriptor, bypassing the SSL layer, so the bytes reach the
client's TLS engine as a record whose MAC cannot verify.

The client must treat that as session-fatal: Read raises TLS_Error
and the transport stops reporting Is_Connected. Both backends are held
to this (test_tls_corrupt).

Prints `READY tlscorrupt 127.0.0.1:8773` once listening.
"""

from __future__ import annotations

import os
import socket
import ssl
import sys

HOST = "127.0.0.1"
PORT = 8773
BANNER = b"BANNER-BEFORE-CORRUPTION"

# application_data (0x17), version 0x0303, length 0x0020, then 32
# bytes that cannot authenticate. The header is well-formed so the
# peer reads a whole record and fails its integrity check.
CORRUPT_RECORD = b"\x17\x03\x03\x00\x20" + bytes(32)

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
    print(f"READY tlscorrupt {HOST}:{PORT}", flush=True)

    while True:
        conn, _ = lsock.accept()
        try:
            tls = ctx.wrap_socket(conn, server_side=True)
            tls.sendall(BANNER)
            # Straight to the fd, bypassing the SSL layer; os.write may
            # write short, and a partial record would test framing.
            written = 0
            while written < len(CORRUPT_RECORD):
                n = os.write(tls.fileno(), CORRUPT_RECORD[written:])
                if n <= 0:
                    raise OSError("short write injecting the record")
                written += n
            # Hold the connection open: the client must fail on the bad
            # record itself, not on a close that follows it.
            try:
                tls.recv(1)
            except OSError:
                pass
            tls.close()
        except (OSError, ssl.SSLError):
            try:
                conn.close()
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
