#!/usr/bin/env python3
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  Copyright (C) 2026 Contributors to AHT
#  SPDX-License-Identifier: Apache-2.0
"""Fragmented-record TLS fixture for the Try_Read test.

Listens on 127.0.0.1:8778. Per connection: TLS handshake, then one
application-data record carrying BANNER is captured off the SSL layer
and written to the TCP socket in two pieces. The second piece is held
back until the client sends one byte of application data, so the
client can observe, deterministically, that a partial record is "not
yet" rather than data, and that the remainder completes it. After the
record, the server sends close_notify and closes.

Prints `READY tlsfragment 127.0.0.1:8778` once listening.
"""

from __future__ import annotations

import os
import socket
import ssl
import sys

HOST = "127.0.0.1"
PORT = 8778
BANNER = b"FRAGMENTED-RECORD-BANNER"

HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "certs", "server.crt")
KEY = os.path.join(HERE, "certs", "server.key")


def serve_one(conn: socket.socket, ctx: ssl.SSLContext) -> None:
    # Memory BIOs, so the encrypted record is ours to split: the TCP
    # socket is only ever written by this function.
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_side=True)

    def flush():
        pending = outgoing.read()
        if pending:
            conn.sendall(pending)

    # Drive one SSL operation to completion: send whatever it queued,
    # then feed it more ciphertext from the socket while it wants some.
    def pump(step):
        while True:
            try:
                result = step()
            except ssl.SSLWantReadError:
                flush()
                data = conn.recv(65536)
                if not data:
                    raise ConnectionError("peer closed mid-operation")
                incoming.write(data)
                continue
            flush()
            return result

    pump(tls.do_handshake)

    tls.write(BANNER)
    record = outgoing.read()
    split = len(record) // 2
    conn.sendall(record[:split])

    # The client acknowledges the first fragment with a byte of its
    # own; only then does the rest of the record go out.
    pump(lambda: tls.read(1))
    conn.sendall(record[split:])

    # Send our close_notify and close; unwrap() wants the peer's reply,
    # which a one-way shutdown does not need.
    try:
        tls.unwrap()
    except ssl.SSLWantReadError:
        pass
    flush()
    conn.shutdown(socket.SHUT_RDWR)


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
    print(f"READY tlsfragment {HOST}:{PORT}", flush=True)

    while True:
        conn, _ = lsock.accept()
        conn.settimeout(10.0)
        try:
            serve_one(conn, ctx)
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
