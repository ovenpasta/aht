#!/usr/bin/env python3
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
"""Close-watching TLS fixture for test_tls_close.

Listens on 127.0.0.1:8778 and serves one connection at a time. After
the TLS handshake the client sends one line:

    WATCH <token>   the fixture answers "OK", then reads until the
                    client's stream ends and records how it ended:
                    "close_notify" for an authenticated close, "eof"
                    for a TCP EOF without one, "error <name>" for
                    anything else.
    QUERY <token>   the fixture answers with the recorded result for
                    <token>, or "none", then closes.

Ragged EOFs are not suppressed, so the two endings stay distinct.

Prints `READY tlsclosewatch 127.0.0.1:8778` once listening.
"""

from __future__ import annotations

import os
import socket
import ssl
import sys

HOST = "127.0.0.1"
PORT = 8778

HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "certs", "server.crt")
KEY = os.path.join(HERE, "certs", "server.key")


def read_line(tls: ssl.SSLSocket) -> str:
    data = b""
    while not data.endswith(b"\n"):
        chunk = tls.recv(1)
        if not chunk:
            raise ConnectionError("stream ended before the command line")
        data += chunk
    return data.decode("ascii").strip()


def watch(tls: ssl.SSLSocket) -> str:
    tls.sendall(b"OK\n")
    try:
        while tls.recv(4096):
            pass
        return "close_notify"
    except ssl.SSLEOFError:
        return "eof"
    except (OSError, ssl.SSLError) as exc:
        return f"error {type(exc).__name__}"


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

    results: dict[str, str] = {}

    lsock = socket.create_server((HOST, PORT), reuse_port=False)
    lsock.listen(8)
    print(f"READY tlsclosewatch {HOST}:{PORT}", flush=True)

    while True:
        conn, _ = lsock.accept()
        conn.settimeout(10.0)
        try:
            tls = ctx.wrap_socket(
                conn, server_side=True, suppress_ragged_eofs=False
            )
            command, token = read_line(tls).split(" ", 1)
            if command == "WATCH":
                results[token] = watch(tls)
            elif command == "QUERY":
                tls.sendall(results.get(token, "none").encode() + b"\n")
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
