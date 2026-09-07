#!/usr/bin/env python3
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
"""Mid-session corruption under concurrency.

Listens on 127.0.0.1:8776. Per connection, on one thread (an OpenSSL
connection object is not safe for simultaneous use):

  1. TLS handshake.
  2. Send a banner for the client's reader to consume.
  3. Receive at least one client payload: the client's writer is
     active alongside its reader, a fact the test can assert on.
  4. Send OVERLAP, the marker the test looks for, only after (3).
  5. Inject a record whose MAC cannot verify, straight to the fd.
  6. Keep draining until the hold expires or the client goes away, so
     the client's writer never stalls on backpressure.

The hold outlasts the test's writer bound, so only the library
poisoning the session can make that writer fail. Pinned by
test_tls_concurrent_corrupt.

Prints `READY tlsconcurrent 127.0.0.1:8776` once listening.
"""

from __future__ import annotations

import os
import socket
import ssl
import sys
import time

HOST = "127.0.0.1"
PORT = 8776

BANNER = b"CONCURRENT-SESSION-BANNER"
OVERLAP = b"OVERLAP-CONFIRMED"

# Valid record framing, contents that cannot authenticate.
CORRUPT_RECORD = b"\x17\x03\x03\x00\x20" + bytes(32)

WRITER_WAIT = 10.0    # how long to wait for proof the writer is active
POLL = 0.5            # drain granularity once corruption is injected
HOLD = 30.0           # must exceed the test's 20 s writer bound


def handle(conn: socket.socket, ctx: ssl.SSLContext) -> None:
    tls = ctx.wrap_socket(conn, server_side=True)
    try:
        tls.sendall(BANNER)

        # Wait for something the client's writer sent.
        tls.settimeout(WRITER_WAIT)
        saw_writer = False
        try:
            saw_writer = bool(tls.recv(65536))
        except (TimeoutError, OSError):
            saw_writer = False

        if saw_writer:
            # Sent only now, so the marker in the client's read stream
            # means its writer was running concurrently.
            tls.sendall(OVERLAP)
        else:
            print(
                "WARN tlsconcurrent: no client payload before corruption",
                flush=True,
            )

        # Raw fd write, so the SSL layer does not frame these bytes;
        # os.write may write short.
        written = 0
        while written < len(CORRUPT_RECORD):
            n = os.write(tls.fileno(), CORRUPT_RECORD[written:])
            if n <= 0:
                raise OSError("short write injecting the record")
            written += n

        # Keep consuming so the client's writer never blocks on
        # backpressure, and stay open so the client must diagnose the
        # record itself.
        tls.settimeout(POLL)
        deadline = time.monotonic() + HOLD
        while time.monotonic() < deadline:
            try:
                if not tls.recv(65536):
                    break          # client closed: it has diagnosed
            except TimeoutError:
                continue           # idle writer, keep holding
            except (OSError, ssl.SSLError):
                break
    except (OSError, ssl.SSLError):
        pass
    finally:
        try:
            tls.close()
        except OSError:
            pass


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    cert = os.path.join(here, "certs", "server.crt")
    key = os.path.join(here, "certs", "server.key")
    if not (os.path.exists(cert) and os.path.exists(key)):
        print(
            f"FATAL: missing cert/key ({cert}, {key}); "
            "run scripts/generate_cert.sh first",
            file=sys.stderr,
            flush=True,
        )
        return 2

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)

    # Bind before printing READY, so a bind failure exits non-zero.
    lsock = socket.create_server((HOST, PORT), reuse_port=False)
    lsock.listen(8)
    print(f"READY tlsconcurrent {HOST}:{PORT}", flush=True)

    # One connection at a time, served start to finish on this thread.
    while True:
        conn, _ = lsock.accept()
        handle(conn, ctx)


if __name__ == "__main__":
    sys.exit(main())
