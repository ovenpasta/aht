#!/usr/bin/env python3
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
"""Mid-session corruption under concurrency.

Listens on 127.0.0.1:8776. Per connection, on ONE thread (an OpenSSL
connection object is not safe for simultaneous use — using two threads
here would recreate in the fixture the very hazard the client engine
exists to avoid):

  1. TLS handshake.
  2. Send a banner, so the client's reader has something to consume.
  3. RECEIVE at least one client payload. This is what proves the
     client's writer is genuinely active alongside its reader; the
     overlap is then a fact the test can assert, not something inferred
     from a sleep on either side.
  4. Send OVERLAP, the marker the test looks for — only after (3), so
     seeing it means the writer really was running.
  5. Inject a record whose MAC cannot verify, straight to the fd,
     bypassing the SSL layer.
  6. Keep draining (so the client's writer never stalls on
     backpressure) until the hold expires or the client goes away.

The hold deliberately outlasts the test's writer bound, so the only
thing that can make that writer fail is the library poisoning the
session — never this fixture closing the connection out from under it.

Pinned by test_tls_concurrent_corrupt.

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

        # Proof of overlap: wait for something the client's WRITER sent.
        tls.settimeout(WRITER_WAIT)
        saw_writer = False
        try:
            saw_writer = bool(tls.recv(65536))
        except (TimeoutError, OSError):
            saw_writer = False

        if saw_writer:
            # Only now — so the marker's presence in the client's read
            # stream means its writer really was running concurrently.
            tls.sendall(OVERLAP)
        else:
            print(
                "WARN tlsconcurrent: no client payload before corruption",
                flush=True,
            )

        # Raw fd write: the SSL layer must not frame or protect these
        # bytes. Loop, since os.write may write short.
        written = 0
        while written < len(CORRUPT_RECORD):
            n = os.write(tls.fileno(), CORRUPT_RECORD[written:])
            if n <= 0:
                raise OSError("short write injecting the record")
            written += n

        # Keep consuming so the client's writer never blocks on
        # backpressure, and stay open so the client must diagnose the
        # record itself rather than inferring anything from a close.
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

    # Bind before announcing readiness, so a bind failure exits non-zero
    # instead of masquerading as a ready fixture.
    lsock = socket.create_server((HOST, PORT), reuse_port=False)
    lsock.listen(8)
    print(f"READY tlsconcurrent {HOST}:{PORT}", flush=True)

    # One connection at a time, served start to finish on this thread.
    while True:
        conn, _ = lsock.accept()
        handle(conn, ctx)


if __name__ == "__main__":
    sys.exit(main())
