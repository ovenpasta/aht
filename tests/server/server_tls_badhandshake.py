#!/usr/bin/env python3
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
"""Malformed-handshake TLS fixtures (two ports, one process).

Neither port runs a real TLS server.

  8774 - invalid: answer the ClientHello with a record carrying an
         undefined content type, then hold the connection open. The
         client must reject the record itself; a close would let a
         client that diagnosed nothing fail fast on the EOF.

  8775 - dribble: answer with part of a record header, pause, send one
         more byte, then go silent with the connection held. The
         client's handshake deadline must fire: a budget measured from
         Connect gives up at about the deadline, one restarted per
         read at about deadline + pause.

Both: the client must not report Is_Connected and must leave the
transport reusable. Covered by test_tls_bad_handshake.

Prints `READY tlsbadhandshake 127.0.0.1:8774+8775` only after both
sockets are listening.
"""

from __future__ import annotations

import socket
import sys
import threading
import time

HOST = "127.0.0.1"
INVALID_PORT = 8774
DRIBBLE_PORT = 8775

# Content type 0xFF is not a defined TLS record type, so a peer can
# reject this from the header alone.
INVALID_RECORD = b"\xff\x03\x03\x00\x08" + bytes(8)

# A partial record header, then (after a pause) one more byte: still
# short of the five a record header needs.
DRIBBLE_FIRST = b"\x16\x03"
DRIBBLE_PAUSE = 3.0
DRIBBLE_SECOND = b"\x03"


def serve_invalid(lsock: socket.socket) -> None:
    while True:
        conn, _ = lsock.accept()
        try:
            conn.settimeout(30.0)
            conn.recv(4096)              # the ClientHello, discarded
            conn.sendall(INVALID_RECORD)
            conn.recv(1)                 # hold open until the peer goes
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def serve_dribble(lsock: socket.socket) -> None:
    while True:
        conn, _ = lsock.accept()
        try:
            conn.settimeout(30.0)
            conn.recv(4096)              # the ClientHello, discarded
            conn.sendall(DRIBBLE_FIRST)
            time.sleep(DRIBBLE_PAUSE)
            conn.sendall(DRIBBLE_SECOND)
            conn.recv(1)                 # hold open, silent
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def main() -> int:
    # Bind on the main thread before printing READY, so a bind failure
    # exits non-zero.
    invalid_sock = socket.create_server((HOST, INVALID_PORT), reuse_port=False)
    invalid_sock.listen(8)
    dribble_sock = socket.create_server((HOST, DRIBBLE_PORT), reuse_port=False)
    dribble_sock.listen(8)

    threading.Thread(
        target=serve_invalid, args=(invalid_sock,), daemon=True
    ).start()
    threading.Thread(
        target=serve_dribble, args=(dribble_sock,), daemon=True
    ).start()

    print(
        f"READY tlsbadhandshake {HOST}:{INVALID_PORT}+{DRIBBLE_PORT}",
        flush=True,
    )
    threading.Event().wait()             # serve until killed
    return 0


if __name__ == "__main__":
    sys.exit(main())
