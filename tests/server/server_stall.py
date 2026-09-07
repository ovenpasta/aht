#!/usr/bin/env python3
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
"""AHT stall fixture for the handshake- and upgrade-timeout tests.

Listens on 127.0.0.1:8767, accepts TCP connections and never sends a
byte. Over TLS (`https://`, `wss://`) the client blocks after its
ClientHello, so `Handshake_Deadline` must raise `Timeout_Error`; this
is the only fixture that exercises that path. In the clear (`ws://`)
the connect succeeds and the HTTP upgrade hangs, which
test_ws_connect_bounds uses for `Upgrade_Deadline`. Accepted sockets
are parked open and unread, so the peer sees silence and not a reset
(a reset would surface as Transport_Error).

Prints `READY stall 127.0.0.1:8767` once listening.
"""

from __future__ import annotations

import socket
import sys

HOST = "127.0.0.1"
STALL_PORT = 8767


def main() -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, STALL_PORT))
    srv.listen(16)

    print(f"READY stall {HOST}:{STALL_PORT}", flush=True)

    parked: list[socket.socket] = []
    try:
        while True:
            conn, _ = srv.accept()
            # Never recv, send or close; the held reference keeps the
            # connection alive and silent.
            parked.append(conn)
    except KeyboardInterrupt:
        pass
    finally:
        for c in parked:
            try:
                c.close()
            except OSError:
                pass
        srv.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
