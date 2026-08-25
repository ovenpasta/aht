#!/usr/bin/env python3
"""AHT stall fixture for the handshake- and upgrade-timeout tests.

Listens on 127.0.0.1:8767 and accepts TCP connections but never speaks
a single byte — no TLS ServerHello, no HTTP response, nothing. Which
wait that stalls depends on how the client dials it, and both are used:

  * Over TLS (`https://`, `wss://`) a client that has sent its
    ClientHello blocks waiting for the server's response, so a bounded
    `Handshake_Deadline` must trip `Timeout_Error` instead of hanging
    forever. This is the only way to exercise the handshake-deadline
    path: the real HTTPS fixture (server_tls.py) completes its
    handshake in milliseconds, so it can never time out.
  * In the clear (`ws://`) there is no handshake to stall, so the
    connect succeeds and the HTTP upgrade is what hangs — which is
    what test_ws_connect_bounds needs for `Upgrade_Deadline`.

Accepted sockets are parked (kept open, never read, never closed) so
the peer sees a live but silent connection rather than a reset — a
reset would surface as Transport_Error, not the Timeout_Error we want
to assert.

Prints `READY stall 127.0.0.1:8767` to stdout once listening so
tests/run_tests.sh can wait for it instead of racing.
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
            # Deliberately do nothing: never recv, never send, never
            # close. Holding the reference keeps the connection alive
            # and silent for the client's handshake read to block on.
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
