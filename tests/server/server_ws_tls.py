#!/usr/bin/env python3
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
"""AHT secure-WebSocket test fixture.

The echo endpoint of server_ws.py over TLS, on wss://127.0.0.1:8768/,
so the Ada client exercises the full wss:// path (TLS handshake,
upgrade, masked frame I/O, close handshake) against an independent
peer. Uses the self-signed cert/key from scripts/generate_cert.sh.

Prints `READY wss 127.0.0.1:8768` once listening.
"""

from __future__ import annotations

import asyncio
import os
import ssl
import sys

import websockets

HOST = "127.0.0.1"
PORT = 8768

HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "certs", "server.crt")
KEY = os.path.join(HERE, "certs", "server.key")


async def echo(websocket):
    """Echo every received message back verbatim (text or binary)."""
    async for message in websocket:
        await websocket.send(message)


def select_subprotocol(connection, subprotocols):
    """Negotiate "chat" when the client offers it, else no subprotocol.

    The library's default selector answers HTTP 400 to a client that
    offers none once the server advertises any; test_ws_tls offers
    none, ex_08 offers "chat".
    """
    del connection  # unused; signature is (connection, subprotocols)
    if "chat" in subprotocols:
        return "chat"
    return None


async def main() -> int:
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

    # Advertise a subprotocol so the client's negotiation path has
    # something to select; select_subprotocol tolerates clients that
    # offer none.
    async with websockets.serve(
        echo, HOST, PORT, ssl=ctx, select_subprotocol=select_subprotocol
    ):
        print(f"READY wss {HOST}:{PORT}", flush=True)
        # Sleep until the runner kills the process.
        await asyncio.Future()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except (KeyboardInterrupt, asyncio.CancelledError):
        sys.exit(0)
