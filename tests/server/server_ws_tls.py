#!/usr/bin/env python3
"""AHT secure-WebSocket test fixture.

TLS-wraps the same echo endpoint as server_ws.py and listens on
wss://127.0.0.1:8768/. The `websockets` library handles the RFC 6455
handshake and frame layer; passing an `ssl.SSLContext` makes it run
the WS protocol over a TLS connection, so the Ada client exercises
the full wss:// path (TLS handshake → upgrade → masked frame I/O →
close handshake) against a faithful peer.

Reuses the self-signed cert/key from scripts/generate_cert.sh (SANs
for localhost + 127.0.0.1), same as server_tls.py.

Prints `READY wss 127.0.0.1:8768` to stdout once listening so
tests/run_tests.sh can sync on that line instead of racing.
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

    The asyncio server's *default* selector rejects a client that offers
    no subprotocol with HTTP 400 once the server advertises any (it
    raises NegotiationError). test_ws_tls connects without offering one,
    so the default would break it. This tolerant selector picks "chat"
    when offered (for the ex_08 example) and otherwise continues without
    a subprotocol — never aborting the handshake.
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

    # Negotiate a subprotocol so the Ada client's negotiation path (and
    # the ex_08 example) has something to select, while staying tolerant
    # of clients that offer none (see select_subprotocol above).
    async with websockets.serve(
        echo, HOST, PORT, ssl=ctx, select_subprotocol=select_subprotocol
    ):
        print(f"READY wss {HOST}:{PORT}", flush=True)
        # Sleep forever — the orchestrator signals shutdown by
        # killing us, which raises CancelledError out of this wait.
        await asyncio.Future()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except (KeyboardInterrupt, asyncio.CancelledError):
        sys.exit(0)
