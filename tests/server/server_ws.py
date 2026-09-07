#!/usr/bin/env python3
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
"""AHT WebSocket test fixture.

Serves one echo endpoint at ws://127.0.0.1:8765/ using the
`websockets` library, so the Ada client talks to an independent RFC
6455 peer.

Prints `READY ws 127.0.0.1:8765` once listening.
"""

from __future__ import annotations

import asyncio
import sys

import websockets

HOST = "127.0.0.1"
PORT = 8765


async def echo(websocket):
    """Echo every received message back verbatim, text or binary.

    When the client closes or drops the transport the loop exits and
    the library completes the close handshake.
    """
    async for message in websocket:
        await websocket.send(message)


async def main() -> int:
    # Inbound frame cap above the default 1 MiB, so test_ws_echo case 9
    # can bounce a >12 MB message; the default would answer 1009.
    async with websockets.serve(echo, HOST, PORT, max_size=32 * 1024 * 1024):
        print(f"READY ws {HOST}:{PORT}", flush=True)
        # Sleep until the runner kills the process.
        await asyncio.Future()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except (KeyboardInterrupt, asyncio.CancelledError):
        sys.exit(0)
