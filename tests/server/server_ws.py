#!/usr/bin/env python3
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
"""AHT WebSocket test fixture.

Serves a single echo endpoint at ws://127.0.0.1:8765/ using the
`websockets` library. The library handles the RFC 6455 handshake
and frame layer on the server side, so the Ada client gets a
faithful peer to talk to without us having to hand-roll a WS
implementation in Python too.

Prints `READY ws 127.0.0.1:8765\\n` to stdout once it's listening
so tests/run_tests.sh can sync on that line.
"""

from __future__ import annotations

import asyncio
import sys

import websockets

HOST = "127.0.0.1"
PORT = 8765


async def echo(websocket):
    """Echo every received message back to the sender, verbatim.

    Works for both text and binary because `websockets` preserves
    the message kind across the round trip. Connection terminates
    naturally when the client sends a close frame or drops the
    transport — `async for` exits, the handler returns, and the
    library completes the close handshake.
    """
    async for message in websocket:
        await websocket.send(message)


async def main() -> int:
    # Raise the inbound frame cap well above the default 1 MiB so the
    # §9 large-send regression (test_ws_echo case 9) can bounce a >12 MB
    # message off this fixture; the default would reject it with 1009.
    async with websockets.serve(echo, HOST, PORT, max_size=32 * 1024 * 1024):
        print(f"READY ws {HOST}:{PORT}", flush=True)
        # Sleep forever — the orchestrator signals shutdown by
        # killing us, which raises CancelledError out of this wait.
        await asyncio.Future()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except (KeyboardInterrupt, asyncio.CancelledError):
        sys.exit(0)
