#!/usr/bin/env python3
"""WebSocket peer that overruns a client's configured ceilings.

Listens on 127.0.0.1:8777. Raw sockets rather than the `websockets`
library, because every behaviour here is one that library exists to
prevent: declaring a payload it never sends, running a fragment
sequence past a size limit, flooding a reader that is not draining.

The request path selects the behaviour:

  /huge   Send a frame header declaring 1 GiB and then nothing at all,
          holding the socket open. This is the case that separates a
          ceiling enforced in the decoder from one applied to a
          decoded frame: only the former can object, because the
          latter is still waiting for a gigabyte that never comes.

  /frag   A fragment sequence, 64 KiB per part, that keeps going well
          past any small ceiling. Each part is individually tiny, so
          this is only refused if the limit is tracked across the
          logical message rather than per frame.

  /flood  Many small messages back to back, to outrun a client that
          is not calling Receive.

  /echo   Ordinary echo, for the cases that need a working peer.

After the handshake the connection is held open, and inbound bytes are
drained and discarded — so a client that fails is failing on its own
limits, never because this peer went away or stopped reading.

Prints `READY wslimits 127.0.0.1:8777` once listening.
"""

from __future__ import annotations

import base64
import hashlib
import socket
import sys
import threading
import time

HOST = "127.0.0.1"
PORT = 8777

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

HOLD = 30.0           # keep the connection open well past any assertion
FRAG_PART = 64 * 1024
FRAG_PARTS = 512      # 32 MiB total, far past the small ceilings tested
FLOOD_COUNT = 20_000
FLOOD_PAYLOAD = b"x" * 256

OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CONT = 0x0


def frame(fin: bool, opcode: int, payload: bytes) -> bytes:
    """One unmasked server-to-client frame (RFC 6455 §5.2)."""
    b0 = (0x80 if fin else 0x00) | opcode
    n = len(payload)
    if n < 126:
        head = bytes([b0, n])
    elif n < 65536:
        head = bytes([b0, 126]) + n.to_bytes(2, "big")
    else:
        head = bytes([b0, 127]) + n.to_bytes(8, "big")
    return head + payload


def lying_header(declared: int) -> bytes:
    """A binary frame header declaring `declared` bytes, with no body.

    Always the 64-bit form, so the declaration is a full ten bytes and
    nothing about it is ambiguous.
    """
    return bytes([0x80 | OP_BINARY, 127]) + declared.to_bytes(8, "big")


def read_request(conn: socket.socket) -> str:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            break
    return buf.decode("latin-1")


def handshake(conn: socket.socket, req: str) -> str:
    """Complete the upgrade; return the request path."""
    path = "/"
    key = ""
    for i, line in enumerate(req.split("\r\n")):
        if i == 0:
            parts = line.split(" ")
            if len(parts) >= 2:
                path = parts[1]
        elif line.lower().startswith("sec-websocket-key:"):
            key = line.split(":", 1)[1].strip()

    accept = base64.b64encode(
        hashlib.sha1((key + GUID).encode("ascii")).digest()
    ).decode("ascii")

    conn.sendall(
        (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        ).encode("ascii")
    )
    return path


def drain(conn: socket.socket, stop: threading.Event) -> None:
    """Keep reading so the client's writer never stalls on us."""
    conn.settimeout(0.25)
    while not stop.is_set():
        try:
            if not conn.recv(65536):
                break
        except TimeoutError:
            continue
        except OSError:
            break


def serve(conn: socket.socket) -> None:
    try:
        path = handshake(conn, read_request(conn))
    except OSError:
        conn.close()
        return

    stop = threading.Event()
    reader = threading.Thread(target=drain, args=(conn, stop), daemon=True)
    reader.start()

    try:
        if path.startswith("/huge"):
            conn.sendall(lying_header(1024 * 1024 * 1024))

        elif path.startswith("/frag"):
            part = b"f" * FRAG_PART
            conn.sendall(frame(False, OP_BINARY, part))
            for _ in range(FRAG_PARTS - 1):
                conn.sendall(frame(False, OP_CONT, part))
            conn.sendall(frame(True, OP_CONT, part))

        elif path.startswith("/flood"):
            for _ in range(FLOOD_COUNT):
                conn.sendall(frame(True, OP_BINARY, FLOOD_PAYLOAD))

        elif path.startswith("/echo"):
            pass          # the drain thread is all this one needs

        # Hold the connection open so a client that fails is failing on
        # its own limits, not because the peer vanished.
        deadline = time.monotonic() + HOLD
        while time.monotonic() < deadline:
            time.sleep(0.1)
    except OSError:
        pass              # client tore the connection down: expected
    finally:
        stop.set()
        try:
            conn.close()
        except OSError:
            pass


def main() -> int:
    lsock = socket.create_server((HOST, PORT), reuse_port=False)
    lsock.listen(16)
    print(f"READY wslimits {HOST}:{PORT}", flush=True)

    while True:
        conn, _ = lsock.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
