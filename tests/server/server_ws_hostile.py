#!/usr/bin/env python3
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
"""WebSocket peer that misbehaves in ways a client has to survive.

Listens on 127.0.0.1:8777 on raw sockets. The request path selects
the behaviour; every path may carry a trailing /<token> that ties a
report to the connection it describes.

  /huge   A frame header declaring 1 GiB, then nothing, socket held
          open. Only a ceiling enforced in the decoder can object.

  /frag   A fragment sequence, 64 KiB per part, past any small
          ceiling. Refused only if the limit is tracked across the
          logical message.

  /fragstall
          The first fragment of a text message (FIN = 0), then a Ping,
          then nothing, socket held open. The client is left holding
          reassembly state a reconnect has to discard; the payload
          names itself, so a leak into the next generation is visible.

  /flood  Many small messages back to back, to outrun a client that
          is not calling Receive.

  /deaf   Stops reading for a long while, with a tiny receive buffer
          so the client's writer backs up after a few KB. A WebSocket
          write carries no deadline of its own.

  /echo   Drains what it is sent, holds the socket open and sends
          nothing, not even a Close in answer to one; tearing the
          connection down has to abort the receiver. Real echo is on
          8765.

  /deafping/<t>
          /deaf, plus a Ping once the connection has been seen writing
          (by peek, so the peer stays deaf). Only then is a writer
          holding the send guard for the receiver to queue behind.

  /pong/<t>
          Answers whether a Pong was seen on the connection using
          token <t>, waiting a bounded time. Frames are processed in
          order, so a Pong means everything sent before the Ping was
          consumed.

  /traffic/<t>
          Waits until the connection using token <t> has put bytes on
          the wire, detected by peek so a /deaf peer stays deaf.

  /report/<t>
          Answers the close code observed on the connection that used
          token <t>, waiting a bounded time. Tests assert on the code
          that reaches the peer.

After the handshake the connection is held open and inbound frames are
drained and parsed, so a failing client fails on its own limits and
the Close frame it sends is recorded.

Prints `READY wshostile 127.0.0.1:8777` once listening.
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

# /fragstall's opening fragment, distinctive so a test that finds it in
# a later generation's message knows what leaked.
FRAGSTALL_PART = b"STALE-FRAGMENT-"
REPORT_WAIT = 5.0     # how long /report waits for its token's close
DEAF_SECONDS = 20.0   # /deaf: outlasts any working client bound

OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CONT = 0x0
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

# Close codes observed, keyed by the token in the path and waited for:
# a test cannot know when this reader has parsed the Close frame, and
# the token keeps a late close from being taken for another case's.
_closes: dict[str, "int | None"] = {}
_closes_cv = threading.Condition()


# Whether a connection has sent anything, keyed the same way. Peeked,
# so asking does not change the answer.
_traffic: dict[str, bool] = {}
_traffic_cv = threading.Condition()


# Pongs observed, keyed by token. A Pong proves the client's receiver
# processed the frames ahead of it.
_pongs: dict[str, bool] = {}
_pongs_cv = threading.Condition()


def record_pong(token: str) -> None:
    if not token:
        return
    with _pongs_cv:
        if token not in _pongs:
            _pongs[token] = True
            _pongs_cv.notify_all()


def await_pong(token: str, timeout: float) -> bool:
    """Wait (bounded) for this token's Pong, then forget it."""
    with _pongs_cv:
        found = _pongs_cv.wait_for(lambda: token in _pongs, timeout)
        if found:
            _pongs.pop(token, None)
        return found


def record_traffic(token: str) -> None:
    """Record once; a connection that keeps sending cannot re-create
    a record a reader has already consumed."""
    if not token:
        return
    with _traffic_cv:
        if token not in _traffic:
            _traffic[token] = True
            _traffic_cv.notify_all()


def await_traffic(token: str, timeout: float) -> bool:
    """Wait (bounded) for this token's first traffic, then forget it,
    so a backout run against the same fixture cannot pass on a stale
    answer."""
    with _traffic_cv:
        found = _traffic_cv.wait_for(lambda: token in _traffic, timeout)
        if found:
            _traffic.pop(token, None)
        return found


def record_close(token: str, code: int | None) -> None:
    if not token:
        return
    with _closes_cv:
        # First close per token wins: a client may also send a routine
        # close while tearing down, and that must not overwrite the
        # diagnosis under test.
        if token not in _closes:
            _closes[token] = code
            _closes_cv.notify_all()


def await_close(token: str, timeout: float) -> "tuple[bool, int | None]":
    """Wait (bounded) for this token's close, then forget it."""
    with _closes_cv:
        found = _closes_cv.wait_for(lambda: token in _closes, timeout)
        return (found, _closes.pop(token) if found else None)


def frame(fin: bool, opcode: int, payload: bytes) -> bytes:
    """One unmasked server-to-client frame (RFC 6455 section 5.2)."""
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
    """A binary frame header declaring `declared` bytes, with no body,
    always in the ten-byte 64-bit form."""
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


def token_of(path: str) -> str:
    """The trailing /<token> segment, or "" if there is none."""
    parts = [p for p in path.split("/") if p]
    return parts[1] if len(parts) > 1 else ""


def route_of(path: str) -> str:
    """The leading path segment, matched exactly: `/fragstall` starts
    with `/frag`. Anything after it is the token."""
    parts = [p for p in path.split("/") if p]
    return parts[0] if parts else ""


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


def take_frame(buf: bytes) -> tuple[int, bytes, bytes] | None:
    """Split one client frame off `buf`.

    Returns (opcode, payload, rest), or None if `buf` does not yet
    hold a whole frame. Client frames are always masked (RFC 6455
    section 5.3).
    """
    if len(buf) < 2:
        return None
    b0, b1 = buf[0], buf[1]
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    n = b1 & 0x7F
    i = 2
    if n == 126:
        if len(buf) < i + 2:
            return None
        n = int.from_bytes(buf[i:i + 2], "big")
        i += 2
    elif n == 127:
        if len(buf) < i + 8:
            return None
        n = int.from_bytes(buf[i:i + 8], "big")
        i += 8
    key = b""
    if masked:
        if len(buf) < i + 4:
            return None
        key = buf[i:i + 4]
        i += 4
    if len(buf) < i + n:
        return None
    body = bytearray(buf[i:i + n])
    if masked:
        for j in range(n):
            body[j] ^= key[j % 4]
    return opcode, bytes(body), buf[i + n:]


def drain(
    conn: socket.socket,
    stop: threading.Event,
    token: str,
    deaf_for: float = 0.0,
) -> None:
    """Keep reading so the client's writer never stalls, and parse
    what arrives so the Close frame is recorded under `token`; with no
    token (a /report client) nothing is recorded."""
    # Read by the deaf loop below, so bound before it.
    seen_traffic = False

    # /deaf waits in slices so stop is honoured. Each slice peeks, so
    # the client's writer stays blocked while the test is told it is
    # writing.
    waited = 0.0
    if deaf_for > 0.0:
        conn.settimeout(0.05)
    while waited < deaf_for and not stop.is_set():
        try:
            if not seen_traffic and conn.recv(1, socket.MSG_PEEK):
                seen_traffic = True
                record_traffic(token)
        except (TimeoutError, OSError):
            pass
        time.sleep(0.1)
        waited += 0.1

    conn.settimeout(0.25)
    seen_close = False
    buf = b""
    while not stop.is_set():
        try:
            chunk = conn.recv(65536)
            if not chunk:
                break
            buf += chunk
        except TimeoutError:
            continue
        except OSError:
            break

        while True:
            taken = take_frame(buf)
            if taken is None:
                break
            opcode, payload, buf = taken
            if not seen_traffic:
                seen_traffic = True
                record_traffic(token)
            if opcode == OP_PONG:
                record_pong(token)
            if opcode == OP_CLOSE and not seen_close:
                seen_close = True
                record_close(
                    token,
                    int.from_bytes(payload[:2], "big")
                    if len(payload) >= 2 else None,
                )


def serve(conn: socket.socket) -> None:
    try:
        path = handshake(conn, read_request(conn))
    except OSError:
        conn.close()
        return

    route = route_of(path)

    if route in ("deaf", "deafping"):
        # Small receive window, so a writer backs up after a few KB.
        try:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        except OSError:
            pass

    stop = threading.Event()
    reader = threading.Thread(
        target=drain,
        args=(conn, stop,
              ""
              if route in ("report", "traffic", "pong")
              else token_of(path),
              DEAF_SECONDS if route in ("deaf", "deafping") else 0.0),
        daemon=True,
    )
    reader.start()

    try:
        if route == "huge":
            conn.sendall(lying_header(1024 * 1024 * 1024))

        elif route == "frag":
            part = b"f" * FRAG_PART
            conn.sendall(frame(False, OP_BINARY, part))
            for _ in range(FRAG_PARTS - 1):
                conn.sendall(frame(False, OP_CONT, part))
            conn.sendall(frame(True, OP_CONT, part))

        elif route == "fragstall":
            conn.sendall(frame(False, OP_TEXT, FRAGSTALL_PART))
            # Then a Ping, and nothing else. Frames are processed in
            # order, so a Pong coming back proves the fragment ahead of
            # it was consumed.
            conn.sendall(frame(True, OP_PING, token_of(path).encode()))

        elif route == "flood":
            for _ in range(FLOOD_COUNT):
                conn.sendall(frame(True, OP_BINARY, FLOOD_PAYLOAD))

        elif route == "traffic":
            seen = await_traffic(token_of(path), REPORT_WAIT)
            conn.sendall(
                frame(True, OP_TEXT,
                      (b"traffic=yes" if seen else b"traffic=no"))
            )

        elif route == "pong":
            seen = await_pong(token_of(path), REPORT_WAIT)
            conn.sendall(
                frame(True, OP_TEXT,
                      (b"pong=yes" if seen else b"pong=no"))
            )

        elif route == "report":
            found, code = await_close(token_of(path), REPORT_WAIT)
            if not found:
                answer = "close=timeout"
            elif code is None:
                answer = "close=none"
            else:
                answer = f"close={code}"
            conn.sendall(frame(True, OP_TEXT, answer.encode("ascii")))

        elif route == "deaf":
            pass          # never reads; see drain

        elif route == "deafping":
            # Ping only once this connection has been seen writing; the
            # drain thread peeks, so asking does not unblock the writer.
            if await_traffic(token_of(path), REPORT_WAIT):
                try:
                    conn.sendall(frame(True, OP_PING, b"gate"))
                except OSError:
                    pass

        elif route == "echo":
            pass          # the drain thread is all this one needs

        # Hold the connection open, so a failing client fails on its
        # own limits.
        deadline = time.monotonic() + HOLD
        while time.monotonic() < deadline:
            time.sleep(0.1)
    except OSError:
        pass              # client tore the connection down: expected
    finally:
        # Let the reader finish before closing the socket: it exits
        # when the peer closes, and the bytes in flight then include
        # the Close frame the tests assert on. Sends can fail long
        # before the client is done talking, so this runs on that path
        # too.
        reader.join(timeout=5.0)
        stop.set()
        reader.join(timeout=1.0)
        try:
            conn.close()
        except OSError:
            pass


def main() -> int:
    lsock = socket.create_server((HOST, PORT), reuse_port=False)
    lsock.listen(16)
    print(f"READY wshostile {HOST}:{PORT}", flush=True)

    while True:
        conn, _ = lsock.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
