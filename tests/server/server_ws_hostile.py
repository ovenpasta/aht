#!/usr/bin/env python3
"""WebSocket peer that misbehaves in ways a client has to survive.

Listens on 127.0.0.1:8777. Raw sockets rather than the `websockets`
library, because every behaviour here is one that library exists to
prevent: declaring a payload it never sends, running a fragment
sequence past a size limit, flooding a reader that is not draining,
or simply stopping reading.

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

  /deaf   Stop reading for a long while, with a tiny receive buffer
          so the client's writer backs up after a few KB rather than
          after however many megabytes the kernel felt like holding.
          A WebSocket write carries no deadline of its own, so this
          is all it takes to park a writer indefinitely — which is
          how a caller ends up waiting on a latch that writer holds.

  /echo   Ordinary echo, for the cases that need a working peer.

  /traffic/<t>
          Waits until the connection using token <t> has actually put
          bytes on the wire, and answers. Detected by PEEKING, so the
          bytes are not consumed and a /deaf peer stays deaf — which
          matters, because the point of asking is usually to confirm a
          writer is blocked, and reading would unblock it.

  /report/<t>
          Sends back the close code observed on the connection that
          used token <t>, waiting a bounded time for it to arrive.
          Without this the tests could only check the client's own
          diagnostic text, and swapping 1008 for 1009 in the client
          would go unnoticed — the code that actually reaches the peer
          is the part of the contract worth pinning.

Every path may carry a trailing /<token>, which is how a report is
tied to the connection it describes rather than to whatever happened
most recently.

After the handshake the connection is held open and inbound frames are
drained — so a client that fails is failing on its own limits, never
because this peer went away or stopped reading. Draining also parses,
so the Close frame the client sends on its way out is recorded.

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
REPORT_WAIT = 5.0     # how long /report waits for its token's close
DEAF_SECONDS = 20.0   # /deaf: long enough to outlast any client bound
                      # that is working, and to be obvious when one is
                      # not

OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CONT = 0x0
OP_CLOSE = 0x8

# Close codes observed, keyed by the token the test put in the path.
#
# Keyed rather than "the most recent one", and waited for rather than
# sampled. A test cannot know when this fixture's reader has parsed the
# Close frame -- its own Close returning proves only that IT finished
# -- so a single non-blocking read here would sometimes answer before
# the frame arrived. The token also means a late or duplicated close
# can never be mistaken for another case's.
_closes: dict[str, "int | None"] = {}
_closes_cv = threading.Condition()


# Whether a connection has sent anything, keyed the same way. Peeked
# rather than read, so asking does not change the answer.
_traffic: dict[str, bool] = {}
_traffic_cv = threading.Condition()


def record_traffic(token: str) -> None:
    """Record once. Callers hold a per-connection flag as well, so a
    connection that keeps sending cannot re-create evidence a reader
    has already consumed -- which would make consuming it pointless."""
    if not token:
        return
    with _traffic_cv:
        if token not in _traffic:
            _traffic[token] = True
            _traffic_cv.notify_all()


def await_traffic(token: str, timeout: float) -> bool:
    """Wait for this token's first traffic, then forget it.

    Consumed on read for the same reason close codes are: a token that
    answered yes forever would let a later run -- or a backout run
    against the same fixture -- pass without anything having been
    written at all.
    """
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


def token_of(path: str) -> str:
    """The trailing /<token> segment, or "" if there is none."""
    parts = [p for p in path.split("/") if p]
    return parts[1] if len(parts) > 1 else ""


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

    Returns (opcode, payload, rest) or None if `buf` does not yet hold
    a whole frame. Client frames are always masked (RFC 6455 §5.3), so
    the mask is not optional here.
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
    """Keep reading so the client's writer never stalls on us, and
    parse what arrives so the Close frame it ends with is recorded.

    Publishes under `token`, or not at all when there is none — which
    is how /report's own client, whose close is of no interest, stays
    out of the record.
    """
    # Declared before the deaf loop below, which reads it: a name
    # bound only afterwards would raise UnboundLocalError on the first
    # peek and take this thread down without a word.
    seen_traffic = False

    # Not reading at all is the point of /deaf, but stop must still be
    # honoured, so the wait is in slices rather than one sleep. Each
    # slice peeks: peeking reports what has arrived without removing
    # it, so the client's writer stays blocked exactly as intended
    # while the test still gets told it really is writing.
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

    if path.startswith("/deaf"):
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
              if path.startswith("/report")
              or path.startswith("/traffic")
              else token_of(path),
              DEAF_SECONDS if path.startswith("/deaf") else 0.0),
        daemon=True,
    )
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

        elif path.startswith("/traffic"):
            seen = await_traffic(token_of(path), REPORT_WAIT)
            conn.sendall(
                frame(True, OP_TEXT,
                      (b"traffic=yes" if seen else b"traffic=no"))
            )

        elif path.startswith("/report"):
            found, code = await_close(token_of(path), REPORT_WAIT)
            if not found:
                answer = "close=timeout"
            elif code is None:
                answer = "close=none"
            else:
                answer = f"close={code}"
            conn.sendall(frame(True, OP_TEXT, answer.encode("ascii")))

        elif path.startswith("/deaf"):
            pass          # the point is what this one does NOT do

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
        # Let the reader finish on its own before pulling the socket
        # out from under it. It exits as soon as the peer closes, and
        # the bytes still in flight at that moment include the Close
        # frame carrying the diagnosis these tests assert on — closing
        # here first would race exactly the thing being observed.
        # Sends can fail long before the client is done talking, so
        # this cannot be skipped just because the write side broke.
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
