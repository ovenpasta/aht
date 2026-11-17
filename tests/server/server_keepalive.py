#!/usr/bin/env python3
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
"""AHT keep-alive test fixture.

HTTP/1.1 with persistent connections on 127.0.0.1:8779, and the same
routes over TLS on 127.0.0.1:8780 (the scripts/generate_cert.sh
certificate, as server_tls.py). Every response names the connection
it travelled on and its place there:

    X-Conn: <id>     connections are numbered from 1 in accept order
    X-Req:  <n>      the n-th request on that connection

so a test reads reuse off the wire instead of inferring it. Routes:

    GET  /ka/hello       -> 200 Content-Length body
    GET  /ka/chunked     -> 200 chunked body
    GET  /ka/gzip        -> 200 gzip-coded Content-Length body
    GET  /ka/eof         -> 200 body ended by closing the connection
    GET  /ka/close       -> 200 Content-Length body, Connection: close
    GET  /ka/idle-close  -> 200 Content-Length body, then the server
                            closes the connection without saying so
    ANY  /ka/drop-second -> 200 as the first request on a connection;
                            as a later one, the connection is closed
                            with no response (the peer-closed-idle race)
    ANY  /ka/garble-second
                         -> 200 as the first request on a connection;
                            as a later one, a status line followed by
                            a malformed header line, then close
    GET  /ka/extra       -> 200 with Content-Length: 5, then, in the
                            same write as the body (so the same TLS
                            record), a complete second response whose
                            X-Conn is "stale"
    GET  /ka/dup-length  -> 200 with Content-Length: 5 and
                            Content-Length: 10
    GET  /ka/te-and-cl   -> 200 chunked that also carries a
                            Content-Length
    GET  /ka/redirect    -> 302 to /ka/hello with a body
    GET  /ka/redirect-big
                         -> 302 to /ka/hello with a 200 000-byte body
    GET  /ka/stats       -> 200, two lines:
                            "accepted=<a> closed=<c> dropped=<d>
                            garbled=<g>": connections accepted,
                            connections the server has seen end,
                            drop-second drops, garble-second garbles;
                            "closed_ids=,<id>,<id>,": the X-Conn of
                            every connection that has ended.
                            One count across both listeners. A
                            connection whose first request is
                            /ka/stats is not counted, so asking for
                            the counts does not move them.

Prints `READY keepalive 127.0.0.1:8779+8780` once both listen.
"""

from __future__ import annotations

import gzip
import http.server
import itertools
import os
import socketserver
import ssl
import sys
import threading

HOST = "127.0.0.1"
PORT = 8779
TLS_PORT = 8780

HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "certs", "server.crt")
KEY = os.path.join(HERE, "certs", "server.key")

_lock = threading.Lock()
_ids = itertools.count(1)
_stats = {"accepted": 0, "closed": 0, "dropped": 0, "garbled": 0}
_closed_ids: list[int] = []

_GZ_PLAIN = b"keep-alive and compressed\n" * 200
_GZ_WIRE = gzip.compress(_GZ_PLAIN, mtime=0)


def _bump(key: str) -> None:
    with _lock:
        _stats[key] += 1


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # noqa: D401, ARG002
        pass

    def setup(self):
        super().setup()
        with _lock:
            self.conn_id = next(_ids)
            _stats["accepted"] += 1
        self.req_no = 0
        self.counted = True

    def finish(self):
        try:
            super().finish()
        finally:
            if self.counted:
                with _lock:
                    _stats["closed"] += 1
                    _closed_ids.append(self.conn_id)

    def _head(self, status: int, extra=()) -> None:
        self.send_response(status)
        self.send_header("X-Conn", str(self.conn_id))
        self.send_header("X-Req", str(self.req_no))
        for name, value in extra:
            self.send_header(name, value)

    def _fixed(self, status: int, body: bytes, extra=()) -> None:
        self._head(status, (("Content-Length", str(len(body))),) + tuple(extra))
        self.end_headers()
        self.wfile.write(body)

    def _route(self) -> None:
        self.req_no += 1
        if self.req_no == 1 and self.path == "/ka/stats":
            self.counted = False
            with _lock:
                _stats["accepted"] -= 1
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            self.rfile.read(length)
        path = self.path

        if path == "/ka/hello":
            self._fixed(200, b"hello, kept alive\n")
        elif path == "/ka/chunked":
            self._head(200, (("Transfer-Encoding", "chunked"),))
            self.end_headers()
            for piece in (b"kept ", b"alive, ", b"chunked\n"):
                self.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        elif path == "/ka/gzip":
            self._fixed(200, _GZ_WIRE, (("Content-Encoding", "gzip"),))
        elif path == "/ka/eof":
            self._head(200)
            self.end_headers()
            self.wfile.write(b"until close\n")
            self.close_connection = True
        elif path == "/ka/close":
            self._fixed(200, b"closing\n", (("Connection", "close"),))
            self.close_connection = True
        elif path == "/ka/idle-close":
            self._fixed(200, b"closing quietly\n")
            self.close_connection = True
        elif path == "/ka/drop-second":
            if self.req_no == 1:
                self._fixed(200, b"first on this connection\n")
            else:
                _bump("dropped")
                self.close_connection = True
        elif path == "/ka/garble-second":
            if self.req_no == 1:
                self._fixed(200, b"first on this connection\n")
            else:
                _bump("garbled")
                self.wfile.write(b"HTTP/1.1 200 OK\r\nno colon here\r\n\r\n")
                self.close_connection = True
        elif path == "/ka/extra":
            self._head(200, (("Content-Length", "5"),))
            self.end_headers()
            self.wfile.write(
                b"exact"
                b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n"
                b"X-Conn: stale\r\nX-Req: 0\r\n\r\nstale\n")
        elif path == "/ka/dup-length":
            self._head(200, (("Content-Length", "5"),
                             ("Content-Length", "10")))
            self.end_headers()
            self.wfile.write(b"0123456789")
            self.close_connection = True
        elif path == "/ka/te-and-cl":
            self._head(200, (("Transfer-Encoding", "chunked"),
                             ("Content-Length", "5")))
            self.end_headers()
            self.wfile.write(b"5\r\nhello\r\n0\r\n\r\n")
        elif path == "/ka/redirect":
            self._fixed(302, b"moved, not for you\n", (("Location", "/ka/hello"),))
        elif path == "/ka/redirect-big":
            self._fixed(302, b"x" * 200_000, (("Location", "/ka/hello"),))
        elif path == "/ka/stats":
            with _lock:
                line = ("accepted={accepted} closed={closed} "
                        "dropped={dropped} garbled={garbled}\n")
                ids = "".join(f",{i}" for i in _closed_ids) + ","
                body = (line.format(**_stats)
                        + f"closed_ids={ids}\n").encode()
            self._fixed(200, body)
        else:
            self._fixed(404, b"not found\n")

    do_GET = _route
    do_POST = _route
    do_PUT = _route


class Server(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def server_bind(self):
        # As in server.py: skip the reverse lookup of the bound address.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class TLSServer(Server):
    """Handshakes in the handler thread, so a stalled client cannot
    hold the accept loop."""

    def __init__(self, address, handler, context):
        super().__init__(address, handler)
        self.context = context

    def get_request(self):
        sock, addr = self.socket.accept()
        return self.context.wrap_socket(
            sock, server_side=True, do_handshake_on_connect=False), addr

    def finish_request(self, request, client_address):
        try:
            request.do_handshake()
        except (ssl.SSLError, OSError):
            return
        super().finish_request(request, client_address)

    def shutdown_request(self, request):
        # As server_tls.py: close_notify before the TCP close, or the
        # client reads the close as truncation.
        try:
            request.settimeout(2.0)
            request = request.unwrap()
        except (OSError, ValueError):
            pass
        super().shutdown_request(request)


def main() -> int:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT, KEY)
    servers = [Server((HOST, PORT), Handler),
               TLSServer((HOST, TLS_PORT), Handler, context)]
    threads = [threading.Thread(target=s.serve_forever, daemon=True)
               for s in servers]
    for t in threads:
        t.start()
    print(f"READY keepalive {HOST}:{PORT}+{TLS_PORT}", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()
            s.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
