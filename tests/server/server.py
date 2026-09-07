#!/usr/bin/env python3
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
"""AHT plain-HTTP test fixture.

Serves a handful of HTTP/1.1 routes on 127.0.0.1:8764 that the Ada
integration tests in tests/src/test_http_*.adb hit:

    GET  /hello      -> 200 text/plain "hello, world\\n"
    GET  /slow       -> 200 text/plain, but only after SLOW_DELAY seconds
    GET  /chunked    -> 200 with Transfer-Encoding: chunked, three frames
    GET  /chunked-big
                     -> 200 chunked, one >12 MB chunk
    GET  /json       -> 200 application/json
    GET  /redirect   -> 302 Location: /hello
    GET  /protected  -> 401 without Authorization header,
                        200 echoing the header value otherwise
    POST /echo       -> 200 echoing the request body and Content-Type

Every response carries `Connection: close`, so the client sees a
clean EOF after each one.

Prints `READY http 127.0.0.1:8764` once listening.
"""

from __future__ import annotations

import http.server
import socketserver
import sys
import time

HOST = "127.0.0.1"
HTTP_PORT = 8764

#  How long /slow withholds its response. test_http_phase_bounds
#  brackets it: a 1 s read deadline must trip on this route and a 6 s
#  one must not. Each handler runs on its own thread.
SLOW_DELAY = 3.0


class Handler(http.server.BaseHTTPRequestHandler):
    # HTTP/1.1, so chunked transfer is legal on the wire.
    protocol_version = "HTTP/1.1"

    # Silence the per-request access log.
    def log_message(self, fmt, *args):  # noqa: D401, ARG002
        pass

    def _send_fixed(self, status: int, body: bytes, ctype: str,
                    extra_headers: tuple[tuple[str, str], ...] = ()) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for name, value in extra_headers:
            self.send_header(name, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):  # noqa: N802 (BaseHTTPRequestHandler API)
        if self.path == "/hello":
            self._send_fixed(200, b"hello, world\n", "text/plain")

        elif self.path == "/slow":
            #  Withhold the whole response, status line included, so
            #  the client's read deadline decides the outcome.
            time.sleep(SLOW_DELAY)
            self._send_fixed(200, b"slow, world\n", "text/plain")

        elif self.path == "/chunked":
            # Three uneven chunks so the Ada decoder has to reassemble
            # across boundaries.
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            for chunk in (b"AHT ", b"rocks", b"!\n"):
                self.wfile.write(f"{len(chunk):x}\r\n".encode("ascii"))
                self.wfile.write(chunk)
                self.wfile.write(b"\r\n")
            self.wfile.write(b"0\r\n\r\n")

        elif self.path == "/chunked-big":
            # One >12 MB chunk, larger than the client's thread stack,
            # so a Size-sized decode buffer would overflow. The body is
            # a 0..255 ramp so the client can verify reassembly.
            n = 13_000_000
            pattern = bytes(range(256))
            body = (pattern * (n // 256 + 1))[:n]
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(f"{n:x}\r\n".encode("ascii"))
            self.wfile.write(body)
            self.wfile.write(b"\r\n")
            self.wfile.write(b"0\r\n\r\n")

        elif self.path == "/json":
            self._send_fixed(200, b'{"ok":true}\n', "application/json")

        elif self.path == "/redirect":
            self._send_fixed(302, b"", "text/plain",
                             extra_headers=(("Location", "/hello"),))

        elif self.path == "/protected":
            auth = self.headers.get("Authorization")
            if not auth:
                self._send_fixed(
                    401, b"missing Authorization\n", "text/plain",
                    extra_headers=(
                        ("WWW-Authenticate", 'Basic realm="aht-tests"'),
                    ),
                )
            else:
                # Echo the header value so the test can check what AHT
                # transmitted, not only the 401 -> 200 flip.
                self._send_fixed(200, auth.encode("utf-8") + b"\n",
                                 "text/plain")

        else:
            self._send_fixed(404, b"not found\n", "text/plain")

    def do_HEAD(self):  # noqa: N802
        # HEAD mirrors GET /hello's headers, Content-Length included,
        # with no body; the client must return an empty Body_B.
        if self.path == "/hello":
            body = b"hello, world\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(b"not found\n")))
            self.send_header("Connection", "close")
            self.end_headers()

    def do_POST(self):  # noqa: N802
        if self.path == "/echo":
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length > 0 else b""
            ctype = self.headers.get("Content-Type",
                                     "application/octet-stream")
            self._send_fixed(200, body, ctype)
        else:
            self._send_fixed(404, b"not found\n", "text/plain")


class Server(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def server_bind(self):
        # HTTPServer.server_bind resolves the bound address with
        # socket.getfqdn().  These fixtures only use a numeric loopback
        # address, and that reverse lookup can stall on hosted macOS.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


def main() -> int:
    srv = Server((HOST, HTTP_PORT), Handler)
    print(f"READY http {HOST}:{HTTP_PORT}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.shutdown()
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
