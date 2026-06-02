#!/usr/bin/env python3
"""AHT plain-HTTP test fixture.

Serves a handful of HTTP/1.1 routes on 127.0.0.1:8764 that the Ada
integration tests in tests/src/test_http_*.adb hit. Routes mirror the
plan in docs/plan.md:

    GET  /hello      → 200 text/plain "hello, world\\n"
    GET  /chunked    → 200 with Transfer-Encoding: chunked, three frames
    GET  /json       → 200 application/json
    GET  /redirect   → 302 Location: /hello
    GET  /protected  → 401 without Authorization header,
                       200 echoing the header value otherwise
    POST /echo       → 200 echoing the request body and Content-Type

The handler emits `Connection: close` everywhere so the Ada client
(also Connection: close in v1) sees a clean EOF after each response
without keep-alive parsing.

Prints `READY http 127.0.0.1:8764\\n` to stdout once it is listening
so tests/run_tests.sh can wait for that line instead of racing.
"""

from __future__ import annotations

import http.server
import sys

HOST = "127.0.0.1"
HTTP_PORT = 8764


class Handler(http.server.BaseHTTPRequestHandler):
    # Match the default protocol so chunked transfer is legal on the wire.
    protocol_version = "HTTP/1.1"

    # Silence the per-request access log: the tests' own output is the
    # signal we care about, and BaseHTTPRequestHandler's default goes to
    # stderr and clutters CI output.
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

        elif self.path == "/chunked":
            # Three deliberately uneven chunks so the Ada decoder has
            # to reassemble across boundaries.
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
            # One deliberately huge (>12 MB) chunk in a single
            # chunk-frame. The chunk-size line names a length far larger
            # than the client's thread stack, so a naive Size-sized
            # decode buffer overflows; this exercises the bounded-window
            # chunk reader. Body is a 0..255 ramp so the client can
            # verify reassembly byte-for-byte.
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
                # Echo the header value so the test can confirm AHT
                # actually transmitted what it built (not just that the
                # server flipped 401 → 200 on header presence).
                self._send_fixed(200, auth.encode("utf-8") + b"\n",
                                 "text/plain")

        else:
            self._send_fixed(404, b"not found\n", "text/plain")

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
