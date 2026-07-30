#!/usr/bin/env python3
"""AHT HTTPS test fixture.

Wraps the plain-HTTP routes from server.py in a TLS layer and listens
on 127.0.0.1:8766. The cert/key are produced by
scripts/generate_cert.sh (self-signed, SANs for localhost +
127.0.0.1). Two Ada tests share this fixture:

    tests/src/test_tls.adb      — transport level, speaks raw HTTP over
                                  the TLS socket to exercise the
                                  handshake / verify / read / write path
    tests/src/test_http_tls.adb — the HTTP client over https:// (lands
                                  with split C2)

Prints `READY tls 127.0.0.1:8766` to stdout once listening so
tests/run_tests.sh can wait for it instead of racing.
"""

from __future__ import annotations

import http.server
import os
import ssl
import sys

from server import Handler  # reuse the plain-HTTP route table

HOST = "127.0.0.1"
TLS_PORT = 8766

HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "certs", "server.crt")
KEY = os.path.join(HERE, "certs", "server.key")


class Server(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def shutdown_request(self, request):
        # Send TLS close_notify before the TCP close. http.server's
        # default teardown does a bare socket shutdown, which the AHT
        # OpenSSL backend (correctly) treats as truncation; unwrap()
        # runs the SSL shutdown handshake so clients see a clean EOF.
        # Bounded and best-effort: the client may already be gone.
        try:
            request.settimeout(2.0)
            request = request.unwrap()
        except (OSError, ValueError):
            pass
        super().shutdown_request(request)


def main() -> int:
    if not (os.path.exists(CERT) and os.path.exists(KEY)):
        print(
            f"FATAL: missing cert/key ({CERT}, {KEY}); "
            "run scripts/generate_cert.sh first",
            file=sys.stderr,
            flush=True,
        )
        return 2

    srv = Server((HOST, TLS_PORT), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT, keyfile=KEY)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)

    print(f"READY tls {HOST}:{TLS_PORT}", flush=True)
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
