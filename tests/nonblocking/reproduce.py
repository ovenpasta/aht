#!/usr/bin/env python3
# Copyright (C) 2026 Zack Boll
# SPDX-License-Identifier: Apache-2.0
"""Real-socket AHT-TLS-001 controls; not OMS WSS acceptance.

Build nonblocking.gpr first. Keys/results go to new external scratch.
Adapted from the OMS TASK108 pinned-TLS blocker reproducer.
"""
import argparse
import json
import os
from pathlib import Path
import select
import socket
import ssl
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


class Peer:
    def __init__(self, probe, certs, name="server", host="localhost", ca="ca.pem",
                 maximum_version=None, minimum_version=ssl.TLSVersion.TLSv1_2):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(2)
        self.process = subprocess.Popen(
            [str(probe), host, str(self.listener.getsockname()[1]), str(certs / ca)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.pending = b""
        self.socket, _ = self.listener.accept()
        self.socket.settimeout(2)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = minimum_version
        if maximum_version is not None:
            context.maximum_version = maximum_version
        if minimum_version < ssl.TLSVersion.TLSv1_2:
            # Permit the negative-test peer to offer legacy protocols;
            # the AHT client must still reject them.
            context.set_ciphers("ALL:@SECLEVEL=0")
        self.sni = []
        context.sni_callback = lambda sock, name, ctx: self.sni.append(name)
        context.load_cert_chain(certs / f"{name}.pem", certs / f"{name}.key")
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_side=True)

    def flush(self):
        data = self.outgoing.read()
        if data:
            self.socket.sendall(data)

    def handshake(self):
        while True:
            try:
                self.tls.do_handshake()
                self.flush()
                return
            except ssl.SSLWantReadError:
                self.flush()
                data = self.socket.recv(65536)
                if not data:
                    raise EOFError("client closed during handshake")
                self.incoming.write(data)
            except ssl.SSLError:
                # Deliver the server's fatal alert rather than turning a
                # protocol rejection into a stalled-peer timeout.
                self.flush()
                raise

    def line(self, timeout=2):
        end = time.monotonic() + timeout
        while b"\n" not in self.pending:
            remaining = end - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise TimeoutError("probe output deadline")
            data = os.read(self.process.stdout.fileno(), 65536)
            if not data:
                raise RuntimeError(f"probe exited: {self.process.poll()}")
            self.pending += data
        line, self.pending = self.pending.split(b"\n", 1)
        return line.decode()

    def command(self, text, timeout=2):
        self.send_command(text)
        return self.line(timeout)

    def send_command(self, text):
        self.process.stdin.write((text + "\n").encode())
        self.process.stdin.flush()

    def await_ciphertext(self):
        # Observe the actual client receive queue, not an assumed delay.
        deadline = time.monotonic() + 1
        while True:
            row = self.command("available")
            assert row.startswith("AVAILABLE "), row
            count = int(row.split()[1])
            assert count >= 0, row
            if count:
                return count
            assert time.monotonic() < deadline, "ciphertext never queued"

    def close(self):
        self.socket.close()
        self.listener.close()
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=2)
        self.process.stdin.close()
        self.process.stdout.close()
        self.process.stderr.close()


def certificates(directory):
    def openssl(*args):
        subprocess.run(["openssl", *args], cwd=directory, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10)

    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-subj", "/CN=AHT-TLS-001 ephemeral CA", "-keyout", "ca.key", "-out", "ca.pem")
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-subj", "/CN=AHT-TLS-001 unrelated CA", "-keyout", "other.key", "-out", "other.pem")
    (directory / "index").write_text("")
    (directory / "serial").write_text("1000\n")
    (directory / "ca.cnf").write_text(
        "[ca]\ndefault_ca=local\n[local]\ndatabase=index\nserial=serial\n"
        "new_certs_dir=.\ncertificate=ca.pem\nprivate_key=ca.key\n"
        "default_md=sha256\npolicy=policy\n[policy]\ncommonName=supplied\n")
    for name, san in [("server", "DNS:localhost"),
                      ("ip", "IP:127.0.0.1"),
                      ("wrong", "DNS:wrong.invalid"),
                      ("expired", "DNS:localhost")]:
        (directory / f"{name}.ext").write_text(
            f"subjectAltName={san}\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n")
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=unused.invalid",
                "-keyout", f"{name}.key", "-out", f"{name}.csr")
        if name == "expired":
            openssl("ca", "-batch", "-notext", "-config", "ca.cnf",
                    "-in", f"{name}.csr", "-out", f"{name}.pem",
                    "-startdate", "20200101000000Z", "-enddate", "20200102000000Z",
                    "-extfile", f"{name}.ext")
        else:
            openssl("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem",
                    "-CAkey", "ca.key", "-CAcreateserial", "-days", "2",
                    "-extfile", f"{name}.ext", "-out", f"{name}.pem")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--aht", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--backend", choices=("openssl", "mbedtls"), default="openssl")
    args = parser.parse_args()
    scratch = args.scratch.resolve()
    if scratch.is_relative_to(ROOT):
        raise ValueError("certificates must be generated outside the repository")
    scratch.mkdir(parents=True, exist_ok=False, mode=0o700)
    if ssl.OPENSSL_VERSION_INFO[0] != 3:
        raise ValueError("the reproducer requires OpenSSL 3")
    observed = subprocess.check_output(["git", "-C", str(args.aht), "rev-parse", "HEAD"], text=True).strip()
    certificates(scratch)
    results = []

    def record(name, **values):
        results.append(dict(case=name, **values))
        print(name, json.dumps(values), flush=True)

    def connected():
        peer = Peer(args.probe.resolve(), scratch)
        peer.handshake()
        assert peer.line() == "CONNECTED"
        assert peer.sni == ["localhost"], peer.sni
        return peer

    peer = connected()
    try:
        # Blocking Read retains its positive-deadline semantics.
        idle = [peer.command("0.05") for _ in range(4)]
        assert all(row.startswith("TIMEOUT ") and float(row.split()[1]) >= 0.04 for row in idle), idle
        record("positive-deadline-idle-waits", observations=idle)

        def attempt():
            row = peer.command("try")
            assert row.startswith("TRY "), row
            assert float(row.split()[-1]) < 0.04, row
            return row

        idle = [attempt() for _ in range(32)]
        assert all(row.startswith("TRY IDLE 0 0 ") for row in idle), idle
        record("nonblocking-idle", observations=idle)
        assert peer.command("empty") == "EMPTY_IDLE"
        assert peer.command("expired") == "EXPIRED"
        peer.tls.write(b"A" * 8192)
        peer.flush()
        queued = peer.await_ciphertext()
        rows = []
        for _ in range(32):
            rows.append(attempt())
            if (rows[-1].startswith("TRY DATA_READY ")
                    and not any(row.startswith("TRY DATA_READY ") for row in rows[:-1])):
                # The rest of this record must now be inside TLS, not TCP.
                assert peer.command("available") == "AVAILABLE 0"
            if sum(int(row.split()[2]) for row in rows) == 8192:
                break
        assert sum(int(row.split()[2]) for row in rows) == 8192, rows
        assert sum(int(row.split()[3]) for row in rows) == 65 * 8192, rows
        assert rows[-1].startswith("TRY DATA_READY 4096 "), rows
        record("queued-and-buffered-8192", queued_ciphertext=queued, observations=rows)

        peer.tls.write(b"fragment")
        ciphertext = peer.outgoing.read()
        assert len(ciphertext) > 6
        peer.socket.sendall(ciphertext[:6])  # record header plus partial body
        assert peer.await_ciphertext() == 6
        partial = [attempt() for _ in range(8)]
        assert all(row.startswith("TRY IDLE 0 0 ") for row in partial), partial
        assert peer.command("available") == "AVAILABLE 0"
        peer.socket.sendall(ciphertext[6:])
        peer.await_ciphertext()
        resumed = attempt()
        assert resumed.startswith("TRY DATA_READY 8 852 "), resumed
        record("partial-record-resumes", partial=partial, resumed=resumed)

        # Real abrupt TCP EOF must remain an error, not a successful close.
        peer.socket.shutdown(socket.SHUT_RDWR)
        for _ in range(32):
            truncation = peer.command("try")
            if truncation.startswith("TRY_ERROR "):
                break
        assert truncation.startswith("TRY_ERROR AHT.TRANSPORT.TLS.TLS_ERROR "), truncation
        record("truncation-rejected", observation=truncation)
        closed = peer.command("abort", timeout=0.4)
        assert closed.startswith("ABORTED ") and float(closed.split()[1]) < 0.1, closed
        record("failed-read-abortive-close", observation=closed)
    finally:
        peer.close()

    peer = connected()
    try:
        assert peer.command("congest", timeout=5) == "CONGESTED"
        before = len(list(Path(f"/proc/{peer.process.pid}/fd").iterdir()))
        # The peer remains connected and never resets or reads the junk.
        start = time.monotonic()
        closed = peer.command("abort-stay", timeout=0.4)
        elapsed = time.monotonic() - start
        assert closed.startswith("ABORTED ") and float(closed.split()[1]) < 0.1, closed
        assert closed.endswith("connected=FALSE"), closed
        after = len(list(Path(f"/proc/{peer.process.pid}/fd").iterdir()))
        assert before - after >= 3, (before, after)
        for _ in range(32):
            assert peer.command("abort-stay").startswith("ABORTED ")
        assert len(list(Path(f"/proc/{peer.process.pid}/fd").iterdir())) == after
        assert peer.command("abort").startswith("ABORTED ")
        peer.process.wait(timeout=2)
        assert peer.process.returncode == 0
        record("backpressured-abortive-close", seconds=elapsed, observation=closed,
               descriptors_before=before, descriptors_after=after)
    finally:
        peer.close()

    peer = connected()
    try:
        assert peer.command("congest", timeout=5) == "CONGESTED"
        failure = peer.command("write")
        assert failure.startswith("WRITE_ERROR AHT.TRANSPORT.TIMEOUT_ERROR "), failure
        assert 0.04 <= float(failure.split()[2]) < 0.5, failure
        assert failure.endswith("connected=FALSE"), failure
        closed = peer.command("abort")
        assert closed.startswith("ABORTED ") and float(closed.split()[1]) < 0.1, closed
        peer.process.wait(timeout=2)
        assert peer.process.returncode == 0
        record("failed-write-poisons-and-cleans-up", observation=failure, close=closed)
    finally:
        peer.close()

    peer = connected()
    try:
        peer.tls.write(b"XYZ")
        peer.flush()
        time.sleep(0.05)
        for _ in range(32):
            row = peer.command("shifted")
            if row.startswith("SHIFTED DATA_READY "):
                break
            assert row == "SHIFTED IDLE 0 0", row
        assert row == "SHIFTED DATA_READY 7 88", row
        # Switching to blocking Read must return the same buffered suffix.
        row = peer.command("0.05")
        assert row.startswith("READ  2 "), row
        assert peer.command("abort").startswith("ABORTED ")
        record("shifted-index-and-blocking-interoperation", observation=row)
    finally:
        peer.close()

    peer = connected()
    try:
        # Many individual records exercise finite work across event-loop turns.
        for _ in range(256):
            peer.tls.write(b"q")
        peer.flush()
        time.sleep(0.05)
        rows = [peer.command("try") for _ in range(512)]
        assert all(row.startswith("TRY ") and float(row.split()[-1]) < 0.04 for row in rows), rows
        assert sum(int(row.split()[2]) for row in rows) == 256, rows
        assert sum(int(row.split()[3]) for row in rows) == 256 * 113, rows
        # A maximum-size application record plus TLS overhead exceeds the
        # per-invocation ciphertext receive budget; no call waits to finish it.
        peer.tls.write(b"Z" * 16_384)
        peer.flush()
        time.sleep(0.05)
        rows = []
        for _ in range(32):
            row = peer.command("try")
            rows.append(row)
            assert row.startswith("TRY ") and float(row.split()[-1]) < 0.04, row
            if sum(int(r.split()[2]) for r in rows) == 16_384:
                break
        assert sum(int(r.split()[2]) for r in rows) == 16_384, rows
        assert sum(int(r.split()[3]) for r in rows) == 16_384 * 90, rows
        record("record-larger-than-receive-budget", observations=rows)
        assert peer.command("abort").startswith("ABORTED ")
    finally:
        peer.close()

    peer = connected()
    try:
        # A real close_notify, unlike a raw TCP FIN, is clean EOF.
        try:
            peer.tls.unwrap()
        except ssl.SSLWantReadError:
            pass
        peer.flush()
        time.sleep(0.05)  # allow TCP delayed ACK/Nagle, outside timed operation
        rows = []
        for _ in range(32):
            row = peer.command("try")
            rows.append(row)
            assert row.startswith("TRY "), row
            assert float(row.split()[-1]) < 0.04, row
            if row.startswith("TRY PEER_CLOSED 0 0 "):
                break
        assert rows[-1].startswith("TRY PEER_CLOSED 0 0 "), rows
        assert peer.command("try").startswith("TRY PEER_CLOSED 0 0 ")
        assert peer.command("abort").startswith("ABORTED ")
        record("authenticated-clean-shutdown", observations=rows)
    finally:
        peer.close()

    peer = Peer(args.probe.resolve(), scratch, name="ip", host="127.0.0.1")
    try:
        peer.handshake()
        assert peer.line() == "CONNECTED"
        # Preserve existing backend policy: mbedTLS sends numeric SNI.
        assert peer.sni == ([None] if args.backend == "openssl" else ["127.0.0.1"]), peer.sni
        assert peer.command("abort").startswith("ABORTED ")
        record("trusted-ip-san", observation="CONNECTED")
    finally:
        peer.close()

    peer = Peer(args.probe.resolve(), scratch, maximum_version=ssl.TLSVersion.TLSv1_2)
    try:
        peer.handshake()
        assert peer.line() == "CONNECTED"
        assert peer.tls.version() == "TLSv1.2"
        peer.tls.write(b"tls12")
        peer.flush()
        time.sleep(0.05)
        for _ in range(32):
            row = peer.command("try")
            assert row.startswith("TRY ") and float(row.split()[-1]) < 0.04, row
            if row.startswith("TRY DATA_READY "):
                break
        assert row.startswith("TRY DATA_READY 5 438 "), row
        assert peer.command("abort").startswith("ABORTED ")
        record("tls12-nonblocking", observation=row)
    finally:
        peer.close()

    peer = connected()
    try:
        assert peer.command("congest", timeout=5) == "CONGESTED"
        start = time.monotonic()
        assert peer.command("finalize", timeout=0.4) == "FINALIZING"
        peer.process.wait(timeout=0.4)
        elapsed = time.monotonic() - start
        assert peer.process.returncode == 0 and elapsed < 0.4
        record("backpressured-automatic-finalization", seconds=elapsed)
    finally:
        peer.close()

    for case, name, host, ca, reason in [
        ("untrusted", "server", "localhost", "other.pem", "certificate verify failed"),
        ("wrong-dns", "wrong", "localhost", "ca.pem", "hostname mismatch"),
        ("expired", "expired", "localhost", "ca.pem", "certificate has expired"),
        ("wrong-ip-san", "server", "127.0.0.1", "ca.pem", "IP address mismatch"),
    ]:
        peer = Peer(args.probe.resolve(), scratch, name, host, ca)
        try:
            try:
                peer.handshake()
            except (ssl.SSLError, EOFError, ConnectionError):
                pass
            line = peer.line()
            assert line.startswith("CONNECT_ERROR AHT.TRANSPORT.TLS.TLS_ERROR "), line
            if args.backend == "openssl":
                assert reason in line, line
            peer.process.wait(timeout=2)
            assert peer.process.returncode == 0
            record(case, observation=line)
        finally:
            peer.close()

    for case in ["plaintext-on-tls", "stalled-handshake"]:
        peer = Peer(args.probe.resolve(), scratch)
        try:
            start = time.monotonic()
            if case == "plaintext-on-tls":
                peer.socket.sendall(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
            line = peer.line()
            assert line.startswith("CONNECT_ERROR "), line
            if case == "stalled-handshake":
                assert "TIMEOUT_ERROR" in line, line
            elapsed = time.monotonic() - start
            assert elapsed < 1.5, elapsed
            peer.process.wait(timeout=2)
            assert peer.process.returncode == 0
            record(case, seconds=elapsed, observation=line)
        finally:
            peer.close()

    peer = Peer(args.probe.resolve(), scratch,
                minimum_version=ssl.TLSVersion.TLSv1,
                maximum_version=ssl.TLSVersion.TLSv1_1)
    try:
        try:
            peer.handshake()
        except (ssl.SSLError, EOFError, ConnectionError):
            pass
        row = peer.line()
        assert row.startswith("CONNECT_ERROR AHT.TRANSPORT.TLS.TLS_ERROR "), row
        peer.process.wait(timeout=2)
        assert peer.process.returncode == 0
        record("legacy-tls-rejected", observation=row)
    finally:
        peer.close()

    # AHT correction qualification only, not OMS WSS acceptance.
    (scratch / "result.json").write_text(json.dumps(dict(
        disposition="CONTROLS_PASSED", aht=observed, openssl=ssl.OPENSSL_VERSION,
        backend=args.backend, cases=results, wss_acceptance=False), indent=2) + "\n")
    print("AHT_TLS_001_CONTROLS_PASSED")


if __name__ == "__main__":
    main()