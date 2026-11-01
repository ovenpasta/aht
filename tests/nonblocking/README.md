<!--
SPDX-FileCopyrightText: 2026 Zack Boll
SPDX-License-Identifier: Apache-2.0
-->

# Nonblocking TLS and abortive cleanup controls

These Linux real-socket tests exercise `TLS.Try_Read` and
`TLS.Abortive_Close` against both TLS backends. They cover transport
behavior, not application-level WebSocket acceptance.

## Run

With GNAT, GPRbuild, Python 3.11+, OpenSSL 3 headers/runtime/CLI and a C
compiler installed, run from the AHT checkout:

```sh
alr build
alr exec -- sh tests/nonblocking/run.sh
AHT_TLS_BACKEND=mbedtls alr build
AHT_TLS_BACKEND=mbedtls alr exec -- sh tests/nonblocking/run.sh
```

The driver creates keys, certificates and JSON results in a new external
mode-0700 directory. The shell runner removes that directory on exit.
To retain results, build `tests/nonblocking/nonblocking.gpr` and invoke
`reproduce.py` directly with `--probe`, `--aht`, `--backend` and a new
external `--scratch` path. Treat that path as secret: it contains private
keys. Do not commit generated evidence or keys.

Select compilers with workspace-local Alire configuration in **separate
checkouts**, so objects and runtimes cannot be mixed:

```sh
alr toolchain --select --local gnat_native=16.1.0 gprbuild=26.0.1
# In a second checkout with system GNAT 14.2.0 on PATH:
alr -f toolchain --select --local gnat_external=14.2.0 gprbuild=26.0.1
```

The `--force` override accepts the external-compiler/binary-GPRbuild origin
mix; verify `alr exec -- gnat --version` before building. Local Alire
configuration and generated build products are ignored, not dependency
manifest changes.

## Assertions

* Positive-deadline blocking `Read` still waits on idle input.
* Repeated `Try_Read` calls return promptly on idle input and deliver a
  queued 8 KiB record plus its decrypted suffix without another send.
  Test-only `FIONREAD` observes the client's queued ciphertext first.
* An observed six-byte partial record is consumed without waiting for its
  remainder; repeated reads return `Idle`, then deliver the remainder.
* Empty and shifted-index destinations, expired compound deadlines,
  switching back to blocking `Read`, 256 small records and a record larger
  than the per-call receive budget are exercised.
* `close_notify` is authenticated clean shutdown; raw TCP EOF raises
  `TLS_Error` on the new API in both backends.
* Cleanup and automatic finalization finish under established send
  backpressure, without resetting or reading from the peer first.
  Repeated cleanup is idempotent; `/proc/PID/fd` confirms descriptors are
  released while the process is still alive. Failed-write cleanup is
  tested separately from failed-read cleanup.
* Trusted DNS/IP SANs succeed; unrelated CA, wrong DNS/IP SAN and expired
  leaf certificates fail. DNS SNI and each backend's existing numeric-SNI
  policy are checked. TLS 1.2 works; TLS 1.0/1.1-only peers, plaintext and
  stalled handshakes fail.

The pressure helper deliberately fills the actual send buffer with junk
ciphertext. The peer never parses it. Its 200 ms selector wait establishes
backpressure **in the test fixture only**, not in the library's nonblocking
path. This is a cleanup test, not valid application-stream behavior.
Timing assertions are liveness backstops, not hard realtime guarantees.

Run the existing regression suite separately for each backend:

```sh
bash tests/run_tests.sh
AHT_TLS_BACKEND=mbedtls bash tests/run_tests.sh
```

See `docs/tls.md` for the exclusive-use preconditions, work bounds,
unchanged verification policies and legacy backend differences. In
particular, explicit graceful `Close` may still wait for output capacity;
abortive cleanup and finalization intentionally do not send `close_notify`.