<!--
SPDX-FileCopyrightText: 2026 Aldo Nicolas Bruno
SPDX-License-Identifier: Apache-2.0
-->

# Contributing

Issues and pull requests are welcome.

## Licensing

AHT is licensed under the Apache License 2.0. By submitting a
contribution you agree that it is licensed under the same terms, as
described in section 5 of the license. No separate agreement is
required. Every authored file carries an SPDX header and the
repository is [REUSE](https://reuse.software) compliant; keep it that
way (`reuse lint` runs in CI). Third-party material in a contribution
must be identified in the pull request with its source and license.

## Layout

```
src/                         the library
src/tls/{openssl,mbedtls}/   one TLS backend body per directory
src/os/{posix,windows}/      one entropy body per OS
csrc/                        C glue for each TLS backend
tests/src/                   one .adb per test main, listed in tests/tests.gpr
tests/server/                Python fixtures, one per port
tests/autobahn/              RFC 6455 conformance harness and BASELINE.md
scripts/                     fetch, binding regeneration, probes
docs/                        design documentation, one file per subsystem
examples/                    nine programs, easy to hard
```

Exactly one backend directory and one OS directory compile, selected
by scenario variables. `docs/websocket.md` is the design document for
the WebSocket client and the best starting point.

## Building and testing

```sh
bash tests/run_tests.sh                          # openssl, debug
AHT_TLS_BACKEND=mbedtls bash tests/run_tests.sh  # the other backend
bash examples/run_examples.sh
```

Run both backends before opening a pull request. They differ in
default trust, iPAddress SANs and error taxonomy, and a change that
passes one regularly fails the other.

The runner starts the Python fixtures itself (in `tests/.venv`) and
refuses to run if any of them fails to come up. The fixtures bind
fixed ports in the range 8759 to 8799; "port already in use" means a
fixture from an earlier run is still alive, or something else owns the
port.

### The Windows cross build

```sh
AHT_TLS_BACKEND=mbedtls AHT_OS=windows bash tests/run_tests.sh
```

Cross-compiles with mingw-w64 and runs the resulting `.exe` under
wine against the same native fixtures. Only the testee crosses over,
so a difference is attributable to the port. Needs
`x86_64-w64-mingw32-gnat` and `wine`; `AHT_CROSS_TARGET` names a
different triplet, and that one string drives `gprbuild --target`,
the cross C toolchain and the object, library and mbedTLS directory
names.

Windows is not a supported configuration (`windows = false` in
`alire.toml`), and wine is not Windows: it implements the API AHT
calls, not the one Windows has. The cross build is the fast loop. It
has found two bugs invisible on Linux: a `Poison` that could not wake
a reader, because Winsock does not signal a parked `select` on a
locally initiated shutdown; and a session left attached to its
collection uninitialized by an abort inside `new`, which hung library
finalization on a zero-filled `CRITICAL_SECTION` (a zeroed
`pthread_mutex_t` is a valid unlocked one, so Linux never notices).

Two cases of `test_ws_abort` are skipped under Windows. GNAT on Linux
interrupts a blocking syscall with a signal, so aborting a task parked
in `Check_Selector` unwinds it; Windows has no such mechanism, so the
abort is deferred until the call returns, which for a `Forever` wait
is never. Cases 2 and 4 aim a transfer of control at a task parked in
a socket call. The library's own teardown paths pair every abort with
`Abort_Pending`, which wakes the selector explicitly; a caller who
aborts a task sitting in `Send` or `Connect` gets a hang on Windows.
See *Abort safety is structural* in `docs/websocket.md`.

## The testing standard

This is stricter than usual and is the main thing to absorb before
changing anything.

**Establish the premise, do not assume it.** A test that races
something must prove the race happened. A `delay` may give it a
chance, but it is never the evidence. Assert on an observed fact: a
counter, a protected flag, a token the fixture recorded, a task's
`'Terminated`. Timing is allowed only as a liveness backstop so a
broken build reports instead of hanging.

**Validate both directions.** Back the guard out and confirm the test
fails; then make the race not happen and confirm it fails
differently. A test that has only ever been seen passing has not been
tested.

**Say exactly what is proven.** Where a property rests on a structural
argument rather than a test, the code says so. See the notes in
`test_ws_abort`, `test_ws_masking` and `AHT.Websocket.Handoffs`: each
records what its checks do not cover and why the gap was accepted. Do
not widen those claims.

**Avoid statistical thresholds.** If a test needs a race to land
within a window, it will flake. Restructure so the property is
deterministic.

Ada traps that have bitten this codebase, all silently:

- Tasks declared in a declarative part activate before the enclosing
  `begin`. Declaring them alongside the object they use means they
  run before it is ready.
- An exception raised while elaborating a declaration propagates out
  of the block, past that block's own handler.
- A bare `accept` in a task nothing will call parks it forever, and
  the master waits for it: the process hangs after reporting.
- Counting completions proves nothing about parking: zero returned is
  equally true of "all blocked" and "never started".

## Concurrency and abort

The WebSocket client's correctness argument is about abort. Four GNAT
behaviours were measured and are recorded in
`docs/websocket.md` under *Abort safety is structural*. Read that
before touching the lifecycle controller, the send guard or the
handoff record; each is shaped by one of them.

`AHT.Websocket.Send_Guards` and `AHT.Websocket.Handoffs` are separate
units so their protocols can be driven directly by a test. An
abort-safety claim tested against a hand-written replica is not
tested at all.

## Conformance

`tests/autobahn/` runs about 500 RFC 6455 cases against the client.
Re-run it after changes to the frame path, the session lifecycle or
the connect path, and read `tests/autobahn/BASELINE.md` first: the
OK/NON-STRICT split moves between runs, and which cases may move is
recorded there. Zero hard failures is the pass criterion.

## Bindings

The OpenSSL and mbedTLS bindings under `src/tls/` are generated with
`gcc -fdump-ada-spec` (`scripts/regen_*_bindings.sh`) and curated by
hand. Do not hand-write a `pragma Import`; regenerate and curate.

## Documentation

`docs/` is design documentation, not a changelog. Rewrite from the
implementation rather than patching prose, and when a claim narrows,
grep for every restatement of it.

## Commits

A subject line describing the change and an optional body explaining
why. No trailers, no tool attribution.
