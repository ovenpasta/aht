# Working on this repository

Notes for anyone contributing, human or agent. Most of it is the
project's testing standard, which is stricter than usual and is the
main thing to absorb before changing anything.

## Layout

```
src/                     the library
src/tls/{openssl,mbedtls}/   one TLS backend body per directory
src/os/{posix,windows}/      one entropy body per OS
csrc/                    C glue for each TLS backend
tests/src/               one .adb per test main, listed in tests/tests.gpr
tests/server/            Python fixtures, one per port
tests/autobahn/          RFC 6455 conformance harness + BASELINE.md
docs/                    the durable design documentation
examples/
```

Exactly one backend directory and one OS directory compile, chosen by
scenario variables. `docs/websocket.md` is the design document for the
WebSocket client and the best starting point.

## Building and testing

```sh
bash tests/run_tests.sh                          # openssl, debug
AHT_TLS_BACKEND=mbedtls bash tests/run_tests.sh  # the other backend
bash examples/run_examples.sh
```

**Both backends, every time.** They differ in real ways — default
trust, iPAddress SANs, error taxonomy — and a change that passes one
routinely fails the other.

The runner starts the Python fixtures itself and refuses to run if any
of them fails to come up. If it reports a port already in use, a
fixture from an earlier run is still alive.

### The Windows cross build

```sh
AHT_TLS_BACKEND=mbedtls AHT_OS=windows bash tests/run_tests.sh
```

Cross-compiles with mingw-w64 and runs the resulting `.exe` under
wine, against the same native fixtures on the same ports — only the
testee crosses over, so a difference is attributable to the port.
Needs `x86_64-w64-mingw32-gnat*` and `wine`; `AHT_CROSS_TARGET` names
a different triplet. That one string drives `gprbuild --target`, the
cross C toolchain, and the object/library/mbedTLS directory names, so
two architectures cannot land in one tree — and the fetch script
checks it against the compiler's own `-dumpmachine`.

**Windows is not a supported configuration** (`windows = false` in
`alire.toml`), and this is not a substitute for running on Windows —
wine implements the API AHT calls, not the one Windows has. It is the
fast loop, and it has already earned its keep twice: it found a
`Poison` that could not wake a reader, because Winsock does not signal
a parked `select` on a locally initiated shutdown; and it found a
session left attached to its collection uninitialized by an abort
inside `new`, which hung library finalization on a zero-filled
`CRITICAL_SECTION`. Both are invisible on Linux, the second of them
because a zeroed `pthread_mutex_t` is a valid unlocked one.

All 58 pass, with two named skips in `test_ws_abort`. GNAT on Linux
interrupts a blocking syscall with a signal, so aborting a task parked
in `Check_Selector` unwinds it; Windows has no such mechanism, so the
abort is deferred until the call returns on its own — never, for a
`Forever` wait. Measured with a standalone probe, not inferred from
the manual. Cases 2 and 4 aim a transfer of control at a task parked
in a socket call and are skipped; the rest run. **Which two was found
by running it** — case 4 was skipped first on the assumption that it
was the only one, and the main still hung.

The library's own teardown paths pair every abort with
`Abort_Pending`, which wakes the selector explicitly and does not
depend on this. A caller who instead aborts a task sitting in `Send`
or `Connect` gets a hang. That is a real narrowing of the abort
guarantee — see *Abort safety is structural* in `docs/websocket.md` —
and it is why the port is not finished.

## The testing standard

This is the part that matters, and it is not the usual bar.

**Establish the premise, do not assume it.** A test that races
something must prove the race happened. A `delay` may give it a
chance, but it is never the evidence — assert on an observed fact: a
counter, a protected flag, a token the fixture recorded, a task's
`'Terminated`. Timing is allowed only as a liveness backstop so a
broken build reports instead of hanging.

**Validate both directions.** Back the guard out and confirm the test
fails; then make the race *not* happen and confirm it fails
differently. A test that has only ever been seen passing has not been
tested. Several tests here passed while checking nothing until this
was applied to them.

**Say exactly what is proven.** Where a property rests on a structural
argument rather than a test, the code says so. See the notes in
`test_ws_abort`, `test_ws_masking` and `AHT.Websocket.Handoffs` — each
records what its checks do *not* cover, and why the gap was accepted.
Do not quietly widen those claims.

**Statistical thresholds are usually a mistake.** If a test needs a
race to land within a window, it will flake. Prefer restructuring so
the property is deterministic; a sampler that cannot tell whether it
landed is worse than no test. One was removed for exactly this.

Known Ada traps that have bitten this codebase, all of them silently:

- Tasks declared in a declarative part activate **before** the
  enclosing `begin`. Declaring them alongside the object they use
  means they run before it is ready.
- An exception raised while elaborating a declaration propagates *out
  of* the block, past that block's own handler.
- A bare `accept` in a task nothing will call parks it forever, and
  the master waits for it — the process hangs after reporting.
- Counting completions proves nothing about parking: zero returned is
  equally true of "all blocked" and "never started".

## Concurrency and abort

The WebSocket client's correctness argument is about abort, and three
GNAT behaviours were measured rather than assumed. They are recorded
in `docs/websocket.md` under *Abort safety is structural*. Read that
before touching the lifecycle controller, the send guard or the
handoff record — each is shaped by one of them, and each looks
needlessly convoluted until you know which.

`AHT.Websocket.Send_Guards` and `AHT.Websocket.Handoffs` are separate
units so their protocols can be driven directly by a test. An
abort-safety claim tested against a hand-written replica is not
tested at all.

## Conformance

`tests/autobahn/` runs ~500 RFC 6455 cases against the client. Re-run
it after changes to the frame path, the session lifecycle or the
connect path, and read `tests/autobahn/BASELINE.md` first — the
OK/NON-STRICT split moves between runs, and which cases may move is
recorded there. Zero hard failures is the number that matters.

## Documentation

`docs/` is durable design documentation, not a changelog. It drifts:
rewrite from the implementation rather than patching prose, and when a
claim narrows, grep for every restatement of it rather than editing
the paragraph that prompted the change.

## Git commits

- **Do not** add `Co-Authored-By: Claude ...` trailers.
- **Do not** add "Generated with Claude Code" or other tool-attribution
  footers to commits or PR bodies.
- Subject line describing the change, optional body explaining the
  *why*, nothing else.
