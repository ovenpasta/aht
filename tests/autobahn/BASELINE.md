# Autobahn conformance baseline

The generated reports are gitignored — they are ~1000 files and are
rewritten wholesale by every run. This file is the durable record: the
counts a run should reproduce, and the reasoning behind the cases that
are not `OK`.

Phrasing matters here. **Zero hard failures** is what these numbers
say. Not "full conformance": 216 cases are `UNIMPLEMENTED` and five or
six are `NON-STRICT`, and a claim of full conformance would paper over
both.

## Latest run

| | |
|---|---|
| Date | 2026-08-17 |
| Suite | AutobahnTestSuite 25.10.1 / Autobahn 0.10.9 |
| Image | `crossbario/autobahn-testsuite:latest` |
| Image digest | `sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074` |
| Testee | `tests/autobahn/bin/debug-openssl/aht_autobahn` |
| Backend / profile | `AHT_TLS_BACKEND=openssl`, `BUILD_MODE=debug` |
| Commit | `1a076f8` (re-run after the handoff extraction and CA_PEM) |

The digest is recorded because `run.sh` defaults to the mutable
`:latest` tag. Two runs months apart are not necessarily against the
same suite, and without the digest a changed result cannot be told
apart from a changed test.

| Behaviour | Cases |
|---|---|
| OK | 292–293 |
| UNIMPLEMENTED | 216 |
| NON-STRICT | 5–6 |
| INFORMATIONAL | 3 |
| **FAILED / WRONG CODE / UNCLEAN** | **0** |
| Total | 517 |

`UNIMPLEMENTED` is §12 and §13 — `permessage-deflate`. The client
negotiates no extensions, so the suite reports every compression case
that way. This is a scope decision, not a defect.

**The zero is the number to check.** The OK/NON-STRICT split is not
fixed, and an earlier version of this file was wrong to record a
single run's split as though it were.

## Which cases flap, and why

| | |
|---|---|
| Stable `NON-STRICT` | 6.4.1, 6.4.2, 6.4.3, 6.4.4 |
| Flapping | 3.2, 3.3, 4.1.4, 5.15 |

Three runs, for evidence:

```
2026-08-07   NON-STRICT = 5.15, 6.4.1-4
2026-08-17a  NON-STRICT = 3.2, 3.3, 6.4.1-4
2026-08-17b  NON-STRICT = 3.3, 4.1.4, 6.4.1-4
```

The four flapping cases have one shape. A valid message arrives and is
queued; then a protocol violation fails the connection. `OK` requires
that earlier message to be delivered anyway; `NON-STRICT` tolerates it
being dropped. Whether it is delivered depends on whether the testee's
`Receive` pulls it out of the inbox before the teardown stops
admission — after which the borrow is refused and the queued message
is freed with its session.

So it is a race, and it is a consequence of the per-session inbox
rather than a defect: the same generation scoping that stops a
reconnect inheriting a previous connection's backlog. See the delivery
contract in `AHT.Websocket.Client` — pull and push agree on what is
*accepted*, not on what is eventually *observed*. Recovering the `OK`s
would mean keeping a closing session borrowable, which reopens the
reclamation gate, or promoting queued messages to client scope, which
complicates generation isolation and ordering. Neither is worth it for
a classification the suite already accepts.

**Reading a run.** Any case reaching `FAILED`, `WRONG CODE` or
`UNCLEAN` is a regression. A case moving between `OK` and `NON-STRICT`
*within the set above* is not, and neither is the total moving by one.
A case moving out of `OK` that is **not** in that set is worth
explaining here before it is accepted.

## Reproducing

```sh
alr exec -- gprbuild -P tests/autobahn/autobahn.gpr   # build the testee first
sh tests/autobahn/run.sh                              # needs docker
```

Then compare `tests/autobahn/reports/index.json` against the counts
above, reading them as *Reading a run* describes — the zero is the
number that matters, and a case moving between `OK` and `NON-STRICT`
inside the flapping set is expected rather than a regression.
