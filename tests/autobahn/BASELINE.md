<!--
SPDX-FileCopyrightText: 2026 Aldo Nicolas Bruno
SPDX-License-Identifier: Apache-2.0
-->

# Autobahn conformance baseline

The generated reports are gitignored (about 1000 files, rewritten by
every run). This file records the counts a run should reproduce and
the classification of the cases that are not `OK`.

Zero hard failures is the pass criterion. This is not full
conformance: 216 cases are `UNIMPLEMENTED` and four to eleven are
`NON-STRICT`.

## Baseline

| | |
|---|---|
| Suite | AutobahnTestSuite 25.10.1 / Autobahn 0.10.9 |
| Image | `crossbario/autobahn-testsuite:latest` |
| Image digest | `sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074` |
| Testee | `tests/autobahn/bin/debug-openssl/aht_autobahn` |
| Backend / profile | `AHT_TLS_BACKEND=openssl`, `BUILD_MODE=debug` |
| Commit | `a17eba9` |

`run.sh` defaults to the mutable `:latest` tag, so the digest is
what identifies the suite a run was against; compare it before
comparing splits.

| Behaviour | Cases |
|---|---|
| OK | 287–294 |
| UNIMPLEMENTED | 216 |
| NON-STRICT | 4–11 |
| INFORMATIONAL | 3 |
| **FAILED / WRONG CODE / UNCLEAN** | **0** |
| Total | 517 |

`UNIMPLEMENTED` is §12 and §13, `permessage-deflate`. The client
negotiates no extensions, so the suite reports every compression case
that way. This is a scope decision.

## Cases that move between OK and NON-STRICT

| | |
|---|---|
| Stable `NON-STRICT` | 6.4.1, 6.4.2, 6.4.3, 6.4.4 |
| Flapping | 3.2, 3.3, 3.4, 4.1.3, 4.1.4, 4.2.3, 4.2.4, 5.15 |

The flapping cases share one shape. A valid message arrives and is
queued; then a protocol violation fails the connection. `OK` requires
the earlier message to be delivered anyway; `NON-STRICT` tolerates it
being dropped. Whether it is delivered depends on whether the
testee's `Receive` pulls it out of the inbox before the teardown
stops admission, after which the borrow is refused and the queued
message is freed with its session. This is a consequence of the
per-session inbox, the same generation scoping that stops a reconnect
inheriting a previous connection's backlog (see the delivery contract
in `AHT.Websocket.Client`: pull and push agree on what is accepted,
not on what is eventually observed). Recovering the `OK`s would mean
keeping a closing session borrowable, which reopens the reclamation
gate, or promoting queued messages to client scope, which complicates
generation isolation and ordering; neither is worth it for a
classification the suite accepts.

The `NON-STRICT` total is 4 when every race is won (the stable four
alone) and has reached 11 in a single run that lost most of them at
once, on the same binary, digest and machine as its neighbours.

## Running and reading a run

```sh
alr exec -- gprbuild -P tests/autobahn/autobahn.gpr   # the testee
sh tests/autobahn/run.sh                              # needs docker
```

Then compare `tests/autobahn/reports/index.json` against the tables
above:

- Any case reaching `FAILED`, `WRONG CODE` or `UNCLEAN` is a
  regression.
- A case moving between `OK` and `NON-STRICT` within the set above
  is not, and neither is the `NON-STRICT` total moving anywhere
  inside 4–11.
- A case leaving `OK` that is not in that set is explained by a run
  on a clean tree before it is accepted here; the split is noisy
  enough that a pair of runs supports almost any story.
