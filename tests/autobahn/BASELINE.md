# Autobahn conformance baseline

The generated reports are gitignored — they are ~1000 files and are
rewritten wholesale by every run. This file is the durable record: the
counts a run should reproduce, and the reasoning behind the cases that
are not `OK`.

Phrasing matters here. **Zero hard failures** is what these numbers
say. Not "full conformance": 216 cases are `UNIMPLEMENTED` and four to
eleven are `NON-STRICT`, and a claim of full conformance would paper
over both.

## Latest run

| | |
|---|---|
| Date | 2026-08-31 |
| Suite | AutobahnTestSuite 25.10.1 / Autobahn 0.10.9 |
| Image | `crossbario/autobahn-testsuite:latest` |
| Image digest | `sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074` |
| Testee | `tests/autobahn/bin/debug-openssl/aht_autobahn` |
| Backend / profile | `AHT_TLS_BACKEND=openssl`, `BUILD_MODE=debug` |
| Commit | `a17eba9`, with five paired runs at its parent `66308d5` |

The digest is recorded because `run.sh` defaults to the mutable
`:latest` tag. Two runs months apart are not necessarily against the
same suite, and without the digest a changed result cannot be told
apart from a changed test. Here it is unchanged from the 2026-08-25
block, so the two runs are against the same suite and their splits are
comparable.

`a17eba9` and the commits between it and `66e6698` do not touch the
WebSocket path at all — neither `AHT.Websocket.Client` nor the testee
references `AHT.HTTP.Client`. The run is recorded because this file is
the durable record of what was observed, not because the change could
have moved it.

| Behaviour | Cases |
|---|---|
| OK | 287–294 |
| UNIMPLEMENTED | 216 |
| NON-STRICT | 4–11 |
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
| Flapping | 3.2, 3.3, 3.4, 4.1.3, 4.1.4, 4.2.3, 4.2.4, 5.15 |

Twenty-one runs, for evidence. Both dated blocks below are runs
against one unchanged image digest, and each pairs runs on the tree
under test with runs on a tree that does **not** carry the change —
recorded that way on purpose, because it is what separates "these
cases flap" from "this change moved them":

```
2026-08-07   NON-STRICT = 5.15, 6.4.1-4
2026-08-17a  NON-STRICT = 3.2, 3.3, 6.4.1-4
2026-08-17b  NON-STRICT = 3.3, 4.1.4, 6.4.1-4
2026-08-25 @ 69c6cb0, clean tree (pre-66e6698)
  a          NON-STRICT = 3.3, 4.1.3, 6.4.1-4
  b          NON-STRICT = 4.2.3, 6.4.1-4
2026-08-25 + Connect bounds
  a          NON-STRICT = 4.1.3, 4.1.4, 4.2.3, 4.2.4, 6.4.1-4
  b          NON-STRICT = 3.2, 3.3, 4.2.4, 5.15, 6.4.1-4
  c          NON-STRICT = 4.2.4, 6.4.1-4
  d          NON-STRICT = 4.2.3, 4.2.4, 6.4.1-4
  e          NON-STRICT = 4.1.3, 4.1.4, 5.15, 6.4.1-4
2026-08-31 @ 66308d5, the parent (no per-phase bounds)
  a          NON-STRICT = 5.15, 6.4.1-4                          (5)
  b          NON-STRICT = 3.2, 3.3, 6.4.1-4                      (6)
  c          NON-STRICT = 4.2.3, 4.2.4, 6.4.1-4                  (6)
  d          NON-STRICT = 4.1.4, 6.4.1-4                         (5)
  e          NON-STRICT = 3.2, 3.3, 4.2.4, 5.15, 6.4.1-4         (8)
2026-08-31 @ a17eba9, the per-phase bounds
  a          NON-STRICT = 3.2, 3.3, 3.4, 4.1.3, 4.1.4, 4.2.3,
                          5.15, 6.4.1-4                         (11)
  b          NON-STRICT = 6.4.1-4                                (4)
  c          NON-STRICT = 4.2.3, 6.4.1-4                         (5)
  d          NON-STRICT = 4.2.4, 5.15, 6.4.1-4                   (6)
  e          NON-STRICT = 3.2, 4.1.4, 6.4.1-4                    (6)
  f          NON-STRICT = 6.4.1-4                                (4)
```

4.1.3, 4.2.3 and 4.2.4 are additions to the flapping set, and the two
clean-tree runs are why they are recorded as flapping rather than
investigated as a regression: 4.1.3 and 4.2.3 each appear with no
local change at all, one run apart, from the same binary. 4.2.4 was
seen only on the modified tree, but its totals sit inside the
clean-tree range and it is 4.2.3's own pair — the same case with the
fragmented payload — so it is recorded here rather than singled out.

Two runs of one build are not a distribution, and the first reading of
these numbers was wrong for that reason: 8 and 8 against 6 and 5
looked like a consistent step until three more runs came back 5, 6 and
7. Anything drawn from a pair of runs here should be assumed to be
noise until a third contradicts it.

The 2026-08-31 block is why the recorded range moved from 5–8 to
4–11. Both ends were seen on the tree carrying the change and neither
is a defect: 4 is the floor, the stable four alone with every race
won, and 11 is one run in eleven that lost most of them at once.
Nothing separates that run from its five neighbours except which way
the races fell — same binary, same digest, same machine.

3.4 joins the flapping set on structure rather than on a repeat
sighting: it was seen once, on the tree under test, and not
reproduced at the parent. It is admitted anyway because it is 3.2 and
3.3's own sibling — the suite's descriptions have all three sending a
valid text message, then the same message again with `RSV` set, then
a Ping, differing only in the reserved value and whether the octets
arrive frame-wise or octet-wise. That is exactly the shape the whole
set shares, described below. Treating it as a regression would mean
claiming the change reached a path it has no reference to. The single
sighting is recorded plainly instead, so a future run that finds 3.4
routinely has something to compare against.

The flapping cases have one shape. A valid message arrives and is
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
*within the set above* is not, and neither is the `NON-STRICT` total
moving anywhere inside 4–11. A case moving out of `OK` that is **not**
in that set is worth explaining here before it is accepted — and the
way to explain it is a run on a clean tree, not an argument, because
this suite's split is noisy enough that a plausible story fits almost
any pair of runs.

## Reproducing

```sh
alr exec -- gprbuild -P tests/autobahn/autobahn.gpr   # build the testee first
sh tests/autobahn/run.sh                              # needs docker
```

Then compare `tests/autobahn/reports/index.json` against the counts
above, reading them as *Reading a run* describes — the zero is the
number that matters, and a case moving between `OK` and `NON-STRICT`
inside the flapping set is expected rather than a regression.
