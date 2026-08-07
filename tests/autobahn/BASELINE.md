# Autobahn conformance baseline

The generated reports are gitignored — they are ~1000 files and are
rewritten wholesale by every run. This file is the durable record: the
counts a run should reproduce, and the reasoning behind the cases that
are not `OK`.

Phrasing matters here. **Zero hard failures** is what these numbers
say. Not "full conformance": 216 cases are `UNIMPLEMENTED` and five are
`NON-STRICT`, and a claim of full conformance would paper over both.

## Latest run

| | |
|---|---|
| Date | 2026-08-07 |
| Suite | AutobahnTestSuite 25.10.1 / Autobahn 0.10.9 |
| Image | `crossbario/autobahn-testsuite:latest` |
| Image digest | `sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074` |
| Testee | `tests/autobahn/bin/debug-openssl/aht_autobahn` |
| Backend / profile | `AHT_TLS_BACKEND=openssl`, `BUILD_MODE=debug` |
| Commit | the reconnect redesign, through `f13ff6e` |

The digest is recorded because `run.sh` defaults to the mutable
`:latest` tag. Two runs months apart are not necessarily against the
same suite, and without the digest a changed result cannot be told
apart from a changed test.

| Behaviour | Cases |
|---|---|
| OK | 293 |
| UNIMPLEMENTED | 216 |
| NON-STRICT | 5 |
| INFORMATIONAL | 3 |
| **FAILED / WRONG CODE / UNCLEAN** | **0** |
| Total | 517 |

`UNIMPLEMENTED` is §12 and §13 — `permessage-deflate`. The client
negotiates no extensions, so the suite reports every compression case
that way. This is a scope decision, not a defect.

## Delta from the previous baseline

The run before this one was 2026-06-06, against the pre-reconnect
client: 294 OK, 216 UNIMPLEMENTED, 4 NON-STRICT, 3 INFORMATIONAL, zero
failures.

Across the entire redesign — persistent receiver, heap-owned
per-generation sessions, `Reconnect`, limits and delivery modes, the
decoder `Allowance` parameter, and the change of masking source from a
clock-seeded PRNG to the OS entropy pool — **exactly one case moved,
and nothing regressed into failure.**

### Case 5.15: `OK` → `NON-STRICT`, accepted

> Send text Message fragmented into 2 fragments, then Continuation
> Frame with FIN = false where there is nothing to continue, then
> unfragmented Text Message, all sent in one chop.

The connection is failed, correctly, and closed cleanly
(`behaviorClose: OK`). What changed is that the *completed* first
message is no longer delivered ahead of the failure: the suite
observed `received: []` where it would accept
`["fragment1fragment2"]`.

The cause is not the §5.4 sequencing check, which is the obvious
suspect. It is the borrow:

- The inbox is not at fault. `Inbox.Receive` drains queued messages
  and only raises once the queue is empty.
- `Client.Receive` must borrow the session to reach that inbox, and a
  borrow is refused the moment admission stops. When the protocol
  error tears the session down, the completed message is still in the
  inbox and is freed with it.

So a message that was accepted and enqueued, but not yet pulled when
the connection failed, is discarded. That is the same generation
scoping that stops a reconnect inheriting the previous connection's
backlog — pinned deliberately by `test_ws_reconnect_isolation` case 2
— seen from the other side.

**Accepted rather than fixed.** Recovering the `OK` would mean either
keeping a closing session borrowable, which reopens the reclamation
gate the borrow count exists to close, or promoting queued messages to
client scope, which complicates generation isolation and ordering.
Neither is worth one classification: RFC 6455 does not require
delivery of earlier messages when failing the connection, and the
suite accepts the behaviour.

The spec documents the narrower contract this implies — pull and push
agree on what is *accepted*, not on what is eventually *observed*.

## Reproducing

```sh
alr exec -- gprbuild -P tests/autobahn/autobahn.gpr   # build the testee first
sh tests/autobahn/run.sh                              # needs docker
```

Then compare `tests/autobahn/reports/index.json` against the counts
above. A case moving out of `OK`, or any case reaching `FAILED`,
`WRONG CODE` or `UNCLEAN`, is a regression and wants explaining here
before it is accepted.
