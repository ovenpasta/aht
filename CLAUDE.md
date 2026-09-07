<!--
SPDX-FileCopyrightText: 2026 Aldo Nicolas Bruno
SPDX-License-Identifier: Apache-2.0
-->

# Notes for agents

Read `CONTRIBUTING.md` first. It holds the layout, the build and test
commands, the testing standard and the concurrency notes; everything
there applies to agents as it does to people.

Points that agents get wrong most often:

- Run both TLS backends (`bash tests/run_tests.sh` and
  `AHT_TLS_BACKEND=mbedtls bash tests/run_tests.sh`) before claiming a
  change works. If the change touches the frame path, the session
  lifecycle or the connect path, also run `tests/autobahn/run.sh` and
  compare against `tests/autobahn/BASELINE.md`.
- A test that only delays and then checks has not established its
  premise. Assert on an observed fact, and validate by backing the
  guard out.
- Comments and docs state what is, not what used to be. Do not narrate
  history, sessions or measurements in them.
- Do not add `Co-Authored-By`, "Generated with" or any other trailer
  or attribution to commits or pull requests.
- Every new file needs the SPDX header used by its neighbours;
  `reuse lint` must stay clean.
