#!/usr/bin/env python3
"""Run one test binary under a hard wall-clock cap.

Why not timeout(1): it is coreutils, and the macOS CI job installs
only openssl@3 — so on that runner the cap simply would not exist,
which is the one place an abort regression could hang the job
indefinitely. And GNU timeout without -k sends only SIGTERM, so a
process that traps or ignores it outlives the advertised cap anyway.
Python is already a hard requirement here (every fixture is a Python
server), so this depends on nothing new.

The child gets its own process group and the cap is enforced against
the whole group, so a test that leaves helpers behind cannot keep the
run alive after its own process is gone. SIGTERM first, so a test can
still unwind and flush what it printed; SIGKILL after a short grace
period, because the tests this backstops are precisely the ones that
may be unable to unwind — Ada waits for dependent tasks at scope
exit, so a task that refuses to terminate blocks its test after it
has already reported the problem.

Exit status is the child's, or 124 when the cap expired — matching
timeout(1) so the runner's reporting does not have to care which
mechanism enforced it.

    usage: run_one.py SECONDS PROGRAM [ARGS...]
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys

GRACE = 5.0          # seconds between SIGTERM and SIGKILL
TIMEOUT_STATUS = 124  # what timeout(1) reports


def signal_group(proc: subprocess.Popen, sig: int) -> None:
    """Signal the child's whole process group, falling back to the
    child alone where process groups are unavailable."""
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except (AttributeError, ProcessLookupError, PermissionError, OSError):
        try:
            proc.send_signal(sig)
        except (ProcessLookupError, OSError):
            pass


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: run_one.py SECONDS PROGRAM [ARGS...]",
            file=sys.stderr,
            flush=True,
        )
        return 2

    try:
        limit = float(sys.argv[1])
    except ValueError:
        print(f"run_one.py: bad timeout {sys.argv[1]!r}", file=sys.stderr)
        return 2

    argv = sys.argv[2:]

    # start_new_session puts the child in its own process group (and
    # session) on POSIX, which is what makes the group signalling
    # below reach helpers the test spawned.
    proc = subprocess.Popen(argv, start_new_session=True)

    try:
        return proc.wait(timeout=limit)
    except subprocess.TimeoutExpired:
        pass

    signal_group(proc, signal.SIGTERM)
    try:
        proc.wait(timeout=GRACE)
    except subprocess.TimeoutExpired:
        signal_group(proc, signal.SIGKILL)
        try:
            proc.wait(timeout=GRACE)
        except subprocess.TimeoutExpired:
            # Unkillable (uninterruptible sleep, most likely). Report
            # the cap anyway rather than waiting here forever, which
            # would be the very failure this exists to prevent.
            pass

    return TIMEOUT_STATUS


if __name__ == "__main__":
    sys.exit(main())
