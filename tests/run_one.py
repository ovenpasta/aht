#!/usr/bin/env python3
"""Run one test binary under a hard wall-clock cap.

Why not timeout(1): it is coreutils, and the macOS CI job installs
only openssl@3 — so on that runner the cap simply would not exist,
which is the one place an abort regression could hang the job
indefinitely. And GNU timeout without -k sends only SIGTERM, so a
process that traps or ignores it outlives the advertised cap anyway.
Python is already a hard requirement here (every fixture is a Python
server), so this depends on nothing new.

The child gets its own session, and everything below is driven by the
resulting process GROUP rather than by the child itself. That
distinction is the whole point: the group outlives its leader, so
watching only the leader lets helpers escape twice over — once when
the test exits normally having left something behind, and again on
the timeout path, where the leader dying to SIGTERM would otherwise
be read as "done" and skip the SIGKILL that the helper ignoring
SIGTERM still needs.

SIGTERM first, so a test can unwind and flush what it printed;
SIGKILL after a grace period, because the tests this backstops are
precisely the ones that may be unable to unwind — Ada waits for
dependent tasks at scope exit, so a task that refuses to terminate
blocks its test after it has already reported the problem.

Because the child is in its own session it never sees signals sent to
the runner's terminal, so interrupting the suite would otherwise
leave a live test group behind. Termination signals are forwarded to
the group, and the group is cleaned up on every exit path.

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
import time

GRACE = 5.0           # seconds between SIGTERM and SIGKILL
POLL = 0.05
TIMEOUT_STATUS = 124  # what timeout(1) reports


def signal_group(pgid: int, sig: int) -> None:
    """Best-effort signal to a whole process group."""
    try:
        os.killpg(pgid, sig)
    except (AttributeError, ProcessLookupError, PermissionError, OSError):
        pass


def group_alive(pgid: int) -> bool:
    """Whether any process remains in the group.

    Signal 0 checks for existence without delivering anything. A
    reaped leader is gone from the group, so callers should poll the
    child first — otherwise its zombie keeps the group 'alive'.
    """
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True          # exists, just not ours to signal
    except (AttributeError, OSError):
        return False


def reap_group(proc: subprocess.Popen, pgid: int) -> None:
    """Terminate everything left in the group, leader or not.

    Driven by the group: the leader may already be gone (normal exit,
    or killed by the SIGTERM below) while a helper that ignores
    SIGTERM is still running, and that helper is exactly what must not
    survive this call.
    """
    proc.poll()
    if not group_alive(pgid):
        return

    signal_group(pgid, signal.SIGTERM)

    deadline = time.monotonic() + GRACE
    while time.monotonic() < deadline:
        proc.poll()                     # reap the leader if it exited
        if not group_alive(pgid):
            return
        time.sleep(POLL)

    signal_group(pgid, signal.SIGKILL)

    # Give the kill a moment to take, then stop caring: an
    # unkillable process (uninterruptible sleep) must not make this
    # wrapper hang, which would be the very failure it exists to
    # prevent.
    deadline = time.monotonic() + GRACE
    while time.monotonic() < deadline:
        proc.poll()
        if not group_alive(pgid):
            return
        time.sleep(POLL)


def shell_status(status: int) -> int:
    """Translate a subprocess return code into a shell exit status.

    subprocess reports death by signal as a negative code; shells
    report 128 + signal. Passing the negative straight to sys.exit
    wraps it modulo 256, so a test killed by SIGTERM would surface as
    241 instead of 143 — a number the runner would print as an
    ordinary failure with no hint that a signal was involved.
    """
    if status < 0:
        return 128 - status          # status is negative
    return status


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

    # Handlers go in BEFORE the spawn. Installing them afterwards
    # leaves a window between the child existing and the wrapper being
    # able to clean it up: a signal arriving there kills the wrapper
    # by default while the child, isolated in its own session, never
    # sees it and survives. Measured — that window escapes.
    #
    # Until there is a group to clean, the handler can only record
    # what arrived; the spawn honours it immediately afterwards.
    state = {"proc": None, "pgid": None, "pending": None}

    def on_signal(signum, _frame):
        if state["pgid"] is None:
            state["pending"] = signum
            return
        reap_group(state["proc"], state["pgid"])
        os._exit(128 + signum)

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(sig, on_signal)
        except (ValueError, OSError, AttributeError):
            pass                        # not available here; carry on

    if state["pending"] is not None:
        return 128 + state["pending"]   # nothing spawned yet

    # start_new_session puts the child in its own session and process
    # group on POSIX; the group id is then the child's pid. Saved now,
    # so the group stays addressable after the leader is gone.
    proc = subprocess.Popen(argv, start_new_session=True)
    state["proc"] = proc
    state["pgid"] = proc.pid
    pgid = proc.pid

    # A signal that landed during the spawn was recorded rather than
    # acted on, because there was nothing to clean up yet.
    if state["pending"] is not None:
        reap_group(proc, pgid)
        os._exit(128 + state["pending"])

    timed_out = False
    try:
        try:
            status = proc.wait(timeout=limit)
        except subprocess.TimeoutExpired:
            timed_out = True
            status = TIMEOUT_STATUS
        else:
            if group_alive(pgid):
                print(
                    f"run_one.py: {argv[0]} exited leaving processes in"
                    " its group; cleaning up",
                    file=sys.stderr,
                    flush=True,
                )
    finally:
        reap_group(proc, pgid)

    return TIMEOUT_STATUS if timed_out else shell_status(status)


if __name__ == "__main__":
    sys.exit(main())
