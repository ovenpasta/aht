#!/usr/bin/env python3
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
"""Run one test binary under a hard wall-clock cap.

    usage: run_one.py SECONDS PROGRAM [ARGS...]

timeout(1) is coreutils, which the macOS CI job does not install, and
without -k it sends only SIGTERM. The child gets its own session and
everything is driven by the resulting process group, which outlives
its leader, so helpers left behind by a normal exit or ignoring
SIGTERM are still reached. SIGTERM first so a test can flush what it
printed, SIGKILL after a grace period: Ada waits for dependent tasks
at scope exit, and a task that refuses to terminate blocks its test.
Termination signals to the runner are forwarded to the group, and the
group is cleaned up on every exit path.

Exit status is the child's, or 124 when the cap expired, as with
timeout(1).
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

    Signal 0 checks for existence without delivering anything. Poll
    the child first: a reaped leader is gone from the group, an
    unreaped zombie keeps it 'alive'.
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

    The leader may already be gone while a helper that ignores
    SIGTERM is still running; that helper must not survive this call.
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

    # Give the kill a moment to take, then stop waiting: a process in
    # uninterruptible sleep must not hang this wrapper.
    deadline = time.monotonic() + GRACE
    while time.monotonic() < deadline:
        proc.poll()
        if not group_alive(pgid):
            return
        time.sleep(POLL)


def shell_status(status: int) -> int:
    """Translate a subprocess return code into a shell exit status.

    subprocess reports death by signal as a negative code; shells
    report 128 + signal. Passed straight to sys.exit the negative wraps
    modulo 256, so SIGTERM would surface as 241 instead of 143.
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

    # Handlers go in before the spawn: installed afterwards, a signal
    # arriving between the child existing and the handler being in
    # place kills the wrapper while the child, in its own session,
    # survives. Until there is a group the handler only records what
    # arrived; the spawn honours it immediately afterwards.
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
    # group; the group id is the child's pid, saved now so the group
    # stays addressable after the leader is gone.
    proc = subprocess.Popen(argv, start_new_session=True)
    state["proc"] = proc
    state["pgid"] = proc.pid
    pgid = proc.pid

    # A signal that landed during the spawn was only recorded.
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
