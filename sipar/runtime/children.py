"""The child process groups of this process: shell.run commands and MCP servers (round 6, R5/R6).

Each child runs in its own session (start_new_session), so a signal to sipar does not reach it. kill_all() kills
every tracked group; it runs at exit (atexit), on SIGTERM / SIGHUP of `sipar` (install_signal_handlers) and on
the first Ctrl-C of a run on the deep worker thread (sipar/deep.py), so no server or command -- nor anything they
started in their group -- outlives sipar. Known limit (R7-5, SPEC §7a): a grandchild that left the group (setsid,
a daemon) is not reached; macOS has no stdlib way (no subreaper, no cgroups) to find it.
"""
from __future__ import annotations

import atexit
import os
import signal
import subprocess
import threading

_LOCK = threading.Lock()
_PROCS: dict[int, tuple[subprocess.Popen, object]] = {}     # pid -> (child, owner: the run that started it)


def track(p: subprocess.Popen) -> None:
    from .. import deep
    with _LOCK:
        _PROCS[p.pid] = (p, deep.stop_event())


def untrack(p: subprocess.Popen) -> None:
    with _LOCK:
        if p.pid in _PROCS and _PROCS[p.pid][0] is p:
            del _PROCS[p.pid]


def tracked() -> list[subprocess.Popen]:
    with _LOCK:
        return [p for p, _ in _PROCS.values()]


def kill_group(p: subprocess.Popen) -> None:
    """SIGKILL the child's whole process group (the child is its leader), else the child; never waits."""
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except (OSError, AttributeError):
        try:
            p.kill()
        except OSError:
            pass


def kill_all(owner: object = None) -> None:
    """Kill every tracked group (only those of one run when owner is given), then reap the children (briefly;
    they were sent SIGKILL)."""
    with _LOCK:
        pids = [pid for pid, (_, o) in _PROCS.items() if owner is None or o is owner]
        procs = [_PROCS.pop(pid)[0] for pid in pids]
    for p in procs:
        if p.poll() is None:
            kill_group(p)
    for p in procs:
        try:
            p.wait(timeout=1)
        except (subprocess.TimeoutExpired, OSError):
            pass


atexit.register(kill_all)

STOP_SIGNALS = ("SIGTERM", "SIGHUP")


def _on_signal(signum, frame) -> None:
    kill_all()
    raise SystemExit(128 + signum)


def install_signal_handlers() -> None:
    """For the `sipar` command: SIGTERM and SIGHUP kill the children, then exit with 128 + the signal number
    (the `finally` blocks run, so the journal is closed). Only a default handler is replaced, only on the
    main thread."""
    if threading.current_thread() is not threading.main_thread():
        return
    for name in STOP_SIGNALS:
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            if signal.getsignal(sig) is signal.SIG_DFL:
                signal.signal(sig, _on_signal)
        except (OSError, ValueError):
            pass
