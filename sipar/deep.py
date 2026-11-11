"""Run deep recursion safely (round 5, F1/F5).

The parser, the checker and the interpreter are recursive. Python's default limits (1000 frames, an 8 MiB main
thread stack) stop them long before the limits Sipar promises: SIPAR_MAX_DEPTH up to 20000 calls, expressions
nested up to parser.MAX_NESTING levels and AST chains up to parser.MAX_AST_DEPTH. call_deep() runs a function on
a worker thread with a large stack and a high recursion limit, and waits for it. Nested call_deep() calls run
directly on the worker. A RecursionError is still possible for absurd inputs; callers turn it into a Sipar error.
"""
from __future__ import annotations

import ctypes
import sys
import threading
from typing import Any, Callable

from .errors import active_registry, use_registry

STACK_BYTES = 1 << 30           # 1 GiB of address space for the worker; pages are only used when touched
RECURSION_LIMIT = 400_000       # Python frames; with the big stack, C-level recursion hits RecursionError first

_state = threading.local()
_start_lock = threading.Lock()  # threading.stack_size() is process-wide: set, start, restore under a lock


STOP_GRACE = 2.0               # seconds the caller waits for the worker after the first Ctrl-C (round 6, R6)


def inside() -> bool:
    return getattr(_state, "deep", False)


def stop_event() -> threading.Event | None:
    """On the worker: the event set by the first Ctrl-C, for waits that should end at once (sleep, MCP)."""
    return getattr(_state, "stop", None)


def stopping() -> bool:
    ev = stop_event()
    return ev is not None and ev.is_set()


_limit_lock = threading.Lock()
_limit_users = 0                # call_deep calls running now (several host threads may call at once)
_limit_saved = 0                # the host's recursion limit before the first of them


def _raise_limit() -> None:
    global _limit_users, _limit_saved
    with _limit_lock:
        if _limit_users == 0:
            _limit_saved = sys.getrecursionlimit()
            if _limit_saved < RECURSION_LIMIT:
                sys.setrecursionlimit(RECURSION_LIMIT)
        _limit_users += 1


def _restore_limit() -> None:
    """The last running call puts the host's recursion limit back (L6, round 6), unless the host changed it
    meanwhile."""
    global _limit_users
    with _limit_lock:
        _limit_users -= 1
        if _limit_users == 0 and _limit_saved < RECURSION_LIMIT and sys.getrecursionlimit() == RECURSION_LIMIT:
            try:
                sys.setrecursionlimit(_limit_saved)
            except RecursionError:      # the caller is deeper than its old limit: keep the high one
                pass


def call_deep(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """fn(*args, **kwargs) on a big-stack worker thread; its result or exception comes back to the caller.
    Ctrl-C in the caller is passed on to the worker as KeyboardInterrupt, so its cleanup code still runs.
    The recursion limit is high only while a call runs; the thread stack size is the host's again at once."""
    if inside():
        return fn(*args, **kwargs)
    _raise_limit()
    try:
        return _call_on_worker(fn, args, kwargs)
    finally:
        _restore_limit()


def _call_on_worker(fn: Callable[..., Any], args: tuple, kwargs: dict) -> Any:
    box: dict = {}
    reg = active_registry()         # the caller's run-local secret registry goes along (round 5, C1)
    stop = threading.Event()
    done = threading.Event()        # set by the worker when it ends; see the 3.12 note below

    def body() -> None:
        _state.deep = True
        _state.stop = stop
        try:
            with use_registry(reg):
                box["value"] = fn(*args, **kwargs)
        except BaseException as e:          # noqa: BLE001 - every outcome goes back to the caller
            box["error"] = e
        finally:
            done.set()

    worker = None
    with _start_lock:
        old = threading.stack_size()
        try:
            threading.stack_size(STACK_BYTES)
        except (ValueError, RuntimeError):  # the platform refuses a custom stack size: run on this thread
            pass
        else:
            try:
                w = threading.Thread(target=body, name="sipar-run", daemon=True)
                w.start()
                worker = w
            except RuntimeError:            # no memory or no threads left for a big stack: run on this thread
                pass
            finally:
                threading.stack_size(old)
    if worker is None:
        return fn(*args, **kwargs)
    interrupted = False
    # R6b (round 6): wait on our own event, not on join()/is_alive(): on Python 3.12 a join() interrupted
    # by Ctrl-C marks the thread as stopped, so is_alive() said False and the call returned None at once
    while not done.is_set():
        try:
            if not interrupted:
                done.wait()
            else:
                # R6 (round 6): the worker may be blocked in C (I/O) where the KeyboardInterrupt cannot reach
                # it; after a short grace the caller stops waiting (its children are already killed)
                if not done.wait(STOP_GRACE):
                    raise KeyboardInterrupt
        except KeyboardInterrupt:
            if interrupted:                 # a second Ctrl-C, or the grace is over: stop waiting
                raise
            interrupted = True
            stop.set()                      # ends sleep() and MCP waits on the worker at once
            ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_ulong(worker.ident),
                                                       ctypes.py_object(KeyboardInterrupt))
            from .runtime import children   # shell commands and MCP servers die now, so blocked reads end
            children.kill_all(stop)
    if "error" in box:
        err = box.pop("error")
        try:
            raise err
        finally:
            del err
    return box.get("value")
