"""HTTP with a whole-request deadline.

urllib's `timeout` is per socket operation: a server that sends one byte every few seconds keeps a request alive
forever. `fetch` arms a timer that shuts the connection's socket down when the deadline passes, so connect,
headers and body together can never take longer than `seconds` (SPEC §6 budgets, §7 effects).
"""
from __future__ import annotations

import http.client
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from typing import Any

from ..errors import clip


ERROR_BODY = 2000                  # bytes of an HTTP error response kept for the error message
MAX_SECONDS = 86_400.0             # no request deadline is longer (SPEC §7 timeouts)


def env_seconds(name: str, default: float) -> float:
    """The one parser for SIPAR_HTTP_TIMEOUT / SIPAR_AI_TIMEOUT / SIPAR_SHELL_TIMEOUT (SPEC §7): a finite
    number of seconds in (0, MAX_SECONDS]; anything else (unset, empty, text, 0, negative, NaN, infinity,
    larger than the maximum) means the default."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        t = float(raw.strip())
    except (ValueError, OverflowError):
        return default
    if not (0 < t <= MAX_SECONDS):            # also false for NaN
        return default
    return t


class DeadlineExceeded(Exception):
    """The whole request took longer than its deadline."""


class _Deadline:
    def __init__(self, seconds: float):
        self.seconds = seconds
        self.expired = False
        self.socks: list[socket.socket] = []
        self.lock = threading.Lock()

    def add(self, sock: socket.socket) -> None:
        with self.lock:
            self.socks.append(sock)
            if self.expired:
                _kill(sock)

    def fire(self) -> None:
        with self.lock:
            self.expired = True
            for s in self.socks:
                _kill(s)


def _kill(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def _connector(dl: _Deadline):
    def create(*a: Any, **kw: Any) -> socket.socket:
        s = socket.create_connection(*a, **kw)
        dl.add(s)
        return s
    return create


def _handlers(dl: _Deadline) -> list:
    class H(urllib.request.HTTPHandler):
        def http_open(self, req):
            def conn(host, **kw):
                c = http.client.HTTPConnection(host, **kw)
                c._create_connection = _connector(dl)
                return c
            return self.do_open(conn, req)

    class HS(urllib.request.HTTPSHandler):
        def https_open(self, req):
            def conn(host, **kw):
                c = http.client.HTTPSConnection(host, **kw)
                c._create_connection = _connector(dl)
                return c
            return self.do_open(conn, req, context=self._context)

    return [H(), HS()]


def fetch(req: urllib.request.Request, seconds: float, limit: int, handlers: tuple = ()) -> bytes:
    """Body of the response (at most `limit` bytes). Raises DeadlineExceeded when `seconds` pass first;
    otherwise urllib's own errors. An HTTPError gets `.sipar_body` (up to 2000 bytes, read under the deadline)."""
    seconds = min(max(seconds, 0.05), MAX_SECONDS) if seconds == seconds else MAX_SECONDS
    dl = _Deadline(seconds)
    opener = urllib.request.build_opener(*handlers, *_handlers(dl))
    timer = threading.Timer(seconds, dl.fire)
    timer.daemon = True
    t0 = time.monotonic()
    timer.start()
    try:
        try:
            with opener.open(req, timeout=seconds) as resp:
                data = resp.read(limit)
        except urllib.error.HTTPError as e:
            try:
                e.sipar_body = e.read(ERROR_BODY)
            except Exception:
                e.sipar_body = b""
            finally:
                e.close()                      # the body is kept in sipar_body: free the socket now
            if dl.expired:
                raise DeadlineExceeded() from None
            raise
        except Exception:
            if dl.expired or time.monotonic() - t0 >= seconds:
                raise DeadlineExceeded() from None
            raise
        if dl.expired:                         # the socket was cut mid-body: what we have is incomplete
            raise DeadlineExceeded()
        return data
    finally:
        timer.cancel()


BODY_TEXT = 20_000


def body_text(raw: bytes, n: int, cut: bool = False) -> str:
    """Error text from (part of) a response body or stderr: whitespace folded, secrets redacted (all their
    forms), then cut to n chars. cut=True: raw was already cut by a read limit, so a tail that may be the
    start of a secret is dropped as well."""
    return clip(" ".join(raw[:BODY_TEXT].decode("utf-8", "replace").split()), n, partial=cut or len(raw) > BODY_TEXT)
