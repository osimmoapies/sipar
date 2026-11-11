"""Shared helpers for the runtime tests (offline: mock provider, local http.server, temp dirs)."""
from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from sipar.errors import SiparRuntimeError  # noqa: E402
from sipar.parser import parse  # noqa: E402
from sipar.runtime.interp import Interp, run_tests  # noqa: E402
from sipar.runtime.journal import Journal  # noqa: E402

CLEAN_ENV = ("SIPAR_MODEL", "SIPAR_MOCK_SCRIPT", "SIPAR_PRICE_IN", "SIPAR_PRICE_OUT", "SIPAR_DEBUG")


class FakeTTY(io.StringIO):
    def isatty(self):
        return True


class Prog:
    """A program in its own temp dir. `files` = {relative path: text}."""

    def __init__(self, src: str, files: dict | None = None, name: str = "prog.sipar"):
        self.dir = os.path.realpath(tempfile.mkdtemp(prefix="sipar_rt_"))
        self.path = os.path.join(self.dir, name)
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(src)
        for rel, text in (files or {}).items():
            p = os.path.join(self.dir, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(text)
        self.src = src
        self.program = parse(src, self.path)
        self.last: Interp | None = None

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def env(self, extra: dict | None = None):
        e = {k: v for k, v in os.environ.items() if k not in CLEAN_ENV}
        e["SIPAR_MODEL"] = "mock"
        e.update(extra or {})
        return mock.patch.dict(os.environ, e, clear=True)

    def run(self, argv=None, script=None, stdin=None, journal=None, env=None, providers=None) -> str:
        out, err = io.StringIO(), io.StringIO()
        with self.env(env):
            it = Interp(self.program, self.path, journal=journal or Journal(), out=out, err_out=err,
                        stdin=stdin if stdin is not None else io.StringIO(""), mock_script=script,
                        providers=providers)
            self.last = it
            self.stderr = err
            try:
                it.run_main(argv)
            finally:
                self.out = out.getvalue()
        return out.getvalue()

    def error(self, **kw) -> SiparRuntimeError:
        try:
            self.run(**kw)
        except SiparRuntimeError as e:
            return e
        raise AssertionError("expected a runtime error, got output:\n" + self.out)

    def test(self, live=False, record=False, script=None, env=None, providers=None):
        out = io.StringIO()
        with self.env(env):
            p, f = run_tests(self.program, self.path, live=live, record=record, out=out, err_out=io.StringIO(),
                             mock_script=script, providers=providers)
        return p, f, out.getvalue()


def main_src(body: str, head: str = "") -> str:
    return f"{head}\nfn main() {{\n{body}\n}}\n"


def run(body: str, head: str = "", **kw) -> str:
    p = Prog(main_src(body, head))
    try:
        return p.run(**kw)
    finally:
        p.cleanup()


def error(body: str, head: str = "", **kw) -> SiparRuntimeError:
    p = Prog(main_src(body, head))
    try:
        return p.error(**kw)
    finally:
        p.cleanup()


# ------------------------------------------------------------------ local HTTP server

class Server:
    """127.0.0.1 server. Routes: /ok, /echo (POST body + headers as JSON), /redirect?to=URL, /status/<n>,
    /chat/completions (OpenAI-shaped reply from self.chat_reply; dripped when self.chat_drip; no reply at all when
    self.chat_hangup),
    /slow?n=N (announces N bytes, then sends one byte every 0.3 s), /hangup (closes without a reply).
    /status/<n> answers with self.status_body when set."""

    def __init__(self):
        self.hits: list[dict] = []
        self.chat_reply: dict | None = None
        self.chat_status = 200
        self.chat_drip = False
        self.chat_hangup = False
        self.status_body: str | None = None
        srv = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(n).decode() if n else ""

            def _send(self, code, text, headers=None):
                data = text.encode()
                self.send_response(code)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _drip(self, n, ctype="text/plain"):
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(n))
                self.end_headers()
                try:
                    for _ in range(n):
                        self.wfile.write(b" ")
                        self.wfile.flush()
                        time.sleep(0.3)
                except OSError:                       # the client hung up: what the deadline tests expect
                    pass

            def handle_one(self, method):
                body = self._body()
                srv.hits.append({"method": method, "path": self.path, "headers": dict(self.headers), "body": body})
                if self.path.startswith("/ok"):
                    return self._send(200, "hello from server")
                if self.path.startswith("/echo"):
                    return self._send(200, json.dumps({"body": body, "auth": self.headers.get("Authorization")}))
                if self.path.startswith("/redirect"):
                    to = self.path.split("to=", 1)[1]
                    return self._send(302, "", {"Location": to})
                if self.path.startswith("/status/"):
                    code = int(self.path.rsplit("/", 1)[1])
                    return self._send(code, srv.status_body if srv.status_body is not None else "error body " + "x" * 50)
                if self.path.startswith("/hangup"):
                    self.close_connection = True
                    return None
                if self.path.startswith("/slow"):
                    return self._drip(int(self.path.split("n=", 1)[1]) if "n=" in self.path else 40)
                if self.path.startswith("/chat/completions"):
                    if srv.chat_hangup:                  # close the connection without any reply
                        self.close_connection = True
                        return None
                    if srv.chat_drip:
                        return self._drip(40, "application/json")
                    if srv.chat_status != 200:
                        return self._send(srv.chat_status, json.dumps({"error": {"message": "bad key"}}))
                    return self._send(200, json.dumps(srv.chat_reply))
                return self._send(404, "nope")

            def do_GET(self):
                self.handle_one("GET")

            def do_POST(self):
                self.handle_one("POST")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
