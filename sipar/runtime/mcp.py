"""MCP client: call the tools of Model Context Protocol servers from Sipar (SPEC.md §7 MCP).

    allow mcp "fs" ["npx", "-y", "@modelcontextprotocol/server-filesystem", "./data"]
        tools ["read_text_file", "write_file"] readonly ["read_text_file"] pin "sha256:..."

Transport: stdio, one JSON-RPC message per line. The server runs in its own session with the minimal
environment of shell.run (never a secret) in the program folder; its stderr is kept as a log for error messages.

Protocol: first a `server/discover` probe for 2026-07-28 (protocol version in `_meta` on every request); a
server that answers with a non-MCP error or not at all within SIPAR_MCP_PROBE_TIMEOUT gets the 2025-11-25
`initialize` + `notifications/initialized` handshake instead.

Security: every result is labelled untrusted:mcp:<server>/<tool>; arguments are sinks unless the tool is listed
in `readonly`; secrets never go into arguments; only listed tools are callable; the definitions (description and
schemas) of the listed tools are hashed and must match the `pin` of the allow line, or, without a pin, what was
seen on first use (`.sipar/mcp/<program>.pins.json`), and must not change during the run (rug pull). Every
connection and call is journaled; replay serves them from the journal and never starts a server.
"""
from __future__ import annotations

import atexit
import hashlib
import json
import os
import queue
import re
import selectors
import signal
import subprocess
import tempfile
import threading
import time
import weakref
from typing import Any

from .. import __version__
from .. import ast as A
from .. import deep
from ..errors import SiparRuntimeError, secret_labels_in
from ..fileread import program_dir, read_text, why_unreadable
from .builtins import FUNCS
from .decode import MAX_VALUE_DEPTH, TOO_DEEP, from_json, json_loads, too_deep, type_str
from .effects import _deadline, _too_slow, cap_error, shell_env
from . import children, jsondeep, netio
from .values import mark_secrets, scrub_text, secrets_in, to_json, untrusted_in, with_labels

NEW = "2026-07-28"
OLD = "2025-11-25"
LEGACY = (OLD, "2025-06-18", "2025-03-26", "2024-11-05")    # initialize versions whose tools API we speak
MODERN_ERRORS = (-32020, -32021, -32022)                     # only a 2026-07-28 server sends these
MAX_MESSAGE = 10_000_000          # bytes in one JSON-RPC message from the server
MAX_PAGES = 100
MAX_SCHEMA = 20_000               # characters of inputSchema shown to a model
STDERR_KEEP = 65_536
MAX_QUEUED_BYTES = 16_000_000     # read ahead from the server and not handled yet; then its stdout is not read (R2)
MAX_IGNORED = 10_000              # messages while waiting for one answer that are not that answer (R2)
MAX_QUEUED = MAX_IGNORED          # messages read ahead and not handled yet; then the reader pauses (R8-1)
QUEUE_ITEM_COST = 128             # bytes of Python objects per queued message, counted in MAX_QUEUED_BYTES (R8-1)
MAX_MESSAGE_VALUES = 1_000_000    # JSON values (arrays, objects, items) in one message (R8-1: ~600 bytes each parsed)
MAX_IGNORED_BYTES = 64_000_000    # their bytes (R2)
MAX_PENDING_WRITE = 16_000_000    # bytes sent to a server that does not read its stdin (R1)
READ_CHUNK = 65_536               # bytes read from a server pipe at a time
WAIT_SLICE = 0.25                 # seconds; waits are cut into slices so Ctrl-C ends them (R6)
CLIENT_INFO = {"name": "sipar", "version": __version__}
META = {"io.modelcontextprotocol/protocolVersion": NEW,
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": CLIENT_INFO}

_LIVE: "weakref.WeakSet[Conn]" = weakref.WeakSet()


def fail(msg: str, fatal: bool = True) -> SiparRuntimeError:
    """An error of kind `mcp`. fatal=True also stops an agent (a protocol or security problem); a tool that
    reports an error (isError) is not fatal: the model is told and may try again."""
    e = SiparRuntimeError("mcp", scrub_text(msg))       # R8: server text in a message never breaks the journal
    e.fatal = fatal
    return e


def ident(tool: str) -> str:
    """The Sipar name of an MCP tool: mcp.<server>.<ident>(...). Characters outside [A-Za-z0-9_] become _."""
    s = re.sub(r"[^A-Za-z0-9_]", "_", tool)
    return "_" + s if not s or s[0].isdigit() else s


def tool_error_prefix(server: str, tool: str) -> str:
    return f"mcp.{server}.{ident(tool)} reported an error: "


# ------------------------------------------------------------------ configuration (from the allow lines)

class Server:
    def __init__(self, a: A.Allow):
        self.name = a.server
        self.command = list(a.scopes or [])
        self.tools = list(a.tools or [])
        self.readonly = set(a.readonly or [])
        self.pin = a.pin
        self.by_ident = {ident(t): t for t in self.tools}
        self.label = f"untrusted:mcp:{self.name}"


def servers(rt) -> dict[str, Server]:
    s = getattr(rt, "_mcp_servers", None)
    if s is None:
        s = {}
        for it in rt.program.items:
            if isinstance(it, A.Allow) and it.cap == "mcp" and getattr(it, "server", None):
                s.setdefault(it.server, Server(it))
        rt._mcp_servers = s
    return s


def server(rt, name: str) -> Server:
    srv = servers(rt).get(str(name))
    if srv is None:
        raise cap_error(f"this program has no `allow mcp {json.dumps(str(name))} [...]` line")
    return srv


def real_tool(srv: Server, tool: str, by_ident: bool = False) -> str:
    t = srv.by_ident.get(tool) if by_ident else (tool if tool in srv.tools else None)
    if t is None:
        raise cap_error(f"MCP tool {tool!r} is not in the tools list of `allow mcp {json.dumps(srv.name)}`")
    return t


def encode_message(obj: dict) -> bytes:
    """One stdio message: a JSON line. U+2028/U+2029/U+0085 are escaped, so a reader that splits lines on them
    (str.splitlines) still sees one message (F1, round 6)."""
    return jsondeep.dumps_line(obj).encode("utf-8") + b"\n"


# ------------------------------------------------------------------ hashing and pins

def canon(x: Any) -> str:
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def tool_hash(d: dict) -> str:
    return "sha256:" + hashlib.sha256(canon(d).encode("utf-8")).hexdigest()


def server_hash(defs: list[dict]) -> str:
    """The value of `pin` in an allow mcp line: SHA-256 of the definitions of the listed tools."""
    return tool_hash(sorted(defs, key=lambda d: d["name"]))      # type: ignore[arg-type]


def pin_path(program_file: str) -> str:
    base = program_dir(program_file)      # a pipe program: the current folder (round 9, M4)
    stem = os.path.splitext(os.path.basename(program_file))[0] or "program"
    return os.path.join(base, ".sipar", "mcp", stem + ".pins.json")


MAX_PIN_FILE = 16 * 1024 * 1024        # the pin file holds two short strings per tool (round 8)
MAX_PIN_DEPTH = 8                       # {"servers": {name: {tool: {"hash", "first_seen"}}}} is 4 deep


def _depth_ok(x: Any, limit: int) -> bool:
    """x is nested at most `limit` levels deep (iterative: never a RecursionError)."""
    stack = [(x, 1)]
    while stack:
        y, d = stack.pop()
        if isinstance(y, (dict, list)):
            if d > limit:
                return False
            stack.extend((z, d + 1) for z in (y.values() if isinstance(y, dict) else y))
    return True


class PinStore:
    """Trust on first use: the hash of every listed tool, per server, as first seen. A file in normal runs,
    memory in `sipar test` and for programs without a file. The file must be a regular file of at most
    MAX_PIN_FILE bytes nested at most MAX_PIN_DEPTH levels (round 8: a FIFO hung, a deep one was slow)."""

    def __init__(self, path: str | None):
        self.path = path
        self.data: dict = {"version": 1, "servers": {}}
        if path and os.path.exists(path):
            try:
                d = json.loads(read_text(path, MAX_PIN_FILE))
            except (OSError, ValueError) as e:      # round 7: the words of every file read, not Python's text
                why = why_unreadable(e) if isinstance(e, (OSError, UnicodeDecodeError)) else "not valid JSON"
                raise fail(f"cannot read the MCP pin file {path}: {why}; delete it to trust the servers again")
            except RecursionError:
                d = None                            # nested too deeply: malformed (below)
            if not (isinstance(d, dict) and _depth_ok(d, MAX_PIN_DEPTH) and isinstance(d.get("servers"), dict)
                    and all(isinstance(v, dict) for v in d["servers"].values())):
                raise fail(f"the MCP pin file {path} is malformed; delete it to trust the servers again")
            self.data = d

    def check(self, srv: Server, defs: list[dict], err_out) -> None:
        entry = self.data["servers"].setdefault(srv.name, {})
        changed = False
        for d in defs:
            h = tool_hash(d)
            old = entry.get(d["name"])
            old_h = old.get("hash") if isinstance(old, dict) else None
            if old_h is None:
                entry[d["name"]] = {"hash": h, "first_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
                changed = True
            elif old_h != h:
                raise fail(f"MCP server {srv.name!r} changed the definition of tool {d['name']!r} since "
                           f"{old.get('first_seen', 'its first use')} (possible rug pull); refusing to use it. If "
                           f"you reviewed the new definition, delete its entry in {self.path or 'the pin store'} "
                           f"or pin the server: pin {json.dumps(server_hash(defs))}")
        if changed and self.path:
            try:
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
                fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self.path), suffix=".tmp")
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(self.data, f, indent=1, sort_keys=True)
                os.replace(tmp, self.path)
            except OSError as e:
                err_out.write(f"sipar: warning: cannot save MCP tool pins to {self.path}: {e}\n")


def pin_store(rt) -> PinStore:
    st = getattr(rt, "_mcp_pins", None)
    if st is None:
        f = rt.file
        st = PinStore(None if rt.test_mode or not f or f.startswith("<") else pin_path(f))
        rt._mcp_pins = st
    return st


# ------------------------------------------------------------------ one server process

class _Timeout(Exception):
    pass


class _Rpc(Exception):
    def __init__(self, err: Any):
        err = err if isinstance(err, dict) else {}
        code = err.get("code")
        self.code = code if type(code) is int else None
        self.msg = scrub_text(str(err.get("message", ""))[:300])
        self.data = err.get("data")
        super().__init__(f"JSON-RPC error {self.code}: {self.msg}")


class Clock:
    def __init__(self, rt, what: str):
        self.seconds, self.by_budget = _deadline(rt, "SIPAR_MCP_TIMEOUT", 60)
        self.end = time.monotonic() + self.seconds
        self.what = what

    def too_slow(self) -> SiparRuntimeError:
        return _too_slow(self.what, self.seconds, self.by_budget)


def _close_quietly(sel, f) -> None:
    """A reader's end: close its selector and its own pipe (only the reader thread uses that fd)."""
    for x in (sel, f):
        try:
            x.close()
        except (OSError, ValueError):
            pass


_JSON_STR = re.compile(rb'"[^"\\]*(?:\\.[^"\\]*)*"')


def too_many_values(data: bytes) -> bool:
    """R8-1 (round 8): True when a JSON message holds more than MAX_MESSAGE_VALUES values. Parsed, each value
    costs about 600 bytes, so a 10 MB message of 3.3 million empty arrays took 2 GB. Counts `[`, `{` and `,`
    (an upper bound of the values): first in the raw bytes, and only when that is over the limit again with the
    strings taken out (brackets and commas in text are not values)."""
    if data.count(b",") + data.count(b"[") + data.count(b"{") <= MAX_MESSAGE_VALUES:
        return False
    bare = _JSON_STR.sub(b"", data)
    return bare.count(b",") + bare.count(b"[") + bare.count(b"{") > MAX_MESSAGE_VALUES


class Conn:
    q_count = 0                          # messages in self.q (R8-1); set per connection in __init__

    def __init__(self, rt, srv: Server):
        self.srv = srv
        self.q: queue.Queue = queue.Queue()
        self.q_bytes = 0                 # bytes in self.q (R2: the reader waits while there are too many)
        self.q_count = 0                 # messages in self.q (R8-1: an empty or tiny line costs objects, not bytes)
        self.q_cond = threading.Condition()
        self.closed = False
        self.wq: queue.Queue = queue.Queue()        # R1: a writer thread writes; send() never blocks
        self.w_pending = 0
        self.w_failed = False
        self.err_buf = bytearray()
        self.next_id = 0
        self.modern = False
        self.version = ""
        cmd = srv.command
        if any(secret_labels_in(tok) for tok in cmd):
                raise SiparRuntimeError("taint", f"the launch command of MCP server {srv.name!r} contains the "
                                                 "value of a secret; secrets never go into a launch command")
        try:
            self.p = subprocess.Popen(cmd, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, cwd=rt.caps.base_dir, env=shell_env(rt.caps),
                                      start_new_session=True)
        except FileNotFoundError:
            raise fail(f"MCP server {srv.name!r}: command not found: {cmd[0]!r}")
        except OSError as e:
            raise fail(f"MCP server {srv.name!r}: cannot run {cmd[0]!r}: {why_unreadable(e)}")
        _LIVE.add(self)
        children.track(self.p)
        self.readers = [threading.Thread(target=self._read_out, daemon=True),
                        threading.Thread(target=self._read_err, daemon=True)]
        for t in self.readers:
            t.start()
        self.writer = threading.Thread(target=self._write, daemon=True)
        self.writer.start()

    # -- pipes
    # R7-3 (round 7): the readers read the raw pipe fds (os.read after a select slice), never through the
    # buffered file objects, and each reader closes its own pipe when it ends. A buffered readline() holds the
    # file's lock while it blocks, so a close() from another thread waited for as long as a grandchild that left
    # the server's process group (setsid) kept the pipe open: the MCP timeout did not hold. Now close() only
    # sets `closed`; a reader sees it within WAIT_SLICE, stops and closes its pipe itself.
    def _chunk(self, sel, fd: int) -> bytes | None:
        """The next bytes from the pipe (b"" at its end), or None once the connection is closed."""
        while not self.closed:
            if sel.select(WAIT_SLICE):
                return os.read(fd, READ_CHUNK)
        return None

    def _read_out(self) -> None:
        f = self.p.stdout
        sel = selectors.DefaultSelector()
        try:
            fd = f.fileno()
            sel.register(fd, selectors.EVENT_READ)
            buf, scan = bytearray(), 0
            while True:
                nl = buf.find(b"\n", scan)
                if nl < 0:
                    if len(buf) > MAX_MESSAGE:
                        self.q.put(("big", None))
                        return
                    scan = len(buf)
                    chunk = self._chunk(sel, fd)
                    if chunk is None:
                        return
                    if chunk:
                        buf += chunk
                        continue
                    if not buf:
                        break
                    body, buf = bytes(buf), bytearray()       # a last line without a line feed
                else:
                    body = bytes(buf[:nl])
                    del buf[:nl + 1]
                    scan = 0
                if len(body) > MAX_MESSAGE:
                    self.q.put(("big", None))
                    return
                if not body.strip():         # R8-1: a blank line is no message; queued, a flood of them filled memory
                    continue
                # R2: at most MAX_QUEUED_BYTES wait here; then the server waits. R8-1 (round 8): each message also
                # costs QUEUE_ITEM_COST, and at most MAX_QUEUED messages wait, so a flood of tiny lines ("{}") is
                # bounded too; the next request then reads them as messages that are not its answer (MAX_IGNORED)
                with self.q_cond:
                    while ((self.q_bytes > MAX_QUEUED_BYTES or self.q_count >= MAX_QUEUED)
                           and not self.closed):
                        self.q_cond.wait(WAIT_SLICE)
                    if self.closed:
                        return
                    self.q_bytes += len(body) + QUEUE_ITEM_COST
                    self.q_count += 1
                self.q.put(("line", body))
        except (OSError, ValueError):
            pass
        finally:
            _close_quietly(sel, f)
        self.q.put(("eof", None))

    def _take(self, timeout: float) -> tuple:
        kind, data = self.q.get(timeout=timeout)
        if kind == "line":
            with self.q_cond:
                self.q_bytes -= len(data) + QUEUE_ITEM_COST
                self.q_count -= 1
                self.q_cond.notify_all()
        return kind, data

    def _write(self) -> None:
        """R1 (round 6): the only thread that writes to the server. A server that does not read its stdin
        blocks this thread, not the run; the request then times out and the server is killed."""
        f = self.p.stdin
        try:
            fd = f.fileno()
            while True:
                data = self.wq.get()
                if data is None:
                    return
                view = memoryview(data)
                while view:
                    n = os.write(fd, view)
                    view = view[n:]
                with self.q_cond:
                    self.w_pending -= len(data)
        except (OSError, ValueError):
            self.w_failed = True
        finally:
            try:
                f.close()
            except (OSError, ValueError):
                pass

    def _read_err(self) -> None:
        f = self.p.stderr
        sel = selectors.DefaultSelector()
        try:
            fd = f.fileno()
            sel.register(fd, selectors.EVENT_READ)
            while True:
                chunk = self._chunk(sel, fd)
                if not chunk:
                    return
                self.err_buf += chunk
                if len(self.err_buf) > STDERR_KEEP:
                    del self.err_buf[:len(self.err_buf) - STDERR_KEEP]
        except (OSError, ValueError):
            return
        finally:
            _close_quietly(sel, f)

    def log_tail(self, n: int = 300) -> str:
        time.sleep(0.05)                     # let the stderr reader catch up with a server that just died
        return netio.body_text(bytes(self.err_buf[-4 * n:]), n)

    def alive(self) -> bool:
        return self.p.poll() is None

    def close(self) -> None:
        """Kill the server and everything it started (it runs in its own session), then reap it."""
        _LIVE.discard(self)
        with self.q_cond:
            self.closed = True
            self.q_cond.notify_all()
        self.wq.put(None)
        try:
            os.killpg(self.p.pid, signal.SIGKILL)
        except OSError:
            try:
                self.p.kill()
            except OSError:
                pass
        try:
            self.p.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        children.untrack(self.p)
        self.writer.join(1)              # its write fails once the server is dead; it closes stdin itself
        for t in self.readers:           # R7-3: they stop within WAIT_SLICE and close their pipes themselves;
            t.join(2 * WAIT_SLICE)       # never close a pipe here (a reader may be using its fd)

    def send(self, obj: dict) -> None:
        """Queue one message for the writer thread (never blocks)."""
        if self.w_failed or self.closed or not self.writer.is_alive():
            raise self.died()
        data = encode_message(obj)
        with self.q_cond:
            if self.w_pending + len(data) > MAX_PENDING_WRITE and self.w_pending:
                raise fail(f"MCP server {self.srv.name!r} does not read its input "
                           f"({self.w_pending // 1000} KB not taken)")
            self.w_pending += len(data)
        self.wq.put(data)

    def died(self) -> SiparRuntimeError:
        tail = self.log_tail()
        code = self.p.poll()
        return fail(f"MCP server {self.srv.name!r} stopped" + (f" (exit status {code})" if code is not None else "")
                    + (f"; its log ends with: {tail}" if tail else ""))

    # -- JSON-RPC
    def request(self, method: str, params: dict, end: float, modern: bool | None = None) -> dict:
        self.next_id += 1
        rid = self.next_id
        params = dict(params)
        if self.modern if modern is None else modern:
            params["_meta"] = META
        self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        ignored = ignored_bytes = 0
        while True:
            left = end - time.monotonic()
            if left <= 0:
                raise _Timeout()
            if deep.stopping():
                raise KeyboardInterrupt
            try:
                kind, data = self._take(min(left, WAIT_SLICE))
            except queue.Empty:
                continue
            if kind == "eof":
                self.q.put((kind, data))
                raise self.died()
            if kind == "big":
                self.q.put((kind, data))
                raise fail(f"MCP server {self.srv.name!r} sent a message larger than {MAX_MESSAGE // 1_000_000} MB")
            ignored += 1                     # R2: until it is the answer, every message counts against the caps
            ignored_bytes += len(data)
            if ignored > MAX_IGNORED or ignored_bytes > MAX_IGNORED_BYTES:
                raise fail(f"MCP server {self.srv.name!r} sent more than {MAX_IGNORED:,} messages or "
                           f"{MAX_IGNORED_BYTES // 1_000_000} MB that are not the answer to {method}")
            if not data.strip():
                continue
            if too_many_values(data):
                raise fail(f"MCP server {self.srv.name!r} sent a message with more than {MAX_MESSAGE_VALUES:,} "
                           f"JSON values")
            deep_msg = False
            try:
                msg = jsondeep.loads(data)
            except jsondeep.NumberTooLarge as e:     # valid JSON, not "invalid JSON" (round 6); catchable
                raise fail(f"MCP server {self.srv.name!r} sent {e}", fatal=False)
            except (ValueError, UnicodeDecodeError):
                raise fail(f"MCP server {self.srv.name!r} sent invalid JSON: "
                           f"{data[:60].decode('utf-8', 'replace')!r}")
            except RecursionError:
                deep_msg = True
            # R9: the result value sits 2 levels down ({"result": {"structuredContent": ...}}); deeper data
            # would fail later with an uncatchable recursion error
            if deep_msg or too_deep(msg, MAX_VALUE_DEPTH + 2):
                raise fail(f"MCP server {self.srv.name!r} sent a message {TOO_DEEP}", fatal=False)
            if not isinstance(msg, dict):
                raise fail(f"MCP server {self.srv.name!r} sent a message that is not a JSON object")
            if "method" in msg:              # a request or notification from the server
                if "id" in msg:
                    if msg["method"] == "ping":
                        self.send({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
                    else:
                        self.send({"jsonrpc": "2.0", "id": msg["id"],
                                   "error": {"code": -32601, "message": "not supported by the Sipar client"}})
                continue
            if msg.get("id") != rid or isinstance(msg.get("id"), bool):
                continue                     # a late answer to an earlier request (the discover probe)
            if "error" in msg:
                raise _Rpc(msg["error"])
            res = msg.get("result")
            if not isinstance(res, dict):
                raise fail(f"MCP server {self.srv.name!r} answered {method} without a result object")
            return res

    def handshake(self, clock: Clock) -> None:
        probe = netio.env_seconds("SIPAR_MCP_PROBE_TIMEOUT", 10)
        end = min(clock.end, time.monotonic() + probe)
        try:
            r = self.request("server/discover", {}, end, modern=True)
            sv = r.get("supportedVersions")
            if not isinstance(sv, list):
                raise fail(f"MCP server {self.srv.name!r} answered server/discover without supportedVersions")
            if self._modern(sv):
                return
        except _Timeout:
            if end >= clock.end:
                raise
        except _Rpc as e:
            if e.code == -32022:
                sup = e.data.get("supported") if isinstance(e.data, dict) else None
                if self._modern(sup if isinstance(sup, list) else []):
                    return
            elif e.code in MODERN_ERRORS:
                raise fail(f"MCP server {self.srv.name!r} refused server/discover: {e.msg}")
        self._legacy(clock)

    def _modern(self, supported: list) -> bool:
        """True: speak 2026-07-28. False: the server also lists an older version, so initialize."""
        if NEW in supported:
            self.modern, self.version = True, NEW
            return True
        if any(v in supported for v in LEGACY):
            return False
        shown = ", ".join(str(v)[:20] for v in supported[:5]) or "none"
        raise fail(f"MCP server {self.srv.name!r} supports protocol versions {shown}; Sipar speaks {NEW} and {OLD}")

    def _legacy(self, clock: Clock) -> None:
        self.modern = False
        try:
            r = self.request("initialize", {"protocolVersion": OLD, "capabilities": {}, "clientInfo": CLIENT_INFO},
                             clock.end)
        except _Rpc as e:
            raise fail(f"MCP server {self.srv.name!r} refused initialize: {e.msg}")
        v = r.get("protocolVersion")
        if v not in LEGACY:
            raise fail(f"MCP server {self.srv.name!r} wants protocol version {str(v)[:20]!r}; Sipar speaks {NEW} "
                       f"and {OLD}")
        self.version = v
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def list_tools(self, clock: Clock) -> dict[str, dict]:
        out: dict[str, dict] = {}
        cursor = None
        seen = set()
        for _ in range(MAX_PAGES):
            try:
                r = self.request("tools/list", {} if cursor is None else {"cursor": cursor}, clock.end)
            except _Rpc as e:
                raise fail(f"MCP server {self.srv.name!r} refused tools/list: {e.msg}")
            check_result_type(self.srv, "tools/list", r)
            ts = r.get("tools")
            if not isinstance(ts, list):
                raise fail(f"MCP server {self.srv.name!r} answered tools/list without a tools list")
            for t in ts:
                if isinstance(t, dict) and isinstance(t.get("name"), str):
                    out.setdefault(t["name"], t)
            cursor = r.get("nextCursor")
            if cursor is None:
                return out
            if not isinstance(cursor, str) or cursor in seen:
                raise fail(f"MCP server {self.srv.name!r} sent a bad tools/list cursor")
            seen.add(cursor)
        raise fail(f"MCP server {self.srv.name!r} sent more than {MAX_PAGES} pages of tools")


def check_result_type(srv: Server, method: str, r: dict) -> None:
    t = r.get("resultType")
    if t is None or t == "complete":
        return
    if t == "input_required":
        raise fail(f"MCP server {srv.name!r} asked for more input in {method} (input_required); Sipar does not "
                   "support that")
    raise fail(f"MCP server {srv.name!r} answered {method} with an unknown resultType {str(t)[:30]!r}")


def definition(srv: Server, t: dict) -> dict:
    """What is hashed and pinned of a tool: name, title, description, inputSchema, outputSchema."""
    d = {"name": t["name"], "description": t.get("description", "")}
    for k in ("title", "description"):
        if k in t and not isinstance(t[k], str):
            raise fail(f"MCP server {srv.name!r}: tool {t['name']!r} has a {k} that is not a string")
    if not isinstance(t.get("inputSchema"), dict):
        raise fail(f"MCP server {srv.name!r}: tool {t['name']!r} has no inputSchema object")
    d["inputSchema"] = t["inputSchema"]
    if "title" in t:
        d["title"] = t["title"]
    if t.get("outputSchema") is not None:
        d["outputSchema"] = t["outputSchema"]
    return scrub_text(d)                 # R8: a lone surrogate becomes U+FFFD (it would break the journal)


def pick(srv: Server, listed: dict[str, dict]) -> list[dict]:
    missing = [t for t in srv.tools if t not in listed]
    if missing:
        raise fail(f"MCP server {srv.name!r} has no tool {missing[0]!r} (it offers: "
                   f"{', '.join(sorted(listed)[:12]) or 'none'})")
    return [definition(srv, listed[t]) for t in srv.tools]


# ------------------------------------------------------------------ a session: one server in one run

class Session:
    def __init__(self, rt, srv: Server):
        self.rt = rt
        self.srv = srv
        self.conn: Conn | None = None
        self.defs: dict[str, dict] = {}
        self.hashes: dict[str, str] = {}

    def _launch(self, clock: Clock) -> tuple[Conn, list[dict]]:
        conn = Conn(self.rt, self.srv)
        try:
            conn.handshake(clock)
            defs = pick(self.srv, conn.list_tools(clock))
        except _Timeout:
            conn.close()
            raise clock.too_slow()
        except BaseException:
            conn.close()
            raise
        return conn, defs

    def start(self) -> None:
        srv = self.srv
        request = {"server": srv.name, "command": srv.command, "tools": sorted(srv.tools), "pin": srv.pin}

        def perform():
            conn, defs = self._launch(Clock(self.rt, f"starting MCP server {srv.name!r}"))
            try:
                h = server_hash(defs)
                if srv.pin is not None and srv.pin != h:
                    raise fail(f"the tool definitions of MCP server {srv.name!r} do not match the pin in its allow "
                               f"line (they are {h}); if you reviewed them, update the pin")
                if srv.pin is None:
                    pin_store(self.rt).check(srv, defs, self.rt.err)
            except BaseException:
                conn.close()
                raise
            self.conn = conn
            return {"version": conn.version, "tools": defs, "hash": h}

        resp = self.rt.journal.effect("mcp.connect", request, perform, [srv.label])
        self.defs = {d["name"]: d for d in resp["tools"]}
        self.hashes = {n: tool_hash(d) for n, d in self.defs.items()}

    def verify(self, conn: Conn, clock: Clock) -> None:
        """Live: the listed tools must still have the definitions seen at the start (no rug pull)."""
        defs = pick(self.srv, conn.list_tools(clock))
        for d in defs:
            if tool_hash(d) != self.hashes.get(d["name"]):
                raise fail(f"MCP server {self.srv.name!r} changed the definition of tool {d['name']!r} during the "
                           "run (possible rug pull); refusing to call it")

    def call(self, tool: str, args: dict) -> dict:
        srv = self.srv
        what = f"mcp.{srv.name}.{ident(tool)}"
        request = {"server": srv.name, "tool": tool, "args": args}

        def perform():
            clock = Clock(self.rt, what)
            try:
                if self.conn is None or not self.conn.alive():
                    if self.conn is not None:
                        self.conn.close()
                    self.conn = None
                    self.conn, _ = self._launch(clock)
                conn = self.conn
                self.verify(conn, clock)
                r = conn.request("tools/call", {"name": tool, "arguments": args}, clock.end)
                return normalize(srv, tool, r)
            except _Timeout:
                self.stop()
                raise clock.too_slow()
            except _Rpc as e:
                raise fail(f"{tool_error_prefix(srv.name, tool)}{e.msg}", fatal=False)
            except SiparRuntimeError as e:
                if getattr(e, "fatal", False):
                    self.stop()
                raise

        try:
            return self.rt.journal.effect("mcp", request, perform, [f"{srv.label}/{tool}"])
        except SiparRuntimeError as e:
            if e.kind == "mcp" and not hasattr(e, "fatal"):      # replayed from the journal
                # a tool's own error, a too-deep reply and a too-large number were catchable when recorded
                # (R9 and trivia, round 6)
                e.fatal = not (e.message.startswith(tool_error_prefix(srv.name, tool)) or e.message.endswith(TOO_DEEP)
                               or e.message.startswith(f"MCP server {srv.name!r} sent a number too large to read ("))
            raise

    def stop(self) -> None:
        if self.conn is not None:
            self.conn.close()
            self.conn = None


def b64_size(data) -> int:
    """Decoded size of base64 text, without decoding it (padding and whitespace do not count)."""
    if not isinstance(data, str):
        return 0
    return len("".join(data.split()).rstrip("=")) * 3 // 4


def marker_text(v: Any, n: int) -> str:
    """Server text shown inside a «mcp ...» marker: the first n characters, with control, line-break, format
    (bidi) and other unprintable characters and the marker quotes « » escaped as \\uXXXX, so a server cannot
    start a fake line or a fake marker there; missing, empty or not text is "unknown" (round 6)."""
    if not isinstance(v, str) or not v:
        return "unknown"
    return "".join(c if c.isprintable() and c not in "«»" else
                   (f"\\u{ord(c):04x}" if ord(c) <= 0xFFFF else f"\\U{ord(c):08x}") for c in v[:n])


def normalize(srv: Server, tool: str, r: dict) -> dict:
    """tools/call result -> what is journaled: {"text": joined text parts, "structured": structuredContent?}."""
    check_result_type(srv, "tools/call", r)
    content = r.get("content")
    if content is None:                 # missing and null mean the same: no content parts (round 6)
        content = []
    if not isinstance(content, list):
        raise fail(f"MCP server {srv.name!r}: the result of {tool!r} has no content list")
    parts = []
    for c in content:
        if not isinstance(c, dict):
            raise fail(f"MCP server {srv.name!r}: the result of {tool!r} has a content item that is not an object")
        t = c.get("type")
        if t == "text":
            if not isinstance(c.get("text"), str):
                raise fail(f"MCP server {srv.name!r}: a text item of {tool!r} has no text")
            parts.append(c["text"])
        elif t in ("image", "audio"):
            data = c.get("data")
            n = b64_size(data)
            parts.append(f"«mcp {t}: {marker_text(c.get('mimeType'), 60)}, {n} bytes»")
        elif t == "resource_link":
            parts.append(f"«mcp resource_link: {marker_text(c.get('uri'), 200)}»")
        elif t == "resource":
            res = c.get("resource") if isinstance(c.get("resource"), dict) else {}
            if isinstance(res.get("text"), str):
                parts.append(res["text"])
            else:
                blob = res.get("blob")
                n = b64_size(blob)
                parts.append(f"«mcp resource: {marker_text(res.get('uri'), 200)}, {n} bytes»")
        else:
            parts.append(f"«mcp {marker_text(t, 40)}»")
    text = scrub_text("\n".join(parts))      # R8: a lone surrogate becomes U+FFFD, like all outside text
    if r.get("isError") is True:
        raise fail(tool_error_prefix(srv.name, tool) + (text[:500] or "(no message)"), fatal=False)
    out: dict = {"text": text}
    if r.get("structuredContent") is not None:
        sc = r["structuredContent"]
        if too_deep(sc):                 # R9: catchable, instead of a recursion error later
            raise fail(f"MCP server {srv.name!r}: the structuredContent of {tool!r} is {TOO_DEEP}", fatal=False)
        out["structured"] = scrub_text(sc)
    return out


def session(rt, srv: Server) -> Session:
    reg = getattr(rt, "_mcp_sessions", None)
    if reg is None:
        reg = rt._mcp_sessions = {}
        hooks = getattr(rt.journal, "on_close", None)
        if hooks is not None:
            hooks.append(lambda: close_all(rt))
    s = reg.get(srv.name)
    if s is None:
        s = Session(rt, srv)
        s.start()
        reg[srv.name] = s
    return s


def close_all(rt) -> None:
    for s in (getattr(rt, "_mcp_sessions", None) or {}).values():
        s.stop()


@atexit.register
def _kill_all() -> None:
    for c in list(_LIVE):
        try:
            c.close()
        except Exception:      # noqa: BLE001 - best effort at exit
            pass


# ------------------------------------------------------------------ calls from Sipar

def check_args(srv: Server, tool: str, args: dict, what: str) -> None:
    """Arguments are sinks (SPEC §7a). R3 (round 6): an argument name is sent too, so it is checked like a
    value (the keys of a Map argument already are: labels_of takes them in)."""
    for k, v in args.items():
        for x, part in ((k, f"the argument name {str.__str__(k)!r}"), (v, k)):
            sec = secrets_in(x)
            if sec:
                raise SiparRuntimeError("taint", f"{', '.join(sec)} cannot flow into {what}({part}); secrets never "
                                                 "go into MCP tool arguments")
            if tool not in srv.readonly:
                un = untrusted_in(x)
                if un:
                    raise SiparRuntimeError("taint", f"untrusted data ({', '.join(un[:3])}) cannot flow into "
                                                     f"{what}({part}) (the tool is not listed as readonly in its "
                                                     "allow mcp line); check it, then use trust(x, \"reason\") or "
                                                     "approve(x, \"question\")")


def call_tool(rt, srv: Server, tool: str, args: dict, te: A.TypeExpr | None = None) -> Any:
    what = f"mcp.{srv.name}.{ident(tool)}"
    if not all(isinstance(k, str) for k in args):
        raise SiparRuntimeError("type", f"{what}: argument names must be Str")
    check_args(srv, tool, args, what)
    plain = {str.__str__(k): to_json(v) for k, v in args.items()}
    resp = session(rt, srv).call(tool, plain)
    if not (isinstance(resp, dict) and isinstance(resp.get("text"), str)):
        raise SiparRuntimeError("replay", f"journal entry for {what} is malformed")
    labels = frozenset({f"{srv.label}/{tool}"})
    if te is None:
        return mark_secrets(with_labels(resp["text"], labels))
    if "structured" in resp:
        data = resp["structured"]
    else:
        try:
            data = json_loads(resp["text"])         # a huge integer: the target type decides the error (round 6)
        except ValueError:
            raise SiparRuntimeError("decode", f"{what}: the result has no structured content and its text is not "
                                              f"JSON, so it cannot be a {type_str(te)}")
    try:
        return mark_secrets(from_json(data, te, rt.tenv, labels))
    except SiparRuntimeError as e:
        if e.kind != "decode":
            raise
        raise SiparRuntimeError("decode", f"{what}: the result does not match {type_str(te)}: {e.message}")


def dotted(c: Any) -> bool:
    """mcp.<server>.<tool>"""
    return isinstance(c, A.Field) and isinstance(c.obj, A.Field) and isinstance(c.obj.obj, A.Name) \
        and c.obj.obj.name == "mcp"


def call_dotted(rt, n: A.Call, env) -> Any:
    c = n.callee
    pos, named = rt.eval_args(n.args, env)
    what = f"mcp.{c.obj.name}.{c.name}"
    if pos:
        raise SiparRuntimeError("type", f"{what}: MCP tool arguments must be named, e.g. {what}(path: \"x\")")
    srv = server(rt, c.obj.name)
    return call_tool(rt, srv, real_tool(srv, c.name, by_ident=True), named, getattr(n, "mcp_type", None))


def call_dynamic(rt, a: dict) -> Any:
    """mcp.call(server, tool, args): the tool by its MCP name; the result is Str."""
    srv = server(rt, a["server"])
    args = a.get("args")
    return call_tool(rt, srv, real_tool(srv, str(a["tool"])), dict(args or {}))


FUNCS["mcp.call"] = call_dynamic


# ------------------------------------------------------------------ agent tools

class AgentTool:
    """`tools [mcp.fs.read_text_file]` in an agent fn: what run_agent needs of a tool."""
    is_mcp = True

    def __init__(self, rt, qname: str):
        parts = qname.split(".")
        if len(parts) != 3:
            raise SiparRuntimeError("type", f"bad MCP tool name {qname!r}")
        self.srv = server(rt, parts[1])
        self.tool = real_tool(self.srv, parts[2], by_ident=True)
        self.name = qname
        self.defn = session(rt, self.srv).defs[self.tool]
        self.params = schema_params(self.defn.get("inputSchema"))

    def spec(self) -> dict:
        schema = self.defn.get("inputSchema") or {"type": "object"}
        if len(canon(schema)) > MAX_SCHEMA:
            raise fail(f"the inputSchema of MCP tool {self.tool!r} is larger than {MAX_SCHEMA} characters")
        desc = str(self.defn.get("description") or "")[:2000]
        return {"name": self.name,
                "description": f"[untrusted: written by MCP server {self.srv.name!r}, not by the program] {desc}",
                "parameters": schema, "returns": "Str"}

    def call(self, rt, args: dict) -> Any:
        """run_agent decodes every parameter; an optional one the model left out arrives as none and is not sent."""
        opt = {p.name for p in self.params if isinstance(p.type, A.TOptional)}
        return call_tool(rt, self.srv, self.tool, {k: v for k, v in args.items() if not (k in opt and v is None)})


def schema_params(schema) -> list:
    """The parameters run_agent checks the model's args against: the properties of the tool's inputSchema,
    each of type Any (the server validates the values), optional unless listed in `required`."""
    props = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(props, dict):
        return []
    req = schema.get("required")
    req = set(req) if isinstance(req, list) and all(isinstance(r, str) for r in req) else set()
    out = []
    for name in props:
        t = A.TName(0, 0, "Any")
        out.append(A.Param(0, 0, str(name), t if name in req else A.TOptional(0, 0, t)))
    return out
