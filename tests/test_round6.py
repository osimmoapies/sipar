"""Round-6 fixes. Each test failed before the fix unless marked *guard* or *coverage*.

The fake MCP server below is written to a temp dir; every server it starts records its pid, and every test
checks that no such server is still alive afterwards (and kills it if one is, then fails)."""

import io
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from rt_helpers import Prog  # noqa: E402
from sipar.checker import check_source  # noqa: E402
from sipar.errors import SiparRuntimeError  # noqa: E402
from sipar.runtime import mcp as MCP  # noqa: E402
from sipar.runtime.journal import Journal  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SECRET = "abc-123-zzz"                       # a fake secret value
STOP = tuple(getattr(signal, n) for n in ("SIGINT", "SIGHUP", "SIGTERM") if hasattr(signal, n))


def default_signals():
    """preexec_fn of a spawned `sipar`: the signals these tests send start at their default action, even when
    the suite itself runs with them ignored (`nohup`, `trap '' INT` in CI; round 9, M5). A process started
    with a signal ignored keeps it ignored by design (SPEC §9)."""
    for sig in STOP:
        signal.signal(sig, signal.SIG_DFL)

SERVER = r'''
import json, os, signal, sys, time
mode, log = sys.argv[1], sys.argv[2]
data = sys.argv[3] if len(sys.argv) > 3 else None
with open(log + ".pids", "a") as f:
    f.write(f"{os.getpid()}\n")
def L(s):
    with open(log, "a", encoding="utf-8") as f:
        f.write(s + "\n")
def out(o):
    sys.stdout.write(json.dumps(o) + "\n"); sys.stdout.flush()
if mode == "sticky":                          # ignores EOF and polite signals
    signal.signal(signal.SIGTERM, signal.SIG_IGN); signal.signal(signal.SIGHUP, signal.SIG_IGN)
desc = "reads\ud800 it" if mode == "surrdesc" else "reads"
TOOLS = [{"name": "read", "description": desc, "inputSchema": {"type": "object"}},
         {"name": "write", "description": "writes", "inputSchema": {"type": "object"}}]
inp = sys.stdin.buffer
while True:
    line = inp.readline(65536)
    if not line:
        break
    if not line.endswith(b"\n"):              # a long line: a "deaf" server stops reading here
        if mode == "deaf":
            L("DEAF")
            time.sleep(120)
        continue
    try:
        m = json.loads(line)
    except Exception:
        continue
    meth, i = m.get("method"), m.get("id")
    if i is None:
        continue
    if meth == "server/discover":
        out({"jsonrpc": "2.0", "id": i, "error": {"code": -32601, "message": "no"}}); continue
    if meth == "initialize":
        out({"jsonrpc": "2.0", "id": i, "result": {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                                                   "serverInfo": {"name": "x", "version": "1"}}}); continue
    if meth == "tools/list":
        out({"jsonrpc": "2.0", "id": i, "result": {"tools": TOOLS}}); continue
    if meth != "tools/call":
        out({"jsonrpc": "2.0", "id": i, "result": {}}); continue
    a = m["params"].get("arguments") or {}
    L("CALL " + m["params"]["name"] + " " + json.dumps(a))
    if mode == "env":
        L("ENV " + json.dumps(dict(os.environ)))
    if mode == "silent":
        time.sleep(120)
    if mode == "flood":
        for k in range(int(a.get("n", 0))):
            out({"jsonrpc": "2.0", "method": "notifications/message", "params": {"data": "x" * int(a.get("size", 1))}})
    if mode == "struct":
        with open(data) as f:
            d = json.load(f)
        out({"jsonrpc": "2.0", "id": i, "result": {"content": [{"type": "text", "text": json.dumps(d)}],
                                                   "structuredContent": d}}); continue
    if mode == "deep":
        n = int(data)
        sys.stdout.write('{"jsonrpc": "2.0", "id": %d, "result": {"content": [], "structuredContent": %s}}\n'
                         % (i, '{"a": ' * n + '1' + '}' * n)); sys.stdout.flush(); continue
    if mode == "raw":                         # the result object as raw JSON text from a file
        with open(data, encoding="utf-8") as f:
            sys.stdout.write('{"jsonrpc": "2.0", "id": %d, "result": %s}\n' % (i, f.read().strip()))
        sys.stdout.flush(); continue
    if mode == "surr":
        out({"jsonrpc": "2.0", "id": i, "result": {"content": [{"type": "text", "text": "a\ud800b"}],
                                                   "structuredContent": {"k": "c\udc00d"}}}); continue
    if mode == "surrerr":
        out({"jsonrpc": "2.0", "id": i, "error": {"code": 1, "message": "bad\ud800 thing"}}); continue
    if mode == "surriserr":
        out({"jsonrpc": "2.0", "id": i, "result": {"isError": True, "content": [{"type": "text", "text": "e\udfff"}]}})
        continue
    out({"jsonrpc": "2.0", "id": i, "result": {"content": [{"type": "text", "text": "R:" + json.dumps(a)}]}})
if mode == "sticky":
    time.sleep(120)
'''


def setUpModule():
    global TMP, SRV
    TMP = tempfile.mkdtemp(prefix="sipar_r6_")
    SRV = os.path.join(TMP, "srv.py")
    with open(SRV, "w", encoding="utf-8") as f:
        f.write(SERVER)


def tearDownModule():
    import shutil
    shutil.rmtree(TMP, ignore_errors=True)


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:                                     # a zombie child of this process is dead
        done, _ = os.waitpid(pid, os.WNOHANG)
        return done == 0
    except ChildProcessError:
        return True


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="t_", dir=TMP)
        self.n = 0
        self.addCleanup(self.no_servers_left)

    def log(self, name="log"):
        return os.path.join(self.dir, name)

    def pids(self):
        out = []
        for f in os.listdir(self.dir):
            if f.endswith(".pids"):
                with open(os.path.join(self.dir, f)) as fh:
                    out += [int(x) for x in fh.read().split()]
        return out

    def no_servers_left(self, wait=5.0):
        end = time.monotonic() + wait
        left = [p for p in self.pids() if alive(p)]
        while left and time.monotonic() < end:
            time.sleep(0.1)
            left = [p for p in left if alive(p)]
        for p in left:                       # our own fake servers only
            try:
                os.kill(p, signal.SIGKILL)
            except OSError:
                pass
        self.assertEqual(left, [], "a fake MCP server outlived the test")

    def allow(self, mode, name="s", data=None, readonly=("read",), log=None):
        cmd = [sys.executable, SRV, mode, log or self.log()] + ([str(data)] if data is not None else [])
        line = f'allow mcp "{name}" {json.dumps(cmd)} tools ["read", "write"]'
        if readonly:
            line += f" readonly {json.dumps(list(readonly))}"
        return line + "\n"

    def src(self, body, mode="plain", head="", uses="mcp, io", **kw):
        return (self.allow(mode, **kw) + "allow io\n" + textwrap.dedent(head) + f"\nfn main() uses {uses} {{\n"
                + textwrap.dedent(body) + "\n}\n")

    def P(self, body, mode="plain", head="", uses="mcp, io", **kw):
        src = self.src(body, mode, head, uses, **kw)
        p = Prog(src)
        self.addCleanup(p.cleanup)
        program, d = check_source(src, p.path)
        errs = [(x.code, x.message) for x in d if x.severity == "error"]
        self.assertEqual(errs, [])
        p.program = program
        return p

    def run_p(self, p, journal=None, **kw):
        j = journal if journal is not None else Journal()
        try:
            return p.run(journal=j, **kw)
        finally:
            j.close()

    def err_p(self, p, journal=None, **kw):
        j = journal if journal is not None else Journal()
        try:
            return p.error(journal=j, **kw)
        finally:
            j.close()

    def calls(self, log=None):
        try:
            with open(log or self.log(), encoding="utf-8") as f:
                return [x for x in f.read().splitlines() if x.startswith("CALL ")]
        except FileNotFoundError:
            return []

    # -- a real `python -m sipar run` process
    def spawn(self, src, env=None):
        path = os.path.join(self.dir, "prog.sipar")
        with open(path, "w", encoding="utf-8") as f:
            f.write(src)
        e = {k: v for k, v in os.environ.items() if not k.startswith("SIPAR_")}
        e.update({"PYTHONPATH": ROOT, "PYTHONUNBUFFERED": "1", "SIPAR_MODEL": "mock"}, **(env or {}))
        p = subprocess.Popen([sys.executable, "-m", "sipar", "run", path], cwd=self.dir, env=e,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                             start_new_session=True, preexec_fn=default_signals)
        self.addCleanup(self.reap, p)
        lines: list = []
        threading.Thread(target=lambda: lines.extend(iter(p.stdout.readline, b"")), daemon=True).start()
        p.lines = lines
        return p

    def reap(self, p):
        if p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except OSError:
                pass
        p.wait(10)
        for f in (p.stdout, p.stderr):
            f.close()

    def wait_for(self, cond, timeout, what):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if cond():
                return
            time.sleep(0.05)
        self.fail(f"timed out waiting for {what}")


# ====================================================================== R1. a server that does not read stdin

class T_R1(Base):
    def test_big_request_to_deaf_server_times_out(self):
        src = self.src('let big = "x".repeat(2000000)\n'
                       'try { print(mcp.s.read(path: big)) } catch e { print("caught {e.kind}") }\n'
                       'print("after")', mode="deaf")
        t = time.monotonic()
        p = self.spawn(src, {"SIPAR_MCP_TIMEOUT": "2"})
        try:
            p.wait(25)
        except subprocess.TimeoutExpired:
            self.fail("sipar hung writing to a server that does not read its input")
        took = time.monotonic() - t
        out = b"".join(p.lines).decode()
        self.assertEqual(out, "caught io\nafter\n", p.stderr.read().decode()[-500:])
        self.assertLess(took, 20)

    def test_deaf_inside_budget_is_budget(self):
        p = self.P('let big = "x".repeat(2000000)\n'
                   'try { budget(seconds: 1.5) { print(mcp.s.read(path: big)) } } catch e { print("caught {e.kind}") }',
                   mode="deaf")
        done: list = []
        th = threading.Thread(target=lambda: done.append(self.run_p(p)), daemon=True)
        th.start()
        th.join(20)
        self.assertEqual(done, ["caught budget\n"])

    def test_pending_writes_are_capped(self):
        # a run that keeps queueing requests to a deaf server gets kind mcp, not unbounded memory
        p = self.P('let big = "x".repeat(300000)\nprint(mcp.s.read(path: big))', mode="deaf")
        with mock.patch.object(MCP, "MAX_PENDING_WRITE", 100_000, create=True), \
                mock.patch.dict(os.environ, {"SIPAR_MCP_TIMEOUT": "20"}):
            conn = MCP.Conn

            def send_twice(self, obj, _orig=conn.send):     # a second big write while the first is stuck
                _orig(self, obj)
                if obj.get("method") == "tools/call":
                    time.sleep(0.5)
                    _orig(self, obj)
            with mock.patch.object(MCP.Conn, "send", send_twice):
                done: list = []
                th = threading.Thread(target=lambda: done.append(self.err_p(p)), daemon=True)
                th.start()
                th.join(15)
        self.assertEqual([(e.kind, e.message[:38]) for e in done], [("mcp", "MCP server 's' does not read its input")])


# ====================================================================== R2. message floods

class T_R2(Base):
    def test_message_count_cap(self):
        p = self.P('print(mcp.s.read(n: 200, size: 1))', mode="flood")
        with mock.patch.object(MCP, "MAX_IGNORED", 50, create=True):
            e = self.err_p(p)
        self.assertEqual(e.kind, "mcp")
        self.assertTrue(e.message.startswith("MCP server 's' sent more than 50 messages"), e.message)

    def test_message_bytes_cap(self):
        p = self.P('print(mcp.s.read(n: 5, size: 1000000))', mode="flood")
        with mock.patch.object(MCP, "MAX_IGNORED_BYTES", 2_000_000, create=True):
            e = self.err_p(p)
        self.assertEqual(e.kind, "mcp")
        self.assertIn("2 MB that are not the answer to tools/call", e.message)

    def test_under_the_caps_is_fine(self):                     # guard
        p = self.P('print(mcp.s.read(n: 30, size: 10).len())', mode="flood")
        with mock.patch.object(MCP, "MAX_IGNORED", 50, create=True):
            self.assertEqual(self.run_p(p), f"{len('R:' + json.dumps({'n': 30, 'size': 10}))}\n")

    def test_read_ahead_is_capped(self):
        peak = [0]
        orig = getattr(MCP.Conn, "_take", None)
        self.assertIsNotNone(orig, "no bounded queue")

        def take(self, timeout):
            # R8C-2 (round 8): sample once the reader has queued something (a real condition, not a race with
            # the reader thread); q_bytes is raised before the line is put, so a queued line means q_bytes > 0
            deadline = time.monotonic() + timeout
            while self.q.empty() and time.monotonic() < deadline:
                time.sleep(0.001)
            peak[0] = max(peak[0], self.q_bytes)
            return orig(self, timeout)
        p = self.P('print(mcp.s.read(n: 40, size: 100000).len())', mode="flood")
        with mock.patch.object(MCP, "MAX_QUEUED_BYTES", 300_000), mock.patch.object(MCP.Conn, "_take", take):
            out = self.run_p(p)
        self.assertTrue(out.strip().isdigit(), out)
        self.assertLessEqual(peak[0], 300_000 + 100_200)       # the cap plus at most one message
        self.assertGreater(peak[0], 0)


# ====================================================================== R3. untrusted map keys

class T_R3(Base):
    HEAD_U = 'let u = mcp.s.read(path: "a")\n'

    def test_untrusted_key_to_write_tool(self):
        p = self.P(self.HEAD_U + 'try { print(mcp.call("s", "write", [u: "x"])) } catch e { print(e.kind) }')
        self.assertEqual(self.run_p(p), "taint\n")
        self.assertEqual([c.split()[1] for c in self.calls()], ["read"])

    def test_untrusted_key_static_call(self):
        p = self.P(self.HEAD_U + 'try { print(mcp.s.write(text: [u: "x"])) } catch e { print(e.kind) }')
        self.assertEqual(self.run_p(p), "taint\n")

    def test_nested_untrusted_key(self):                        # guard: labels_of takes keys in
        p = self.P(self.HEAD_U + 'try { print(mcp.call("s", "write", ["a": [u: "x"]])) } catch e { print(e.kind) }')
        self.assertEqual(self.run_p(p), "taint\n")

    def test_untrusted_key_readonly_ok(self):                   # guard
        p = self.P(self.HEAD_U + 'print(mcp.call("s", "read", [u: "x"]).len() > 0)')
        self.assertEqual(self.run_p(p), "true\n")

    def test_secret_key_never(self):
        p = self.P('let k = env.secret("R6_TOKEN")\n'
                   'try { print(mcp.call("s", "read", [k: "x"])) } catch e { print(e.kind) }',
                   head='allow secret ["R6_TOKEN"]\n', uses="mcp, io, secret")
        self.assertEqual(self.run_p(p, env={"R6_TOKEN": SECRET}), "taint\n")
        self.assertEqual(self.calls(), [])

    def test_error_names_the_key_not_the_value(self):
        p = self.P(self.HEAD_U + 'try { print(mcp.call("s", "write", [u: "x"])) } catch e { print(e.message) }')
        out = self.run_p(p)
        self.assertIn("mcp.s.write(the argument name 'R:", out)


# ====================================================================== R4. a secret inside an allow env variable

class T_R4(Base):
    HEAD = 'allow env ["R6_X", "R6_Y"]\nallow secret ["R6_TOKEN"]\n'
    ENV = {"R6_TOKEN": SECRET, "R6_X": f"pre-{SECRET}-post", "R6_Y": "plain-value"}

    def server_env(self):
        with open(self.log(), encoding="utf-8") as f:
            envs = [json.loads(x[4:]) for x in f.read().splitlines() if x.startswith("ENV ")]
        self.assertEqual(len(envs), 1)
        return envs[0]

    def test_mcp_child_env(self):
        p = self.P('print(mcp.s.read(path: "a").len() > 0)', mode="env", head=self.HEAD)
        self.assertEqual(self.run_p(p, env=self.ENV), "true\n")
        e = self.server_env()
        self.assertEqual(e.get("R6_Y"), "plain-value")
        self.assertNotIn("R6_X", e)
        self.assertNotIn("R6_TOKEN", e)
        with open(self.log(), encoding="utf-8") as f:
            self.assertNotIn(SECRET, f.read())

    def test_mcp_child_env_after_secret_read(self):            # guard: the registry already caught this
        p = self.P('let k = env.secret("R6_TOKEN")\nprint(mcp.s.read(path: "a").len() > 0)', mode="env",
                   head=self.HEAD, uses="mcp, io, secret")
        self.assertEqual(self.run_p(p, env=self.ENV), "true\n")
        self.assertNotIn("R6_X", self.server_env())

    def test_shell_env(self):
        src = (self.HEAD + 'allow shell ["env"]\nallow io\nfn main() uses shell, io {\n'
               '    let o = shell.run("env")\n    print(o.contains("R6_Y=plain-value"))\n'
               '    print(o.contains("R6_X"))\n    print(o.contains("zzz"))\n}\n')
        p = Prog(src)
        self.addCleanup(p.cleanup)
        self.assertEqual(p.run(env=self.ENV), "true\nfalse\nfalse\n")

    def test_env_get_is_secret(self):
        p = Prog('allow env ["R6_X", "R6_Y"]\nallow secret ["R6_TOKEN"]\nallow io\nfn main() uses env, io {\n'
                 '    print(env.get("R6_Y") ?? "none")\n'
                 '    try { print(env.get("R6_X") ?? "none") } catch e { print(e.kind) }\n}\n')
        self.addCleanup(p.cleanup)
        path = os.path.join(p.dir, "j.jsonl")
        j = Journal(path)
        try:
            out = p.run(env=self.ENV, journal=j)
        finally:
            j.close()
        self.assertEqual(out, "plain-value\ntaint\n")
        with open(path, encoding="utf-8") as f:
            self.assertNotIn(SECRET, f.read())

    def test_four_char_secret_is_a_filter(self):               # coverage: the 4-character boundary
        p = self.P('print(mcp.s.read(path: "a").len() > 0)', mode="env", head=self.HEAD)
        self.assertEqual(self.run_p(p, env=dict(self.ENV, R6_TOKEN="q7w8", R6_X="pre-q7w8-post")), "true\n")
        self.assertNotIn("R6_X", self.server_env())

    def test_env_get_unit(self):                               # coverage: env_get registers only what it finds
        from sipar.runtime import effects
        rt = mock.Mock()
        rt.caps.secret_names.return_value = ["R6_TOKEN"]
        rt.caps.grants = {"env": None}                           # round 9: guarded_names() reads the grants
        rt.journal.effect.side_effect = lambda kind, req, fn: fn()
        with mock.patch.dict(os.environ, self.ENV):
            self.assertEqual(effects.env_get(rt, "R6_Y"), "plain-value")
            rt.journal.add_secret.assert_not_called()
            effects.env_get(rt, "R6_X")
            rt.journal.add_secret.assert_called_once_with(SECRET, "secret:R6_TOKEN")
            rt.caps.check_env.side_effect = SiparRuntimeError("capability", "no")
            rt.journal.effect.reset_mock()
            with self.assertRaises(SiparRuntimeError):
                effects.env_get(rt, "R6_Z")
            rt.journal.effect.assert_not_called()

    def test_short_secret_not_a_filter(self):                  # guard: under 4 characters is no secret
        p = self.P('print(mcp.s.read(path: "a").len() > 0)', mode="env", head=self.HEAD)
        self.assertEqual(self.run_p(p, env=dict(self.ENV, R6_TOKEN="pre")), "true\n")
        self.assertEqual(self.server_env().get("R6_X"), f"pre-{SECRET}-post")


# ====================================================================== R5. SIGTERM / SIGHUP of sipar

class T_R5(Base):
    def sticky(self, sig):
        src = self.src('print(mcp.s.read(path: "a").len() > 0)\nsleep(60)\nprint("never")', mode="sticky",
                       head="allow time\n", uses="mcp, io, time")
        p = self.spawn(src)
        self.wait_for(lambda: p.lines, 20, "the first line")
        self.assertEqual(self.pids() and all(alive(x) for x in self.pids()), True)
        os.kill(p.pid, sig)
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            self.fail("sipar did not stop")
        return p

    def test_sigterm_kills_server(self):
        p = self.sticky(signal.SIGTERM)
        self.no_servers_left(wait=3)
        self.assertEqual(p.returncode, 128 + signal.SIGTERM)

    def test_sighup_kills_server(self):
        p = self.sticky(signal.SIGHUP)
        self.no_servers_left(wait=3)
        self.assertEqual(p.returncode, 128 + signal.SIGHUP)

    def test_normal_end_kills_sticky_server(self):             # guard
        p = self.P('print(mcp.s.read(path: "a").len() > 0)', mode="sticky")
        self.assertEqual(self.run_p(p), "true\n")
        self.no_servers_left(wait=3)

    def test_handlers_only_replace_default(self):
        from sipar.runtime import children
        old = signal.getsignal(signal.SIGTERM)
        try:
            marker = lambda *a: None                            # noqa: E731
            signal.signal(signal.SIGTERM, marker)
            children.install_signal_handlers()
            self.assertIs(signal.getsignal(signal.SIGTERM), marker)
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            children.install_signal_handlers()
            self.assertIs(signal.getsignal(signal.SIGTERM), children._on_signal)
        finally:
            signal.signal(signal.SIGTERM, old)

    def test_kill_all_by_owner(self):
        from sipar.runtime import children
        a = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
        b = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
        try:
            owner = object()
            with children._LOCK:
                children._PROCS[a.pid] = (a, owner)
                children._PROCS[b.pid] = (b, None)
            children.kill_all(owner)
            self.assertIsNotNone(a.poll())
            self.assertIsNone(b.poll())
            self.assertIn(b, children.tracked())
            self.assertNotIn(a, children.tracked())
        finally:
            children.untrack(b)
            for x in (a, b):
                x.kill()
                x.wait()


# ====================================================================== R6. one Ctrl-C

class T_R6(Base):
    def interrupt(self, src, ready):
        p = self.spawn(src)
        self.wait_for(ready(p), 20, "the program to block")
        t = time.monotonic()
        os.kill(p.pid, signal.SIGINT)
        try:
            p.wait(8)
        except subprocess.TimeoutExpired:
            self.fail("one Ctrl-C did not stop the run")
        self.assertLess(time.monotonic() - t, 6)
        self.assertEqual(p.returncode, 1)
        self.assertIn(b"interrupted", p.stderr.read())

    def test_ctrl_c_in_sleep(self):
        src = 'allow io\nallow time\nfn main() uses io, time {\n print("ready")\n sleep(60)\n print("never")\n}\n'
        self.interrupt(src, lambda p: lambda: p.lines)

    def test_ctrl_c_in_mcp_call(self):
        src = self.src('print(mcp.s.read(path: "a"))', mode="silent")
        self.interrupt(src, lambda p: lambda: self.calls())
        self.no_servers_left(wait=3)

    def test_sleep_on_main_thread(self):                       # coverage: no deep worker -> time.sleep
        from sipar.runtime import effects
        with mock.patch.object(effects._time, "sleep") as s:
            effects._pause(0.5)
        s.assert_called_once_with(0.5)


# ====================================================================== R7. typed decode labels

class T_R7(Base):
    def data(self, d):
        path = os.path.join(self.dir, "d.json")
        with open(path, "w") as f:
            json.dump(d, f)
        return path

    def sink(self, expr):
        return f'try {{ print(mcp.w.write(text: {expr})) }} catch e {{ print(e.kind) }}\n'

    def test_mcp_typed_lengths(self):
        d = self.data({"bs": [True, False, True], "m": {"k": True}})
        head = self.allow("plain", name="w", log=self.log("w")) + "type R = { bs: List[Bool], m: Map[Bool] }\n"
        p = self.P('let r: R = mcp.s.read(path: "a")\n' + self.sink('"{r.bs.len()}"') + self.sink('"{r.m.len()}"')
                   + self.sink('"{r.bs.filter(fn(b: Bool) -> Bool => b).len()}"'), mode="struct", data=d, head=head)
        self.assertEqual(self.run_p(p), "taint\ntaint\ntaint\n")
        self.assertEqual(self.calls(self.log("w")), [])

    def test_ai_typed_length(self):
        head = (self.allow("plain", name="w", log=self.log("w")) + "allow ai\n"
                'ai fn bools() -> List[Bool] { "give" }\nai fn flags() -> Map[Bool] { "give" }\n')
        p = self.P(self.sink('"{bools().len()}"') + self.sink('"{flags().len()}"'), head=head, uses="mcp, io, ai")
        self.assertEqual(self.run_p(p, script=["[true, false]", '{"a": true}']), "taint\ntaint\n")

    def test_as_typed_length(self):
        head = self.allow("plain", name="w", log=self.log("w")) + 'allow ai\nai fn s() -> Str { "give" }\n'
        p = self.P('let bs = s() as List[Bool]\n' + self.sink('"{bs.len()}"'), head=head, uses="mcp, io, ai")
        self.assertEqual(self.run_p(p, script=["[true, true]"]), "taint\n")

    def test_trusted_lengths_stay_clean(self):                 # guard
        head = self.allow("plain", name="w", log=self.log("w"))
        p = self.P('let bs = [true, false]\n' + self.sink('"{bs.len()}"'), head=head)
        self.assertEqual(self.run_p(p), 'R:{"text": "2"}\n')


# ====================================================================== R8. lone surrogates

class T_R8(Base):
    def journal(self):
        path = os.path.join(self.dir, "j.jsonl")
        return path, Journal(path)

    def check_journal(self, path):
        with open(path, encoding="utf-8") as f:
            text = f.read()
        self.assertTrue(text)
        for line in text.splitlines():
            json.loads(line)

    def test_text_and_structured(self):
        p = self.P('let t = mcp.s.read(path: "a")\nprint(t)\nlet k: K = mcp.s.read(path: "b")\nprint(k.k)',
                   mode="surr", head="type K = { k: Str }\n")
        path, j = self.journal()
        self.assertEqual(self.run_p(p, journal=j), "a�b\nc�d\n")
        self.check_journal(path)

    def test_rpc_error_message(self):
        p = self.P('try { print(mcp.s.read(path: "a")) } catch e { print(e.kind)\n print(e.message) }',
                   mode="surrerr")
        path, j = self.journal()
        out = self.run_p(p, journal=j)
        self.assertEqual(out.split("\n")[0], "mcp")
        self.assertNotIn("\ud800", out)
        self.assertIn("�", out)

    def test_is_error_text(self):
        p = self.P('try { print(mcp.s.read(path: "a")) } catch e { print(e.kind)\n print(e.message) }',
                   mode="surriserr")
        path, j = self.journal()
        out = self.run_p(p, journal=j)
        self.assertTrue(out.startswith("mcp\n"), out)
        self.assertIn("e�", out)
        self.assertNotIn("\udfff", out)

    def test_description(self):
        p = self.P('print(mcp.s.read(path: "a").len())', mode="surrdesc")
        path, j = self.journal()
        out = self.run_p(p, journal=j)
        self.assertEqual(out, f"{len('R:' + json.dumps({'path': 'a'}))}\n")
        self.check_journal(path)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn("\\ud800", text)
        self.assertNotIn("\ud800", text)


# ====================================================================== R9. deep structuredContent

class T_R9(Base):
    def test_deep_structured_is_catchable(self):
        p = self.P('try { let k: K = mcp.s.read(path: "a")\n print("got") } catch e { print(e.kind) }\nprint("after")',
                   mode="deep", data=30000, head="type K = { a: Int }\n")
        self.assertEqual(self.run_p(p), "mcp\nafter\n")

    def test_deep_untyped_is_catchable(self):
        p = self.P('try { print(mcp.s.read(path: "a")) } catch e { print(e.kind) }\nprint("after")',
                   mode="deep", data=30000)
        self.assertEqual(self.run_p(p), "mcp\nafter\n")

    def test_deep_replays_as_catchable(self):
        p = self.P('try { print(mcp.s.read(path: "a")) } catch e { print(e.kind) }\nprint("after")',
                   mode="deep", data=30000)
        path = os.path.join(self.dir, "j.jsonl")
        self.assertEqual(self.run_p(p, journal=Journal(path)), "mcp\nafter\n")
        with mock.patch("subprocess.Popen", side_effect=AssertionError("replay started a process")):
            self.assertEqual(self.run_p(p, journal=Journal(replay=Journal.load(path))), "mcp\nafter\n")

    def test_limit_exact(self):                               # coverage: 20,000 levels still decode
        self.assertFalse(MCP.too_deep({"result": {"structuredContent": [[1]]}}, MCP.MAX_VALUE_DEPTH + 2))
        v = 1
        for _ in range(MCP.MAX_VALUE_DEPTH):
            v = [v]
        self.assertFalse(MCP.too_deep({"r": {"s": v}}, MCP.MAX_VALUE_DEPTH + 2))
        self.assertTrue(MCP.too_deep({"r": {"s": [v]}}, MCP.MAX_VALUE_DEPTH + 2))


# ====================================================================== R10. docs: pins and local servers

class T_R10(unittest.TestCase):
    def test_spec_says_pins_do_not_stop_local_code(self):
        with open(os.path.join(ROOT, "SPEC.md"), encoding="utf-8") as f:
            spec = " ".join(f.read().split())
        self.assertIn("a stdio server runs as the same user, in the program's folder, and can edit "
                      "`.sipar/mcp/*.pins.json` itself", spec)
        self.assertIn("Pins defend against a *remote* server", spec)


# ====================================================================== L. labels_of is linear

class T_L(unittest.TestCase):
    SRC = ('allow io\nallow mcp "s" ["true"] tools ["read"]\ntype N = { kids: List[N], tag: Str }\n'
           'fn main(args: List[Str]) uses io {\n'
           '    let n = 6000\n    var x = N { kids: [], tag: "a" }\n    var i = 0\n'
           '    while i < n { x = N { kids: [x], tag: "b" }; i = i + 1 }\n'
           '    var y = x\n    var d = 0\n'
           '    while y.kids.len() > 0 { y = y.kids[0]; d = d + 1 }\n    print(d)\n}\n')

    def test_deep_walk_is_fast(self):
        p = Prog(self.SRC)
        self.addCleanup(p.cleanup)
        t = time.monotonic()
        self.assertEqual(p.run(argv=[]), "6000\n")
        self.assertLess(time.monotonic() - t, 5.0)             # 084abd0: 18.5 s (quadratic)


class T_Lmemo(unittest.TestCase):
    """The memo must forget a container that changed in place (coverage for every mutated() call)."""
    HEAD = ('allow io\nallow ai\nallow fs.write ["./out"]\nai fn u() -> Str { "give" }\n'
            'type R = { xs: List[Str], m: Map[Str] }\n')
    USES = "io, ai, fs.write"

    def out(self, body, head=""):
        p = Prog(self.HEAD + head + f"fn main() uses {self.USES} {{\n" + textwrap.dedent(body) + "\n}\n",
                 files={"out/keep": ""})
        self.addCleanup(p.cleanup)
        return p.run(script=["evil"] * 4).replace("clean", "false").replace("taint", "true")

    def labelled(self, expr):          # prints taint when the text built from expr is labelled
        return f'try {{ fs.write("out/x.txt", "{{{expr}}}")\n print("clean") }} catch e {{ print(e.kind) }}\n'

    def test_push_and_pop(self):
        body = ('var xs = ["a"]\n' + self.labelled("xs.len()") + 'xs.push(u())\n' + self.labelled("xs.len()")
                + 'let t = xs.pop()\n' + self.labelled("xs.len()"))
        self.assertEqual(self.out(body), "false\ntrue\nfalse\n")

    def test_index_assign(self):
        body = ('var xs = ["a", "b"]\n' + self.labelled("xs.len()") + 'xs[0] = u()\n' + self.labelled("xs.len()")
                + 'xs[0] = "c"\n' + self.labelled("xs.len()"))
        self.assertEqual(self.out(body), "false\ntrue\nfalse\n")

    def test_map_assign_and_remove(self):
        body = ('var m = ["a": "1"]\n' + self.labelled("m.len()") + 'm["b"] = u()\n' + self.labelled("m.len()")
                + 'let t = m.remove("b")\n' + self.labelled("m.len()"))
        self.assertEqual(self.out(body), "false\ntrue\nfalse\n")

    def test_field_assign(self):
        body = ('var r = R { xs: ["a"], m: ["k": "v"] }\nlet keep = r.xs\n' + self.labelled("r.xs.len()")
                + 'r.xs = [u()]\n' + self.labelled("r.xs.len()") + 'r.xs = keep\n' + self.labelled("r.xs.len()"))
        self.assertEqual(self.out(body), "false\ntrue\nfalse\n")

    def test_shared_inner_list(self):
        body = ('var inner = ["a"]\nlet outer = [inner, inner]\n' + self.labelled("outer.len()")
                + 'inner.push(u())\n' + self.labelled("outer.len()"))
        self.assertEqual(self.out(body), "false\ntrue\n")

    def test_cycle(self):
        body = ('var x = N { kids: [], tag: "a" }\nx.kids.push(x)\n' + self.labelled("x.kids.len()")
                + 'x.kids.push(N { kids: [], tag: u() })\n' + self.labelled("x.kids.len()"))
        self.assertEqual(self.out(body, head="type N = { kids: List[N], tag: Str }\n"), "false\ntrue\n")

    def test_memo_hits(self):
        from sipar.runtime import values as V
        V.mutated()
        leaf = V.with_labels("a", ["x"])
        inner = [[leaf]]
        outer = [inner, V.with_labels("b", ["y"])]
        self.assertEqual(V.labels_of(inner), frozenset({"x"}))
        with mock.patch.object(V, "_labels_memo", side_effect=AssertionError("walked again")):
            self.assertEqual(V.labels_of(inner), frozenset({"x"}))       # a top-level hit
        calls = []
        orig = V._labels_memo

        def count(v, memo, path):
            calls.append(v)
            return orig(v, memo, path)
        with mock.patch.object(V, "_labels_memo", count):
            self.assertEqual(V.labels_of(outer), frozenset({"x", "y"}))
        self.assertEqual(len(calls), 2)                                    # outer, then inner from the memo

    def test_memo_bounded_and_reset(self):
        from sipar.runtime import values as V
        with mock.patch.object(V, "MEMO_MAX", 3):
            xs = [[V.with_labels("a", ["x"])] for _ in range(10)]
            for v in xs:
                self.assertEqual(V.labels_of(v), frozenset({"x"}))
            self.assertLessEqual(len(V._memo()), 4)
        with mock.patch.object(V, "MEMO_MAX", 3):              # exactly MEMO_MAX entries are kept
            V.mutated()
            for _ in range(3):
                V.labels_of([V.with_labels("a", ["x"])])
            self.assertEqual(len(V._memo()), 3)
        v = [V.with_labels("a", ["x"])]
        self.assertEqual(V.labels_of(v), frozenset({"x"}))
        v.append(V.with_labels("b", ["y"]))
        V.mutated()
        self.assertEqual(V.labels_of(v), frozenset({"x", "y"}))


# ====================================================================== R5 / R6 units: children.py, deep.py

class T_R5unit(unittest.TestCase):
    """children.py without real signals (mutation survivors of the first pass). Fake children never reach
    os.killpg: kill_group is patched."""

    def setUp(self):
        from sipar.runtime import children
        self.ch = children
        p = mock.patch.object(children, "_PROCS", {})
        p.start()
        self.addCleanup(p.stop)

    def fake(self, pid, done):
        p = mock.Mock(pid=pid)
        p.poll.return_value = 0 if done else None
        return p

    def test_kill_all_skips_finished_and_waits_each(self):
        done, live = self.fake(-101, True), self.fake(-102, False)
        live.wait.side_effect = subprocess.TimeoutExpired("x", 1)       # a child that does not die at once
        self.ch.track(done)
        self.ch.track(live)
        with mock.patch.object(self.ch, "kill_group") as kg:
            self.ch.kill_all()
        kg.assert_called_once_with(live)          # an exited child's pid may be reused: never signal it
        done.wait.assert_called_once_with(timeout=1)
        live.wait.assert_called_once_with(timeout=1)
        self.assertEqual(self.ch.tracked(), [])

    def test_untrack_only_that_child(self):
        a, b = self.fake(-201, False), self.fake(-201, False)          # b: another child with a reused pid
        self.ch.track(a)
        self.ch.untrack(b)
        self.assertEqual(self.ch.tracked(), [a])
        self.ch.untrack(a)
        self.assertEqual(self.ch.tracked(), [])

    def test_every_access_holds_the_lock(self):
        lock = mock.MagicMock()
        p = self.fake(-301, True)
        with mock.patch.object(self.ch, "_LOCK", lock):
            self.ch.track(p)
            self.ch.tracked()
            self.ch.untrack(p)
            self.ch.kill_all()
        self.assertEqual(lock.__enter__.call_count, 4)

    def test_signal_handler_kills_then_exits(self):
        with mock.patch.object(self.ch, "kill_all") as ka:
            with self.assertRaises(SystemExit) as cm:
                self.ch._on_signal(signal.SIGTERM, None)
        ka.assert_called_once_with()
        self.assertEqual(cm.exception.code, 128 + signal.SIGTERM)

    def test_normal_exit_kills_tracked_children(self):           # atexit, in a real Python process
        code = ("import subprocess, sys\nfrom sipar.runtime import children\n"
                "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], start_new_session=True)\n"
                "children.track(p)\nprint(p.pid, flush=True)\n")
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=20,
                             env={**os.environ, "PYTHONPATH": ROOT}).stdout
        pid = int(out.split()[0])

        def gone():
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            return False

        if not gone():                             # reparented to init: it dies, then init reaps it
            deadline = time.monotonic() + 5
            while not gone() and time.monotonic() < deadline:
                time.sleep(0.05)
        alive = not gone()
        if alive:
            os.kill(pid, signal.SIGKILL)           # our own child: never leave it running
        self.assertFalse(alive, "the tracked child outlived the process")


class T_R6unit(unittest.TestCase):
    """deep.call_deep and the first Ctrl-C, with a real SIGINT sent to the main thread."""

    def setUp(self):
        from sipar import deep
        from sipar.runtime import children
        self.deep, self.ch = deep, children
        # round 9, M5: Ctrl-C raises KeyboardInterrupt here even when the suite started with SIGINT ignored
        self.addCleanup(signal.signal, signal.SIGINT, signal.signal(signal.SIGINT, signal.default_int_handler))

    def ctrl_c(self, after):
        t = threading.Timer(after, signal.pthread_kill, (threading.main_thread().ident, signal.SIGINT))
        t.start()
        self.addCleanup(t.cancel)

    def test_first_ctrl_c_stops_the_worker(self):
        seen = {}

        def fn():
            ev = self.deep.stop_event()
            try:
                ev.wait(3)                     # like sleep(): ends when the stop is set (or the interrupt lands)
                end = time.monotonic() + 3
                while time.monotonic() < end:
                    time.sleep(0.01)
            finally:
                seen["set"] = ev.is_set()
                time.sleep(0.2)                # cleanup the caller waits for
                seen["done"] = True

        with mock.patch.object(self.ch, "kill_all") as ka:
            self.ctrl_c(0.3)
            t0 = time.monotonic()
            with self.assertRaises(KeyboardInterrupt):
                self.deep.call_deep(fn)
            took = time.monotonic() - t0
        self.assertEqual(seen, {"set": True, "done": True})
        self.assertLess(took, 1.8)
        self.assertEqual(ka.call_count, 1)
        self.assertIsInstance(ka.call_args[0][0], threading.Event)

    def test_ctrl_c_does_not_trust_is_alive(self):
        # R6b: on 3.12 a join() cut by Ctrl-C marks the thread stopped, so is_alive() lies (says False);
        # the caller must still raise KeyboardInterrupt and wait for the worker's cleanup
        seen = {}

        def fn():
            try:
                self.deep.stop_event().wait(3)
            finally:
                time.sleep(0.2)
                seen["done"] = True

        with mock.patch.object(self.ch, "kill_all"), \
                mock.patch.object(threading.Thread, "is_alive", lambda self: False):
            self.ctrl_c(0.3)
            with self.assertRaises(KeyboardInterrupt):
                self.deep.call_deep(fn)
        self.assertEqual(seen, {"done": True})

    def test_stuck_worker_is_left_after_the_grace(self):
        release = threading.Event()
        self.addCleanup(release.set)

        def fn():                                  # ignores the stop and the KeyboardInterrupt, like C code
            end = time.monotonic() + 3
            while time.monotonic() < end and not release.is_set():
                try:
                    while time.monotonic() < end and not release.is_set():
                        time.sleep(0.02)
                except KeyboardInterrupt:
                    pass
            return "free"

        with mock.patch.object(self.deep, "STOP_GRACE", 0.3), mock.patch.object(self.ch, "kill_all"):
            self.ctrl_c(0.2)
            t0 = time.monotonic()
            with self.assertRaises(KeyboardInterrupt):
                self.deep.call_deep(fn)
            took = time.monotonic() - t0
        self.assertLess(took, 1.5)

    def test_long_run_is_not_cut(self):
        with mock.patch.object(self.deep, "STOP_GRACE", 0.1), mock.patch.object(self.ch, "kill_all") as ka:
            self.assertEqual(self.deep.call_deep(lambda: time.sleep(0.4) or 7), 7)
        ka.assert_not_called()

    def test_stack_size_restored(self):
        before = threading.stack_size()
        self.assertEqual(self.deep.call_deep(lambda: 5), 5)
        self.assertEqual(threading.stack_size(), before)

    def where(self):
        return self.deep.call_deep(lambda: threading.current_thread() is threading.main_thread())

    def test_refused_stack_size_runs_here(self):
        real = threading.stack_size

        def refuse(*a):
            if a and a[0]:
                raise ValueError("refused")
            return real(*a)

        with mock.patch.object(threading, "stack_size", refuse):
            self.assertIs(self.where(), True)

    def test_no_thread_left_runs_here(self):
        class NoThread:
            def __init__(self, *a, **k):
                pass

            def start(self):
                raise RuntimeError("can't start new thread")

        before = threading.stack_size()
        with mock.patch.object(threading, "Thread", NoThread):
            self.assertIs(self.where(), True)
        self.assertEqual(threading.stack_size(), before)


def cli(*argv):
    from sipar.cli import main as cli_main
    out, err = io.StringIO(), io.StringIO()
    rc = cli_main(list(argv), out, err)
    return rc, out.getvalue(), err.getvalue()


class T_B3(unittest.TestCase):
    """Batch 3 (round-6 CLI/docs/API critic)."""

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="sipar_b3_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.d, ignore_errors=True)

    def put(self, name, text, mode="w"):
        p = os.path.join(self.d, name)
        with open(p, mode) as f:
            f.write(text)
        return p

    # ---- M1: control characters never reach the terminal raw
    def test_m1_check_snippet_escaped(self):
        p = self.put("esc.sipar", "fn main() { let = 1 } // \x1b[2J\x1b]0;pwned\x07 hi\n")
        rc, o, e = cli("check", p)
        self.assertNotEqual(rc, 0)
        self.assertNotIn("\x1b", o + e)
        self.assertNotIn("\x07", o + e)
        self.assertIn("\\x1b[2J", o + e)

    def test_m1_test_name_escaped(self):
        p = self.put("t.sipar", 'fn f() -> Int { 1 }\ntest "t\x1b]0;pwned\x07x" { assert f() == 2 }\n')
        rc, o, e = cli("test", p)
        self.assertNotIn("\x1b", o + e)
        self.assertIn("t\\x1b]0;pwned\\x07x", o + e)

    def test_m1_missing_file_escaped(self):
        rc, o, e = cli("check", os.path.join(self.d, "zz\x1b[31mX.sipar"))
        self.assertEqual(rc, 2)
        self.assertNotIn("\x1b", e)
        self.assertIn("zz\\x1b[31mX.sipar", e)

    def test_m1_file_ok_escaped(self):
        p = self.put("w\x1b[1mW.sipar", "fn main() { print(1) }\n")
        rc, o, e = cli("check", p)
        self.assertEqual(rc, 0, e)
        self.assertNotIn("\x1b", o)
        self.assertIn("w\\x1b[1mW.sipar: ok", o)

    def test_m1_json_keeps_raw_text(self):
        p = self.put("j\x1bk.sipar", "fn main() { let = 1 } // \x1b[2J\n")
        rc, o, e = cli("check", p, "--json")
        d = json.loads(o)
        self.assertEqual(d[0]["file"], p)

    def test_m1_render_escapes_hint(self):
        from sipar.errors import Diagnostic
        r = Diagnostic("E1", "error", "f", 1, 1, "m", "use \x1b[2J").render()
        self.assertNotIn("\x1b", r)
        self.assertIn("\\x1b[2J", r)

    # ---- M2: an out= writer needs only write()
    def test_m2_writer_without_flush(self):
        import sipar
        from sipar.runtime.interp import Interp
        p = self.put("h.sipar", 'allow io\nfn hello(x: Str) -> Str { print("hi {x}")\n x }\n'
                              'fn ask() -> Str uses io { input("q? ") }\n'
                              'fn ok() -> Str uses io { approve("v", "fine?") }\n'
                              'fn main() uses io { print(approve("v", "fine?")) }\n')
        prog = sipar.load(p)

        class Writer:
            def __init__(self):
                self.parts = []

            def write(self, s):
                self.parts.append(s)
        w = Writer()
        self.assertEqual(prog.call("hello", "a", out=w), "a")          # print()
        self.assertEqual("".join(w.parts), "hi a\n")
        with self.assertRaises(SiparRuntimeError) as cm:                 # input(): the API has no stdin
            prog.call("ask", out=w)
        self.assertIn("end of input", str(cm.exception))
        self.assertTrue("".join(w.parts).endswith("q? "))

        class TTYIn(io.StringIO):
            def isatty(self):
                return True
        o, e = Writer(), Writer()                                        # approve() asks on err
        it = Interp(prog.program, p, out=o, err_out=e, stdin=TTYIn("y\n"))
        it.run_main()
        self.assertEqual("".join(o.parts), "v\n")
        self.assertIn("approve? [y/N] ", "".join(e.parts))

    def test_m2_flush_helper(self):
        from sipar.errors import flush
        calls = []

        class F:
            def flush(self):
                calls.append(1)
        flush(F())
        flush(object())                         # no flush(): nothing happens

        class G:
            flush = None                        # not callable
        flush(G())
        self.assertEqual(calls, [1])

    # ---- L12: trace and replay treat a bad journal the same way
    def test_l12_trace_non_utf8(self):
        prog = self.put("p.sipar", "fn main() { print(1) }\n")
        j = self.put("j.jsonl", b'{"k": "\xff\xfe"}\n', "wb")
        rc_t, o, e_t = cli("trace", j)
        rc_r, o, e_r = cli("replay", prog, j)
        self.assertEqual(rc_t, 2)                       # round 7: an unreadable input, like a missing one
        self.assertEqual(rc_t, rc_r)
        self.assertEqual(e_t, f"sipar: cannot read {j}: not UTF-8 text\n")
        self.assertEqual(e_r, e_t)
        self.assertNotIn("Traceback", e_t)

    @unittest.skipIf(os.geteuid() == 0, "root reads everything")
    def test_l12_same_permission_wording(self):
        prog = self.put("p.sipar", "fn main() { print(1) }\n")
        j = self.put("j.jsonl", "{}\n")
        os.chmod(j, 0)
        try:
            rc_t, _, e_t = cli("trace", j)
            rc_r, _, e_r = cli("replay", prog, j)
        finally:
            os.chmod(j, 0o600)
        self.assertEqual((rc_t, rc_r), (2, 2))
        self.assertIn(f"cannot read {j}: permission denied", e_t)       # round 7: one lowercase wording
        self.assertIn(f"cannot read {j}: permission denied", e_r)

    def test_l12_trace_directory_and_missing(self):
        rc, _, e = cli("trace", self.d)
        self.assertEqual(rc, 2)
        self.assertIn("is a directory, not a journal file", e)
        rc, _, e = cli("trace", os.path.join(self.d, "none.jsonl"))
        self.assertEqual(rc, 2)
        self.assertIn("no such journal", e)

    # ---- L13: usage diagnostics in --json have a hint
    def test_l13_json_usage_hint(self):
        rc, o, e = cli("check", os.path.join(self.d, "none.sipar"), "--json")
        d = json.loads(o)
        self.assertEqual(d[0]["code"], "usage")
        self.assertIn("sipar --help", d[0]["hint"])

    # ---- L14: long source lines are cut around the column
    def test_l14_long_line_cut(self):
        from sipar.errors import Diagnostic, MAX_SNIPPET
        self.assertEqual(MAX_SNIPPET, 200)
        line = "a" * 600 + "X" + "b" * 600
        r = Diagnostic("E1", "error", "f", 1, 601, "m").render(line).split("\n")
        snip, caret = r[1], r[2]
        body = snip.split("| ", 1)[1]
        self.assertEqual(body, "…" + "a" * 100 + "X" + "b" * 99 + "…")
        self.assertEqual(caret.index("^"), snip.index("X"))

    def test_l14_cut_at_the_ends(self):
        from sipar.errors import Diagnostic
        line = "X" + "b" * 400
        r = Diagnostic("E1", "error", "f", 1, 1, "m").render(line).split("\n")
        self.assertEqual(r[1].split("| ", 1)[1], "X" + "b" * 199 + "…")
        self.assertEqual(r[2].index("^"), r[1].index("X"))
        line = "a" * 400 + "X"
        r = Diagnostic("E1", "error", "f", 1, 401, "m").render(line).split("\n")
        self.assertEqual(r[1].split("| ", 1)[1], "…" + "a" * 199 + "X")
        self.assertEqual(r[2].index("^"), r[1].index("X"))
        line = "c" * 200                         # exactly the limit: not cut
        r = Diagnostic("E1", "error", "f", 1, 5, "m").render(line).split("\n")
        self.assertEqual(r[1].split("| ", 1)[1], line)

    def test_l14_caret_after_escaped_control(self):
        from sipar.errors import Diagnostic
        r = Diagnostic("E1", "error", "f", 1, 3, "m").render("\x1bbX").split("\n")
        self.assertEqual(r[2].index("^"), r[1].index("X"))

    # ---- L15: `sipar spec` keeps blank lines inside code fences
    def test_l15_spec_keeps_fenced_blank_lines(self):
        from sipar.cli import spec_text
        lines = spec_text().split("\n")
        fence, inside_blank, outside_blank = False, 0, 0
        for ln in lines:
            if ln.lstrip().startswith("```"):
                fence = not fence
            elif not ln.strip():
                if fence:
                    inside_blank += 1
                else:
                    outside_blank += 1
        self.assertGreater(inside_blank, 0)
        self.assertLessEqual(outside_blank, 1)    # only a trailing newline

    # ---- L16: every argument has a help text
    def test_l16_help_texts(self):
        from sipar.cli import build_parser
        p = build_parser()
        for name, sp in p.subs.items():
            for act in sp._actions:
                if act.dest != "help":
                    self.assertTrue(act.help, f"{name} {act.dest} has no help")

    # ---- L6: prog.call leaves the host's recursion limit and stack size alone
    def test_l6_limits_restored(self):
        import sipar
        p = self.put("s.sipar", "fn plain(x: Str) -> Int { x as Int }\n")
        prog = sipar.load(p)
        old = sys.getrecursionlimit()
        sys.setrecursionlimit(1500)
        try:
            st = threading.stack_size()
            self.assertEqual(prog.call("plain", "5"), 5)
            self.assertEqual(sys.getrecursionlimit(), 1500)
            self.assertEqual(threading.stack_size(), st)
            with self.assertRaises(SiparRuntimeError):
                prog.call("plain", "x")
            self.assertEqual(sys.getrecursionlimit(), 1500)
        finally:
            sys.setrecursionlimit(old)

    def test_l6_high_limit_while_running(self):
        from sipar import deep
        old = sys.getrecursionlimit()
        sys.setrecursionlimit(1200)
        try:
            self.assertEqual(deep.call_deep(sys.getrecursionlimit), deep.RECURSION_LIMIT)
            self.assertEqual(sys.getrecursionlimit(), 1200)
        finally:
            sys.setrecursionlimit(old)

    def test_l6_host_change_kept(self):
        from sipar import deep
        old = sys.getrecursionlimit()
        sys.setrecursionlimit(1200)
        try:
            deep.call_deep(lambda: sys.setrecursionlimit(5000))  # the host (another thread) changed it
            self.assertEqual(sys.getrecursionlimit(), 5000)
            sys.setrecursionlimit(deep.RECURSION_LIMIT + 1)     # a host limit above ours is never lowered
            deep.call_deep(lambda: None)
            self.assertEqual(sys.getrecursionlimit(), deep.RECURSION_LIMIT + 1)
        finally:
            sys.setrecursionlimit(old)

    def test_l6_overlapping_calls(self):
        from sipar import deep
        old = sys.getrecursionlimit()
        sys.setrecursionlimit(1200)
        go, seen = threading.Event(), []
        try:
            def slow():
                go.wait(5)
                return sys.getrecursionlimit()
            t = threading.Thread(target=lambda: seen.append(deep.call_deep(slow)))
            t.start()
            time.sleep(0.1)
            seen.append(deep.call_deep(sys.getrecursionlimit))   # ends first: the other call still runs
            seen.append(sys.getrecursionlimit())
            go.set()
            t.join(5)
            self.assertEqual(seen, [deep.RECURSION_LIMIT, deep.RECURSION_LIMIT, deep.RECURSION_LIMIT])
            self.assertEqual(sys.getrecursionlimit(), 1200)
        finally:
            go.set()
            sys.setrecursionlimit(old)


M5_SRC = '''allow ai
enum Team { billing, tech, spam }
type Verdict = { team: Team, urgent: Bool, summary: Str }
@retries(1)
ai fn classify(ticket: Str) -> Verdict { "Route: {ticket}" }
ai fn count(t: Str) -> Int { "How many: {t}" }
fn add(a: Int, b: Int) -> Int { a + b }
@max_steps(4)
agent fn ag(goal: Str) -> Int { tools [add]
 "Goal: {goal}" }
fn main() uses ai { print(classify("hi").team) }
'''
VERDICT = {"team": "spam", "urgent": False, "summary": "an ad"}


class T_M5(unittest.TestCase):
    """M5: with a script the mock is strict; the default answer is kept only without a script."""

    def setUp(self):
        import sipar
        self.d = tempfile.mkdtemp(prefix="sipar_m5_")
        self.path = os.path.join(self.d, "m5.sipar")
        with open(self.path, "w") as f:
            f.write(M5_SRC)
        self.prog = sipar.load(self.path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.d, ignore_errors=True)

    def err(self, fn, *args, **kw):
        from sipar import SiparError
        with self.assertRaises(SiparError) as c:
            self.prog.call(fn, *args, **kw)
        return c.exception

    def test_default_without_script_kept(self):          # guard
        self.assertEqual(self.prog.call("classify", "x"), {"team": "billing", "urgent": False, "summary": "mock"})
        self.assertEqual(self.prog.call("ag", "x"), 0)

    def test_valid_script_used(self):                    # guard: the fixed SPEC / api.py example
        self.assertEqual(self.prog.call("classify", "hi", model="mock", mock_script=[VERDICT]), VERDICT)

    def test_empty_script_fails(self):
        e = self.err("classify", "x", mock_script=[])
        self.assertEqual(e.kind, "ai")
        self.assertIn("no reply left for classify()", e.message)
        self.assertIn("never invents an answer", e.message)

    def test_old_doc_example_fails_naming_the_reply(self):
        e = self.err("classify", "hi", mock_script=["spam"])      # the old SPEC.md / api.py example
        self.assertEqual(e.kind, "ai")
        self.assertIn("no reply left for classify()", e.message)
        self.assertIn("the last scripted reply was rejected", e.message)
        self.assertNotIn("Your reply was invalid", e.message)

    def test_invalid_then_valid_retry_ok(self):          # guard: @retries still feeds the next reply
        self.assertEqual(self.prog.call("classify", "hi", mock_script=["spam", VERDICT]), VERDICT)

    def test_script_runs_out_mid_program(self):
        e = self.err("classify", "x", mock_script={"classify": []})
        self.assertIn("no reply left for classify()", e.message)

    def test_dict_without_this_fn(self):
        from sipar import SiparError
        src = M5_SRC.replace('fn main() uses ai { print(classify("hi").team) }',
                             'fn main() uses ai { print(count("a")) }')
        p = Prog(src)
        try:
            with self.assertRaises(SiparError) as c:
                p.run(script={"classify": [VERDICT]})
            self.assertEqual(c.exception.kind, "ai")
            self.assertIn("the mock script has no reply for count()", c.exception.message)
        finally:
            p.cleanup()

    def test_unknown_key_api(self):
        e = self.err("classify", "x", mock_script={"clasify": [VERDICT]})
        self.assertEqual(e.kind, "ai")
        self.assertIn("names no ai/agent fn: 'clasify'", e.message)
        self.assertIn("ag, classify, count", e.message)

    def test_unknown_key_plain_fn(self):
        e = self.err("classify", "x", mock_script={"classify": [VERDICT], "add": [1]})
        self.assertIn("'add'", e.message)

    def test_unknown_key_env_file(self):
        f = os.path.join(self.d, "script.json")
        with open(f, "w") as fh:
            json.dump({"clasify": [VERDICT]}, fh)
        rc, o, e = run_cli_env(["run", self.path], {"SIPAR_MODEL": "mock", "SIPAR_MOCK_SCRIPT": f})
        self.assertNotEqual(rc, 0)
        self.assertIn("names no ai/agent fn: 'clasify'", e)
        self.assertNotIn("billing", o)

    def test_env_file_scalar_rejected(self):
        f = os.path.join(self.d, "script.json")
        with open(f, "w") as fh:
            json.dump("spam", fh)
        rc, o, e = run_cli_env(["run", self.path], {"SIPAR_MODEL": "mock", "SIPAR_MOCK_SCRIPT": f})
        self.assertNotEqual(rc, 0)
        self.assertIn("SIPAR_MOCK_SCRIPT", e)
        self.assertIn("a JSON list of replies or an object", e)

    def test_null_reply_is_a_reply(self):
        e = self.err("count", "x", mock_script=[None])
        self.assertEqual(e.kind, "ai")
        self.assertIn("rejected", e.message)

    def test_agent_script_runs_out(self):
        e = self.err("ag", "x", mock_script={"ag": [{"tool": "add", "args": {"a": 1, "b": 2}}]})
        self.assertEqual(e.kind, "ai")
        self.assertIn("no reply left for ag()", e.message)

    def test_agent_bad_final_named(self):
        e = self.err("ag", "x", mock_script={"ag": [{"final": "five"}]})
        self.assertIn("no reply left for ag()", e.message)
        self.assertIn("rejected: Your final answer is invalid", e.message)

    def test_used_up_sends_no_request(self):
        from sipar.runtime.providers import MockProvider
        m = MockProvider([])
        with self.assertRaises(SiparRuntimeError) as c:
            m.complete([{"role": "user", "content": "q"}], "m", 0.0, 5, {"fn": "classify"})
        self.assertTrue(c.exception.no_request)          # nothing was sent: no charge, the next model is tried


def run_cli_env(argv, env):
    from sipar.cli import main as cli_main
    out, err = io.StringIO(), io.StringIO()
    clean = {k: v for k, v in os.environ.items() if not k.startswith("SIPAR_")}
    clean.update(env)
    with mock.patch.dict(os.environ, clean, clear=True):
        rc = cli_main(list(argv), out, err)
    return rc, out.getvalue(), err.getvalue()


def _gitignore_rules(root):
    rules = []
    with open(os.path.join(root, ".gitignore"), encoding="utf-8") as f:
        for line in f:
            p = line.rstrip("\n").strip()
            if not p or p.startswith("#"):
                continue
            neg = p.startswith("!")
            p = p[1:] if neg else p
            dir_only = p.endswith("/")
            core = p.strip("/")
            rules.append((neg, dir_only, "/" in core, core))
    return rules


def _ignored(rules, rel, is_dir):
    """A small .gitignore matcher (enough for this repository's patterns): last match wins; a file under an
    ignored directory stays ignored (git cannot re-include it)."""
    import fnmatch
    parts = rel.split("/")
    for i in range(1, len(parts)):
        if _ignored(rules, "/".join(parts[:i]), True):
            return True
    hit = False
    for neg, dir_only, anchored, core in rules:
        if dir_only and not is_dir:
            continue
        if fnmatch.fnmatchcase(rel if anchored else parts[-1], core):
            hit = not neg
    return hit


def _clone_like_copy(dst):
    """Copy what a clone of the committed tree holds: every file of examples/ that .gitignore does not hide."""
    import shutil
    rules = _gitignore_rules(ROOT)
    n = 0
    for d, dirs, files in os.walk(os.path.join(ROOT, "examples")):
        reld = os.path.relpath(d, ROOT).replace(os.sep, "/")
        dirs[:] = [x for x in dirs if not _ignored(rules, f"{reld}/{x}", True)]
        for f in files:
            rel = f"{reld}/{f}"
            if not _ignored(rules, rel, False):
                os.makedirs(os.path.join(dst, reld), exist_ok=True)
                shutil.copy(os.path.join(ROOT, rel), os.path.join(dst, rel))
                n += 1
    return n


class T_M4(unittest.TestCase):
    """M4: the README quick start works on a fresh clone (examples/out was gitignored, so it did not exist)."""

    def clone_like_copy(self, dst):
        return _clone_like_copy(dst)

    def test_out_dir_is_kept_in_git(self):
        self.assertTrue(os.path.isfile(os.path.join(ROOT, "examples", "out", ".gitkeep")))
        rules = _gitignore_rules(ROOT)
        self.assertFalse(_ignored(rules, "examples/out/.gitkeep", False))
        self.assertTrue(_ignored(rules, "examples/out/billing.txt", False))      # run output stays out of git

    def test_matcher_agrees_with_git(self):            # coverage: keeps the small matcher honest
        import shutil
        if not shutil.which("git") or not os.path.exists(os.path.join(ROOT, ".git")):
            self.skipTest("no git checkout")
        paths = ["examples/out/.gitkeep", "examples/out/billing.txt", "examples/triage.sipar",
                 "examples/.sipar/x.jsonl", "examples/mcp/reader.sipar", "x/__pycache__/a.pyc", "a.vsix"]
        for rel in paths:
            r = subprocess.run(["git", "-C", ROOT, "check-ignore", "--no-index", "-q", rel], capture_output=True)
            with self.subTest(rel=rel):
                self.assertEqual(_ignored(_gitignore_rules(ROOT), rel, False), r.returncode == 0)

    def test_quick_start_on_a_fresh_copy(self):
        import shutil
        dst = tempfile.mkdtemp(prefix="sipar_m4_")
        self.addCleanup(shutil.rmtree, dst, True)
        self.assertGreater(self.clone_like_copy(dst), 5)
        env = {k: v for k, v in os.environ.items() if not k.startswith("SIPAR_")}
        env["PYTHONPATH"] = ROOT
        for args, extra in ((["check", "examples/triage.sipar"], {}), (["test", "examples/triage.sipar"], {}),
                            (["run", "examples/triage.sipar"], {"SIPAR_MODEL": "mock"})):
            with self.subTest(args=args):
                p = subprocess.run([sys.executable, "-m", "sipar", *args], cwd=dst, env={**env, **extra},
                                   capture_output=True, text=True, timeout=60)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertNotIn("Traceback", p.stderr)
        self.assertTrue(os.listdir(os.path.join(dst, "examples", "out")))


class T_L10(unittest.TestCase):
    """L10: the injection example's header gives the full command, and that command shows the block."""

    def test_header_command_runs(self):
        import shlex
        with open(os.path.join(ROOT, "examples", "injection", "assistant.sipar"), encoding="utf-8") as f:
            head = [ln[2:].strip() for ln in f.read().splitlines() if ln.startswith("//")]
        cmd = [ln for ln in head if "sipar run" in ln]
        self.assertEqual(len(cmd), 1, head)
        words = shlex.split(cmd[0])
        env = {k: v for k, v in os.environ.items() if not k.startswith("SIPAR_")}
        while "=" in words[0]:
            k, v = words.pop(0).split("=", 1)
            env[k] = v
        self.assertEqual(env.get("SIPAR_MODEL"), "mock")
        self.assertIn("SIPAR_MOCK_SCRIPT", env)
        self.assertEqual(words[:2], ["sipar", "run"])
        env["PYTHONPATH"] = ROOT
        import shutil
        dst = tempfile.mkdtemp(prefix="sipar_l10_")         # a copy: the run writes its journal next to the program
        self.addCleanup(shutil.rmtree, dst, True)
        _clone_like_copy(dst)
        p = subprocess.run([sys.executable, "-m", "sipar", *words[1:]], cwd=dst, env=env, capture_output=True,
                           text=True, timeout=60)
        self.assertIn("BLOCKED (taint)", p.stdout + p.stderr)
        self.assertIn("shell.run(cmd)", p.stdout + p.stderr)


class T_L9(unittest.TestCase):
    """L9: bin/sipar works through a symlink (absolute, relative, a chain, a path with spaces)."""

    def setUp(self):
        import shutil
        self.d = os.path.realpath(tempfile.mkdtemp(prefix="sipar l9 "))
        self.addCleanup(shutil.rmtree, self.d, True)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("SIPAR_") and k != "PYTHONPATH"}
        self.env["PATH"] = os.path.dirname(sys.executable) + os.pathsep + self.env.get("PATH", "")
        self.real = os.path.join(ROOT, "bin", "sipar")

    def run_it(self, path):
        return subprocess.run([path, "check", os.path.join(ROOT, "examples", "triage.sipar")], cwd=self.d,
                              env=self.env, capture_output=True, text=True, timeout=30)

    def test_direct(self):                               # guard
        p = self.run_it(self.real)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("triage.sipar: ok", p.stdout)

    def test_absolute_symlink(self):
        link = os.path.join(self.d, "sipar")
        os.symlink(self.real, link)
        p = self.run_it(link)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("triage.sipar: ok", p.stdout)

    def test_relative_chain(self):
        os.makedirs(os.path.join(self.d, "a", "b"))
        os.symlink(os.path.relpath(self.real, os.path.join(self.d, "a", "b")), os.path.join(self.d, "a", "b", "s1"))
        os.symlink(os.path.join("b", "s1"), os.path.join(self.d, "a", "s2"))
        os.symlink(os.path.join("a", "s2"), os.path.join(self.d, "s3"))
        p = self.run_it(os.path.join(self.d, "s3"))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("triage.sipar: ok", p.stdout)

    def test_via_path_lookup(self):
        os.makedirs(os.path.join(self.d, "bin dir"))
        os.symlink(self.real, os.path.join(self.d, "bin dir", "sipar"))
        self.env["PATH"] = os.path.join(self.d, "bin dir") + os.pathsep + self.env["PATH"]
        p = subprocess.run(["sipar", "check", os.path.join(ROOT, "examples", "triage.sipar")], cwd=self.d,
                           env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_symlink_loop_ends(self):
        a, b = os.path.join(self.d, "la"), os.path.join(self.d, "lb")
        os.symlink(b, a)
        os.symlink(a, b)
        with open(self.real) as f:
            text = f.read()
        # the launcher's own text with $0 = a link loop: the link walk must stop (40 links), not hang
        p = subprocess.run(["/bin/sh", "-c", text, a, "--help"], capture_output=True, text=True, timeout=20,
                           env=self.env, cwd=self.d)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("No module named sipar", p.stderr)


class T_L11(unittest.TestCase):
    """L11: docs/ERRORS.md said a prompt calling a user function is E305; the checker reports E230."""

    def codes(self, src):
        return sorted({d.code for d in check_source(src, "t.sipar")[1]})

    def test_doc_names_the_code_the_checker_gives(self):
        with open(os.path.join(ROOT, "docs", "ERRORS.md"), encoding="utf-8") as f:
            doc = " ".join(f.read().split())
        prompt = 'allow ai\nai fn f(a: Str) -> Str { "{g()} {a}" }\nfn g() -> Str { "x" }\nfn main() { }\n'
        const = 'fn g() -> Int { 1 }\nlet A = g()\nfn main() { }\n'
        self.assertEqual(self.codes(prompt), ["E230"])
        self.assertEqual(self.codes(const), ["E305"])
        self.assertTrue("calling a user function there is E230" in doc)
        self.assertTrue("A constant calling a user function or using a later constant is E305" in doc)
        self.assertFalse("no calls of user functions (E305)" in doc)


class T_L17(unittest.TestCase):
    """L17: a parameter named like a module (E202) was then checked as the module: E212/E301/E205 cascades."""

    def diags(self, src):
        return [(d.code, d.line) for d in check_source(src, "t.sipar")[1]]

    def test_mcp_param_one_error(self):
        src = ('type M = { call: fn(Str) -> Str }\nfn f(mcp: M) -> Str { mcp.call("x") }\n'
               'fn main() { print(f(M { call: fn(s: Str) -> Str => s })) }\n')
        self.assertEqual(self.diags(src), [("E202", 2)])

    def test_mcp_param_dotted_one_error(self):
        src = ('type S = { read: fn(Str) -> Str }\ntype M = { fs: S }\nfn f(mcp: M) -> Str { mcp.fs.read("x") }\n'
               'fn main() { }\n')
        self.assertEqual(self.diags(src), [("E202", 3)])

    def test_shell_param_one_error(self):
        src = ('type Sh = { run: fn(Str) -> Str }\nfn f(shell: Sh) -> Str { shell.run("ls") }\nfn main() { }\n')
        self.assertEqual(self.diags(src), [("E202", 2)])

    def test_ai_param_one_error(self):
        src = 'allow ai\nai fn f(fs: Str) -> Str { "say {fs}" }\nfn main() { }\n'
        self.assertEqual(self.diags(src), [("E202", 2)])

    def test_param_still_typed(self):                    # the shadowing parameter keeps its type: wrong use found
        src = 'fn f(time: Int) -> Str { time }\nfn main() { }\n'
        self.assertEqual([c for c, _ in self.diags(src)], ["E202", "E210"])

    def test_let_module_name_guard(self):                # guard: `let` already bound the name
        src = 'type Sh = { run: fn(Str) -> Str }\nfn main() { let shell = Sh { run: fn(s: Str) -> Str => s }\n' \
              '  print(shell.run("ls")) }\n'
        self.assertEqual(self.diags(src), [("E202", 2)])

    def test_real_module_call_still_checked(self):       # guard: no parameter named mcp -> module rules apply
        src = 'fn f() -> Str { mcp.call("x") }\nfn main() { }\n'
        self.assertEqual(sorted({c for c, _ in self.diags(src)}), ["E205", "E212", "E301"])


class T_L18(unittest.TestCase):
    """L18: README.ru.md said nothing of MCP, LSP or VS Code."""

    def read(self, name):
        with open(os.path.join(ROOT, name), encoding="utf-8") as f:
            return f.read()

    def test_readme_ru_names_mcp_lsp_vscode(self):
        ru = self.read("README.ru.md")
        for word in ("allow mcp", "untrusted:mcp:", "sipar lsp", "editors/vscode/", "sipar.path", "SPEC.md §7a"):
            self.assertIn(word, ru)
        for path in ("examples/mcp", "editors/vscode/README.md", "bin/sipar"):
            self.assertTrue(os.path.exists(os.path.join(ROOT, path)), path)


class T_MutGaps(Base):
    """Mutation gaps the CLI critic found (deep.py #12/#29, errors.py #18/#40, mcp_check.py #76/#208)."""

    SRC = ('allow secret ["K"]\nfn hello(x: Str) -> Str { x }\n'
           'fn outer() -> Int uses secret {\n  print("tick")\n  let s = env.secret("K")\n  0\n}\n')

    def prog(self):
        import sipar
        path = os.path.join(self.dir, "p.sipar")
        with open(path, "w") as f:
            f.write(self.SRC)
        return sipar.load(path)

    def test_reentrant_call_from_out_writer(self):      # deep #12: a nested call_deep must run fn, not skip it
        prog, got = self.prog(), []

        class W:
            def write(self, s):
                if s.strip():
                    got.append(prog.call("hello", "inner", out=io.StringIO()))

        with mock.patch.dict(os.environ, {"K": "abc-123-zzz"}):
            self.assertEqual(prog.call("outer", out=W()), 0)
        self.assertEqual(got, ["inner"])

    def test_nested_registry_is_restored(self):         # errors #18: the inner run must not leave its registry
        from sipar.errors import DEFAULT
        prog = self.prog()

        class W:
            def write(self, s):
                if s.strip():
                    prog.call("hello", "inner", out=io.StringIO())

        with mock.patch.dict(os.environ, {"K": "abc-123-zzz"}):
            prog.call("outer", out=W())
        self.assertNotIn("abc-123-zzz", DEFAULT.secrets)
        self.assertNotIn("abc-123-zzz", DEFAULT.labels)

    def test_use_registry_nesting(self):                 # errors #18, unit form
        from sipar.errors import SecretRegistry, active_registry, use_registry
        a, b = SecretRegistry(), SecretRegistry()
        before = active_registry()
        with use_registry(a):
            with use_registry(b):
                self.assertIs(active_registry(), b)
            self.assertIs(active_registry(), a)
        self.assertIs(active_registry(), before)

    def test_short_secret_not_registered(self):          # errors #40: under 4 chars would redact every "abc"
        from sipar.errors import MIN_SECRET_LEN, SecretRegistry, register_secret, use_registry
        self.assertEqual(MIN_SECRET_LEN, 4)
        reg = SecretRegistry()
        with use_registry(reg):
            register_secret("abc", "secret:K")
            register_secret(1234, "secret:K")
        self.assertEqual((reg.secrets, reg.labels), ({}, {}))
        with use_registry(reg):
            register_secret("abcd", "secret:K")
        self.assertEqual(reg.secrets.get("abcd"), "«secret:K»")

    def test_call_deep_uses_a_worker(self):              # deep #29: not on the caller's own (smaller) stack
        from sipar.deep import call_deep
        self.assertEqual(call_deep(lambda: threading.current_thread().name), "sipar-run")

    def test_mcp_allow_without_command(self):            # mcp_check #76
        d = check_source('allow mcp "fs" tools ["read_text_file"]\nfn main() { }\n', "t.sipar")[1]
        self.assertEqual(len(d), 1)
        self.assertIn("needs the command that starts the server, as a list of strings", d[0].message)

    def test_mcp_unknown_tool_hint(self):                # mcp_check #208: no similar name -> how to add it
        src = ('allow mcp "fs" ["python3", "s.py"] tools ["read_text_file"]\n'
               'fn f() -> Str uses mcp { mcp.fs.zzzzqq(path: "a") }\nfn main() { }\n')
        d = [x for x in check_source(src, "t.sipar")[1] if x.code == "E205"]
        self.assertEqual(len(d), 1)
        self.assertEqual(d[0].hint, 'add it to the line: tools ["zzzzqq"]')


class T_BigStack(Base):
    """deep #1/#32: the worker's own big stack. A host that set a small default thread stack (256 KiB) must
    still run an 18,000-level value. On 3.12.8 a 256 KiB worker crashes (SIGBUS) on it; 3.14 does not need
    the stack, so there the test is a guard."""

    SRC = ("type N = { kids: List[N] }\nfn build(n: Int) -> N {\n    var x = N { kids: [] }\n    var i = 0\n"
           "    while i < n { x = N { kids: [x] }; i = i + 1 }\n    x\n}\n"
           "fn main(args: List[Str]) {\n    let x = build(args[0] as Int)\n    let y = build(args[0] as Int)\n"
           "    print(x == y)\n    print(json.encode(x).len())\n    print(\"{x}\".len())\n"
           "    print((json.encode(x) as N) == x)\n}\n")
    CHILD = ("import sys, threading\nsys.path.insert(0, sys.argv[1])\nthreading.stack_size(1 << 18)\n"
             "from sipar.cli import main\nsys.exit(main(['run', sys.argv[2], '9000'], sys.stdout, sys.stderr))\n")

    def test_small_host_stack(self):
        path = os.path.join(self.dir, "v.sipar")
        with open(path, "w") as f:
            f.write(self.SRC)
        env = {k: v for k, v in os.environ.items() if not k.startswith("SIPAR_") and k != "PYTHONPATH"}
        p = subprocess.run([sys.executable, "-c", self.CHILD, ROOT, path], capture_output=True, text=True,
                           timeout=300, env=env, cwd=self.dir)
        self.assertEqual(p.returncode, 0, p.stderr[-500:])
        self.assertEqual(p.stdout.split(), ["true", "108012", "108012", "true"])


LSEPS = "a\u2028b\u2029c\u0085d"          # U+2028, U+2029, U+0085: str.splitlines() breaks a line on each


class T_F1(unittest.TestCase):
    """F1: a value holding U+2028/U+2029/U+0085 broke replay and trace ("line 1 is not valid JSON")."""

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="sipar_f1_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.d, ignore_errors=True)

    def journal(self, value):
        path = os.path.join(self.d, "j.jsonl")
        j = Journal(path)
        j.effect("fs.read", {"path": "d.txt"}, lambda: value)
        j.close()
        return path

    def test_written_escaped_and_read_back(self):
        path = self.journal(LSEPS)
        with open(path, "rb") as f:
            raw = f.read()
        for ch in ("\u2028", "\u2029", "\u0085"):
            self.assertNotIn(ch.encode("utf-8"), raw)
        self.assertEqual(raw.count(b"\n"), 1)
        self.assertEqual([e["response"] for e in Journal.load(path)], [LSEPS])

    def test_old_journal_with_raw_separators_loads(self):  # a journal written before the fix
        path = os.path.join(self.d, "old.jsonl")
        e = {"seq": 1, "kind": "fs.read", "request": {"path": "d.txt"}, "response": LSEPS, "labels": []}
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
        self.assertEqual([x["response"] for x in Journal.load(path)], [LSEPS])
        from sipar.trace import read_entries
        with open(path, encoding="utf-8") as f:
            self.assertEqual([x["response"] for x in read_entries(f.read())], [LSEPS])

    def test_crlf_journal_still_loads(self):                 # guard: a journal saved with CRLF line ends
        path = os.path.join(self.d, "crlf.jsonl")
        e = {"seq": 1, "kind": "fs.read", "request": {"path": "d.txt"}, "response": "x", "labels": []}
        with open(path, "wb") as f:
            f.write((json.dumps(e) + "\r\n").encode() * 2)
        self.assertEqual(len(Journal.load(path)), 2)

    def test_run_replay_trace_end_to_end(self):
        with open(os.path.join(self.d, "d.txt"), "w", encoding="utf-8") as f:
            f.write(LSEPS)
        prog = os.path.join(self.d, "p.sipar")
        with open(prog, "w", encoding="utf-8") as f:
            f.write('allow fs.read ["./d.txt"]\nfn main() uses fs.read {\n    print(fs.read("d.txt").len())\n}\n')
        rc, out, err = cli("run", prog)
        self.assertEqual((rc, out, err), (0, "7\n", ""))
        runs = os.path.join(self.d, ".sipar", "runs")
        jpath = os.path.join(runs, os.listdir(runs)[0])
        rc, out, err = cli("replay", prog, jpath)
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(out, "7\n")
        rc, out, err = cli("trace", jpath)
        self.assertEqual((rc, err), (0, ""))
        self.assertIn("fs.read", out)

    def test_line_helper(self):
        from sipar.runtime import jsondeep
        s = jsondeep.dumps_line({"k": LSEPS, "x": [1, "\u2028"]})
        self.assertEqual(s, '{"k": "a\\u2028b\\u2029c\\u0085d", "x": [1, "\\u2028"]}')
        self.assertEqual(json.loads(s), {"k": LSEPS, "x": [1, "\u2028"]})
        self.assertEqual(jsondeep.dumps_line({"k": "é"}), '{"k": "é"}')       # other text stays as it is

    def test_mcp_request_line_has_no_raw_separators(self):
        b = MCP.encode_message({"jsonrpc": "2.0", "id": 1, "params": {"arguments": {"q": LSEPS}}})
        self.assertTrue(b.endswith(b"\n"))
        self.assertEqual(b.count(b"\n"), 1)
        for ch in ("\u2028", "\u2029", "\u0085"):
            self.assertNotIn(ch.encode("utf-8"), b)
        self.assertEqual(json.loads(b)["params"]["arguments"]["q"], LSEPS)


class T_F2(unittest.TestCase):
    """F2: `xs.push(i); xs.len()` (and index / map / field writes) in a loop was quadratic: every write dropped
    the whole labels cache, so the next len() walked the whole list again. Labels must stay exact."""
    HEAD, USES, out, labelled = T_Lmemo.HEAD, T_Lmemo.USES, T_Lmemo.out, T_Lmemo.labelled

    def test_push_len_loop_is_fast(self):
        src = ('type R = { n: Int }\nfn main() {\n    var xs: List[R] = []\n    var m: Map[Int] = [:]\n'
               '    var t = 0\n    var i = 0\n    while i < 15000 {\n'
               '        xs.push(R { n: i }); xs[i].n = i + 1; xs[i] = R { n: i }; m["k{i}"] = i\n'
               '        t = t + xs.len() + m.len() + (xs.last() ?? R { n: 0 }).n\n        i = i + 1\n    }\n'
               '    while i > 10000 { i = i - 1; let p = xs.pop(); let r = m.remove("k{i}"); t = t + xs.len() + m.len() }\n'
               '    print(t)\n}\n')
        p = Prog(src)
        self.addCleanup(p.cleanup)
        t0 = time.perf_counter()
        out = p.run()
        took = time.perf_counter() - t0
        self.assertEqual(out, "462502500\n")
        self.assertLess(took, 4.0)               # about 0.4 s now; 20+ s when every write dropped the cache

    def test_pop_keeps_labels_until_the_labelled_item_goes(self):
        body = ('var xs = [u(), "a"]\n' + self.labelled("xs.len()") + 'xs.push("b")\n' + self.labelled("xs.len()")
                + 'let p1 = xs.pop()\n' + self.labelled("xs.len()") + 'let p2 = xs.pop()\n'
                + self.labelled("xs.len()") + 'let p3 = xs.pop()\n' + self.labelled("xs.len()"))
        self.assertEqual(self.out(body), "true\ntrue\ntrue\ntrue\nfalse\n")

    def test_overwrite_with_same_labels(self):
        body = ('var xs = [u(), "a"]\n' + self.labelled("xs.len()") + 'xs[1] = u()\n' + self.labelled("xs.len()")
                + 'xs[0] = "c"\n' + self.labelled("xs.len()") + 'xs[1] = "d"\n' + self.labelled("xs.len()"))
        self.assertEqual(self.out(body), "true\ntrue\ntrue\nfalse\n")

    def test_map_remove_and_labelled_key(self):
        body = ('var m = ["a": "1", "b": "2"]\n' + self.labelled("m.len()") + 'let r1 = m.remove("a")\n'
                + self.labelled("m.len()") + 'm["c"] = u()\n' + self.labelled("m.len()") + 'let r2 = m.remove("c")\n'
                + self.labelled("m.len()") + 'm[u()] = "x"\n' + self.labelled("m.len()") + 'm["c"] = "y"\n'
                + self.labelled("m.len()"))
        self.assertEqual(self.out(body), "false\nfalse\ntrue\nfalse\ntrue\ntrue\n")

    def test_record_view_write_reaches_the_original(self):   # the view shares the fields of the original
        body = ('var xs = [S { s: "a" }]\n' + self.labelled("xs.len()") + 'let i = u().len() * 0\n'
                'let t = xs[i]\n' + self.labelled("xs.len()") + 't.s = "plain"\n' + self.labelled("xs[0].s")
                + self.labelled("xs.len()"))
        self.assertEqual(self.out(body, head="type S = { s: Str }\n"), "false\nfalse\ntrue\ntrue\n")

    def test_mutated_rules(self):                               # unit: when the cache is kept
        from sipar.runtime import values as V
        U = frozenset({"untrusted:x"})

        def keeps(container, added, dropped=()):
            before = V._EPOCH[0]
            V.mutated(container, added, dropped)
            return V._EPOCH[0] == before

        V.mutated()
        plain, own = ["a"], V.LList(["a"], U)
        self.assertTrue(keeps(plain, V.EMPTY))                  # no cache needed: nothing new
        self.assertFalse(keeps(plain, U))                       # not cached: unknown
        V.labels_of(plain)
        self.assertFalse(keeps(plain, U))                       # cached, but U is new
        self.assertTrue(keeps(own, U))                          # inside its own labels
        lab = [V.with_labels("x", U)]
        V.labels_of(lab)
        self.assertTrue(keeps(lab, U))                          # inside its cached labels
        self.assertFalse(keeps(lab, V.EMPTY, (V.with_labels("y", U),)))   # a labelled item went
        self.assertTrue(keeps(lab, V.EMPTY, ("y",)))
        m = {"a": "1"}
        self.assertFalse(keeps(m, V.EMPTY, None))               # removed key not known, no cache
        V.labels_of(m)
        self.assertTrue(keeps(m, V.EMPTY, None))                # nothing inside was labelled
        lm = {"a": V.with_labels("1", U)}
        V.labels_of(lm)
        self.assertFalse(keeps(lm, V.EMPTY, None))
        rec = V.LRecord("S", {"s": "a"}, U)
        V.labels_of(rec)
        self.assertFalse(keeps(rec, U))                         # a record view: never by its own labels
        self.assertTrue(keeps(rec, V.EMPTY, ("b",)))
        self.assertFalse(keeps(None, None) or keeps(plain, None))   # a plain call always drops the cache


class _Lazy:
    """A byte stream made of segments: bytes, or an int n meaning n bytes of b"a" (never built in one piece).
    Like a real pipe, it refuses one read or readline of more than CAP bytes (MemoryError)."""
    CAP = 128 * 1024 * 1024

    def __init__(self, *segments):
        self.segs = [s for s in segments]
        self.reads = []

    def _take(self, n, stop_at_newline):
        out = []
        size = 0
        while self.segs and (n < 0 or size < n):
            seg = self.segs[0]
            want = -1 if n < 0 else n - size
            if isinstance(seg, int):
                k = seg if want < 0 else min(seg, want)
                if size + k > self.CAP:
                    raise MemoryError("a read of more than 128 MiB")
                out.append(b"a" * k)
                size += k
                if seg - k:
                    self.segs[0] = seg - k
                else:
                    self.segs.pop(0)
                continue
            k = len(seg) if want < 0 else min(len(seg), want)
            if stop_at_newline and b"\n" in seg[:k]:
                k = seg.index(b"\n") + 1
            out.append(seg[:k])
            size += k
            if seg[k:]:
                self.segs[0] = seg[k:]
            else:
                self.segs.pop(0)
            if stop_at_newline and out[-1].endswith(b"\n"):
                break
        return b"".join(out)

    def read(self, n=-1):
        if n > self.CAP:
            raise MemoryError("a read of more than 128 MiB")
        self.reads.append(n)
        return self._take(n, False)

    def readline(self, limit=-1):
        return self._take(limit, True)


def _frame(obj):
    body = json.dumps(obj).encode()
    return b"Content-Length: %d\r\n\r\n" % len(body) + body


class T_F5(unittest.TestCase):
    """F5: a frame with a huge Content-Length made read_message ask for the whole body at once (MemoryError,
    the server died). Over 64 MiB the body is now read past in 1 MiB chunks and skipped with a log line.
    Also: an endless header line is read in bounded pieces; Content-Length takes ASCII digits only."""

    INIT = {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}
    PING = {"jsonrpc": "2.0", "id": 9, "method": "shutdown"}

    def serve(self, stream):
        from sipar import lsp
        out, err = io.BytesIO(), io.StringIO()
        code = lsp.serve(stream, out, err)
        ids = [json.loads(m).get("id") for m in re.split(rb"Content-Length: \d+\r\n\r\n", out.getvalue()) if m]
        return code, ids, err.getvalue()

    def test_huge_body_is_skipped_and_the_server_goes_on(self):
        n = 200 * 1024 * 1024
        s = _Lazy(_frame(self.INIT), b"Content-Length: %d\r\n\r\n" % n, n, _frame(self.PING))
        code, ids, err = self.serve(s)
        self.assertEqual(ids, [0, 9])                       # the request after the big frame is answered
        self.assertIn("skipped a message larger than 67108864 bytes", err)
        self.assertNotIn("Traceback", err)
        self.assertLessEqual(max(s.reads), 1024 * 1024)

    def test_huge_length_at_end_of_input_exits(self):
        s = _Lazy(_frame(self.INIT), b"Content-Length: 99999999999999\r\n\r\n{}")
        code, ids, err = self.serve(s)
        self.assertEqual((code, ids), (1, [0]))
        self.assertNotIn("Traceback", err)

    def test_body_at_the_cap_is_read(self):                    # *guard*
        from sipar import lsp
        body = b" " * (lsp.MAX_BODY - 2) + b"{}"
        self.assertEqual(lsp.read_message(io.BytesIO(b"Content-Length: %d\r\n\r\n" % len(body) + body)), body)

    def test_endless_header_line(self):
        n = 200 * 1024 * 1024
        s = _Lazy(b"X-Junk: ", n, b"\r\n", _frame(self.INIT), _frame(self.PING))
        code, ids, err = self.serve(s)
        self.assertEqual(ids, [0, 9])
        from sipar import lsp
        s = _Lazy(b"X-Junk: ", n)                            # and it ends without a newline
        self.assertIsNone(lsp.read_message(s))

    def test_content_length_digits_only(self):
        from sipar import lsp
        for bad in [b"1_7", b"+2", b"-2", b"2.0", b"0x2", b"\xd9\xa2", b"", b"2 2"]:
            got = lsp.read_message(io.BytesIO(b"Content-Length: " + bad + b"\r\n\r\n{}"))
            self.assertEqual(got, b"", bad)
            self.assertEqual(got.reason, "skipped a message without a valid Content-Length header")
        self.assertEqual(lsp.read_message(io.BytesIO(b"Content-Length:  2 \r\n\r\n{}")), b"{}")   # *guard*
        self.assertEqual(lsp.read_message(io.BytesIO(b"Content-Length: 0002\r\n\r\n{}")), b"{}")
        long = b"9" * 5000                                   # int() refuses it: over the cap, not a crash
        s = _Lazy(b"Content-Length: " + long + b"\r\n\r\n", 3 * 1024 * 1024)
        self.assertIsNone(lsp.read_message(s))
        self.assertLessEqual(max(s.reads), 1024 * 1024)
        code, ids, err = self.serve(io.BytesIO(b"Content-Length: 1_7\r\n\r\n" + _frame(self.INIT)))
        self.assertIn("without a valid Content-Length", err)


class T_F7(unittest.TestCase):
    """F7: a position whose line or character is not an integer (a string, null, NaN, inf, [], {}, also 1.5
    and true) gave -32603 with a traceback (or was accepted); now -32602. A bad didChange range is an
    invalid-params log line, not a traceback, and leaves the document as it was."""

    URI = "file:///tmp/f7.sipar"
    TEXT = "fn main() {\n    let xs = [1]\n    print(xs.len())\n}\n"

    def setUp(self):
        from sipar import lsp
        self.srv = lsp.Server(io.BytesIO(), io.StringIO())
        self.srv.handle({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}})
        self.open()

    def open(self):
        self.srv.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen",
                         "params": {"textDocument": {"uri": self.URI, "text": self.TEXT, "version": 1}}})

    def call(self, method, params, notify=False):
        self.srv.out, self.srv.err = io.BytesIO(), io.StringIO()
        msg = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notify:
            msg["id"] = 7
        self.srv.handle(msg)
        raw = self.srv.out.getvalue()
        replies = [json.loads(m) for m in re.split(rb"Content-Length: \d+\r\n\r\n", raw) if m]
        return [r for r in replies if r.get("id") == 7], self.srv.err.getvalue()

    def test_bad_position_types(self):
        bad = ["x", None, 1.5, True, False, float("nan"), float("inf"), [], {}, [1], "1"]
        for m in ["textDocument/hover", "textDocument/definition", "textDocument/completion"]:
            for key in ["line", "character"]:
                for v in bad:
                    pos = {"line": 2, "character": 12}
                    pos[key] = v
                    replies, err = self.call(m, {"textDocument": {"uri": self.URI}, "position": pos})
                    self.assertEqual(replies[0]["error"]["code"], -32602, (m, key, v))
                    self.assertIn(f"position.{key} must be an integer", replies[0]["error"]["message"])
                    self.assertNotIn("Traceback", err)

    def test_good_positions_still_work(self):                  # *guard*
        for pos in [{"line": 2, "character": 12}, {"line": -1, "character": -5}, {"line": 10 ** 30, "character": 0},
                    {"line": 2, "character": 10 ** 30}]:          # round 7: {} is an error now (T7_L6)
            replies, err = self.call("textDocument/hover", {"textDocument": {"uri": self.URI}, "position": pos})
            self.assertNotIn("error", replies[0], pos)
        replies, _ = self.call("textDocument/hover", {"textDocument": {"uri": self.URI},
                                                       "position": {"line": 2, "character": 13}})
        self.assertIn("len", json.dumps(replies[0]["result"]))

    def test_bad_did_change(self):
        rng = lambda start, end: {"start": start, "end": end}                      # noqa: E731
        p0 = {"line": 0, "character": 0}
        bad = [rng({"line": "x", "character": 0}, p0), rng({"line": None, "character": 0}, p0),
               rng(p0, {"line": 0, "character": 1.5}), rng(p0, {"line": True, "character": 0}),
               rng({"line": float("nan"), "character": 0}, p0), "x", 1, [], {"start": 1}, {}, {"start": p0},
               rng([], p0)]
        for r in bad:
            _, err = self.call("textDocument/didChange",
                               {"textDocument": {"uri": self.URI, "version": 2},
                                "contentChanges": [{"text": "ok"}, {"range": r, "text": "zz"}]}, notify=True)
            self.assertIn("invalid params", err, r)
            self.assertNotIn("Traceback", err)
            self.assertEqual(self.srv.docs[self.URI].text, self.TEXT)     # nothing applied
        _, err = self.call("textDocument/didChange",
                           {"textDocument": {"uri": self.URI, "version": 2},
                            "contentChanges": [{"range": rng(p0, {"line": 0, "character": 2}), "text": "FN"}]},
                           notify=True)
        self.assertEqual(self.srv.docs[self.URI].text, "FN" + self.TEXT[2:])   # *guard*: a good range

    def test_uri_not_a_string(self):
        for uri in [["a"], {"a": 1}, 5, None]:
            for m in ["textDocument/documentSymbol", "textDocument/hover"]:
                replies, err = self.call(m, {"textDocument": {"uri": uri}, "position": {"line": 0, "character": 0}})
                self.assertEqual(replies[0]["error"]["code"], -32602, (m, uri))
                self.assertNotIn("Traceback", err)
            for m in ["textDocument/didChange", "textDocument/didClose"]:
                _, err = self.call(m, {"textDocument": {"uri": uri}, "contentChanges": []}, notify=True)
                self.assertIn("invalid params", err, (m, uri))
                self.assertNotIn("Traceback", err)


class T_F8(unittest.TestCase):
    """F8: in a file with CR-only line endings the lexer saw one line while the LSP (as the LSP spec says)
    counted \\r as a line break, so diagnostics and hover were wrong. A lone \\r is now a line break for the
    lexer, the LSP and error snippets (as for Python's universal newlines, used when sipar reads a file)."""

    SRC = "fn main() {\n    let x = 1\n    print(y)\n}\n"

    def diags_and_hover(self, text):
        from sipar import lsp
        srv = lsp.Server(io.BytesIO(), io.StringIO())
        srv.handle({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}})
        srv.out = io.BytesIO()
        srv.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen",
                    "params": {"textDocument": {"uri": "file:///tmp/f8.sipar", "text": text, "version": 1}}})
        srv.handle({"jsonrpc": "2.0", "id": 5, "method": "textDocument/hover",
                    "params": {"textDocument": {"uri": "file:///tmp/f8.sipar"}, "position": {"line": 1, "character": 9}}})
        msgs = [json.loads(m) for m in re.split(rb"Content-Length: \d+\r\n\r\n", srv.out.getvalue()) if m]
        diags = [m for m in msgs if m.get("method") == "textDocument/publishDiagnostics"][0]["params"]["diagnostics"]
        hover = [m for m in msgs if m.get("id") == 5][0]["result"]
        return [(d["range"], d["message"].split("\n")[0]) for d in diags], hover

    def test_cr_only_file_in_the_lsp(self):
        want = self.diags_and_hover(self.SRC)
        self.assertEqual(want[0][0][0]["start"], {"line": 2, "character": 10})
        self.assertIsNotNone(want[1])
        self.assertEqual(self.diags_and_hover(self.SRC.replace("\n", "\r\n")), want)     # *guard*
        self.assertEqual(self.diags_and_hover(self.SRC.replace("\n", "\r")), want)

    def test_lexer_and_lsp_agree_on_mixed_endings(self):
        from sipar import lsp
        from sipar.lexer import Lexer
        text = "let a = 1\rlet b = 2\r\r\nlet c = 3\n\rlet d = 4"
        toks = [t for t in Lexer(text).tokenize() if getattr(t, "value", None) in ("a", "b", "c", "d")]
        starts = lsp.line_starts(text)
        self.assertEqual([t.line - 1 for t in toks], [0, 1, 3, 5])
        self.assertEqual(len(starts), 6)
        self.assertEqual(len(lsp.split_lines(text)), 6)

    def test_check_and_error_snippet(self):
        errs = check_source(self.SRC.replace("\n", "\r"), "f8.sipar")[1]
        self.assertEqual([(e.line, e.col) for e in errs], [(3, 11)])
        self.assertIn("    print(y)", errs[0].render(self.SRC.replace("\n", "\r")))


class T_F6(unittest.TestCase):
    """F6: every memory.save rewrote the whole store file (and every load re-read it), so N saves cost N².
    Now a store over SMALL_STORE bytes takes later writes in an append-only log that is folded in when it
    outgrows the store file, and the parsed store is kept between calls. Atomicity, locking and labels stay."""

    def setUp(self):
        from sipar.runtime import memory as MEM
        self.MEM = MEM
        self.d = tempfile.mkdtemp(prefix="sipar_f6_")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))
        self.p = os.path.join(self.d, "m.json")

    def big(self, n=0):             # every write goes to the log (the store file is "big" at once)
        return mock.patch.object(self.MEM, "SMALL_STORE", n)

    def seed(self):                 # a 5 KB store file: a few log lines stay below it (no compaction)
        with self.big(10 ** 9):
            self.MEM.FileStore(self.p).put("seed", {"value": "x" * 5000, "labels": [], "enc": 2})

    def entry(self, i):
        return {"value": i, "labels": [], "enc": 2}

    def prog(self, src):                          # a real program file, run through the CLI (with the checker)
        path = os.path.join(self.d, "prog.sipar")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(src)
        return path

    def test_many_saves_and_loads_are_fast(self):
        path = self.prog('allow memory\nfn main() uses memory {\n    for i in 0..4000 { memory.save("k{i}", i) }\n'
                         '    var t = 0\n    for k in memory.keys() { let v: Int? = memory.load(k)\n'
                         '        t = t + (v ?? 0) }\n    print(t)\n}\n')
        t0 = time.perf_counter()
        got = cli("run", path)
        took = time.perf_counter() - t0
        self.assertEqual(got, (0, "7998000\n", ""))
        self.assertLess(took, 12.0)                # about 2 s alone, 6 s under a parallel full run; 21 s when every save rewrote the store

    def test_full_rewrites_are_few(self):
        calls = []
        real = self.MEM.dump_store
        with self.big(), mock.patch.object(self.MEM, "dump_store", side_effect=lambda *a: calls.append(1) or real(*a)):
            s = self.MEM.FileStore(self.p)
            for i in range(2000):
                s.put(f"k{i}", self.entry(i))
        self.assertLess(len(calls), 40)            # about log2(N) compactions, not one rewrite per save
        fresh = self.MEM.FileStore(self.p)
        self.assertEqual(len(fresh.keys()), 2000)
        self.assertEqual(fresh.get("k1999"), self.entry(1999))

    def test_log_round_trip_with_labels_and_deletes(self):
        lab = {"value": ["a", "x\u2028y"], "labels": [[[1], ["untrusted:ai:u"]]], "enc": 2}
        self.seed()                                 # a big store file first, then log only (no compaction)
        with self.big(0):
            s = self.MEM.FileStore(self.p)
            s.put("a", lab)
            s.put("b", self.entry(2))
            self.assertEqual((s.delete("b"), s.delete("b"), s.delete("zz")), (True, False, False))
            s.put("c", self.entry(3))
            self.assertTrue(os.path.exists(self.p + ".log"))
            with open(self.p + ".log", encoding="utf-8") as fh:
                log = fh.read()
            self.assertNotIn("\u2028", log)
            self.assertEqual(log.count("\n"), 5)            # header, a, b, delete b, c; none for a no-op delete
            self.assertEqual(set(json.loads(log.split("\n")[0])), {"g"})     # round 7: the store's gen
            other = self.MEM.FileStore(self.p)              # another process reads store file + log
            self.assertEqual(other.keys(), ["a", "c", "seed"])
            self.assertEqual(other.get("a"), lab)
            got = other.get("a")
            got["value"].append("changed")                  # the caller's copy, not the cache
            self.assertEqual(other.get("a"), lab)
            s.put("d", self.entry(4))                       # written by s: other sees it on its next read
            self.assertEqual(other.keys(), ["a", "c", "d", "seed"])
            other.delete("a")
            self.assertIsNone(s.get("a"))

    def test_torn_last_line_is_ignored_then_cut(self):
        self.seed()
        with self.big(0):
            s = self.MEM.FileStore(self.p)
            s.put("a", self.entry(1))
            with open(self.p + ".log", "ab") as fh:
                fh.write(b'{"k": "b", "e": {"val')               # a crash in the middle of a write
            self.assertEqual(self.MEM.FileStore(self.p).keys(), ["a", "seed"])
            s2 = self.MEM.FileStore(self.p)
            s2.put("c", self.entry(3))
            with open(self.p + ".log", encoding="utf-8") as fh:
                lines = fh.read().split("\n")
            self.assertEqual(set(json.loads(lines[0])), {"g"})            # round 7: the header line first
            self.assertEqual([json.loads(x)["k"] for x in lines[1:] if x], ["a", "c"])
            self.assertEqual(self.MEM.FileStore(self.p).keys(), ["a", "c", "seed"])

    def test_bad_log_is_an_io_error_and_kept(self):
        self.seed()
        log = self.p + ".log"
        for bad in [b"{x\n", b"[1]\n", b'{"k": 1, "e": {}}\n', b'{"k": "a"}\n', b'{"k": "a", "d": 2}\n',
                    b'{"k": "a", "e": "\\ud800"}\n', b"\xff\n", b"[" * 100000 + b"]" * 100000 + b"\n"]:
            with open(log, "wb") as fh:
                fh.write(bad)
            with self.big(0):
                for f in (lambda s: s.keys(), lambda s: s.put("z", self.entry(9))):
                    with self.assertRaises(SiparRuntimeError) as cm:
                        f(self.MEM.FileStore(self.p))
                    self.assertEqual(cm.exception.kind, "io", bad[:20])
                    self.assertIn(f"memory store log {log}", cm.exception.message)
            with open(log, "rb") as fh:
                self.assertEqual(fh.read(), bad)

    def test_old_log_already_folded_in_is_harmless(self):   # a crash between the rename and the log removal
        with self.big(0):
            s = self.MEM.FileStore(self.p)
            for i in range(50):
                s.put(f"k{i}", self.entry(i))
            s.delete("k3")
            with open(self.p + ".log", "rb") as fh:
                pending = fh.read()
            want = s.keys()
            entries = {k: s.get(k) for k in want}
            with open(self.p, "w", encoding="utf-8") as fh:
                fh.write(self.MEM.dump_store(entries))     # the folded store file ...
            with open(self.p + ".log", "wb") as fh:
                fh.write(pending)                           # ... and the log it already holds
            self.assertEqual(self.MEM.FileStore(self.p).keys(), want)
            self.assertNotIn("k3", want)

    def test_failed_append_keeps_the_store_right(self):
        self.seed()
        with self.big(0):
            s = self.MEM.FileStore(self.p)
            s.put("a", self.entry(1))
            with mock.patch("os.fsync", side_effect=OSError(28, "No space left on device")):
                with self.assertRaises(SiparRuntimeError) as cm:
                    s.put("b", self.entry(2))
            self.assertEqual(cm.exception.message, f"cannot write memory store {self.p}: no space left on device")   # R8C-8 (round 8): lowercase
            self.assertEqual(sorted(os.listdir(self.d)), ["m.json", "m.json.lock", "m.json.log"])
            self.assertEqual(self.MEM.FileStore(self.p).keys(), ["a", "seed"])     # the failed line was cut
            self.assertEqual(s.keys(), ["a", "seed"])
            with mock.patch("os.replace", side_effect=OSError(28, "No space left on device")):
                for i in range(150):                        # compactions fail: the saves are still kept
                    s.put(f"c{i}", self.entry(i))
            self.assertEqual(len(self.MEM.FileStore(self.p).keys()), 152)
            s.put("last", self.entry(0))                    # and the next write folds the log in
            self.assertEqual(sorted(os.listdir(self.d)), ["m.json", "m.json.lock"])
            self.assertEqual(len(self.MEM.FileStore(self.p).keys()), 153)

    def test_reads_lock_shared_writes_exclusive(self):
        import fcntl
        with self.big(0), mock.patch("fcntl.flock", wraps=fcntl.flock) as flock:
            s = self.MEM.FileStore(self.p)
            s.put("a", self.entry(1))
            s.get("a")
            s.keys()
        self.assertEqual([c.args[1] for c in flock.call_args_list],
                         [fcntl.LOCK_EX, fcntl.LOCK_UN, fcntl.LOCK_SH, fcntl.LOCK_UN, fcntl.LOCK_SH, fcntl.LOCK_UN])

    def test_read_only_folder_still_reads(self):            # *guard*: no lock file can be made there
        s = self.MEM.FileStore(self.p)
        s.put("a", self.entry(1))
        os.remove(self.p + ".lock")
        os.chmod(self.d, 0o555)
        self.addCleanup(os.chmod, self.d, 0o755)
        self.assertEqual(self.MEM.FileStore(self.p).get("a"), self.entry(1))
        self.assertEqual(self.MEM.FileStore(os.path.join(self.d, "nope", "m.json")).keys(), [])

    def test_labels_survive_a_big_store_across_runs(self):  # e2e: two real runs, the store goes over SMALL_STORE
        path = self.prog(
            'allow memory\nallow ai\nallow fs.write ["./out"]\nai fn u() -> Str { "give" }\n'
            'fn main() uses memory, ai, fs.write {\n    let n = memory.load("n") ?? 0\n'
            '    if n == 0 {\n        for i in 0..600 { memory.save("k{i}", "filler {i}") }\n'
            '        memory.save("u", u())\n        memory.save("p", "plain")\n        memory.save("n", 1)\n'
            '        print("saved")\n    } else {\n        let a = memory.load("u") ?? ""\n'
            '        let b = memory.load("p") ?? ""\n'
            '        try { fs.write("out/a.txt", a)\n print("clean") } catch e { print(e.kind) }\n'
            '        try { fs.write("out/b.txt", b)\n print("clean") } catch e { print(e.kind) }\n    }\n}\n')
        os.makedirs(os.path.join(self.d, "out"))
        script = os.path.join(self.d, "script.json")
        with open(script, "w", encoding="utf-8") as fh:
            json.dump({"u": ["evil"]}, fh)
        env = {"SIPAR_MODEL": "mock", "SIPAR_MOCK_SCRIPT": script}
        self.assertEqual(run_cli_env(["run", path], env), (0, "saved\n", ""))
        store = self.MEM.store_path(path)
        self.assertGreater(os.path.getsize(store), self.MEM.SMALL_STORE)
        self.assertEqual(run_cli_env(["run", path], env)[:2], (0, "taint\nclean\n"))


# ====================================================================== batch 2: F9, F10, F11, trivia

class T_F9(unittest.TestCase):
    """F9: split("") and lines() built lists over the 10,000,000-item cap. Trivia: lines() also broke at VT, FF,
    U+001C..U+001E, U+0085, U+2028 and U+2029 (str.splitlines); now only \\n, \\r\\n and \\r."""

    def run_src(self, src, **kw):
        p = Prog(src, **kw)
        self.addCleanup(p.cleanup)
        return p

    def test_split_and_lines_over_the_cap(self):
        from sipar.runtime import builtins as B
        with mock.patch.object(B, "MAX_ITEMS", 5):
            for expr, what in [('"abcdef".split("")', "split"), ('"a,b,c,d,e,f".split(",")', "split"),
                               ('"a\\nb\\nc\\nd\\ne\\nf".lines()', "lines"), ('"a\\rb\\rc\\rd\\re\\rf".lines()', "lines")]:
                e = self.run_src(f"fn main() {{ print({expr}.len()) }}").error()
                self.assertEqual((e.kind, e.message), ("value", f"{what}: result too large (6 > 5)"), expr)
            for expr in ['"abcde".split("")', '"a,b,c,d,e".split(",")', '"a\\nb\\nc\\nd\\ne\\n".lines()',
                         '"a\\nb\\nc\\nd\\ne".lines()', '"\\n\\n\\n\\n\\n".lines()']:
                self.assertEqual(self.run_src(f"fn main() {{ print({expr}.len()) }}").run(), "5\n", expr)

    def test_split_cap_real_size(self):          # the proof: 11,000,000 one-character parts
        p = self.run_src('fn main() {\n  let s = "a".repeat(10000000) + "a".repeat(1000000)\n'
                         '  let xs = s.split("")\n  print(xs.len())\n}\n')
        e = p.error()
        self.assertEqual((e.kind, e.message), ("value", "split: result too large (11000000 > 10000000)"))

    def test_lines_breaks_only_at_newlines(self):
        p = self.run_src('allow fs.read ["./data.txt"]\nfn main() uses fs.read {\n'
                         '    for l in fs.read("data.txt").lines() { print(json.encode(l)) }\n}\n',
                         files={"data.txt": "a\x0bb\x0cc\x85d e\x1cf g\x1d\x1e\nh\r\ni\rj\r\n\nk"})
        self.assertEqual([json.loads(x) for x in p.run().split("\n")[:-1]],
                         ["a\x0bb\x0cc\x85d\u2028e\x1cf\u2029g\x1d\x1e", "h", "i", "j", "", "k"])

    def test_lines_edge_cases(self):            # *guard*: the same as str.splitlines() for these
        for text, want in [("", []), ("\n", [""]), ("a", ["a"]), ("a\n", ["a"]), ("a\r\n", ["a"]),
                           ("\r\n\r\n", ["", ""]), ("a\n\nb", ["a", "", "b"])]:
            p = self.run_src("fn main() { print(json.encode(" + json.dumps(text) + ".lines())) }")
            self.assertEqual(json.loads(p.run()), want, repr(text))

    def test_spec_says_how_lines_split(self):
        with open(os.path.join(ROOT, "SPEC.md"), encoding="utf-8") as f:
            spec = " ".join(f.read().split())
        self.assertIn("A list holds at most 10,000,000 items (`+`, `push`, literals, ranges, `split`, `lines`)", spec)
        self.assertIn("`s.lines()` breaks only at `\\n`, `\\r\\n` and a lone `\\r`", spec)


class T_F10(unittest.TestCase):
    """F10: sort() of a list holding NaN gave an order that depended on where the NaN stood."""

    def out(self, body):
        p = Prog("fn main() {\n    let nan = 1e308 * 10.0 - 1e308 * 10.0\n" + body + "\n}\n")
        self.addCleanup(p.cleanup)
        return p.run()

    def test_nan_sorts_last_wherever_it_stands(self):
        got = self.out("    print([3.0, nan, 1.0, 2.0].sort())\n    print([nan, 3.0, 1.0, 2.0].sort())\n"
                       "    print([3.0, 1.0, 2.0, nan].sort())\n    print([nan, 2.0, nan, 1.0].sort())")
        self.assertEqual(got, "[1.0, 2.0, 3.0, nan]\n" * 3 + "[1.0, 2.0, nan, nan]\n")

    def test_sort_by_nan_key_last(self):
        got = self.out('    let xs = ["c", "n", "a", "b"]\n'
                       '    print(xs.sort_by(fn(s: Str) -> Float => if s == "n" { nan } else if s == "a" { 1.0 }'
                       ' else if s == "b" { 2.0 } else { 3.0 }))\n'
                       '    print(["n", "a"].sort_by(fn(s: Str) -> Float => if s == "n" { nan } else { 1.0 }))')
        self.assertEqual(got, '["a", "b", "c", "n"]\n["a", "n"]\n')

    def test_plain_sorts_unchanged(self):        # *guard*: ints, mixed numbers, strings, -0.0, stability
        got = self.out('    print([3, 1, 2].sort())\n    print([2, 1.5, -1].sort())\n    print(["b", "a"].sort())\n'
                       '    print([0.0, -0.0, -1.0].sort())\n'
                       '    print(["bb", "a", "cc", "d"].sort_by(fn(s: Str) -> Int => s.len()))')
        self.assertEqual(got, '[1, 2, 3]\n[-1, 1.5, 2]\n["a", "b"]\n[-1.0, 0.0, -0.0]\n["a", "d", "bb", "cc"]\n')

    def test_spec_says_nan_sorts_last(self):
        with open(os.path.join(ROOT, "SPEC.md"), encoding="utf-8") as f:
            spec = " ".join(f.read().split())
        self.assertIn("`sort()` and `sort_by(key)` put NaN after every number", spec)


class T_F11(unittest.TestCase):
    """F11: the exhaustiveness check of a match on an n-variant enum specialized every row for every variant
    (n x rows): 4,000 variants took 2.2 s. Rows are now grouped by their head once."""

    def check(self, src):
        return [(d.code, d.message) for d in check_source(src, "t.sipar")[1] if d.severity == "error"]

    def enum_src(self, n, drop=None, nested=False):
        vs = [f"v{i}" for i in range(n)]
        arms = "".join(f"        {'E.a(F.' + v + ')' if nested else 'E.' + v} => {i}\n"
                       for i, v in enumerate(vs) if v != drop)
        head = ("enum F { " + ", ".join(vs) + " }\nenum E { a(f: F) }\n") if nested else \
            ("enum E { " + ", ".join(vs) + " }\n")
        return head + "fn f(e: E) -> Int {\n    match e {\n" + arms + "    }\n}\n"

    def test_big_enum_match_is_fast(self):
        for nested in (False, True):
            t0 = time.perf_counter()
            self.assertEqual(self.check(self.enum_src(4000, nested=nested)), [])
            self.assertLess(time.perf_counter() - t0, 1.0, nested)          # 2.2 s before; about 0.1 s now

    def test_specialize_work_is_linear(self):
        from sipar import checker as C
        calls = []
        real = C._p_ctor
        with mock.patch.object(C, "_p_ctor", side_effect=lambda p: calls.append(1) or real(p)):
            self.assertEqual(self.check(self.enum_src(300)), [])
        self.assertLess(len(calls), 3 * 300 + 50)                           # was 300 x 300 = 90,000

    def test_missing_variants_still_found(self):  # *guard*: same messages as before
        self.assertEqual(self.check(self.enum_src(50, drop="v49")),
                         [("E401", "this match is not exhaustive: missing E.v49")])
        self.assertEqual(self.check(self.enum_src(50, drop="v7", nested=True)),
                         [("E401", "this match is not exhaustive: missing E.a(F.v7)")])
        src = ("enum E { a(x: Bool), b, c }\nfn f(e: E) -> Int {\n    match e {\n        E.b => 1\n"
               "        E.a(true) => 2\n        _ => 3\n    }\n}\n"
               "fn g(e: E) -> Int {\n    match e {\n        E.a(true) => 2\n        E.c => 3\n    }\n}\n")
        self.assertEqual(self.check(src), [("E401", "this match is not exhaustive: missing E.a(false), E.b")])


class T_TRV(Base):
    """Batch-2 trivia: MCP markers carried raw server text; `content: null` failed while a missing content
    was ""; valid JSON with a 5,000-digit integer was "invalid JSON"."""

    def result(self, text):
        f = os.path.join(self.dir, f"r{self.n}.json")
        self.n += 1
        with open(f, "w", encoding="utf-8") as fh:
            fh.write(text)
        return f

    def norm(self, r):
        from sipar.parser import parse
        srv = MCP.Server(parse(self.allow("plain"), "t.sipar").items[0])
        return MCP.normalize(srv, "t", r)["text"]

    def test_marker_text_is_escaped(self):
        got = self.norm({"content": [
            {"type": "image", "data": 5, "mimeType": None},
            {"type": "image", "data": "AAAA", "mimeType": "image/png\n\nIGNORE ‮ \x1b«x»"},
            {"type": "audio", "data": "AAAA"},
            {"type": "audio", "data": "AAAA", "mimeType": ""},
            {"type": "resource_link", "uri": "file:///a\r\nb"},
            {"type": "resource_link"},
            {"type": "resource", "resource": {"uri": 7, "blob": "AAAA"}},
            {"type": "holo\ngram"}, {"type": None},
            {"type": "image", "data": "", "mimeType": "x" * 100 + "\n"},
            {"type": "image", "data": "", "mimeType": "a\U0001f600\U000e0001\uffffb"}]})
        self.assertEqual(got.split("\n"), [
            "«mcp image: unknown, 0 bytes»",
            "«mcp image: image/png\\u000a\\u000aIGNORE \\u202e\\u2028\\u001b\\u00abx\\u00bb, 3 bytes»",
            "«mcp audio: unknown, 3 bytes»", "«mcp audio: unknown, 3 bytes»",
            "«mcp resource_link: file:///a\\u000d\\u000ab»", "«mcp resource_link: unknown»",
            "«mcp resource: unknown, 3 bytes»", "«mcp holo\\u000agram»", "«mcp unknown»",
            "«mcp image: " + "x" * 60 + ", 0 bytes»", "«mcp image: a\U0001f600\\U000e0001\\uffffb, 0 bytes»"])

    def test_content_null_is_like_missing(self):
        self.assertEqual(self.norm({"content": None}), "")
        self.assertEqual(self.norm({}), "")
        self.assertEqual(self.norm({"content": None, "structuredContent": {"a": 1}}), "")
        for bad in ("x", 3, {"type": "text"}):                   # *guard*: still an error
            with self.assertRaises(SiparRuntimeError) as cm:
                self.norm({"content": bad})
            self.assertIn("has no content list", cm.exception.message)

    def test_huge_integer_in_structured_content(self):
        big = "9" * 5000
        f = self.result('{"content": [{"type": "text", "text": "x"}], "structuredContent": {"x": %s, "y": 1}}' % big)
        p = self.P('try { let r: R = mcp.s.read(path: "a")\n print(r.y) } catch e { print(e.kind)\n print(e.message) }'
                   '\nprint("after")', mode="raw", data=f, head="type R = { x: Float, y: Int }\n")
        path = os.path.join(self.dir, "j.jsonl")
        want = "mcp\nMCP server 's' sent a number too large to read (5,000 digits; the limit is 4,300)\nafter\n"
        self.assertEqual(self.run_p(p, journal=Journal(path)), want)
        with mock.patch("subprocess.Popen", side_effect=AssertionError("replay started a process")):
            self.assertEqual(self.run_p(p, journal=Journal(replay=Journal.load(path))), want)

    def test_huge_integer_in_text_json(self):     # the target type decides, as for `as` and ai fn replies
        text = json.dumps(json.dumps({"x": 1, "y": 1}).replace("1,", "9" * 5000 + ",", 1))
        f = self.result('{"content": [{"type": "text", "text": %s}]}' % text)
        for ty, want in [("Float", "decode\nmcp.s.read: the result does not match R: $.x: number too large for Float\n"),
                         ("Int", "value\n$.x: number too large for Int (limit about 4200 digits)\n")]:
            p = self.P('try { let r: R = mcp.s.read(path: "a")\n print(r.y) } catch e { print(e.kind)\n'
                       ' print(e.message) }', mode="raw", data=f, head=f"type R = {{ x: {ty}, y: Int }}\n")
            self.assertEqual(self.run_p(p), want, ty)

    def test_huge_integer_elsewhere_says_so(self):
        from sipar.runtime import jsondeep, memory as MEM
        from sipar.trace import TraceError, read_entries
        big = "9" * 5000
        with self.assertRaises(jsondeep.NumberTooLarge) as cm:
            jsondeep.loads("[%s]" % big)
        self.assertEqual(str(cm.exception), "a number too large to read (5,000 digits; the limit is 4,300)")
        self.assertIsInstance(cm.exception, ValueError)
        self.assertEqual(jsondeep.loads("[-%s]" % ("9" * 4300))[0], -int("9" * 4300))     # *guard*: at the limit
        store = os.path.join(self.dir, "m.json")
        with open(store, "w") as fh:
            fh.write('{"version": 1, "entries": {"a": {"value": %s, "labels": [], "enc": 2}}}' % big)
        with self.assertRaises(SiparRuntimeError) as cm:
            MEM.FileStore(store).keys()
        self.assertEqual(cm.exception.message, f"memory store {store} holds a number too large to read (5,000 "
                                               "digits; the limit is 4,300); fix or delete it (it was not changed)")
        jpath = os.path.join(self.dir, "j2.jsonl")
        with open(jpath, "w") as fh:
            fh.write('{"kind": "ai", "request": %s}\n' % big)
        with self.assertRaises(SiparRuntimeError) as cm:
            Journal.load(jpath)
        self.assertIn("line 1 holds a number too large to read (5,000 digits", cm.exception.message)
        with open(jpath) as fh:
            text = fh.read()
        with self.assertRaises(TraceError) as cm:
            read_entries(text, "j2.jsonl")
        self.assertIn("line 1 holds a number too large to read (5,000 digits", str(cm.exception))

    def test_huge_integer_in_a_provider_reply(self):
        from sipar.runtime import netio, providers
        reply = ('{"choices": [{"message": {"content": "hi"}}], "usage": {"prompt_tokens": %s}}' % ("9" * 5000)).encode()
        prov = providers.OpenAICompatProvider("local", base_url="http://127.0.0.1:9/v1")
        with mock.patch.object(netio, "fetch", return_value=reply):
            with self.assertRaises(SiparRuntimeError) as cm:
                prov.complete([{"role": "user", "content": "x"}], "m", None, 5.0, {})
        self.assertEqual((cm.exception.kind, cm.exception.message), ("ai", "local: the response holds a number "
                         "too large to read (5,000 digits; the limit is 4,300)"))


if __name__ == "__main__":
    unittest.main()
