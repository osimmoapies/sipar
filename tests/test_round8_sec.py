"""Round-8 security fixes. Each test failed before the fix unless marked *guard*.

R8-1  an MCP server filled memory with empty or tiny lines read ahead (the cap counted only payload bytes), and
      one 10 MB message of millions of empty arrays took 2 GB to parse
R8-2  a secret with surrounding whitespace (a trailing space, the \\r of a Windows .env file): its trimmed form
      was not labelled, redacted or kept out of a child's environment / env.get
R8-3  a non-ASCII case copy of a secret (ß -> SS, ı -> I, ﬀ -> FF) passed the R7-6 filters
R8-4  a secret echoed JSON-escaped with \\/ or percent-encoded was not labelled or redacted
"""

import json
import os
import queue
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock
from urllib.parse import quote, quote_plus

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from rt_helpers import Prog  # noqa: E402
from sipar.checker import check_source  # noqa: E402
from sipar.errors import SecretRegistry, redact_text, register_secret, secret_labels_in, use_registry  # noqa: E402
from sipar.parser import parse  # noqa: E402
from sipar.runtime import mcp as MCP  # noqa: E402
from sipar.runtime.journal import Journal  # noqa: E402

SECRET = "abc-123-zzz"                       # fake secret values
LAB = "secret:R8_TOKEN"
MARK = "«secret:R8_TOKEN»"


def prog(test, src):
    p = Prog(src)
    test.addCleanup(p.cleanup)
    program, d = check_source(src, p.path)
    test.assertEqual([(x.code, x.message) for x in d if x.severity == "error"], [])
    p.program = program
    return p


def main(body, head, uses):
    return head + f"fn main() uses {uses} {{\n" + textwrap.dedent(body) + "\n}\n"


class Reg(unittest.TestCase):
    """Registry checks under a fresh per-test registry (as one run has)."""

    def labels(self, secret, text):
        with use_registry(SecretRegistry()):
            register_secret(secret, LAB)
            return secret_labels_in(text), redact_text(text)

    def assertCaught(self, secret, echo):
        found, red = self.labels(secret, f"you sent: {echo}!")
        self.assertEqual(found, frozenset({LAB}), repr(echo))
        self.assertEqual(red, f"you sent: {MARK}!", repr(echo))

    def assertMissed(self, secret, echo):
        found, red = self.labels(secret, f"x {echo} x")
        self.assertEqual(found, frozenset(), repr(echo))
        self.assertEqual(red, f"x {echo} x")


# ====================================================================== env helpers (R8-2, R8-3)

ENV_HEAD = 'allow secret ["R8_TOKEN"]\nallow env ["MYV"]\nallow shell ["env"]\nallow io\n'


class EnvBase(unittest.TestCase):
    def child_env(self, token, myv):
        p = prog(self, main('let o = shell.run("env")\nprint(o.contains("MYV="))', ENV_HEAD, "shell, io"))
        return p.run(env={"R8_TOKEN": token, "MYV": myv})

    def env_get(self, token, myv):
        p = prog(self, main('try { print(env.get("MYV") ?? "none") } catch e { print(e.kind) }', ENV_HEAD,
                            "env, io"))
        path = os.path.join(p.dir, "j.jsonl")
        j = Journal(path)
        try:
            out = p.run(env={"R8_TOKEN": token, "MYV": myv}, journal=j)
        finally:
            j.close()
        with open(path, encoding="utf-8") as f:
            return out, f.read()


# ====================================================================== R8-2. surrounding whitespace

class T_R8_2_Whitespace(Reg, EnvBase):
    def test_trailing_space_trimmed_form_registered(self):
        self.assertCaught(SECRET + " ", SECRET)

    def test_trailing_cr_trimmed_form_registered(self):
        self.assertCaught(SECRET + "\r", SECRET)

    def test_leading_tab_and_newline_trimmed(self):
        self.assertCaught("\t" + SECRET + "\n", SECRET)

    def test_trimmed_and_upper_case(self):
        self.assertCaught(SECRET + " ", SECRET.upper())

    def test_trimmed_under_4_chars_not_registered(self):         # guard: the documented 4-character limit
        self.assertMissed("ab  ", "ab")

    def test_untrimmed_secret_unchanged(self):                     # guard
        self.assertCaught(SECRET, SECRET)
        self.assertMissed(SECRET, "abc-123")

    def test_env_get_trimmed_copy_is_secret(self):
        out, journal = self.env_get(SECRET + " ", SECRET)
        self.assertEqual(out, "taint\n")
        self.assertNotIn(SECRET, journal)

    def test_env_get_trimmed_copy_is_labelled_not_refused(self):
        # like an exact copy (round 6): the value is read and labelled secret, not refused as an unseen form
        p = prog(self, main('try { print(env.get("MYV") ?? "none") } catch e { print(e.message.contains("holds the '
                            'value")) }', ENV_HEAD, "env, io"))
        self.assertEqual(p.run(env={"R8_TOKEN": SECRET + " ", "MYV": SECRET}), "false\n")
        self.assertEqual(p.run(env={"R8_TOKEN": "abc/123+zzz", "MYV": "abc%2F123%2Bzzz"}), "false\n")
        self.assertEqual(p.run(env={"R8_TOKEN": SECRET, "MYV": "AbC-123-zzz"}), "true\n")   # guard: R7-6

    def test_env_get_trimmed_copy_cr(self):
        out, journal = self.env_get(SECRET + "\r", "x=" + SECRET)
        self.assertEqual(out, "taint\n")
        self.assertNotIn(SECRET, journal)

    def test_child_env_trimmed_copy_dropped(self):
        self.assertEqual(self.child_env(SECRET + " ", SECRET), "false\n")

    def test_short_secret_with_space_whole_value(self):
        out, journal = self.env_get("Q9z ", "Q9z")
        self.assertEqual(out, "taint\n")
        self.assertNotIn("Q9z", journal)
        self.assertEqual(self.child_env("Q9z ", "q9Z"), "false\n")

    def test_short_secret_padded_copy(self):
        self.assertEqual(self.child_env("Q9z", "Q9z\r"), "false\n")

    def test_public_value_passes(self):                            # guard
        self.assertEqual(self.child_env(SECRET + " ", "plain-value"), "true\n")
        self.assertEqual(self.env_get(SECRET + " ", "plain-value")[0], "plain-value\n")

    def test_whitespace_only_secret_does_not_block_everything(self):   # guard: trimmed form is empty
        self.assertEqual(self.child_env("     ", "plain"), "true\n")


# ====================================================================== R8-3. non-ASCII case copies

class T_R8_3_Casefold(Reg, EnvBase):
    def test_env_get_sharp_s_copy_is_taint(self):
        out, journal = self.env_get("ßtok-1", "SStok-1")
        self.assertEqual(out, "taint\n")
        self.assertNotIn("SStok-1", journal)

    def test_child_env_sharp_s(self):
        self.assertEqual(self.child_env("ßtok-1", "SSTOK-1"), "false\n")
        self.assertEqual(self.child_env("ßtok-1", "x sstok-1"), "false\n")
        self.assertEqual(self.child_env("ßtok-1", "x SsToK-1"), "false\n")      # mixed: only caseless compare

    def test_child_env_dotless_i(self):
        self.assertEqual(self.child_env("ıtok-1", "ITOK-1"), "false\n")
        self.assertEqual(self.child_env("ıtok-1", "itok-1"), "false\n")
        self.assertEqual(self.child_env("ıtok-1", "ItOK-1"), "false\n")

    def test_child_env_ff_ligature(self):
        self.assertEqual(self.child_env("ﬀtok-1", "FFTOK-1"), "false\n")
        self.assertEqual(self.child_env("ﬀtok-1", "fFtOK-1"), "false\n")

    def test_short_secret_sharp_s(self):
        self.assertEqual(self.child_env("ßq", "SSQ"), "false\n")

    def test_registry_casefold_forms(self):
        self.assertCaught("ßtok-1", "sstok-1")
        self.assertCaught("ßtok-1", "SSTOK-1")                     # guard: upper-case was already registered
        self.assertCaught("ıtok-1", "itok-1")
        self.assertCaught("ﬀtok-1", "fftok-1")

    def test_unrelated_non_ascii_passes(self):                     # guard
        self.assertEqual(self.child_env("ßtok-1", "straße"), "true\n")
        self.assertEqual(self.env_get("ßtok-1", "straße")[0], "straße\n")


# ====================================================================== R8-4. escaped echoes

class T_R8_4_Escaped(Reg):
    S = "abc/123+zzz"

    def test_json_slash_escape(self):
        self.assertCaught(self.S, "abc\\/123+zzz")

    def test_percent_quote(self):
        self.assertCaught(self.S, quote(self.S, safe=""))

    def test_percent_quote_keeps_slash(self):
        self.assertCaught(self.S, quote(self.S))

    def test_percent_quote_plus(self):
        self.assertCaught("abc 123/zzz", quote_plus("abc 123/zzz"))

    def test_percent_lower_hex(self):
        self.assertCaught(self.S, "abc%2f123%2bzzz")

    def test_percent_utf8(self):
        self.assertCaught("пароль-1", quote("пароль-1"))

    def test_combination_trimmed_upper_percent(self):
        self.assertCaught(" " + self.S + "\r", quote(self.S.upper(), safe=""))

    def test_old_forms_still_caught(self):                         # guard: repr / JSON / bytes forms
        self.assertCaught('ab"c\\d', json.dumps('ab"c\\d')[1:-1])
        self.assertCaught("ab\tcd", repr("ab\tcd")[1:-1])

    def test_lone_surrogate_secret(self):                          # guard: no crash, plain form registered
        self.assertCaught("abc\udcffdef", "abc\udcffdef")
        self.assertCaught("abc\udcffdef", "abc%FFdef")

    def test_short_secret_not_registered(self):                    # guard: escaped forms of a 3-char secret
        self.assertMissed("a/b", "a%2Fb")

    def test_form_count_bounded(self):
        from sipar.errors import secret_forms
        self.assertEqual(secret_forms(SECRET), [SECRET, SECRET.upper()])  # lower == as is
        worst = secret_forms(" Straße/ı+ﬀ \"x\" \r")
        self.assertLessEqual(len(worst), 160)


# ====================================================================== R8-2 / R8-4 end to end over HTTP

class _Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        v = (self.headers.get("X-Key") or "").strip()     # RFC 9110: no surrounding whitespace in a field value
        b = {"/trim": v, "/php": json.dumps(v).replace("/", "\\/"), "/url": quote(v, safe="")}[self.path].encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class T_R8_Http(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
        cls.port = cls.srv.server_address[1]
        cls.th = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.th.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def run_get(self, token, field):
        head = f'allow secret ["R8_TOKEN"]\nallow net ["127.0.0.1:{self.port}"]\nallow io\n'
        body = (f'let s = env.secret("R8_TOKEN")\n'
                f'let r = http.get("http://127.0.0.1:{self.port}/{field}", headers: ["X-Key": s])\n'
                f'try {{ print(r) }} catch e {{ print(e.kind) }}')
        p = prog(self, main(body, head, "secret, net, io"))
        path = os.path.join(p.dir, "j.jsonl")
        j = Journal(path)
        try:
            out = p.run(env={"R8_TOKEN": token}, journal=j)
        finally:
            j.close()
        with open(path, encoding="utf-8") as f:
            return out, f.read()

    def test_trimmed_echo_is_secret(self):
        out, journal = self.run_get(SECRET + " ", "trim")
        self.assertEqual(out, "taint\n")
        self.assertNotIn(SECRET, journal)

    def test_php_json_echo_is_secret(self):
        out, journal = self.run_get("abc/123+zzz", "php")
        self.assertEqual(out, "taint\n")
        self.assertNotIn("zzz", journal)

    def test_percent_echo_is_secret(self):
        out, journal = self.run_get("abc/123+zzz", "url")
        self.assertEqual(out, "taint\n")
        self.assertNotIn("zzz", journal)


# ====================================================================== R8-1. MCP read-ahead and big messages

SERVER = r'''
import json, os, sys
mode, pidlog = sys.argv[1], sys.argv[2]
with open(pidlog, "a") as f:
    f.write(f"{os.getpid()}\n")
def out(o):
    sys.stdout.write(json.dumps(o) + "\n"); sys.stdout.flush()
TOOLS = [{"name": "read", "description": "reads", "inputSchema": {"type": "object"}}]
calls = 0
for line in sys.stdin:
    if not line.strip():
        continue
    m = json.loads(line); meth, i = m.get("method"), m.get("id")
    if i is None:
        continue
    if meth == "server/discover":
        out({"jsonrpc": "2.0", "id": i, "result": {"supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}}}})
    elif meth == "tools/list":
        out({"jsonrpc": "2.0", "id": i, "result": {"tools": TOOLS}})
    elif meth == "tools/call":
        calls += 1
        if mode == "many":
            n = int(m["params"]["arguments"].get("n", 0))
            sys.stdout.write('{"jsonrpc": "2.0", "id": %d, "result": {"content": [], "structuredContent": '
                             '{"xs": [%s], "t": "%s"}}}\n' % (i, ",".join(["[]"] * n), "[{," * 3000))
            sys.stdout.flush(); continue
        out({"jsonrpc": "2.0", "id": i, "result": {"content": [{"type": "text", "text": "ok%d" % calls}]}})
        unit = {"blank": b"\n", "crlf": b" \r\n", "tiny": b"{}\n"}.get(mode)
        if unit and calls == 1:
            sys.stdout.buffer.write(unit * 3000); sys.stdout.flush()
    else:
        out({"jsonrpc": "2.0", "id": i, "error": {"code": -32601, "message": "no"}})
'''


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        done, _ = os.waitpid(pid, os.WNOHANG)
        return done == 0
    except ChildProcessError:
        return True


class T_R8_1_Mcp(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="sipar_r8m_")
        self.srv = os.path.join(self.d, "srv.py")
        self.pidlog = os.path.join(self.d, "pids")
        with open(self.srv, "w", encoding="utf-8") as f:
            f.write(SERVER)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        import shutil
        import signal
        try:
            with open(self.pidlog) as f:
                pids = [int(x) for x in f.read().split()]
        except FileNotFoundError:
            pids = []
        end = time.monotonic() + 5
        while any(_alive(p) for p in pids) and time.monotonic() < end:
            time.sleep(0.05)
        left = [p for p in pids if _alive(p)]
        for p in left:                       # only this test's fake servers
            os.kill(p, signal.SIGKILL)
        shutil.rmtree(self.d, ignore_errors=True)
        self.assertEqual(left, [], "a fake MCP server outlived the test")

    def P(self, mode, body):
        cmd = [sys.executable, self.srv, mode, self.pidlog]
        src = (f'allow mcp "s" {json.dumps(cmd)} tools ["read"] readonly ["read"]\nallow io\nallow time\n'
               f'fn main() uses mcp, io, time {{\n{textwrap.dedent(body)}\n}}\n')
        return prog(self, src)

    def run_p(self, p, err=False):
        j = Journal()                        # closing the journal stops the run's MCP servers
        try:
            return p.error(journal=j) if err else p.run(journal=j)
        finally:
            j.close()

    TWO_CALLS = 'print(mcp.s.read())\nsleep(0.5)\ntry { print(mcp.s.read()) } catch e { print("caught {e.kind}") }'

    # -- the reader, on a pipe
    def reader(self, data: bytes, **caps):
        srv = MCP.Server(parse('allow mcp "fs" ["x"] tools ["t"]\n', "t.sipar").items[0])
        c = MCP.Conn.__new__(MCP.Conn)
        c.srv, c.q = srv, queue.Queue()
        c.q_bytes, c.q_cond, c.closed = 0, threading.Condition(), False
        r, w = os.pipe()

        def write():                         # more than a pipe holds: write while the reader reads
            with os.fdopen(w, "wb") as f:
                f.write(data)
        wt = threading.Thread(target=write, daemon=True)
        wt.start()
        c.p = mock.Mock(stdout=os.fdopen(r, "rb"))
        patches = [mock.patch.object(MCP, k, v) for k, v in caps.items()]
        for x in patches:
            x.start()
        try:
            th = threading.Thread(target=c._read_out, daemon=True)
            th.start()
            th.join(1.0)
            n = c.q.qsize()
            with c.q_cond:
                c.closed = True
                c.q_cond.notify_all()
            th.join(2)
        finally:
            for x in patches:
                x.stop()
        return n, c

    def test_blank_lines_not_queued(self):
        n, c = self.reader(b"\n" * 100_000 + b" \r\n\t\n" + b'{"a": 1}\n')
        self.assertEqual(c.q.get_nowait(), ("line", b'{"a": 1}'))
        self.assertEqual(n, 2)                              # the message and the end of the pipe

    def test_tiny_lines_count_capped(self):
        n, _ = self.reader(b"{}\n" * 500, MAX_QUEUED=50)
        self.assertLessEqual(n, 50)

    def test_tiny_lines_cost_bytes(self):
        n, c = self.reader(b"{}\n" * 500, MAX_QUEUED_BYTES=1000)
        self.assertLessEqual(n, 1000 // MCP.QUEUE_ITEM_COST + 1)
        self.assertGreaterEqual(c.q_bytes, n * MCP.QUEUE_ITEM_COST)

    def test_queue_released_on_take(self):                         # guard: the counters go back to 0
        n, c = self.reader(b"{}\n" * 5)
        for _ in range(5):
            c._take(0.1)
        self.assertEqual((c.q_count, c.q_bytes), (0, 0))

    # -- end to end
    def test_blank_flood_after_answer_is_harmless(self):
        p = self.P("blank", self.TWO_CALLS)
        with mock.patch.object(MCP, "MAX_IGNORED", 50):
            self.assertEqual(self.run_p(p), "ok1\nok2\n")

    def test_crlf_blank_flood_is_harmless(self):
        p = self.P("crlf", self.TWO_CALLS)
        with mock.patch.object(MCP, "MAX_IGNORED", 50):
            self.assertEqual(self.run_p(p), "ok1\nok2\n")

    def test_tiny_flood_is_mcp_error_and_stops_server(self):
        # the queue holds at most MAX_QUEUED; the next call reads them as not its answer: fatal kind mcp
        p = self.P("tiny", self.TWO_CALLS)
        with mock.patch.object(MCP, "MAX_IGNORED", 50), mock.patch.object(MCP, "MAX_QUEUED", 50):
            e = self.run_p(p, err=True)
        self.assertEqual(p.out, "ok1\n")
        self.assertEqual(e.kind, "mcp")
        self.assertTrue(e.message.startswith("MCP server 's' sent more than 50 messages"), e.message)
        self.assertIsNone(p.last._mcp_sessions["s"].conn)          # the server was stopped

    def test_too_many_values_is_mcp_error(self):
        p = self.P("many", 'print(mcp.s.read(n: 2000))')
        with mock.patch.object(MCP, "MAX_MESSAGE_VALUES", 1000):
            e = self.run_p(p, err=True)
        self.assertEqual((e.kind, e.message), ("mcp", "MCP server 's' sent a message with more than 1,000 JSON values"))
        self.assertIsNone(p.last._mcp_sessions["s"].conn)

    def test_brackets_in_strings_are_not_values(self):              # guard: 9,000 `[{,` inside a string
        p = self.P("many", 'let r = mcp.s.read(n: 300)\nprint("ok")')
        with mock.patch.object(MCP, "MAX_MESSAGE_VALUES", 1000):
            self.assertEqual(self.run_p(p), "ok\n")

    def test_too_many_values_counter(self):
        f = MCP.too_many_values
        with mock.patch.object(MCP, "MAX_MESSAGE_VALUES", 10):
            self.assertTrue(f(b"[" + b"[]," * 10 + b"[]]"))
            self.assertFalse(f(b"[" + b"[]," * 3 + b"[]]"))
            self.assertFalse(f(b'{"a": "' + b"[{," * 50 + b'"}'))
            self.assertFalse(f(b'{"a": "\\"' + b"[{," * 50 + b'\\""}'))
            self.assertTrue(f(b'{"a": "\\\\", "b": [' + b"1," * 20 + b"1]}"))


if __name__ == "__main__":
    unittest.main()
