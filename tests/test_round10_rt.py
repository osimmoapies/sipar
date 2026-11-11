"""Round-10 runtime fixes (fuzz report). Each test failed before the fix unless marked *guard*.

F1  bytes on stdin that are not UTF-8 ended `input()` with "internal error (UnicodeDecodeError)", not catchable
F2  print / "{t}" of a value nested 160,000 deep was quadratic (20 s)
F3  the 100,000,000-character Str limit was checked by `+` only: "{s}{s}" and join went past it; a value that
    shares a part many times (t = T.node(t, t)) was copied out in full before any check (4 GB, killed)
F4  sum() skipped the Int limit of `+`
F5  a host (str, Enum) member or a str/int/float subclass reached Sipar through its __str__/__int__/__float__
F6  NaN equality depended on object identity ([nan] == [nan] true for one shared NaN)
F7  an LSP document version 1e400 / NaN stopped publishDiagnostics
R1  a secret in a response (model reply "482913" equal to PIN) was journaled as «secret:PIN» and replay saw
    the marker: an Int reply failed to decode, replay retried the call and diverged
"""

import enum
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sipar  # noqa: E402
from sipar import lsp  # noqa: E402
from sipar.checker import check_source  # noqa: E402
from sipar.deep import call_deep  # noqa: E402
from sipar.errors import SecretRegistry, SiparRuntimeError, use_registry  # noqa: E402
from sipar.runtime.journal import Journal  # noqa: E402
from sipar.runtime import values as V  # noqa: E402
from sipar.runtime.values import EnumVal, Record, equal, render  # noqa: E402
from rt_helpers import FakeTTY, Prog, Server  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PIN = "482913"


def prog(test, src, files=None):
    p = Prog(src, files)
    test.addCleanup(p.cleanup)
    program, d = check_source(src, p.path)
    test.assertEqual([(x.code, x.message) for x in d if x.severity == "error"], [])
    p.program = program
    return p


def run_limited(src, args=(), stdin=b"", timeout=10.0, extra_env=None):
    """`sipar run` of src in a child process: (exit code, stdout, stderr, max RSS in bytes, seconds).
    Killed after `timeout` seconds (then the exit code is None)."""
    d = tempfile.mkdtemp(prefix="sipar_r10rt_")
    path = os.path.join(d, "p.sipar")
    with open(path, "w", encoding="utf-8") as f:
        f.write(src)
    env = {k: v for k, v in os.environ.items() if not k.startswith("SIPAR_")}
    env["PYTHONPATH"] = ROOT
    env.update(extra_env or {})
    t0 = time.monotonic()
    p = subprocess.Popen([sys.executable, "-m", "sipar", "run", path, *args], cwd=d, env=env,
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    killed = []

    def kill():
        killed.append(1)
        p.kill()

    timer = threading.Timer(timeout, kill)
    timer.start()
    try:
        out, err = p.communicate(stdin)      # reads both pipes; the process is reaped below by wait4
    finally:
        timer.cancel()
        shutil.rmtree(d, ignore_errors=True)
    secs = time.monotonic() - t0
    rss = 0
    try:
        _, status, ru = os.wait4(p.pid, 0)
        rss = ru.ru_maxrss * (1 if sys.platform == "darwin" else 1024)
        code = os.waitstatus_to_exitcode(status)
    except ChildProcessError:                # communicate() reaped it already: no per-child usage
        code = p.returncode
    return (None if killed else code), out.decode("utf-8", "replace"), err.decode("utf-8", "replace"), rss, secs


GB = 1 << 30


# ====================================================================== F1

class Bytes(io.TextIOWrapper):
    """A strict UTF-8 text stream over bytes, as Python's sys.stdin is."""

    def __init__(self, data: bytes, tty=False):
        super().__init__(io.BytesIO(data), encoding="utf-8")
        self._tty = tty

    def isatty(self):
        return self._tty


class T_F1_Stdin(unittest.TestCase):
    SRC = 'allow io\nfn main() uses io { let l = input("q"); print(l); print(l.len()) }\n'

    def test_invalid_bytes_become_fffd(self):
        p = prog(self, self.SRC)
        out = p.run(stdin=Bytes(b"x\xc0z\n"))
        self.assertEqual(out, "qx�z\n3\n")

    def test_truncated_sequence_at_end(self):
        p = prog(self, self.SRC)
        self.assertEqual(p.run(stdin=Bytes(b"ab\xe2\x82")), "qab�\n3\n")

    def test_valid_utf8_unchanged(self):                             # guard
        p = prog(self, self.SRC)
        self.assertEqual(p.run(stdin=Bytes("é😀\n".encode())), "qé😀\n2\n")

    def test_journal_and_replay_hold_fffd(self):
        p = prog(self, self.SRC)
        path = os.path.join(p.dir, "j.jsonl")
        j = Journal(path)
        try:
            live = p.run(stdin=Bytes(b"x\xff\xfez\n"), journal=j)
        finally:
            j.close()
        self.assertEqual(live, "qx��z\n4\n")
        rep = p.run(stdin=io.StringIO(""), journal=Journal(replay=Journal.load(path)))
        self.assertEqual(rep, live)

    def test_approve_reads_bad_bytes(self):
        src = 'allow io\nfn main() uses io { print(try { approve("v", "ok?") } catch e { e.kind }) }\n'
        p = prog(self, src)
        self.assertTrue(p.run(stdin=Bytes(b"y\n\xc0\n", tty=True)).endswith("v\n"))    # the bad line comes later
        self.assertTrue(p.run(stdin=Bytes(b"y\xc0\n", tty=True)).endswith("denied\n"))  # "y\ufffd" is not "y"

    def test_undecodable_stream_is_catchable_io(self):
        class Bad:                           # no reconfigure: the decode error itself must become `io`
            errors = "strict"

            def readline(self):
                return b"\xc0".decode("utf-8")

            def isatty(self):
                return False
        src = 'allow io\nfn main() uses io { print(try { input("q") } catch e { e.kind }) }\n'
        p = prog(self, src)
        self.assertEqual(p.run(stdin=Bad()), "qio\n")

    def test_cli_pipe_and_replay(self):
        src = 'allow io\nfn main() uses io { let l = input(""); print(l.len()); print(l) }\n'
        code, out, err, _, _ = run_limited(src, stdin=b"x\xc0z\n")
        self.assertEqual((code, out), (0, "3\nx�z\n"), err)


# ====================================================================== F2 / F3 / F4

DEEP = '''enum T { leaf, node(c: T) }
fn main(args: List[Str]) { var t = T.leaf
  let n = args[0] as Int
  for i in 0..n { t = T.node(t) }
  print("{t}".len()) }
'''


class T_F2_Deep(unittest.TestCase):
    def test_print_160k_deep_is_linear(self):
        code, out, err, rss, secs = run_limited(DEEP, ["160000"], timeout=10)
        self.assertEqual((code, out), (0, "3520006\n"), err[-300:])
        self.assertLess(rss, GB)

    def test_layout_matches_json_dumps(self):                       # guard: the rewrite keeps the layout
        import random
        rnd = random.Random(10)

        def gen(d=0):
            c = rnd.randrange(8 if d < 5 else 4)
            if c == 0:
                return rnd.randrange(-10**6, 10**6)
            if c == 1:
                return "".join(rnd.choice('ab"\\\né😀\x01') for _ in range(rnd.randrange(4)))
            if c == 2:
                return rnd.choice([None, True, False, 1.5, -0.0])
            if c == 3:
                return []
            if c < 6:
                return [gen(d + 1) for _ in range(rnd.randrange(4))]
            return {"".join(rnd.choice('k"é') for _ in range(rnd.randrange(3))): gen(d + 1)
                    for _ in range(rnd.randrange(4))}
        for _ in range(3000):
            v = gen()
            self.assertEqual(V._json_text(v), json.dumps(v, ensure_ascii=False))
        self.assertEqual(V._json_text([float("nan"), float("inf"), {"a": float("-inf")}]),
                         '[nan, inf, {"a": -inf}]')


class T_F3_StrLimit(unittest.TestCase):
    def check_value_error(self, body, want="string too large", timeout=10, head=""):
        src = head + "fn main() {\n" + textwrap.dedent(body) + "\n}\n"
        code, out, err, rss, secs = run_limited(src, timeout=timeout)
        self.assertIsNotNone(code, f"killed after {timeout} s")
        self.assertIn(want, out + err)
        self.assertLess(rss, GB)
        return out

    def test_interpolation(self):
        out = self.check_value_error('''
            var s = "x".repeat(10000000)
            var i = 0
            while i < 3 { s = "{s}{s}"; i = i + 1 }
            print(s.len())
            print(try { "{s}{s}".len() as Str } catch e { e.kind + ": " + e.message })''')
        self.assertEqual(out.splitlines()[0], "80000000")
        self.assertTrue(out.splitlines()[1].startswith("value: string too large"), out)

    def test_join(self):
        self.check_value_error('''
            let s = "x".repeat(10000000)
            let xs = [s, s, s, s, s, s, s, s, s, s, s]
            print(try { xs.join("").len() as Str } catch e { e.kind + ": " + e.message })''',
                               "value: join: string too large")

    def test_upper_of_long_expanding_text(self):
        self.check_value_error('''
            var s = "ΐ".repeat(10000000)
            s = "{s}{s}"
            s = "{s}{s}"
            print(s.len())
            print(try { s.upper().len() as Str } catch e { e.kind + ": " + e.message })''',
                               "value: upper: string too large")

    def test_shared_value_print_is_refused_before_copying(self):
        out = self.check_value_error('''
            var t = T.leaf
            for i in 0..60 { t = T.node(t, t) }
            print(try { "{t}".len() as Str } catch e { e.kind + ": " + e.message })
            print(try { json.encode(t).len() as Str } catch e { e.kind + ": " + e.message })''',
                                     "value: value too large", timeout=10,
                                     head="enum T { leaf, node(l: T, r: T) }\n").replace("\n", " ")
        self.assertEqual(out.count("value: value too large"), 2, out)

    def test_labelled_str_shared_in_list(self):
        src = ('allow io\nfn main() uses io {\n let s = input("").repeat(10000000)\n'
               ' let xs = (0..40).map(fn(i: Int) => s)\n'
               ' print(try { "{xs}".len() as Str } catch e { e.kind + ": " + e.message }) }\n')
        code, out, err, rss, secs = run_limited(src, stdin=b"y\n", timeout=10)
        self.assertIn("value: value too large", out, err[-300:])
        self.assertLess(rss, GB)

    def test_json_size_is_a_lower_bound(self):                      # guard for the precheck
        t = EnumVal("T", "leaf")
        for _ in range(5):
            t = EnumVal("T", "node", {"l": t, "r": t})
        vals = [t, [1, "ab", None, [], {}], {"k": [1.5, "é"]}, Record("R", {"a": "x", "bb": [t]}),
                EnumVal("E", "v", {"x": 1}, wrapped=True)]
        for v in vals:
            self.assertLessEqual(V._json_size(v, False), len(render(v)))
        cyc: list = [1]
        cyc.append(cyc)
        self.assertIn("[...]", render(cyc))                         # cycles still shown, never refused

    def test_small_values_still_print(self):                        # guard
        p = prog(self, 'fn main() { let xs = [[1, 2], [3]]\n print(xs)\n print("{xs}")\n print(json.encode(xs)) }\n')
        self.assertEqual(p.run(), "[[1, 2], [3]]\n" * 3)


class T_F4_Sum(unittest.TestCase):
    def test_sum_has_the_int_limit(self):
        p = prog(self, 'fn main() { var x = 1\n for k in 0..13999 { x = x * 2 }\n x = x - 1 + x\n'
                       ' print(try { [x, x].sum() as Str } catch e { e.kind + ": " + e.message })\n'
                       ' print(([x, x - x].sum() == x)) }\n')
        out = p.run().splitlines()
        self.assertTrue(out[0].startswith("value: number too large for Int"), out)
        self.assertEqual(out[1], "true")                             # guard: just under the limit is fine

    def test_sum_int_and_huge_float_mix(self):
        p = prog(self, 'fn main() { let xs: List[Float] = [1e308, 1e308]\n print(xs.sum()) }\n')
        self.assertEqual(p.run(), "inf\n")                           # guard: Float overflow is inf, as `+`


# ====================================================================== F5

class SE(str, enum.Enum):
    A = "a"


class S2(str):
    def __str__(self):
        return "HIJACK"


class I2(int):
    def __int__(self):
        return 10 ** 5000

    def __float__(self):
        return 9.5


class F2(float):
    def __float__(self):
        return float("nan")


class IE(enum.IntEnum):
    A = 3


class T_F5_HostSubclasses(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp(prefix="sipar_r10rt_")
        self.addCleanup(shutil.rmtree, d, True)
        self.path = os.path.join(d, "p.sipar")
        with open(self.path, "w") as f:
            f.write('fn echo(s: Str) -> Str { s }\nfn twice(s: Str) -> Str { s + s }\n'
                    'fn keys(m: Map[Int]) -> List[Str] { m.keys() }\nfn up(s: Str) -> Str { s.upper() }\n'
                    'fn fi(x: Int) -> Int { x + 0 }\nfn ff(x: Float) -> Float { x + 0.0 }\n')
        self.p = sipar.load(self.path)

    def test_str_enum_and_str_subclass(self):
        for fn, arg, want in [("echo", SE.A, "a"), ("twice", SE.A, "aa"), ("up", SE.A, "A"), ("echo", S2("x"), "x"),
                              ("twice", S2("x"), "xx"), ("keys", {SE.A: 1}, ["a"]), ("keys", {S2("k"): 1}, ["k"])]:
            r = self.p.call(fn, arg)
            self.assertEqual(r, want, (fn, arg))
            self.assertIs(type(r[0] if isinstance(r, list) else r), str)

    def test_number_subclasses_read_by_value(self):
        self.assertEqual(self.p.call("fi", I2(5)), 5)
        self.assertEqual(self.p.call("ff", I2(5)), 5.0)
        self.assertEqual(self.p.call("ff", F2(2.5)), 2.5)
        self.assertEqual(self.p.call("fi", IE.A), 3)
        self.assertEqual(self.p.call("ff", IE.A), 3.0)


# ====================================================================== F6

class T_F6_Nan(unittest.TestCase):
    def test_nan_never_equal(self):
        p = prog(self, '''fn main() { let nan = (1e308*10.0) - (1e308*10.0)
  print([nan] == [nan]); print([nan].contains(nan)); print(nan in [nan]); print(nan == nan)
  print([nan].index_of(nan) == none); print([nan] != [nan]); let ys = [[1.0], [nan]]; print(ys == ys)
  print(["a": [nan]] == ["a": [nan]]); let m = ["a": [nan]]; print(m == m) }
''')
        self.assertEqual(p.run(), "false\n" * 4 + "true\ntrue\nfalse\nfalse\nfalse\n")

    def test_shared_values_without_nan_equal(self):                 # guard
        p = prog(self, 'fn main() { let xs = [1.0, 2.0]\n print([xs] == [xs]); print(xs == xs)\n'
                       ' let r = [xs, [3.0]]\n print(r == r) }\n')
        self.assertEqual(p.run(), "true\ntrue\ntrue\n")

    def test_equal_unit_identity(self):
        nan = float("nan")
        box = [nan]
        self.assertFalse(equal(box, box))
        self.assertFalse(equal({"a": box}, {"a": box}))
        self.assertFalse(equal(Record("R", {"x": box}), Record("R", {"x": box})))
        self.assertTrue(equal([1.0], [1.0]))


# ====================================================================== F7

def body_frame(text: str) -> bytes:
    b = text.encode()
    return b"Content-Length: %d\r\n\r\n" % len(b) + b


class T_F7_LspVersion(unittest.TestCase):
    def session(self):
        out, err = io.BytesIO(), io.StringIO()
        srv = lsp.Server(out, err)
        return srv, out

    def send(self, srv, out, text):
        srv.handle_bytes(lsp.read_message(io.BytesIO(body_frame(text))))
        data = out.getvalue()
        out.seek(0)
        out.truncate()
        msgs = []
        while data:
            head, _, rest = data.partition(b"\r\n\r\n")
            n = int(head.split(b":")[1])
            msgs.append(json.loads(rest[:n]))
            data = rest[n:]
        return msgs

    def test_odd_versions_still_publish(self):
        for v in ("1e400", "-1e400", "NaN", "Infinity", "1.5", "true", '"7"', "null"):
            srv, out = self.session()
            self.send(srv, out, '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}')
            self.send(srv, out, '{"jsonrpc":"2.0","method":"initialized","params":{}}')
            msgs = self.send(srv, out, '{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":'
                                       '{"uri":"file:///t/a.sipar","languageId":"sipar","version":%s,'
                                       '"text":"fn main() { let x: Int = \\"s\\" }"}}}' % v)
            pub = [m for m in msgs if m.get("method") == "textDocument/publishDiagnostics"]
            self.assertEqual(len(pub), 1, (v, msgs))
            self.assertIsNone(pub[0]["params"]["version"])
            self.assertTrue(pub[0]["params"]["diagnostics"], v)
            msgs = self.send(srv, out, '{"jsonrpc":"2.0","method":"textDocument/didChange","params":{"textDocument":'
                                       '{"uri":"file:///t/a.sipar","version":%s},"contentChanges":[{"text":'
                                       '"fn main() { }"}]}}' % v)
            pub = [m for m in msgs if m.get("method") == "textDocument/publishDiagnostics"]
            self.assertEqual((len(pub), pub[0]["params"]["diagnostics"]), (1, []), v)

    def test_integer_version_kept(self):                            # guard
        srv, out = self.session()
        self.send(srv, out, '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}')
        self.send(srv, out, '{"jsonrpc":"2.0","method":"initialized","params":{}}')
        msgs = self.send(srv, out, '{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":'
                                   '{"uri":"file:///t/a.sipar","languageId":"sipar","version":42,"text":""}}}')
        self.assertEqual(msgs[-1]["params"]["version"], 42)


# ====================================================================== R1

class R1Base(unittest.TestCase):
    def record_replay(self, src, env, script=None, files=None, providers=None):
        """(live output, replay output, journal text). The replay re-reads the secret from env."""
        p = prog(self, src, files)
        path = os.path.join(p.dir, "j.jsonl")
        j = Journal(path)
        try:
            live = p.run(env=env, journal=j, script=script, providers=providers)
        finally:
            j.close()
        with open(path, encoding="utf-8") as f:
            text = f.read()
        j2 = Journal(replay=Journal.load(path))
        try:
            rep = p.run(env=env, journal=j2)
        finally:
            j2.close()
        self.assertEqual(j2.unused(), 0)
        return live, rep, text

    def assert_clean(self, text, secret=PIN):
        self.assertNotIn(secret, text)
        self.assertNotIn(secret.upper(), text)


HEAD = 'allow io\nallow ai\nallow secret ["PIN"]\n'


class T_R1_Replay(R1Base):
    def test_int_reply(self):                     # the report's repro
        src = HEAD + ('ai fn guess(q: Str) -> Int { "Give a number for {q}" }\n'
                      'fn main() uses ai, secret, io {\n let p = env.secret("PIN")\n let n = guess("x")\n'
                      ' print((n + 1) == 482914) }\n')
        live, rep, text = self.record_replay(src, {"PIN": PIN}, script={"guess": [PIN]})
        self.assertEqual((live, rep), ("true\n", "true\n"))
        self.assert_clean(text)
        self.assertIn('"restore"', text)

    def test_str_reply(self):
        src = HEAD + ('ai fn say(q: Str) -> Str { "Say {q}" }\n'
                      'fn main() uses ai, secret, io {\n let p = env.secret("PIN")\n let s = say("x")\n'
                      ' print(s.len() == 10); print(s.starts_with("pin ")) }\n')
        live, rep, text = self.record_replay(src, {"PIN": PIN}, script={"say": ["pin " + PIN]})
        self.assertEqual((live, rep), ("true\ntrue\n", "true\ntrue\n"))
        self.assert_clean(text)

    def test_float_reply(self):
        src = HEAD + ('ai fn f(q: Str) -> Float { "{q}" }\n'
                      'fn main() uses ai, secret, io {\n let p = env.secret("PIN")\n let x = f("x")\n'
                      ' print(x * 2.0 == 9659.0) }\n')
        live, rep, text = self.record_replay(src, {"PIN": "4829.5"}, script={"f": ["4829.5"]})
        self.assertEqual((live, rep), ("true\n", "true\n"))
        self.assert_clean(text, "4829.5")

    def test_record_fields(self):
        src = HEAD + ('type R = { a: Int, b: Str }\nai fn r(q: Str) -> R { "{q}" }\n'
                      'fn main() uses ai, secret, io {\n let p = env.secret("PIN")\n let v = r("x")\n'
                      ' print(v.a == 482913); print(v.b.len() == 8) }\n')
        live, rep, text = self.record_replay(src, {"PIN": PIN}, script={"r": ['{"a": 482913, "b": "x%sy"}' % PIN]})
        self.assertEqual((live, rep), ("true\ntrue\n", "true\ntrue\n"))
        self.assert_clean(text)

    def test_case_variant_form_comes_back(self):
        src = HEAD + ('ai fn say(q: Str) -> Str { "Say {q}" }\n'
                      'fn main() uses ai, secret, io {\n let p = env.secret("PIN")\n let s = say("x")\n'
                      ' print(s.starts_with("ABCD")); print(s.ends_with("x1234")) }\n')
        live, rep, text = self.record_replay(src, {"PIN": "abcdx1234"}, script={"say": ["ABCDX1234"]})
        self.assertEqual((live, rep), ("true\nfalse\n", "true\nfalse\n"))
        self.assert_clean(text, "abcdx1234")

    def test_literal_marker_stays_a_marker(self):                   # guard
        src = HEAD + ('ai fn say(q: Str) -> Str { "Say {q}" }\n'
                      'fn main() uses ai, secret, io {\n let p = env.secret("PIN")\n let s = say("x")\n'
                      ' print(s.len() == 12) }\n')
        live, rep, text = self.record_replay(src, {"PIN": PIN}, script={"say": ["«secret:PIN»"]})
        self.assertEqual((live, rep), ("true\n", "true\n"))
        self.assertNotIn('"restore"', text)

    def test_escaped_copy_stays_a_marker(self):                     # guard: the documented limit (SPEC §7)
        # an HTML-entity copy is found through the decoded view only: it is no registered form, so the journal
        # has nothing to point at and replay keeps the marker (the journal still never holds the secret)
        src = HEAD + ('ai fn say(q: Str) -> Str { "Say {q}" }\n'
                      'fn main() uses ai, secret, io {\n let p = env.secret("PIN")\n let s = say("x")\n'
                      ' print(s.len() == 12) }\n')
        ent = "".join("&#%d;" % ord(c) for c in PIN)
        live, rep, text = self.record_replay(src, {"PIN": PIN}, script={"say": [ent]})
        self.assertEqual((live, rep), ("false\n", "true\n"))
        self.assert_clean(text)
        self.assertNotIn(ent, text)
        self.assertNotIn('"restore"', text)

    def test_agent_tool_args(self):
        src = HEAD + ('/// Note a number.\nfn add(a: Int, b: Int) -> Int uses io { print(a + b == 482914); 0 }\n'
                      'agent fn ag(goal: Str) -> Int uses io { tools [add]\n "Goal: {goal}" }\n'
                      'fn main() uses ai, secret, io {\n let p = env.secret("PIN")\n print(ag("x") == 7) }\n')
        script = {"ag": [{"tool": "add", "args": {"a": int(PIN), "b": 1}}, {"final": 7}]}
        live, rep, text = self.record_replay(src, {"PIN": PIN}, script=script)
        self.assertEqual((live, rep), ("true\ntrue\n", "true\ntrue\n"))     # the tool got the number both times
        self.assert_clean(text)

    def test_mcp_result(self):
        mcp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "fake_mcp_server.py")
        allow = (f'allow mcp "fs" {json.dumps([sys.executable, mcp, "--era", "both", "--mode", "normal"])} '
                 f'tools ["read_text_file"] readonly ["read_text_file"]\n')
        src = allow + HEAD + ('fn main() uses mcp, secret, io {\n let p = env.secret("PIN")\n'
                              ' let t = mcp.fs.read_text_file(path: "a.txt")\n print(t.len() == 11) }\n')
        live, rep, text = self.record_replay(src, {"PIN": PIN}, files={"a.txt": f"pin {PIN}\n"})
        self.assertEqual((live, rep), ("true\n", "true\n"))
        self.assert_clean(text)

    def test_http_result(self):
        srv = Server()
        self.addCleanup(srv.close)
        src = (f'allow net ["127.0.0.1:{srv.port}"]\n' + HEAD +
               'fn main() uses net, secret, io {\n let k = env.secret("PIN")\n'
               f' let r = http.get("{srv.url}/echo", headers: ["Authorization": k])\n print(r.contains(k)) }}\n')
        live, rep, text = self.record_replay(src, {"PIN": PIN})
        self.assertEqual((live, rep), ("true\n", "true\n"))
        self.assert_clean(text)


class T_R1_Unit(unittest.TestCase):
    def setUp(self):
        self.scope = use_registry(SecretRegistry())
        self.scope.__enter__()
        self.addCleanup(self.scope.__exit__, None, None, None)

    def fresh(self):
        self.scope.__exit__(None, None, None)
        self.scope = use_registry(SecretRegistry())
        self.scope.__enter__()

    def test_error_message_same_in_run_and_replay(self):          # guard: the message is redacted for the program too
        j = Journal()
        j.add_secret(PIN, "secret:PIN")

        def boom():
            raise SiparRuntimeError("io", f"bad {PIN} here")
        with self.assertRaises(SiparRuntimeError) as live:
            j.effect("io", {"url": "u"}, boom)
        self.assertEqual(live.exception.message, "bad «secret:PIN» here")
        self.assertNotIn(PIN, json.dumps(j.entries))
        self.assertNotIn("restore", j.entries[-1])
        entries = json.loads(json.dumps(j.entries))
        self.fresh()
        r = Journal(replay=entries)
        r.add_secret(PIN, "secret:PIN")
        with self.assertRaises(SiparRuntimeError) as cm:
            r.effect("io", {"url": "u"}, boom)
        self.assertEqual(cm.exception.message, live.exception.message)

    def test_keys_values_nested(self):
        j = Journal()
        j.add_secret(PIN, "secret:PIN")
        resp = {"text": [f"{PIN}", {f"k{PIN}": f"a{PIN}b{PIN}"}, 5, None, "plain"]}
        self.assertEqual(j.effect("x", {"q": 1}, lambda: resp), resp)
        entries = json.loads(json.dumps(j.entries))
        self.assertNotIn(PIN, json.dumps(entries))
        self.fresh()
        r = Journal(replay=entries)
        r.add_secret(PIN, "secret:PIN")
        self.assertEqual(r.effect("x", {"q": 1}, lambda: None), resp)

    def test_without_the_secret_replay_keeps_markers(self):        # guard: nothing to restore from
        j = Journal()
        j.add_secret(PIN, "secret:PIN")
        j.effect("mcp", {}, lambda: {"text": PIN})
        entries = json.loads(json.dumps(j.entries))
        self.fresh()
        self.assertEqual(Journal(replay=entries).effect("mcp", {}, lambda: None), {"text": "«secret:PIN»"})

    def test_tampered_restore_is_ignored(self):
        base = {"seq": 1, "kind": "mcp", "request": {}, "response": {"text": "a«secret:PIN»b"}}
        for bad in ({"response": [[0, [[1, 13, 99]]]]}, {"response": [[0, [[0, 5, 0]]]]}, {"response": "x"},
                    {"response": [[0, [[1, 13]]]]}, {"response": [[0, [[1, 99, 0]]]]}, [1, 2],
                    {"response": [[0, [[True, 13, 0]]]]}, {"response": [["0", [[1, 13, 0]]]]}):
            self.fresh()
            r = Journal(replay=[dict(base, restore=bad)])
            r.add_secret(PIN, "secret:PIN")
            self.assertEqual(r.effect("mcp", {}, lambda: None), {"text": "a«secret:PIN»b"}, bad)
        self.fresh()
        r = Journal(replay=[dict(base, restore={"response": [[1, [[1, 13, 0]]]]})])     # good: string #1
        r.add_secret(PIN, "secret:PIN")
        self.assertEqual(r.effect("mcp", {}, lambda: None), {"text": f"a{PIN}b"})

    def test_two_keys_that_became_one(self):                       # guard: no crash, no restore
        j = Journal()
        j.add_secret(PIN, "secret:PIN")
        resp = {PIN: 1, "«secret:PIN»": 2}
        j.effect("mcp", {}, lambda: resp)
        self.assertNotIn("restore", j.entries[-1])
        self.assertNotIn(PIN, json.dumps(j.entries))

    def test_deep_response_restored_without_recursion(self):
        j = Journal()
        j.add_secret(PIN, "secret:PIN")
        resp: object = PIN
        for _ in range(50_000):
            resp = [resp]
        call_deep(j.effect, "x", {}, lambda: resp)     # scrub (older code) recurses; the runtime runs it deep
        entry = j.entries[-1]
        self.assertIn("restore", entry)
        self.fresh()
        r = Journal(replay=[entry])
        r.add_secret(PIN, "secret:PIN")
        got = r.effect("x", {}, lambda: None)      # restore itself is iterative: on the normal stack
        for _ in range(50_000):
            got = got[0]
        self.assertEqual(got, PIN)


if __name__ == "__main__":
    unittest.main()
