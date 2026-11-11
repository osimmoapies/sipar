"""Round 4: regression tests for the critics' findings (security S1-S5, correctness F1-F8, CLI/docs C1-C16, M).

Every test not marked "guard" (behaviour that must stay) or "coverage"
(a sink or mutation survivor that already behaved, now pinned) failed on the code before the fix (pre-fix copy of
the master tree in /tmp/sipar_r4_old). Proof programs: /tmp/sipar_r4_sec, /tmp/sipar_r4_fuzz, /tmp/sipar_r4_cli."""
from __future__ import annotations

import contextlib
import glob
import hashlib
import io
import json
import os
import re
import shutil
import stat
import tempfile
import unittest
from unittest import mock

from rt_helpers import CLEAN_ENV, ROOT, FakeTTY, Prog, Server, main_src

import sipar
from sipar.checker import check_source
from sipar.cli import main as cli_main
from sipar.cli import USAGE_HINT, spec_text
from sipar.errors import Diagnostic, SiparRuntimeError
from sipar.runtime.effects import Caps
from sipar.runtime.interp import Interp, _fixture_name
from sipar.runtime.journal import Journal
from sipar.runtime.values import LDict, LList, LRecord, render, to_json

SECRET = "hunter2xyz"
ENV = {"R4K": SECRET}
ALPHA = "abcdefghijklmnopqrstuvwxyz0123456789"
# table()[c] is ["item-c"]: a list picked with the secret's first letter has the secret label on the list
# itself (own labels), not on its plain items -- the shape every S finding leaked through
TABLES = f'''type Ch = {{ c: Str }}
fn table() -> Map[List[Str]] {{
    var m: Map[List[Str]] = [:]
    for c in "{ALPHA}".split("") {{ m[c] = ["item-" + c] }}
    m
}}
fn maps() -> Map[Map[Str]] {{
    var m: Map[Map[Str]] = [:]
    for c in "{ALPHA}".split("") {{ m[c] = ["X-C": "item-" + c] }}
    m
}}
fn recs() -> Map[Ch] {{
    var m: Map[Ch] = [:]
    for c in "{ALPHA}".split("") {{ m[c] = Ch {{ c: "item-" + c }} }}
    m
}}
'''
HEAD = 'allow secret ["R4K"]\nallow io\n' + TABLES
PICK = 'let k = env.secret("R4K")\nlet t = table()\nlet p = t[k[0]]\n'
LEAK = "item-h"            # the picked item: SECRET starts with "h"


def tmpdir(tc: unittest.TestCase) -> str:
    d = os.path.realpath(tempfile.mkdtemp(prefix="sipar_r4t_"))
    tc.addCleanup(shutil.rmtree, d, True)
    return d


def write(d: str, name: str, text: str | bytes) -> str:
    path = os.path.join(d, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb" if isinstance(text, bytes) else "w", **({} if isinstance(text, bytes) else
                                                                 {"encoding": "utf-8"})) as fh:
        fh.write(text)
    return path


def clean_env(extra: dict | None = None):
    e = {k: v for k, v in os.environ.items() if k not in CLEAN_ENV}
    e["SIPAR_MODEL"] = "mock"
    e.update(extra or {})
    return mock.patch.dict(os.environ, e, clear=True)


def cli(*argv: str, env: dict | None = None) -> tuple[int, str, str]:
    """The real CLI (check before run/replay/test), in-process; argparse errors are caught too."""
    out, err = io.StringIO(), io.StringIO()
    with clean_env(env), contextlib.redirect_stderr(err):
        try:
            rc = cli_main(list(argv), out, err)
        except SystemExit as x:
            rc = x.code
    return rc, out.getvalue(), err.getvalue()


def runs(d: str) -> list[str]:
    return sorted(glob.glob(os.path.join(d, ".sipar", "runs", "*.jsonl")))


def diags(src: str, file: str = "t.sipar"):
    return check_source(src, file)[1]


def codes(src: str, file: str = "t.sipar") -> list:
    return [(d.code, d.severity) for d in diags(src + "\nfn main() { }\n", file)]


class Base(unittest.TestCase):
    def prog(self, src: str, files: dict | None = None) -> Prog:
        p = Prog(src, files)
        self.addCleanup(p.cleanup)
        return p

    def secret_prog(self, body: str, head: str = "", files: dict | None = None) -> Prog:
        return self.prog(main_src(PICK + body, HEAD + head), files)

    def assert_redacted(self, text: str):
        self.assertNotIn(SECRET, text)
        self.assertNotIn(LEAK, text)


# ====================================================================== S1. Python API

API_SRC = 'allow secret ["R4K"]\nallow ai\n' + TABLES + '''
type R = { k: Str }
ai fn u() -> R { "give" }
fn leak_list() -> List[Str] uses secret { let k = env.secret("R4K"); let t = table(); t[k[0]] }
fn leak_map() -> Map[Str] uses secret { let k = env.secret("R4K"); let t = maps(); t[k[0]] }
fn leak_rec() -> Ch uses secret { let k = env.secret("R4K"); let t = recs(); t[k[0]] }
fn leak_nested() -> List[List[Str]] uses secret { let k = env.secret("R4K"); let t = table(); [["x"], t[k[0]]] }
fn leak_in_map() -> Map[List[Str]] uses secret { let k = env.secret("R4K"); let t = table(); ["a": t[k[0]]] }
fn upick() -> List[Str] uses ai { let r = u(); let t = table(); t[r.k] }
fn plain() -> List[Str] { let t = table(); t["b"] }
'''


class T_S1(unittest.TestCase):
    def load(self):
        d = tmpdir(self)
        return sipar.load(write(d, "api.sipar", API_SRC))

    def call(self, fn: str, **kw):
        with clean_env(ENV):
            return self.load().call(fn, **kw)

    def test_api_picked_container_taint(self):
        for fn in ("leak_list", "leak_map", "leak_rec"):
            with self.subTest(fn=fn):
                with self.assertRaises(sipar.SiparError) as cm:
                    self.call(fn)
                self.assertEqual(cm.exception.kind, "taint", cm.exception.message)
                self.assertNotIn(LEAK, cm.exception.message)

    def test_api_nested_pick(self):
        for fn, where in (("leak_nested", "leak_nested()[1]"), ("leak_in_map", "leak_in_map().a")):
            with self.subTest(fn=fn):
                with self.assertRaises(sipar.SiparError) as cm:
                    self.call(fn)
                self.assertEqual(cm.exception.kind, "taint")
                self.assertIn(where, cm.exception.message)

    def test_api_untrusted_dropped(self):                      # guard: SPEC §10, labels other than secret drop
        self.assertEqual(self.call("upick", mock_script={"u": [{"k": "b"}]}), ["item-b"])
        self.assertEqual(self.call("plain"), ["item-b"])


# ====================================================================== S2. journal, render, approve, errors

class T_S2(Base):
    def journal_text(self, p: Prog, **kw) -> str:
        jp = os.path.join(p.dir, "j.jsonl")
        j = Journal(path=jp)
        try:
            p.run(journal=j, env=ENV, **kw)
        finally:
            j.close()
        with open(jp, encoding="utf-8") as fh:
            return fh.read()

    def test_trust_journal_redacted(self):
        p = self.secret_prog('let x = trust(p, "ok")\nlet y = trust(maps()[k[0]], "ok")')
        text = self.journal_text(p)
        self.assert_redacted(text)
        entries = [json.loads(line) for line in text.splitlines()]
        trusts = [e for e in entries if e.get("kind") == "trust"]
        self.assertEqual(len(trusts), 2, text)
        for e in trusts:
            self.assertIn("«secret:R4K»", json.dumps(e, ensure_ascii=False))

    def test_render_to_json_redact(self):
        lab = frozenset({"secret:R4K"})
        for v in (LList(["item-h"], lab), LDict({"X": "item-h"}, lab), LRecord("Ch", {"c": "item-h"}, lab)):
            with self.subTest(v=type(v).__name__):
                self.assertEqual(render(v, redact=True), "«secret:R4K»")
                self.assertEqual(to_json(v, redact=True), "«secret:R4K»")
                self.assertEqual(to_json([1, v], redact=True), [1, "«secret:R4K»"])
                self.assertIn("item-h", render(v))                      # unredacted text stays the value

    def test_approve_redacted(self):                # coverage
        for body in ('let x = approve(p, "ok?")', 'let x = approve("v", "ok {p}?")',
                     'let x = approve(maps()[k[0]], "ok?")'):
            with self.subTest(body=body):
                p = self.secret_prog(body)
                e = p.error(env=ENV, stdin=FakeTTY("y\n"))
                self.assertEqual(e.kind, "taint", e.message)
                self.assert_redacted(e.message)
                self.assertEqual(p.stderr.getvalue(), "")             # nothing was shown to the user
        p = self.secret_prog('let x = approve(["a": 1], "ok?")\nprint("yes")')   # guard: plain value shown
        self.assertEqual(p.run(env=ENV, stdin=FakeTTY("y\n")), "yes\n")

    def test_error_message_redacted(self):                # coverage
        for body in ('let xs = [1]\nprint(xs[p.len() + 100])', 'assert false, "{p}"', 'let n = p[0] as Int',
                     'let m = ["a": 1]\nprint(m[p[0]])', 'let n = "{p}" as Float', 'fail("x", "{p}")'):
            with self.subTest(body=body):
                e = self.secret_prog(body).error(env=ENV)
                self.assert_redacted(e.message)
                self.assertNotIn("101", e.message)


# ====================================================================== S3. http headers

class T_S3(Base):
    def setUp(self):
        self.s1, self.s2 = Server(), Server()
        self.addCleanup(self.s1.close)
        self.addCleanup(self.s2.close)

    def run_net(self, body: str) -> tuple[Prog, str]:
        head = f'allow net ["127.0.0.1:{self.s1.port}", "127.0.0.1:{self.s2.port}"]\n'
        p = self.prog(main_src(PICK + body, HEAD + head))
        jp = os.path.join(p.dir, "j.jsonl")
        j = Journal(path=jp)
        try:
            p.run(journal=j, env=ENV)
        finally:
            j.close()
        with open(jp, encoding="utf-8") as fh:
            return p, fh.read()

    @staticmethod
    def hdr(hit: dict) -> dict:
        return {k.lower(): v for k, v in hit["headers"].items()}

    def test_picked_header_map_journal(self):
        _, text = self.run_net(f'let h = maps()[k[0]]\nlet r = http.get("{self.s1.url}/ok", headers: h)')
        self.assertEqual(self.hdr(self.s1.hits[-1]).get("x-c"), LEAK)   # it was sent: headers are the sink
        self.assert_redacted(text)

    def test_picked_header_map_redirect(self):
        self.run_net(f'let h = maps()[k[0]]\n'
                     f'let r = http.get("{self.s1.url}/redirect?to={self.s2.url}/ok", headers: h)')
        self.assertEqual(self.hdr(self.s1.hits[-1]).get("x-c"), LEAK)
        self.assertEqual(len(self.s2.hits), 1)
        self.assertNotIn("x-c", self.hdr(self.s2.hits[0]))

    def test_secret_header_name(self):                # coverage
        head = f'allow net ["127.0.0.1:{self.s1.port}"]\n'
        for hdrs in ('[k: "v"]', '["{k}x": "v"]', '[p[0]: "v"]'):
            with self.subTest(hdrs=hdrs):
                p = self.prog(main_src(PICK + f'let r = http.get("{self.s1.url}/ok", headers: {hdrs})',
                                       HEAD + head))
                e = p.error(env=ENV)
                self.assertEqual(e.kind, "taint", e.message)
        self.assertEqual(self.s1.hits, [])

    def test_plain_secret_value_header(self):                  # guard: one secret value, the rest plain
        _, text = self.run_net(f'let r = http.get("{self.s1.url}/redirect?to={self.s2.url}/ok", '
                               f'headers: ["X-Key": k, "X-Plain": "pv"])')
        self.assertNotIn(SECRET, text)
        self.assertIn("pv", text)
        self.assertEqual(self.hdr(self.s1.hits[0]).get("x-key"), SECRET)
        h2 = self.hdr(self.s2.hits[0])
        self.assertNotIn("x-key", h2)
        self.assertEqual(h2.get("x-plain"), "pv")


# ====================================================================== S4. every sink sees own labels

class T_S4(Base):
    def blocked(self, body: str, head: str = "", files: dict | None = None):
        e = self.secret_prog(body, head, files).error(env=ENV)
        self.assertEqual(e.kind, "taint", e.message)
        self.assert_redacted(e.message)
        return e

    def test_sinks_print(self):                # coverage
        self.blocked("print(p)")
        self.blocked('print("{p}")')

    def test_sinks_fs_write(self):                # coverage
        self.blocked('fs.write("out/x.txt", "{p}")', 'allow fs.write ["out"]\n', {"out/.keep": ""})
        self.blocked('fs.write("out/{p}.txt", "x")', 'allow fs.write ["out"]\n', {"out/.keep": ""})

    def test_sinks_json_encode(self):                # coverage
        self.blocked("let s = json.encode(p)")
        self.blocked("let s = json.encode([p])")

    def test_sinks_memory_save(self):                # coverage
        self.blocked('memory.save("k", p)', "allow memory\n")
        self.blocked('memory.save("k", maps()[k[0]])', "allow memory\n")

    def test_sinks_shell(self):                # coverage
        self.blocked('let o = shell.run("echo {p}")', 'allow shell ["echo"]\n')

    def test_sinks_error_value(self):                # coverage
        e = self.secret_prog('fail("x", "{p}")').error(env=ENV)      # the error text is redacted, not refused
        self.assertEqual((e.kind, e.message), ("x", "«secret:R4K»"))

    def test_prompt_picked(self):                # coverage
        self.blocked("let r = f(p)", 'allow ai\nai fn f(x: List[Str]) -> Str { "say {x}" }\n')
        self.blocked("let r = g(recs()[k[0]])", 'allow ai\nai fn g(x: Ch) -> Str { "say {x}" }\n')


# ====================================================================== S5. broad scopes

class T_S5(unittest.TestCase):
    def warn(self, scope: str, file: str) -> list:
        return [(d.code, d.severity, d.message) for d in diags(f"{scope}\nfn main() {{ }}\n", file)]

    def test_fs_broad_scope(self):
        d = tmpdir(self)
        f = os.path.join(d, "a", "b", "prog.sipar")
        home = os.path.expanduser("~")
        for entry, why in (("/", "whole file system"), (home, "home folder"), ("/".join([".."] * 40), "whole"),
                           ("..", "above the program"), ("../..", "above the program"), ("/.", "whole"),
                           (d, "above the program")):
            for eff in ("fs.read", "fs.write"):
                with self.subTest(entry=entry, eff=eff):
                    w = self.warn(f'allow {eff} [{json.dumps(entry)}]', f)
                    self.assertEqual(len(w), 1, w)
                    self.assertEqual(w[0][:2], ("E311", "warning"))
                    self.assertIn(why, w[0][2])

    def test_fs_narrow_ok(self):                               # guard
        d = tmpdir(self)
        f = os.path.join(d, "prog.sipar")
        for entry in ("out", "./data/in", "a/../b", ".", os.path.join(d, "out")):
            with self.subTest(entry=entry):
                self.assertEqual(self.warn(f'allow fs.read [{json.dumps(entry)}]', f), [])

    def test_net_public_suffix(self):
        for entry in ("*.co.uk", "*.com.au", "*.github.io", "*.com.br", "*.CO.UK"):
            with self.subTest(entry=entry):
                w = self.warn(f'allow net ["{entry}"]', "t.sipar")
                self.assertEqual([x[:2] for x in w], [("E311", "warning")])
                self.assertIn("public suffix", w[0][2])
        for entry in ("*.example.com", "*.example.co.uk", "api.co.uk", "*.bbc.co.uk"):
            with self.subTest(entry=entry):
                self.assertEqual(self.warn(f'allow net ["{entry}"]', "t.sipar"), [])

    def test_net_suffix_rule(self):
        """The SECOND_LEVEL rule ("co"/"com"/... under a TLD of 1..3 letters) and the hosting list, one by one."""
        from sipar import netscope
        for host in ("*.com.ve", "*.co.xyz", "*.ne.jp", "*.me.uk", "*.glitch.me", "*.ngrok.io", "*.s3.amazonaws.com"):
            with self.subTest(host=host):
                self.assertEqual(netscope.broad_wildcard(host), "allows every host under the public suffix "
                                 f"{host[2:]!r}, where anyone can register a name")
        self.assertEqual(netscope.broad_wildcard("*.com"), "allows every host under a top-level domain")
        for host in ("*.co.abcd", "*.example.co", "*.shop.me", "*.a.co.uk", "co.uk", "*.foo.ngrok.io", "*.xco.uk"):
            with self.subTest(host=host):
                self.assertIsNone(netscope.broad_wildcard(host))

    def test_scope_errors_exact(self):
        """Every netscope.parse branch: the exact (why, hint), so each check is proven to fire on its own."""
        from sipar import netscope
        bad = {
            "": ("is empty", 'remove it or write what it grants, e.g. ["example.com"]'),
            "   ": ("is empty", 'remove it or write what it grants, e.g. ["example.com"]'),
            " a.com": ("has spaces around it", 'allow net ["a.com"]'),
            "https://a.com/x": ("has a scheme; list host names only", 'allow net ["a.com"]'),
            "a.com/x/y": ("has a path; hosts are matched, not URLs", 'allow net ["a.com"]'),
            "[::1": ("has an unclosed '['", 'IPv6 addresses are written in brackets: ["[::1]:8080"]'),
            "[zz]": ("is not a valid IPv6 address", 'allow net ["[::1]"] or ["[::1]:8080"]'),
            "[::1]x": ("has text after ']'", 'allow net ["[::1]:8080"]'),
            "a:b:c": ("has more than one ':'", 'write host:port, and put IPv6 addresses in brackets: '
                                               '["example.com:8080", "[::1]:8080"]'),
            "a!b.com": ("is not a host name", 'allow net ["example.com"] or ["*.example.com"]'),
            "a.com:0": ("has an invalid port (use 1..65535)", 'allow net ["example.com:8080"]'),
            "a.com:65536": ("has an invalid port (use 1..65535)", 'allow net ["example.com:8080"]'),
            "a.com:x": ("has an invalid port (use 1..65535)", 'allow net ["example.com:8080"]'),
            "a.com:١٢": ("has an invalid port (use 1..65535)", 'allow net ["example.com:8080"]'),
            "[::1]:0": ("has an invalid port (use 1..65535)", 'allow net ["example.com:8080"]'),
        }
        for entry, want in bad.items():
            with self.subTest(entry=entry):
                with self.assertRaises(netscope.ScopeError) as cm:
                    netscope.parse(entry)
                self.assertEqual((cm.exception.why, cm.exception.hint, str(cm.exception)), want + (want[0],))
        good = {"a.com:65535": ("a.com", 65535), "a.com:1": ("a.com", 1), "A.COM.": ("a.com", None),
                "[::1]": ("::1", None), "[0:0::1]:80": ("::1", 80), "*": ("*", None), "*.X.com": ("*.x.com", None),
                "1.2.3.4:443": ("1.2.3.4", 443)}
        for entry, want in good.items():
            with self.subTest(entry=entry):
                self.assertEqual(netscope.parse(entry), want)


# ====================================================================== F1. Int -> Float widening

WIDEN = '''type P = { f: Float, xs: List[Float] }
fn r() -> Float { return 3 }
fn main() {
    let a: List[Float] = [1, 3]
    print(a[1] / 2)
    let m: Map[Float] = ["k": 5]
    print(m["k"] / 2)
    var v: Float = 1.5
    v = 5
    print(v / 2)
    let p = P { f: 1.0, xs: [] }
    p.f = 7
    print(p.f / 2)
    p.xs.push(9)
    print(p.xs[0] / 2)
    print(r() / 2)
    let g: fn(Int) -> Float = fn(x) => x
    print(g(3) / 2)
    print("{v} {a}")
    let x: Float = 2
    print(x)
}
'''
WIDEN2 = '''fn one() -> Int { 1 }
fn main() {
    let xs = [1, 2.5]
    print(xs[0] / 2)
    let c = true
    let v = if c { 1 } else { 2.5 }
    print(v / 2)
    let w = match 3 { 3 => 1, _ => 2.5 }
    print(w / 2)
    let o: Float? = none
    let z = o ?? 3
    print(z / 2)
    let h: fn() -> Float = one
    print(h() / 2)
    let t = try { 1 } catch e { 2.5 }
    print(t / 2)
    let m = ["a": 1, "b": 2.5]
    print(m["a"] / 2)
}
'''


class T_F1(unittest.TestCase):
    def run_cli(self, src: str) -> str:
        d = tmpdir(self)
        rc, out, err = cli("run", write(d, "w.sipar", src))
        self.assertEqual(rc, 0, err)
        return out

    def test_containers(self):
        self.assertEqual(self.run_cli(WIDEN).splitlines(),
                         ["1.5", "2.5", "2.5", "3.5", "4.5", "1.5", "1.5", "5.0 [1.0, 3.0]", "2.0"])

    def test_branches_fnvalues(self):
        self.assertEqual(self.run_cli(WIDEN2).splitlines(), ["0.5"] * 4 + ["1.5"] * 0 + ["0.5"] * 3
                         if False else ["0.5", "0.5", "0.5", "1.5", "0.5", "0.5", "0.5"])

    def test_api_json(self):
        d = tmpdir(self)
        p = sipar.load(write(d, "a.sipar", 'fn f() -> Float { 2 }\nfn g() -> List[Float] { [1, 2] }\n'
                                         'fn h() -> Str { json.encode([1, 2.5]) }\n'
                                         'fn k(x: Float) -> Float { x }\n'))
        with clean_env():
            f, g, h, k = p.call("f"), p.call("g"), p.call("h"), p.call("k", 3)
        self.assertIs(type(f), float)
        self.assertEqual(f, 2.0)
        self.assertEqual([type(x) for x in g], [float, float])
        self.assertEqual(json.loads(h), [1.0, 2.5])
        self.assertIn("1.0", h)
        self.assertIs(type(k), float)

    def test_covariance_rejected(self):                        # guard: already E210
        src = ('fn widen(xs: List[Float]) { xs.push(1.5) }\n'
               'fn main() { let a: List[Int] = [1]\nwiden(a)\nlet n: Int = a[1] }\n')
        self.assertIn("E210", [d.code for d in diags(src)])


# ====================================================================== F2. budget(seconds)

BUDGET = '''allow time
fn main() uses time {
    let xs = range(0, 200000).map(fn(x) => x * 7919 % 200003)
    let t0 = time.now()
    let r = try {
        budget(seconds: 0.005) {
            xs.sort().len() + xs.sort().len() + xs.sort().len() + xs.sort().len() + xs.sort().len()
        }
    } catch e {
        print("caught {e.kind}")
        0
    }
    let t1 = time.now()
    print("result {r} after {t1 - t0}")
}
'''


class T_F2(unittest.TestCase):
    def test_builtin_budget(self):
        d = tmpdir(self)
        rc, out, err = cli("run", write(d, "b.sipar", BUDGET))
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.splitlines()[0], "caught budget")
        self.assertTrue(out.splitlines()[1].startswith("result 0 after "))

    def test_replay_same(self):
        d = tmpdir(self)
        path = write(d, "b.sipar", BUDGET)
        rc, out, err = cli("run", path)
        self.assertEqual(rc, 0, err)
        [jp] = runs(d)
        with open(jp, encoding="utf-8") as fh:
            kinds = [json.loads(line).get("kind") for line in fh]
        self.assertIn("budget", kinds)
        rc2, out2, err2 = cli("replay", path, jp)
        self.assertEqual((rc2, out2), (0, out), err2)


# ====================================================================== F3/F4. lexer and conversions

class T_F3(Base):
    def e101(self, src: str):
        ds = diags(src)
        self.assertEqual([d.code for d in ds], ["E101"], [d.message for d in ds])
        return ds[0]

    def test_lexer_unicode(self):
        for src in ("²", "fn main() { print(1.²) }", "fn main() { let x = ١٢ }", "fn main() { let x = 1٢ }",
                    "fn main() { let x = ⁵ }", "fn main() { let x = 1 }"):
            with self.subTest(src=src):
                self.e101(src)

    def test_ident_ascii(self):
        for src in ("fn main() { let café = 1 }", "fn main() { let ℌ = 1 }", "fn ﬁx() { }\nfn main() { }",
                    "fn main() { let x́ = 1 }"):
            with self.subTest(src=src):
                d = self.e101(src)
                self.assertIn("ASCII", d.message)

    def test_as_conversions(self):
        cases = {'"١٢" as Int': "decode", '"١٢" as Float': "decode", '"1__0" as Float': "decode",
                 '"_1" as Float': "decode", '"1_" as Float': "decode", '"1__0" as Int': "decode",
                 '"²" as Int': "decode", '"1.5" as Int': "decode"}
        for expr, kind in cases.items():
            with self.subTest(expr=expr):
                self.assertEqual(self.prog(main_src(f"let x = {expr}")).error().kind, kind)
        ok = self.prog(main_src('print("1_0" as Int)\nprint("1_0" as Float)\nprint(" 7 " as Float)', "allow io"))
        self.assertEqual(ok.run().splitlines(), ["10", "10.0", "7.0"])


class T_F4(unittest.TestCase):
    def test_bigint_literal(self):
        d = diags("fn main() { print(" + "9" * 5000 + ") }")
        self.assertEqual([x.code for x in d], ["E101"])
        self.assertIn("too large", d[0].message)
        self.assertIn("14,000 bits", d[0].hint)
        self.assertEqual(diags("fn main() { let x = " + "9" * 4000 + " }"), [])           # guard: in range


# ====================================================================== F5. round

class T_F5(Base):
    def test_round(self):
        xs = ["0.49999999999999994", "4503599627370497.0", "-2.5", "2.5", "0.5", "-0.5", "1.5", "-1.5",
              "2.4999999999999996", "-0.49999999999999994", "1e20", "3", "-3"]
        want = ["0", "4503599627370497", "-3", "3", "1", "-1", "2", "-2", "2", "0", "100000000000000000000",
                "3", "-3"]
        p = self.prog(main_src("\n".join(f"print(round({x}))" for x in xs), "allow io"))
        self.assertEqual(p.run().splitlines(), want)


# ====================================================================== F6. match exhaustiveness

F6_HEAD = '''enum In { p, q }
enum Out { a(i: In), z }
enum E { b(flag: Bool), c(o: Int?) }
enum T { leaf, node(l: T, r: T) }
enum S { s(t: Str) }
'''


class T_F6(unittest.TestCase):
    def check(self, fn: str) -> list:
        return [(d.code, d.message) for d in diags(F6_HEAD + fn + "\nfn main() { }\n")]

    def test_bool_payload(self):
        self.assertEqual(self.check("fn f(e: E) -> Int { match e { E.b(true) => 1, E.b(false) => 2, E.c(_) => 3 } }"),
                         [])

    def test_nested(self):
        for fn in ("fn f(e: Out) -> Int { match e { Out.a(In.p) => 1, Out.a(In.q) => 2, Out.z => 3 } }",
                   "fn f(e: E) -> Int { match e { E.b(_) => 1, E.c(none) => 3, E.c(n) => 4 } }",
                   "fn f(t: T) -> Int { match t { T.leaf => 0, T.node(T.leaf, _) => 1, T.node(T.node(_, _), r) => 2 } }",
                   "fn f(o: Bool?) -> Int { match o { true => 1, false => 2, none => 3 } }"):
            with self.subTest(fn=fn):
                self.assertEqual(self.check(fn), [])

    def test_true_positives(self):
        for fn, missing in (("fn f(e: E) -> Int { match e { E.b(true) => 1, E.c(_) => 3 } }", "E.b(false)"),
                            ("fn f(t: T) -> Int { match t { T.leaf => 0, T.node(T.leaf, _) => 1 } }",
                             "T.node(T.node(_, _), _)"),
                            ("fn f(e: Out) -> Int { match e { Out.a(In.p) => 1, Out.z => 3 } }", "Out.a(In.q)"),
                            ("fn f(o: Bool?) -> Int { match o { true => 1, none => 3 } }", "false"),
                            ('fn f(e: S) -> Int { match e { S.s("x") => 1 } }', "S.s(_)")):
            with self.subTest(fn=fn):
                got = self.check(fn)
                self.assertEqual([c for c, _ in got], ["E401"])
                self.assertIn("missing " + missing, got[0][1])


# ====================================================================== F7. inf rendering, json.encode(fn)

class T_F7(Base):
    def test_inf_render(self):
        p = self.prog(main_src('let x = 1e308 * 10.0\nprint([x])\nprint(x)\nprint([0.0 - x, 1.5])\n'
                               'print(["k": x])\nprint("{[x]}")', "allow io"))
        self.assertEqual(p.run().splitlines(), ["[inf]", "inf", "[-inf, 1.5]", '{"k": inf}', "[inf]"])

    def test_json_fn(self):
        for expr in ("f", "[f]", '["k": f]'):
            with self.subTest(expr=expr):
                p = self.prog(main_src(f"let f = fn(x: Int) -> Int => x\nprint(json.encode({expr}))", "allow io"))
                e = p.error()
                self.assertEqual(e.kind, "value", e.message)
                self.assertIn("function", e.message)
                self.assertEqual(p.out, "")


class T_F8(unittest.TestCase):
    def test_effect_const(self):                               # guard: already E305 before round 4
        src = ('allow random\nfn roll() -> Int uses random { random.int(1, 6) }\nlet G = roll\n'
               'fn pure() -> Int { G() }\nfn main() { print(pure()) }\n')
        self.assertIn("E305", [d.code for d in diags(src)])


# ====================================================================== C1. bad journals

class T_C1(Base):
    def bad_files(self, d: str) -> list[str]:
        return [write(d, "bad_utf8.jsonl", b'{"seq": 1, "kind": "\xff\xfe"}\n'),
                write(d, "deep.jsonl", "[" * 200000 + "]" * 200000 + "\n"),
                write(d, "deep_obj.jsonl", '{"a":' * 100000 + "1" + "}" * 100000 + "\n")]

    def test_load_clean_error(self):
        d = tmpdir(self)
        for path in self.bad_files(d):
            with self.subTest(path=os.path.basename(path)):
                with self.assertRaises(SiparRuntimeError) as cm:
                    Journal.load(path)
                self.assertEqual(cm.exception.kind, "replay")
                self.assertIn(os.path.basename(path), cm.exception.message)

    def test_cli_replay(self):
        d = tmpdir(self)
        prog = write(d, "p.sipar", 'allow io\nfn main() uses io { print("x") }\n')
        for path in self.bad_files(d):
            with self.subTest(path=os.path.basename(path)):
                rc, out, err = cli("replay", prog, path)
                if path.endswith("bad_utf8.jsonl"):     # round 7: an unreadable input file is exit 2 (SPEC §9)
                    self.assertEqual((rc, err), (2, f"sipar: cannot read {path}: not UTF-8 text\n"))
                    continue
                self.assertEqual(rc, 1)
                self.assertIn("error[replay]", err)
                self.assertNotIn("Traceback", err)

    def test_fixture(self):
        p = self.prog('allow ai\nai fn hi(n: Str) -> Str { "hi {n}" }\ntest "t" { assert hi("a") == "mock" }\n')
        write(p.dir, os.path.join(".sipar", "fixtures", _fixture_name("t") + ".jsonl"), b"\xff\xfe\n")
        passed, failed, out = p.test()
        self.assertEqual((passed, failed), (0, 1), out)
        self.assertIn("error[replay]", out)


# ====================================================================== C2/C3. sipar test

TWO_CALLS = 'allow ai\nai fn hi(n: Str) -> Str { "hi {n}" }\ntest "t" { let a = hi("a")\nlet b = hi("b") }\n'
EARLY = 'allow ai\nai fn hi(n: Str) -> Str { "hi {n}" }\ntest "t" { let a = hi("a")\nif a == a { return }\nlet b = hi("b") }\n'


class T_C2(Base):
    def test_return_unused(self):
        p = self.prog(TWO_CALLS)
        self.assertEqual(p.test(record=True)[:2], (1, 0))
        fix = os.path.join(p.dir, ".sipar", "fixtures", _fixture_name("t") + ".jsonl")
        self.assertTrue(os.path.isfile(fix))
        q = Prog(EARLY)
        self.addCleanup(q.cleanup)
        os.makedirs(os.path.join(q.dir, ".sipar", "fixtures"))
        shutil.copy(fix, os.path.join(q.dir, ".sipar", "fixtures"))
        passed, failed, out = q.test()
        self.assertEqual((passed, failed), (0, 1), out)
        self.assertIn("unused entr", out)
        self.assertIn(_fixture_name("t"), out)

    def test_return_ok(self):                                  # guard: `return` with every entry used passes
        p = self.prog(EARLY)
        self.assertEqual(p.test(record=True)[:2], (1, 0))
        self.assertEqual(p.test()[:2], (1, 0))


class T_C3(Base):
    SRC = TWO_CALLS + 'test "u" { let c = hi("c") }\n'

    def fixtures(self, p: Prog) -> list[str]:
        return sorted(os.listdir(os.path.join(p.dir, ".sipar", "fixtures")))

    def boom(self, exc: BaseException):
        orig = Interp.exec_block
        state = {"n": 0}

        def wrapped(it, body, env):
            r = orig(it, body, env)
            if it.test_mode and state["n"] == 0 and body is it.program.items[2].body:
                state["n"] += 1
                raise exc
            return r
        return mock.patch.object(Interp, "exec_block", wrapped)

    def test_record_exception_removes_fixture(self):
        p = self.prog(self.SRC)
        with self.boom(RuntimeError("bug")):
            passed, failed, out = p.test(record=True)
        self.assertEqual((passed, failed), (1, 1), out)
        self.assertIn("FAIL t", out)
        self.assertIn("error[internal]: RuntimeError: bug", out)
        self.assertIn("PASS u", out)                           # the run went on
        self.assertEqual(self.fixtures(p), [_fixture_name("u") + ".jsonl"])

    def test_record_interrupt_removes_fixture(self):
        p = self.prog(self.SRC)
        with self.boom(KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                p.test(record=True)
        self.assertEqual(self.fixtures(p), [])


# ====================================================================== C4/C5. net scopes

class T_C4(Base):
    def test_checker(self):
        for src in ('allow net ["[::1]:9"]', 'allow net ["[::1]"]', 'allow net ["[2001:db8::1]:443"]'):
            with self.subTest(src=src):
                self.assertEqual(codes(src), [])
        for src, why in (('allow net ["a:b:c"]', "more than one ':'"), ('allow net ["example.com:8080:1"]', "more than one ':'"),
                         ('allow net ["::1"]', "more than one ':'"), ('allow net ["[::1]x"]', ""),
                         ('allow net ["[nothost]:9"]', ""), ('allow net ["[::1]:0"]', "port")):
            with self.subTest(src=src):
                ds = diags(src + "\nfn main() { }\n")
                self.assertEqual([d.code for d in ds], ["E310"])
                self.assertIn(why, ds[0].message)

    def test_runtime(self):
        m = Caps.host_matches
        self.assertTrue(m("::1", 9, "[::1]:9"))
        self.assertTrue(m("0:0:0:0:0:0:0:1", 9, "[::1]:9"))
        self.assertTrue(m("::1", 80, "[::1]"))
        self.assertFalse(m("::1", 8, "[::1]:9"))
        self.assertFalse(m("::2", 9, "[::1]:9"))
        for bad in ("a:b:c", "example.com:8080:1", "::1"):
            with self.subTest(bad=bad):
                self.assertFalse(m("example.com", 8080, bad))
                self.assertFalse(m("a", 0, bad))

    def test_runtime_v6_request(self):
        p = self.prog(main_src('try { print(http.get("http://[::1]:9/")) } catch e { print(e.kind) }\n'
                               'try { print(http.get("http://[::2]:9/")) } catch e { print(e.kind) }',
                               'allow net ["[::1]:9"]\nallow io'))
        self.assertEqual(p.run().splitlines(), ["io", "capability"])


class T_C5(unittest.TestCase):
    def test_hint(self):
        [d] = diags('allow net ["*"]\nfn main() { }\n')
        self.assertEqual(d.code, "E311")
        self.assertNotIn("bare", d.hint)
        self.assertIn('allow net ["api.example.com"]', d.hint)
        self.assertIn("matches no host", d.message)


# ====================================================================== C6/C7/C8. docs vs code

def readme_blocks(name: str) -> list[str]:
    with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        return re.findall(r"```(?:sipar|rust)\n(.*?)```", fh.read(), re.S)


def spec_section(n: int) -> str:
    with open(os.path.join(ROOT, "SPEC.md"), encoding="utf-8") as fh:
        text = fh.read()
    return text.split(f"\n## {n}.", 1)[1].split("\n## ", 1)[0]


class T_C6(unittest.TestCase):
    def test_readme_blocks(self):
        blocks = readme_blocks("README.md")
        self.assertGreaterEqual(len(blocks), 2)
        for i, b in enumerate(blocks):
            with self.subTest(block=i):
                self.assertEqual([(d.code, d.message) for d in diags(b, f"block{i}.sipar")], [])

    def test_taste_runs(self):
        [taste] = [b for b in readme_blocks("README.md") if "try it" in b]
        d = tmpdir(self)
        os.makedirs(os.path.join(d, "out"))
        path = write(d, "taste.sipar", taste)
        old = os.getcwd()
        os.chdir(d)
        try:
            rc, out, err = cli("run", "taste.sipar")
        finally:
            os.chdir(old)
        self.assertEqual(rc, 0, err)
        self.assertTrue(out.strip())
        self.assertTrue(os.listdir(os.path.join(d, "out")))
        self.assertTrue(os.path.isfile(path))


class T_C7(unittest.TestCase):
    def test_spec_has_s5(self):
        rc, out, _ = cli("spec")
        self.assertEqual(rc, 0)
        self.assertIn("## 5. Standard library", out)
        for line in spec_section(5).splitlines():
            if line.strip():
                with self.subTest(line=line[:40]):
                    self.assertIn(line.rstrip(), out)


class T_C8(unittest.TestCase):
    def test_spec_matches_stdlib(self):
        from sipar.stdlib import FUNCTIONS, METHODS
        s5 = spec_section(5)
        parts = {"Str": s5.split("Methods — Str:", 1)[1].split("List:", 1)[0],
                 "List": s5.split("List:", 1)[1].split("A list holds", 1)[0],
                 "Map": s5.split("Map:", 1)[1].split("Functions:", 1)[0]}

        def call_re(name: str, params) -> str:
            ps = r",\s*".join(re.escape(p) + r"(?::\s*[^,)]+)?" for p, _ in params)
            return re.escape(name) + r"\(" + ps + r"\)"

        for ty, ms in METHODS.items():
            for name, sig in ms.items():
                with self.subTest(method=f"{ty}.{name}"):
                    pat = (call_re(name, sig.params) if sig.params else
                           r"(?<![\w.])" + re.escape(name) + r"(?:\(\))?(?![\w(])")
                    self.assertRegex(parts[ty], pat)
        for name, sig in FUNCTIONS.items():
            with self.subTest(fn=name):
                self.assertRegex(s5, call_re(name, sig.params))


# ====================================================================== C9/C10. hints, BOM

BAD_SOURCES = ["fn main() { let x = 12a }", "fn main() {", "@max_steps(x)\nai fn f() -> Str { \"x\" }",
               "@model(\"m\")\nfn main() { }", "enum E { a, a }\nfn main() { }", "fn f(a: Int, a: Int) { }",
               "type R = { a: Int, a: Int }", "enum E { }", "fn main() { f(a: 1, 2) }", "fn main() { f(a: 1, a: 2) }",
               "fn let() { }", "fn main() { let x: List[Int] = [\"a\"] }", "fn main() { print(y) }",
               "allow net\nfn main() { }", "allow net [\"a:b:c\"]\nfn main() { }", "fn main() { 1 +  }",
               "fn main() { let x = \"abc }", "fn main() uses ai { }", "type R = { a: Nope }\nfn main() { }"]


class T_C9(unittest.TestCase):
    def test_no_empty_hint(self):
        for src in BAD_SOURCES:
            with self.subTest(src=src):
                ds = diags(src)
                self.assertTrue(ds, src)
                for d in ds:
                    self.assertTrue(d.hint.strip(), (d.code, d.message))

    def test_specific_hints(self):
        for src, code, words in (("fn main() {", "E104", "'}'"), ("enum E { }", "E201", "enum Color"),
                                 ("fn main() { f(a: 1, 2) }", "E114", "positional"),
                                 ("fn let() { }", None, "keywords are reserved"),
                                 ('fn f() { let a = ["a"].sum() }', "E214", "xs.map(fn(x) => x.n).sum()"),
                                 ("type R = { a: Int }\nfn f(r: List[R]) { let s = r.sort_by(fn(x) => x) }", "E214",
                                  "xs.sort_by(fn(x) => x.name)")):
            with self.subTest(src=src):
                d = [x for x in diags(src) if code is None or x.code == code][0]
                self.assertIn(words, d.hint)

    def test_fallback(self):
        d = Diagnostic("E999", "error", "x", "f.sipar", 1, 1)
        self.assertIn("E999", d.hint)
        self.assertIn("docs/ERRORS.md", d.hint)


class T_C10(unittest.TestCase):
    def test_bom(self):
        d = tmpdir(self)
        path = write(d, "bom.sipar", b'\xef\xbb\xbfallow io\nfn main() uses io { print("hi") }\n')
        self.assertEqual(cli("check", path)[0], 0)
        rc, out, err = cli("run", path)
        self.assertEqual((rc, out), (0, "hi\n"), err)
        self.assertEqual(diags('﻿fn main() { }\n'), [])


# ====================================================================== C11/C12/C16. docs text

def doc(name: str) -> str:
    with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        return fh.read()


class T_C11(unittest.TestCase):
    def test_errors_md(self):
        e306 = doc("docs/ERRORS.md").split("### E306", 1)[1].split("### ", 1)[0]
        self.assertIn("secret", e306)
        self.assertIn("memory", e306)


class T_C12(Base):
    def test_typo(self):
        e = self.prog(main_src('print(env.secret("R4K"))', 'allow secret ["R4K"]\nallow io')).error(env=ENV)
        self.assertIn("http header values", e.message)
        self.assertNotIn("headers values", e.message)
        for name in ("SPEC.md", "README.md", "docs/ERRORS.md"):
            self.assertNotIn("headers values", doc(name))


class T_C16(unittest.TestCase):
    def test_readme_ru(self):
        ru = doc("README.ru.md")
        for words in ("sipar check", "«secret:", "trust(x, ", "approve(x, ", "json.encode"):
            with self.subTest(words=words):
                self.assertIn(words, ru)


# ====================================================================== C13/C14/C15. CLI

class T_C13(unittest.TestCase):
    def setUp(self):
        self.d = tmpdir(self)
        self.prog = write(self.d, "p.sipar", 'allow io\nfn main() uses io { print("x") }\n')

    def test_replay_directory(self):
        rc, _, err = cli("replay", self.prog, self.d)
        self.assertEqual(rc, 2)
        self.assertIn("is a directory", err)

    def test_replay_missing(self):                # coverage
        rc, _, err = cli("replay", self.prog, os.path.join(self.d, "nope.jsonl"))
        self.assertEqual(rc, 2)
        self.assertIn("no such journal", err)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root reads every file")
    def test_replay_unreadable(self):
        j = write(self.d, "np.jsonl", '{"seq": 1}\n')
        os.chmod(j, 0)
        self.addCleanup(os.chmod, j, stat.S_IRUSR | stat.S_IWUSR)
        for cmd in (("replay", self.prog, j), ("trace", j)):
            with self.subTest(cmd=cmd[0]):
                rc, _, err = cli(*cmd)
                self.assertEqual(rc, 2, err)
                self.assertIn("cannot read", err)
                self.assertNotIn("Traceback", err)

    def test_replay_unused(self):
        self.assertEqual(cli("run", self.prog)[0], 0)
        [jp] = runs(self.d)
        write(self.d, "p.sipar", 'allow io\nfn main() uses io { }\n')
        with open(jp, encoding="utf-8") as fh:
            first = fh.readline()
        j2 = write(self.d, "j2.jsonl", first + json.dumps({"seq": 2, "kind": "print", "request": "x"}) + "\n")
        rc, _, err = cli("replay", self.prog, j2)
        self.assertEqual(rc, 1, err)
        self.assertIn("p.sipar:1:1: runtime error[replay]", err)
        self.assertIn("were not used", err)
        self.assertIn("j2.jsonl", err)

    def test_no_main(self):
        path = write(self.d, "nm.sipar", "fn helper() { }\n")
        rc, _, err = cli("run", path)
        self.assertEqual(rc, 1)
        self.assertIn("nm.sipar:1:1: runtime error[type]: the program has no 'fn main()'", err)
        self.assertEqual(runs(self.d), [])


class T_C14(unittest.TestCase):
    def test_empty_file(self):
        d = tmpdir(self)
        path = write(d, "empty.sipar", "")
        rc, _, err = cli("run", path)
        self.assertEqual(rc, 1)
        self.assertIn("has no 'fn main()'", err)
        self.assertNotIn("journal:", err)
        self.assertEqual(runs(d), [])

    def test_extra_args(self):
        d = tmpdir(self)
        path = write(d, "na.sipar", "fn main() { }\n")
        rc, _, err = cli("run", path, "x", "y")
        self.assertEqual(rc, 1)
        self.assertIn("na.sipar:1:1: runtime error[value]: fn main() takes no arguments, but 2 were given", err)
        self.assertEqual(runs(d), [])
        self.assertEqual(cli("run", path)[0], 0)                                  # guard

    def test_args_ok(self):                                    # guard
        d = tmpdir(self)
        path = write(d, "a.sipar", "allow io\nfn main(args: List[Str]) uses io { print(args) }\n")
        self.assertEqual(cli("run", path, "x", "y")[:2], (0, '["x", "y"]\n'))


class T_C15(unittest.TestCase):
    def test_check_json_unreadable(self):
        d = tmpdir(self)
        rc, out, _ = cli("check", "--json", os.path.join(d, "nope.sipar"))
        self.assertEqual(rc, 2)
        [item] = json.loads(out)
        self.assertEqual((item["code"], item["severity"]), ("usage", "error"))
        self.assertIn("nope.sipar", item["message"])

    def test_check_two_files(self):
        rc, _, err = cli("check", "a.sipar", "b.sipar")
        self.assertEqual(rc, 2)
        self.assertIn("usage: sipar check", err)
        self.assertIn("unrecognized arguments: b.sipar", err)

    def test_interrupt_journal_path(self):
        d = tmpdir(self)
        path = write(d, "p.sipar", "fn main() { }\n")
        with mock.patch.object(Interp, "run_main", side_effect=KeyboardInterrupt):
            rc, _, err = cli("run", path)
        self.assertEqual(rc, 1)
        self.assertIn("sipar: interrupted", err)
        [jp] = runs(d)
        self.assertIn(f"journal: {jp}", err)

    def test_space_entry_strict(self):
        self.assertEqual(codes('allow net [" example.com"]'), [("E310", "error")])
        self.assertEqual(codes('allow net ["example.com "]'), [("E310", "error")])
        self.assertFalse(Caps.host_matches("example.com", 80, " example.com"))

    def test_enum_name_message(self):
        [d] = diags("enum http { a, b }\nfn main() { }\n")
        self.assertEqual(d.code, "E202")
        self.assertIn("enum name", d.message)
        [d] = diags("type json = { a: Int }\nfn main() { }\n")
        self.assertIn("type name", d.message)

    def test_spec_tag_order(self):
        text = spec_text()
        post = [line for line in text.splitlines() if line.startswith("  http.post(")][0]
        self.assertIn("untrusted not allowed in body,url", post)
        self.assertIn("secret not allowed in body,url", post)
        save = [line for line in text.splitlines() if line.startswith("  memory.save(")][0]
        self.assertIn("secret not allowed in key,value", save)


# ====================================================================== M. mutation survivors

class T_M(Base):
    def test_ldict_pick_len_keys(self):                # coverage
        files = {"idx.txt": "0", "out/.keep": ""}
        head = 'allow fs.read ["idx.txt"]\nallow fs.write ["out"]\nallow io'
        pre = 'let k = fs.read("idx.txt")\nlet mm = ["0": ["b": 5], "1": ["b": 6]]\nlet inner = mm[k]\n'
        for expr in ("inner.len()", "inner.keys()", "inner.values()"):
            with self.subTest(expr=expr):
                p = self.prog(main_src(pre + f'fs.write("out/a.txt", "{{{expr}}}")', head), files)
                self.assertEqual(p.error().kind, "taint")
        p = self.prog(main_src(pre + 'fs.write("out/a.txt", "{mm.len()}")\nprint("ok")', head), files)
        self.assertEqual(p.run(), "ok\n")                                          # guard

    def test_pop_check_mutable(self):                # coverage
        files = {"idx.txt": "0"}
        head = 'allow fs.read ["idx.txt"]\nallow io'
        pre = 'let i = fs.read("idx.txt") as Int\nlet ls = [[1, 2], [3]]\nlet inner = ls[i]\n'
        for stmt in ("print(inner.pop())", "inner.push(9)"):
            with self.subTest(stmt=stmt):
                e = self.prog(main_src(pre + stmt, head), files).error()
                self.assertEqual(e.kind, "value")
                self.assertIn("read-only copy", e.message)
        p = self.prog(main_src(pre + "print(ls[i].pop())\nprint(ls)", head), files)
        self.assertEqual(p.run().splitlines(), ["2", "[[1], [3]]"])

    def test_push_cap_boundary(self):                # coverage
        from sipar.runtime import builtins
        with mock.patch.object(builtins, "MAX_ITEMS", 50):
            ok = self.prog(main_src('var l: List[Int] = []\nfor i in 0..50 { l.push(i) }\nprint(l.len())', "allow io"))
            self.assertEqual(ok.run(), "50\n")
            e = self.prog(main_src('var l: List[Int] = []\nfor i in 0..51 { l.push(i) }', "allow io")).error()
            self.assertEqual(e.kind, "value")
            self.assertEqual(e.message, "push: result too large (51 > 50)")

    def test_max_steps_one(self):                # coverage
        src = ('allow ai\n/// T.\nfn t() -> Str { "x" }\n@max_steps(1)\nagent fn a(q: Str) -> Str {\n    tools [t]\n'
               '    "do {q}"\n}\nfn main() uses ai { print(a("x")) }\n')
        self.assertEqual(diags(src), [])
        self.assertEqual(self.prog(src).run(script={"a": [{"final": "ok"}]}), "ok\n")

    def test_port_bounds(self):
        self.assertEqual(codes('allow net ["example.com:65535", "example.com:1"]'), [])
        for port in ("65536", "0", "99999", "-1", "８０"):
            with self.subTest(port=port):
                ds = diags(f'allow net ["example.com:{port}"]\nfn main() {{ }}\n')
                self.assertEqual([d.code for d in ds], ["E310"])
                self.assertIn("invalid port", ds[0].message)
        self.assertTrue(Caps.host_matches("example.com", 65535, "example.com:65535"))
        self.assertFalse(Caps.host_matches("example.com", 65536, "example.com:65536"))

    def test_bad_host_with_port(self):
        for entry in ("bad_host!:80", "a b:80", "-x.com:80", "x..com:80"):
            with self.subTest(entry=entry):
                ds = diags(f'allow net ["{entry}"]\nfn main() {{ }}\n')
                self.assertEqual([d.code for d in ds], ["E310"])
                self.assertIn("not a host name", ds[0].message)

    def test_fixture_name_sha12(self):                # coverage
        for name in ("a b", "x" * 100, "..hidden", "ünï/code"):
            with self.subTest(name=name):
                got = _fixture_name(name)
                digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]
                self.assertTrue(got.endswith("-" + digest), got)
                self.assertEqual(len(got.rsplit("-", 1)[1]), 12)
                self.assertFalse(got.startswith("."))
                self.assertLessEqual(len(got), 60 + 13)
        self.assertNotEqual(_fixture_name("a b"), _fixture_name("a_b"))

    def test_tampered_memory_path(self):                # coverage
        d = tmpdir(self)
        path = write(d, "prog.sipar", 'allow memory\nallow io\nfn main() uses memory, io {\n'
                                    '    let n: Int? = memory.load("k")\n    print(n ?? 0)\n}\n')
        for value, labels, ok in ((5, [[[{"own": True}], ["untrusted:x"]]], False),
                                  (5, [[[], ["untrusted:x"]]], True)):                  # guard: leaf path
            with self.subTest(value=value, labels=labels):
                store = {"version": 1, "entries": {"k": {"value": value, "labels": labels, "enc": 2}}}
                write(d, os.path.join(".sipar", "memory", "prog.json"), json.dumps(store))
                rc, out, err = cli("run", path)
                if ok:
                    self.assertEqual((rc, out), (0, "5\n"), err)
                else:
                    self.assertEqual(rc, 1)
                    self.assertIn("error[decode]", err)
                    self.assertIn("do not fit", err)


# ====================================================================== M (cli.py). mutation survivors

class T_MC(unittest.TestCase):
    """Exact CLI output for the paths the mutation run of sipar/cli.py found untested."""          # coverage

    BAD = 'fn main() {\n    let x: Int = "s"\n    print("RAN")\n}\n'

    def test_check_text_exact(self):
        d = tmpdir(self)
        ok = write(d, "ок.sipar", "fn main() { }\n")
        self.assertEqual(cli("check", ok), (0, f"{ok}: ok\n", ""))
        bad = write(d, "bad.sipar", self.BAD)
        ds = diags(self.BAD, bad)
        n_err = sum(d.severity == "error" for d in ds)
        self.assertGreaterEqual(n_err, 1)
        want = "".join(x.render(self.BAD) + "\n" for x in ds) + f"{n_err} error(s), {len(ds) - n_err} warning(s)\n"
        self.assertEqual(cli("check", bad), (1, want, ""))

    def test_check_json_exact(self):
        d = tmpdir(self)
        bad = write(d, "плохо.sipar", self.BAD)
        want = json.dumps([x.to_dict() for x in diags(self.BAD, bad)], ensure_ascii=False, indent=2) + "\n"
        self.assertEqual(cli("check", "--json", bad), (1, want, ""))
        miss = os.path.join(d, "нет.sipar")
        want = json.dumps([{"code": "usage", "severity": "error", "file": miss, "line": 0, "col": 0,
                            "message": f"no such file: {miss}", "hint": USAGE_HINT}],
                          ensure_ascii=False, indent=2) + "\n"
        self.assertEqual(cli("check", "--json", miss), (2, want, ""))

    def test_no_checker(self):
        """Without the checker module: check and run parse only, and a syntax error still stops them."""
        d = tmpdir(self)
        ok = write(d, "ok.sipar", 'allow io\nfn main() uses io { print("hi") }\n')
        bad = write(d, "syn.sipar", "fn main( {\n")
        with mock.patch("sipar.cli._checker", return_value=None):
            self.assertEqual(cli("check", ok), (0, f"{ok}: syntax ok (checker not installed)\n", ""))
            rc, out, err = cli("check", bad)
            self.assertEqual(rc, 1)
            self.assertTrue(out.endswith("\n1 error(s), 0 warning(s)\n"), out)
            self.assertIn("error[", out)
            rc, out, err = cli("run", ok)
            self.assertEqual((rc, out), (0, "hi\n"), err)
            rc, out, err = cli("run", bad)
            self.assertEqual((rc, out), (1, ""))
            self.assertTrue(err.startswith(f"{bad}:1:10: error[E110]") and err.endswith("\n"), err)
            self.assertNotIn("Traceback", err)
            self.assertEqual(len(runs(d)), 1)             # only the good run wrote a journal

    def test_checker_found(self):
        from sipar.cli import _checker
        self.assertIs(_checker(), check_source)

    def test_run_refuses_checked_errors(self):
        d = tmpdir(self)
        bad = write(d, "bad.sipar", self.BAD)
        rc, out, err = cli("run", bad)
        self.assertEqual((rc, out), (1, ""))
        self.assertTrue(err.endswith("sipar: 1 error(s); not running\n"), err)
        self.assertEqual(runs(d), [])

    def test_run_with_warnings_only(self):
        d = tmpdir(self)
        src = 'allow net ["*.com"]\nallow io\nfn main() uses io { print("RAN") }\n'
        self.assertEqual([x.severity for x in diags(src)], ["warning"])
        prog = write(d, "w.sipar", src)
        rc, out, err = cli("run", prog)
        self.assertEqual((rc, out), (0, "RAN\n"), err)
        self.assertIn("warning[E311]", err)

    def test_run_uses_checked_program(self):
        """run executes the program the checker annotated (Int -> Float widening), not a fresh parse."""
        d = tmpdir(self)
        prog = write(d, "f.sipar", 'allow io\nfn main() uses io {\n    let a: List[Float] = [1, 3]\n    print(a)\n}\n')
        self.assertEqual(cli("run", prog)[:2], (0, "[1.0, 3.0]\n"))      # an unchecked parse prints "[1, 3]"

    def test_read_directory(self):
        d = tmpdir(self)
        self.assertEqual(cli("check", d), (2, "", f"sipar: cannot read {d}: is a directory\n"))   # round 9, F4
        prog = write(d, "p.sipar", "fn main() { }\n")
        self.assertEqual(cli("replay", prog, d), (2, "", f"sipar: {d} is a directory, not a journal file\n"))

    def test_runtime_error_gets_file(self):
        from sipar.cli import _render_runtime_error
        self.assertIn("f.sipar", _render_runtime_error(SiparRuntimeError("value", "boom", 1, 1, ""), "f.sipar"))
        self.assertIn("g.sipar", _render_runtime_error(SiparRuntimeError("value", "boom", 1, 1, "g.sipar"), "f.sipar"))
        self.assertNotIn("f.sipar", _render_runtime_error(SiparRuntimeError("value", "boom", 1, 1, "g.sipar"), "f.sipar"))

    def test_main_errors_exact(self):
        """main(): every except branch, with the exact text and exit code."""
        import sys
        cases = [
            (KeyboardInterrupt(), 1, "\nsipar: interrupted\n"),
            (SiparRuntimeError("io", "cannot write the journal", 1, 1, ""), 1, None),
            (ValueError("x"), 1, "sipar: internal error (ValueError); set SIPAR_DEBUG=1 for details\n"),
        ]
        for exc, code, want in cases:
            with self.subTest(exc=type(exc).__name__), mock.patch.dict("sipar.cli.COMMANDS",
                                                                     {"spec": mock.Mock(side_effect=exc)}):
                rc, out, err = cli("spec")
                self.assertEqual((rc, out), (code, ""))
                if want is None:
                    self.assertEqual(err, "runtime error[io]: cannot write the journal\n")   # no ":1:1:" without a file
                else:
                    self.assertEqual(err, want)
        with mock.patch.dict("sipar.cli.COMMANDS", {"spec": mock.Mock(side_effect=ValueError("x"))}):
            rc, out, err = cli("spec", env={"SIPAR_DEBUG": "1"})
        self.assertIn("Traceback", err)
        self.assertTrue(err.endswith("sipar: internal error (ValueError); set SIPAR_DEBUG=1 for details\n"))
        saved = sys.stdout
        try:
            with mock.patch.dict("sipar.cli.COMMANDS", {"spec": mock.Mock(side_effect=BrokenPipeError())}):
                self.assertEqual(cli("spec"), (141, "", ""))  # round 5, C11: 128 + SIGPIPE
        finally:
            if sys.stdout is not saved:
                sys.stdout.close()
            sys.stdout = saved

    def test_usage_paths(self):
        rc, out, err = cli()
        self.assertEqual((rc, out), (2, ""))
        self.assertTrue(err.startswith("usage: sipar"), err)
        rc, out, err = cli("bogus")
        self.assertEqual((rc, out), (2, ""))
        # argparse quotes the choices differently across Python versions (3.12.8 drops the quotes): accept both
        # (round 5, C10)
        self.assertRegex(err, r"\Ausage: sipar \[-h\] \[--version\] command \.\.\.\nsipar: argument command: "
                              r"invalid choice: '?bogus'? \(choose from '?run'?, '?check'?, '?test'?, '?replay'?, "
                              r"'?trace'?, '?spec'?, '?lsp'?\)\n\Z")
        so = io.StringIO()
        with contextlib.redirect_stdout(so):
            rc, out, err = cli("test", "--help")
        self.assertEqual(rc, 0)
        self.assertIn("record fixtures to .sipar/fixtures/<name>-<hash>.jsonl", so.getvalue())

    def test_trace_paths(self):
        d = tmpdir(self)
        bad = write(d, "j.jsonl", "not json\n")
        self.assertEqual(cli("trace", bad), (1, "", "sipar: trace: j.jsonl line 1 is not valid JSON\n".replace(
            "sipar: trace", "sipar trace")))
        prog = write(d, "p.sipar", 'allow io\nfn main() uses io { print("hi") }\n')
        self.assertEqual(cli("run", prog)[0], 0)
        j = runs(d)[0]
        rc, out, err = cli("trace", "--json", j)
        from sipar.trace import read_entries, summarize
        with open(j, encoding="utf-8") as fh:
            s = summarize(read_entries(fh.read(), os.path.basename(j)))
        self.assertEqual((rc, out, err), (0, json.dumps(s, ensure_ascii=False, indent=2) + "\n", ""))
        rc, out, err = cli("trace", j)
        self.assertEqual((rc, err), (0, ""))
        self.assertNotEqual(out, "")
        self.assertFalse(out.lstrip().startswith("{"), out)
        hand = write(d, "h.jsonl", json.dumps({"seq": 1, "kind": "ai", "request": {"fn": "résumé"}, "fn": "résumé",
                                               "t": 1.0, "ms": 2.0, "response": {"text": "x"}, "labels": []}) + "\n")
        rc, out, err = cli("trace", "--json", hand)
        self.assertEqual((rc, err), (0, ""))
        self.assertIn('"résumé"', out)
        self.assertIn("résumé", json.loads(out)["functions"])

    def test_spec_tables(self):
        from sipar.stdlib import ATTRIBUTES, BUDGET_LIMITS, FUNCTIONS, METHODS
        text = spec_text()
        lines = text.splitlines()
        for head in ("## Standard library (generated from sipar/stdlib.py)", "Functions:"):
            self.assertIn(head, lines)
        for ty in METHODS:
            self.assertIn(f"{ty} methods:", lines)
        self.assertIn("Attributes on ai/agent fn: " + ", ".join(f"@{k}({v})" for k, v in ATTRIBUTES.items()), lines)
        self.assertIn("Budget limits: " + ", ".join(f"{k}: {v}" for k, v in BUDGET_LIMITS.items()), lines)

        def line(name):
            return next(x for x in lines if x.startswith(f"  {name}("))
        for name, s in FUNCTIONS.items():
            with self.subTest(name=name):
                ln = line(name)
                self.assertEqual(f"result untrusted:{s.source}" in ln, bool(s.source))
                self.assertEqual("result secret" in ln, bool(s.secret))
                self.assertEqual("secret not allowed in" in ln, bool(s.no_secret))
                self.assertEqual("untrusted not allowed in" in ln, bool(s.sink))
                self.assertEqual("   [" in ln, bool(s.effects or s.source or s.secret or s.sink
                                                                     or s.no_secret))
                if s.doc:
                    self.assertTrue(ln.endswith("  — " + s.doc), ln)


if __name__ == "__main__":
    unittest.main()
