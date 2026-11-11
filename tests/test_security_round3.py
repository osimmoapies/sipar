"""Security round 3: regression tests for the critic's findings 1-9.

Every test not marked "guard" failed on the code before the fix (pre-fix copy in /tmp/sipar_r3_old, run with
PYTHONPATH pointing at it). Proof programs: /tmp/sipar_attack3."""
from __future__ import annotations

import json
import os
import unittest

from rt_helpers import ROOT, Prog, main_src

from sipar import ast as A
from sipar.checker import check, check_source
from sipar.errors import SiparRuntimeError, SiparSyntaxError
from sipar.parser import parse

SECRET = "hunter2xyz"
ENV = {"R3K": SECRET}
SEC_HEAD = 'allow secret ["R3K"]\nallow io\nallow fs.write ["./out"]'
OUT = {"out/.keep": ""}

# untrusted source: an ai fn whose reply is decided by the mock script
U_HEAD = '''allow ai
allow io
allow fs.write ["./out"]
type R = { n: Int, k: Str, flag: Bool }
type C = { c: Str }
ai fn u() -> R { "give" }
'''
U_SCRIPT = {"u": [{"n": 1, "k": "b", "flag": True}]}


class Base(unittest.TestCase):
    def prog(self, src: str, files: dict | None = None) -> Prog:
        p = Prog(src, files)
        self.addCleanup(p.cleanup)
        return p

    def secret_run(self, body: str, head: str = "") -> str:
        p = self.prog(main_src('let k = env.secret("R3K")\n' + body, SEC_HEAD + "\n" + head), OUT)
        return p.run(env=ENV)

    def secret_blocked(self, body: str, head: str = ""):
        """body must try to print a value derived from the secret: the print is blocked (taint)."""
        p = self.prog(main_src('let k = env.secret("R3K")\n' + body, SEC_HEAD + "\n" + head), OUT)
        e = p.error(env=ENV)
        self.assertEqual(e.kind, "taint", e.message)
        self.assertIn("secret:R3K", e.message)
        return p

    def untrusted_write(self, expr: str, head: str = "", setup: str = "") -> SiparRuntimeError | str:
        """fs.write of expr (derived from the untrusted reply r): returns the error or 'written'."""
        src = main_src(f'let r = u()\n{setup}\nfs.write("out/p.txt", {expr})\nprint("written")', U_HEAD + head)
        p = self.prog(src, OUT)
        try:
            p.run(script=json.loads(json.dumps(U_SCRIPT)))
            return "written"
        except SiparRuntimeError as e:
            return e

    def assert_untrusted_blocked(self, expr: str, setup: str = ""):
        r = self.untrusted_write(expr, setup=setup)
        self.assertIsInstance(r, SiparRuntimeError, f"{expr} was written")
        self.assertEqual(r.kind, "taint", r.message)
        self.assertIn("untrusted", r.message)


# ====================================================================== 1. secret through selection

class T1Selection(Base):
    def test_1_1_map_get_secret_key(self):                     # sl2.sipar
        self.secret_blocked('''
var abc: Map[Str] = [:]
for c in "abcdefghijklmnopqrstuvwxyz0123456789".split("") { abc[c] = c }
var out = ""
for i in 0..k.len() { out = out + (abc.get(k[i]) ?? "?") }
print(out)''')

    def test_1_2_take_last(self):                              # sl3.sipar
        self.secret_blocked('''
let al = "abcdefghijklmnopqrstuvwxyz0123456789".split("")
var out = ""
for i in 0..k.len() {
    let n = al.index_of(k[i]) ?? 0
    out = out + (al.take(n + 1).last() ?? "?")
}
print(out)''')

    def test_1_3_take_and_slice_count(self):                   # sl.sipar
        ruler = 'let ruler = "0123456789abcdefghijklmnop".split("")\n'
        self.secret_blocked(ruler + 'print(ruler.take(k.len()).join(""))')
        self.secret_blocked(ruler + 'print(ruler[0..k.len()].join(""))')
        self.secret_blocked(ruler + 'print(ruler.take(k.len()).len())')

    def test_1_4_remove(self):
        self.secret_blocked('var m = ["h": "H", "x": "X"]\nprint(m.remove(k[0]) ?? "-")')

    def test_1_5_skip(self):
        self.secret_blocked('let al = "0123456789abcdef".split("")\nprint(al.skip(k.len()).first() ?? "-")')

    def test_1_6_sort_by(self):
        self.secret_blocked('''
let names = ["a", "b"]
let s = names.sort_by(fn(x: Str) -> Int => if x == "a" { k.len() } else { 5 })
print(s.first() ?? "-")''')

    def test_1_7_sort_order(self):
        # the constant 5 ends up first only because the secret's length is larger: the order is labelled
        self.secret_blocked('let s = [k.len(), 5].sort()\nprint(s[0])')

    def test_1_8_bool_list_len(self):
        # Bool items are never labelled, but a list picked by a labelled count carries the label itself
        self.secret_blocked('let bs = [true, false, true, true, false, true, true, true, true, true, true, true]\n'
                            'print(bs.take(k.len()).len())')

    def test_1_9_record_field(self):
        self.secret_blocked('let cs = [C { c: "zero" }, C { c: "one" }]\n'
                            'print(cs[k.len() - 9].c)', head="type C = { c: Str }")

    def test_1_10_nested_list(self):
        self.secret_blocked('let g = [["zero"], ["one"]]\nprint(g[k.len() - 9][0])')

    def test_1_11_map_record(self):
        self.secret_blocked('let m = ["h": C { c: "H" }, "x": C { c: "X" }]\nprint(m[k[0]].c)',
                            head="type C = { c: Str }")

    def test_1_12_bool_enum_declassified(self):                # guard: SPEC §6 decision
        out = self.secret_run('''
let flags = ["h": true, "x": false]
let kinds = ["h": Mood.happy, "x": Mood.sad]
print(flags[k[0]])
print(flags.get(k[0]) ?? false)
print(kinds[k[0]])
print([false, true][k.len() - 9])''', head="enum Mood { happy, sad }")
        self.assertEqual(out.split(), ["true", "true", "happy", "true"])

    def test_1_13_index_and_get_same(self):
        for expr in ("m[r.k]", 'm.get(r.k) ?? ""'):
            with self.subTest(expr=expr):
                self.assert_untrusted_blocked(expr, setup='let m = ["a": "safe", "b": "danger"]')

    def test_1_14_aliasing_kept(self):
        src = main_src('''
let r = u()
var cs = [C { c: "a" }, C { c: "b" }]
cs[r.n].c = "changed"
let t = cs[r.n]
t.c = "again"
var m: Map[List[Str]] = ["a": [], "b": []]
m[r.k].push("x")
m[r.k][0] = "y"
let n = m[r.k].pop()
print(trust(cs[1].c, "t"))
print(trust(m["b"].len(), "t"))
print(trust(n ?? "-", "t"))''', U_HEAD)
        out = self.prog(src).run(script=json.loads(json.dumps(U_SCRIPT)))
        self.assertEqual(out.split(), ["again", "0", "y"])

    def test_1_15_frozen_copy(self):
        src = main_src('''
let r = u()
var m: Map[List[Str]] = ["a": [], "b": []]
let g = m[r.k]
g.push("lost?")''', U_HEAD)
        e = self.prog(src).error(script=json.loads(json.dumps(U_SCRIPT)))
        self.assertEqual(e.kind, "value")
        self.assertIn("read-only copy", e.message)

    def test_1_16_write_at_labelled_index(self):
        self.secret_blocked('var l = ["_", "_", "_"]\nl[k.len() - 9] = "X"\nprint(l.join(""))')
        self.secret_blocked('var m: Map[Str] = [:]\nm[k] = "X"\nprint(m.values().join(""))')

    def test_1_17_fn_pick(self):
        self.secret_blocked('let fs = [fn() -> Str => "zero", fn() -> Str => "one"]\n'
                            'let f = fs[k.len() - 9]\nprint(f())')

    def test_1_18_derived_ops(self):
        pick = 'let p = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"].take(k.len())\n'
        for tail in ('print(p.map(fn(x: Str) -> Str => x).join(""))',
                     'print(p.reduce("", fn(a: Str, x: Str) -> Str => a + x))',
                     'var s = ""\nfor x in p { s = s + x }\nprint(s)',
                     'print(p.reverse()[0])', 'print(p.pop() ?? "-")'):
            with self.subTest(tail=tail):
                self.secret_blocked(pick + tail)

    def test_1_19_trust_container(self):
        # untrusted pick: trust removes the label (container's own label included)
        self.assertEqual(self.untrusted_write('trust(["x", "y"][0..r.n], "ok").join(",")'), "written")
        # secret pick: trust keeps the secret label
        self.secret_blocked('let p = ["a", "b"].take(k.len() - 9)\nprint(trust(p, "t").join(""))')

    def test_1_20_memory(self):
        src = '''allow ai
allow io
allow memory
allow fs.write ["./out"]
type R = { n: Int, k: Str, flag: Bool }
ai fn u() -> R { "give" }
fn main() uses ai, memory, io {
    let r = u()
    let flags = [true, false, true, true]
    memory.save("p", flags.take(r.n + 1))
}
'''
        p = self.prog(src, OUT)
        p.run(script=json.loads(json.dumps(U_SCRIPT)))
        q_src = '''allow io
allow memory
allow fs.write ["./out"]
fn main() uses memory, fs.write, io {
    let p: List[Bool]? = memory.load("p")
    let xs = p ?? []
    fs.write("out/n.txt", "{xs.len()}")
}
'''
        q = Prog(q_src)
        self.addCleanup(q.cleanup)
        q.path = p.path         # same program path: same memory store (.sipar/memory/prog.json)
        q.program = parse(q_src, q.path)
        self.assertEqual([d.code for d in check(q.program, q_src) if d.severity == "error"], [])
        e = q.error()
        self.assertEqual(e.kind, "taint", e.message)
        self.assertIn("untrusted", e.message)

    def test_1_21_unlabelled_unchanged(self):                  # guard: no over-taint
        out = self.secret_run('''
let al = "abc".split("")
let m = ["a": [1, 2], "b": [3]]
var g = m["a"]
g.push(9)
print(al.take(2).join(""))
print(al[1])
print(m.get("b") ?? [])
print(m["a"])
print(["x": "y"].get("x") ?? "")''')
        self.assertEqual(out.split("\n")[:5], ["ab", "b", "[3]", "[1, 2, 9]", "y"])

    def test_1_22_api_plain(self):                             # guard: Python embedding gets plain values
        import sipar
        path = os.path.join(self.prog("").dir, "lib.sipar")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write('fn pick(xs: List[List[Int]], i: Int) -> List[Int] { xs[i] }\n')
        mod = sipar.load(path)
        self.assertEqual(mod.call("pick", [[1, 2], [3]], 1), [3])
        self.assertIs(type(mod.call("pick", [[1, 2], [3]], 0)), list)


# ====================================================================== 2. untrusted selection

class T2Untrusted(Base):
    FORMS = {
        "mapget": ('["a": "s", "b": "d"].get(r.k) ?? ""', ""),
        "mapidx": ('["a": "s", "b": "d"][r.k]', ""),
        "take": '["x", "y"].take(r.n).join(",")',
        "skip": '["x", "y"].skip(r.n).first() ?? ""',
        "remove": ('m.remove(r.k) ?? ""', 'var m = ["a": "s", "b": "d"]'),
        "sortby": '["a", "b"].sort_by(fn(x: Str) -> Int => if x == "a" { r.n } else { 0 }).join("")',
        "sortby2": '["a", "b"].sort_by(fn(x: Str) -> Str => if x == "a" { r.k } else { "a" })[0]',
        "listslice": '["x", "y"][0..r.n].join(",")',
        "idx-record": ('cs[r.n].c', 'let cs = [C { c: "s" }, C { c: "d" }]'),
        "idx-nested": '[["s"], ["d"]][r.n][0]',
        "mapidx-record": ('["a": C { c: "s" }, "b": C { c: "d" }][r.k].c', ""),
        "first-last": '["x", "y"].take(r.n).last() ?? ""',
        "range-take": '"{(0..5).take(r.n)}"',
    }

    def test_2_untrusted_forms(self):
        for name, form in self.FORMS.items():
            expr, setup = form if isinstance(form, tuple) else (form, "")
            with self.subTest(form=name):
                r = self.untrusted_write(expr, head="", setup=setup)
                self.assertIsInstance(r, SiparRuntimeError, f"{name}: written")
                self.assertEqual(r.kind, "taint", r.message)

    def test_2_documented_not_blocked(self):                   # guard: SPEC §6 documented limits
        cases = {
            "filter-bool": '["x", "y"].filter(fn(s: Str) -> Bool => r.flag).join("")',
            "for-range": '{ var s = ""; for i in 0..r.n { s = s + "x" }; s }',
            "pushmut": ('l[0]', 'var l = ["a"]\nl.push(r.k)\nl[0] = "const"'),
        }
        for name, form in cases.items():
            expr, setup = form if isinstance(form, tuple) else (form, "")
            with self.subTest(case=name):
                self.assertEqual(self.untrusted_write(expr, setup=setup), "written")


# ====================================================================== 3. budget limits

class T3Budget(Base):
    def test_3_budget_non_finite(self):
        for lim in ("seconds: 1e308 * 10.0", "usd: (1e308 * 10.0) - (1e308 * 10.0)", "seconds: 0.0 - (1e308 * 10.0)"):
            with self.subTest(lim=lim):
                p = self.prog(main_src(f'budget({lim}) {{ print("ran") }}', "allow io"))
                e = p.error()
                self.assertEqual(e.kind, "type", e.message)
                self.assertIn("finite", e.message)
                self.assertEqual(p.out, "")

    def test_3_budget_finite(self):                            # guard
        p = self.prog(main_src('budget(seconds: 30, usd: 0.5, ai_calls: 0) { print("ran") }', "allow io"))
        self.assertEqual(p.run(), "ran\n")


# ====================================================================== 4. fixture names

TEST_SRC = '''allow ai
ai fn f(x: Str) -> Str { "say {x}" }
fn main() { }
test "{A}" {
    assert f("1") == "{V}"
}
test "{B}" {
    assert f("1") == "{V}"
}
'''


class T4Fixtures(Base):
    def fixtures(self, p: Prog) -> list:
        return sorted(os.listdir(os.path.join(p.dir, ".sipar", "fixtures")))

    def test_4_fixture_names_unique(self):                     # fx/fx.sipar
        src = TEST_SRC.replace("{A}", "a b").replace("{B}", "a_b").replace("{V}", "one")
        p = self.prog(src)
        self.assertEqual(p.test(record=True, script={"f": ["one", "one"]})[:2], (2, 0))
        files = self.fixtures(p)
        self.assertEqual(len(files), 2, files)
        self.assertEqual(p.test(env={"SIPAR_MODEL": ""})[:2], (2, 0))      # both replay offline

    def test_4_old_fixture_loads(self):
        from sipar.runtime.interp import _fixture_name, _old_fixture_name
        src = TEST_SRC.replace("{A}", "alpha").replace("{B}", "beta").replace("{V}", "one")
        p = self.prog(src)
        p.test(record=True, script={"f": ["one", "one"]})
        fx = os.path.join(p.dir, ".sipar", "fixtures")
        os.rename(os.path.join(fx, _fixture_name("alpha") + ".jsonl"),
                  os.path.join(fx, _old_fixture_name("alpha") + ".jsonl"))
        self.assertEqual(p.test(env={"SIPAR_MODEL": ""})[:2], (2, 0))

    def test_4_old_fixture_ambiguous(self):
        src = TEST_SRC.replace("{A}", "a b").replace("{B}", "a_b").replace("{V}", "one")
        p = self.prog(src)
        fx = os.path.join(p.dir, ".sipar", "fixtures")
        os.makedirs(fx)
        # an old-style fixture a_b.jsonl may belong to either test: it must not be replayed for "a b"
        q = self.prog(TEST_SRC.replace("{A}", "a_b").replace("{B}", "zzz").replace("{V}", "two"))
        q.test(record=True, script={"f": ["two", "two"]})
        from sipar.runtime.interp import _fixture_name
        os.rename(os.path.join(q.dir, ".sipar", "fixtures", _fixture_name("a_b") + ".jsonl"),
                  os.path.join(fx, "a_b.jsonl"))
        passed, failed, out = p.test()
        # ignored: both tests make a fresh (unmocked) call instead of replaying the other test's answer "two"
        self.assertEqual(out.count("unmocked call"), 2, out)
        self.assertNotIn("assert", out)

    def test_4_odd_names(self):
        from sipar.runtime.interp import _fixture_name
        names = ["", "мой тест", "x" * 300, "../../etc/passwd", "a b", "a_b", "a/b", "a\\b"]
        out = [_fixture_name(n) for n in names]
        self.assertEqual(len(set(out)), len(names))
        for f in out:
            self.assertRegex(f, r"^[A-Za-z0-9_.-]{1,80}$")
            self.assertNotIn("/", f)
            self.assertFalse(f.startswith("."))


# ====================================================================== 5. allow scopes

def codes(src: str) -> list:
    _, ds = check_source(src + "\nfn main() { }\n", "t.sipar")
    return [(d.code, d.severity) for d in ds]


class T5Scopes(unittest.TestCase):
    def test_5_malformed_scopes(self):
        bad = ['allow net [""]', 'allow net ["http://x.com"]', 'allow net ["x.com/api"]', 'allow net ["x:70000"]',
               'allow net ["x:0"]', 'allow net ["x:abc"]', 'allow net ["a b.com"]', 'allow net ["x*.com"]',
               'allow fs.read [""]', 'allow fs.write ["  "]', 'allow shell ["echo \\"hi"]', 'allow shell [""]',
               'allow env ["*"]', 'allow env ["MY VAR"]', 'allow env ["1X"]', 'allow secret ["*"]',
               'allow secret ["A-B"]', 'allow net ["a:b:c"]', 'allow net ["example.com:8080:1"]',
               'allow net ["::1"]', 'allow net ["[::1"]', 'allow net ["[::1]:0"]', 'allow net ["[x]:80"]']
        for src in bad:
            with self.subTest(src=src):
                self.assertIn(("E310", "error"), codes(src))

    def test_5_broad_scopes(self):
        for src in ('allow net ["*"]', 'allow net ["*.com"]', 'allow fs.read ["/"]', 'allow fs.write ["~"]',
                    'allow fs.write ["~/"]', 'allow fs.read ["/."]', 'allow fs.read ["//"]'):
            with self.subTest(src=src):
                self.assertEqual(codes(src), [("E311", "warning")])

    def test_5_good_scopes(self):                              # guard
        for src in ('allow net ["api.x.com", "*.x.com", "127.0.0.1:8080", "localhost", "x.com."]',
                    'allow fs.read ["./data", "data/in", "/tmp/sipar"]', 'allow shell ["git status", "ls -la"]',
                    'allow env ["HOME", "_X1"]', 'allow secret ["API_KEY"]',
                    'allow net ["[::1]:8080", "[::1]", "[2001:db8::1]:443"]'):
            with self.subTest(src=src):
                self.assertEqual(codes(src), [])

    def test_5_examples_clean(self):                           # guard
        for dp, _, fs in os.walk(os.path.join(ROOT, "examples")):
            for f in fs:
                if f.endswith(".sipar"):
                    with self.subTest(f=f):
                        with open(os.path.join(dp, f), encoding="utf-8") as fh:
                            src = fh.read()
                        _, ds = check_source(src, f)
                        self.assertEqual([d.code for d in ds], [])


# ====================================================================== 6. list size

class T6ListCap(Base):
    def test_6_list_concat_cap(self):                          # i4.sipar
        from sipar.runtime import builtins
        orig = builtins.MAX_ITEMS
        import sipar.runtime.interp as I
        try:
            I.MAX_ITEMS = builtins.MAX_ITEMS = 1000
            p = self.prog(main_src('var l = [1]\nfor i in 0..26 { l = l + l }\nprint(l.len())', "allow io"))
            e = p.error()
            self.assertEqual(e.kind, "value")
            self.assertIn("too large", e.message)
        finally:
            I.MAX_ITEMS = builtins.MAX_ITEMS = orig

    def test_6_push_cap(self):
        from sipar.runtime import builtins
        orig = builtins.MAX_ITEMS
        try:
            builtins.MAX_ITEMS = 50
            p = self.prog(main_src('var l: List[Int] = []\nfor i in 0..100 { l.push(i) }', "allow io"))
            e = p.error()
            self.assertEqual(e.kind, "value")
            self.assertEqual(e.message, "push: result too large (51 > 50)")
        finally:
            builtins.MAX_ITEMS = orig


# ====================================================================== 7. module names

class T7ModuleNames(unittest.TestCase):
    def test_7_module_names(self):
        for src in ('enum shell { run(c: Str) }', 'type shell = { run: Str }', 'enum http { get(u: Str) }',
                    'type memory = { a: Int }', 'enum json { a }', 'type fs = { a: Int }', 'enum env { a }',
                    'type time = { a: Int }', 'enum random { a }'):
            with self.subTest(src=src):
                self.assertIn("E202", [c for c, _ in codes(src)])
        self.assertEqual(codes('enum Shell { run }'), [])                      # guard


# ====================================================================== 8. non-finite floats

class T8Floats(Base):
    def test_8_json_encode_non_finite(self):
        for expr in ("1e308 * 10.0", "(1e308 * 10.0) - (1e308 * 10.0)", "[1.0, 0.0 - (1e308 * 10.0)]"):
            with self.subTest(expr=expr):
                p = self.prog(main_src(f'print(json.encode({expr}))', "allow io"))
                e = p.error()
                self.assertEqual(e.kind, "value", e.message)
                self.assertEqual(p.out, "")

    def test_8_as_float_non_finite(self):
        for s in ("nan", "inf", "-inf", "Infinity", "1e400", "NaN"):
            with self.subTest(s=s):
                p = self.prog(main_src(f'print("{s}" as Float)', "allow io"))
                self.assertEqual(p.error().kind, "decode")

    def test_8_float_literal_range(self):
        for lit in ("1e400", "1.5e309", "99999e99999"):
            with self.subTest(lit=lit):
                with self.assertRaises(SiparSyntaxError) as cm:
                    parse(f"fn main() {{ let x = {lit} }}\n", "t.sipar")
                self.assertIn("float literal out of range", str(cm.exception))
                _, ds = check_source(f"fn main() {{ let x = {lit} }}\n", "t.sipar")
                self.assertEqual([d.code for d in ds], ["E101"])

    def test_8_finite_ok(self):                                # guard
        p = self.prog(main_src('print(1e308)\nprint("1.5" as Float)\nprint(json.encode([1.5, 2]))\n'
                               'print(0.0000001e-300)', "allow io"))
        # unchecked run (Prog): no Int->Float widening plan, so the 2 stays an Int; `sipar run` prints [1.5, 2.0]
        self.assertEqual(p.run().split("\n"), ["1e+308", "1.5", "[1.5, 2]", "1e-307", ""])


# ====================================================================== 9. attribute values

class T9Attrs(Base):
    AGENT = '''allow ai
fn t() -> Str { "x" }
@{ATTR}
agent fn a(q: Str) -> Str {
    tools [t]
    "do {q}"
}
ai fn b(q: Str) -> Str { "do {q}" }
fn main() uses ai { print({CALL}) }
'''

    def test_9_checker_rejects(self):                          # guard: already E231
        for attr, call in (("max_steps(-1)", 'a("x")'), ("retries(-1)", 'b("x")')):
            src = self.AGENT.replace("{ATTR}", attr).replace("{CALL}", call)
            if attr.startswith("retries"):
                src = src.replace("@" + attr + "\nagent", "agent").replace("ai fn b", "@" + attr + "\nai fn b")
            with self.subTest(attr=attr):
                _, ds = check_source(src, "t.sipar")
                self.assertIn("E231", [d.code for d in ds])

    def test_9_runtime_rejects(self):
        for attr, call in (("max_steps(-1)", 'a("x")'), ("max_steps(0)", 'a("x")'), ("retries(-1)", 'b("x")')):
            src = self.AGENT.replace("{ATTR}", attr).replace("{CALL}", call)
            if attr.startswith("retries"):
                src = src.replace("@" + attr + "\nagent", "agent").replace("ai fn b", "@" + attr + "\nai fn b")
            with self.subTest(attr=attr):
                p = self.prog(src)
                e = p.error(script={"a": [{"final": "ok"}], "b": ["ok"]})
                self.assertEqual(e.kind, "type", e.message)
                self.assertIn(attr.split("(")[0], e.message)


if __name__ == "__main__":
    unittest.main()
