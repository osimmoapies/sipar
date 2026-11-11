"""Phase 2 — Python embedding API (cases P1-P14)."""
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from rt_helpers import ROOT
import sipar

SRC = '''allow ai
allow fs.read ["data"]
type Point = { x: Int, y: Float, label: Str? }
enum Shape { dot, circle(r: Float), poly(points: List[Point]) }

fn add(a: Int, b: Int) -> Int { a + b }
fn half(x: Float) -> Float { x / 2 }
fn neg(b: Bool) -> Bool { not b }
fn maybe(n: Int?) -> Str { if n == none { "none" } else { "some" } }
fn sum_map(m: Map[Int]) -> Int {
    var t = 0
    for k in m.keys() { t = t + (m[k] ?? 0) }
    return t
}
fn move(p: Point, dx: Int) -> Point { Point { x: p.x + dx, y: p.y, label: p.label } }
fn area(s: Shape) -> Float {
    match s {
        Shape.dot => 0.0,
        Shape.circle(r) => r * r * 3.0,
        Shape.poly(points) => points.len() as Float,
    }
}
fn grow(s: Shape) -> Shape {
    match s {
        Shape.circle(r) => Shape.circle(r: r * 2),
        _ => Shape.dot,
    }
}
fn pairs(xs: List[List[Int]]) -> Int { xs.len() }
fn get_fn() -> fn(Int) -> Int { fn(x: Int) -> Int => x }
fn boom(n: Int) -> Int { 10 / n }
fn shout(s: Str) -> Str { print("said {s}")
    s.upper() }
fn peek() -> Str uses fs.read { fs.read("/etc/hosts") }
let K = 3
type Node = { v: Int, next: Node? }
type Bag = { xs: List[Int] }
fn k() -> Int { K }
fn rng() -> List[Int] { 0..3 }
fn cyc() -> Node {
    var n = Node { v: 1, next: none }
    n.next = n
    return n
}
fn bag(b: Bag) -> Int { b.xs.len() }
fn mlen(m: Map[List[Int]]) -> Int { (m["a"] ?? []).len() }
ai fn classify(text: Str) -> Str { "Classify: {text}" }
@model("openrouter/never/used")
ai fn ext(text: Str) -> Str { "x {text}" }
'''


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="sipar_api_")
        cls.path = os.path.join(cls.dir, "lib.sipar")
        with open(cls.path, "w") as fh:
            fh.write(SRC)
        cls.p = sipar.load(cls.path)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def err(self, *a, **kw) -> sipar.SiparError:
        with self.assertRaises(sipar.SiparError) as cm:
            self.p.call(*a, **kw)
        return cm.exception


class TestApi(Base):
    def test_P1_load_and_call(self):
        self.assertEqual(self.p.call("add", 1, 2), 3)
        self.assertIs(type(self.p.call("add", 1, 2)), int)
        self.assertEqual(self.p.call("add", a=5, b=6), 11)

    def test_P2_check_error(self):
        bad = os.path.join(self.dir, "bad.sipar")
        with open(bad, "w") as fh:
            fh.write('fn f() -> Int { "x" }\n')
        with self.assertRaises(sipar.CheckError) as cm:
            sipar.load(bad)
        d = cm.exception.diagnostics
        self.assertEqual(d[0]["code"], "E210")
        self.assertEqual(set(d[0]), {"code", "severity", "file", "line", "col", "message", "hint"})
        with open(bad, "w") as fh:
            fh.write('fn f( {\n')
        with self.assertRaises(sipar.CheckError) as cm:
            sipar.load(bad)
        self.assertEqual(len(cm.exception.diagnostics), 1)
        self.assertTrue(cm.exception.diagnostics[0]["code"].startswith("E1"))

    def test_P3_missing_file_is_oserror(self):
        with self.assertRaises(FileNotFoundError):
            sipar.load(os.path.join(self.dir, "nope.sipar"))

    def test_P4_scalars_in(self):
        self.assertEqual(self.p.call("half", 3), 1.5)                 # int widened to Float
        self.assertIs(type(self.p.call("half", 3)), float)
        self.assertEqual(self.p.call("neg", True), False)
        self.assertEqual(self.p.call("pairs", [(1, 2), [3]]), 2)       # tuples accepted
        self.assertEqual(self.p.call("sum_map", {"a": 1, "b": 2}), 3)
        self.assertEqual(self.err("add", True, 1).kind, "decode")     # bool is not Int
        self.assertEqual(self.err("add", "1", 1).kind, "decode")
        self.assertEqual(self.err("neg", 1).kind, "decode")

    def test_P5_records_and_enums(self):
        self.assertEqual(self.p.call("move", {"x": 1, "y": 2, "label": "a"}, 2), {"x": 3, "y": 2.0, "label": "a"})
        self.assertEqual(self.p.call("move", {"x": 1, "y": 2}, 0), {"x": 1, "y": 2.0, "label": None})
        self.assertEqual(self.p.call("area", "dot"), 0.0)
        self.assertEqual(self.p.call("area", {"circle": {"r": 1}}), 3.0)
        self.assertEqual(self.p.call("area", {"tag": "circle", "r": 2}), 12.0)
        self.assertEqual(self.p.call("area", {"poly": {"points": [{"x": 1, "y": 1}, {"x": 2, "y": 2}]}}), 2.0)
        self.assertEqual(self.p.call("grow", {"circle": {"r": 1.5}}), {"circle": {"r": 3.0}})
        self.assertEqual(self.p.call("grow", "dot"), "dot")
        self.assertEqual(self.err("area", "square").kind, "decode")
        self.assertEqual(self.err("area", {"circle": {}}).kind, "decode")
        self.assertEqual(self.err("move", {"x": 1}, 0).kind, "decode")

    def test_P6_unknown_function_and_arity(self):
        self.assertEqual(self.err("nope").kind, "type")
        self.assertEqual(self.err("add", 1).kind, "type")
        self.assertEqual(self.err("add", 1, 2, 3).kind, "type")
        self.assertEqual(self.err("add", 1, 2, c=3).kind, "type")
        self.assertEqual(self.err("add", 1, a=3).kind, "type")

    def test_P7_ai_fn_with_mock(self):
        r = self.p.call("classify", "hello", mock_script=["spam"])
        self.assertEqual(r, "spam")
        self.assertIs(type(r), str)                                   # labels dropped: plain str

    def test_P8_runtime_error(self):
        e = self.err("boom", 0)
        self.assertEqual(e.kind, "zero")
        self.assertTrue(e.message)

    def test_P9_check_source(self):
        self.assertEqual(sipar.check_source("fn main() { print(1) }\n"), [])
        d = sipar.check_source('fn main() { let x: Int = "a" }\n', "m.sipar")
        self.assertEqual([x["code"] for x in d], ["E210"])
        self.assertEqual(d[0]["file"], "m.sipar")
        d = sipar.check_source("fn (")
        self.assertEqual(len(d), 1)
        self.assertEqual(d[0]["severity"], "error")
        json.dumps(d)

    def test_P10_model_default_mock_overrides_attr(self):
        self.assertEqual(self.p.call("ext", "a", mock_script=["ok"]), "ok")
        old = os.environ.pop("SIPAR_OPENROUTER_URL", None), os.environ.pop("OPENROUTER_API_KEY", None)
        try:
            e = self.err("ext", "a", model=None)                      # program's own @model: no key -> ai error
            self.assertEqual(e.kind, "ai")
            e = self.err("ext", "a", model="nope/x")
            self.assertEqual(e.kind, "ai")
            self.assertEqual(self.p.call("ext", "a", model="openrouter/x | mock", mock_script=["fb"]), "fb")
        finally:
            for k, v in zip(("SIPAR_OPENROUTER_URL", "OPENROUTER_API_KEY"), old):
                if v is not None:
                    os.environ[k] = v

    def test_P11_capabilities_enforced(self):
        self.assertEqual(self.err("peek").kind, "capability")

    def test_P12_map_non_str_key(self):
        e = self.err("sum_map", {1: 2})
        self.assertEqual(e.kind, "decode")

    def test_P13_fn_result(self):
        self.assertEqual(self.err("get_fn").kind, "type")

    def test_P14_optional_param(self):
        self.assertEqual(self.p.call("maybe"), "none")
        self.assertEqual(self.p.call("maybe", None), "none")
        self.assertEqual(self.p.call("maybe", 3), "some")

    def test_print_goes_to_out(self):
        out = io.StringIO()
        self.assertEqual(self.p.call("shout", "hi", out=out), "HI")
        self.assertEqual(out.getvalue(), "said hi\n")

    def test_journal_written(self):
        jp = os.path.join(self.dir, "j.jsonl")
        self.p.call("classify", "x", mock_script=["a"], journal=jp)
        with open(jp) as fh:
            e = json.loads(fh.readline())
        self.assertEqual((e["kind"], e["meta"]["model"]), ("ai", "mock"))

    def test_secret_result_refused(self):
        p = os.path.join(self.dir, "sec.sipar")
        with open(p, "w") as fh:
            fh.write('allow secret ["TOKEN"]\nfn tok() -> Str uses secret { env.secret("TOKEN") }\n')
        os.environ["TOKEN"] = "abcd1234"
        try:
            with self.assertRaises(sipar.SiparError) as cm:
                sipar.load(p).call("tok")
            self.assertEqual(cm.exception.kind, "taint")
            self.assertNotIn("abcd1234", cm.exception.message)
        finally:
            del os.environ["TOKEN"]

    def test_E4_python_c(self):
        code = (f"import sipar; p = sipar.load({self.path!r}); print(p.call('add', 2, 3)); "
                "print(p.call('grow', {'circle': {'r': 1}}))")
        r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, "5\n{'circle': {'r': 2.0}}\n")

    def test_mutation_survivors(self):
        self.assertIs(self.p.call("neg", False), True)                # True is not turned into 1
        self.assertEqual(self.p.call("k"), 3)                          # top-level lets are initialised
        self.assertEqual(self.p.call("rng"), [0, 1, 2])                # ranges come out as lists
        e = self.err("cyc")
        self.assertEqual((e.kind, e.message), ("value", "cyc().next: the result contains itself (a cycle)"))
        self.assertEqual(self.p.call("bag", {"xs": (1, 2, 3)}), 3)     # tuples inside records
        self.assertEqual(self.p.call("mlen", {"a": (1, 2)}), 2)        # tuples inside maps
        self.assertEqual(self.p.call("area", {"poly": {"points": ({"x": 1, "y": 1},)}}), 1.0)
        self.assertEqual(self.p.call("move", {"x": 1, "y": 2, "zz": 5}, 0),   # extra fields ignored, as in decode
                         {"x": 1, "y": 2.0, "label": None})
        self.assertEqual(sipar.check_source("fn (")[0]["file"], "<input>")
        bad = os.path.join(self.dir, "two.sipar")
        with open(bad, "w") as fh:
            fh.write('fn f() -> Int { "x" }\nfn g() -> Int { "y" }\n')
        with self.assertRaises(sipar.CheckError) as cm:
            sipar.load(bad)
        self.assertTrue(str(cm.exception).endswith("(+1 more)"), str(cm.exception))
        self.assertIn("[E210]", str(cm.exception))
        with open(bad, "w") as fh:
            fh.write('fn f() -> Int { "x" }\n')
        with self.assertRaises(sipar.CheckError) as cm:
            sipar.load(bad)
        self.assertNotIn("more)", str(cm.exception))               # one error: no "(+0 more)"
        self.assertIn("given twice", self.err("add", 1, a=3).message)

    def test_lazy_exports(self):
        self.assertIn("load", dir(sipar))
        with self.assertRaises(AttributeError):
            sipar.nothing_here


if __name__ == "__main__":
    unittest.main()
