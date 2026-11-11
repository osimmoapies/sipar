"""Tests for sipar.checker."""
import os
import re
import sys
import textwrap
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sipar.checker import check, check_source  # noqa: E402
from sipar.parser import parse  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
ALLOW_ALL = ('allow ai\nallow net ["x.com"]\nallow fs.read ["."]\nallow fs.write ["."]\n'
             'allow shell ["ls"]\nallow env ["HOME"]\nallow time\nallow random\nallow io\n')


def diags(src):
    _, d = check_source(textwrap.dedent(src), "t.sipar")
    return d


def errs(src):
    return [d.code for d in diags(src) if d.severity == "error"]


def warns(src):
    return [d.code for d in diags(src) if d.severity == "warning"]


def fn(stmts, ret="", uses="", pre="", params=""):
    """Wrap statements in a function f (all capabilities allowed)."""
    r = f" -> {ret}" if ret else ""
    u = f" uses {uses}" if uses else ""
    return ALLOW_ALL + pre + f"\nfn f({params}){r}{u} {{\n{textwrap.dedent(stmts)}\n}}\n"


def type_of(expr, stmts="", pre=""):
    """The checker's type for `expr`, read from a mismatch message against a probe record type."""
    src = fn(stmts + f"\nlet probe__: Probe__ = {expr}", pre="type Probe__ = { p: Int }\n" + pre,
             uses="ai, net, fs.read, fs.write, shell, env, time, random, io")
    ds = [d for d in diags(src) if d.severity == "error"]
    for d in ds:
        m = re.search(r"declared as Probe__, but the value is (.+)$", d.message)
        if m:
            return m.group(1)
    if ds:
        return "ERR " + " ".join(f"{d.code}:{d.message}" for d in ds)
    return "silent"


class Base(unittest.TestCase):
    def ok(self, src, warnings=()):
        """No errors, and exactly the listed warning codes (default: none)."""
        ds = diags(src)
        self.assertEqual([], [(d.code, d.line, d.message) for d in ds if d.severity == "error"])
        self.assertEqual(sorted(warnings), sorted(d.code for d in ds if d.severity == "warning"),
                         [(d.code, d.line, d.message) for d in ds])

    def bad(self, src, code, count=None, hint=None, msg=None):
        ds = diags(src)
        got = [d.code for d in ds]
        self.assertIn(code, got, f"diagnostics: {[(d.code, d.message) for d in ds]}")
        if count is not None:
            self.assertEqual(count, len([d for d in ds if d.severity == "error"]),
                             [(d.code, d.message) for d in ds])
        d = next(d for d in ds if d.code == code)
        if hint is not None:
            self.assertIn(hint, d.hint)
        if msg is not None:
            self.assertIn(msg, d.message)
        return d


# ---------------------------------------------------------------- names
class Names(Base):
    def test_C01_unknown_variable_did_you_mean(self):
        d = self.bad(fn("let count = 1\nprint(cuont)"), "E203", count=1, hint="`count`")
        self.assertEqual((13, 7), (d.line, d.col))

    def test_C01_unknown_function(self):
        self.bad(fn("prnt(1)"), "E203", hint="`print`")

    def test_C01_unknown_type(self):
        self.bad(fn("let x: Strr = \"a\""), "E204", count=1, hint="`Str`")

    def test_C01_unknown_field(self):
        self.bad(fn("let r = R { name: 1 }\nprint(r.nmae)", pre="type R = { name: Int }"), "E205", hint="`name`")

    def test_C01_unknown_variant(self):
        self.bad(fn("let m = Mood.hapy", pre="enum Mood { happy, sad }"), "E205", hint="`happy`")

    def test_C01_unknown_method(self):
        self.bad(fn('let n = "a".lenght()'), "E205", hint="`len`")

    def test_C01_unknown_module_fn(self):
        self.bad(fn('let s = http.gett("u")', uses="net"), "E205", hint="`get`", count=1)

    def test_C02_duplicate_variable_same_scope(self):
        self.bad(fn("let a = 1\nlet a = 2"), "E202")

    def test_C02_shadow_in_inner_block_ok(self):
        self.ok(fn("let a = 1\nif true { let a = \"s\"\nprint(a) }\nprint(a)"))

    def test_C02_shadow_param_loop_catch(self):
        self.ok(fn("let a = 1\nfor x in [1] { let x = \"s\"\nprint(x) }\n"
                   "try { print(1) } catch e { let e = 2\nprint(e) }", params="a: Int"))
        self.ok(fn("let a = \"s\"", params="a: Int"))
        self.bad(fn("let x = 1\nlet x = 2"), "E202", count=1)

    def test_C02_duplicate_param(self):
        # the parser already rejects duplicate parameters
        self.assertEqual(["E201"], errs("fn f(a: Int, a: Int) { }"))

    def test_C03_duplicate_fn_type_const_test(self):
        self.bad("fn a() { }\nfn a() { }", "E202")
        self.bad("type T = { x: Int }\nenum T { a }", "E202")
        self.bad("let K = 1\nlet K = 2", "E202")
        self.bad("let K = 1\nfn K() { }", "E202")
        self.bad('test "t" { }\ntest "t" { }', "E202")

    def test_C03_builtin_names(self):
        self.bad("fn print(x: Int) { }", "E202", msg="built-in function")
        self.bad("fn http() { }", "E202", msg="built-in module")
        self.bad("type Str = { a: Int }", "E202")
        self.bad("type Error = { a: Int }", "E202")
        self.bad(fn("let fs = 1"), "E202")
        self.bad("fn f(json: Int) { }", "E202")

    def test_C04_module_as_value(self):
        self.bad(fn("let h = http"), "E206", hint="http.get")
        self.bad(fn("let h = http.get", uses="net"), "E206", hint="http.get(...)")

    def test_C05_type_enum_builtin_as_value(self):
        self.bad(fn("let t = R", pre="type R = { a: Int }"), "E206")
        self.bad(fn("let t = Mood", pre="enum Mood { a }"), "E206", hint="Mood.a")
        self.bad(fn("let p = print"), "E206", hint="fn(x) => print(x)")
        self.bad(fn("let p = R.a", pre="type R = { a: Int }"), "E206")
        self.bad(fn("print(Mood { a: 1 })", pre="enum Mood { a }"), "E206")

    def test_C06_catch_error_record(self):
        self.ok(fn('try { fail("user", "x") } catch e { print("{e.kind} {e.message}") }'))
        self.bad(fn('try { print(1) } catch e { print(e.code) }'), "E205", hint="fields of Error")
        self.assertEqual("Error", type_of("err", 'var err = Error { kind: "a", message: "b" }'))


# ---------------------------------------------------------------- types
class Types(Base):
    def test_C10_int_widens_to_float(self):
        self.ok(fn("let x: Float = 1\nvar y = 1.5\ny = 2"))
        self.ok(fn("return 1", ret="Float"))
        self.ok(fn("g(3)", pre="fn g(x: Float) { }"))
        self.assertEqual("List[Float]", type_of("[1, 2.5]"))
        self.assertEqual("Float", type_of("1 + 2.5"))
        self.assertEqual("Int", type_of("7 / 2"))

    def test_C11_float_to_int(self):
        self.bad(fn("let x: Int = 1.5"), "E210", hint="as Int")
        self.bad(fn("g(1.5)", pre="fn g(x: Int) { }"), "E210")

    def test_C12_optionals_and_none(self):
        self.ok(fn("let a: Int? = 1\nlet b: Int? = none\nlet c: Int? = a"))
        self.bad(fn("let a: Int = none"), "E219", hint="Int?")
        self.bad(fn("let a = none"), "E211", hint="let a: Str? = none")
        self.bad(fn("let a: Int? = 1\nlet b: Int = a"), "E210", hint="??")
        self.bad(fn("let n = 3\nprint(n == none)"), "E214", msg="never none")

    def test_C13_coalesce(self):
        self.assertEqual("Int", type_of("a ?? 0", "let a: Int? = none"))
        self.assertEqual("Float", type_of("a ?? 0.5", "let a: Int? = none"))
        self.assertEqual("Int?", type_of("a ?? b", "let a: Int? = none\nlet b: Int? = 1"))
        self.assertEqual(["E250"], warns(fn("let a = 1\nprint(a ?? 2)")))
        self.bad(fn('let a: Int? = none\nprint(a ?? "x")'), "E210")

    def test_C14_match_narrows_optional(self):
        self.assertEqual("Int", type_of("match a { none => 0, v => v }", "let a: Int? = 1"))
        self.assertEqual("Int?", type_of("match a { v => v }", "let a: Int? = 1"))
        self.ok(fn("let a: Str? = none\nmatch a { none => print(0), s => print(s.len()) }"))

    def test_C15_immutable(self):
        self.bad(fn("let a = 1\na = 2"), "E207", hint="var a")
        self.bad(fn("a = 2", params="a: Int"), "E207", msg="parameter")
        self.bad(fn("K = 2", pre="let K = 1"), "E207", msg="constant")
        self.bad(fn("for i in 0..3 { i = 1 }"), "E207", msg="loop variable")
        self.bad(fn("f = 1"), "E207", msg="function")
        self.bad(fn("zz = 1"), "E203", hint="var zz")
        self.bad(fn("let a: Int? = 1\nmatch a { none => print(0), v => { v = 2 } }"), "E207")

    def test_C16_field_and_element_assignment(self):
        self.ok(fn("let r = R { a: 1 }\nr.a = 2\nlet xs = [1]\nxs[0] = 3\nlet m = [\"k\": 1]\nm[\"k\"] = 2",
                   pre="type R = { a: Int }"))
        self.bad(fn("let r = R { a: 1 }\nr.a = \"s\"", pre="type R = { a: Int }"), "E210")
        self.bad(fn("let xs = [1]\nxs[0] = \"s\""), "E210")
        self.bad(fn("let r = R { a: 1 }\nr.b = 1", pre="type R = { a: Int }"), "E205")
        self.bad(fn('var s = "ab"\ns[0] = "c"'), "E220")
        self.bad(fn("let xs = [1, 2]\nxs[0..1] = [3]"), "E220")

    def test_C17_record_literals(self):
        pre = "type R = { a: Int, b: Str }"
        self.ok(fn('let r = R { a: 1, b: "x" }', pre=pre))
        self.bad(fn("let r = R { a: 1 }", pre=pre), "E217", msg="b", count=1)
        self.bad(fn('let r = R { a: 1, b: "x", c: 2 }', pre=pre), "E205", count=1)
        self.bad(fn('let r = R { a: "1", b: "x" }', pre=pre), "E210", count=1)
        self.bad(fn("let r = Q { a: 1 }", pre=pre), "E204")

    def test_C18_enum_constructors(self):
        pre = "enum Act { go(to: Str, n: Int), stop }"
        self.ok(fn('let a = Act.go("x", 1)\nlet b = Act.go(to: "y", n: 2)\nlet c = Act.go("z", n: 3)\n'
                   'let d = Act.stop', pre=pre))
        self.bad(fn('let a = Act.go("x")', pre=pre), "E212", msg="n")
        self.bad(fn('let a = Act.go("x", 1, 2)', pre=pre), "E212")
        self.bad(fn('let a = Act.go(too: "x", n: 1)', pre=pre), "E212", hint="`to`")
        self.bad(fn("let a = Act.go", pre=pre), "E212", hint="Act.go(to: ..., n: ...)")
        self.bad(fn("let a = Act.stop()", pre=pre), "E212", hint="Act.stop")
        self.bad(fn('let a = Act.go(1, 1)', pre=pre), "E210")
        self.bad(fn('let a = Act.jump(1)', pre=pre), "E205", count=1)

    def test_C19_as_table(self):
        pre = "type R = { a: Int }\nenum E { x, y }\ntype F = { f: fn(Int) -> Int }"
        for e, t in [('"1" as Int', "Int"), ('"1.5" as Float', "Float"), ('"true" as Bool', "Bool"),
                     ("1 as Float", "Float"), ("1.5 as Int", "Int"), ("[1] as Str", "Str"),
                     ('"\\{\\}" as R', "R"), ('"x" as E', "E"), ('"[1]" as List[Int]', "List[Int]"),
                     ('"\\{\\}" as Map[Str]', "Map[Str]"), ("true as Str", "Str")]:
            self.assertEqual(t, type_of(e, pre=pre), e)
        self.bad(fn("let b = 1 as Bool"), "E216")
        self.bad(fn('let b = "x" as F', pre=pre), "E216")
        self.bad(fn("let b = [1] as Int"), "E216")
        self.bad(fn("let b = 1 as R", pre=pre), "E216")

    def test_C20_str_plus_non_str(self):
        self.bad(fn('let s = "n=" + 1'), "E214", hint="interpolation", count=1)
        self.bad(fn('let s = 1 + "n"'), "E214", hint="interpolation")
        self.assertEqual("Str", type_of('"a" + "b"'))
        self.assertEqual("List[Int]", type_of("[1] + [2]"))
        self.bad(fn('let s = [1] + ["a"]'), "E214")
        self.bad(fn("let s = true + 1"), "E214")
        self.bad(fn("let s = -true"), "E214")
        self.bad(fn("let s = not 1"), "E214")
        self.bad(fn("let s = 1 and true"), "E214")

    def test_C21_in(self):
        self.ok(fn('let a = "x" in "xyz"\nlet b = 1 in [1, 2]\nlet c = "k" in ["k": 1]\nlet d = 1.5 in [1, 2]'))
        self.bad(fn('let a = 1 in "xyz"'), "E214")
        self.bad(fn('let a = "1" in [1]'), "E214")
        self.bad(fn('let a = 1 in ["k": 1]'), "E214")
        self.bad(fn("let a = 1 in 5"), "E214")

    def test_C22_ranges_slices_index(self):
        self.assertEqual("List[Int]", type_of("0..5"))
        self.assertEqual("List[Str]", type_of('xs[1..2]', 'let xs = ["a", "b"]'))
        self.assertEqual("Str", type_of('"abc"[0..2]'))
        self.assertEqual("Str", type_of('"abc"[1]'))
        self.assertEqual("Int", type_of("m[\"a\"]", 'let m = ["a": 1]'))
        self.assertEqual("Int", type_of("xs[0]", "let xs = [1]"))
        self.bad(fn("let a = 5[0]"), "E220")
        self.bad(fn('let a = [1]["x"]'), "E210")
        self.bad(fn('let a = ["k": 1][0]'), "E210")
        self.bad(fn('let a = [1][0.."2"]'), "E210")
        self.bad(fn("let a = 5[0..1]"), "E220")
        self.bad(fn('let a = 1.5..3'), "E214")
        self.bad(fn("let a: Int? = 1\nlet b = a[0]"), "E219")
        self.bad(fn('for c in "abc" { }'), "E220", hint="lines")
        self.bad(fn("for c in 5 { }"), "E220")
        self.bad(fn("let a: List[Int]? = none\nfor c in a { }"), "E219")
        self.ok(fn('for k in ["a": 1] { print(k.upper()) }'))

    def test_C23_comparisons(self):
        self.ok(fn('let a = 1 < 2.5\nlet b = "a" <= "b"\nlet c = 1 == 1.0\nlet d = [1] == [2]'))
        self.bad(fn('let a = 1 < "2"'), "E214")
        self.bad(fn("let a = R { x: 1 } < R { x: 2 }", pre="type R = { x: Int }"), "E214")
        self.bad(fn('let a = 1 == "1"'), "E214")
        self.bad(fn("let a = g == g", pre="fn g() { }"), "E214")

    def test_C24_conditions(self):
        self.bad(fn("if 1 { }"), "E215", hint="x != 0")
        self.bad(fn('while "x" { }'), "E215")
        self.bad(fn("assert [1]"), "E215")
        self.bad(fn("let a: Int? = 1\nif a { }"), "E215", hint="!= none")
        self.bad(fn("assert true, 5"), "E210")

    def test_C25_empty_containers(self):
        self.bad(fn("let xs = []"), "E211", hint="List[Str]")
        self.bad(fn("let m = [:]"), "E211", hint="Map[Int]")
        self.ok(fn("let xs: List[Int] = []\nlet m: Map[Str] = [:]\nvar ys = [1]\nys = []"))
        self.ok(fn("g([])", pre="fn g(x: List[Int]) { }"))

    def test_C26_list_items(self):
        self.bad(fn('let xs = [1, "a"]'), "E218")
        self.bad(fn('let m = ["a": 1, "b": "x"]'), "E218")
        self.bad(fn('let m = [1: 1]'), "E210")
        self.assertEqual("List[Int?]", type_of("[1, none]"))
        self.assertEqual("List[List[Int]]", type_of("[[], [1]]"))

    def test_C27_branches(self):
        self.bad(fn('let a = if true { 1 } else { "x" }'), "E218")
        self.bad(fn('let a = match 1 { 1 => 1, _ => "x" }'), "E218")
        self.ok(fn('if true { 1 } else { "x" }\nmatch 1 { 1 => 1, _ => "x" }'))
        self.bad(fn("let a = if true { 1 }"), "E218", hint="else")
        self.assertEqual("Int?", type_of("if true { 1 } else { none }"))
        self.assertEqual("Int", type_of('if true { 1 } else { fail("user", "x") }'))
        self.assertEqual("Float", type_of("if true { 1 } else { 2.5 }"))
        self.assertEqual("Int", type_of('try { 1 } catch e { 2 }'))
        self.bad(fn('let a = try { 1 } catch e { "x" }'), "E218")

    def test_C28_field_on_optional(self):
        self.bad(fn("let r: R? = none\nprint(r.a)", pre="type R = { a: Int }"), "E219", hint="??")
        self.bad(fn("let s: Str? = none\nprint(s.len())"), "E219")

    def test_C29_bad_type_forms(self):
        self.bad(fn("let m: Map[Str, Int] = [:]"), "E204", hint="Map[Int]", count=1)
        self.bad(fn("let m: List = []"), "E204", count=1)
        self.bad(fn("let m: Int[Str] = 1"), "E204", count=1)

    def test_C30_no_cascade(self):
        self.bad(fn("let x = undefined_thing\nlet y = x + 1\nprint(y.foo)\nlet z: Int = x.bar()"), "E203", count=1)
        self.bad(fn("let x: Nope = 1\nprint(x.a)"), "E204", count=1)
        self.bad(fn("let r = Q { a: 1 }\nprint(r.a)"), "E204", count=1)


# ---------------------------------------------------------------- calls
class Calls(Base):
    pre = "fn g(a: Int, b: Str) -> Int { a }"

    def test_C40_arity_and_named(self):
        self.ok(fn('g(1, "x")\ng(1, b: "x")\ng(b: "x", a: 1)', pre=self.pre))
        self.bad(fn('g(1, "x", 3)', pre=self.pre), "E212", count=1)
        self.bad(fn("g(1)", pre=self.pre), "E212", msg="b", count=1)
        self.bad(fn('g(1, c: "x")', pre=self.pre), "E212", count=1)
        self.bad(fn('g(1, a: 2, b: "x")', pre=self.pre), "E212", msg="twice")
        self.bad(fn('g(1, bb: "x")', pre=self.pre), "E212", hint="`b`")

    def test_C41_optional_params(self):
        self.ok(fn('let s = http.get("u", headers: ["a": "b"])\nlet t = http.get("u")', uses="net"))
        self.bad(fn('let s = http.get("u", ["a": "b"])', uses="net"), "E212", msg="headers: ...")
        self.bad(fn('let s = http.get("u", headers: 5)', uses="net"), "E210")

    def test_C42_generics(self):
        self.assertEqual("Int", type_of('trust(1, "ok")'))
        self.assertEqual("Int?", type_of("xs.first()", "let xs = [1]"))
        self.assertEqual("List[Str]", type_of('xs.map(fn(x) => "{x}")', "let xs = [1]"))
        self.assertEqual("Float", type_of("xs.reduce(0.0, fn(acc, x) => acc + x)", "let xs = [1, 2]"))
        self.assertEqual("List[Int]", type_of("xs.filter(fn(x) => x > 1)", "let xs = [1]"))
        self.assertEqual("Int?", type_of('m.get("a")', 'let m = ["a": 1]'))
        self.assertEqual("List[Int]", type_of("m.values()", 'let m = ["a": 1]'))
        self.assertEqual("Int", type_of("xs.sum()", "let xs = [1]"))
        self.bad(fn('let xs = [1]\nxs.push("a")'), "E210", msg="Int")
        self.bad(fn("let xs = [1]\nlet y = xs.map(fn(x) => x.upper())"), "E205")
        self.bad(fn('let xs = [1]\nlet y = xs.contains("a")'), "E210")

    def test_C43_num(self):
        self.assertEqual("Int", type_of("min(1, 2)"))
        self.assertEqual("Float", type_of("max(1, 2.5)"))
        self.assertEqual("Float", type_of("abs(-2.5)"))
        self.assertEqual("Int", type_of("round(2.5)"))
        self.bad(fn('let a = abs("x")'), "E210", msg="Int or Float")
        self.bad(fn("let a = min(1, true)"), "E210")

    def test_C44_any_never(self):
        self.ok(fn('print(1)\nprint("a")\nprint([1])\nprint(json.encode(["a": [1]]))'))
        self.ok(fn('if true { return 1 }\nfail("user", "no")', ret="Int"))
        self.ok(fn('let a: Int = if true { 1 } else { fail("user", "x") }'))

    def test_C45_lambda_inference(self):
        self.bad(fn("let f2 = fn(x) => x"), "E211", hint="fn(x: Int)")
        self.ok(fn("let f2 = fn(x: Int) => x + 1\nprint(f2(2))"))
        self.ok(fn("let f2: fn(Int) -> Int = fn(x) => x + 1"))
        self.ok(fn("h(fn(x) => x * 2)", pre="fn h(cb: fn(Int) -> Int) -> Int { cb(1) }"))
        self.bad(fn("h(fn(x, y) => x)", pre="fn h(cb: fn(Int) -> Int) -> Int { cb(1) }"), "E212")
        self.bad(fn('h(fn(x) => "s")', pre="fn h(cb: fn(Int) -> Int) -> Int { cb(1) }"), "E210")
        self.assertEqual("fn(Int) -> Int", type_of("fn(x: Int) => x"))
        self.assertEqual("fn(Int) -> Int?", type_of("fn(x: Int) => { if x > 0 { return none }\nx }"))
        self.bad(fn('let k = fn(x: Int) => { if x > 0 { return "s" }\nx }'), "E218")
        self.ok(fn("let k = fn(x: Int) -> Int => { return x }"))

    def test_C46_fns_as_values(self):
        pre = ("/// G.\nfn g(a: Int) -> Int { a }\nai fn q(s: Str) -> Str { \"{s}\" }\n"
               "agent fn ag(s: Str) -> Str { tools [g]\n\"{s}\" }\n/// doc\n")
        self.assertEqual("fn(Int) -> Int", type_of("g", pre=pre))
        self.assertEqual("fn(Str) -> Str", type_of("q", pre=pre))
        self.assertEqual("fn(Str) -> Str", type_of("ag", pre=pre))
        self.ok(fn("let h = g\nprint(h(1))\nlet hs = [g]\nprint(hs[0](2))", pre=pre))
        self.ok(fn("let r = Box { f: g }\nprint(r.f(1))", pre=pre + "type Box = { f: fn(Int) -> Int }"))
        self.bad(fn("let n = 1\nn(2)"), "E213")
        self.bad(fn("let r = Box { v: 1 }\nr.v()", pre="type Box = { v: Int }"), "E213")
        self.bad(fn("let k: (fn(Int) -> Int)? = none\nk(1)"), "E219")
        self.bad(fn("let h = g\nh(a: 1)", pre=pre), "E212")
        self.ok(fn("let r = (fn(x: Int) => x)(3)"))

    def test_C47_methods(self):
        self.ok(fn('let a = "a,b".split(",").map(fn(s) => s.upper()).join("-")\nlet m = ["a": 1]\n'
                   'print(m.keys())\nprint(m.has("a"))'))
        self.bad(fn("let a = [1].foo()"), "E205", count=1)
        self.bad(fn("let a = [1].len"), "E206", hint=".len()")
        self.bad(fn("let a = 5.len()"), "E205", hint="as Str")
        self.bad(fn('let a = "s".split()'), "E212")
        self.bad(fn('let a = R { x: 1 }.go()', pre="type R = { x: Int }"), "E205")

    def test_C48_element_constraints(self):
        self.bad(fn("let xs = [R { a: 1 }]\nlet ys = xs.sort()", pre="type R = { a: Int }"), "E214", hint="sort_by")
        self.bad(fn('let s = ["a"].sum()'), "E214")
        self.ok(fn("let xs = [R { a: 1 }]\nlet ys = xs.sort_by(fn(r) => r.a)", pre="type R = { a: Int }"))
        self.bad(fn("let xs = [R { a: 1 }]\nlet ys = xs.sort_by(fn(r) => r)", pre="type R = { a: Int }"), "E214")
        self.ok(fn('let s = ["b", "a"].sort()\nlet t = [1.5].sum()'))


# ---------------------------------------------------------------- flow
class Flow(Base):
    def test_C50_missing_return(self):
        self.bad(fn("if true { return 1 }", ret="Int"), "E402")
        self.bad(fn("let a = 1", ret="Int"), "E402")
        self.bad(fn("", ret="Int"), "E402")
        self.bad(fn("if true { 1 }", ret="Int"), "E218", count=1, hint="else")
        self.bad(fn("if true { print(1) }", ret="Int"), "E402", count=1)
        self.bad(fn('"s"', ret="Int"), "E210")

    def test_C51_all_paths_return(self):
        self.ok(fn("if true { return 1 } else { return 2 }", ret="Int"))
        self.ok(fn("match 3 { 1 => { return 1 }, _ => { return 2 } }", ret="Int"))
        self.ok(fn("while true { }", ret="Int"))
        self.bad(fn("while true { break }", ret="Int"), "E402")
        self.ok(fn("while true { for i in 0..2 { break } }", ret="Int"))
        self.ok(fn("if true { 1 } else { 2 }", ret="Int"))
        self.ok(fn('try { return 1 } catch e { return 2 }', ret="Int"))
        self.ok(fn('fail("user", "x")', ret="Int"))

    def test_C52_break_outside_loop(self):
        self.bad(fn("break"), "E403")
        self.bad(fn("continue"), "E403")
        self.bad(fn("for i in 0..3 { let k = fn(x: Int) => { break } }"), "E403")
        self.ok(fn("for i in 0..3 { if i > 1 { break } else { continue } }"))

    def test_C53_unreachable(self):
        ds = diags(fn("return\nprint(1)\nprint(2)"))
        self.assertEqual(["E404"], [d.code for d in ds])
        self.assertEqual("warning", ds[0].severity)
        self.assertEqual(["E404"], warns(fn("for i in 0..2 { break\nprint(i) }")))

    def test_C54_returns(self):
        self.bad(fn("return 1"), "E221")
        self.ok(fn("return"))
        self.bad(fn("return", ret="Int"), "E210", hint="return <value>")
        self.bad(fn('return "s"', ret="Int"), "E210")
        self.ok(fn("let k = fn(x: Int) => { return x }\nprint(k(1))"))


# ---------------------------------------------------------------- match
class Match(Base):
    pre = "enum Mood { happy, sad, neutral }\nenum Act { go(to: Str), stop }\nlet LIMIT = 3"

    def test_C60_exhaustive(self):
        self.bad(fn("let m = Mood.happy\nmatch m { Mood.happy => 1, Mood.sad => 2 }", pre=self.pre),
                 "E401", msg="Mood.neutral")
        self.bad(fn("match true { true => 1 }"), "E401", msg="false")
        self.bad(fn("let a: Int? = 1\nmatch a { v => 1 }\nmatch a { none => 1, 3 => 2 }"), "E401", msg="other Int")
        self.bad(fn("let a: Int? = 1\nmatch a { 3 => 1, _ => 2 }\nmatch a { 1 => 1 }"), "E401", msg="none")
        self.bad(fn("match 1 { 1 => 1 }"), "E401", msg="other Int")
        self.ok(fn("match true { true => 1, false => 2 }\nmatch 1 { 1 => 1, n => n }\n"
                   "let m = Mood.happy\nmatch m { Mood.happy => 1, Mood.sad => 2, Mood.neutral => 3 }", pre=self.pre))
        self.ok(fn("let a: Act? = none\nmatch a { none => 0, Act.go(t) => 1, Act.stop => 2 }", pre=self.pre))
        self.bad(fn('match Act.stop { Act.go("x") => 1, Act.stop => 2 }', pre=self.pre), "E401", msg="Act.go")
        self.ok(fn("match Act.stop { Act.go => 1, Act.stop => 2 }", pre=self.pre))

    def test_C61_unreachable_arm(self):
        self.assertEqual(["E405"], warns(fn("match 1 { _ => 1, 2 => 2 }")))
        self.assertEqual(["E405"], warns(fn("match Mood.sad { Mood.sad => 1, Mood.sad => 2, _ => 3 }", pre=self.pre)))
        self.assertEqual(["E405"], warns(fn("match 1 { 1 => 1, 1 => 2, _ => 3 }")))
        self.assertEqual(["E405"], warns(fn("let a: Int? = 1\nmatch a { none => 1, none => 2, _ => 3 }")))

    def test_C62_pattern_errors(self):
        self.bad(fn('match 1 { "a" => 1, _ => 2 }'), "E406")
        self.bad(fn("match Mood.sad { Act.stop => 1, _ => 2 }", pre=self.pre), "E406")
        self.bad(fn("match Mood.sad { Mood.angry => 1, _ => 2 }", pre=self.pre), "E205")
        self.bad(fn('match Act.stop { Act.go(a, b) => 1, _ => 2 }', pre=self.pre), "E406", hint="Act.go(to)")
        self.bad(fn("match 1 { none => 1, _ => 2 }"), "E406")
        self.bad(fn("match 1 { Zed.a => 1, _ => 2 }"), "E204")
        self.ok(fn('match Act.go("x") { Act.go(t) => print(t.upper()), Act.stop => print(0) }', pre=self.pre))
        self.ok(fn("match 2.5 { 1 => 0, _ => 1 }"))

    def test_C63_binding_like_const(self):
        self.assertIn("E407", warns(fn("match 3 { LIMIT => 1 }", pre=self.pre)))
        self.assertIn("E407", warns(fn("match Mood.sad { happy => 1 }", pre=self.pre)))


# ---------------------------------------------------------------- effects
class Effects(Base):
    def test_C70_missing_uses(self):
        d = self.bad(ALLOW_ALL + 'fn f() -> Str { http.get("https://x.com") }', "E301",
                     hint="add `uses net` to fn f", count=1)
        self.assertEqual((10, 17), (d.line, d.col))
        self.bad(ALLOW_ALL + 'fn f() uses io { shell.run("ls") }', "E301", hint="uses io, shell")

    def test_C71_effects_through_calls(self):
        pre = ALLOW_ALL + "fn g() uses net { }\nai fn q(s: Str) -> Str { \"{s}\" }\n"
        self.bad(pre + "fn f() { g() }", "E301", msg="net")
        self.bad(pre + 'fn f() { print(q("a")) }', "E301", msg="ai")
        self.bad(pre + '/// d\nfn t() -> Int { 1 }\nagent fn a(s: Str) -> Str { tools [t]\n"{s}" }\n'
                 'fn f() { print(a("x")) }', "E301", msg="ai")
        self.ok(pre + 'fn f() uses ai, net { g()\nprint(q("a")) }')

    def test_C72_effects_through_values_and_lambdas(self):
        pre = ALLOW_ALL + "fn g() uses net { }\n"
        self.bad(pre + "fn f() { let h = g }", "E301", msg="net")
        self.bad(pre + 'fn f() { let k = fn(x: Int) => shell.run("ls") }', "E301", msg="shell")
        self.ok(pre + 'fn f() uses net { let k = fn(x: Int) => g() }')

    def test_C73_not_allowed(self):
        self.bad('fn f() uses net { http.get("u") }', "E302", hint='allow net ["example.com"]', count=1)
        self.bad("ai fn q(s: Str) -> Str { \"{s}\" }", "E302", hint="allow ai")
        self.bad('fn main() uses time { print(time.now()) }', "E302", hint="allow time")

    def test_C74_agent_tools(self):
        pre = ALLOW_ALL + ("/// web\nfn web(u: Str) -> Str uses net { http.get(u) }\n"
                           "/// cb\nfn cb(k: fn(Int) -> Int) -> Int { k(1) }\n"
                           "/// rf\nfn rf() -> fn(Int) -> Int { fn(x: Int) => x }\n"
                           "/// sub\nagent fn sub(s: Str) -> Str { tools [ok]\n\"{s}\" }\n"
                           "/// ok\nfn ok() -> Int { 1 }\n")
        self.ok(pre + 'agent fn a(s: Str) -> Str uses net { tools [web, ok]\n"{s}" }')
        self.bad(pre + 'agent fn a(s: Str) -> Str { tools [web]\n"{s}" }', "E301", hint="add `uses net` to agent fn a")
        self.bad(pre + 'agent fn a(s: Str) -> Str { tools [wbe]\n"{s}" }', "E203", hint="`web`")
        self.bad(pre + 'agent fn a(s: Str) -> Str { tools [sub]\n"{s}" }', "E232")
        self.bad(pre + 'agent fn a(s: Str) -> Str { tools [cb]\n"{s}" }', "E232")
        self.bad(pre + 'agent fn a(s: Str) -> Str { tools [rf]\n"{s}" }', "E232")
        self.bad(pre + 'agent fn a(s: Str) -> Str { tools [print]\n"{s}" }', "E232")
        self.bad(pre + 'agent fn a(s: Str) -> Str { tools [ok, ok]\n"{s}" }', "E202")
        self.assertIn("E308", warns(ALLOW_ALL + 'fn nd() -> Int { 1 }\nagent fn a(s: Str) -> Str { tools [nd]\n"{s}" }'))

    def test_C75_ai_jsonable(self):
        self.bad(ALLOW_ALL + 'ai fn q(k: fn(Int) -> Int) -> Str { "x" }', "E230")
        self.bad(ALLOW_ALL + 'ai fn q(s: Str) -> fn(Int) -> Int { "{s}" }', "E230")
        self.bad(ALLOW_ALL + 'type B = { f: fn() -> Int }\nai fn q(s: Str) -> B { "{s}" }', "E230")
        self.ok(ALLOW_ALL + 'type Node = { v: Int, kids: List[Node] }\nenum E { a(n: Node?), b }\n'
                'ai fn q(s: Str) -> Node { "{s}" }\nai fn q2(n: Node) -> E? { "{n.v}" }')

    def test_C76_prompt(self):
        pre = ALLOW_ALL + 'let STYLE = "short"\nfn helper() -> Str { "x" }\n'
        self.ok(pre + 'ai fn q(s: Str, n: Int) -> Str { "{STYLE}: {s} {n + 1} {s.upper()}" }')
        self.bad(pre + 'ai fn q(s: Str) -> Str { "{helper()} {s}" }', "E230", hint="parameter")
        self.bad(pre + 'ai fn q(s: Str) -> Str { "{time.now()} {s}" }', "E304")
        self.bad(pre + 'ai fn q(s: Str) -> Str { "{zz} {s}" }', "E203")

    def test_C77_attributes(self):
        def ai(attrs, kind="ai"):
            return ALLOW_ALL + f'/// t\nfn t() -> Int {{ 1 }}\n{attrs}\n{kind} fn q(s: Str) -> Str {{ ' + \
                ("tools [t]\n" if kind == "agent" else "") + '"{s}" }'
        self.ok(ai('@model("mock") @retries(0) @temperature(1) @system("be brief")'))
        self.ok(ai("@max_steps(1) @temperature(0.5)", "agent"))
        self.bad(ai("@modle(\"x\")"), "E231", hint="`model`")
        self.bad(ai("@max_steps(3)"), "E231", msg="agent fn")
        self.bad(ai("@retries(\"3\")"), "E231", hint="@retries(3)")
        self.bad(ai("@temperature(\"hot\")"), "E231")
        self.bad(ai("@retries(1.5)"), "E231")
        self.bad(ai("@retries(1) @retries(2)"), "E231", msg="twice")
        self.bad(ai("@retries(-1)"), "E231", msg="at least 0")
        self.bad(ai("@temperature(-0.5)"), "E231")
        self.bad(ai("@max_steps(0)", "agent"), "E231", msg="at least 1")

    def test_C78_allow(self):
        self.assertEqual(["E303"], warns('allow net ["a.com"]\nallow net ["b.com"]'))
        self.bad("allow net", "E306", hint='allow net ["example.com"]')
        self.bad('allow ai ["x"]', "E306", hint="allow ai")
        self.assertEqual(["E307"], warns("allow net []"))
        self.ok('allow fs.read ["./d"]\nallow time\nallow io')

    def test_C79_consts(self):
        self.ok('let A = 1\nlet B = A + 1\nlet C = "{B}"\nlet D = [A, B].map(fn(x) => x * 2)')
        self.bad(ALLOW_ALL + "let T = time.now()", "E304")
        self.bad("fn g() -> Int { 1 }\nlet K = g()", "E305")
        self.bad("let A = B + 1\nlet B = 1", "E305", hint="move `let B`")
        self.bad("let A: Int = \"s\"", "E210")
        self.ok("let A = 1\nfn f() -> Int { A + 1 }")

    def test_C80_tests_effects(self):
        self.ok(ALLOW_ALL + 'test "t" { print(time.now())\nprint(http.get("u")) }')
        self.bad('test "t" { print(time.now()) }', "E302", hint="allow time")

    def test_C81_mock(self):
        pre = ALLOW_ALL + 'type R = { a: Int }\nai fn q(s: Str) -> R { "{s}" }\nfn g(a: Int, b: Int) -> Int { a }\n'
        self.ok(pre + 'test "t" { mock q(s) => R { a: s.len() }\nmock g(x, y) => x + y\nassert q("ab").a == 2 }')
        self.bad(pre + "fn f() { mock g(a, b) => 1 }", "E240")
        self.bad(pre + 'test "t" { mock zz(a) => 1 }', "E203")
        self.bad(pre + 'test "t" { mock print(a) => 1 }', "E241")
        self.bad(pre + 'test "t" { mock g(a) => 1 }', "E241", hint="mock g(a, b)")
        self.bad(pre + 'test "t" { mock q(s) => "x" }', "E210")
        self.bad(pre + 'test "t" { mock g(a, b) => a.upper() }', "E205")

    def test_C82_budget(self):
        self.ok(fn("budget(ai_calls: 2, tokens: 100, usd: 0.5, seconds: 3) { print(1) }"))
        self.bad(fn("budget(calls: 2) { }"), "E242", hint="ai_calls")
        self.bad(fn("budget(ai_calls: 1.5) { }"), "E242")
        self.bad(fn('budget(usd: "1") { }'), "E242")
        self.assertEqual("Int", type_of("budget(seconds: 1) { 5 }"))

    def test_C83_main(self):
        self.ok("fn main() { }")
        self.ok("fn main(args: List[Str]) { print(args) }")
        self.bad("fn main(n: Int) { }", "E243")
        self.bad("fn main(a: List[Str], b: Int) { }", "E243")
        self.bad('allow ai\nai fn main(s: Str) -> Str { "{s}" }', "E243")


# ---------------------------------------------------------------- whole programs
class Programs(Base):
    def test_C93_errors_doc_examples(self):
        """Every code in docs/ERRORS.md has an example, and the example produces exactly that code."""
        with open(os.path.join(ROOT, "docs", "ERRORS.md"), encoding="utf-8") as f:
            doc = f.read()
        secs = re.findall(r"^### (E\d{3}).*?```sipar\n(.*?)```", doc, re.S | re.M)
        documented = [c for c, _ in secs]
        used = set()
        for name in ("checker.py", "parser.py", "lexer.py"):
            with open(os.path.join(ROOT, "sipar", name), encoding="utf-8") as f:
                used |= set(re.findall(r'"(E\d{3})"', f.read()))
        self.assertEqual(sorted(used), sorted(documented))
        for code, src in secs:
            with self.subTest(code=code):
                _, ds = check_source(src, "doc.sipar")
                self.assertEqual({code}, {d.code for d in ds}, [d.message for d in ds])

    def test_C90_tour(self):
        path = os.path.join(ROOT, "examples", "tour.sipar")
        with open(path, encoding="utf-8") as f:
            src = f.read()
        prog, ds = check_source(src, path)
        self.assertIsNotNone(prog)
        self.assertEqual([], [(d.code, d.line, d.message) for d in ds])

    def test_C91_sorted_and_syntax_errors(self):
        ds = diags(fn("let a = zz\nlet b = yy\nlet c = xx"))
        self.assertEqual([12, 13, 14], [d.line for d in ds])
        prog, ds = check_source("fn f( {", "bad.sipar")
        self.assertIsNone(prog)
        self.assertEqual(1, len(ds))
        self.assertTrue(ds[0].code.startswith("E1"))
        self.assertEqual("bad.sipar", ds[0].file)
        prog = parse("fn f() { let a = zz }", "p.sipar")
        ds = check(prog)
        self.assertEqual(["E203"], [d.code for d in ds])
        self.assertEqual("p.sipar", ds[0].file)

    def test_C92_many_errors(self):
        src = 'fn a() -> Int { "s" }\nfn b() { let x: Strr = 1 }\nfn c() { break }\nfn d() uses net { }'
        self.assertEqual(["E210", "E204", "E403", "E302"], errs(src))



# ---------------------------------------------------------------- precision (from mutation testing)
E2 = "enum C { red, green }\n"
R2 = "type R = { a: Int }\n"


class Precision(Base):
    """One mistake gives exactly one diagnostic, with the right words; the arguments of a wrong call are still
    checked (the `zz` cases). Most tests here were added because a mutation of checker.py survived."""

    def test_loops_break_continue(self):
        self.ok(fn("while true { break }\nfor x in [1] { break }\nfor x in [1] { continue }\nwhile true { continue }"))
        self.ok(fn("while true { continue }\nprint(1)"), warnings=["E404"])
        self.bad(fn("while true { break }\nbreak"), "E403", count=1, msg="`break`")
        self.bad(fn("for x in [1] { continue }\ncontinue"), "E403", count=1, msg="`continue`")
        self.bad(fn("while true { let g = fn(x: Int) => { break } }"), "E403", count=1)

    def test_block_scope_ends(self):
        self.bad(fn("if true { let y = 1 }\nprint(y)"), "E203", count=1)
        self.ok(fn("if true { let x = 1 }\nlet x = 2"))
        self.bad(fn("let a = 1\nmatch a { x => print(x), _ => print(1) }\nprint(x)"), "E203", count=1)

    def test_statement_branches_need_no_value(self):
        self.ok(fn("let c = true\nwhile c { if c { 1 } else { 2 } }\nfor i in [1] { if c { 1 } else { \"s\" } }"))
        self.ok('test "t" { if true { 1 } else { "s" } }')

    def test_one_error_each(self):
        cases = [
            (fn("for x in nope { print(x) }"), ["E203"]),
            (fn('let x: Int[Str] = "s"'), ["E204"]),
            (fn("let a = C", pre=E2), ["E206"]),
            (fn("let a = R", pre=R2), ["E206"]),
            (fn("let a = C { x: zz }", pre=E2), ["E206", "E203"]),
            (fn("let a = R.a", pre=R2), ["E206"]),
            (fn("let a = C.red\nlet b = a.x", pre=E2), ["E205"]),
            (fn("let a = 1\nlet b = a.x"), ["E205"]),
            (fn('let a = "abc"\nlet b = a["x"]'), ["E210"]),
            (fn('let a: List[Int]? = none\nlet b = a[0]'), ["E219"]),
            (fn("let a = 1\nlet b = a[0]"), ["E220"]),
            (fn('let a = [1]\nlet b = a["x"..1]'), ["E210"]),
            (fn("let a = 1\nlet b = a[0..1]"), ["E220"]),
            (fn("let a: List[Int]? = none\nlet b = a[0..1]"), ["E219"]),
            (fn('let a = ["a": 1]\nlet b = a[1]'), ["E210"]),
            (fn('let a = [1, "s", 2]'), ["E218"]),
            (fn('let a = ["a": 1, "b": "s", "c": 2]'), ["E218"]),
            (fn("let a = [1: 1]"), ["E210"]),
            (fn('let a = -"s"\nlet b: Int = a'), ["E214"]),
            (fn("let a = not 1\nlet b: Bool = a"), ["E214"]),
            (fn("let a = 1 and true\nlet b: Bool = a"), ["E214"]),
            (fn('let a: Int? = none\nlet b: Int = a ?? "s"'), ["E210"]),
            (fn('let a = 1 + "s"'), ["E214"]),
            (fn("let a: Int = if true { 1 }"), ["E218"]),
            (fn("let g: fn(Int) -> Int = fn(x: Str) => 1"), ["E210"]),
            (fn("let g: fn(Int) -> Int = fn(x: Int, y: Int) => 1"), ["E212"]),
            (fn("let a = [1].map(fn(x: Int, y: Int) => 1)"), ["E212"]),
            (fn("let g = fn(a: Int) => a\ng(a: 1)"), ["E212"]),
            ("type R = { h: fn(Int) -> Int }\nfn f(r: R) { r.h(a: 1) }", ["E212"]),
            ("type R = { h: Int }\nfn f(r: R) { r.h(zz) }", ["E213", "E203"]),
            ("type R = { h: Int }\nfn f(r: R) { r.k(zz) }", ["E205", "E203"]),
            (fn("let a: Int? = 1\nlet b = a.len()"), ["E219"]),
            (fn("let a = 1\nlet b = a.len(zz)"), ["E205", "E203"]),
            (fn('let a = "s"\nlet b = a.nope(zz)'), ["E205", "E203"]),
            (fn("let a = zz.len(yy)"), ["E203", "E203"]),
            (fn("let a = http.nope(zz)"), ["E205", "E203"]),
            (fn("let a = 1\nlet b = a(zz)"), ["E213", "E203"]),
            (fn("let g: (fn() -> Int)? = none\nlet b = g()"), ["E219"]),
            (fn("budget(tokenz: zz) { }"), ["E242", "E203"]),
            (fn('budget(tokens: "s") { }'), ["E242"]),
            ('allow ai\nfn h() -> Str { "x" }\nai fn g() -> Str {\n  "{h()}"\n}', ["E230"]),
        ]
        for src, codes in cases:
            with self.subTest(src=src.splitlines()[-2]):
                self.assertEqual(codes, errs(src), diags(src))

    def test_messages_and_hints(self):
        self.bad(fn("var a = 1\nvar a = 2"), "E202", hint="assign with `a = ...`")
        d = self.bad(fn("let a = 1\nlet a = 2"), "E202")
        self.assertNotIn("assign", d.hint)
        self.bad(fn("let m: Map[Str, Int?] = [:]"), "E204", hint="write Map[Int?]")
        self.bad(fn("let m: Map[Str, fn(Int) -> Int] = [:]"), "E204", hint="write Map[fn(Int) -> Int]")
        self.bad(fn('if "s" { }'), "E215", hint='s != ""')
        self.bad(fn("if [1] { }"), "E215", hint="xs.len() > 0")
        self.bad(fn("if 1 { }"), "E215", hint="x != 0")
        self.bad(fn('let a = ["a"].sum()'), "E214", msg="the list items to be Int or Float, found Str")
        d = self.bad("type R = { a: Int }\nfn f(r: List[R]) { r.sort() }", "E214",
                     msg="the list items to be Int, Float or Str, found R")
        self.assertIn("sort_by", d.hint)
        d = self.bad("type R = { a: Int }\nfn f(r: List[R]) { let s = r.sort_by(fn(x) => x) }", "E214",
                     msg="`sort_by` needs the key to be Int, Float or Str")
        self.assertIn("xs.sort_by(fn(x) => x.name)", d.hint)            # round 4 (C9): no empty hints
        self.ok("type R = { a: Int }\nfn f(r: List[R]) { let s = r.sort_by(fn(x) => x.a) }")
        self.bad(fn("let a = not 1"), "E214", msg="`not` needs a Bool, found Int")
        self.bad(fn("let a = -true"), "E214", msg="cannot negate a value of type Bool")
        self.bad(fn("let a = true or 2"), "E214", msg="`or` needs Bool operands, found Int")
        self.bad(fn("let a = 2 and true"), "E214", msg="`and` needs Bool operands, found Int")
        self.bad(fn("let a = 1\nlet b = a == none"), "E214", msg="always false")
        self.bad(fn("let a = 1\nlet b = a != none"), "E214", msg="always true")
        self.bad(fn("let a = 1\nlet b = none == a"), "E214", msg="type Int is never none")
        self.bad(fn("let a: Int = if true { 1 }"), "E218", msg="no value when the condition is false")
        self.bad(fn('let a = "abc"\nlet b = a["x"]'), "E210", msg="a string index")
        self.bad(fn('let a = [1]\nlet b = a["x"]'), "E210", msg="a list index")
        self.bad(fn("let a = [1].map(fn(x: Str) => 1)"), "E210", msg="parameter `x` is Str, but this lambda is given Int")
        self.bad(fn('budget(tokens: "s") { }'), "E242", hint="tokens: 5")
        self.bad(fn("budget(tokenz: 5) { }"), "E242", hint="did you mean `tokens`?")
        self.bad(fn("budget(nonsense: 5) { }"), "E242", hint="limits: ai_calls, tokens")
        self.bad(fn('let a = ["s", 2]\nlet b: Int = 1', ret=""), "E218", msg="found Str and Int")

    def test_none_and_optionals(self):
        self.bad(fn("let a: Int = none"), "E219", msg="Int is not optional", hint="(Int?)")
        self.ok(fn("let a: Int? = none\nlet b: Int = a ?? 2\nlet c: Int = none ?? 3\nlet d = a ?? none"))
        self.assertEqual("Int", type_of("a ?? 2", "let a: Int? = none"))
        self.assertEqual("Int?", type_of("a ?? b", "let a: Int? = none\nlet b: Int? = none"))
        self.assertEqual("Int?", type_of("a ?? none", "let a: Int? = none"))
        self.ok(fn("let a = 1\nlet b = a ?? 2"), warnings=["E250"])

    def test_comparisons(self):
        for op in ("<", "<=", ">", ">="):
            with self.subTest(op=op):
                self.assertEqual("Bool", type_of(f"1 {op} 2.5"))
                self.bad(fn(f"let a = [1] {op} [2]"), "E214", count=1)
        self.assertEqual("Bool", type_of('"a" == "b"'))
        self.assertEqual("Bool", type_of('"a" != "b"'))

    def test_patterns(self):
        pre = E2 + R2
        cases = [
            (fn("let a = 1\nmatch a { none => print(1), _ => print(2) }"), "E406", "never none"),
            (fn('let a = 1\nmatch a { "s" => print(1), _ => print(2) }'), "E406", "pattern is a Str"),
            (fn("let a = 1\nmatch a { Q.v(x) => print(x), _ => print(2) }", pre=pre), "E204", "unknown enum"),
            (fn("let a = 1\nmatch a { R.v(x) => print(x), _ => print(2) }", pre=pre), "E406", "is a record"),
            (fn("let a = 1\nmatch a { C.red(x) => print(x), _ => print(2) }", pre=pre), "E406", "is a C"),
            (fn("let a = C.red\nmatch a { C.blue(x) => print(x), _ => print(2) }", pre=pre), "E205", "no variant"),
            (fn("let a = C.red\nmatch a { C.red(x) => print(x), _ => print(2) }", pre=pre), "E406", "0 field(s)"),
            (fn("let a = C.red\nmatch a { C.red => print(1) }", pre=pre), "E401", "missing C.green"),
            (fn("let a = true\nmatch a { true => print(1) }"), "E401", "missing false"),
            (fn("let a = true\nmatch a { false => print(1) }"), "E401", "missing true"),
            (fn("let a: C? = none\nmatch a { C.red => print(1), C.green => print(2) }", pre=pre), "E401", "missing none"),
            (fn("let a = 1.5\nmatch a { 1 => print(1) }"), "E401", "other Float values"),
        ]
        for src, code, msg in cases:
            with self.subTest(src=src.splitlines()[-2]):
                self.bad(src, code, count=1, msg=msg)
        self.ok(fn("let a: C? = none\nmatch a { none => print(0), C.red => print(1), C.green => print(2) }", pre=pre))
        self.ok(fn("let a: Int? = none\nmatch a { none => print(0), 1 => print(1), _ => print(2) }"))
        self.ok(fn("let a = 1.5\nmatch a { 1 => print(1), 2.5 => print(2), _ => print(3) }"))
        self.ok(fn("let a = true\nmatch a { true => print(1), false => print(2) }"))
        self.ok('let K = 1\nfn f(a: Int) { match a { K => print(1) } }', warnings=["E407"])

    def test_sub_patterns(self):
        pre = "enum P { v(n: Int), w }\nenum Q { u(p: P?), z }\n"
        self.ok(fn("let a = P.w\nmatch a { P.v(x) => print(x + 1), P.w => print(0) }", pre=pre))
        self.ok(fn("let a = Q.z\nmatch a { Q.u(P.v(1)) => print(1), Q.u(none) => print(2), _ => print(3) }", pre=pre))
        self.ok(fn("let a = Q.z\nmatch a { Q.u(P.v(n)) => print(n + 1), _ => print(3) }", pre=pre))
        cases = [
            ("let a = P.w\nmatch a { P.v(none) => print(1), _ => print(2) }", "never none"),
            ('let a = P.w\nmatch a { P.v("s") => print(1), _ => print(2) }', "pattern is a Str"),
            ("let a = P.w\nmatch a { P.v(1.5) => print(1), _ => print(2) }", "pattern is a Float"),
            ("let a = Q.z\nmatch a { Q.u(Q.z) => print(1), _ => print(2) }", "is a Q, but the value is P"),
        ]
        for body, msg in cases:
            with self.subTest(body=body):
                self.bad(fn(body, pre=pre), "E406", count=1, msg=msg)
        # a wrong literal arm reports E406 once and is not counted as covering that value
        src = fn('let a = 1\nmatch a { "s" => print(1), "s" => print(2), _ => print(3) }')
        self.assertEqual(["E406", "E406"], errs(src))
        self.assertEqual([], warns(src))

    def test_expected_type_flows_into_lambdas(self):
        self.ok("fn f() -> fn(Int) -> Int { fn(x) => x }")
        self.ok("fn f() -> fn(Int) -> Int { return fn(x) => x }")
        self.ok(fn("var g: fn(Int) -> Int = fn(x) => x\ng = fn(x) => x + 1"))
        self.ok(fn("let a: (fn(Int) -> Int)? = none\nlet g: fn(Int) -> Int = a ?? fn(x) => x"))
        self.ok("fn g() -> fn(Int) -> Int { fn(x) => x }\ntest \"t\" { mock g() => fn(x) => x + 1 }")
        self.ok(fn('let g: fn(Int) -> None = fn(x) => "s"'))
        self.bad(fn('let g: fn(Int) -> Int = fn(x) => "s"'), "E210", count=1, msg="this lambda must return Int")
        self.bad(fn("let g = fn(x: Int) => if x > 0 { 1 }"), "E218", count=1)
        self.bad(fn("let g = fn(x: Int) => x\nprint(x)"), "E203", count=1)
        self.bad(fn('let g = fn(x: Int) => {\nif x > 0 { return 1 }\n"s"\n}'), "E218", count=1, msg="returns both")

    def test_more_single_errors(self):
        cases = [
            (fn("let a: Int = none"), ["E219"]),
            (fn("let a = print(1)\nlet b: Int = a"), ["E210"]),
            (fn("let a = none\nlet b: Int = a"), ["E211"]),
            (fn("let a = []\nlet b: Int = a"), ["E211"]),
            (fn('let a: List[Int] = ["s", 2.5]'), ["E210", "E210"]),
            (fn('let a = [1, "s", "t"]'), ["E218"]),
            (fn('let a: Map[Int] = ["a": "s", "b": 2.5]'), ["E210", "E210"]),
            (fn('let a = ["a": 1, "b": "s", "c": "t"]'), ["E218"]),
            (fn("let a = R { a: 1, b: zz }", pre=R2), ["E203", "E205"]),
            (fn("let a = -zz\nlet b: Str = a"), ["E203"]),
            (fn("let a = not zz\nlet b: Int = a"), ["E203", "E210"]),
            (fn('let a = 1\nlet b: Str = a ?? "s"'), ["E210"]),
            (fn('let a = if true { 1 } else { "s" }\nlet b: Bool = a'), ["E218"]),
            (fn('let a = 1\na = "s"'), ["E207"]),
            (fn('let s = "ab"\ns[zz] = "c"'), ["E220", "E203"]),
            ("fn g(a: Int, b: Int) -> Int { a }\ntest \"t\" { mock g(a) => a + 1 }", ["E241"]),
            ("fn g(a: Int, b: Int) -> Int { a }\nfn f() { mock g(a, b) => 1 }", ["E240"]),
        ]
        for src, codes in cases:
            with self.subTest(src=src.splitlines()[-2]):
                self.assertEqual(codes, errs(src), diags(src))
        self.ok(fn("let c = true\nwhile c { if c { 1 } }\nfor i in [1] { if true { 1 } }"))
        self.ok(fn("assert true\nprint(1)"))
        self.ok("fn g(x: Int, y: Int) -> Int { x }\ntest \"t\" { mock g(x, y) => x + y\nlet x = 1 }")
        self.bad("fn g(x: Int, y: Int) -> Int { x }\ntest \"t\" { mock g(x, y) => x + y\nreturn 1 }", "E221",
                 msg='test "t" does not return')
        self.bad(fn("let a: Str = 1"), "E210", hint="as Str")
        self.assertEqual("List[Int]", type_of("[1] + []"))
        self.assertEqual("List[Int]", type_of("[] + [1]"))

    def test_bad_calls_give_unknown_and_still_check_args(self):
        cases = [
            (fn("let a = min(1, 2, 3)\nlet b: Str = a"), ["E212"]),
            (fn("let a = min(zz, 2)\nlet b: Str = a"), ["E203"]),
            (fn('let a = http.get("u", headerz: zz)\nlet b: Int = a', uses="net"), ["E212", "E203"]),
            (fn('let a = http.get(headers: ["a": "b"])\nlet b: Int = a', uses="net"), ["E212"]),
            (fn('let a = http.get("u", headers: 5)', uses="net"), ["E210"]),
            (fn("let a = [1].sort_by(zz)"), ["E203"]),
            ('allow ai\nallow net ["x.com"]\nfn h() -> Str uses net { "x" }\nai fn g() -> Str {\n  "{h()}"\n}', ["E230"]),
            ('allow ai\nfn h(a: Int) -> Str { "x" }\nai fn g() -> Str {\n  "{h(zz)}"\n}', ["E230", "E203"]),
            ('allow net ["x.com"]\nfn h() -> Str uses net { "x" }\nlet K = h()\n', ["E305"]),
            (fn("let a = http.get", uses="net"), ["E206"]),
            (fn("let a = http.nope"), ["E205"]),
            (fn("let a: R? = none\nlet b = a.a", pre=R2), ["E219"]),
            (fn("let b = [1].len"), ["E206"]),
            (fn("let a = C.blue(zz)", pre=E2), ["E205", "E203"]),
            (fn("let a = C.red(zz)", pre=E2), ["E212", "E203"]),
            (fn("let a = zz(yy)"), ["E203", "E203"]),
            (fn("let a = 1\nlet b: Str = a(2)"), ["E213"]),
            (fn("let a: Int? = 1\nlet b = a.len(zz)"), ["E219", "E203"]),
        ]
        for src, codes in cases:
            with self.subTest(src=src.strip().splitlines()[-2]):
                self.assertEqual(codes, errs(src), diags(src))
        self.bad(fn("let g = fn(a: Int) => a\ng(a: 1)"), "E212", count=1, msg="positional arguments only")
        self.bad(fn("let a = C.red\nlet b = a.x", pre=E2), "E205", msg="values have no fields")
        self.bad(fn("let a = R.a", pre=R2), "E206", msg="read fields from a value")

    def test_C94_fuzz_never_crashes(self):
        """Robustness: 600 mutated programs (lines deleted / duplicated / swapped, tokens inserted) built from
        tour.sipar and the ERRORS.md examples. check_source must return diagnostics, never raise."""
        import random
        with open(os.path.join(ROOT, "examples", "tour.sipar"), encoding="utf-8") as f:
            corpus = [f.read()]
        with open(os.path.join(ROOT, "docs", "ERRORS.md"), encoding="utf-8") as f:
            corpus += re.findall(r"```sipar\n(.*?)```", f.read(), re.S)
        toks = ["{", "}", "(", ")", "[", "]", ",", ":", "=>", "->", "?", "??", "none", "fn", "let x = ",
                "return", "match", "if", "else", "uses net", ".", "..", '"s"', '"{x}"', "1", "1.5", "_",
                "\n", "break", "as Int", "Int", "List[", "x", "@model(\"m\")", "catch e", "try"]
        rng = random.Random(20261107)
        for n in range(600):
            lines = rng.choice(corpus).split("\n")
            for _ in range(rng.randint(1, 3)):
                k = rng.randrange(len(lines))
                op = rng.randrange(4)
                if op == 0 and len(lines) > 1:
                    del lines[k]
                elif op == 1:
                    lines.insert(k, lines[k])
                elif op == 2:
                    j = rng.randrange(len(lines))
                    lines[k], lines[j] = lines[j], lines[k]
                else:
                    ln = lines[k]
                    c = rng.randint(0, len(ln))
                    lines[k] = ln[:c] + " " + rng.choice(toks) + " " + ln[c:]
            src = "\n".join(lines)
            try:
                _, ds = check_source(src, "fuzz.sipar")
            except Exception as ex:  # noqa: BLE001
                self.fail(f"program {n} raised {type(ex).__name__}: {ex}\n{src}")
            self.assertTrue(all(d.code.startswith("E") for d in ds))



class SecretLikeEnv(unittest.TestCase):
    def test_E309_secret_like_names_warn(self):
        for name in ["API_KEY", "github_token", "DB_PASSWORD", "MY_SECRET", "AUTH_HEADER"]:
            w = warns('allow env ["%s"]\nfn main() uses env { print(env.get("%s") ?? "") }' % (name, name))
            self.assertEqual(w, ["E309"], name)

    def test_E309_plain_names_quiet(self):
        w = warns('allow env ["HOME", "LANG", "PATH"]\nfn main() uses env { print(env.get("HOME") ?? "") }')
        self.assertEqual(w, [])

if __name__ == "__main__":
    unittest.main()
