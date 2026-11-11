"""Interpreter core (cases I1-I28)."""
import unittest

from rt_helpers import Prog, error, main_src, run

from sipar.stdlib import FUNCTIONS, METHODS


def lines(out):
    return out.strip("\n").split("\n")


class Scopes(unittest.TestCase):
    def test_I1_let_var_shadowing(self):
        out = run('let x = 1\nvar y = 2\n{ let x = 10\n y = y + x\n print(x) }\nprint(x)\nprint(y)')
        self.assertEqual(lines(out), ["10", "1", "12"])

    def test_I2_assign_to_let(self):
        e = error('let x = 1\nx = 2')
        self.assertEqual(e.kind, "type")
        self.assertIn("let", e.message)
        self.assertEqual(e.line, 4)

    def test_I2_assign_undeclared(self):
        self.assertEqual(error('zz = 2').kind, "type")


class Arithmetic(unittest.TestCase):
    def test_I3_floor_div_mod(self):
        out = run('print(-7 / 2)\nprint(-7 % 2)\nprint(7 / -2)\nprint(7 % -2)\nprint(7 / 2)\nprint(7.0 / 2)')
        self.assertEqual(lines(out), ["-4", "1", "-4", "-1", "3", "3.5"])

    def test_I4_zero(self):
        for expr in ("1 / 0", "1 % 0", "1.0 / 0.0", "1.5 % 0"):
            with self.subTest(expr=expr):
                e = error(f'let z = {expr}')
                self.assertEqual(e.kind, "zero")

    def test_I4_zero_catchable(self):
        out = run('let r = try { 1 / 0 } catch e { e.kind }\nprint(r)')
        self.assertEqual(out, "zero\n")

    def test_I5_widening(self):
        src = 'fn half(x: Float) -> Float { x / 2.0 }\nfn main() {\n print(half(3))\n print(1 + 2.5)\n let f: Float = 2\n print(f) }'
        p = Prog(src)
        self.assertEqual(lines(p.run()), ["1.5", "3.5", "2.0"])

    def test_I21_short_circuit_and_coalesce(self):
        out = run('print(false and 1 / 0 == 1)\nprint(true or 1 / 0 == 1)\nlet a: Int? = none\n'
                  'print(a ?? 5)\nprint(3 ?? 1 / 0)\nlet m = ["k": 1]\nprint(m.get("x") ?? m.get("k") ?? 0)')
        self.assertEqual(lines(out), ["false", "true", "5", "3", "1"])

    def test_bool_ops_type_error(self):
        self.assertEqual(error('print(1 and true)').kind, "type")
        self.assertEqual(error('print(not 1)').kind, "type")
        self.assertEqual(error('if 1 { print(1) }').kind, "type")

    def test_comparisons(self):
        out = run('print(1 < 2.5)\nprint("a" < "b")\nprint(2 >= 2)\nprint(1 == 1.0)\nprint(true == 1)')
        self.assertEqual(lines(out), ["true", "true", "true", "true", "false"])
        self.assertEqual(error('print(1 < "a")').kind, "type")

    def test_string_and_list_concat(self):
        out = run('print("a" + "b")\nprint([1] + [2, 3])')
        self.assertEqual(lines(out), ["ab", "[1, 2, 3]"])
        self.assertEqual(error('print("a" + 1)').kind, "type")

    def test_in_operator(self):
        out = run('print(2 in [1, 2])\nprint("k" in ["k": 1])\nprint("ell" in "hello")\nprint(5 in [1])')
        self.assertEqual(lines(out), ["true", "true", "true", "false"])


class References(unittest.TestCase):
    def test_I6_reference_semantics(self):
        src = ('type P = { n: Int }\nfn bump(p: P) { p.n = p.n + 1 }\nfn main() {\n'
               ' let xs = [1]\n let ys = xs\n ys.push(2)\n print(xs)\n'
               ' let m = ["a": 1]\n let m2 = m\n m2["b"] = 2\n print(m)\n'
               ' let p = P { n: 1 }\n bump(p)\n print(p.n) }')
        self.assertEqual(lines(Prog(src).run()), ["[1, 2]", '{"a": 1, "b": 2}', "2"])

    def test_I7_structural_equality(self):
        src = ('type P = { n: Int, xs: List[Int] }\nenum E { a, b(x: Int) }\nfn main() {\n'
               ' print(P { n: 1, xs: [1] } == P { n: 1, xs: [1] })\n print(P { n: 1, xs: [1] } == P { n: 1, xs: [2] })\n'
               ' print(E.b(1) == E.b(1))\n print(E.b(1) == E.b(2))\n print(E.a == E.a)\n'
               ' print([["a": [1]]] == [["a": [1]]])\n print([1, 2] != [2, 1]) }')
        self.assertEqual(lines(Prog(src).run()), ["true", "false", "true", "false", "true", "true", "true"])

    def test_I25_cyclic_list(self):
        out = run('let xs: List[Any] = [1]\nxs.push(xs)\nprint(xs)\nprint(xs.len())')
        self.assertEqual(lines(out), ['[1, "[...]"]', "2"])


class Functions(unittest.TestCase):
    def test_I8_closures_higher_order(self):
        src = ('fn adder(n: Int) -> fn(Int) -> Int { fn(x: Int) -> Int => x + n }\nfn main() {\n'
               ' let add5 = adder(5)\n print(add5(1))\n var k = 1\n let f = fn() => k\n k = 7\n print(f())\n'
               ' print([1, 2, 3].map(fn(x) => x * 10))\n print([1, 2, 3, 4].filter(fn(x) => x % 2 == 0))\n'
               ' print([1, 2, 3].reduce(0, fn(a, x) => a + x))\n print(["bb", "a", "ccc"].sort_by(fn(s) => s.len()))\n'
               ' print([3, 1, 2].sort())\n print([1, 2].any(fn(x) => x > 1))\n print([1, 2].all(fn(x) => x > 1)) }')
        self.assertEqual(lines(Prog(src).run()),
                         ["6", "7", "[10, 20, 30]", "[2, 4]", "6", '["a", "bb", "ccc"]', "[1, 2, 3]", "true", "false"])

    def test_fn_ref_and_builtin_as_value(self):
        src = 'fn dbl(x: Int) -> Int { x * 2 }\nfn main() {\n let f = dbl\n print([1, 2].map(f))\n print(f(4)) }'
        self.assertEqual(lines(Prog(src).run()), ["[2, 4]", "8"])

    def test_named_args_and_missing(self):
        src = 'fn f(a: Int, b: Int) -> Int { a - b }\nfn main() {\n print(f(b: 1, a: 5)) }'
        self.assertEqual(Prog(src).run(), "4\n")
        src2 = 'fn f(a: Int, b: Int) -> Int { a - b }\nfn main() {\n print(f(1)) }'
        self.assertEqual(Prog(src2).error().kind, "type")

    def test_return_early(self):
        src = 'fn f(x: Int) -> Str {\n if x > 0 { return "pos" }\n "non-pos" }\nfn main() { print(f(1))\n print(f(0)) }'
        self.assertEqual(lines(Prog(src).run()), ["pos", "non-pos"])

    def test_I20_deep_recursion_clean_error(self):
        src = 'fn f(n: Int) -> Int { if n == 0 { 0 } else { 1 + f(n - 1) } }\nfn main() { print(f(100000)) }'
        e = Prog(src).error()
        self.assertEqual(e.kind, "value")
        self.assertIn("depth", e.message)

    def test_I20_moderate_recursion_ok(self):
        src = 'fn f(n: Int) -> Int { if n == 0 { 0 } else { 1 + f(n - 1) } }\nfn main() { print(f(500)) }'
        self.assertEqual(Prog(src).run(), "500\n")

    def test_I26_main_args(self):
        p = Prog('fn main(args: List[Str]) { print(args)\n print(args.len()) }')
        self.assertEqual(lines(p.run(argv=["a b", "ç"])), ['["a b", "ç"]', "2"])
        self.assertEqual(lines(p.run(argv=[])), ["[]", "0"])

    def test_no_main(self):
        self.assertEqual(Prog('fn other() { }').error().kind, "type")

    def test_I27_constants(self):
        src = 'let A = 2\nlet B = A * 3\nfn f() -> Int { B + 1 }\nfn main() { print(f()) }'
        self.assertEqual(Prog(src).run(), "7\n")


class ControlFlow(unittest.TestCase):
    def test_I9_expressions(self):
        src = ('enum C { r, g }\nfn main() {\n let a = { let t = 2\n t * 3 }\n'
               ' let b = if a > 5 { "big" } else { "small" }\n'
               ' let c = match C.g { C.r => 1, C.g => 2 }\n'
               ' let d = try { fail("user", "x") } catch e { e.message }\n'
               ' let f = budget(ai_calls: 1) { 42 }\n'
               ' let g = if false { 1 }\n'
               ' print("{a} {b} {c} {d} {f} {g}") }')
        self.assertEqual(Prog(src).run(), "6 big 2 x 42 none\n")

    def test_I10_for_forms(self):
        out = run('for x in [1, 2] { print(x) }\nlet m = ["z": 1, "a": 2]\nfor k in m { print(k) }\n'
                  'for i in 0..3 { if i == 1 { continue }\n print(i) }\n'
                  'for i in range(5, 100) { if i == 7 { break }\n print(i) }\nfor ch in "hé" { print(ch) }')
        self.assertEqual(lines(out), ["1", "2", "z", "a", "0", "2", "5", "6", "h", "é"])

    def test_I10_while_break(self):
        out = run('var i = 0\nwhile true { i = i + 1\n if i > 3 { break } }\nprint(i)')
        self.assertEqual(out, "4\n")

    def test_I11_for_over_mutated_list_terminates(self):
        out = run('let xs = [1, 2]\nfor x in xs { xs.push(x) }\nprint(xs)')
        self.assertEqual(out, "[1, 2, 1, 2]\n")

    def test_I12_match_patterns(self):
        src = ('enum Sh { circle(r: Int), rect(w: Int, h: Int), dot }\n'
               'fn d(s: Sh) -> Str { match s { Sh.circle(1) => "unit", Sh.circle(r) => "c{r}", '
               'Sh.rect(w, _) => "w{w}", Sh.dot => "dot" } }\n'
               'fn lit(x: Int?) -> Str { match x { none => "none", 0 => "zero", n => "n{n}" } }\n'
               'fn main() { print(d(Sh.circle(1)))\n print(d(Sh.circle(r: 3)))\n print(d(Sh.rect(2, 5)))\n'
               ' print(d(Sh.dot))\n print(lit(none))\n print(lit(0))\n print(lit(9))\n'
               ' print(match "hi" { "hi" => true, _ => false }) }')
        self.assertEqual(lines(Prog(src).run()), ["unit", "c3", "w2", "dot", "none", "zero", "n9", "true"])

    def test_I13_no_arm(self):
        e = error('let x = match 5 { 1 => "a" }')
        self.assertEqual(e.kind, "value")

    def test_I22_try_catch_fail(self):
        out = run('let r = try { fail("user", "boom") } catch e { "{e.kind}:{e.message}" }\nprint(r)\n'
                  'try { let xs = [1]\n print(xs[5]) } catch e { print(e.kind) }')
        self.assertEqual(lines(out), ["user:boom", "index"])

    def test_I22_uncaught_position(self):
        p = Prog(main_src('let a = 1\nlet b = [1][3]'))
        e = p.error()
        self.assertEqual((e.kind, e.line), ("index", 4))
        self.assertGreater(e.col, 0)

    def test_I23_assert(self):
        e = error('assert 1 == 2, "math is broken"')
        self.assertEqual((e.kind, e.message), ("assert", "math is broken"))
        self.assertEqual(error('assert false').message, "assertion failed")
        self.assertEqual(run('assert true\nprint("ok")'), "ok\n")

    def test_break_in_closure_inside_loop_is_error_not_crash(self):
        src = 'fn f() { break }\nfn main() { for x in [1] { f() } }'
        self.assertEqual(Prog(src).error().kind, "type")


class Rendering(unittest.TestCase):
    def test_I14_interpolation(self):
        src = ('type P = { name: Str, n: Int }\nenum E { a, b(x: Str) }\nfn main() {\n'
               ' let p = P { name: "Ала", n: 1 }\n print("{p}")\n print("{[\"x\", 1]}")\n'
               ' print("{none} {true} {1.5} {E.a} {[E.a]} {E.b(\"q\")}")\n print(["k": "v"])\n print("日本 {2}") }')
        self.assertEqual(lines(Prog(src).run()),
                         ['{"name": "Ала", "n": 1}', '["x", 1]', 'none true 1.5 a ["a"] {"tag": "b", "x": "q"}',
                          '{"k": "v"}', "日本 2"])


class Conversions(unittest.TestCase):
    def test_I15_scalars(self):
        out = run('print("42" as Int + 1)\nprint(" 2.5 " as Float)\nprint("TRUE" as Bool)\nprint(3.9 as Int)\n'
                  'print(-3.9 as Int)\nprint(2 as Float)\nprint([1] as Str)\nprint(1 as Str + "x")')
        self.assertEqual(lines(out), ["43", "2.5", "true", "3", "-3", "2.0", "[1]", "1x"])

    def test_I15_bad_input(self):
        for expr in ('"4x" as Int', '"" as Float', '"yes" as Bool'):
            with self.subTest(expr=expr):
                self.assertEqual(error(f'let v = {expr}').kind, "decode")

    def test_I16_json_decode(self):
        src = ('type R = { a: Int, b: Str?, xs: List[Float] }\nenum M { happy, sad }\nfn main() {\n'
               ' let r = "\\{\\"a\\": 1, \\"xs\\": [1, 2.5], \\"extra\\": 0\\}" as R\n print(r)\n'
               ' print("\\"sad\\"" as M)\n print("[1, 2]" as List[Int])\n print("\\{\\"k\\": true\\}" as Map[Bool]) }')
        self.assertEqual(lines(Prog(src).run()),
                         ['{"a": 1, "b": null, "xs": [1.0, 2.5]}', "sad", "[1, 2]", '{"k": true}'])

    def test_I16_json_errors(self):
        head = 'type R = { a: Int, b: Str }\nenum M { happy, sad }'
        cases = ['"\\{\\"a\\": 1\\}" as R', '"\\{\\"a\\": \\"x\\", \\"b\\": \\"y\\"\\}" as R', '"\\{nope" as R',
                 '"\\"angry\\"" as M', '"[1, \\"a\\"]" as List[Int]', '"[1]" as Map[Int]']
        for c in cases:
            with self.subTest(c=c):
                e = error(f'let v = {c}', head)
                self.assertEqual(e.kind, "decode", e.message)

    def test_I16_decode_error_has_path(self):
        e = error('let v = "\\{\\"a\\": \\"x\\", \\"b\\": \\"y\\"\\}" as R', 'type R = { a: Int, b: Str }')
        self.assertIn("$.a", e.message)


class Indexing(unittest.TestCase):
    def test_I17_errors(self):
        self.assertEqual(error('let v = [1, 2][2]').kind, "index")
        self.assertEqual(error('let v = [1, 2][-1]').kind, "index")
        self.assertEqual(error('let v = "ab"[5]').kind, "index")
        self.assertEqual(error('let v = ["a": 1]["b"]').kind, "key")
        self.assertEqual(error('let v = [1][true]').kind, "type")

    def test_I17_assign_index(self):
        out = run('let xs = [1, 2]\nxs[1] = 9\nprint(xs)')
        self.assertEqual(out, "[1, 9]\n")
        self.assertEqual(error('let xs = [1]\nxs[3] = 1').kind, "index")

    def test_I18_slices(self):
        out = run('let xs = [0, 1, 2, 3]\nprint(xs[1..3])\nprint(xs[2..99])\nprint(xs[3..1])\n'
                  'print("日本語です"[1..3])\nprint("abc"[-5..2])\nprint("日本"[1])')
        self.assertEqual(lines(out), ["[1, 2]", "[2, 3]", "[]", "本語", "ab", "本"])


class Stdlib(unittest.TestCase):
    def test_I19_global_functions(self):
        out = run('print(min(1, 2.5))\nprint(max(3, 2))\nprint(abs(-2))\nprint(abs(-2.5))\nprint(round(2.5))\n'
                  'print(round(-2.5))\nprint(round(2.4))\nprint(floor(-1.5))\nprint(range(1, 4))\nprint(range(3, 1))\n'
                  'print(json.encode(["a": [1, none]]))')
        self.assertEqual(lines(out), ["1.0", "3", "2", "2.5", "3", "-3", "2", "-2", "[1, 2, 3]", "[]",
                                      '{"a": [1, null]}'])

    def test_I19_str_methods(self):
        out = run('let s = " Hi, There "\nprint(s.len())\nprint(s.upper())\nprint(s.lower())\nprint(s.trim())\n'
                  'print("a,b".split(","))\nprint("a\\nb".lines())\nprint(s.contains("Hi"))\n'
                  'print("abc".starts_with("ab"))\nprint("abc".ends_with("bc"))\nprint("aXa".replace("a", "b"))\n'
                  'print("abc".find("c"))\nprint("abc".find("z"))\nprint("ab".repeat(3))')
        self.assertEqual(lines(out), ["11", " HI, THERE ", " hi, there ", "Hi, There", '["a", "b"]', '["a", "b"]',
                                      "true", "true", "true", "bXb", "2", "none", "ababab"])

    def test_I19_list_methods(self):
        out = run('let xs = [3, 1, 2]\nprint(xs.len())\nxs.push(5)\nprint(xs.pop())\nprint([].pop())\n'
                  'print(xs.join("-"))\nprint(xs.reverse())\nprint(xs.contains(1))\nprint(xs.index_of(2))\n'
                  'print(xs.index_of(9))\nprint(xs.first())\nprint(xs.last())\nprint([].first())\nprint(xs.sum())\n'
                  'print([1.5, 2].sum())\nprint(xs.take(2))\nprint(xs.skip(2))\nprint(xs.take(-1))')
        self.assertEqual(lines(out), ["3", "5", "none", "3-1-2", "[2, 1, 3]", "true", "2", "none", "3", "2", "none",
                                      "6", "3.5", "[3, 1]", "[2]", "[]"])

    def test_I19_map_methods(self):
        out = run('let m = ["a": 1, "b": 2]\nprint(m.len())\nprint(m.keys())\nprint(m.values())\nprint(m.has("a"))\n'
                  'print(m.get("z"))\nprint(m.remove("a"))\nprint(m)')
        self.assertEqual(lines(out), ["2", '["a", "b"]', "[1, 2]", "true", "none", "1", '{"b": 2}'])

    def test_I19_every_stdlib_entry_has_an_implementation(self):
        from sipar.runtime.builtins import FUNCS, m_list, m_map, m_str
        self.assertEqual(set(FUNCTIONS) - set(FUNCS), set())
        import inspect
        srcs = {"Str": inspect.getsource(m_str), "List": inspect.getsource(m_list), "Map": inspect.getsource(m_map)}
        for ty, ms in METHODS.items():
            for name in ms:
                self.assertIn(f'"{name}"', srcs[ty], f"{ty}.{name}")

    def test_sort_mixed_types_error(self):
        self.assertEqual(error('print([1, "a"].sort())').kind, "type")

    def test_unknown_method(self):
        self.assertEqual(error('print("a".nope())').kind, "type")
        self.assertEqual(error('print(1.len())').kind, "type")

    def test_I24_huge_allocations_refused(self):
        self.assertEqual(error('let s = "a".repeat(1000000000)').kind, "value")
        self.assertEqual(error('let xs = range(0, 1000000000)').kind, "value")
        self.assertEqual(error('let xs = 0..1000000000\nprint(xs.len())').kind, "value")

    def test_I24_big_range_loop_not_materialised(self):
        out = run('var n = 0\nfor i in 0..1000000000 { n = n + 1\n if n == 3 { break } }\nprint(n)')
        self.assertEqual(out, "3\n")


class Records(unittest.TestCase):
    def test_record_literal_errors(self):
        head = 'type P = { a: Int, b: Str? }'
        self.assertEqual(run('print(P { a: 1 })', head), '{"a": 1, "b": null}\n')
        self.assertEqual(error('print(P { b: "x" })', head).kind, "type")
        self.assertEqual(error('print(P { a: 1, z: 2 })', head).kind, "type")
        self.assertEqual(error('let p = P { a: 1 }\nprint(p.zz)', head).kind, "type")

    def test_enum_payload_access_and_errors(self):
        head = 'enum E { a, b(x: Int) }'
        self.assertEqual(error('let v = E.zz', head).kind, "type")
        self.assertEqual(error('let v = E.a(1)', head).kind, "type")
        self.assertEqual(run('print(E.b(x: 2))', head), '{"tag": "b", "x": 2}\n')


if __name__ == "__main__":
    unittest.main()
