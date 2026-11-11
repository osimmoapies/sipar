"""Lexer + parser tests (cases P01-P26).

Expressions are compared through a compact S-expression rendering (`sx`), so a precedence
or shape change shows up as a readable diff."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sipar import ast as A                      # noqa: E402
from sipar.errors import SiparSyntaxError       # noqa: E402
from sipar.lexer import tokenize                # noqa: E402
from sipar.parser import parse                  # noqa: E402


def ty(t) -> str:
    if isinstance(t, A.TOptional):
        return ty(t.inner) + "?"
    if isinstance(t, A.TFn):
        return f"fn({', '.join(ty(p) for p in t.params)})->{ty(t.ret)}"
    return t.name + (f"[{', '.join(ty(a) for a in t.args)}]" if t.args else "")


def sx(e) -> str:
    """Render an expression / statement / pattern as an S-expression."""
    if isinstance(e, A.IntLit) or isinstance(e, A.FloatLit):
        return repr(e.value)
    if isinstance(e, A.BoolLit):
        return "true" if e.value else "false"
    if isinstance(e, A.NoneLit):
        return "none"
    if isinstance(e, A.StrLit):
        return '"' + "".join(p if isinstance(p, str) else "{" + sx(p) + "}" for p in e.parts) + '"'
    if isinstance(e, A.Name):
        return e.name
    if isinstance(e, A.ListLit):
        return "[" + ", ".join(sx(i) for i in e.items) + "]"
    if isinstance(e, A.MapLit):
        return "[" + (", ".join(f"{sx(k)}: {sx(v)}" for k, v in e.entries) or ":") + "]"
    if isinstance(e, A.RecordLit):
        return e.type_name + "{" + ", ".join(f"{n}: {sx(v)}" for n, v in e.fields) + "}"
    if isinstance(e, A.Call):
        return "(call " + " ".join([sx(e.callee)] + [(a.name + "=" if a.name else "") + sx(a.value)
                                                       for a in e.args]) + ")"
    if isinstance(e, A.Field):
        return f"{sx(e.obj)}.{e.name}"
    if isinstance(e, A.Index):
        return f"(idx {sx(e.obj)} {sx(e.index)})"
    if isinstance(e, A.Unary):
        return f"({e.op} {sx(e.operand)})"
    if isinstance(e, A.Binary):
        return f"({e.op} {sx(e.left)} {sx(e.right)})"
    if isinstance(e, A.As):
        return f"(as {sx(e.expr)} {ty(e.type)})"
    if isinstance(e, A.Lambda):
        ps = " ".join(p.name + (":" + ty(p.type) if p.type else "") for p in e.params)
        return f"(fn ({ps}) {ty(e.ret) if e.ret else '_'} {sx(e.body)})"
    if isinstance(e, A.Block):
        return "{" + "; ".join(sx(s) for s in e.stmts) + "}"
    if isinstance(e, A.If):
        return f"(if {sx(e.cond)} {sx(e.then)}" + (f" {sx(e.else_)}" if e.else_ else "") + ")"
    if isinstance(e, A.Match):
        return f"(match {sx(e.subject)} " + " ".join(f"[{sx(a.pattern)} => {sx(a.body)}]" for a in e.arms) + ")"
    if isinstance(e, A.Try):
        return f"(try {sx(e.body)} {e.err_name} {sx(e.handler)})"
    if isinstance(e, A.Budget):
        return "(budget " + " ".join(f"{a.name}={sx(a.value)}" for a in e.limits) + f" {sx(e.body)})"
    # patterns
    if isinstance(e, A.PWild):
        return "_"
    if isinstance(e, A.PLit):
        return "lit:" + sx(e.value)
    if isinstance(e, A.PBind):
        return "bind:" + e.name
    if isinstance(e, A.PVariant):
        args = "" if e.args is None else "(" + ", ".join(sx(p) for p in e.args) + ")"
        return f"{e.enum}.{e.variant}{args}"
    # statements
    if isinstance(e, A.Let):
        return f"({'var' if e.mutable else 'let'} {e.name}" + (f":{ty(e.type)}" if e.type else "") + f" {sx(e.value)})"
    if isinstance(e, A.Assign):
        return f"(= {sx(e.target)} {sx(e.value)})"
    if isinstance(e, A.ExprStmt):
        return sx(e.expr)
    if isinstance(e, A.While):
        return f"(while {sx(e.cond)} {sx(e.body)})"
    if isinstance(e, A.For):
        return f"(for {e.var} {sx(e.iter)} {sx(e.body)})"
    if isinstance(e, A.Return):
        return "(return" + (f" {sx(e.value)}" if e.value is not None else "") + ")"
    if isinstance(e, A.Break):
        return "(break)"
    if isinstance(e, A.Continue):
        return "(continue)"
    if isinstance(e, A.Assert):
        return f"(assert {sx(e.cond)}" + (f" {sx(e.message)}" if e.message is not None else "") + ")"
    if isinstance(e, A.Mock):
        return f"(mock {e.fn_name}({', '.join(e.params)}) {sx(e.body)})"
    raise AssertionError(f"sx: unknown node {type(e).__name__}")


def body(src: str) -> list:
    """Statements of `fn f() { src }`."""
    prog = parse("fn f() {\n" + src + "\n}")
    return prog.items[0].body.stmts


def ex(src: str) -> str:
    """S-expression of one expression statement."""
    stmts = body(src)
    assert len(stmts) == 1, [sx(s) for s in stmts]
    return sx(stmts[0])


class Base(unittest.TestCase):
    def err(self, src: str, code: str, line: int | None = None, col: int | None = None, msg: str = ""):
        with self.assertRaises(SiparSyntaxError) as cm:
            parse(src)
        d = cm.exception.diag
        self.assertEqual(code, d.code, d.message)
        if line is not None:
            self.assertEqual((line, col), (d.line, d.col), d.message)
        if msg:
            self.assertIn(msg, d.message)
        return d


# ---------------------------------------------------------------- lexer
class Lexer(Base):
    def test_P01_empty(self):
        for src in ("", "\n\n", "   \n\t\n"):
            self.assertEqual([], parse(src).items)

    def test_P02_comments_only(self):
        self.assertEqual([], parse("// a\n/// doc with no item\n  // b\n").items)

    def test_P03_crlf(self):
        lf = parse("fn f() -> Int {\n  let a = 1\n  a + 2\n}\n")
        crlf = parse("fn f() -> Int {\r\n  let a = 1\r\n  a + 2\r\n}\r\n")
        self.assertEqual([sx(s) for s in lf.items[0].body.stmts], [sx(s) for s in crlf.items[0].body.stmts])
        self.assertEqual(["(let a 1)", "(+ a 2)"], [sx(s) for s in crlf.items[0].body.stmts])
        # positions are not shifted by \r
        self.assertEqual((3, 5), (crlf.items[0].body.stmts[1].expr.line, crlf.items[0].body.stmts[1].expr.col))
        # CRLF inside a triple string does not leave \r in the value
        self.assertEqual('"a\nb"', ex('"""\r\n  a\r\n  b\r\n  """'))

    def test_P04_unicode(self):
        self.assertEqual('"Привет, мир — 你好 🙂"', ex('"Привет, мир — 你好 🙂" // комментарий'))
        self.assertEqual('"ё{x}"', ex('"ё{x}"'))

    def test_P05_numbers(self):
        self.assertEqual("42", ex("42"))
        self.assertEqual("3.14", ex("3.14"))
        self.assertEqual("1000", ex("1_000"))
        self.assertEqual("1000.5", ex("1_000.5"))
        self.assertEqual("1000.0", ex("1e3"))
        self.assertEqual("0.025", ex("2.5e-2"))
        self.assertEqual("-5", ex("-5"))            # negative literals are folded
        self.assertIsInstance(body("-5")[0].expr, A.IntLit)
        self.assertEqual("-2.5", ex("-2.5"))
        self.assertIsInstance(body("1e3")[0].expr, A.FloatLit)
        self.assertIsInstance(body("7")[0].expr, A.IntLit)
        # `1.foo` is a field access on 1, not a float
        self.assertEqual("1.foo", ex("1.foo"))
        self.assertEqual("(.. 0 10)", ex("0..10"))

    def test_P06_bad_numbers(self):
        self.err("let x = 12abc", "E101", 1, 9, "12a")
        self.err("let x = 0x10", "E101", 1, 9)
        for bad in ("1_", "1__0", "1_.5", "1_e3"):
            self.err(f"let x = {bad}", "E101", 1, 9, "misplaced '_'")
        self.err("let x = $", "E101", 1, 9, "unexpected character")

    def test_P07_escapes(self):
        st = body(r'"a\nb\tc\"d\\e\{f\}"')[0].expr
        self.assertEqual(['a\nb\tc"d\\e{f}'], st.parts)
        self.err(r'let s = "a\qb"', "E102", 1, 11, r"\q")
        self.err(r'let s = "\u"', "E102", 1, 10)

    def test_P08_interpolation(self):
        self.assertEqual('"x={(+ a 1)}!"', ex('"x={a + 1}!"'))
        self.assertEqual('"{(idx m "a")}"', ex('"{m["a"]}"'))
        self.assertEqual('"{(call f "}")}"', ex(r'"{f("\}")}"'))
        self.assertEqual('"{(call f "a b")}"', ex('"{f("a b")}"'))
        self.err('let s = "{f("}")}"', "E103", msg="unmatched")
        self.assertEqual('"{a}{b}"', ex('"{a}{b}"'))
        self.err('let s = "a{}b"', "E103", 1, 11, "empty")
        self.err('let s = "a}b"', "E103", 1, 11, "unmatched")
        self.err('let s = "{1 2}"', "E103", 1, 13)
        # interpolated expressions carry their real position
        e = body('let s = "ab{cd}"')[0].value.parts[1]
        self.assertEqual((2, 13), (e.line, e.col))

    def test_P09_triple_strings(self):
        src = 'let s = """\n    Hello {name},\n      indented\n    bye\n    """'
        st = body(src)[0].value
        self.assertEqual('"Hello {name},\n  indented\nbye"', sx(st))
        # interpolation inside a triple string has its own source line and column
        nm = st.parts[1]
        self.assertEqual((3, 12), (nm.line, nm.col))
        # only ONE leading/trailing blank line is dropped
        self.assertEqual('"\na\n"', ex('"""\n\n  a\n\n  """'))
        self.assertEqual('"x"', ex('"""x"""'))
        # a triple string may contain single quotes
        self.assertEqual('"say "hi""', ex(r'"""say "hi\""""'))
        # error inside a triple-string interpolation points at the source line
        self.err('let s = """\n  a\n  b{1+}\n  """', "E110", 3, 7)

    def test_P10_unterminated(self):
        self.err('let s = "abc', "E101", 1, 9, "unterminated")
        self.err('let s = "a{b', "E101", 1, 9, "unterminated")
        self.err('let s = "ab\ncd"', "E101", 1, 9, "newline")
        self.err('let s = """abc', "E101", 1, 9, "unterminated")

    def test_P22_single_line_triple_column(self):
        e = body('let s = """ab{cd}"""')[0].value.parts[1]
        self.assertEqual((2, 15), (e.line, e.col))

    def test_tokens(self):
        kinds = [t.kind for t in tokenize("a.b ?? c -> d => e .. f")]
        self.assertEqual(["ident", ".", "ident", "??", "ident", "->", "ident", "=>", "ident", "..", "ident",
                          "newline", "eof"], kinds[:11] + kinds[-2:] if len(kinds) > 11 else kinds)


# ---------------------------------------------------------------- newline rules
class Newlines(Base):
    def test_P11_continuations(self):
        self.assertEqual(["(call f 1 2)"], [sx(s) for s in body("f(1,\n  2)")])
        self.assertEqual(["[1, 2]"], [sx(s) for s in body("[\n1,\n2\n]")])
        self.assertEqual(["(+ 1 2)"], [sx(s) for s in body("1 +\n 2")])
        self.assertEqual(["(and a b)"], [sx(s) for s in body("a and\n b")])
        self.assertEqual(["(let x 1)"], [sx(s) for s in body("let x =\n 1")])
        self.assertEqual(["(call xs.map (fn (x) _ x))"], [sx(s) for s in body("xs.map(fn(x) =>\n x)")])
        self.assertEqual(["(call xs.filter (fn (x) _ x))"], [sx(s) for s in body("xs\n  .filter(fn(x) => x)")])
        self.assertEqual(["(call (call xs.a).b)"], [sx(s) for s in body("xs\n  .a()\n  .b()")])
        self.assertEqual(["(let f:fn(Int)->Int g)"], [sx(s) for s in body("let f: fn(Int) ->\n Int = g")])
        # a binary operator at the START of a line does not continue (a statement starts with `-`)
        self.assertEqual(["1", "-2"], [sx(s) for s in body("1\n- 2")])
        # two statements on two lines
        self.assertEqual(["a", "b"], [sx(s) for s in body("a\nb")])

    def test_P12_braces_inside_parens(self):
        # a lambda with a block body as an argument: newlines inside its { } separate statements
        s = body("f(fn(x) => {\n  let y = x\n  y\n})")
        self.assertEqual(["(call f (fn (x) _ {(let y x); y}))"], [sx(t) for t in s])
        s = body("g(match v {\n  1 => a\n  _ => b\n}, 2)")
        self.assertEqual(["(call g (match v [lit:1 => a] [_ => b]) 2)"], [sx(t) for t in s])
        # and the ( ) inside { } inside ( ) ignore newlines again
        s = body("f(fn(x) => {\n  g(1,\n    2)\n  x\n})")
        self.assertEqual(["(call f (fn (x) _ {(call g 1 2); x}))"], [sx(t) for t in s])

    def test_P13_semicolons(self):
        self.assertEqual(["(let a 1)", "(let b 2)", "(+ a b)"], [sx(s) for s in body("let a = 1; let b = 2; a + b")])
        self.assertEqual(["a", "b"], [sx(s) for s in body("a;\nb;")])

    def test_P21_else_catch_next_line(self):
        self.assertEqual("(if c {1} {2})", ex("if c {\n 1\n}\nelse {\n 2\n}"))
        self.assertEqual("(try {(call f)} e {e.kind})", ex("try {\n f()\n}\ncatch e {\n e.kind\n}"))

    def test_P23_leading_close_bracket_no_crash(self):
        # used to raise IndexError inside the lexer
        self.err(")", "E110", 1, 1, "expected an item")
        self.err("]", "E110", 1, 1)
        self.err("}", "E110", 1, 1)
        self.err("\n\n)", "E110", 3, 1)


# ---------------------------------------------------------------- items
class Items(Base):
    def test_P14_allow(self):
        p = parse('allow ai\nallow net ["wttr.in", "*.github.com"]\nallow fs.read ["./data"]\n'
                  'allow fs.write ["./out"]\nallow shell ["ls"]\nallow env ["HOME"]\nallow time\n'
                  'allow random\nallow io')
        self.assertEqual([("ai", None), ("net", ["wttr.in", "*.github.com"]), ("fs.read", ["./data"]),
                          ("fs.write", ["./out"]), ("shell", ["ls"]), ("env", ["HOME"]), ("time", None),
                          ("random", None), ("io", None)], [(a.cap, a.scopes) for a in p.items])

    def test_P14_type_enum(self):
        p = parse("/// A review.\ntype R = { score: Int, tags: List[Str], m: Map[Float?], f: fn(Int) -> Str, }\n"
                  "enum Mood { happy, sad }\nenum Act { search(q: Str), stop, ask(a: Int, b: Str?), }")
        t, m, a = p.items
        self.assertEqual("A review.", t.doc)
        self.assertEqual([("score", "Int"), ("tags", "List[Str]"), ("m", "Map[Float?]"), ("f", "fn(Int)->Str")],
                         [(n, ty(x)) for n, x in t.fields])
        self.assertEqual(["happy", "sad"], [v.name for v in m.variants])
        self.assertEqual([("search", ["q"]), ("stop", []), ("ask", ["a", "b"])],
                         [(v.name, [f for f, _ in v.fields]) for v in a.variants])
        self.assertEqual("Str?", ty(a.variants[2].fields[1][1]))

    def test_P14_fns(self):
        p = parse('/// Adds.\nfn add(a: Int, b: Int) -> Int uses net, fs.read { a + b }\n'
                  '@retries(3) @temperature(0.2) @model("m")\nai fn r(code: Str) -> Str {\n"""\nReview {code}\n"""\n}\n'
                  '@max_steps(8)\nagent fn ag(goal: Str) -> Str uses net {\n tools [a, b]\n "Goal: {goal}"\n}\n'
                  'fn none_ret() { }')
        f, r, ag, nr = p.items
        self.assertEqual(("fn", "add", "Adds.", ["net", "fs.read"], "Int"), (f.kind, f.name, f.doc, f.uses, ty(f.ret)))
        self.assertEqual(["a", "b"], [x.name for x in f.params])
        self.assertEqual(("ai", None, ["retries", "temperature", "model"]), (r.kind, r.body, [a.name for a in r.attrs]))
        self.assertEqual('"Review {code}"', sx(r.prompt))
        self.assertEqual(3, r.attrs[0].value.value)
        self.assertEqual(("agent", ["a", "b"], ["net"]), (ag.kind, ag.tools, ag.uses))
        self.assertEqual('"Goal: {goal}"', sx(ag.prompt))
        self.assertIsNone(nr.ret)
        self.assertEqual([], nr.body.stmts)

    def test_P14_const_test(self):
        p = parse('let LIMIT = 10\nlet NAME: Str = "x"\ntest "adds" {\n assert 1 + 1 == 2, "math"\n}')
        c1, c2, t = p.items
        self.assertEqual(("LIMIT", None, "10"), (c1.name, c1.type, sx(c1.value)))
        self.assertEqual(("NAME", "Str"), (c2.name, ty(c2.type)))
        self.assertEqual(("adds", ['(assert (== (+ 1 1) 2) "math")']), (t.name, [sx(s) for s in t.body.stmts]))

    def test_P24_parenthesised_types(self):
        p = parse("fn f(k: (fn(Int) -> Int)?, x: (Int)) -> List[(fn() -> Str)?] { }")
        self.assertEqual(["fn(Int)->Int?", "Int"], [ty(x.type) for x in p.items[0].params])
        self.assertIsInstance(p.items[0].params[0].type, A.TOptional)
        self.assertIsInstance(p.items[0].params[0].type.inner, A.TFn)
        self.assertEqual("List[fn()->Str?]", ty(p.items[0].ret))
        # without parentheses `?` binds to the return type
        p = parse("fn g(k: fn(Int) -> Int?) { }")
        self.assertIsInstance(p.items[0].params[0].type, A.TFn)
        self.err("fn f(k: (Int) { }", "E110")


# ---------------------------------------------------------------- statements
class Statements(Base):
    def test_P15_statements(self):
        src = ("let x = 1\nlet y: Float = 2\nvar n = 0\nn = n + 1\np.score = 3\nxs[0] = 4\n"
               "while n < 3 { n = n + 1 }\nfor i in 0..10 { continue }\nfor k in m { break }\n"
               "return\nreturn x\nassert x\nassert x, \"m\"\nmock rv(code, b) => R { a: code }\nf()")
        self.assertEqual(["(let x 1)", "(let y:Float 2)", "(var n 0)", "(= n (+ n 1))", "(= p.score 3)",
                          "(= (idx xs 0) 4)", "(while (< n 3) {(= n (+ n 1))})", "(for i (.. 0 10) {(continue)})",
                          "(for k m {(break)})", "(return)", "(return x)", "(assert x)", '(assert x "m")',
                          "(mock rv(code, b) R{a: code})", "(call f)"], [sx(s) for s in body(src)])

    def test_P15_return_before_brace(self):
        self.assertEqual(["(if c {(return)})"], [sx(s) for s in body("if c { return }")])
        self.assertEqual(["(if c {(return 1)})"], [sx(s) for s in body("if c { return 1 }")])

    def test_P15_block_exprs(self):
        self.assertEqual("(let m (if (> a b) {a} {b}))", ex("let m = if a > b { a } else { b }"))
        self.assertEqual("(if a {1} (if b {2} {3}))", ex("if a { 1 } else if b { 2 } else { 3 }"))
        self.assertEqual("(try {(call f)} e {e.message})", ex("try { f() } catch e { e.message }"))
        self.assertEqual("(budget ai_calls=5 seconds=30 {(call f)})", ex("budget(ai_calls: 5, seconds: 30) { f() }"))
        self.assertEqual("{(let a 1); a}", ex("{ let a = 1; a }"))


# ---------------------------------------------------------------- expressions
class Expressions(Base):
    def test_P16_precedence(self):
        cases = {
            "a ?? b or c": "(?? a (or b c))",
            "a or b and c": "(or a (and b c))",
            "not a and b": "(and (not a) b)",
            "not a == b": "(not (== a b))",
            "a == b + 1": "(== a (+ b 1))",
            "x in xs and y": "(and (in x xs) y)",
            "a < b .. c": "(< a (.. b c))",
            "a .. b + 1": "(.. a (+ b 1))",
            "a + b * c - d": "(- (+ a (* b c)) d)",
            "a * b / c % d": "(% (/ (* a b) c) d)",
            "-a * b": "(* (- a) b)",
            "-x as Float": "(- (as x Float))",
            "a + b as Str": "(+ a (as b Str))",
            "s as List[Int]": "(as s List[Int])",
            "f(x).y[0]": "(idx (call f x).y 0)",
            "-f(x)": "(- (call f x))",
            "not not a": "(not (not a))",
            "--a": "(- (- a))",
            "(a + b) * c": "(* (+ a b) c)",
            "a - b - c": "(- (- a b) c)",
            "a / b / c": "(/ (/ a b) c)",
            "a != b": "(!= a b)",
            "a <= b": "(<= a b)",
            "a >= b": "(>= a b)",
            "a > b": "(> a b)",
        }
        for src, want in cases.items():
            with self.subTest(src=src):
                self.assertEqual(want, ex(src))

    def test_P17_coalesce_right_assoc_and_chain(self):
        self.assertEqual("(?? a (?? b c))", ex("a ?? b ?? c"))
        self.err("fn f() { a < b < c }", "E110", 1, 16, "chained")
        self.err("fn f() { a == b == c }", "E110", msg="chained")
        self.err("fn f() { a in b in c }", "E110", msg="chained")

    def test_P16_literals(self):
        self.assertEqual("[1, 2]", ex("[1, 2]"))
        self.assertEqual("[]", ex("[]"))
        self.assertEqual("[:]", ex("[:]"))
        self.assertEqual('["a": 1, "b": 2]', ex('["a": 1, "b": 2,]'))
        self.assertEqual("R{score: 1, v: \"\"}", ex('R { score: 1, v: "" }'))
        self.assertEqual("R{}", ex("R {}"))
        self.assertEqual("Mood.happy", ex("Mood.happy"))
        self.assertEqual('(call Act.search q="x")', ex('Act.search(q: "x")'))
        self.assertEqual('(call Act.search "x")', ex('Act.search("x")'))
        self.assertEqual("(fn (x:Int) Int (* x 2))", ex("fn(x: Int) -> Int => x * 2"))
        self.assertEqual("(fn (a b) _ (+ a b))", ex("fn(a, b) => a + b"))
        self.assertEqual("(fn () _ {1})", ex("fn() => { 1 }"))
        self.assertEqual("(idx s (.. 1 3))", ex("s[1..3]"))
        self.assertEqual("(call http.get url headers=h)", ex("http.get(url, headers: h)"))
        self.assertEqual("(call f 1 2)", ex("f(1, 2,)"))
        self.assertEqual("true", ex("true"))
        self.assertEqual("none", ex("none"))

    def test_P18_record_vs_block(self):
        self.assertEqual("(if (== x LIMIT) {})", ex("if x == LIMIT { }"))
        self.assertEqual("(if (== x LIMIT) {(call f)})", ex("if x == LIMIT { f() }"))
        self.assertEqual("(while Ok {(break)})", ex("while Ok { break }"))
        self.assertEqual("(for x xs {x})", ex("for x in xs { x }"))
        self.assertEqual("(match v [_ => 1])", ex("match v { _ => 1 }"))
        # parentheses restore a record literal in a condition
        self.assertEqual("(if (== x P{a: 1}) {})", ex("if x == (P { a: 1 }) { }"))
        # record literal nested in a call inside the condition is still allowed
        self.assertEqual("(if (call f P{a: 1}) {})", ex("if f(P { a: 1 }) { }"))
        # outside a condition a record literal is fine, and nested ones too
        self.assertEqual("(let p P{a: Q{b: 1}})", ex("let p = P { a: Q { b: 1 } }"))

    def test_P19_patterns(self):
        src = ('match v {\n _ => 0\n 1 => 1\n -1 => 2\n 2.5 => 3\n "s" => 4\n true => 5\n none => 6\n'
               ' x => 7\n E.a => 8\n E.b(p, _) => 9\n E.c() => 10\n E.d(1, "q") => 11,\n}')
        self.assertEqual("(match v [_ => 0] [lit:1 => 1] [lit:-1 => 2] [lit:2.5 => 3] [lit:\"s\" => 4] "
                         "[lit:true => 5] [lit:none => 6] [bind:x => 7] [E.a => 8] [E.b(bind:p, _) => 9] "
                         "[E.c() => 10] [E.d(lit:1, lit:\"q\") => 11])", ex(src))
        self.assertEqual("(match v [lit:1 => {(call f); 2}] [_ => 3])", ex("match v { 1 => { f(); 2 }, _ => 3 }"))

    def test_P16_positions(self):
        e = body("  a + bc")[0].expr
        self.assertEqual((2, 5), (e.line, e.col))           # binary op at the operator
        self.assertEqual((2, 7), (e.right.line, e.right.col))


# ---------------------------------------------------------------- errors
class Errors(Base):
    def test_P20_errors(self):
        self.err("fn f() {\n  let x = 1\n", "E104", 1, 8, "missing '}'")
        self.err("@retries(3) fn f() {}", "E111", 1, 1, "only allowed")
        self.err("@retries(3) type T = { a: Int }", "E111", 1, 1)
        self.err('@retries(1+2) ai fn f() -> Int { "x" }', "E111", 1, 10, "plain literal")
        self.err('@m("a{x}") ai fn f() -> Int { "x" }', "E111", 1, 4)
        self.err("var x = 1", "E110", 1, 1, "top-level 'var'")
        self.err("print(1)", "E110", 1, 1, "expected an item")
        self.err("fn f() { g(a: 1, 2) }", "E114", 1, 18, "positional")
        self.err("fn f() { g(a: 1, a: 2) }", "E114", 1, 24, "duplicate")
        self.err("fn f() { g() = 1 }", "E113", 1, 14)
        self.err("fn f() { a + b = 1 }", "E113")
        self.err("allow foo", "E112", 1, 7, "unknown capability")
        self.err("fn f() uses foo { }", "E112")
        self.err("fn let() {}", "E110", 1, 4, "keyword")
        self.err("fn f() { let if = 1 }", "E110", msg="keyword")
        self.err("fn f() { 1 +* 2 }", "E110", 1, 13)
        self.err('let x = "a" "b"', "E110", 1, 13, "end of statement")
        self.err("fn f( { }", "E110")
        self.err("type T = { a Int }", "E110")
        self.err("fn f() { match v { 1 2 } }", "E110")
        self.err("fn f() { if c { 1 } else 2 }", "E110")

    def test_P20_duplicates_E201(self):
        self.err("type T = { a: Int, a: Str }", "E201", 1, 20, "duplicate field")
        self.err("enum E { a, a }", "E201", 1, 13, "duplicate variant")
        self.err("enum E { }", "E201", 1, 1, "at least one variant")
        self.err("fn f(a: Int, a: Int) {}", "E201", 1, 14, "duplicate parameter")
        self.err("fn f() { T { a: 1, a: 2 } }", "E201", 1, 20, "duplicate field")

    def test_P25_errors_never_crash(self):
        # every prefix of a real program either parses or raises SiparSyntaxError (no Python crash)
        here = os.path.dirname(__file__)
        with open(os.path.join(here, "..", "examples", "tour.sipar"), encoding="utf-8") as fh:
            src = fh.read()
        for n in range(0, len(src), 7):
            try:
                parse(src[:n])
            except SiparSyntaxError:
                pass

    def test_P26_tour_parses(self):
        here = os.path.dirname(__file__)
        with open(os.path.join(here, "..", "examples", "tour.sipar"), encoding="utf-8") as fh:
            p = parse(fh.read())
        self.assertGreater(len(p.items), 5)


if __name__ == "__main__":
    unittest.main()
