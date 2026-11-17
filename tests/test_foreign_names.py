"""Names and patterns from Python/Rust/JS get a hint that says what Sipar writes instead.

Found by the AgentDojo planner (gpt-oss-120b): `None => ..., tx => ...` made `tx` dead and `Some(tx)` was a bare
"expected '=>'" error; four retries never found `none`."""
import os
import sys
import textwrap
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sipar.checker import check_source  # noqa: E402


def diag(src):
    _, d = check_source(textwrap.dedent(src), "t.sipar")
    return [x for x in d if x.severity == "error"]


def match_with(arm):
    return f"""
fn main() {{
    let v: Int? = none
    let r = match v {{
        {arm}
        _ => 3
    }}
    print(r)
}}
"""


class T_ForeignPatterns(unittest.TestCase):
    def one(self, arm):
        d = diag(match_with(arm))
        self.assertEqual(len(d), 1, d)
        return d[0]

    def test_None_pattern_is_an_error_not_a_catch_all(self):
        for name in ("None", "null", "nil", "NULL", "undefined", "Nil", "Null"):
            e = self.one(f"{name} => 0,")
            self.assertIn(f"`{name}` is not a Sipar pattern", e.message)
            self.assertIn("`none`", e.hint)

    def test_True_False(self):
        self.assertIn("`true`", self.one("True => 0,").hint)
        self.assertIn("`false`", self.one("False => 0,").hint)

    def test_Some_call_pattern(self):
        e = self.one("Some(t) => t,")
        self.assertIn("`Some(...)` is not a Sipar pattern", e.message)
        self.assertIn("none =>", e.hint)

    def test_Ok_Err_call_pattern(self):
        for n in ("Ok", "Err"):
            e = self.one(f"{n}(t) => 1,")
            self.assertIn(f"`{n}(...)` is not a Sipar pattern", e.message)
            self.assertIn("try", e.hint)

    def test_other_call_pattern_names_the_enum(self):
        e = self.one("Foo(t) => 1,")
        self.assertIn("`MyEnum.Foo(...)`", e.hint)

    def test_real_patterns_still_work(self):
        self.assertEqual(diag(match_with("none => 0,\n        x => x,")), [])
        src = """
enum E { a(n: Int), b }
fn main() {
    let e = E.a(1)
    print(match e { E.a(n) => n, E.b => 0 })
}
"""
        self.assertEqual(diag(src), [])

    def test_lower_case_names_are_plain_bindings(self):
        self.assertEqual(diag(match_with("some => 0,").replace("_ => 3", "")), [])


class T_ForeignNames(unittest.TestCase):
    def hint(self, expr):
        d = diag(f"fn main() {{\n    let w = {expr}\n    print(w)\n}}\n")
        self.assertEqual([x.code for x in d], ["E203"], d)
        return d[0].hint

    def test_none_spellings(self):
        for n in ("None", "null", "nil", "NULL", "undefined"):
            self.assertIn("`none`", self.hint(n))

    def test_bools(self):
        self.assertIn("`true`", self.hint("True"))
        self.assertIn("`false`", self.hint("False"))

    def test_Some_Ok_Err(self):
        self.assertIn("not `Some(x)`", self.hint("Some(3)"))
        self.assertIn("no Result type", self.hint("Ok(3)"))
        self.assertIn("`fail(kind, message)`", self.hint("Err(3)"))

    def test_a_defined_name_wins(self):
        self.assertEqual(diag("fn main() {\n    let Null = 1\n    print(Null)\n}\n"), [])

    def test_ordinary_typo_still_gets_did_you_mean(self):
        d = diag("fn main() {\n    let count = 1\n    print(cuont)\n}\n")
        self.assertIn("did you mean `count`?", d[0].hint)


if __name__ == "__main__":
    unittest.main()
