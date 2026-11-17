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

    def test_lower_case_some_ok_err_call_pattern(self):
        self.assertIn("none =>", self.one("some(t) => t,").hint)
        self.assertIn("try", self.one("ok(t) => 1,").hint)
        self.assertIn("try", self.one("err(t) => 1,").hint)

    def test_Option_dot_none_pattern(self):
        for arm in ("Option.none => 0,", "Optional.none => 0,", "Maybe.none => 0,"):
            e = self.one(arm)
            self.assertIn("is not a Sipar type", e.message)
            self.assertIn("none =>", e.hint)

    def test_Option_dot_some_pattern_is_an_unknown_enum_with_a_hint(self):
        for arm in ("Option.some(t) => t,", "Optional.Some(t) => t,", "Maybe.x => 0,"):
            d = diag(match_with(arm))
            self.assertIn("E204", [x.code for x in d], d)
            self.assertTrue(any("Sipar has no Option type" in x.hint for x in d), d)

    def test_a_user_enum_called_Option_still_works(self):
        src = """
enum Option { yes(v: Int), no }
fn main() {
    let o = Option.yes(1)
    print(match o { Option.yes(v) => v, Option.no => 0 })
}
"""
        self.assertEqual(diag(src), [])

    def test_a_user_enum_called_like_a_foreign_one_still_works(self):
        src = """
enum Opt { some(v: Int), nothing }
fn main() {
    let o = Opt.some(1)
    print(match o { Opt.some(v) => v, Opt.nothing => 0 })
}
"""
        self.assertEqual(diag(src), [])

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


class T_ModelMistakes(unittest.TestCase):
    """Mistakes the AgentDojo planner (gpt-oss-120b) made, each with the hint that says what to write."""

    def one(self, src):
        d = diag(src)
        self.assertEqual(len(d), 1, d)
        return d[0]

    def test_generic_fn(self):
        for br in ("[T]", "<T>"):
            e = self.one(f"fn keep{br}(v: Int) -> Int {{ v }}\nfn main() {{ print(keep(1)) }}\n")
            self.assertIn("not generic", e.message)
            self.assertIn("fn keep(value: Str)", e.hint)

    def test_uses_before_return_type(self):
        e = self.one("allow io\nfn ask(v: Str) uses io -> Str { approve(v, \"ok?\") }\n"
                     "fn main() uses io { print(ask(\"x\")) }\n")
        self.assertIn("return type comes before `uses`", e.message)
        self.assertIn("fn ask(...) -> T uses io", e.hint)

    def test_right_order_still_works(self):
        self.assertEqual(diag("allow io\nfn ask(v: Str) -> Str uses io { approve(v, \"ok?\") }\n"
                              "fn main() uses io { print(ask(\"x\")) }\n"), [])

    def test_some_space_name_pattern(self):
        for w in ("some", "Some"):
            e = self.one(match_with(f"{w} t => t,"))
            self.assertIn(f"`{w} t` is not a Sipar pattern", e.message)
            self.assertIn("none =>", e.hint)

    def test_list_method_on_str(self):
        e = self.one('fn main() {\n    let s = "a"\n    print(s.filter(fn(c: Str) => true))\n}\n')
        self.assertEqual(e.code, "E205")
        self.assertIn("List method and this value is a Str", e.hint)
        self.assertIn("let xs: List[Item]", e.hint)

    def test_unknown_str_method_keeps_old_hint(self):
        e = self.one('fn main() {\n    let s = "a"\n    print(s.uppr())\n}\n')
        self.assertIn("did you mean `upper`?", e.hint)

    def test_json_in_prompt_string(self):
        src = 'fn main() {\n    print("""\n    {\n        "recipient": "<IBAN>"\n    }\n    """)\n}\n'
        e = self.one(src)
        self.assertEqual(e.code, "E103")
        self.assertIn("for a literal brace", e.hint)

    def test_lexer_error_inside_interpolation(self):
        e = self.one('fn main() {\n    print("y {true|false}")\n}\n')
        self.assertEqual(e.code, "E101")
        self.assertTrue(e.hint.startswith("`{` inside a string starts an interpolation"), e.hint)
        self.assertEqual(e.hint.count("literal brace"), 1)

    def test_escaped_braces_are_fine(self):
        self.assertEqual(diag('fn main() {\n    print("\\{\\"a\\": 1\\}")\n}\n'), [])

    def test_none_as_variant_name(self):
        e = self.one("enum Action { send, none }\nfn main() {}\n")
        self.assertIn("`skip`", e.hint)

    def test_other_keyword_as_name_keeps_old_hint(self):
        e = self.one("enum Action { send, match }\nfn main() {}\n")
        self.assertIn("keywords are reserved", e.hint)

    def test_type_defined_twice_names_first_line(self):
        for kw in ("type T = { a: Int }", "enum T { a, b }"):
            e = self.one(f"type T = {{ a: Int }}\n\n{kw}\nfn main() {{}}\n")
            self.assertIn("already defined (line 1)", e.message)

    def test_nested_interpolation_hint_once(self):
        e = self.one('fn main() {\n    print("a {"b {1|2}"}")\n}\n')
        self.assertEqual(e.hint.count("literal brace"), 1, e.hint)

    def test_too_deep_strings_keep_their_hint(self):
        from sipar.parser import MAX_STR_NESTING
        n = MAX_STR_NESTING + 1
        src = "fn main() {\n    print(" + '"{' * n + "1" + '}"' * n + ")\n}\n"
        e = self.one(src)
        self.assertEqual(e.code, "E115")
        self.assertNotIn("literal brace", e.hint)


if __name__ == "__main__":
    unittest.main()
