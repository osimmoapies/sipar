"""Round 5: regression tests for the critics' findings (security S1-S3, correctness F1-F7, low notes L1-L3).

Every test not marked "guard" (behaviour that must stay) or "coverage" (already behaved,
now pinned) failed on the code before the fix.
Proof programs: /tmp/sipar_r5_sec, /tmp/sipar_r5_fuzz."""
from __future__ import annotations

import contextlib
import glob
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

from rt_helpers import CLEAN_ENV, ROOT, FakeTTY, Prog, main_src

import sipar
from sipar.checker import check, check_source
from sipar.cli import main as cli_main
from sipar.errors import SiparRuntimeError
from sipar.runtime.interp import Interp
from sipar.runtime.journal import Journal
from sipar.runtime import jsondeep
from sipar.deep import call_deep

TOKEN = "dummyvalue1"                  # 11 characters: k.len() + 9000 == 9011
ENV = {"R5_TOKEN": TOKEN}
SECRET_HEAD = 'allow secret ["R5_TOKEN"]\nallow ai\nallow io\nai fn get() -> Str { "give" }\n'
SECRET_HEAD += 'ai fn ask(x: Str) -> Str { "say {x}" }\n'
MASK = "«secret:R5_TOKEN»"
NAN = "let big = 1e308 * 10.0\nlet nan = big - big\n"


@contextlib.contextmanager
def clean_env(extra: dict | None = None):
    e = {k: v for k, v in os.environ.items() if k not in CLEAN_ENV}
    e["SIPAR_MODEL"] = "mock"
    e.update(extra or {})
    with mock.patch.dict(os.environ, e, clear=True):
        yield


def cli(*argv: str, env: dict | None = None) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with clean_env(env), contextlib.redirect_stderr(err):
        try:
            rc = cli_main(list(argv), out, err)
        except SystemExit as x:
            rc = x.code
    return rc, out.getvalue(), err.getvalue()


def diags(src: str):
    return check_source(src, "t.sipar")[1]


def codes(src: str) -> set:
    return {d.code for d in diags(src)}


class Base(unittest.TestCase):
    def prog(self, src: str) -> Prog:
        p = Prog(src)
        self.addCleanup(p.cleanup)
        check(p.program, src)           # as `sipar run` does: the checker plans Int->Float widening
        return p

    def out(self, body: str, head: str = "", **kw) -> str:
        return self.prog(main_src(body, head)).run(**kw)

    def err(self, body: str, head: str = "", **kw) -> SiparRuntimeError:
        return self.prog(main_src(body, head)).error(**kw)

    def secret_err(self, body: str, **kw) -> SiparRuntimeError:
        return self.err('let k = env.secret("R5_TOKEN")\nlet xs = [1, 2, 3]\n' + body, SECRET_HEAD, env=ENV, **kw)

    def tmpdir(self) -> str:
        d = os.path.realpath(tempfile.mkdtemp(prefix="sipar_r5_"))
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d

    def write(self, d: str, name: str, text: str) -> str:
        p = os.path.join(d, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return p


def tty_run(test: Base, src: str, script=None, stdin=None, journal=None) -> tuple[str, str]:
    """Run main() with stdout and stderr that say they are terminals."""
    p = test.prog(src)
    out, err = FakeTTY(), FakeTTY()
    with p.env(None):
        it = Interp(p.program, p.path, journal=journal or Journal(), out=out, err_out=err,
                    stdin=stdin if stdin is not None else io.StringIO(""), mock_script=script)
        it.run_main(None)
    return out.getvalue(), err.getvalue()


# ====================================================================== S1. secret-derived numbers in errors

class T_S1(Base):
    def assert_masked(self, e: SiparRuntimeError, *numbers: str):
        for n in numbers:
            self.assertNotIn(n, e.message)
        self.assertIn(MASK, e.message)

    def test_index_masked(self):                       # coverage: already masked before round 5
        self.assert_masked(self.secret_err("let y = xs[k.len() + 9000]"), "9011")

    def test_repeat_size_masked(self):
        self.assert_masked(self.secret_err('let z = "a".repeat(k.len() + 10000000)'), "10000011")

    def test_range_masked(self):                       # coverage
        self.assert_masked(self.secret_err("let r = range(0, k.len() + 20000000)"), "20000011")

    def test_as_int_masked(self):                      # coverage
        self.assert_masked(self.secret_err('let n = ((k.len() + 9000) as Str + "z") as Int'), "9011")

    def test_budget_limit_masked(self):
        e = self.secret_err("budget(ai_calls: k.len() - 10) {\n let a = get()\n let b = get()\n}",
                            script=["x", "y"])
        self.assertEqual(e.kind, "budget")
        self.assertIn(MASK, e.message)
        self.assertNotRegex(e.message.replace(MASK, ""), r"\d")

    def test_caught_message_is_secret(self):
        e = self.secret_err("try { let y = xs[k.len()] } catch e { print(e.message) }")
        self.assertEqual(e.kind, "taint", e.message)

    def test_caught_message_to_model_blocked(self):
        e = self.secret_err('try { let z = "a".repeat(k.len() + 10000000) } catch e { let r = ask(e.message) }',
                            script=["ok"])
        self.assertEqual(e.kind, "taint", e.message)

    def test_public_numbers_kept(self):              # guard
        e = self.err("let xs = [1, 2, 3]\nlet y = xs[7]")
        self.assertIn("7", e.message)
        self.assertIn("3", e.message)
        self.assertNotIn("«", e.message)
        self.assertEqual(self.out("try { let y = [1][5] } catch e { print(e.message) }"),
                         "index 5 out of range (length 1)\n")

    SRC = (SECRET_HEAD + "fn f() -> Int uses secret {\n let k = env.secret(\"R5_TOKEN\")\n let xs = [1, 2, 3]\n"
           " return \"a\".repeat(k.len() + 10000000).len()\n}\nfn main() uses secret {\n print(f())\n}\n")

    def test_cli_stderr_and_journal(self):
        d = self.tmpdir()
        path = self.write(d, "s.sipar", self.SRC)
        rc, out, err = cli("run", path, env=ENV)
        self.assertEqual(rc, 1, err)
        self.assertIn("runtime error", err)
        self.assertNotIn("10000011", err)
        self.assertIn(MASK, err)
        for jp in glob.glob(os.path.join(d, ".sipar", "runs", "*.jsonl")):
            with open(jp, encoding="utf-8") as fh:
                text = fh.read()
            self.assertNotIn("10000011", text)
            self.assertNotIn(TOKEN, text)

    def test_python_api(self):
        d = self.tmpdir()
        path = self.write(d, "s.sipar", self.SRC)
        with clean_env(ENV):
            with self.assertRaises(sipar.SiparError) as cm:
                sipar.load(path).call("f")
        self.assertNotIn("10000011", cm.exception.message)
        self.assertIn(MASK, cm.exception.message)


# ====================================================================== S2. sleep durations

class T_S2(Base):
    BODY = NAN + ('for d in [nan, big, 1e9, 86400.5, -1.0] {\n'
                  ' try { sleep(d)\n print("slept") } catch e { print(e.kind) }\n}\nsleep(0.0)\nprint("ok")')

    def setUp(self):
        p = mock.patch("sipar.runtime.effects._pause",  # round 6, R6: was _time.sleep
                       side_effect=AssertionError("real sleep"))
        self.slept = p.start()
        self.addCleanup(p.stop)

    def test_bad_durations_run(self):
        self.slept.side_effect = None
        self.assertEqual(self.out(self.BODY, "allow time"), "value\n" * 5 + "ok\n")
        self.assertEqual([c.args for c in self.slept.call_args_list], [(0.0,)])

    def test_bad_durations_replay(self):
        self.assertEqual(self.out(self.BODY, "allow time", journal=Journal(replay=[])), "value\n" * 5 + "ok\n")

    def test_budget_holds_after_nan_replay(self):
        body = NAN + ("budget(seconds: 1) {\n try { sleep(nan) } catch e { print(e.kind) }\n sleep(5.0)\n"
                      " print(\"after\")\n}")
        p = self.prog(main_src(body, "allow time"))
        j = Journal()
        e = p.error(journal=j)
        self.assertEqual((e.kind, p.out), ("budget", "value\n"), e.message)
        e2 = p.error(journal=Journal(replay=list(j.entries)))
        self.assertEqual((e2.kind, e2.message, p.out), (e.kind, e.message, "value\n"))

    def test_budget_holds_after_nan_run(self):
        body = NAN + ("budget(seconds: 1) {\n try { sleep(nan) } catch e { print(e.kind) }\n sleep(5.0)\n"
                      " print(\"after\")\n}")
        e = self.err(body, "allow time")
        self.assertEqual(e.kind, "budget", e.message)
        self.slept.assert_not_called()

    def test_in_range_sleeps(self):                    # guard
        self.slept.side_effect = None
        self.assertEqual(self.out("sleep(0.25)\nsleep(2)\nprint(1)", "allow time"), "1\n")
        self.assertEqual([c.args for c in self.slept.call_args_list], [(0.25,), (2.0,)])


# ====================================================================== S3. terminal control characters

EVIL = "\x1b[8mhidden\x1b]0;title\x07\u202eabc"
EVIL_SHOWN = "\\x1b[8mhidden\\x1b]0;title\\x07\\u202eabc"
AI_HEAD = 'allow ai\nallow io\nai fn get() -> Str { "give" }\n'


class T_S3(Base):
    def test_print_tty_escaped(self):
        out, _ = tty_run(self, main_src("print(get())", AI_HEAD), script=[EVIL])
        self.assertEqual(out, EVIL_SHOWN + "\n")

    def test_print_pipe_exact(self):                  # guard
        self.assertEqual(self.out("print(get())", AI_HEAD, script=[EVIL]), EVIL + "\n")

    def test_print_tty_keeps_newline_tab(self):        # guard
        out, _ = tty_run(self, main_src('print("a\\tb\\nc\\\\x")'))
        self.assertEqual(out, "a\tb\nc\\x\n")

    def test_input_prompt_tty_escaped(self):
        out, _ = tty_run(self, main_src("let s = input(get())\nprint(s)", AI_HEAD), script=[EVIL],
                         stdin=io.StringIO("typed\n"))
        self.assertEqual(out, EVIL_SHOWN + "typed\n")

    def test_approve_resets_terminal_first(self):
        _, err = tty_run(self, main_src('let x = approve("v", "ok?")\nprint(x)', "allow io"),
                         stdin=FakeTTY("y\n"))
        self.assertTrue(err.startswith("\x1b[0m\x1b[?25h"), repr(err[:20]))

    def test_render_escaped(self):
        e = SiparRuntimeError("value", "bad " + EVIL)
        self.assertNotIn("\x1b", e.render())
        self.assertIn("\\x1b[8m", e.render())
        self.assertIn("\\u202e", e.render())

    def test_cli_stderr_escaped(self):
        d = self.tmpdir()
        self.write(d, "m.json", json.dumps([EVIL]))
        path = self.write(d, "a.sipar", AI_HEAD + 'fn main() uses ai {\n fail("value", get())\n}\n')
        rc, out, err = cli("run", path, env={"SIPAR_MOCK_SCRIPT": os.path.join(d, "m.json")})
        self.assertEqual(rc, 1, err)
        self.assertNotIn("\x1b", err)
        self.assertIn("\\x1b[8mhidden", err)


# ====================================================================== F1. deep nesting

def deep(kind: str, n: int) -> str:
    e = {"paren": lambda: "(" * n + "1" + ")" * n, "neg": lambda: "-" * n + "abs(1)",
         "not": lambda: "not " * n + "true", "list": lambda: "[" * n + "1" + "]" * n,
         "add": lambda: "+".join(["1"] * n), "if": lambda: "if true { " * n + "1" + " }" * n,
         "block": lambda: "{ " * n + "1" + " }" * n, "lam": lambda: "fn() => " * n + "1",
         "call": lambda: "abs(" * n + "1" + ")" * n, "str": lambda: '"{' * n + "1" + '}"' * n,
         "idx": lambda: "[1]" + "[0]" * n, "field": lambda: "1" + " as Str" * n,
         "coal": lambda: "??".join(["none"] * n) + "?? 1"}[kind]()
    return "fn main() {\n    let x = " + e + "\n    print(x)\n}\n"


NESTED = ("paren", "list", "if", "block", "lam", "call")
CHAINS = ("neg", "not", "add", "idx", "field", "coal")


class T_F1(Base):
    def test_nested_e115(self):
        for kind in NESTED:
            with self.subTest(kind=kind):
                self.assertEqual(codes(deep(kind, 300)), {"E115"})

    def test_string_nesting_e115(self):
        self.assertEqual(codes(deep("str", 17)), {"E115"})
        self.assertNotIn("E115", codes(deep("str", 16)))          # guard: 16 levels fine

    def test_long_chains_e115(self):
        for kind in CHAINS:
            with self.subTest(kind=kind):
                self.assertEqual(codes(deep(kind, 12000)), {"E115"})

    def test_api_check_source_and_load_do_not_raise(self):
        d = self.tmpdir()
        for kind in NESTED + CHAINS + ("str",):
            with self.subTest(kind=kind):
                src = deep(kind, 12000 if kind in CHAINS else 300)
                self.assertEqual({x["code"] for x in sipar.check_source(src)}, {"E115"})
                with self.assertRaises(sipar.CheckError) as cm:
                    sipar.load(self.write(d, kind + ".sipar", src))
                self.assertEqual(cm.exception.diagnostics[0]["code"], "E115")

    def test_check_json_stays_json(self):
        d = self.tmpdir()
        for kind in ("paren", "add", "str"):
            with self.subTest(kind=kind):
                path = self.write(d, kind + ".sipar", deep(kind, 20000 if kind == "add" else 400))
                rc, out, err = cli("check", "--json", path)
                self.assertEqual(rc, 1, err)
                self.assertEqual([x["code"] for x in json.loads(out)], ["E115"])

    def test_flat_sum_500_runs(self):                  # guard
        self.assertEqual(diags(deep("add", 500)), [])
        self.assertEqual(self.prog(deep("add", 500)).run(), "500\n")

    def test_moderate_nesting_runs(self):              # guard: within the limit
        for kind, n in (("paren", 254), ("list", 254), ("call", 254), ("lam", 254), ("block", 127)):
            with self.subTest(kind=kind):
                self.assertEqual([x.code for x in diags(deep(kind, n))], [])
                self.prog(deep(kind, n)).run()
                self.assertEqual(codes(deep(kind, n + 1)), {"E115"})     # a value block counts two levels (SPEC §1)

    def test_errors_doc_has_e115(self):
        with open(os.path.join(ROOT, "docs", "ERRORS.md"), encoding="utf-8") as fh:
            self.assertIn("### E115", fh.read())


# ====================================================================== F2. empty Float sum

class T_F2(Base):
    def test_empty_float_sum(self):
        self.assertEqual(self.out("let xs: List[Float] = []\nprint(xs.sum())\nprint([1.5, 2.0].take(0).sum())"),
                         "0.0\n0.0\n")

    def test_int_sum_stays_int(self):                  # guard
        self.assertEqual(self.out("let xs: List[Int] = []\nprint(xs.sum())\nprint([1, 2].sum())"), "0\n3\n")


# ====================================================================== F3. match exhaustiveness cost

def bool_rows(n: int) -> str:
    fields = ", ".join(f"f{i}: Bool" for i in range(n))
    rows = []
    for i in range(n):
        pats = ["_"] * n
        pats[i] = "true"
        rows.append(f"        R.r({', '.join(pats)}) => {i}")
    rows.append(f"        R.r({', '.join(['false'] * n)}) => {n}")
    return (f"enum R {{ r({fields}) }}\nfn f(x: R) -> Int {{\n    match x {{\n" + ",\n".join(rows)
            + "\n    }\n}\nfn main() { print(f(R.r(" + ", ".join(["false"] * n) + "))) }\n")


class T_F3(Base):
    def test_n24_fast(self):
        src = bool_rows(24)
        code = ("import sys, time\nsys.path.insert(0, sys.argv[1])\nfrom sipar.checker import check_source\n"
                "src = open(sys.argv[2]).read()\nt = time.time()\n_, ds = check_source(src, 'x.sipar')\n"
                "print(time.time() - t, sorted({d.code for d in ds}))\n")
        d = self.tmpdir()
        path = self.write(d, "m.sipar", src)
        try:
            r = subprocess.run([sys.executable, "-c", code, ROOT, path], capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            self.fail("match check of 24 Bool fields took more than 30 s")
        secs, found = r.stdout.split(" ", 1)
        self.assertLess(float(secs), 0.5)
        self.assertEqual(found.strip(), "[]")

    def test_non_exhaustive_still_found(self):         # guard
        src = bool_rows(10).replace(f"        R.r({', '.join(['false'] * 10)}) => 10", "        R.r(" +
                                    ", ".join(["true"] * 10) + ") => 10")
        self.assertIn("E401", codes(src))

    def test_e408_warning(self):
        with open(os.path.join(ROOT, "docs", "ERRORS.md"), encoding="utf-8") as fh:
            doc = fh.read()
        sec = doc[doc.index("### E408"):]
        src = sec[sec.index("```sipar") + 9:sec.index("```", sec.index("```sipar") + 9)]
        ds = diags(src)
        self.assertEqual([(x.code, x.severity) for x in ds], [("E408", "warning")])
        closed = src.replace("=> 35\n", "=> 35,\n        _ => 99\n")
        self.assertNotEqual(closed, src)
        self.assertEqual(diags(closed), [])


# ====================================================================== F4. contravariant fn params

class T_F4(Base):
    SRC = "fn half(x: Float) -> Float { x / 2.0 }\nfn main() {\n print([1, 2].map(half))\n}\n"

    def test_map_float_fn_on_ints(self):
        self.assertEqual(diags(self.SRC), [])
        self.assertEqual(self.prog(self.SRC).run(), "[0.5, 1.0]\n")

    def test_covariant_still_rejected(self):           # guard: a fn(Int) is not a fn(Float)
        src = "fn inc(x: Int) -> Int { x + 1 }\nfn main() {\n print([1.5].map(inc))\n}\n"
        self.assertTrue(any(d.severity == "error" for d in diags(src)))


# ====================================================================== F5. SIPAR_MAX_DEPTH=20000

class T_F5(Base):
    SRC = ("fn down(n: Int) -> Int {\n    if n == 0 { return 0 }\n    return 1 + down(n - 1)\n}\n"
           "fn main(args: List[Str]) {\n    let n = args[0] as Int\n"
           "    print(try { down(n) as Str } catch e { \"{e.kind}: {e.message}\" })\n}\n")

    def run_depth(self, n: int) -> str:
        d = self.tmpdir()
        path = self.write(d, "r.sipar", self.SRC)
        env = {k: v for k, v in os.environ.items() if k not in CLEAN_ENV}
        env.update(SIPAR_MAX_DEPTH="20000", PYTHONPATH=ROOT)
        r = subprocess.run([sys.executable, "-m", "sipar", "run", path, str(n)], capture_output=True, text=True,
                           timeout=300, env=env, cwd=d)
        return (r.stdout + r.stderr).strip()

    def test_19000_deep(self):
        self.assertTrue(self.run_depth(19000).startswith("19000"))

    def test_20001_is_depth_error(self):               # guard
        out = self.run_depth(20001)
        self.assertIn("depth", out)
        self.assertNotIn("Traceback", out)


# ====================================================================== F6. huge Int

class T_F6(Base):
    def conv(self, expr: str) -> str:
        return self.out(f'print(try {{ {expr} }} catch e {{ "{{e.kind}}: {{e.message}}" }})').strip()

    def test_as_int(self):
        for k in (4250, 4400):
            with self.subTest(k=k):
                self.assertEqual(self.conv(f'("9".repeat({k}) as Int) as Str'),
                                 "value: number too large for Int (limit about 4200 digits)")
        self.assertEqual(self.conv('(("-" + "9".repeat(4400)) as Int) as Str'),
                         "value: number too large for Int (limit about 4200 digits)")

    def test_as_list_int(self):
        out = self.conv('(("[" + "9".repeat(4400) + "]") as List[Int]).len() as Str')
        self.assertEqual(out, "value: $[0]: number too large for Int (limit about 4200 digits)")

    def test_as_list_float(self):
        self.assertTrue(self.conv('(("[" + "9".repeat(4400) + "]") as List[Float]).len() as Str')
                        .startswith("decode: "))

    def test_ai_int(self):
        src = "allow ai\nai fn n() -> Int { \"give\" }\nfn main() uses ai {\n" \
              " print(try { n() as Str } catch e { \"{e.kind}\" })\n}\n"
        for k in (4250, 4400):
            with self.subTest(k=k):
                self.assertEqual(self.prog(src).run(script=["9" * k] * 3), "value\n")

    def test_small_ints_fine(self):                    # guard
        self.assertEqual(self.conv('("1_000" as Int) as Str'), "1000")
        self.assertEqual(self.conv('("x1" as Int) as Str')[:7], "decode:")


# ====================================================================== F7. \r and \0 documented

class T_F7(Base):
    def test_escapes_work(self):                       # guard
        self.assertEqual(self.out('print("a\\rb".len())\nprint("\\0".len())'), "3\n1\n")

    def test_e102_hint_lists_them(self):
        [d] = diags('fn main() {\n let s = "\\q"\n}\n')
        self.assertEqual(d.code, "E102")
        self.assertIn("\\r", d.hint)
        self.assertIn("\\0", d.hint)

    def test_docs(self):
        with open(os.path.join(ROOT, "SPEC.md"), encoding="utf-8") as fh:
            spec = fh.read()
        with open(os.path.join(ROOT, "docs", "ERRORS.md"), encoding="utf-8") as fh:
            errs = fh.read()
        self.assertIn("\\r \\0", spec)
        self.assertIn("\\r \\0", errs)


# ====================================================================== L1-L3. low notes

class T_Low(Base):
    def test_minmax_nan_either_order(self):
        body = NAN + "print(min(nan, 1.0))\nprint(min(1.0, nan))\nprint(max(nan, 1.0))\nprint(max(1.0, nan))"
        self.assertEqual(self.out(body), "nan\n" * 4)

    def test_minmax_signed_zero(self):
        body = ("print(min(0.0, -0.0))\nprint(min(-0.0, 0.0))\nprint(max(0.0, -0.0))\nprint(max(-0.0, 0.0))\n"
                "print(min(1, 2.5))\nprint(max(3, 2))")
        self.assertEqual(self.out(body), "-0.0\n-0.0\n0.0\n0.0\n1.0\n3\n")

    def test_as_float_grammar(self):
        for s in ("1_0e1_0", "1e1_0", "1__0", "_1", "1_", "0x10", "1.5.2"):
            with self.subTest(s=s):
                self.assertEqual(self.out(f'print(try {{ ("{s}" as Float) as Str }} catch e {{ e.kind }})'),
                                 "decode\n")
        for s, want in (("1_0.5", "10.5"), (".5", "0.5"), ("5.", "5.0"), ("-1.5e3", "-1500.0"), (" 7.25 ", "7.25")):
            with self.subTest(s=s):                    # guard
                self.assertEqual(self.out(f'print("{s}" as Float)'), want + "\n")

    def test_no_widen_hint(self):
        for src in ("fn main() {\n print([[1], [2.5]])\n}\n", "fn main() {\n print([0.5] + [3])\n}\n"):
            with self.subTest(src=src):
                [d] = diags(src)
                self.assertIn(d.code, ("E218", "E214"))
                self.assertIn("containers do not widen", d.hint)

    def test_literal_widening_kept(self):              # guard
        self.assertEqual(self.out("print([1, 2.5])\nlet xs: List[Float] = [1, 2]\nprint(xs)"),
                         "[1.0, 2.5]\n[1.0, 2.0]\n")



# ====================================================================== C1. secrets are per run

PLAIN_C = 'allow fs.read ["d"]\nfn rd() -> Str uses fs.read { let t = fs.read("d/a.txt"); print(t); t }\n'
SEC_A = ('allow secret ["MYSEC"]\nfn touch() -> Int uses secret { let s = env.secret("MYSEC")\n 0 }\n'
         'fn bad() -> Int uses secret { (env.secret("MYSEC") + "x") as Int }\n')


class T_C1(Base):
    def setUp(self):
        self.d = self.tmpdir()
        os.mkdir(os.path.join(self.d, "d"))
        self.write(self.d, "d/a.txt", "2024")
        cwd = os.getcwd()
        os.chdir(self.d)
        self.addCleanup(os.chdir, cwd)

    def test_api_calls_do_not_share_secrets(self):
        c = sipar.load(self.write(self.d, "c.sipar", PLAIN_C))
        a = sipar.load(self.write(self.d, "a.sipar", SEC_A))
        self.assertEqual(c.call("rd", out=io.StringIO()), "2024")
        with clean_env({"MYSEC": "2024"}):
            self.assertEqual(a.call("touch"), 0)
        o = io.StringIO()
        with clean_env():
            self.assertEqual(c.call("rd", out=o), "2024")
        self.assertEqual(o.getvalue(), "2024\n")

    def test_runs_do_not_share_secrets(self):
        a = self.prog(SEC_A + 'fn main() uses secret { print(touch()) }\n')
        self.assertEqual(a.run(env={"MYSEC": "2024"}), "0\n")
        c = self.prog(PLAIN_C.replace('"d"', f'"{self.d}/d"').replace('"d/a.txt"', f'"{self.d}/d/a.txt"')
                      + 'fn main() uses fs.read { let t = rd() }\n')
        self.assertEqual(c.run(), "2024\n")

    def test_test_blocks_do_not_share_secrets(self):
        src = (SEC_A + PLAIN_C.replace('"d"', f'"{self.d}/d"').replace('"d/a.txt"', f'"{self.d}/d/a.txt"')
               + 'test "a" { assert touch() == 0 }\ntest "c" { assert rd() == "2024" }\n')
        p, f, out = self.prog(src).test(env={"MYSEC": "2024"})
        self.assertEqual((p, f), (2, 0), out)

    def test_error_redacted_after_call_ends(self):            # guard: the error keeps its run's registry
        a = sipar.load(self.write(self.d, "a.sipar", SEC_A))
        with clean_env({"MYSEC": "zq2024zq"}):
            with self.assertRaises(sipar.SiparError) as cm:
                a.call("bad")
        self.assertNotIn("zq2024zq", str(cm.exception))
        self.assertNotIn("zq2024zq", cm.exception.message)
        self.assertEqual(cm.exception.kind, "decode")

    def test_registry_scope_restored(self):                    # guard: nothing leaks into the process default
        from sipar.errors import DEFAULT
        a = sipar.load(self.write(self.d, "a.sipar", SEC_A))
        before = dict(DEFAULT.secrets)
        with clean_env({"MYSEC": "zq2024zq"}):
            a.call("touch")
        self.assertEqual(DEFAULT.secrets, before)
        from sipar.errors import active_registry
        self.assertIsNone(active_registry())                   # the call's scope is closed again
        with clean_env({"MYSEC": "zq2024zq"}):
            try:
                a.call("bad")
            except sipar.SiparError:                           # the traceback keeps call()'s frame alive here,
                self.assertIsNone(active_registry())           # so only an explicit exit closes the scope


# ====================================================================== D. value depth cap (MAX_VALUE_DEPTH)

DEEP_SRC = '''allow memory
type N = { kids: List[N] }
fn conv(s: Str) -> Str { try { let v = s as N
 "ok" } catch e { e.kind + ": " + e.message } }
fn build(n: Int) -> N {
 var x = N { kids: [] }
 var i = 0
 while i < n { x = N { kids: [x] }; i = i + 1 }
 x
}
fn save(n: Int) -> Str uses memory { try { memory.save("a", build(n))
 "saved" } catch e { e.kind + ": " + e.message } }
fn load() -> Str uses memory { try { let v: N? = memory.load("a")
 "loaded {v != none}" } catch e { e.kind + ": " + e.message } }
fn take(xs: List[Int]) -> Int { xs.len() }
'''
TOO_DEEP_MSG = "nested too deeply (more than 20,000 levels)"


def nest(n: int) -> str:
    return '{"kids": [' * n + '{"kids": []}' + ']}' * n


class T_Depth(Base):
    def setUp(self):
        self.d = self.tmpdir()
        cwd = os.getcwd()
        os.chdir(self.d)
        self.addCleanup(os.chdir, cwd)
        self.p = sipar.load(self.write(self.d, "p.sipar", DEEP_SRC))

    def call(self, *a):
        with clean_env():
            return self.p.call(*a)

    def test_as_below_cap(self):                               # guard: 9,000 records = 18,001 levels
        self.assertEqual(self.call("conv", nest(9000)), "ok")

    def test_as_over_cap_is_decode(self):
        self.assertEqual(self.call("conv", nest(10001)), "decode: $: " + TOO_DEEP_MSG)

    def test_save_is_linear(self):
        import time
        t = time.time()
        self.assertEqual(self.call("save", 9000), "saved")     # was quadratic: about 20 s
        self.assertLess(time.time() - t, 4.0)
        self.assertEqual(self.call("load"), "loaded true")

    def test_save_over_cap_is_value(self):
        self.assertEqual(self.call("save", 10001), "value: memory.save: value " + TOO_DEEP_MSG)
        self.assertEqual(self.call("load"), "loaded false")    # nothing half-written

    def test_load_over_cap_is_io(self):
        os.makedirs(os.path.join(self.d, ".sipar", "memory"))
        store = '{"version": 1, "entries": {"a": {"value": ' + nest(10001) + ', "labels": [], "enc": 2}}}'
        self.write(self.d, ".sipar/memory/p.json", store)
        self.assertEqual(self.call("load"), "io: memory.load('a'): the stored value is nested too deeply")

    def test_api_result_over_cap(self):
        with self.assertRaises(sipar.SiparError) as cm:
            self.call("build", 10001)
        self.assertEqual(cm.exception.kind, "value")
        self.assertIn("nested too deeply to return to Python (more than 20,000 levels)", cm.exception.message)
        self.assertEqual(json.dumps(self.call("build", 3)), '{"kids": [{"kids": [{"kids": [{"kids": []}]}]}]}')

    def test_api_argument_over_cap(self):
        deep: list = []
        for _ in range(20001):
            deep = [deep]
        with self.assertRaises(sipar.SiparError) as cm:
            self.call("take", deep)
        self.assertEqual(cm.exception.kind, "value")
        self.assertIn("take.xs: an argument is " + TOO_DEEP_MSG, cm.exception.message)


# ====================================================================== D3. depth on Python 3.12's C json codec

def _text_depth(s: str) -> int:
    d = top = 0
    in_str = esc = False
    for ch in s:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            d += 1
            top = max(top, d)
        elif ch in "]}":
            d -= 1
    return top


def _value_depth(v) -> int:
    top = 0
    todo = [(v, 1)]
    while todo:
        x, d = todo.pop()
        if isinstance(x, (list, tuple, dict)):
            top = max(top, d)
            todo.extend((y, d + 1) for y in (x.values() if isinstance(x, dict) else x))
    return top


@contextlib.contextmanager
def c_json_limit(limit: int = 10_000):
    """On any Python, make the standard json codec fail as Python 3.12's C codec does: RecursionError past a
    fixed depth of about 10,000 levels, whatever the stack (README promises Python 3.12+)."""
    import json.decoder
    import json.encoder
    raw, enc = json.decoder.JSONDecoder.raw_decode, json.encoder.JSONEncoder.encode

    def raw_decode(self, s, idx=0):
        if type(self) is json.decoder.JSONDecoder and _text_depth(s[idx:]) > limit:
            raise RecursionError("maximum recursion depth exceeded while decoding a JSON array")
        return raw(self, s, idx)

    def encode(self, o):
        if type(self) is json.encoder.JSONEncoder and _value_depth(o) > limit:
            raise RecursionError("maximum recursion depth exceeded while encoding a JSON object")
        return enc(self, o)

    with mock.patch.object(json.decoder.JSONDecoder, "raw_decode", raw_decode), \
            mock.patch.object(json.encoder.JSONEncoder, "encode", encode):
        yield


D3_SRC = DEEP_SRC + '''fn enc(n: Int) -> Str { json.encode(build(n)) }
allow ai
ai fn tree() -> N { "a tree" }
fn grow() -> N uses ai { tree() }
'''


class T_D3(T_Depth):
    """The T_Depth cases again, with the C codec limited as on Python 3.12 (they failed there before the fix)."""

    def setUp(self):
        super().setUp()
        self.p = sipar.load(self.write(self.d, "p3.sipar", D3_SRC))
        lim = c_json_limit()
        lim.__enter__()
        self.addCleanup(lim.__exit__, None, None, None)

    def test_emulation_bites(self):                            # guard: the C codec really fails here
        with self.assertRaises(RecursionError):
            json.loads(nest(9000))
        with self.assertRaises(RecursionError):
            json.dumps(call_deep(json.loads, nest(9000), cls=jsondeep.PyDecoder))
        # on the big-stack thread: the host's own recursion limit is not raised for good any more (L6, round 6)
        self.assertEqual(call_deep(json.loads, nest(4000)), call_deep(json.loads, nest(4000), cls=jsondeep.PyDecoder))

    def test_json_encode_builtin(self):
        self.assertEqual(self.call("enc", 9000), nest(9000))

    def test_ai_reply(self):
        for pre in ("", "Here it is: "):
            with clean_env():
                got = self.p.call("grow", mock_script=[pre + nest(9000)])
            self.assertEqual(call_deep(jsondeep.dumps, got), nest(9000))

    def test_memory_file_text(self):
        self.assertEqual(self.call("save", 3), "saved")
        small = open(os.path.join(self.d, ".sipar/memory/p3.json"), encoding="utf-8").read()
        self.assertEqual(self.call("save", 9000), "saved")
        big = open(os.path.join(self.d, ".sipar/memory/p3.json"), encoding="utf-8").read()
        gen = re.compile(r'"gen": "[0-9a-f]{16}"')                 # round 7: a new gen on every rewrite
        self.assertEqual(gen.sub("G", big.replace(nest(9000), nest(3))), gen.sub("G", small))

    def test_load_over_cap_is_io(self):
        os.makedirs(os.path.join(self.d, ".sipar", "memory"))
        store = '{"version": 1, "entries": {"a": {"value": ' + nest(10001) + ', "labels": [], "enc": 2}}}'
        self.write(self.d, ".sipar/memory/p3.json", store)
        self.assertEqual(self.call("load"), "io: memory.load('a'): the stored value is nested too deeply")


def _corpus(seed: int, n: int):
    import random
    rnd = random.Random(seed)
    leaves = [None, True, False, 0, -7, 10**30, 1.5, -0.0, 1e300, 1e-7, float("nan"), float("inf"),
              -float("inf"), "", "a", "é", " ", "\x00", "\"\\", "\ud800", "😀", " "]
    keys = ["", "a", "é", "\x00", "😀", "k", 1, 2.5, True, None, False, -3, float("nan")]

    def gen(d=0):
        r = rnd.random()
        if d > 4 or r < 0.4:
            return rnd.choice(leaves)
        if r < 0.7:
            return [gen(d + 1) for _ in range(rnd.randrange(4))]
        if r < 0.75:
            return tuple(gen(d + 1) for _ in range(rnd.randrange(3)))
        return {k: gen(d + 1) for k in rnd.sample(keys, rnd.randrange(4))}
    return [gen() for _ in range(n)]


def _outcome(f, *a, **kw):
    try:
        return ("ok", f(*a, **kw))
    except (TypeError, ValueError) as e:
        return (type(e).__name__, str(e))


class T_D3_Codec(unittest.TestCase):
    """sipar.runtime.jsondeep: the same text and errors as json, at any depth, in linear time."""

    FLAGS = [dict(ensure_ascii=a, sort_keys=s, allow_nan=n) for a in (True, False) for s in (True, False)
             for n in (True, False)]

    def test_same_text_as_json(self):
        for v in _corpus(5, 1500):
            for fl in self.FLAGS:
                self.assertEqual(_outcome(jsondeep._dumps_iter, v, fl["ensure_ascii"], fl["sort_keys"],
                                          fl["allow_nan"]), _outcome(json.dumps, v, **fl), (v, fl))

    def test_same_errors_as_json(self):
        c: list = [1]
        c.append(c)
        d: dict = {}
        d["x"] = [d]
        cases = [c, d, {"a": {1, 2}}, {(1,): 2}, [b"x"], {"k": float("nan")}, {float("inf"): 1}, object()]
        for v in cases:
            for fl in self.FLAGS:
                self.assertEqual(_outcome(jsondeep._dumps_iter, v, fl["ensure_ascii"], fl["sort_keys"],
                                          fl["allow_nan"]), _outcome(json.dumps, v, **fl), (v, fl))
        same = [1, 2]
        self.assertEqual(jsondeep._dumps_iter([same, same, {"a": same}], True, False, True),
                         "[[1, 2], [1, 2], {\"a\": [1, 2]}]")       # shared, not circular
        self.assertEqual(jsondeep._dumps_iter({1: "a", "1": "b"}, True, False, True), '{"1": "a", "1": "b"}')

    def test_fast_path_is_json(self):
        with mock.patch.object(jsondeep, "_dumps_iter") as it:
            self.assertEqual(jsondeep.dumps({"b": [1.5, "é"]}, ensure_ascii=False, sort_keys=True),
                             '{"b": [1.5, "é"]}')
            self.assertEqual(jsondeep.loads('{"a": 1}'), {"a": 1})
        it.assert_not_called()

    def test_defaults_are_json_defaults(self):                 # ascii, input order, nan allowed: both paths
        v = {"b": [float("nan")], "a": "é"}
        want = json.dumps(v)
        self.assertEqual(jsondeep.dumps(v), want)
        with c_json_limit(1):
            self.assertEqual(jsondeep.dumps(v), want)

    def test_deep_is_linear(self):
        import time
        from sipar.deep import call_deep
        v: list = []
        for _ in range(100_000):
            v = [v, {"a": 1}]
        with c_json_limit():
            t = time.time()
            s = jsondeep.dumps(v)
            self.assertLess(time.time() - t, 3.0)
            self.assertEqual(s, '[' * 100_000 + '[]' + ', {"a": 1}]' * 100_000)
            back = call_deep(jsondeep.loads, s)
        self.assertEqual(call_deep(jsondeep.dumps, back), s)

    def test_loads_keeps_options_and_errors(self):
        with c_json_limit(3):
            self.assertEqual(jsondeep.loads('[[[[7]]]]', parse_int=str), [[[["7"]]]])
            with self.assertRaises(json.JSONDecodeError) as cm:
                jsondeep.loads('[[[[7]]]')
            self.assertIsNone(cm.exception.__context__)            # no chained RecursionError
            self.assertEqual(jsondeep.dumps([[[["é"]]]], ensure_ascii=False), '[[[["é"]]]]')
            with self.assertRaises(ValueError):
                jsondeep.dumps([[[[float("nan")]]]], allow_nan=False)


# Every operation that walks a whole value, on 9,000 nested records (18,001 levels, under the 20,000 cap).
DEEP_OPS_SRC = '''allow memory
allow io
allow ai
type N = { kids: List[N] }
type Box = { n: N, tag: Str }
type R = { tag: Str }
enum W { One(n: N), Zero }
fn build(n: Int) -> N {
 var x = N { kids: [] }
 var i = 0
 while i < n { x = N { kids: [x] }; i = i + 1 }
 x
}
fn er(e: Error) -> Str { "ERR " + e.kind + ": " + e.message }
ai fn summ(a: N) -> R uses ai { "summarise {a}" }
fn eq(a: N, b: N) -> Str { try { "{a == b}" } catch e { er(e) } }
fn ne(a: N) -> Str { try { "{a != build(8999)}" } catch e { er(e) } }
fn rend(a: N) -> Str { try { "{"{a}".len()}" } catch e { er(e) } }
fn enc(a: N) -> Str { try { "{json.encode(a).len()}" } catch e { er(e) } }
fn tr(a: N) -> Str { try { let c = trust(a, "ok")
 "{c == a}" } catch e { er(e) } }
fn bx(a: N, b: N) -> Str { try { let x = Box { n: a, tag: "x" }
 "{x.n == b}" } catch e { er(e) } }
fn lst(a: N, b: N) -> Str { try { "{[a, b].contains(b)}" } catch e { er(e) } }
fn dec(a: N) -> Str { try { let s = json.encode(a)
 let c = s as N
 "{c == a}" } catch e { er(e) } }
fn mem(a: N) -> Str uses memory { try { memory.save("k", a)
 let c: N? = memory.load("k")
 "{c != none}" } catch e { er(e) } }
fn mp(a: N, b: N) -> Str { try { let m = ["k": a]
 let n = ["k": b]
 "{m == n}" } catch e { er(e) } }
fn en(a: N, b: N) -> Str { try { "{W.One(a) == W.One(b)}" } catch e { er(e) } }
fn enr(a: N) -> Str { try { "{"{W.One(a)}".len()}" } catch e { er(e) } }
fn ai1(a: N) -> Str uses ai { try { let r = summ(a)
 r.tag } catch e { er(e) } }
fn main() uses memory, io, ai {
 let a = build(9000)
 let b = build(9000)
 print(a)
 print("eq " + eq(a, b) + " ne " + ne(a) + " render " + rend(a) + " json " + enc(a))
 print("trust " + tr(a) + " box " + bx(a, b) + " list " + lst(a, b) + " decode " + dec(a) + " mem " + mem(a))
 print("map " + mp(a, b) + " enum " + en(a, b) + " enumrender " + enr(a) + " ai " + ai1(a))
}
'''
DEEP_OPS_OUT = [nest(9000), "eq true ne true render 108012 json 108012",
                "trust true box true list true decode true mem true", "map true enum true enumrender 108033 ai mock"]


def _python312() -> str | None:
    import shutil
    for p in (shutil.which("python3.12"), "/opt/homebrew/bin/python3.12", "/usr/local/bin/python3.12"):
        if p and os.path.exists(p):
            return p
    return None


def _ref_equal(x, y) -> bool:
    """Python's == as Sipar used it before round 5 (recursive): the reference for values.equal. Round 10, F6:
    without Python's "the same object is equal" shortcut, so a NaN equals nothing even when shared (SPEC)."""
    if isinstance(x, list) or isinstance(y, list):
        return (isinstance(x, list) and isinstance(y, list) and len(x) == len(y)
                and all(_ref_equal(p, q) for p, q in zip(x, y)))
    if isinstance(x, Record) or isinstance(y, Record):
        return (isinstance(x, Record) and isinstance(y, Record) and x.type_name == y.type_name
                and _ref_equal(x.fields, y.fields))
    if isinstance(x, EnumVal) or isinstance(y, EnumVal):
        return (isinstance(x, EnumVal) and isinstance(y, EnumVal) and (x.enum, x.variant) == (y.enum, y.variant)
                and _ref_equal(x.fields, y.fields))
    if isinstance(x, dict) or isinstance(y, dict):
        return (isinstance(x, dict) and isinstance(y, dict) and x.keys() == y.keys()
                and all(_ref_equal(x[k], y[k]) for k in x))
    return x == y


def _value_corpus(seed: int, n: int) -> list:
    import random
    rnd = random.Random(seed)
    nan = float("nan")
    shared = [[1, nan], {"a": nan}]
    leaves = [None, True, False, 0, 1, 1.0, -0.0, 0.0, 2, nan, "", "a", "1", 10**20, float(10**20)]

    def gen(d=0):
        r = rnd.random()
        if d > 3 or r < 0.35:
            return rnd.choice(leaves + shared)
        k = rnd.randrange(3)
        if r < 0.5:
            return [gen(d + 1) for _ in range(k)]
        if r < 0.6:
            return LList([gen(d + 1) for _ in range(k)], labels=frozenset({"untrusted:x"}))
        if r < 0.72:
            return {rnd.choice("abc"): gen(d + 1) for _ in range(k)}
        if r < 0.78:
            return LDict({rnd.choice("ab"): gen(d + 1) for _ in range(k)})
        if r < 0.9:
            return Record(rnd.choice("PQ"), {f: gen(d + 1) for f in rnd.sample("xyz", k)})
        if r < 0.94:
            return LRecord("P", {"x": gen(d + 1)}, labels=frozenset({"untrusted:y"}))
        return EnumVal("E", rnd.choice(("A", "B")), {f: gen(d + 1) for f in rnd.sample("uv", k % 2)})
    return [gen() for _ in range(n)]


class T_D3_Ops(Base):
    """Walks over a whole value used C recursion (any(...) over a generator, str.join over a generator,
    Python's == on lists, maps and records): Python 3.12 stops that at about 10,000 levels whatever the stack.
    to_json also copied its cycle set at every level (quadratic)."""

    def setUp(self):
        self.d = self.tmpdir()
        cwd = os.getcwd()
        os.chdir(self.d)
        self.addCleanup(os.chdir, cwd)
        self.path = self.write(self.d, "ops.sipar", DEEP_OPS_SRC)
        self.p = sipar.load(self.path)

    def test_ops_on_this_python(self):
        rc, out, err = cli("run", self.path)
        self.assertEqual((rc, out.splitlines()), (0, DEEP_OPS_OUT), err[-300:])

    @unittest.skipUnless(_python312(), "no python3.12 here")
    def test_ops_on_python312(self):                           # was: eq/ne "too deeply nested", render "[...]"
        env = {k: v for k, v in os.environ.items() if k not in CLEAN_ENV}
        env.update(SIPAR_MODEL="mock", PYTHONPATH=ROOT)
        r = subprocess.run([_python312(), "-m", "sipar", "run", self.path], capture_output=True, text=True,
                           env=env, cwd=self.d, timeout=120)
        self.assertEqual((r.returncode, r.stdout.splitlines()), (0, DEEP_OPS_OUT), r.stderr[-300:])

    def test_walks_are_linear(self):                           # was 1.6 to 2.4 s each (quadratic to_json)
        import time
        for name, want in (("rend", "108012"), ("enc", "108012"), ("tr", "true"), ("dec", "true")):
            best = None
            for _ in range(3):              # CPU time, best of 3: a busy machine is not a slow walk
                with clean_env():
                    a = self.p.call("build", 9000)
                    t = time.process_time()
                    got = self.p.call(name, a)
                    spent = time.process_time() - t
                self.assertEqual(got, want, name)
                best = spent if best is None else min(best, spent)
                if best < 1.0:
                    break
            self.assertLess(best, 1.0, name)

    def test_equal_any_depth_no_stack(self):                   # explicit stack: works on the main thread
        from sipar.runtime.values import equal
        a: list = []
        b: list = []
        for _ in range(100_000):
            a, b = [a, 1], [b, 1]
        self.assertTrue(equal(a, b))
        b[0][0][1] = 2
        self.assertFalse(equal(a, b))
        r1, r2 = Record("N", {"k": []}), Record("N", {"k": []})
        for _ in range(100_000):
            r1, r2 = Record("N", {"k": [r1]}), Record("N", {"k": [r2]})
        self.assertTrue(r1 == r2)
        self.assertFalse(r1 != r2)

    def test_equal_cycles(self):
        from sipar.runtime.values import equal
        a: list = [1]
        a.append(a)
        b: list = [1]
        b.append(b)
        self.assertTrue(equal(a, a))                           # the same object: the item shortcut ends it
        with self.assertRaises(SiparRuntimeError) as cm:
            equal(a, b)
        self.assertEqual((cm.exception.kind, cm.exception.message), ("value", "value too deeply nested to compare"))

    def test_equal_matches_python(self):
        from sipar.runtime.values import equal
        vals = _value_corpus(11, 400)
        nan = float("nan")
        vals += [nan, [nan], {"a": nan}, Record("P", {}), EnumVal("E", "A"), EnumVal("E", "A", {}), [True], [1]]
        seen = {True: 0, False: 0}
        for i, x in enumerate(vals):
            for y in vals[i:i + 40] + [x]:
                want = (isinstance(x, bool) == isinstance(y, bool)) and _ref_equal(x, y)
                self.assertEqual(equal(x, y), want, (x, y))
                self.assertEqual(equal(y, x), want, (y, x))
                seen[want] += 1
        self.assertGreater(min(seen.values()), 500)            # both answers really occur
        self.assertFalse(equal(nan, nan))                      # the top is not the item shortcut
        self.assertTrue(equal([[1.0], {"a": 0}], [[1], {"a": -0.0}]))
        self.assertFalse(equal(True, 1))
        self.assertTrue(equal([True], [1]))                    # as before: the Bool rule is for the top only
        self.assertFalse(equal(Record("P", {"x": 1}), {"x": 1}))
        self.assertFalse(equal(EnumVal("E", "A"), EnumVal("E", "B")))

    def test_render_shared_is_not_a_cycle(self):
        from sipar.runtime.values import render
        x = [1, [2]]
        self.assertEqual(render([x, x, {"k": x}]), '[[1, [2]], [1, [2]], {"k": [1, [2]]}]')
        c: list = [1]
        c.append([c])
        self.assertEqual(render(c), '[1, ["[...]"]]')


class T_D3_Walkers(unittest.TestCase):
    """The rewritten walkers, case by case (mutation check of round 5, D3)."""

    def test_equal_depth_cap_exact(self):
        from sipar.deep import RECURSION_LIMIT
        from sipar.runtime import values as V
        self.assertEqual(V.MAX_COMPARE_DEPTH, RECURSION_LIMIT)

        def lists(k):                                           # k lists inside each other
            v: list = []
            for _ in range(k - 1):
                v = [v]
            return v
        with mock.patch.object(V, "MAX_COMPARE_DEPTH", 10):
            self.assertTrue(V.equal(lists(9), lists(9)))
            self.assertFalse(V.equal(lists(9), lists(8)))
            with self.assertRaises(SiparRuntimeError):
                V.equal(lists(10), lists(10))
            self.assertTrue(V.equal(3, 3))                      # a leaf has no depth

    def test_has_function(self):
        from sipar.runtime.values import Closure, has_function
        f = Closure([], None, None)
        x = [1, "a", 2.5]
        self.assertIs(has_function([x, x, {"k": x}]), False)   # shared, looked at once: still no function
        self.assertFalse(has_function(["s", 1, 2.0, None, True, Record("P", {"a": [x]}), EnumVal("E", "A")]))
        for v in ([[f]], {"k": [1, f]}, Record("P", {"a": 1, "b": [f]}), EnumVal("E", "A", {"u": f}), [len]):
            self.assertTrue(has_function(v), v)
        self.assertTrue(has_function(f))
        c: list = [1]
        c.append(c)
        self.assertFalse(has_function(c))                       # a cycle ends
        c.append(f)
        self.assertTrue(has_function(c))

    def test_to_json_leaves(self):
        from sipar.runtime.values import Closure, to_json
        sec = set_labels("tok", frozenset({"secret:K"}))
        v = [None, True, False, 1, 1.5, "s", RangeVal(1, 3), Closure([], None, None), EnumVal("E", "A"),
             EnumVal("E", "B", {"x": 1}), Record("P", {"f": [2]}), {"k": sec}]
        want = '[null, true, false, 1, 1.5, "s", [1, 2], "<fn>", "A", {"tag": "B", "x": 1}, {"f": [2]}, {"k": "tok"}]'
        self.assertEqual(json.dumps(to_json(v)), want)
        self.assertEqual(json.dumps(to_json(v, True)), want.replace('"tok"', '"\\u00absecret:K\\u00bb"'))
        self.assertEqual(to_json(sec, redact=True), MASK.replace("R5_TOKEN", "K"))

    def test_render_numbers_inside(self):
        from sipar.runtime.values import render
        inf = float("inf")
        self.assertEqual(render([1.5, inf, {"a": -inf, "b": [float("nan")]}]), '[1.5, inf, {"a": -inf, "b": [nan]}]')


# ====================================================================== C2. lone surrogates are never a Sipar Str

LONE = "text holds a lone surrogate (an unpaired \\ud800-\\udfff escape); it is not valid Unicode"


class T_C2(Base):
    def test_print_after_as(self):                              # sur.sipar / sur4.sipar: was an internal error
        src = ('fn main() {\n let xs = "[\\"\\\\ud800x\\"]" as List[Str]\n print(xs[0])\n}\n')
        e = self.prog(src).error()
        self.assertEqual((e.kind, e.message), ("decode", "$[0]: " + LONE))

    def test_catchable(self):                                   # sur4.sipar: try/catch sees a decode error
        out = self.out('try { let xs = "[\\"\\\\ud800x\\"]" as List[Str]\n print(xs[0]) } '
                       'catch e { print("caught {e.kind}") }\nprint("after")')
        self.assertEqual(out, "caught decode\nafter\n")

    def test_map_key(self):
        e = self.err('let m = "\\{\\"\\\\udc00\\": 1\\}" as Map[Int]')
        self.assertEqual((e.kind, e.message), ("decode", "$: a key " + LONE))

    def test_paired_surrogates_fine(self):                      # guard: a real pair is one emoji
        out = self.out('let xs = "[\\"\\\\ud83d\\\\ude00\\"]" as List[Str]\nprint(xs[0])')
        self.assertEqual(out, "\U0001F600\n")

    def test_api_argument(self):
        d = self.tmpdir()
        p = sipar.load(self.write(d, "p.sipar", "fn echo(s: Str) -> Str { s }\n"))
        with clean_env():
            with self.assertRaises(sipar.SiparError) as cm:
                p.call("echo", "a\ud800")
            self.assertEqual(p.call("echo", "a\U0001F600"), "a\U0001F600")
        self.assertEqual((cm.exception.kind, cm.exception.message), ("decode", "echo.s: " + LONE))

    def test_os_text_is_replaced(self):                         # argv, env.get, input: U+FFFD
        src = ('allow env ["R5X"]\nallow io\nfn main(args: List[Str]) uses env, io {\n print(args[0])\n'
               ' print(env.get("R5X") ?? "-")\n print(input(""))\n}\n')
        out = self.prog(src).run(argv=["a\udcff"], env={"R5X": "b\udcfe"}, stdin=io.StringIO("c\udcfd\n"))
        self.assertEqual(out, "a\ufffd\nb\ufffd\nc\ufffd\n")

    def test_mock_and_http_replies_are_replaced(self):
        d = self.tmpdir()
        p = sipar.load(self.write(d, "p.sipar", 'allow ai\nai fn c() -> Str { "x" }\n'))
        with clean_env():
            self.assertEqual(p.call("c", mock_script=["a\ud800"]), "a\ufffd")
        from rt_helpers import Server
        srv = Server()
        self.addCleanup(srv.close)
        srv.chat_reply = {"choices": [{"message": {"content": "h\ud800i"}}]}
        src = 'allow ai\n@model("local/m") @retries(0)\nai fn c() -> Str { "x" }\nfn main() uses ai { print(c()) }\n'
        self.assertEqual(self.prog(src).run(env={"SIPAR_LOCAL_URL": srv.url}), "h\ufffdi\n")

    def test_journal_line_is_replay(self):
        d = self.tmpdir()
        j = self.write(d, "j.jsonl", '{"seq": 1, "kind": "args", "request": {}, "response": ["\\ud800"]}\n')
        with self.assertRaises(SiparRuntimeError) as cm:
            Journal.load(j)
        self.assertEqual((cm.exception.kind, cm.exception.message),
                         ("replay", "journal j.jsonl line 1 holds text that is not valid Unicode (a lone surrogate)"))

    def test_memory_store_is_io(self):
        d = self.tmpdir()
        os.makedirs(os.path.join(d, ".sipar", "memory"))
        self.write(d, ".sipar/memory/p.json",
                   '{"version": 1, "entries": {"a": {"value": "\\ud800", "labels": [], "enc": 2}}}')
        p = sipar.load(self.write(d, "p.sipar", 'allow memory\nfn ld() -> Str uses memory { try { let v: Str? = '
                                              'memory.load("a")\n "loaded" } catch e { e.kind + ": " + e.message } }\n'))
        cwd = os.getcwd()
        os.chdir(d)
        self.addCleanup(os.chdir, cwd)
        with clean_env():
            got = p.call("ld")
        self.assertTrue(got.startswith("io: "), got)
        self.assertIn("holds text that is not valid Unicode (a lone surrogate); fix or delete it (it was not changed)", got)


# ====================================================================== C3/C4. usage of failed attempts

class _Err500:
    """127.0.0.1 server: every POST answers HTTP 500 with a JSON body that reports usage 500/7 (srv.py)."""

    def __init__(self, body: str):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                data = body.encode()
                self.send_response(500)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


FB_SRC = ('allow ai\nallow io\n@model("local/m | mock") @retries(0)\nai fn c(t: Str) -> Str { "Say {t}" }\n'
          'fn main() uses ai, io { budget(tokens: 100000) { print(c("hi")) } }\n')
USAGE_500 = json.dumps({"error": {"message": "overloaded"}, "usage": {"prompt_tokens": 500, "completion_tokens": 7}})


class T_C3(Base):
    def run_fb(self, body: str) -> list[dict]:
        srv = _Err500(body)
        self.addCleanup(srv.close)
        j = Journal()
        self.assertEqual(self.prog(FB_SRC).run(journal=j, env={"SIPAR_LOCAL_URL": srv.url}), "mock answer\n")
        return [e for e in j.entries if e.get("kind") == "ai"]

    def test_error_body_usage_is_charged(self):                 # fb.sipar + srv.py: was 31/0
        failed = self.run_fb(USAGE_500)[0]
        self.assertEqual(failed["meta"]["usage"], {"input": 500, "output": 7})

    def test_no_usage_falls_back_to_estimate(self):             # guard: SPEC §7 estimate
        failed = self.run_fb('{"error": {"message": "overloaded"}}')[0]
        self.assertEqual(failed["meta"]["usage"]["output"], 0)
        self.assertGreater(failed["meta"]["usage"]["input"], 0)

    def test_bad_usage_in_error_body_is_estimated(self):        # a huge or negative count is not trusted
        for u in ({"prompt_tokens": -5, "completion_tokens": 7}, {"prompt_tokens": 10 ** 12, "completion_tokens": 1}):
            failed = self.run_fb(json.dumps({"usage": u}))[0]
            self.assertEqual(failed["meta"]["usage"]["output"], 0, u)
        failed = self.run_fb("not json {")[0]
        self.assertEqual(failed["meta"]["usage"]["output"], 0)

    def test_unit_error_body_usage(self):
        from sipar.runtime.providers import _error_body_usage
        self.assertEqual(_error_body_usage(USAGE_500.encode()), {"input": 500, "output": 7})
        for bad in (b"", None, "text", b"[1]", b"{", b'{"usage": 3}', b"\xff\xfe"):
            self.assertIsNone(_error_body_usage(bad), bad)


def _trace_of(entries: list[dict]):
    from sipar import trace
    return trace.summarize(entries), trace.render(trace.summarize(entries))


class T_C4(Base):
    FAILED = {"seq": 1, "kind": "ai", "request": {"fn": "c"}, "response": None, "error": {"kind": "ai"},
              "meta": {"model": "local/m", "usd": 3.1e-05, "usage": {"input": 500, "output": 7}}, "fn": "c"}
    OK = {"seq": 2, "kind": "ai", "request": {"fn": "c"}, "response": {"text": "x", "usage": {"input": 31,
          "output": 3}}, "meta": {"model": "mock", "usd": 3.4e-07}, "fn": "c"}

    def test_failed_attempt_tokens_counted(self):               # failed_attempt_500.jsonl: tokens 31 vs usd
        s, _ = _trace_of([self.FAILED, self.OK])
        t = s["totals"]
        self.assertEqual((t["tokens_in"], t["tokens_out"], t["errors"]), (531, 10, 1))
        self.assertEqual(s["models"]["local/m"]["tokens_in"], 500)

    def test_response_usage_wins(self):                         # guard: a reply's own usage is not doubled
        e = dict(self.OK, meta={"model": "mock", "usage": {"input": 999, "output": 999}})
        s, _ = _trace_of([e])
        self.assertEqual(s["totals"]["tokens_in"], 31)

    def test_bad_meta_usage_ignored(self):
        for u in ("x", {"input": -1, "output": "a"}, {"input": 10 ** 9 * 11, "output": 1.5e300}):
            e = dict(self.FAILED, meta={"model": "m", "usage": u})
            s, _ = _trace_of([e])
            self.assertEqual((s["totals"]["tokens_in"], s["totals"]["tokens_out"]), (0, 0), u)

    def test_text_usd_precision(self):                          # C11: the text showed 0 for 3.4e-07
        _, text = _trace_of([self.OK])
        self.assertIn(" 0.00000034 ", text)
        from sipar.trace import _cell
        self.assertEqual([_cell(x) for x in (0.0, 0.5, 1.0, 12.345, 1e-09, 4e-10)],
                         ["0", "0.5", "1.00", "12.35", "0.000000001", "0"])


# ====================================================================== C5-C8. Python API

API_SRC = 'allow ai\nallow io\nfn add(a: Int, b: Int) -> Int uses io { print("x")\n a + b }\nai fn c() -> Str { "x" }\n'


class T_API(Base):
    def setUp(self):
        self.d = self.tmpdir()
        cwd = os.getcwd()
        os.chdir(self.d)
        self.addCleanup(os.chdir, cwd)
        self.p = sipar.load(self.write(self.d, "q.sipar", API_SRC))

    def call(self, *a, **kw):
        kw.setdefault("out", io.StringIO())
        with clean_env():
            return self.p.call(*a, **kw)

    def test_journal_bare_name(self):                           # C5: makedirs("") crashed
        self.assertEqual(self.call("add", 1, 2, journal="j.jsonl"), 3)
        self.assertTrue(os.path.isfile(os.path.join(self.d, "j.jsonl")))

    def test_journal_replaced_not_appended(self):               # C5: two runs in one file broke replay
        for t in ("t1", "t2"):
            self.assertEqual(self.call("c", journal="j.jsonl", mock_script=[t]), t)
        entries = Journal.load("j.jsonl")
        self.assertEqual([(e["seq"], e["response"]["text"]) for e in entries], [(1, "t2")])
        from pathlib import Path
        self.assertEqual(self.call("add", 1, 2, journal=Path("sub") / "k.jsonl"), 3)   # PathLike, new dir
        self.assertTrue(os.path.isfile(os.path.join(self.d, "sub", "k.jsonl")))

    def test_journal_errors_are_clean(self):                    # C6: no __context__ chain
        with self.assertRaises(sipar.SiparError) as cm:
            self.call("add", 1, 2, journal=self.d)
        self.assertEqual(cm.exception.kind, "io")
        self.assertIn("cannot write journal", cm.exception.message)
        self.assertIsNone(cm.exception.__context__)
        self.assertIsNone(cm.exception.__cause__)

    def test_check_error_not_chained(self):                     # C6
        with self.assertRaises(sipar.CheckError) as cm:
            sipar.load(self.write(self.d, "bad.sipar", "fn f({ }\n"))
        self.assertIsNone(cm.exception.__context__)
        self.assertRegex(str(cm.exception), r"bad\.sipar:1:6: \[E110\] ")

    def test_load_not_utf8(self):                               # C7: was UnicodeDecodeError
        with open(os.path.join(self.d, "b.sipar"), "wb") as fh:
            fh.write(b"\xff\xfe")
        with self.assertRaises(sipar.SiparError) as cm:
            sipar.load(os.path.join(self.d, "b.sipar"))
        self.assertEqual((cm.exception.kind, cm.exception.message),
                         ("io", f"cannot read {os.path.join(self.d, 'b.sipar')}: not UTF-8 text"))
        self.assertIsNone(cm.exception.__context__)
        with self.assertRaises(FileNotFoundError):              # guard: SPEC §10, a missing file is OSError
            sipar.load(os.path.join(self.d, "missing.sipar"))

    def test_check_source_types(self):                          # C7: bytes crashed deep in the lexer
        with self.assertRaisesRegex(TypeError, r"^check_source: src must be str, got bytes$"):
            sipar.check_source(b"fn main() {}")
        with self.assertRaisesRegex(TypeError, r"^check_source: file must be str, got int$"):
            sipar.check_source("fn main() {}", 3)
        self.assertEqual(sipar.check_source("fn main() {}"), [])

    def test_bad_model(self):                                   # C7/C8
        with self.assertRaisesRegex(TypeError, r"model must be a str .* got int"):
            self.call("c", model=5)
        with self.assertRaisesRegex(TypeError, r"got list"):
            self.call("c", model=["mock"])
        for m in ("", "  "):
            with self.assertRaisesRegex(ValueError, r"model is empty"):
                self.call("c", model=m)
        self.assertEqual(self.call("c", model="mock"), "mock answer")          # guard

    def test_bad_mock_script(self):                             # C8: "x" was ignored silently
        with self.assertRaisesRegex(TypeError, r"mock_script must be a list of replies or a dict .* got str"):
            self.call("c", mock_script="x")
        with self.assertRaisesRegex(TypeError, r"dict keys must be function names"):
            self.call("c", mock_script={1: ["a"]})
        for bad in ([object()], [float("nan")], {"c": [{1, 2}]}):
            with self.assertRaisesRegex(TypeError, r"replies must be JSON data"):
                self.call("c", mock_script=bad)
        self.assertEqual(self.call("c", mock_script=("t1",)), "t1")            # a tuple is a list
        self.assertEqual(self.call("c", mock_script={"c": "t2"}), "t2")         # guard
        self.assertEqual(self.call("c", mock_script=[1]), "1")                  # documented: JSON text

    def test_bad_out_and_journal(self):                         # C7: out=42 was AttributeError mid-run
        with self.assertRaisesRegex(TypeError, r"out must have a write\(\) method, got int"):
            self.call("add", 1, 2, out=42)
        with self.assertRaisesRegex(TypeError, r"journal must be a path \(str or os.PathLike\) or None, got int"):
            self.call("add", 1, 2, journal=7)
        with self.assertRaisesRegex(ValueError, r"journal must be a non-empty str path"):
            self.call("add", 1, 2, journal="")
        with self.assertRaisesRegex(ValueError, r"journal must be a non-empty str path"):
            self.call("add", 1, 2, journal=_BytesPath())
        self.assertFalse(os.path.exists(os.path.join(self.d, "j.jsonl")))


class _BytesPath:
    """A PathLike whose fspath is bytes: refused (the journal writer takes text paths)."""

    def __fspath__(self):
        return b"j.jsonl"


os.PathLike.register(_BytesPath)


# ====================================================================== C9/C11. CLI

def _sub(args: list[str], env: dict, cwd: str):
    e = {k: v for k, v in os.environ.items() if k not in CLEAN_ENV}
    e.update(PYTHONPATH=ROOT, SIPAR_MODEL="mock", **env)
    return subprocess.run([sys.executable, "-m", "sipar", *args], capture_output=True, env=e, cwd=cwd, timeout=60)


class T_CLI(Base):
    def test_ascii_stdout(self):                                # C9: was internal error (UnicodeEncodeError)
        d = self.tmpdir()
        self.write(d, "u.sipar", 'fn main() { print("hé") }\n')
        for env in ({"PYTHONIOENCODING": "ascii"}, {"PYTHONIOENCODING": "", "LC_ALL": "C", "LANG": "C",
                                                     "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0"}):
            r = _sub(["run", "u.sipar"], env, d)
            if env.get("LC_ALL") and r.stdout == "hé\n".encode():
                continue                                        # this Python still writes UTF-8 under C
            self.assertEqual((r.returncode, r.stdout, r.stderr), (0, b"h\\xe9\n", b""), env)

    def test_ascii_stderr(self):                                # C9: an error message with é
        d = self.tmpdir()
        self.write(d, "u.sipar", 'fn main() { assert false, "café" }\n')
        r = _sub(["run", "u.sipar"], {"PYTHONIOENCODING": "ascii"}, d)
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"caf\\xe9", r.stderr)
        self.assertNotIn(b"internal error", r.stderr)

    def test_closed_pipe_exit_141(self):                        # C11: `run | head` exited 1
        d = self.tmpdir()
        self.write(d, "l.sipar", "fn main() { for i in 0..300000 { print(i) } }\n")
        e = {k: v for k, v in os.environ.items() if k not in CLEAN_ENV}
        e.update(PYTHONPATH=ROOT)
        p = subprocess.Popen([sys.executable, "-m", "sipar", "run", "l.sipar"], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=e, cwd=d)
        self.assertEqual(p.stdout.readline(), b"0\n")
        p.stdout.close()
        self.assertEqual(p.wait(timeout=60), 141)
        self.assertEqual(p.stderr.read(), b"")
        p.stderr.close()
        from sipar.cli import PIPE_EXIT
        self.assertEqual(PIPE_EXIT, 141)

    def test_was_given(self):                                   # C11: "1 were given"
        d = self.tmpdir()
        prog = self.write(d, "m.sipar", 'fn main() { print("x") }\n')
        rc, out, err = cli("run", prog, "a")
        self.assertEqual(rc, 1)
        self.assertIn("fn main() takes no arguments, but 1 was given;", err)
        rc, out, err = cli("run", prog, "a", "b")
        self.assertIn("fn main() takes no arguments, but 2 were given;", err)
        msgs = [d.message for d in diags("fn f() -> Int { 1 }\nfn main() { let x = f(1)\n let y = f(1, 2) }\n")
                if d.code == "E212"]
        self.assertEqual(msgs, ["fn f takes 0 positional argument(s), but 1 was given",
                                "fn f takes 0 positional argument(s), but 2 were given"])


# ====================================================================== C12. every complete example checks

def md_blocks(path: str) -> list[tuple[int, str, str]]:
    """(line, info string, text) of every fenced block in a markdown file."""
    out, cur = [], None
    with open(path, encoding="utf-8") as fh:
        for i, ln in enumerate(fh.read().splitlines(), 1):
            if ln.startswith("```"):
                if cur is None:
                    cur = (i, ln[3:].strip(), [])
                else:
                    out.append((cur[0], cur[1], "\n".join(cur[2]) + "\n"))
                    cur = None
            elif cur is not None:
                cur[2].append(ln)
    assert cur is None, f"{path}: unclosed block at line {cur[0]}"
    return out


class T_C12(Base):
    """Every ```sipar block in SPEC.md (```rust in README.md) is a complete program that checks without errors;
    a block that is only a piece of a program says so: ```sipar fragment. Every block names its language."""

    def test_doc_blocks(self):
        seen = 0
        for name in ("SPEC.md", "README.md"):
            for line, info, text in md_blocks(os.path.join(ROOT, name)):
                where = f"{name}:{line}"
                self.assertTrue(info, f"{where}: a fenced block needs a language (sipar, sipar fragment, sh, text...)")
                program = "rust" if name == "README.md" else "sipar"     # GitHub colours `rust`, not `sipar`
                if info != program:
                    self.assertIn(info, (program + " fragment", "sh", "text", "python", "json"), where)
                    continue
                seen += 1
                errs = [f"{d['line']}:{d['col']} {d['code']} {d['message']}"
                        for d in sipar.check_source(text, where) if d["severity"] == "error"]
                self.assertEqual(errs, [], where)
        self.assertGreaterEqual(seen, 3)

    def test_spec_items_example_tests_pass(self):               # the §3 example: its own test block passes
        spec = [t for _, i, t in md_blocks(os.path.join(ROOT, "SPEC.md")) if i == "sipar"][0]
        self.assertIn("tools [weather, cpython_issues]", spec)
        prog = self.write(self.tmpdir(), "items.sipar", spec)
        self.assertEqual(cli("test", prog), (0, "PASS review is parsed\n1 passed, 0 failed\n", ""))


# ====================================================================== M. mutation survivors (critic's mutmut run)

from sipar import ast as A                                   # noqa: E402
from sipar.runtime import memory as MEM                      # noqa: E402
from sipar.runtime.journal import first_diff, new_run_path   # noqa: E402
from sipar.runtime.values import (EnumVal, LList, LDict, LRecord, RangeVal, Record,  # noqa: E402
                                  labels_of, own_labels, set_labels)


def lab(v, *labels):
    return set_labels(v, frozenset(labels))


def types_of(test: Base, src: str):
    """{fn name: type of its first parameter}, and the program's TypeEnv (for decode)."""
    p = test.prog(src)
    it = Interp(p.program, p.path, journal=Journal(), out=io.StringIO(), err_out=io.StringIO(),
                stdin=io.StringIO(""))
    return {d.name: d.params[0].type for d in p.program.items if isinstance(d, A.FnDecl) and d.params}, it.tenv


class T_M_Journal(Base):
    def test_first_diff_messages(self):
        long_a, long_b = "x" * 30 + "A" + "y" * 50, "x" * 30 + "B" + "y" * 50
        cases = [
            ((1, "1"), '$: journal 1 vs program "1"'),
            (({"a": 1}, {"a": 1, "b": 2}), ".b: not in journal, program has 2"),
            (({"a": 1, "b": 2}, {"a": 1}), ".b: journal has 2, program has nothing"),
            (({"a": 1, "b": 1}, {"a": 2, "b": 2}), ".a: journal 1 vs program 2"),
            (({"a": {"x": [1, 2]}}, {"a": {"x": [1, 3]}}), ".a.x[1]: journal 2 vs program 3"),
            (([1], [1, 2]), "$: journal has 1 items, program has 2"),
            (({"m": [1, 2]}, {"m": [1]}), ".m: journal has 2 items, program has 1"),
            (("abc", "abd"), "$ differs at char 2: journal 'abc' vs program 'abd'"),
            (("ab", "abc"), "$ differs at char 2: journal 'ab' vs program 'abc'"),
            ((long_a, long_b), f"$ differs at char 30: journal {long_a[10:70]!r} vs program {long_b[10:70]!r}"),
            (({"s": "ab"}, {"s": "xb"}), ".s differs at char 0: journal 'ab' vs program 'xb'"),
            ((1, 2), "$: journal 1 vs program 2"),
            (({"a": 1}, {"a": 1}), '$: journal {"a": 1} vs program {"a": 1}'),
            ((1, "z" * 200), '$: journal 1 vs program "' + "z" * 119 + "…"),
            ((1, "z" * 118), '$: journal 1 vs program "' + "z" * 118 + '"'),
        ]
        for (a, b), want in cases:
            self.assertEqual(first_diff(a, b), want, (a, b))
        self.assertEqual(first_diff([1], ["1"], "$.req"), '$.req[0]: journal 1 vs program "1"')

    def test_canon_of_non_json(self):
        from sipar.runtime.journal import canon
        self.assertEqual(canon(object()), "\0not-json:object")
        self.assertEqual(canon({"b": 1, "a": "é"}), '{"a": "é", "b": 1}')

    def test_new_run_path(self):
        d = self.tmpdir()
        prog = os.path.join(d, "p.sipar")
        with mock.patch("time.time_ns", return_value=123), \
                mock.patch("time.gmtime", return_value=__import__("time").gmtime(0)):
            p1 = new_run_path(prog)
            self.assertEqual(p1, os.path.join(d, ".sipar", "runs", f"19700101-000000Z-{os.getpid()}-000000123.jsonl"))
            os.makedirs(os.path.dirname(p1))
            open(p1, "w").close()
            p2 = new_run_path(prog)
            self.assertEqual(p2, p1.replace(".jsonl", "-2.jsonl"))
            open(p2, "w").close()
            self.assertEqual(new_run_path(prog), p1.replace(".jsonl", "-3.jsonl"))

    def test_load_messages(self):
        d = self.tmpdir()

        def msg(text=None, raw=None, name="j.jsonl"):
            p = os.path.join(d, name)
            if raw is not None:
                with open(p, "wb") as fh:
                    fh.write(raw)
            elif text is not None:
                self.write(d, name, text)
            with self.assertRaises(SiparRuntimeError) as cm:
                Journal.load(p)
            self.assertEqual(cm.exception.kind, "replay")
            return cm.exception.message

        self.assertEqual(msg(name="missing.jsonl"),
                         f"cannot read journal {os.path.join(d, 'missing.jsonl')}: no such file")     # round 7
        os.mkdir(os.path.join(d, "dir.jsonl"))
        self.assertEqual(msg(name="dir.jsonl"), f"cannot read journal {os.path.join(d, 'dir.jsonl')}: is a directory")
        self.assertEqual(msg(raw=b'{"kind": "x", "request": {}}\n\xff\n'),
                         f"cannot read journal {os.path.join(d, 'j.jsonl')}: not UTF-8 text")      # round 7
        self.assertEqual(msg('\n{"kind": "a", "request": 1}\n{nope\n'), "journal j.jsonl line 3 is not valid JSON")
        self.assertEqual(msg("[" * 200000 + "]" * 200000 + "\n"), "journal j.jsonl line 1 is nested too deeply")
        for bad in ('[1]', '{"kind": "a"}', '{"request": {}}', '"s"'):
            self.assertEqual(msg('{"kind": "a", "request": 1}\n' + bad + "\n"),
                             "journal j.jsonl line 2 lacks 'kind'/'request'", bad)
        self.write(d, "ok.jsonl", '\n  \n{"kind": "a", "request": 1, "s": "\\u00e9"}\n')
        self.assertEqual(Journal.load(os.path.join(d, "ok.jsonl")), [{"kind": "a", "request": 1, "s": "é"}])


class T_M_Encode(Base):
    def test_leaves_and_paths(self):
        U, W = "untrusted:a", "untrusted:b"
        cases = [
            (None, None, []), (True, True, []), (False, False, []),
            ([lab("a", U), "b", lab(3, W, U)], ["a", "b", 3], [[[0], [U]], [[2], [U, W]]]),
            (lab(1.5, U), 1.5, [[[], [U]]]),
            ({lab("k", U): lab("v", W)}, {"k": "v"}, [[[{"key": "k"}], [U]], [["k"], [W]]]),
            ({"a": {lab("k", U): 1}}, {"a": {"k": 1}}, [[["a", {"key": "k"}], [U]]]),
            ({1: "x"}, {"1": "x"}, []),
            (Record("R", {"a": lab("x", U), "b": 2}), {"a": "x", "b": 2}, [[["a"], [U]]]),
            (EnumVal("E", "v"), "v", []),
            (EnumVal("E", "s", {"q": lab("x", U)}), {"s": {"q": "x"}}, [[["q"], [U]]]),
            (RangeVal(1, 4), [1, 2, 3], []),
            (RangeVal(1, 3, frozenset({U})), [1, 2], [[[0], [U]], [[1], [U]]]),
            ([1, RangeVal(0, 1, frozenset({U}))], [1, [0]], [[[1, 0], [U]]]),
            (LList([1], frozenset({U})), [1], [[[{"own": True}], [U]]]),
            ([0, LDict({"k": 1}, frozenset({W}))], [0, {"k": 1}], [[[1, {"own": True}], [W]]]),
            (LRecord("R", {"a": 1}, frozenset({U})), {"a": 1}, [[[{"own": True}], [U]]]),
        ]
        for v, data, paths in cases:
            self.assertEqual(MEM.encode(v), (data, paths), v)
        data, _ = MEM.encode([lab("s", U), lab(7, U), lab(2.5, U)])
        self.assertEqual([type(x) for x in data], [str, int, float])         # plain JSON, no label classes
        shared = [1]
        self.assertEqual(MEM.encode([shared, shared]), ([[1], [1]], []))     # shared, not a cycle

    def test_errors(self):
        def err(v):
            with self.assertRaises(SiparRuntimeError) as cm:
                MEM.encode(v)
            return cm.exception.kind, cm.exception.message
        for x in (float("nan"), float("inf"), float("-inf")):
            self.assertEqual(err([1, x]), ("value", "memory.save: NaN and infinity cannot be stored"))
        cyc: list = []
        cyc.append(cyc)
        self.assertEqual(err(cyc), ("value", "memory.save: the value contains itself (a cycle); it cannot be "
                                             "stored as JSON"))
        d: dict = {}
        d["self"] = d
        self.assertEqual(err(d)[0], "value")
        self.assertEqual(err([lambda: 0]), ("value", "memory.save: functions cannot be stored"))

    def test_depth_limit(self):
        from sipar.runtime.decode import MAX_VALUE_DEPTH, TOO_DEEP

        def nested(n):
            v: list = []
            for _ in range(n):
                v = [v]
            return v
        from sipar.deep import call_deep
        call_deep(MEM.encode, nested(MAX_VALUE_DEPTH))                      # the limit itself is fine
        with self.assertRaises(SiparRuntimeError) as cm:
            call_deep(MEM.encode, nested(MAX_VALUE_DEPTH + 1))
        self.assertEqual(cm.exception.message, f"memory.save: value {TOO_DEEP}")

    def test_valid_paths(self):
        good = [[], [[[], ["a"]]], [[[1, "k", {"key": "k"}, {"own": True}], ["a", "b"]]], [[[0], []]]]
        bad = ["x", None, [[[], ["a"], 1]], [["x", ["a"]]], [[[], "a"]], [[[], [1]]], [[[True], ["a"]]],
               [[[{"key": 1}], ["a"]]], [[[{"key": "k", "x": 1}], ["a"]]], [[[{"own": False}], ["a"]]],
               [[[1.5], ["a"]]], [["notalist"]], [[[], ["a"]], 3], [[[None], ["a"]]]]
        for p in good:
            self.assertTrue(MEM._valid_paths(p), p)
        for p in bad:
            self.assertFalse(MEM._valid_paths(p), p)


DEC_SRC = ('type R = { a: Str, b: Int }\nenum E { v, s(q: Str) }\n'
           'fn s(x: Str) {}\nfn ls(x: List[Str]) {}\nfn mp(x: Map[Int]) {}\nfn r(x: R) {}\nfn e(x: E) {}\n'
           'fn le(x: List[E]) {}\nfn b(x: Bool) {}\nfn f(x: Float) {}\nfn i(x: Int) {}\n')


class T_M_Decode(Base):
    def setUp(self):
        self.t, self.tenv = types_of(self, DEC_SRC)

    def dec(self, fn, value, labels=(), enc=2):
        e = {"value": value, "labels": [list(x) for x in labels]}
        if enc is not None:
            e["enc"] = enc
        return MEM.decode(e, self.t[fn], self.tenv, "k")

    def err(self, fn, entry):
        with self.assertRaises(SiparRuntimeError) as cm:
            MEM.decode(entry, self.t[fn], self.tenv, "k")
        return cm.exception.kind, cm.exception.message

    def test_labels_come_back(self):
        v = self.dec("ls", ["a", "b"], [[[1], ["u:x"]]])
        self.assertEqual((labels_of(v[0]), labels_of(v[1])), (frozenset(), {"u:x"}))
        v = self.dec("ls", ["a"], [[[0], ["u:a"]], [[0], ["u:b"]]])             # two paths, one leaf: merged
        self.assertEqual(labels_of(v[0]), {"u:a", "u:b"})
        v = self.dec("s", "x", [[[], ["u:a"]]])
        self.assertEqual(labels_of(v), {"u:a"})
        self.assertEqual(labels_of(self.dec("f", 1.5, [[[], ["u"]]])), {"u"})
        self.assertEqual(labels_of(self.dec("i", 4, [[[], ["u"]]])), {"u"})

    def test_own_labels(self):
        for fn, val in (("ls", ["a"]), ("mp", {"k": 1}), ("r", {"a": "x", "b": 1})):
            v = self.dec(fn, val, [[[{"own": True}], ["u:a"]], [[{"own": True}], ["u:b"]]])
            self.assertEqual(own_labels(v), {"u:a", "u:b"}, fn)
        r = self.dec("r", {"a": "x", "b": 1}, [[[{"own": True}], ["u"]]])
        self.assertEqual((r.type_name, r.fields["a"], r.fields["b"]), ("R", "x", 1))

    def test_key_labels(self):
        v = self.dec("mp", {"a": 1, "k": 2, "z": 3}, [[[{"key": "k"}], ["u:a"]], [[{"key": "k"}], ["u:b"]]])
        self.assertEqual(list(v), ["a", "k", "z"])                             # order kept
        self.assertEqual([labels_of(k) for k in v], [frozenset(), {"u:a", "u:b"}, frozenset()])
        self.assertEqual(v, {"a": 1, "k": 2, "z": 3})

    def test_field_and_payload(self):
        r = self.dec("r", {"a": "x", "b": 1}, [[["a"], ["u"]]])
        self.assertEqual((labels_of(r.fields["a"]), labels_of(r.fields["b"])), ({"u"}, frozenset()))
        e = self.dec("e", {"s": {"q": "x"}}, [[["q"], ["u"]]])
        self.assertEqual((e.variant, labels_of(e.fields["q"])), ("s", {"u"}))
        m = self.dec("mp", {"a": 1}, [[["a"], ["u"]]])
        self.assertEqual(labels_of(m["a"]), {"u"})
        le = self.dec("le", [{"s": {"q": "x"}}], [[[0, "q"], ["u"]]])
        self.assertEqual(labels_of(le[0].fields["q"]), {"u"})

    def test_labels_that_do_not_fit(self):
        def bad(fn, value, path, t):
            got = self.err(fn, {"value": value, "labels": [[path, ["u"]]], "enc": 2})
            self.assertEqual(got, ("decode", f"memory.load('k'): stored labels ['u'] do not fit {t} at {path}"))
        bad("b", True, [], "Bool")
        bad("e", "v", [], "E")
        bad("ls", ["a"], [], "List[Str]")
        bad("s", "x", [{"own": True}], "Str")
        bad("ls", ["a"], [{"own": True}, 0], "List[Str]")
        bad("mp", {"a": 1}, [{"key": "b"}], "Map[Int]")
        bad("mp", {"a": 1}, [{"key": "a"}, 0], "Map[Int]")
        bad("ls", ["a"], [{"key": "a"}], "List[Str]")
        bad("ls", ["a"], [1], "List[Str]")
        bad("ls", ["a"], [-1], "List[Str]")
        bad("ls", ["a"], ["0"], "List[Str]")
        bad("mp", {"a": 1}, ["b"], "Map[Int]")
        bad("r", {"a": "x", "b": 1}, ["c"], "R")
        bad("e", {"s": {"q": "x"}}, ["z"], "E")
        bad("mp", {"a": 1}, [0], "Map[Int]")

    def test_entry_errors(self):
        for entry in ("x", {"labels": []}, {"value": 1, "labels": "x"}, None):
            self.assertEqual(self.err("i", entry), ("io", "memory entry 'k' is malformed"), entry)
        for enc in (3, 0, True, "2", None):
            self.assertEqual(self.err("i", {"value": 1, "enc": enc}), ("io", "memory entry 'k' has an unknown encoding"))
        self.assertEqual(self.dec("i", 5, enc=None), 5)                         # no "enc": the old form (1)
        self.assertEqual(self.dec("i", 5, enc=1), 5)
        self.assertEqual(self.err("s", {"value": 1, "enc": 2}),
                         ("decode", "memory.load('k'): the stored value does not match Str: $: expected Str, got integer"))
        deep = []
        for _ in range(25000):
            deep = [deep]
        self.assertEqual(self.err("ls", {"value": deep}),
                         ("io", "memory.load('k'): the stored value is nested too deeply"))

    def test_legacy_enum_forms(self):
        self.assertEqual(self.dec("e", {"tag": "s", "q": "x"}, enc=None).fields, {"q": "x"})
        t, tenv = types_of(self, "enum T { tag(tag: Str) }\nfn f(x: T) {}\n")
        with self.assertRaises(SiparRuntimeError) as cm:
            MEM.decode({"value": {"tag": {"tag": "x"}}}, t["f"], tenv, "k")
        self.assertEqual(cm.exception.kind, "io")
        self.assertTrue(cm.exception.message.startswith("memory.load('k'): $: stored in an older format that is "
                                                        "ambiguous for T"), cm.exception.message)
        v = MEM.decode({"value": {"tag": {"tag": "x"}}, "enc": 2}, t["f"], tenv, "k")
        self.assertEqual(v.fields, {"tag": "x"})

    def test_load_needs_a_type(self):
        with self.assertRaises(SiparRuntimeError) as cm:
            MEM.load(None, "k", None)
        self.assertEqual(cm.exception.kind, "type")
        self.assertTrue(cm.exception.message.startswith("memory.load: the type of the stored value is unknown"))

    def test_keys(self):
        for fname in ("memory.save", "memory.load"):
            for key, want in ((3, ("type", f"{fname}: key must be Str")), ("", ("value", f"{fname}: key must not be empty")),
                              ("k" * 257, ("value", f"{fname}: key is 257 characters; the limit is 256"))):
                with self.assertRaises(SiparRuntimeError) as cm:
                    MEM._key(fname, key)
                self.assertEqual((cm.exception.kind, cm.exception.message), want)
        k = MEM._key("memory.save", lab("k" * 256, "u"))
        self.assertEqual((k, type(k)), ("k" * 256, str))


class T_M_Stores(Base):
    def test_memstore(self):
        s = MEM.MemStore()
        self.assertIsNone(s.get("a"))
        e = {"value": [1], "labels": []}
        s.put("b", e)
        s.put("a", {"value": 2})
        e["value"].append(9)                                                # put stores a copy
        got = s.get("b")
        self.assertEqual(got, {"value": [1], "labels": []})
        got["value"].append(8)                                              # get returns a copy
        self.assertEqual(s.get("b"), {"value": [1], "labels": []})
        self.assertEqual(s.keys(), ["a", "b"])
        self.assertEqual((s.delete("a"), s.delete("a")), (True, False))
        self.assertEqual(s.keys(), ["b"])

    def test_filestore_roundtrip(self):
        d = self.tmpdir()
        p = os.path.join(d, "sub", "m.json")
        s = MEM.FileStore(p)
        self.assertEqual((s.get("x"), s.keys()), (None, []))
        s.put("b", {"value": "é", "labels": [], "enc": 2})
        s.put("a", {"value": 1})
        self.assertTrue(os.path.exists(p + ".lock"))
        self.assertEqual(s.keys(), ["a", "b"])
        with open(p, encoding="utf-8") as fh:
            text = fh.read()
        gen = json.loads(text).pop("gen")              # round 7: the store's generation stamp
        self.assertRegex(gen, "^[0-9a-f]{16}$")
        self.assertEqual(text, MEM.dump_store({"b": {"value": "é", "labels": [], "enc": 2}, "a": {"value": 1}}, gen))
        self.assertEqual(json.loads(text), {"version": 1, "gen": gen,
                                            "entries": {"b": {"value": "é", "labels": [], "enc": 2},
                                                        "a": {"value": 1}}})
        self.assertEqual((s.delete("a"), s.delete("a")), (True, False))
        self.assertEqual(s.keys(), ["b"])
        self.assertEqual(sorted(os.listdir(os.path.dirname(p))), ["m.json", "m.json.lock"])   # no temp files
        self.assertEqual(MEM.dump_store({}), '{"version": 1, "entries": {}}\n')
        self.assertEqual(json.loads(MEM.dump_store({})), {"version": 1, "entries": {}})

    def test_filestore_read_errors(self):
        d = self.tmpdir()
        p = os.path.join(d, "m.json")
        s = MEM.FileStore(p)

        def err(text):
            self.write(d, "m.json", text)
            with self.assertRaises(SiparRuntimeError) as cm:
                s.keys()
            self.assertEqual(cm.exception.kind, "io")
            return cm.exception.message
        self.assertEqual(err("{x"), f"memory store {p} is not valid JSON; fix or delete it (it was not changed)")
        self.assertEqual(err("[" * 200000 + "]" * 200000),
                         f"memory store {p} is nested too deeply to read; fix or delete it (it was not changed)")
        fmt = f"memory store {p} has an unknown format (expected \"version\": 1); it was not changed"
        for bad in ('[]', '{"version": 2, "entries": {}}', '{"version": 1, "entries": []}', '{"entries": {}}'):
            self.assertEqual(err(bad), fmt, bad)
        os.remove(p)
        os.mkdir(p)
        with self.assertRaises(SiparRuntimeError) as cm:
            s.get("a")
        self.assertEqual(cm.exception.message, f"cannot read memory store {p}: is a directory")     # round 7

    def test_filestore_write_errors(self):
        d = self.tmpdir()
        self.write(d, "file", "")
        s = MEM.FileStore(os.path.join(d, "file", "m.json"))
        with self.assertRaises(SiparRuntimeError) as cm:
            s.put("a", {"value": 1})
        self.assertEqual((cm.exception.kind, cm.exception.message),
                         ("io", f"cannot open memory store {os.path.join(d, 'file', 'm.json')}: "
                          f"{os.path.join(d, 'file')} is not a directory"))
        p = os.path.join(d, "m.json")
        s = MEM.FileStore(p)
        s.put("a", {"value": 1})
        for exc, shown in ((PermissionError(13, "Permission denied"), "permission denied"), (OSError("plain"), "plain")):
            with mock.patch("os.replace", side_effect=exc):
                with self.assertRaises(SiparRuntimeError) as cm:
                    s.put("b", {"value": 2})
            self.assertEqual(cm.exception.message, f"cannot write memory store {p}: {shown}")
            self.assertEqual(sorted(os.listdir(d)), ["file", "m.json", "m.json.lock"])   # temp file removed
        self.assertEqual(s.keys(), ["a"])                                   # the old file is kept

    def test_store_path(self):
        self.assertEqual(MEM.store_path("/tmp/x/p.sipar"), "/tmp/x/.sipar/memory/p.json")
        self.assertEqual(MEM.store_path("/tmp/x/"), "/tmp/.sipar/memory/program.json")


MEM_RUN = ('allow memory\nallow io\nfn main() uses memory, io {\n memory.save("a", [1, 2])\n memory.save("b", "x")\n'
           ' print(memory.keys())\n print(memory.delete("a"))\n print(memory.delete("a"))\n'
           ' let v: List[Int]? = memory.load("a")\n print(v ?? [0])\n let w: Str? = memory.load("b")\n print(w ?? "-")\n}\n')


class T_M_MemoryJournal(Base):
    def test_records_and_replay(self):
        p = self.prog(MEM_RUN)
        j = Journal()
        out = p.run(journal=j)
        self.assertEqual(out, '["a", "b"]\ntrue\nfalse\n[0]\nx\n')
        got = [(e["kind"], e["request"], e["response"]) for e in j.entries]
        self.assertEqual(got, [
            ("memory.save", {"key": "a", "value": [1, 2], "labels": [], "enc": 2}, None),
            ("memory.save", {"key": "b", "value": "x", "labels": [], "enc": 2}, None),
            ("memory.keys", {}, ["a", "b"]),
            ("memory.delete", {"key": "a"}, True),
            ("memory.delete", {"key": "a"}, False),
            ("memory.load", {"key": "a", "type": "List[Int]"}, None),
            ("memory.load", {"key": "b", "type": "Str"}, {"value": "x", "labels": [], "enc": 2}),
        ])
        q = self.prog(MEM_RUN)
        self.assertEqual(q.run(journal=Journal(replay=json.loads(json.dumps(j.entries)))), out)
        bad = json.loads(json.dumps(j.entries))
        bad[2]["response"] = ["a", 1]
        e = self.prog(MEM_RUN).error(journal=Journal(replay=bad))
        self.assertEqual((e.kind, e.message), ("replay", "memory.keys: journal entry is not a list of strings"))
        bad[2]["response"] = "ab"
        e = self.prog(MEM_RUN).error(journal=Journal(replay=bad))
        self.assertEqual(e.kind, "replay")


class T_M_DecodeTypes(Base):
    def test_got_type_names(self):
        from sipar.runtime.decode import _jtype
        from sipar.runtime.decode import HugeInt
        cases = [(None, "null"), (True, "boolean"), (False, "boolean"), (1, "integer"), (0, "integer"),
                 (HugeInt("1" + "0" * 400), "integer"), (1.5, "number"), ("s", "string"), ([1], "array"),
                 ({}, "object"), ({"a": 1}, "object")]
        for v, want in cases:
            self.assertEqual(_jtype(v), want, v)
        for js, got in (("null", "null"), ("true", "boolean"), ("1.5", "number"),
                        ("[1]", "array"), ("\\{\\}", "object"), ("1" + "0" * 400, "integer")):
            e = self.err(f'let v = "[{js}]" as List[Str]')
            self.assertEqual((e.kind, e.message), ("decode", f"$[0]: expected Str, got {got}"), js)
        e = self.err('let v = "[\\"s\\"]" as List[Int]')
        self.assertEqual((e.kind, e.message), ("decode", "$[0]: expected Int, got string"))

    def test_arg_and_schema(self):
        from sipar.runtime.decode import _arg, schema
        T = lambda n, *a: A.TName(1, 1, n, list(a))                 # noqa: E731
        self.assertEqual(_arg(T("Map", T("Str"), T("Int"))).name, "Int")
        self.assertEqual(_arg(T("Map", T("Int"))).name, "Int")
        self.assertEqual(_arg(T("List", T("Str"))).name, "Str")
        self.assertEqual(_arg(T("List")).name, "Any")
        self.assertEqual(_arg(T("Map")).name, "Any")
        self.assertEqual(_arg(T("Result", T("Str"), T("Int")), 1).name, "Int")
        _, tenv = types_of(self, "fn f(x: Int) {}\n")
        self.assertEqual(schema(T("List", T("Int")), tenv), {"type": "array", "items": {"type": "integer"}})
        self.assertEqual(schema(T("Map", T("Str")), tenv), {"type": "object", "additionalProperties": {"type": "string"}})


API_M = ('allow secret ["R5_TOKEN"]\ntype R = { a: Str, n: Int }\nenum E { v, s(q: Str) }\n'
         'fn rng() -> List[Int] { let r = 0..3\n r.map(fn(i: Int) -> Int => i) }\n'
         'fn en(x: E) -> E { x }\nfn rec(x: R) -> R { x }\nfn opt(x: Int?) -> Int { x ?? 7 }\n'
         'fn lst(x: List[List[Int]]) -> Int { x.len() }\nfn mp(m: Map[R]) -> Int { m.len() }\n'
         'fn sec() -> List[Str] uses secret { ["a", env.secret("R5_TOKEN")] }\n'
         'fn seckey() -> Map[Int] uses secret { let k = env.secret("R5_TOKEN")\n [k: 1] }\n'
         'fn fnv() -> fn(Int) -> Int { fn(i: Int) -> Int => i }\nfn two(a: Int, b: Int) -> Int { a - b }\n')


class T_M_Api(Base):
    def setUp(self):
        d = self.tmpdir()
        self.p = sipar.load(self.write(d, "m.sipar", API_M))

    def call(self, *a, **kw):
        with clean_env(ENV):
            return self.p.call(*a, out=io.StringIO(), **kw)

    def err(self, *a, **kw):
        with self.assertRaises(sipar.SiparError) as cm:
            self.call(*a, **kw)
        self.assertIsNone(cm.exception.__context__)
        return cm.exception.kind, cm.exception.message

    def test_values_out(self):
        self.assertEqual(self.call("rng"), [0, 1, 2])
        self.assertEqual(self.call("en", "v"), "v")
        self.assertEqual(self.call("en", {"s": {"q": "x"}}), {"s": {"q": "x"}})
        self.assertEqual(self.call("en", {"tag": "s", "q": "y"}), {"s": {"q": "y"}})
        self.assertEqual(self.call("rec", {"a": "x", "n": 2}), {"a": "x", "n": 2})
        self.assertEqual((self.call("opt", None), self.call("opt", 3)), (7, 3))
        self.assertEqual(self.call("lst", ((1, 2), (3,))), 2)                 # tuples are lists
        self.assertEqual(self.call("mp", {"k": {"a": "x", "n": 1}}), 1)
        self.assertEqual(self.call("two", 5, 2), 3)
        self.assertEqual(self.call("two", b=5, a=2), -3)

    def test_range_result(self):
        from sipar.api import _py_out
        self.assertEqual(_py_out(RangeVal(2, 5), "f()"), [2, 3, 4])
        self.assertEqual(_py_out([RangeVal(0, 0)], "f()"), [[]])

    def test_errors_out(self):
        self.assertEqual(self.err("sec"), ("taint", "sec()[1]: the result contains a secret; it cannot be returned "
                                                    "to Python"))
        self.assertEqual(self.err("seckey"), ("taint", "seckey(): a map key of the result is a secret; it cannot be "
                                                       "returned to Python"))
        self.assertEqual(self.err("fnv"), ("type", "fnv(): a function value cannot be returned to Python"))
        from sipar.api import _py_out
        with self.assertRaises(sipar.SiparError) as cm:
            _py_out({"a": [Record("R", {"b": lambda: 0})]}, "f()")
        self.assertEqual(cm.exception.message, "f().a[0].b: a function value cannot be returned to Python")

    def test_errors_in(self):
        self.assertEqual(self.err("nope"), ("type", "the program has no function 'nope'"))
        self.assertEqual(self.err("two", 1, 2, 3), ("type", "two takes 2 argument(s), got 3"))
        self.assertEqual(self.err("two", 1, c=2), ("type", "two has no parameter 'c'"))
        self.assertEqual(self.err("two", 1, a=2), ("type", "two: parameter 'a' given twice"))
        self.assertEqual(self.err("mp", {1: {"a": "x", "n": 1}}), ("decode", "mp.m: Map keys must be str, got int"))
        self.assertEqual(self.err("rec", {"a": 1, "n": 1}), ("decode", "rec.x.a: expected Str, got integer"))

    def test_clean_error(self):
        from sipar.api import _clean_error
        raw = SiparRuntimeError("io", "boom «secret:X»", 3, 4)
        raw.file = "/p.sipar"
        e = _clean_error(raw)
        self.assertEqual((type(e), e.kind, e.message, e.line, e.col, e.file, e.value, e.kind_value),
                         (sipar.SiparError, "io", raw.message, 3, 4, "/p.sipar", raw.message, "io"))

    def test_check_error_text(self):
        d1 = {"file": "a.sipar", "line": 2, "col": 5, "code": "E201", "message": "bad", "severity": "error"}
        d2 = dict(d1, line=3)
        self.assertEqual(str(sipar.CheckError([d1])), "a.sipar:2:5: [E201] bad")
        self.assertEqual(str(sipar.CheckError([d1, d2])), "a.sipar:2:5: [E201] bad (+1 more)")
        self.assertEqual(str(sipar.CheckError([d1, d2, d2])), "a.sipar:2:5: [E201] bad (+2 more)")
        self.assertEqual(str(sipar.CheckError([])), "None:None:None: [None] None")
        self.assertEqual(sipar.CheckError([d1]).diagnostics, [d1])

    def test_load_result(self):
        d = self.tmpdir()
        path = self.write(d, "w.sipar", 'allow net ["*"]\nfn main() {}\nfn g(x: Int) -> Int { x }\n')
        p = sipar.load(path)
        self.assertEqual((p.path, sorted(p.functions), [w["code"] for w in p.warnings]), (path, ["g", "main"], ["E311"]))
        self.assertEqual(p.functions["g"].name, "g")
        with self.assertRaises(sipar.CheckError) as cm:
            sipar.load(self.write(d, "e.sipar", 'allow net ["*"]\nfn main() { let x: Int = "s" }\n'))
        self.assertEqual([x["severity"] for x in cm.exception.diagnostics], ["error"])
        self.assertTrue(str(cm.exception).startswith(os.path.join(d, "e.sipar") + ":2:"), str(cm.exception))


API_M2 = ('let G = 5\nenum E { v, s(q: Str), l(xs: List[Int]) }\ntype R2 = { xs: List[Int] }\n'
          'fn g() -> Int { G }\nfn two(a: Int, b: Int) -> Int { a - b }\nfn r2(x: R2) -> Int { x.xs.len() }\n'
          'fn me(m: Map[E]) -> Int { m.len() }\nfn ml(m: Map[List[Int]]) -> Int { m.len() }\n'
          'fn e(x: E) -> E { x }\nfn ap(f: fn(Int) -> Int) -> Int { f(1) }\nfn b() -> Bool { true }\n'
          'fn bf() -> Bool { false }\nfn fl() -> Float { 1.5 }\nfn m() -> Map[Int] { ["a": 1, "b": 2] }\n'
          'fn bad() -> Int { [1][5] }\n')


class T_M_Api2(Base):
    def setUp(self):
        self.p = sipar.load(self.write(self.tmpdir(), "m2.sipar", API_M2))

    def call(self, *a, **kw):
        return self.p.call(*a, out=io.StringIO(), **kw)

    def test_results_keep_python_types(self):
        for fn, want in (("b", True), ("bf", False), ("fl", 1.5), ("m", {"a": 1, "b": 2}), ("g", 5)):
            got = self.call(fn)
            self.assertEqual((got, type(got)), (want, type(want)), fn)
        self.assertEqual(self.call("e", {"l": {"xs": (1, 2)}}), {"l": {"xs": [1, 2]}})
        self.assertEqual(self.call("e", {"tag": "l", "xs": (1, 2)}), {"l": {"xs": [1, 2]}})

    def test_tuples_inside_are_converted(self):
        self.assertEqual(self.call("r2", {"xs": (1, 2)}), 2)
        self.assertEqual(self.call("ml", {"k": (1, 2), "j": ()}), 2)
        self.assertEqual(self.call("me", {"k": {"tag": "l", "xs": (1, 2)}, "j": {"l": {"xs": (3,)}}}), 2)

    def test_call_errors(self):
        with self.assertRaises(sipar.SiparError) as cm:
            self.call("two", 1)
        self.assertEqual((cm.exception.kind, cm.exception.message), ("type", "two: missing argument 'b'"))
        with self.assertRaises(sipar.SiparError) as cm:
            self.call("ap", 1)
        self.assertEqual((cm.exception.kind, cm.exception.message), ("decode", "ap.f: cannot decode a function"))
        with self.assertRaises(sipar.SiparError) as cm:
            self.call("bad")
        e = cm.exception
        self.assertIsNone(e.__context__)
        self.assertEqual((e.kind, e.message, e.value, e.kind_value), ("index", "index 5 out of range (length 1)",
                                                                     "index 5 out of range (length 1)", "index"))

    def test_call_closes_its_journal(self):
        import gc
        import warnings
        path = os.path.join(self.tmpdir(), "j.jsonl")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self.assertEqual(self.call("g", journal=path), 5)
            gc.collect()
        self.assertEqual([x for x in w if issubclass(x.category, ResourceWarning)], [])

    def test_check_source_default_file(self):
        self.assertEqual({d["file"] for d in sipar.check_source("fn main() { x }")}, {"<input>"})

    def test_py_out_walk(self):
        from sipar.api import _py_out
        shared = [1]
        self.assertEqual(_py_out([shared, shared, {"k": shared}], "f()"), [[1], [1], {"k": [1]}])
        cyc: list = [0]
        cyc.append(cyc)
        with self.assertRaises(sipar.SiparError) as cm:
            _py_out(cyc, "f()")
        self.assertEqual((cm.exception.kind, cm.exception.message), ("value", "f()[1]: the result contains itself (a cycle)"))
        self.assertIs(_py_out(True, "f()"), True)
        self.assertIs(_py_out([False], "f()")[0], False)

    def test_py_out_depth_boundary(self):
        from sipar.api import _py_out
        from sipar.deep import call_deep
        from sipar.runtime.decode import MAX_VALUE_DEPTH

        def nested(n):
            v: list = []
            for _ in range(n):
                v = [v]
            return v
        self.assertEqual(call_deep(lambda: len(_py_out(nested(MAX_VALUE_DEPTH), "f()"))), 1)
        with self.assertRaises(sipar.SiparError) as cm:
            call_deep(_py_out, nested(MAX_VALUE_DEPTH + 1), "f()")
        self.assertEqual((cm.exception.kind, cm.exception.message),
                         ("value", f"f(): the result is nested too deeply to return to Python (more than "
                                   f"{MAX_VALUE_DEPTH:,} levels)"))

    def test_py_out_recursion_error(self):
        from sipar.api import _py_out
        v: list = []
        for _ in range(3000):
            v = [v]
        old = sys.getrecursionlimit()
        sys.setrecursionlimit(1000)
        try:
            with self.assertRaises(sipar.SiparError) as cm:
                _py_out(v, "f()")
        finally:
            sys.setrecursionlimit(old)
        self.assertEqual((cm.exception.kind, cm.exception.message),
                         ("value", "f(): the result is nested too deeply to return to Python"))


class T_M_Memory2(Base):
    def test_encode_keeps_bools(self):
        for v in (True, False, None):
            self.assertIs(MEM.encode(v)[0], v)
        self.assertEqual([type(x) for x in MEM.encode([True, 1, False])[0]], [bool, int, bool])

    def test_store_text_is_utf8_not_escaped(self):
        self.assertEqual(MEM.dump_store({"é": {"value": "ü"}}), '{"version": 1, "entries": {\n "é": {"value": "ü"}\n }}\n')

    def test_decode_recursion_error_is_io(self):
        t, tenv = types_of(self, "fn f(x: List[Int]) {}\n")
        with mock.patch.object(MEM, "from_json", side_effect=RecursionError):
            with self.assertRaises(SiparRuntimeError) as cm:
                MEM.decode({"value": [1], "enc": 2}, t["f"], tenv, "k")
        self.assertEqual((cm.exception.kind, cm.exception.message),
                         ("io", "memory.load('k'): the stored value is nested too deeply"))

    def test_open_error_messages(self):
        d = self.tmpdir()
        self.write(d, "file", "")
        p = os.path.join(d, "file", "sub", "m.json")
        with self.assertRaises(SiparRuntimeError) as cm:
            MEM.FileStore(p).put("a", {"value": 1})
        self.assertEqual((cm.exception.kind, cm.exception.message),
                         ("io", f"cannot open memory store {p}: not a directory"))

    def test_update_locks_syncs_and_closes(self):
        import fcntl
        import gc
        import warnings
        d = self.tmpdir()
        s = MEM.FileStore(os.path.join(d, "m.json"))
        sizes = []
        real_fsync = os.fsync

        def fsync(fd):
            sizes.append(os.fstat(fd).st_size)          # flushed before the sync
            real_fsync(fd)
        with warnings.catch_warnings(record=True) as w, mock.patch("fcntl.flock", wraps=fcntl.flock) as flock, \
                mock.patch("os.fsync", side_effect=fsync):
            warnings.simplefilter("always")
            s.put("a", {"value": 1})
            self.assertEqual(s.delete("a"), True)
            gc.collect()
        self.assertEqual([c.args[1] for c in flock.call_args_list], [fcntl.LOCK_EX, fcntl.LOCK_UN] * 2)
        g = "0" * 16                                    # round 7: the store's gen stamp (16 hex digits)
        self.assertEqual(sizes, [len(MEM.dump_store({"a": {"value": 1}}, g).encode()), len(MEM.dump_store({}, g).encode())])
        self.assertEqual([x for x in w if issubclass(x.category, ResourceWarning)], [])

    def test_lock_released_after_a_failed_write(self):
        import fcntl
        d = self.tmpdir()
        s = MEM.FileStore(os.path.join(d, "m.json"))
        with mock.patch("fcntl.flock", wraps=fcntl.flock) as flock, mock.patch("os.replace", side_effect=OSError("x")):
            with self.assertRaises(SiparRuntimeError):
                s.put("a", {"value": 1})
        self.assertEqual([c.args[1] for c in flock.call_args_list], [fcntl.LOCK_EX, fcntl.LOCK_UN])

    def test_secret_keys_and_values_blocked(self):
        sec = lab("k", "secret:K")
        for f, args, where in ((MEM.save, (sec, 1), "memory.save(key)"), (MEM.save, ("k", [sec]), "memory.save(value)"),
                               (MEM.load, (sec, None), "memory.load(key)"), (MEM.delete, (sec,), "memory.delete(key)")):
            with self.assertRaises(SiparRuntimeError) as cm:
                f(None, *args)
            self.assertEqual((cm.exception.kind, cm.exception.message),
                             ("taint", f"secret:K cannot flow into {where}; secrets may only be used as http header "
                                       "values"))

if __name__ == "__main__":
    unittest.main()
