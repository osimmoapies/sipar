"""Round-10 fixes. Each test failed before the fix unless marked *guard*.

J1  Journal(path) used open(path, "w"): a symbolic link at the journal path was followed (the run was written
    where the link points), and a FIFO with no reader blocked the run forever
S1  a model / MCP / memory result that is a number holding a secret's digits was not labelled: print showed it
S2  a list (or map, enum payload) written at a position chosen by untrusted data (`m[k] = ["echo", "x"]`) was
    stored unlabelled, so untrusted input could pick which command shell.run got
S3  zero-padded HTML numeric references (`&#00000038;`, `&#x0000026;`) hid an echoed secret
N1  (found while merging the F6 fix) `a == b` over values that share one big part walked that part once per
    holder to look for a NaN: 1000 holders of a 200,000-item list took 22 s (1 s before F6). One walk now.
N2  *guard* the text of a list of numbers / Bool / none is what json.dumps writes (numbers no longer go through
    json one by one: 9,000,000 numbers printed in 8 s, not 20 s)
"""

import io
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sipar  # noqa: E402
from sipar.errors import SiparRuntimeError  # noqa: E402
from sipar.runtime.journal import Journal  # noqa: E402
from sipar.errors import (SecretRegistry, redact_text, register_secret, secret_labels_in,  # noqa: E402
                          use_registry)
from sipar.checker import check_source  # noqa: E402
from rt_helpers import Prog  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OK = 'allow io\nfn main() uses io { print("hi") }\n'


class T_J1(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def test_symlink_is_refused_and_target_untouched(self):
        target = os.path.join(self.d, "victim.txt")
        with open(target, "w") as f:
            f.write("keep me")
        link = os.path.join(self.d, "j.jsonl")
        os.symlink(target, link)
        with self.assertRaises(SiparRuntimeError) as cm:
            Journal(path=link)
        self.assertEqual(cm.exception.kind, "io")
        self.assertIn("symbolic link", str(cm.exception))
        with open(target) as f:
            self.assertEqual(f.read(), "keep me")

    def test_dangling_symlink_creates_nothing(self):
        target = os.path.join(self.d, "made.txt")
        link = os.path.join(self.d, "j.jsonl")
        os.symlink(target, link)
        with self.assertRaises(SiparRuntimeError):
            Journal(path=link)
        self.assertFalse(os.path.exists(target))

    def test_fifo_without_reader_does_not_hang(self):
        fifo = os.path.join(self.d, "j.jsonl")
        os.mkfifo(fifo)
        code = textwrap.dedent(f"""
            import sys; sys.path.insert(0, {ROOT!r})
            from sipar.runtime.journal import Journal
            from sipar.errors import SiparRuntimeError
            try:
                Journal(path={fifo!r})
            except SiparRuntimeError as e:
                print(e.kind, e)
        """)
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=20)
        self.assertIn("io", r.stdout)
        self.assertIn("not a regular file", r.stdout)

    def test_fifo_with_reader_is_refused(self):
        fifo = os.path.join(self.d, "j.jsonl")
        os.mkfifo(fifo)
        rfd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        try:
            with self.assertRaises(SiparRuntimeError) as cm:
                Journal(path=fifo)
            self.assertIn("not a regular file", str(cm.exception))
        finally:
            os.close(rfd)

    def test_old_journal_is_replaced(self):  # *guard*
        p = os.path.join(self.d, "j.jsonl")
        with open(p, "w") as f:
            f.write("x" * 5000 + "\n")
        j = Journal(path=p)
        j._fh.write("new\n")
        j._fh.close()
        with open(p) as f:
            self.assertEqual(f.read(), "new\n")

    def test_api_journal_symlink_refused(self):
        prog = os.path.join(self.d, "p.sipar")
        with open(prog, "w") as f:
            f.write(OK)
        target = os.path.join(self.d, "victim.txt")
        with open(target, "w") as f:
            f.write("keep me")
        link = os.path.join(self.d, "j.jsonl")
        os.symlink(target, link)
        p = sipar.load(prog)
        with self.assertRaises(sipar.SiparError) as cm:
            p.call("main", out=io.StringIO(), journal=link)
        self.assertEqual(cm.exception.kind, "io")
        with open(target) as f:
            self.assertEqual(f.read(), "keep me")

    def test_api_journal_regular_file_works(self):  # *guard*
        prog = os.path.join(self.d, "p.sipar")
        with open(prog, "w") as f:
            f.write(OK)
        jp = os.path.join(self.d, "run.jsonl")
        sipar.load(prog).call("main", out=io.StringIO(), journal=jp)
        self.assertTrue(os.path.isfile(jp) and not os.path.islink(jp))   # no effects: an empty journal


def prog(test, src):
    p = Prog(src)
    test.addCleanup(p.cleanup)
    program, d = check_source(src, p.path)
    test.assertEqual([(x.code, x.message) for x in d if x.severity == "error"], [])
    p.program = program
    return p


NUM = """allow io
allow ai
allow secret ["PIN"]
ai fn guess(q: Str) -> {T} {{ "Give a number for {{q}}" }}
fn main() uses ai, secret, io {{
  let p = env.secret("PIN")
  let n = guess("x")
  {BODY}
}}
"""


class T_S1_NumberSecret(unittest.TestCase):
    def run_num(self, t, body, reply, pin="482913"):
        p = prog(self, NUM.format(T=t, BODY=body))
        return p, p.error(script=[reply], env={"PIN": pin})

    def test_int_reply_equal_to_secret_is_not_printed(self):
        p, e = self.run_num("Int", "print(n)", "482913")
        self.assertEqual(e.kind, "taint")
        self.assertNotIn("482913", p.out + str(e))

    def test_int_reply_arithmetic_keeps_label(self):
        p, e = self.run_num("Int", 'print("{n + 1}")', "482913")
        self.assertEqual(e.kind, "taint")
        self.assertNotIn("482914", p.out)

    def test_float_reply_holding_secret_digits(self):
        p, e = self.run_num("Float", "print(n)", "482913.5")
        self.assertEqual(e.kind, "taint")

    def test_other_number_prints(self):  # *guard*
        p = prog(self, NUM.format(T="Int", BODY="print(n)"))
        self.assertEqual(p.run(script=["17"], env={"PIN": "482913"}).strip(), "17")

    def test_record_field_number(self):
        src = """allow io
allow ai
allow secret ["PIN"]
type R = { a: Int, b: Str }
ai fn guess(q: Str) -> R { "Give {q}" }
fn main() uses ai, secret, io {
  let p = env.secret("PIN")
  let r = guess("x")
  print(r.b)
  print(r.a)
}
"""
        p = prog(self, src)
        e = p.error(script=['{"a": 482913, "b": "fine"}'], env={"PIN": "482913"})
        self.assertEqual(e.kind, "taint")
        self.assertEqual(p.out.strip(), "fine")

    def test_huge_int_does_not_crash(self):  # *guard*: more digits than Python prints
        from sipar.runtime.values import mark_secrets
        with use_registry(SecretRegistry()):
            register_secret("482913", "secret:PIN")
            big = 10 ** 5000
            self.assertIs(mark_secrets(big), big)


SLOT = """allow io
allow shell ["echo"]
fn main() uses io, shell {
  let k = input("slot? ")
  BODY
}
"""


class T_S2_WrittenAtLabelledKey(unittest.TestCase):
    def go(self, body, stdin="safe\n"):
        p = prog(self, SLOT.replace("BODY", body))
        return p, p.error(stdin=io.StringIO(stdin))

    def test_list_at_untrusted_key_cannot_pick_command(self):
        p, e = self.go('var m = ["safe": ["echo", "hello"]]\n  m[k] = ["echo", "INJECTED"]\n'
                       '  print(shell.run(m["safe"].join(" ")))')
        self.assertEqual(e.kind, "taint")
        self.assertNotIn("INJECTED", p.out)

    def test_list_at_untrusted_index(self):
        p, e = self.go('var xs = [["echo", "a"], ["echo", "b"]]\n  let i = if k == "safe" { 0 } else { 1 }\n'
                       '  let j = k.len() - 4\n  xs[j] = ["echo", "INJECTED"]\n  print(shell.run(xs[0].join(" ")))')
        self.assertEqual(e.kind, "taint")

    def test_map_value_at_untrusted_key(self):
        p, e = self.go('var m = ["safe": ["c": "echo hello"]]\n  m[k] = ["c": "echo INJECTED"]\n'
                       '  print(shell.run(m["safe"]["c"]))')
        self.assertEqual(e.kind, "taint")

    def test_trusted_key_list_still_runs(self):  # *guard*
        p = prog(self, SLOT.replace("BODY", 'var m = ["safe": ["echo", "hello"]]\n  m["safe"] = ["echo", "hi"]\n'
                                            '  print(shell.run(m["safe"].join(" ")))'))
        self.assertIn("hi", p.run(stdin=io.StringIO("safe\n")))

    def test_bool_at_untrusted_key_stays_unlabelled(self):  # *guard*: choice declassification
        p = prog(self, SLOT.replace("BODY", 'var m = ["safe": false]\n  m[k] = true\n'
                                            '  if m["safe"] { print(shell.run("echo yes")) }'))
        self.assertIn("yes", p.run(stdin=io.StringIO("safe\n")))


class T_S3_ZeroPaddedEntities(unittest.TestCase):
    def setUp(self):
        cm = use_registry(SecretRegistry())
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        register_secret("tok&<9+zz", "secret:K")

    def test_zero_padded_decimal(self):
        t = "x=tok&#00000038;&#00000060;9+zz;"
        self.assertEqual(secret_labels_in(t), frozenset({"secret:K"}))
        self.assertNotIn("tok", redact_text(t))

    def test_zero_padded_hex(self):
        t = "tok&#x0000026;&#x000003C;9+zz"
        self.assertEqual(secret_labels_in(t), frozenset({"secret:K"}))
        self.assertEqual(redact_text(t), "«secret:K»")

    def test_many_zeros_fast(self):  # *guard*: no slow regex on long zero runs
        import time
        t = ("&#" + "0" * 200000 + "x") * 5
        t0 = time.time()
        secret_labels_in(t)
        self.assertLess(time.time() - t0, 2.0)


class T_N1_SharedPartsCompareOnce(unittest.TestCase):
    def test_many_holders_of_one_big_list(self):
        import time
        from sipar.runtime.values import equal
        big = list(range(200_000))
        holders = [[big] for _ in range(3000)]           # 3000 x 200,000 = 600 million looks before the fix
        a, b = list(holders), list(holders)
        t0 = time.time()
        self.assertTrue(equal(a, b))
        self.assertLess(time.time() - t0, 5.0)

    def test_nan_in_a_shared_part_is_still_found(self):
        from sipar.runtime.values import equal
        nan = float("nan")
        clean, dirty = list(range(50)), [1, [2, [nan]]]
        for order in ([[clean], [dirty]], [[dirty], [clean]], [[clean], [clean, dirty]], [[clean, [clean]], [[dirty]]]):
            a, b = list(order), list(order)
            self.assertFalse(equal(a, b), order)
        ok = [[clean], [clean, [clean]], {"k": clean}]
        self.assertTrue(equal(list(ok), list(ok)))

    def test_clean_part_inside_a_dirty_holder(self):       # a "no NaN" answer for the part must not hide the NaN
        from sipar.runtime.values import equal
        nan = float("nan")
        part = [1, 2, 3]
        first, second = [part], [part, nan]
        a, b = [first, second], [first, second]
        self.assertFalse(equal(a, b))
        self.assertTrue(equal([first, first], [first, first]))

    def test_value_holding_itself_does_not_loop(self):     # *guard*
        from sipar.runtime.values import equal
        x: list = [1]
        x.append(x)
        self.assertTrue(equal([x], [x]))


class T_N2_NumberText(unittest.TestCase):
    def test_text_is_what_json_writes(self):               # *guard*
        import json
        from sipar.runtime.values import _json_text
        for d in ([0, -1, 7, 10 ** 30, -(10 ** 30)], [True, False, None], {"a": [1, True, None, "x", 2.5]},
                  [[], {}, [[1], {"k": False}]], 5, True, False, None, -0):
            self.assertEqual(_json_text(d), json.dumps(d, ensure_ascii=False), d)

    def test_bool_is_never_written_as_a_number(self):
        from sipar.runtime.values import _json_text
        self.assertEqual(_json_text([True, 1, False, 0]), "[true, 1, false, 0]")

    def test_printed_program_values(self):                 # *guard*
        p = prog(self, 'allow io\nfn main() uses io {\n  let xs = [1, -2, 300]\n  print(xs)\n'
                       '  print([true, false])\n  let m = ["a": [1, 2]]\n  print(m)\n  print("{xs} {m}")\n'
                       '  let o: Int? = none\n  print([o])\n}\n')
        self.assertEqual(p.run().splitlines(),
                         ["[1, -2, 300]", "[true, false]", '{"a": [1, 2]}', '[1, -2, 300] {"a": [1, 2]}', "[null]"])


if __name__ == "__main__":
    unittest.main()
