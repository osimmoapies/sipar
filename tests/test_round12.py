"""Round 12: a value picked with a labelled argument keeps the labels (SPEC §6, selection). random.int(lo, hi)
dropped the labels of its bounds, so a number a model chose came back from random.int(n, n) unlabelled and
reached shell.run / fs.write; env.get(name) and env.secret(name) dropped the labels of a model-chosen name."""
import os
import unittest
from unittest import mock

from rt_helpers import Prog
from test_runtime_effects import Rt

from sipar.runtime import effects as E
from sipar.runtime.values import labels_of, set_labels

U = frozenset({"untrusted:ai:gen"})
HEAD = ('allow ai\nallow io\nallow random\nallow shell ["echo"]\nallow fs.write ["out"]\n'
        'allow env ["SIPAR_T12", "SIPAR_NONE12"]\n'
        'ai fn pick(q: Str) -> Int { "{q}" }\nai fn txt(q: Str) -> Str { "{q}" }\n')


class Base(unittest.TestCase):
    def prog(self, body):
        p = Prog(HEAD + f'fn main() uses ai, io, random, shell, fs.write, env {{\n{body}\n}}\n')
        self.addCleanup(p.cleanup)
        return p

    def blocked(self, body, where, src, **kw):
        e = self.prog(body).error(**kw)
        self.assertEqual(e.kind, "taint")
        self.assertIn(f"untrusted data (untrusted:ai:{src}) cannot flow into {where}", str(e))


class T_RandomInt(Base):
    def test_same_bounds_to_shell(self):
        self.blocked('let n = pick("n")\nlet m = random.int(n, n)\nprint(shell.run("echo " + (m as Str)))',
                     "shell.run(cmd)", "pick", script={"pick": [4471]})

    def test_same_bounds_to_file_path(self):
        self.blocked('let n = pick("n")\nlet m = random.int(n, n)\nfs.write("out/" + (m as Str) + ".txt", "x")',
                     "fs.write(path)", "pick", script={"pick": [4471]})

    def test_labelled_lo_only(self):
        self.blocked('let n = pick("n")\nlet m = random.int(n, 9)\nprint(shell.run("echo " + (m as Str)))',
                     "shell.run(cmd)", "pick", script={"pick": [9]})

    def test_labelled_hi_only(self):
        self.blocked('let n = pick("n")\nlet m = random.int(3, n)\nprint(shell.run("echo " + (m as Str)))',
                     "shell.run(cmd)", "pick", script={"pick": [3]})

    def test_plain_bounds_stay_unlabelled(self):
        out = self.prog('let m = random.int(7, 7)\nprint(shell.run("echo " + (m as Str)))').run()
        self.assertEqual(out.strip(), "7")

    def test_value_is_still_in_range_and_checked(self):
        out = self.prog('let n = pick("n")\nlet m = random.int(n, n)\nprint(m == 4471)').run(script={"pick": [4471]})
        self.assertEqual(out.strip(), "true")
        e = self.prog('let n = pick("n")\nprint(random.int(n, 1) == 1)').error(script={"pick": [5]})
        self.assertEqual(e.kind, "value")
        self.assertIn("random.int: lo (5) > hi (1)", str(e))

    def test_unit_labels(self):
        rt = Rt("allow random")
        self.assertEqual(labels_of(E.random_int(rt, set_labels(4, U), set_labels(4, U))), U)
        self.assertEqual(labels_of(E.random_int(rt, 4, 4)), frozenset())


class T_EnvName(Base):
    def test_model_chosen_name_to_shell(self):
        self.blocked('let s = txt("s")\nlet v = env.get(s) ?? "none"\nprint(shell.run("echo " + v))',
                     "shell.run(cmd)", "txt", script={"txt": ["SIPAR_T12"]}, env={"SIPAR_T12": "picked"})

    def test_literal_name_passes_as_before(self):
        out = self.prog('let v = env.get("SIPAR_T12") ?? "none"\nprint(shell.run("echo " + v))').run(
            env={"SIPAR_T12": "plain"})
        self.assertEqual(out.strip(), "plain")

    def test_missing_variable_is_plain_none(self):
        out = self.prog('let s = txt("s")\nlet v = env.get(s) ?? "none"\nprint(shell.run("echo " + v))').run(
            script={"txt": ["SIPAR_NONE12"]})
        self.assertEqual(out.strip(), "none")

    def test_unit_env_get_labels(self):
        rt = Rt('allow env ["SIPAR_T12", "SIPAR_NONE12"]')
        with mock.patch.dict(os.environ, {"SIPAR_T12": "value"}):
            os.environ.pop("SIPAR_NONE12", None)
            self.assertEqual(labels_of(E.env_get(rt, set_labels("SIPAR_T12", U))), U)
            self.assertEqual(labels_of(E.env_get(rt, "SIPAR_T12")), frozenset())
            self.assertIsNone(E.env_get(rt, set_labels("SIPAR_NONE12", U)))

    def test_unit_env_secret_keeps_both_labels(self):
        rt = Rt('allow secret ["SIPAR_TOK12"]')
        with mock.patch.dict(os.environ, {"SIPAR_TOK12": "s3cr3t-value-12"}):
            self.assertEqual(labels_of(E.env_secret(rt, set_labels("SIPAR_TOK12", U))),
                             U | {"secret:SIPAR_TOK12"})
            self.assertEqual(labels_of(E.env_secret(rt, "SIPAR_TOK12")), frozenset({"secret:SIPAR_TOK12"}))


if __name__ == "__main__":
    unittest.main()
