"""Round-9 fuzz fixes: memory writes follow no symlink and open no FIFO (F5, F5b), a huge labels path in a stored
entry (F2), a float or bool "enc" (F6), number wording in replies (F3), one message for an empty model chain
(F4). Each test failed before the fix unless marked *guard*. A FIFO case runs in a
subprocess with a timeout, so a regression fails instead of hanging."""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sipar import fileread  # noqa: E402
from sipar.errors import SiparRuntimeError  # noqa: E402
from sipar.runtime import memory as MEM  # noqa: E402
from sipar.runtime import providers  # noqa: E402
from sipar.runtime.decode import MAX_VALUE_DEPTH  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLEAN = ("SIPAR_MODEL", "SIPAR_MOCK_SCRIPT", "SIPAR_PRICE_IN", "SIPAR_PRICE_OUT", "SIPAR_DEBUG",
         "OPENROUTER_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY")


def env(**extra):
    e = {k: v for k, v in os.environ.items() if k not in CLEAN}
    e["PYTHONPATH"] = ROOT
    e.update(extra)
    return e


def sipar(cwd, *argv, timeout=30, **extra):
    p = subprocess.run([sys.executable, "-m", "sipar", *argv], cwd=cwd, env=env(**extra), capture_output=True,
                       text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def py(code, cwd, timeout=10):
    """Run Python code in a child (a hang becomes a TimeoutExpired, i.e. a failure)."""
    p = subprocess.run([sys.executable, "-c", textwrap.dedent(code)], cwd=cwd, env=env(), capture_output=True,
                       text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


class _Dir(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp(prefix="sipar_r9f_"))
        self.addCleanup(shutil.rmtree, self.d, True)
        self.mem = os.path.join(self.d, "w", ".sipar", "memory")
        os.makedirs(self.mem)
        self.store = os.path.join(self.mem, "m.json")
        self.outside = os.path.join(self.d, "outside")
        os.makedirs(self.outside)

    def put(self, name, text):
        p = os.path.join(self.d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return p

    def big_store(self):
        """A stamped store over SMALL_STORE bytes: the next write appends to the log (as in the critic's repro)."""
        MEM.FileStore(self.store).put("big", {"value": "x" * (MEM.SMALL_STORE + 100), "labels": [], "enc": 2})
        self.assertGreater(os.path.getsize(self.store), MEM.SMALL_STORE)
        self.assertFalse(os.path.exists(self.store + ".log"))

    def outside_files(self):
        return sorted(os.listdir(self.outside))


# ====================================================================== F5
class T9_F5_NoSymlinkWrites(_Dir):
    """F5: a dangling symlink as the log (or lock) made memory.save create and write a file outside the store."""

    def test_dangling_log_symlink_cli(self):
        self.big_store()
        os.symlink(os.path.join("..", "..", "..", "outside", "created.log"), self.store + ".log")
        self.put("w/m.sipar", 'allow memory\nfn main() uses memory {\n  memory.save("a", 1)\n  print("saved")\n}\n')
        rc, out, err = sipar(os.path.join(self.d, "w"), "run", "m.sipar")
        self.assertEqual((rc, out), (1, ""), err)
        self.assertIn("runtime error[io]: cannot write memory store log ", err)
        self.assertIn("m.json.log: not a regular file (a symbolic link); delete it", err)
        self.assertEqual(self.outside_files(), [])
        self.assertTrue(os.path.islink(self.store + ".log"))

    def test_log_symlink_to_regular_file_not_written(self):
        self.big_store()
        target = os.path.join(self.outside, "real.log")
        open(target, "wb").close()
        os.symlink(target, self.store + ".log")
        with self.assertRaises(SiparRuntimeError) as cm:
            MEM.FileStore(self.store).put("a", {"value": 1, "labels": [], "enc": 2})
        self.assertEqual(cm.exception.kind, "io")
        self.assertIn("symbolic link", cm.exception.message)
        self.assertEqual(os.path.getsize(target), 0)
        self.assertEqual(MEM.FileStore(self.store).keys(), ["big"])        # the failed save did not land

    def test_dangling_lock_symlink_write_and_read(self):
        os.symlink(os.path.join(self.outside, "lock"), self.store + ".lock")
        for call in (lambda s: s.put("a", {"value": 1, "labels": [], "enc": 2}), lambda s: s.keys()):
            with self.assertRaises(SiparRuntimeError) as cm:
                call(MEM.FileStore(self.store))
            self.assertIn("cannot open memory store lock ", cm.exception.message)
            self.assertIn("m.json.lock: not a regular file (a symbolic link); delete it", cm.exception.message)
            self.assertEqual(self.outside_files(), [])

    def test_store_symlink_is_not_replaced(self):
        target = os.path.join(self.outside, "shared.json")
        MEM.FileStore(target).put("k", {"value": 1, "labels": [], "enc": 2})
        with open(target, "rb") as fh:
            before = fh.read()
        for name in os.listdir(self.outside):
            if name != "shared.json":
                os.unlink(os.path.join(self.outside, name))
        os.symlink(target, self.store)
        self.assertEqual(MEM.FileStore(self.store).keys(), ["k"])            # *guard*: reads follow it
        with self.assertRaises(SiparRuntimeError) as cm:
            MEM.FileStore(self.store).put("a", {"value": 2, "labels": [], "enc": 2})
        self.assertIn("cannot write memory store ", cm.exception.message)
        self.assertIn("m.json: not a regular file (a symbolic link); put the store file itself there",
                      cm.exception.message)
        self.assertTrue(os.path.islink(self.store))
        with open(target, "rb") as fh:
            self.assertEqual(fh.read(), before)
        self.assertEqual([f for f in os.listdir(self.mem) if f.endswith(".tmp")], [])

    def test_regular_files_still_work(self):                                # *guard*
        self.big_store()
        s = MEM.FileStore(self.store)
        s.put("a", {"value": 1, "labels": [], "enc": 2})
        s.put("b", {"value": 2, "labels": [], "enc": 2})
        self.assertTrue(stat.S_ISREG(os.lstat(self.store + ".log").st_mode))
        self.assertEqual(MEM.FileStore(self.store).keys(), ["a", "b", "big"])
        self.assertTrue(MEM.FileStore(self.store).delete("a"))
        self.assertEqual(MEM.FileStore(self.store).keys(), ["b", "big"])

    def test_open_regular_nofollow(self):
        p = os.path.join(self.d, "link")
        os.symlink(os.path.join(self.outside, "x"), p)
        with self.assertRaises(fileread.FileRefused) as cm:
            fileread.open_regular(p, None, write=True, nofollow=True)
        self.assertEqual(cm.exception.strerror, "not a regular file (a symbolic link)")
        self.assertEqual(self.outside_files(), [])
        fd = fileread.open_regular(p, None, write=True)          # *guard*: the default still follows (journal etc.)
        os.close(fd)
        self.assertEqual(self.outside_files(), ["x"])


# ====================================================================== F5b
class T9_F5b_FifoLog(_Dir):
    """F5b: a FIFO swapped in for the log between _sync and _append made the open block for ever."""

    CODE = """
        import os, sys
        sys.path.insert(0, {root!r})
        from sipar.runtime import memory as MEM
        from sipar.errors import SiparRuntimeError
        store = {store!r}
        real = MEM.FileStore._sync
        keep = []
        def sync(self):
            out = real(self)
            if os.path.exists(self.log):
                os.unlink(self.log)
            os.mkfifo(self.log)
            if {reader}:
                keep.append(os.open(self.log, os.O_RDONLY | os.O_NONBLOCK))
            return out
        MEM.FileStore._sync = sync
        try:
            MEM.FileStore(store).put("a", {{"value": 1, "labels": [], "enc": 2}})
            print("saved")
        except SiparRuntimeError as e:
            print(e.kind, e.message)
    """

    def run_child(self, reader):
        self.big_store()
        rc, out, err = py(self.CODE.format(root=ROOT, store=self.store, reader=reader), self.d, timeout=10)
        self.assertEqual(rc, 0, err)
        return out

    def test_fifo_without_reader(self):
        out = self.run_child(False)
        self.assertIn("io cannot write memory store log ", out)
        self.assertIn("m.json.log: not a regular file; delete it", out)

    def test_fifo_with_reader(self):
        out = self.run_child(True)
        self.assertIn("io cannot write memory store log ", out)
        self.assertIn("m.json.log: not a regular file; delete it", out)


# ====================================================================== F2
def load_prog(t):
    return ('allow memory\nfn get() -> %s? uses memory {\n  let v: %s? = memory.load("a")\n  return v\n}\n'
            'fn main() uses memory {\n  print(try { "{get()}" } catch e { e.kind + ": " + e.message })\n}\n' % (t, t))


class T9_F2_HugeLabelPath(_Dir):
    """F2: a labels path of 2,000,000 steps printed a 6 MB error line and wrote a 12 MB journal."""

    def write_store(self, entry):
        with open(self.store, "w", encoding="utf-8") as fh:
            json.dump({"version": MEM.VERSION, "gen": "g1", "entries": {"a": entry}}, fh)

    def run_load(self):
        self.put("w/m.sipar", load_prog("List[List[Int]]"))
        rc, out, err = sipar(os.path.join(self.d, "w"), "run", "m.sipar")
        self.assertEqual(rc, 0, err[:500])
        runs = os.path.join(self.d, "w", ".sipar", "runs")
        return out, sum(os.path.getsize(os.path.join(runs, f)) for f in os.listdir(runs))

    def test_path_over_limit_is_malformed(self):
        self.write_store({"value": [[1]], "labels": [[[0] * 300_000, ["untrusted:x"]]], "enc": 2})
        out, jsize = self.run_load()
        self.assertEqual(out, "io: memory entry 'a' is malformed\n")
        self.assertLess(jsize, 20_000)

    def test_valid_paths_boundary(self):
        lim = MEM.MAX_LABEL_PATH
        self.assertEqual(lim, MAX_VALUE_DEPTH + 1)
        self.assertTrue(MEM._valid_paths([[[0] * lim, ["l"]]]))
        self.assertFalse(MEM._valid_paths([[[0] * (lim + 1), ["l"]]]))
        self.assertTrue(MEM._valid_paths([[[], ["l"]]]))                   # *guard*: the value itself

    def test_long_path_in_message_is_clipped(self):
        self.write_store({"value": [[1]], "labels": [[[0] * 5000, ["untrusted:x"]]], "enc": 2})
        out, _ = self.run_load()
        self.assertTrue(out.startswith("decode: memory.load('a'): stored labels ['untrusted:x'] do not fit "
                                       "List[List[Int]] at [0, 0, 0"), out[:300])
        self.assertIn("... (15,000 characters)\n", out)
        self.assertLess(len(out), 400)

    def test_many_labels_in_message_are_clipped(self):
        labels = ["untrusted:%06d" % i for i in range(20_000)]
        self.write_store({"value": [[1]], "labels": [[[5], labels]], "enc": 2})
        out, _ = self.run_load()
        self.assertTrue(out.startswith("decode: memory.load('a'): stored labels ['untrusted:000000', "), out[:300])
        self.assertLess(len(out), 400)

    def test_nested_misfit_names_the_whole_path(self):
        cases = (([0, 5], "List[List[Int]]", [[1]]),            # the list step, then a bad index
                 ([0, 0, 0], "List[List[Int]]", [[1]]),         # past the leaf
                 (["a", "b"], "Map[Map[Int]]", {"a": {"x": 1}}),  # the map step, then a missing key
                 ([0, "z"], "List[R]", [{"q": 1}]))              # the list step, then a missing field
        for path, t, value in cases:
            with self.subTest(path=path):
                self.write_store({"value": value, "labels": [[path, ["untrusted:x"]]], "enc": 2})
                self.put("w/m.sipar", "type R = { q: Int }\n" + load_prog(t))
                rc, out, err = sipar(os.path.join(self.d, "w"), "run", "m.sipar")
                self.assertEqual(rc, 0, err)
                self.assertEqual(out, f"decode: memory.load('a'): stored labels ['untrusted:x'] do not fit {t} "
                                      f"at {path}\n")

    def test_short_message_unchanged(self):                                  # *guard*
        self.write_store({"value": [[1]], "labels": [[[5], ["untrusted:x"]]], "enc": 2})
        out, _ = self.run_load()
        self.assertEqual(out, "decode: memory.load('a'): stored labels ['untrusted:x'] do not fit "
                              "List[List[Int]] at [5]\n")

    def test_huge_path_rejected_by_get(self):
        with open(self.store, "w", encoding="utf-8") as fh:
            json.dump({"version": MEM.VERSION, "gen": "g1",
                       "entries": {"a": {"value": 1, "labels": [[[0] * 30_000, []]]}}}, fh)
        with self.assertRaises(SiparRuntimeError) as cm:
            MEM.FileStore(self.store).get("a")
        self.assertEqual((cm.exception.kind, cm.exception.message), ("io", "memory entry 'a' is malformed"))


# ====================================================================== F6
class T9_F6_Encoding(_Dir):
    """F6: "enc": 2.0 (and 1.0) were accepted as the integers 2 and 1."""

    def load(self, enc):
        entry = {"value": 7, "labels": []}
        if enc is not None:
            entry["enc"] = enc
        with open(self.store, "w", encoding="utf-8") as fh:
            json.dump({"version": MEM.VERSION, "gen": "g1", "entries": {"a": entry}}, fh)
        self.put("w/m.sipar", load_prog("Int"))
        rc, out, err = sipar(os.path.join(self.d, "w"), "run", "m.sipar")
        self.assertEqual(rc, 0, err)
        return out

    def test_float_and_bool_enc_rejected(self):
        for enc in (2.0, 1.0, True, False, "2", 3, 0):
            with self.subTest(enc=enc):
                self.assertEqual(self.load(enc), "io: memory entry 'a' has an unknown encoding\n")

    def test_int_enc_accepted(self):                                         # *guard*
        for enc in (1, 2, None):
            with self.subTest(enc=enc):
                self.assertEqual(self.load(enc), "7\n")


# ====================================================================== F3
AIPROG = ('allow ai\n@model("mock")\n@retries(0)\nai fn f(x: Str) -> Int { "n {x}" }\n'
          '@model("mock")\n@retries(0)\nai fn g(x: Str) -> Float { "n {x}" }\n'
          'fn main() uses ai {\n'
          '  for i in 0..{n} { print(try { "{f("a")}" } catch e { e.kind + ": " + e.message }) }\n'
          '  for i in 0..{m} { print(try { "{g("a")}" } catch e { e.kind + ": " + e.message }) }\n}\n')
PREFIX = "ai: f: the model reply did not match Int after 1 attempt(s): "
GPREFIX = "ai: g: the model reply did not match Float after 1 attempt(s): "


class T9_F3_NumberWording(_Dir):
    def run_ai(self, f, g=()):
        self.put("w/s.json", json.dumps({"f": list(f), "g": list(g)}))
        self.put("w/m.sipar", AIPROG.replace("{n}", str(len(f))).replace("{m}", str(len(g))))
        rc, out, err = sipar(os.path.join(self.d, "w"), "run", "m.sipar", SIPAR_MOCK_SCRIPT="s.json")
        self.assertEqual(rc, 0, err)
        return out.splitlines()

    def test_infinite_number_is_too_large_for_int(self):
        out = self.run_ai(["1e400", "The answer is 1e400.", "-1e400", "[1e400]", "1e19", "The answer is 1e19."])
        too = PREFIX + "$: number too large for Int"
        self.assertEqual(out[:3], [too] * 3)
        self.assertEqual(out[3], PREFIX + "$: expected Int, got array")     # *guard*
        self.assertEqual(out[4:], [too] * 2)                                  # *guard*: SPEC §9 wording

    def test_nan_for_int(self):
        self.assertEqual(self.run_ai(["NaN"]), [PREFIX + "$: expected Int, got NaN"])

    def test_fraction_still_expected_int(self):                              # *guard*: SPEC wording
        self.assertEqual(self.run_ai(["2.5", "2.0"]), [PREFIX + "$: expected Int, got number", "2"])

    def test_two_numbers_in_reply(self):
        out = self.run_ai(["answer: 12 and 13", "3 or 3", "no number here"], ["between 1.5 and 2.5"])
        self.assertEqual(out[0], PREFIX + "more than one number in the reply; expected exactly one")
        self.assertEqual(out[1], "3")                                         # *guard*: the same number twice
        self.assertEqual(out[2], PREFIX + "no JSON value found in the reply")   # *guard*
        self.assertEqual(out[3], GPREFIX + "more than one number in the reply; expected exactly one")

    def test_as_list_int(self):
        self.put("w/j.sipar", 'fn main() {\n for s in ["[1e400]", "[-1e400]", "[1e19]", "[2.5]"] {\n'
                            '  print(try { "{s as List[Int]}" } catch e { e.kind + ": " + e.message })\n }\n}\n')
        rc, out, err = sipar(os.path.join(self.d, "w"), "run", "j.sipar")
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.splitlines(), ["decode: $[0]: number too large for Int"] * 3
                         + ["decode: $[0]: expected Int, got number"])


# ====================================================================== F4
class T9_F4_EmptyChain(unittest.TestCase):
    def msg(self, spec):
        with self.assertRaises(SiparRuntimeError) as cm:
            providers.parse_chain(spec)
        self.assertEqual(cm.exception.kind, "ai")
        return cm.exception.message

    def test_all_empty_chain_says_empty_entry(self):
        for spec in (" | | ", "|", "mock | ", " | mock", "mock || mock"):
            with self.subTest(spec=spec):
                self.assertIn(f"model chain {spec.strip()!r} has an empty entry", self.msg(spec))

    def test_empty_name(self):                                               # *guard*
        for spec in ("", "   ", None):
            with self.subTest(spec=spec):
                self.assertEqual(self.msg(spec), "empty model name")

    def test_valid_chain(self):                                              # *guard*
        self.assertEqual(providers.parse_chain(" mock | mock "), ["mock", "mock"])


if __name__ == "__main__":
    unittest.main()
