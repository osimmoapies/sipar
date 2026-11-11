"""Round-8 fuzz fixes: model setup failures journaled (M1), round-6 store upgrade crash (M2), FIFOs / devices /
huge files in .sipar/memory (M3), FIFO mock script, source, pin file (L1), deep pin file (L2), journal path
wording (L3), null memory entry (L4). Each test failed before the fix unless marked
*guard*. A FIFO case runs in a subprocess with a timeout, so a regression fails instead of hanging; device
cases use /dev/null (never /dev/zero)."""

import glob
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sipar import fileread  # noqa: E402
from sipar.errors import SiparRuntimeError  # noqa: E402
from sipar.runtime import memory as MEM  # noqa: E402

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
        self.d = os.path.realpath(tempfile.mkdtemp(prefix="sipar_r8f_"))
        self.addCleanup(shutil.rmtree, self.d, True)

    def put(self, name, text):
        p = os.path.join(self.d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return p

    def journals(self):
        return sorted(glob.glob(os.path.join(self.d, ".sipar", "runs", "*.jsonl")))

    def run_replay(self, prog, **extra):
        """run (with `extra` env) then replay with NO model environment at all: (run, replay) results."""
        for j in self.journals():
            os.unlink(j)
        r = sipar(self.d, "run", prog, **extra)
        js = self.journals()
        self.assertEqual(len(js), 1, r)
        q = sipar(self.d, "replay", prog, js[0])
        return r, q, js[0]


# ====================================================================== M1
CAUGHT = """allow ai
ai fn f(x: Str) -> Str { "say {x}" }
fn main() uses ai {
    let r = try { f("a") } catch e { "ERR " + e.kind + ": " + e.message }
    print(trust(r, "t"))
}
"""
UNCAUGHT = """allow ai
ai fn f(x: Str) -> Str { "say {x}" }
fn main() uses ai {
    print(trust(f("a"), "t"))
}
"""


class T8_M1_SetupJournaled(_Dir):
    """M1: a model setup error (no model, bad chain / name, bad mock script, script naming no ai fn) was raised
    outside journal.effect: `run` printed the caught error, `replay` diverged."""

    TRIGGERS = [
        ("no SIPAR_MODEL", {}, None, "no model for f()"),
        ("mock script a string", {"SIPAR_MODEL": "mock"}, '"s"', "cannot load SIPAR_MOCK_SCRIPT"),
        ("mock script NaN", {"SIPAR_MODEL": "mock"}, "[NaN]", "NaN is not a JSON value"),
        ("script names no ai fn", {"SIPAR_MODEL": "mock"}, '{"nosuchfn": ["x"]}', "names no ai/agent fn"),
        ("unknown provider", {"SIPAR_MODEL": "nosuch/x"}, None, "unknown model provider"),
        ("no model name", {"SIPAR_MODEL": "openai"}, None, "needs a model name"),
        ("empty chain entry", {"SIPAR_MODEL": "mock | "}, None, "has an empty entry"),
        ("2nd chain model setup", {"SIPAR_MODEL": "openrouter/x | mock"}, "[NaN]", "cannot load SIPAR_MOCK"),
    ]

    def test_caught_setup_error_replays_identically_without_model_env(self):
        self.put("r.sipar", CAUGHT)
        for name, ev, script, words in self.TRIGGERS:
            with self.subTest(name):
                if script is not None:
                    self.put("s.json", script)
                    ev = dict(ev, SIPAR_MOCK_SCRIPT="s.json")
                (rc, out, err), (qrc, qout, qerr), _ = self.run_replay("r.sipar", **ev)
                self.assertEqual(rc, 0, err)
                self.assertIn("ERR ai: ", out)
                self.assertIn(words, out)
                self.assertEqual((qrc, qout), (0, out), qerr)

    def test_uncaught_setup_error_replays_the_same_error(self):
        self.put("u.sipar", UNCAUGHT)
        (rc, out, err), (qrc, qout, qerr), _ = self.run_replay("u.sipar", SIPAR_MODEL="nosuch/x")
        self.assertEqual(rc, 1)
        self.assertIn("unknown model provider", err)
        self.assertEqual(qrc, 1, qerr)
        line = [ln for ln in err.splitlines() if "error[ai]" in ln]
        self.assertEqual(line, [ln for ln in qerr.splitlines() if "error[ai]" in ln])
        self.assertNotIn("diverged", qerr)

    def test_entry_shape_and_trace_counts_no_call(self):
        self.put("r.sipar", CAUGHT)
        (rc, out, err), _, j = self.run_replay("r.sipar")
        with open(j, encoding="utf-8") as fh:
            entries = [json.loads(x) for x in fh if x.strip()]
        ai = [e for e in entries if e["kind"] == "ai"]
        self.assertEqual(len(ai), 1)
        self.assertEqual(ai[0]["meta"], {"setup": True})
        self.assertEqual(ai[0]["error"]["kind"], "ai")
        trc, tout, terr = sipar(self.d, "trace", j, "--json")
        self.assertEqual(trc, 0, terr)
        self.assertEqual(json.loads(tout)["totals"]["ai_calls"], 0)

    def test_setup_failure_does_not_use_the_ai_calls_budget(self):
        # g has no model (setup failure), f has one: with ai_calls 1, f must still run, in run and replay
        self.put("b.sipar", """allow ai
ai fn g(x: Str) -> Str { "say {x}" }
@model("mock")
ai fn f(x: Str) -> Str { "say {x}" }
fn main() uses ai {
    budget(ai_calls: 1) {
        let a = try { g("a") } catch e { "ERR" }
        print(a)
        print(trust(f("b"), "t"))
    }
}
""")
        (rc, out, err), (qrc, qout, qerr), _ = self.run_replay("b.sipar")
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.splitlines()[0], "ERR")
        self.assertEqual((qrc, qout), (0, out), qerr)

    def test_agent_setup_error_replays(self):
        self.put("a.sipar", """allow ai
/// Add.
fn add(a: Int, b: Int) -> Int { a + b }
agent fn ag(goal: Str) -> Int { tools [add]
 "Goal: {goal}" }
fn main() uses ai {
    let r = try { "{ag("x")}" } catch e { "ERR " + e.kind + ": " + e.message }
    print(trust(r, "t"))
}
""")
        (rc, out, err), (qrc, qout, qerr), _ = self.run_replay("a.sipar")
        self.assertEqual(rc, 0, err)
        self.assertIn("ERR ai: no model for ag()", out)
        self.assertEqual((qrc, qout), (0, out), qerr)

    def test_tampered_setup_entry_without_error_is_a_replay_error(self):
        self.put("r.sipar", CAUGHT)
        _, _, j = self.run_replay("r.sipar")
        with open(j, encoding="utf-8") as fh:
            entries = [json.loads(x) for x in fh if x.strip()]
        entries[0].pop("error")
        entries[0]["response"] = {"text": "hi", "usage": {"input": 1, "output": 1}}
        with open(j, "w", encoding="utf-8") as fh:
            fh.write("".join(json.dumps(e) + "\n" for e in entries))
        qrc, qout, qerr = sipar(self.d, "replay", "r.sipar", j)
        self.assertEqual(qrc, 1)
        self.assertIn("error[replay]", qerr)
        self.assertIn("must hold an error", qerr)

    def test_guard_normal_mock_call_unchanged(self):     # *guard*
        self.put("r.sipar", CAUGHT)
        (rc, out, err), (qrc, qout, qerr), j = self.run_replay("r.sipar", SIPAR_MODEL="mock")
        self.assertEqual((rc, qrc, qout), (0, 0, out))
        self.assertNotIn("ERR", out)
        with open(j, encoding="utf-8") as fh:
            self.assertNotIn('"setup"', fh.read())


# ====================================================================== M2
def r6_store(path, n=10):
    """A round-6 store (no gen) over SMALL_STORE=100 and its header-less log."""
    ents = {f"k{i}": {"value": "v" * 20 + str(i), "labels": [], "enc": 1} for i in range(n)}
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(MEM.dump_store(ents))
    with open(path + ".log", "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"k": "k1", "d": 1}) + "\n"
                 + json.dumps({"k": "new", "e": {"value": "N", "labels": [], "enc": 1}}) + "\n")


class T8_M2_UpgradeCrash(_Dir):
    """M2: a crash between os.replace (stamped store) and os.unlink(log) while upgrading a round-6 store left
    "log has an unknown format" for every later memory operation."""

    def setUp(self):
        super().setUp()
        self.p = os.path.join(self.d, "m.json")
        self.log = self.p + ".log"
        p = mock.patch.object(MEM, "SMALL_STORE", 100)
        p.start()
        self.addCleanup(p.stop)

    def values(self):
        s = MEM.FileStore(self.p)
        return {k: s.get(k)["value"] for k in s.keys()}

    def crash_upgrade(self):
        """put("z") on the round-6 store, crashing at the unlink of the log (after the store was replaced)."""
        real = os.unlink

        def unlink(p, *a, **k):
            if p == self.log:
                raise KeyboardInterrupt("crash")
            return real(p, *a, **k)

        with mock.patch.object(os, "unlink", unlink), self.assertRaises(KeyboardInterrupt):
            MEM.FileStore(self.p).put("z", {"value": "Z", "labels": [], "enc": 2})

    def test_crash_at_unlink_then_everything_still_works(self):
        r6_store(self.p)
        before = self.values()
        self.assertIn("new", before)
        self.assertNotIn("k1", before)
        self.crash_upgrade()
        self.assertTrue(os.path.exists(self.log))
        with open(self.p, encoding="utf-8") as fh:
            self.assertIn("merged", json.load(fh))
        after = self.values()                            # was: io "has an unknown format"
        self.assertEqual(after, dict(before, z="Z"))
        self.assertEqual(self.values(), after)           # a second read (cached check)
        MEM.FileStore(self.p).put("q", {"value": "Q", "labels": [], "enc": 2})
        self.assertEqual(self.values(), dict(after, q="Q"))
        MEM.FileStore(self.p).delete("new")
        exp = dict(after, q="Q")
        exp.pop("new")
        self.assertEqual(self.values(), exp)             # the old log never comes back

    def test_crash_at_unlink_small_store_rewrite_removes_log(self):
        r6_store(self.p)
        self.crash_upgrade()
        with mock.patch.object(MEM, "SMALL_STORE", 10 ** 9):   # next write rewrites the whole store
            MEM.FileStore(self.p).put("q", {"value": "Q", "labels": [], "enc": 2})
        self.assertFalse(os.path.exists(self.log))
        self.assertIn("q", self.values())
        self.assertIn("new", self.values())

    def test_other_headerless_log_is_still_an_error(self):
        r6_store(self.p)
        self.crash_upgrade()
        with open(self.log, "a", encoding="utf-8") as fh:  # not the log that was folded in any more
            fh.write(json.dumps({"k": "extra", "e": {"value": 1, "labels": []}}) + "\n")
        with self.assertRaises(SiparRuntimeError) as cm:
            self.values()
        self.assertEqual(cm.exception.kind, "io")
        self.assertIn("unknown format", cm.exception.message)

    def test_log_without_store_still_never_applied(self):    # round-7 guarantee kept after the crash too
        with open(self.log, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"k": "ghost", "e": {"value": 1, "labels": []}}) + "\n")
        real = os.unlink

        def unlink(p, *a, **k):
            if p == self.log:
                raise KeyboardInterrupt("crash")
            return real(p, *a, **k)

        with mock.patch.object(os, "unlink", unlink), self.assertRaises(KeyboardInterrupt):
            MEM.FileStore(self.p).put("a", {"value": "A", "labels": [], "enc": 2})
        self.assertEqual(self.values(), {"a": "A"})

    def test_cli_crash_at_unlink_then_run_works(self):
        mem = os.path.join(self.d, ".sipar", "memory")
        os.makedirs(mem)
        self.p = os.path.join(mem, "m.json")
        self.log = self.p + ".log"
        r6_store(self.p, n=400)                  # over the real 8 KiB
        self.put("m.sipar", 'allow memory\nfn main() uses memory {\n  memory.save("z", 1)\n'
                          '  print(memory.keys().len())\n}\n')
        crash = ("import os, sys, runpy\nreal = os.unlink\n"
                 "def unlink(p, *a, **k):\n    if p.endswith('.json.log'): os._exit(9)\n    return real(p, *a, **k)\n"
                 "os.unlink = unlink\nsys.argv = ['sipar', 'run', 'm.sipar']\n"
                 "runpy.run_module('sipar', run_name='__main__')\n")
        p = subprocess.run([sys.executable, "-c", crash], cwd=self.d, env=env(), capture_output=True, text=True,
                           timeout=30)
        self.assertEqual(p.returncode, 9, p.stderr)
        self.assertTrue(os.path.exists(self.log))
        rc, out, err = sipar(self.d, "run", "m.sipar")
        self.assertEqual((rc, out), (0, "401\n"), err)       # 400 - k1 + new + z


# ====================================================================== M3
MEMPROG = 'allow memory\nfn main() uses memory {\n  memory.save("a", 1)\n  print(memory.keys())\n}\n'


class T8_M3_OddMemoryFiles(_Dir):
    """M3: a FIFO / device / huge file as the store, log or lock hung the run or ate gigabytes."""

    def setUp(self):
        super().setUp()
        self.put("m.sipar", MEMPROG)
        self.mem = os.path.join(self.d, ".sipar", "memory")
        os.makedirs(self.mem)

    def run_err(self):
        rc, out, err = sipar(self.d, "run", "m.sipar", timeout=10)
        self.assertEqual(rc, 1, (out, err))
        return err

    def test_fifo_store_log_lock_clean_error(self):
        for name, words in (("m.json", "cannot read memory store "), ("m.json.log", "cannot read memory store log "),
                            ("m.json.lock", "cannot open memory store lock ")):
            with self.subTest(name):
                for f in os.listdir(self.mem):
                    os.unlink(os.path.join(self.mem, f))
                os.mkfifo(os.path.join(self.mem, name))
                err = self.run_err()
                self.assertIn("runtime error[io]: " + words, err)
                self.assertIn(name + ": not a regular file", err)

    def test_device_symlink_store_log_lock_clean_error(self):
        for name in ("m.json", "m.json.log", "m.json.lock"):
            with self.subTest(name):
                for f in os.listdir(self.mem):
                    os.unlink(os.path.join(self.mem, f))
                os.symlink(os.devnull, os.path.join(self.mem, name))
                err = self.run_err()
                self.assertIn(name + ": not a regular file", err)

    def test_store_too_large_is_refused(self):
        p = os.path.join(self.mem, "m.json")
        MEM.FileStore(p).put("a", {"value": "x" * 500, "labels": [], "enc": 2})
        with mock.patch.object(MEM, "MAX_FILE", 100):
            with self.assertRaises(SiparRuntimeError) as cm:
                MEM.FileStore(p).keys()
        self.assertEqual(cm.exception.kind, "io")
        self.assertIn("m.json: too large (", cm.exception.message)
        self.assertIn("it was not changed", cm.exception.message)

    def test_log_too_large_is_refused(self):
        p = os.path.join(self.mem, "m.json")
        with mock.patch.object(MEM, "SMALL_STORE", 0):
            MEM.FileStore(p).put("a", {"value": "x" * 500, "labels": [], "enc": 2})     # stamps the store
            MEM.FileStore(p).put("b", {"value": "y" * 50, "labels": [], "enc": 2})
            self.assertTrue(os.path.exists(p + ".log"))
            with mock.patch.object(MEM, "MAX_FILE", os.path.getsize(p + ".log") - 1):
                with self.assertRaises(SiparRuntimeError) as cm:
                    MEM.FileStore(p).keys()
        self.assertIn("m.json.log: too large (", cm.exception.message)

    def test_writes_never_make_a_file_too_large(self):
        p = os.path.join(self.mem, "m.json")
        with mock.patch.object(MEM, "MAX_FILE", 300):
            with self.assertRaises(SiparRuntimeError) as cm:
                MEM.FileStore(p).put("a", {"value": "x" * 400, "labels": [], "enc": 2})
            self.assertIn("would be larger than", cm.exception.message)
            self.assertFalse(os.path.exists(p))
            with mock.patch.object(MEM, "SMALL_STORE", 0):
                MEM.FileStore(p).put("a", {"value": 1, "labels": [], "enc": 2})
                with self.assertRaises(SiparRuntimeError) as cm:
                    MEM.FileStore(p).put("b", {"value": "y" * 400, "labels": [], "enc": 2})
                self.assertIn("log would be larger than", cm.exception.message)
            self.assertEqual(MEM.FileStore(p).keys(), ["a"])   # still readable, nothing half-written

    def test_guard_normal_run(self):     # *guard*
        rc, out, err = sipar(self.d, "run", "m.sipar")
        self.assertEqual((rc, out), (0, '["a"]\n'), err)


# ====================================================================== L1 / L2 / L3
class T8_L1_Fifos(_Dir):
    """L1: FIFO mock script, `sipar check <fifo>`, MCP pin file hung."""

    def test_mock_script_fifo(self):
        self.put("r.sipar", CAUGHT)
        os.mkfifo(os.path.join(self.d, "s.json"))
        rc, out, err = sipar(self.d, "run", "r.sipar", timeout=10, SIPAR_MODEL="mock", SIPAR_MOCK_SCRIPT="s.json")
        self.assertEqual(rc, 0, err)
        self.assertIn("cannot load SIPAR_MOCK_SCRIPT s.json: not a regular file", out)

    def test_mock_script_device_and_too_large(self):
        self.put("r.sipar", CAUGHT)
        rc, out, err = sipar(self.d, "run", "r.sipar", SIPAR_MODEL="mock", SIPAR_MOCK_SCRIPT=os.devnull)
        self.assertIn(f"cannot load SIPAR_MOCK_SCRIPT {os.devnull}: not a regular file", out)
        from sipar.runtime import providers as P
        p = self.put("big.json", "[" + '"x",' * 100 + '"x"]')
        with mock.patch.object(P, "MAX_FILE_BYTES", 50), self.assertRaises(SiparRuntimeError) as cm:
            P.load_script(p)
        self.assertIn("too large (", cm.exception.message)

    def test_check_named_fifo_without_writer_does_not_hang(self):
        os.mkfifo(os.path.join(self.d, "f.sipar"))
        rc, out, err = sipar(self.d, "check", "f.sipar", timeout=10)
        self.assertIn(rc, (0, 1), err)          # read as an empty program: no hang
        self.assertNotIn("Traceback", err)

    def test_check_process_substitution_pipe_works(self):   # *guard*: `sipar check <(gen.sh)` keeps working
        r, w = os.pipe()
        os.write(w, b'fn main() {\n  print("hi")\n}\n')
        os.close(w)
        try:
            p = subprocess.run([sys.executable, "-m", "sipar", "check", f"/dev/fd/{r}"], cwd=self.d, env=env(),
                               capture_output=True, text=True, timeout=10, pass_fds=(r,))
        finally:
            os.close(r)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_check_device_and_too_large_source(self):
        rc, out, err = sipar(self.d, "check", os.devnull)
        self.assertEqual(rc, 2)
        self.assertIn(f"cannot read {os.devnull}: not a regular file", err)
        from sipar import cli
        p = self.put("big.sipar", "fn main() {}\n" * 10)
        with mock.patch.object(cli, "MAX_FILE_BYTES", 20), self.assertRaises(cli.UsageError) as cm:
            cli._read(p)
        self.assertIn("too large (", str(cm.exception))

    def test_pin_file_fifo(self):
        pin = os.path.join(self.d, "p.pins.json")
        os.mkfifo(pin)
        rc, out, err = py(f"""
            from sipar.runtime.mcp import PinStore
            from sipar.errors import SiparRuntimeError
            try:
                PinStore({pin!r})
            except SiparRuntimeError as e:
                print(e.kind, e.message)
            """, self.d)
        self.assertEqual(rc, 0, err)
        self.assertIn("mcp cannot read the MCP pin file", out)
        self.assertIn("not a regular file", out)


class T8_L2_DeepPinFile(_Dir):
    """L2: a deeply nested pin file was slow (json.dump indent) and could raise RecursionError."""

    def check(self, text):
        from sipar.runtime.mcp import PinStore
        p = self.put("p.pins.json", text)
        t = time.monotonic()
        try:
            PinStore(p)
        except SiparRuntimeError as e:
            return e, time.monotonic() - t
        return None, time.monotonic() - t

    def test_deep_pin_file_is_malformed_fast(self):
        for depth in (9, 20000, 200000):
            with self.subTest(depth):
                e, dt = self.check('{"version": 1, "servers": {"s": {"t": ' + "[" * depth + "]" * depth + "}}}")
                self.assertIsNotNone(e)
                self.assertEqual(e.kind, "mcp")
                self.assertIn("is malformed", e.message)
                self.assertLess(dt, 2.0)

    def test_guard_normal_pin_file_loads(self):     # *guard*
        e, _ = self.check('{"version": 1, "servers": {"s": {"t": {"hash": "h", "first_seen": "x"}}}}')
        self.assertIsNone(e)


class T8_L3_JournalPath(_Dir):
    """L3: a FIFO or a symlink loop as the journal said "no such journal"."""

    def setUp(self):
        super().setUp()
        self.put("p.sipar", 'fn main() {\n  print("x")\n}\n')

    def test_fifo_journal(self):
        os.mkfifo(os.path.join(self.d, "j.jsonl"))
        for cmd in (("replay", "p.sipar", "j.jsonl"), ("trace", "j.jsonl")):
            with self.subTest(cmd[0]):
                rc, out, err = sipar(self.d, *cmd, timeout=10)
                self.assertEqual(rc, 2)
                self.assertIn("cannot read j.jsonl: not a regular file", err)

    def test_journal_load_fifo(self):   # Journal.load also reads `sipar test` fixtures (no CLI check before)
        os.mkfifo(os.path.join(self.d, "j.jsonl"))
        rc, out, err = py("""
            from sipar.runtime.journal import Journal
            from sipar.errors import SiparRuntimeError
            try:
                Journal.load("j.jsonl")
            except SiparRuntimeError as e:
                print(e.kind, e.message)
            """, self.d)
        self.assertEqual((rc, out), (0, "replay cannot read journal j.jsonl: not a regular file\n"), err)

    def test_symlink_loop_journal(self):
        os.symlink("b.jsonl", os.path.join(self.d, "a.jsonl"))
        os.symlink("a.jsonl", os.path.join(self.d, "b.jsonl"))
        rc, out, err = sipar(self.d, "trace", "a.jsonl")
        self.assertEqual(rc, 2)
        self.assertIn("cannot read a.jsonl: too many levels of symbolic links", err)

    def test_guard_missing_journal(self):     # *guard*
        rc, out, err = sipar(self.d, "trace", "nope.jsonl")
        self.assertEqual(rc, 2)
        self.assertIn("no such journal: nope.jsonl", err)


# ====================================================================== L4
class T8_L4_BadEntries(_Dir):
    """L4: a hand-edited entry {"a": null} was counted by keys(), loaded as none, deleted as true."""

    PROG = """allow memory
fn main() uses memory {
    print(memory.keys())
    let v: Int? = try { memory.load("a") } catch e { print("ERR " + e.kind + ": " + e.message)
        none }
    print(v)
    print(memory.delete("a"))
    print(memory.keys())
}
"""

    def store(self, entry_json):
        mem = os.path.join(self.d, ".sipar", "memory")
        os.makedirs(mem, exist_ok=True)
        with open(os.path.join(mem, "m.json"), "w", encoding="utf-8") as fh:
            fh.write('{"version": 1, "entries": {"a": ' + entry_json + "}}")

    def test_null_and_shapeless_entries_are_malformed_and_replay(self):
        self.put("m.sipar", self.PROG)
        for entry in ("null", '{"value": 1, "labels": 5}', "5", '{"labels": []}'):
            with self.subTest(entry):
                self.store(entry)
                (rc, out, err), (qrc, qout, qerr), _ = self.run_replay("m.sipar")
                self.assertEqual(rc, 0, err)
                self.assertEqual(out, '["a"]\nERR io: memory entry \'a\' is malformed\nnone\ntrue\n[]\n')
                self.assertEqual((qrc, qout), (0, out), qerr)

    def test_entry_without_labels_loads_and_replays(self):
        self.put("m.sipar", self.PROG)
        self.store('{"value": 7}')
        (rc, out, err), (qrc, qout, qerr), _ = self.run_replay("m.sipar")
        self.assertEqual(out, '["a"]\n7\ntrue\n[]\n', err)
        self.assertEqual((qrc, qout), (0, out), qerr)

    def test_memstore_null_entry(self):
        s = MEM.MemStore()
        s.entries["a"] = None
        with self.assertRaises(SiparRuntimeError) as cm:
            s.get("a")
        self.assertEqual(cm.exception.kind, "io")
        self.assertIsNone(s.get("b"))


# ====================================================================== the safe reader
class T8_SafeReader(_Dir):
    def test_open_regular(self):
        p = self.put("x.txt", "a\r\nb\rc")
        self.assertEqual(fileread.read_text(p), "a\nb\nc")
        for bad, words in ((os.devnull, "not a regular file"), (self.d, "is a directory")):
            with self.assertRaises(OSError) as cm:
                fileread.read_bytes(bad)
            self.assertEqual(fileread.why_unreadable(cm.exception), words)
        with self.assertRaises(fileread.FileRefused) as cm:
            fileread.read_bytes(p, 3)
        self.assertIn("too large (6 bytes; the limit is 3 bytes)", cm.exception.strerror)
        fifo = os.path.join(self.d, "f")
        os.mkfifo(fifo)
        with self.assertRaises(fileread.FileRefused):
            fileread.read_bytes(fifo)
        self.assertEqual(fileread.read_bytes(fifo, allow_pipe=True), b"")     # no writer: empty, no hang
        with self.assertRaises(fileread.FileRefused):
            fileread.open_regular(fifo, None, write=True)


if __name__ == "__main__":
    unittest.main()
