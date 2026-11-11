"""Journal + replay (J1-J7), `sipar test` (X1-X4) and the CLI end to end (L1-L7)."""
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rt_helpers import CLEAN_ENV, ROOT, FakeTTY, Prog, Server, main_src

from sipar import cli
from sipar.errors import SiparRuntimeError
from sipar.runtime.journal import Journal, new_run_path

BIN = os.path.join(ROOT, "bin", "sipar")


def sh(args, cwd=None, env=None, stdin=""):
    e = {k: v for k, v in os.environ.items() if k not in CLEAN_ENV}
    e.update(env or {})
    r = subprocess.run([BIN] + args, cwd=cwd, env=e, input=stdin, capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout, r.stderr


def cli_main(args, env=None):
    out, err = io.StringIO(), io.StringIO()
    e = {k: v for k, v in os.environ.items() if k not in CLEAN_ENV}
    e.update(env or {})
    with mock.patch.dict(os.environ, e, clear=True):
        code = cli.main(args, out, err)
    return code, out.getvalue(), err.getvalue()


EFFECTS_HEAD = '''allow ai
allow net ["127.0.0.1"]
allow fs.read ["./data"]
allow shell ["mkdir"]
allow time
allow random
allow io
ai fn summary(t: Str) -> Str { "Summarise: {t}" }
'''


def effects_body(url):
    return f'''let page = http.get("{url}/ok")
let f = fs.read("data/a.txt")
let o = shell.run("mkdir made")
let t = time.now()
let r = random.int(1, 1000000)
let name = input("name? ")
let ok = approve(f, "use it?")
let tr = trust(page, "fixed test server")
print(summary(page))
print("{{f}} {{r}} {{name}} {{ok}} {{tr}}")
let miss = try {{ fs.read("data/none.txt") }} catch e {{ "missing:{{e.kind}}" }}
print(miss)'''


class JournalReplay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = Server()

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def record(self):
        p = Prog(main_src(effects_body(self.srv.url), EFFECTS_HEAD), {"data/a.txt": "AAA"})
        self.addCleanup(p.cleanup)
        jp = os.path.join(p.dir, ".sipar", "runs", "r.jsonl")
        j = Journal(path=jp)
        out = p.run(journal=j, stdin=FakeTTY("ada\ny\n"), script={"summary": ["short"]})
        j.close()
        return p, jp, out

    def test_J1_entries(self):
        p, jp, out = self.record()
        lines = [json.loads(x) for x in Path(jp).read_text(encoding="utf-8").splitlines()]
        kinds = [e["kind"] for e in lines]
        for k in ("http", "fs.read", "shell", "time", "random", "input", "approve", "trust", "ai"):
            self.assertIn(k, kinds)
        self.assertEqual([e["seq"] for e in lines], list(range(1, len(lines) + 1)))
        for e in lines:
            self.assertTrue({"seq", "kind", "request", "response", "labels"} <= set(e), e)
        http = lines[kinds.index("http")]
        self.assertEqual(http["response"], "hello from server")
        self.assertEqual(http["labels"], ["untrusted:net:127.0.0.1"])
        ai = lines[kinds.index("ai")]
        self.assertEqual(ai["meta"], {"model": "mock"})
        self.assertEqual(ai["response"]["text"], "short")
        err = [e for e in lines if e.get("error")]
        self.assertEqual(err[0]["error"]["kind"], "io")
        self.assertIn("missing:io", out)

    def test_J2_replay_is_identical_and_effect_free(self):
        p, jp, out = self.record()
        hits = len(self.srv.hits)
        os.rmdir(os.path.join(p.dir, "made"))
        os.remove(os.path.join(p.dir, "data", "a.txt"))
        r = Journal(replay=Journal.load(jp))
        out2 = p.run(journal=r, stdin=io.StringIO(""), env={"SIPAR_MODEL": ""})
        self.assertEqual(out2, out)
        self.assertEqual(r.unused(), 0)
        self.assertEqual(len(self.srv.hits), hits)                     # no HTTP request
        self.assertFalse(os.path.exists(os.path.join(p.dir, "made")))  # shell not run
        self.assertEqual(p.last.providers, {})                         # no model provider created

    def test_J3_divergence_diff(self):
        p, jp, out = self.record()
        q = Prog(main_src(effects_body(self.srv.url).replace("data/a.txt", "data/b.txt"), EFFECTS_HEAD))
        self.addCleanup(q.cleanup)
        e = q.error(journal=Journal(replay=Journal.load(jp)), stdin=io.StringIO(""))
        self.assertEqual(e.kind, "replay")
        self.assertIn("#2", e.message)
        self.assertIn("path", e.message)
        q2 = Prog(main_src(effects_body(self.srv.url).replace('time.now()', 'random.int(1, 2)'), EFFECTS_HEAD))
        self.addCleanup(q2.cleanup)
        e = q2.error(journal=Journal(replay=Journal.load(jp)), stdin=io.StringIO(""))
        self.assertIn("journal has time {}, program performs random", e.message)

    def test_J3_replay_error_not_catchable(self):
        p = Prog(main_src('let v = try { time.now() } catch e { 0.0 }\nprint(v)', 'allow time'))
        self.addCleanup(p.cleanup)
        bad = [{"seq": 1, "kind": "random", "request": {}, "response": 1}]
        self.assertEqual(p.error(journal=Journal(replay=bad)).kind, "replay")

    def test_J4_exhausted_and_unused(self):
        p = Prog('allow time\nfn main() uses time {\nprint(time.now() > 0.0)\nprint(time.now() > 0.0)\n}\n')
        self.addCleanup(p.cleanup)
        one = [{"seq": 1, "kind": "time", "request": {}, "response": 5.0, "labels": []}]
        e = p.error(journal=Journal(replay=list(one)))
        self.assertEqual(e.kind, "replay")
        self.assertIn("no more entries", e.message)
        jp = os.path.join(p.dir, "j.jsonl")
        with open(jp, "w") as fh:
            for i in range(3):
                fh.write(json.dumps(dict(one[0], seq=i + 1)) + "\n")
        code, out, err = cli_main(["replay", p.path, jp])
        self.assertEqual(code, 1)
        self.assertIn("1 entr(ies) of journal", err)                     # round 4 (C13): names the journal
        self.assertIn("were not used", err)

    def test_J5_error_entry_reraised(self):
        p = Prog(main_src('print(fs.read("data/x.txt"))', 'allow fs.read ["./data"]'), {"data/x.txt": "x"})
        self.addCleanup(p.cleanup)
        j = [{"seq": 1, "kind": "fs.read", "request": {"path": "data/x.txt"}, "response": None, "labels": [],
              "error": {"kind": "io", "message": "gone"}}]
        e = p.error(journal=Journal(replay=j))
        self.assertEqual((e.kind, e.message), ("io", "gone"))

    def test_J6_corrupt_journal(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        jp = os.path.join(d, "j.jsonl")
        with open(jp, "w") as fh:
            fh.write('{"seq": 1, "kind": "time.now", "request": {}}\n{not json\n')
        with self.assertRaises(SiparRuntimeError) as cm:
            Journal.load(jp)
        self.assertEqual(cm.exception.kind, "replay")
        self.assertIn("line 2", cm.exception.message)
        with open(jp, "w") as fh:
            fh.write('[1, 2]\n')
        with self.assertRaises(SiparRuntimeError):
            Journal.load(jp)

    def test_J7_distinct_paths(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        f = os.path.join(d, "p.sipar")
        paths = set()
        for _ in range(5):
            pth = new_run_path(f)
            os.makedirs(os.path.dirname(pth), exist_ok=True)
            open(pth, "w").close()
            paths.add(pth)
        self.assertEqual(len(paths), 5)
        self.assertTrue(all(x.startswith(os.path.join(d, ".sipar", "runs")) for x in paths))

    def test_secret_replay_rereads_and_checks(self):
        p = Prog(main_src('let k = env.secret("TOK")\nprint(k == "abcdefgh")', 'allow secret ["TOK"]'))
        self.addCleanup(p.cleanup)
        j = Journal()
        self.assertEqual(p.run(journal=j, env={"TOK": "abcdefgh"}), "true\n")
        r = Journal(replay=json.loads(json.dumps(j.entries)))
        self.assertNotIn("abcdefgh", json.dumps(j.entries))
        self.assertEqual(p.run(journal=r, env={"TOK": "abcdefgh"}), "true\n")   # re-read from the env
        with self.assertRaises(SiparRuntimeError) as cm:          # a different value is refused (SPEC §7)
            p.run(journal=Journal(replay=json.loads(json.dumps(j.entries))), env={"TOK": ""})
        self.assertEqual(cm.exception.kind, "replay")


TESTS_SRC = '''allow ai
type Review = { score: Int, verdict: Str }
ai fn review(code: Str) -> Review { "Review: {code}" }
fn grade(code: Str) -> Str uses ai { if review(code).score > 5 { "good" } else { "bad" } }
test "mocked" {
    mock review(code) => Review { score: 9, verdict: "ok {code}" }
    assert grade("x") == "good", "mock used"
    assert review("y").verdict == "ok y", "param bound"
}
test "unmocked" {
    assert grade("x") == "bad", "needs a model"
}
'''


class TestCommand(unittest.TestCase):
    def prog(self, src=TESTS_SRC):
        p = Prog(src)
        self.addCleanup(p.cleanup)
        return p

    def test_X1_X2_mock_scope_and_unmocked(self):
        p = self.prog()
        passed, failed, out = p.test()
        self.assertEqual((passed, failed), (1, 1))
        self.assertIn("PASS mocked", out)
        self.assertIn("FAIL unmocked", out)
        self.assertIn("unmocked call to ai fn review()", out)
        self.assertTrue(out.endswith("1 passed, 1 failed\n"))

    def test_X2_live(self):
        p = self.prog()
        passed, failed, out = p.test(live=True, script={"review": [{"score": 1, "verdict": "meh"}]})
        self.assertEqual((passed, failed), (2, 0), out)
        self.assertFalse(os.path.exists(os.path.join(p.dir, ".sipar", "fixtures")))

    def test_X3_record_then_replay_offline(self):
        p = self.prog()
        passed, failed, out = p.test(record=True, script={"review": [{"score": 2, "verdict": "meh"}]})
        self.assertEqual((passed, failed), (2, 0), out)
        fx = os.path.join(p.dir, ".sipar", "fixtures")
        files = sorted(os.listdir(fx))
        self.assertEqual(len(files), 2)
        unm = [f for f in files if "unmocked" in f][0]
        entries = [json.loads(x) for x in Path(fx, unm).read_text().splitlines()]
        self.assertEqual(entries[0]["kind"], "ai")
        passed, failed, out = p.test(env={"SIPAR_MODEL": ""})         # offline: served from the fixture
        self.assertEqual((passed, failed), (2, 0), out)
        q = Prog(TESTS_SRC.replace("Review: {code}", "Rate: {code}"))
        self.addCleanup(q.cleanup)
        os.makedirs(os.path.join(q.dir, ".sipar"))
        shutil.copytree(fx, os.path.join(q.dir, ".sipar", "fixtures"))
        passed, failed, out = q.test()
        self.assertEqual(failed, 1)
        self.assertIn("replay diverged", out)

    def test_X3_failed_recording_leaves_no_fixture(self):
        p = self.prog()
        passed, failed, out = p.test(record=True, script={"review": [{"score": 9, "verdict": "x"}]})
        self.assertEqual(failed, 1)
        fx = os.path.join(p.dir, ".sipar", "fixtures")
        self.assertFalse([f for f in (os.listdir(fx) if os.path.isdir(fx) else []) if "unmocked" in f])

    def test_X4_counts_and_exit_codes(self):
        p = self.prog('fn main() { }\n')
        self.assertEqual(p.test(), (0, 0, "0 passed, 0 failed\n"))
        q = self.prog('test "a" { assert 1 == 1, "x" }\ntest "b" { assert 1 == 2, "nope" }\n'
                      'test "c" { let x = [1][5] }\n')
        passed, failed, out = q.test()
        self.assertEqual((passed, failed), (1, 2))
        self.assertIn("nope", out)
        code, o, e = cli_main(["test", q.path])
        self.assertEqual(code, 1)
        self.assertIn("1 passed, 2 failed", o)
        r = self.prog('test "a" { assert true, "x" }\n')
        self.assertEqual(cli_main(["test", r.path])[0], 0)

    def test_mock_outside_test_rejected(self):
        p = self.prog('allow ai\nai fn f() -> Int { "x" }\nfn main() uses ai {\nmock f() => 1\n}\n')
        with mock.patch("sipar.cli._checker", lambda: None):
            code, out, err = cli_main(["run", p.path])
        self.assertEqual(code, 1)
        self.assertIn("mock", err)


class CLI(unittest.TestCase):
    def tmp(self, name="p.sipar", src="fn main() { print(\"hi\") }\n"):
        d = tempfile.mkdtemp(prefix="sipar cli ")
        self.addCleanup(shutil.rmtree, d)
        path = os.path.join(d, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(src)
        return d, path

    def test_L1_usage(self):
        self.assertEqual(sh([])[0], 2)
        self.assertEqual(sh(["frobnicate"])[0], 2)
        code, out, err = sh(["run", "/nonexistent/x.sipar"])
        self.assertEqual(code, 2)
        self.assertIn("no such file", err)
        code, out, err = sh(["replay", "/nonexistent/x.sipar"])
        self.assertEqual(code, 2)
        d, path = self.tmp()
        code, out, err = sh(["replay", path, os.path.join(d, "none.jsonl")])
        self.assertEqual(code, 2)
        self.assertIn("no such journal", err)

    def test_L2_syntax_error(self):
        d, path = self.tmp(src="fn main() { let = }\n")
        code, out, err = sh(["run", path])
        self.assertEqual(code, 1)
        self.assertIn("p.sipar:1", out + err)
        self.assertNotIn("Traceback", err)
        code, out, err = sh(["check", "--json", path])
        self.assertEqual(code, 1)
        diags = json.loads(out)
        self.assertEqual(diags[0]["severity"], "error")

    def test_L3_checker_gate(self):
        class D:
            severity = "error"

            def render(self, src):
                return "p.sipar:1:1: error: fake checker error"

        d, path = self.tmp(src='allow shell ["touch"]\nfn main() uses shell { shell.run("touch ran") }\n')
        with mock.patch("sipar.cli._checker", lambda: (lambda src, f: (object(), [D()]))):
            for cmd in (["run", path], ["test", path], ["replay", path, path]):
                code, out, err = cli_main(cmd)
                self.assertEqual(code, 1, cmd)
                self.assertIn("not running", err)
        self.assertFalse(os.path.exists(os.path.join(d, "ran")))

    def test_L4_spec_lists_stdlib(self):
        from sipar.stdlib import FUNCTIONS, METHODS
        code, out, err = sh(["spec"])
        self.assertEqual(code, 0)
        for name in FUNCTIONS:
            self.assertIn(f"  {name}(", out)
        for ms in METHODS.values():
            for name in ms:
                self.assertIn(f"  .{name}(", out)

    def test_L5_version(self):
        code, out, err = sh(["--version"])
        self.assertEqual((code, out.strip()), (0, "sipar 0.1.1"))

    def test_L6_paths_and_cwd(self):
        d, path = self.tmp(name="тест файл.sipar", src='fn main(args: List[Str]) { print("hi {args}") }\n')
        code, out, err = sh(["run", path, "a b", "--x"], cwd="/")
        self.assertEqual((code, out), (0, 'hi ["a b", "--x"]\n'), err)
        runs = os.listdir(os.path.join(d, ".sipar", "runs"))
        self.assertEqual(len(runs), 1)
        code, out2, err = sh(["replay", path, os.path.join(d, ".sipar", "runs", runs[0])], cwd="/")
        self.assertEqual((code, out2), (0, out), err)

    def test_L7_tour(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        tour = os.path.join(d, "tour.sipar")
        shutil.copy(os.path.join(ROOT, "examples", "tour.sipar"), tour)
        code, out, err = sh(["run", tour], env={"SIPAR_MODEL": "mock"})
        self.assertEqual(code, 0, err)
        self.assertTrue(out.strip())
        self.assertEqual(sh(["test", tour])[0], 0)
        code, out, err = sh(["run", tour])
        self.assertEqual(code, 1)
        self.assertIn("runtime error[ai]", err)
        self.assertIn("journal: ", err)
        self.assertNotIn("Traceback", err)

    def test_runtime_error_exit_and_no_traceback(self):
        d, path = self.tmp(src='fn main() { let xs = [1]\nprint(xs[3]) }\n')
        code, out, err = sh(["run", path])
        self.assertEqual(code, 1)
        self.assertIn("p.sipar:2", err)
        self.assertNotIn("Traceback", err)

    def test_internal_error_hidden_unless_debug(self):
        d, path = self.tmp()
        with mock.patch.dict(cli.COMMANDS, {"run": mock.Mock(side_effect=ZeroDivisionError("x"))}):
            code, out, err = cli_main(["run", path])
            self.assertEqual(code, 1)
            self.assertIn("internal error (ZeroDivisionError)", err)
            self.assertNotIn("Traceback", err)
            code, out, err = cli_main(["run", path], env={"SIPAR_DEBUG": "1"})
            self.assertIn("Traceback", err)


if __name__ == "__main__":
    unittest.main()
