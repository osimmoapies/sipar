"""Round-9 CLI / API fixes. Each test failed before the fix unless marked *guard*.

M1  sipar.load() read with plain open(): a FIFO hung, /dev/zero filled memory, /dev/null loaded, no size limit
M2  a closed stdout (`sipar run x >&-`) was "internal error (AttributeError)", exit 1 (SPEC §9: exit 141)
M3  a closed or broken stderr changed the exit code (usage error 2 became 1)
M4  `sipar run <(cmd)` / `cat x | sipar run /dev/stdin` put .sipar/ in /dev/fd/ (cannot write journal)
F4  `sipar run DIR` said "DIR is a directory"; every other reader says "cannot read DIR: is a directory"
M5  tests/test_round6.py failed when the suite started with SIGINT / SIGHUP ignored (fixed there; checked here)
L1  no test that an `Int?` parameter rejects a bool from Python (mutant `x is None` -> `x is True` survived)
L2  the SPEC §10 example called a function `add` that triage.sipar does not have
L3  SPEC §10 said `journal` must be a str, but os.PathLike is accepted
L4  journal="j\\ud800.jsonl" / "j\\0.jsonl" raised a raw UnicodeEncodeError / "embedded null byte"
L5  journal="afile/j.jsonl" with `afile` a file said "file exists"
"""

import io
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sipar  # noqa: E402
from sipar import cli as CLI  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OK = 'allow io\nfn main() uses io { print("hi") }\n'


def spec_text():
    with open(os.path.join(ROOT, "SPEC.md"), encoding="utf-8") as f:
        return f.read()


def env():
    e = {k: v for k, v in os.environ.items() if not k.startswith("SIPAR_")}
    e.update({"PYTHONPATH": ROOT, "SIPAR_MODEL": "mock"})
    return e


def sh(script, *args, cwd, inp=None, timeout=60, **kw):
    """Run `sipar` through sh (for >&-, 2>&-, <(...)); returns (rc, stdout, stderr)."""
    p = subprocess.run(["bash", "-c", script, "sh", sys.executable, *args], cwd=cwd, env=env(), input=inp,
                       capture_output=True, timeout=timeout, **kw)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


class Tmp(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp(prefix="sipar_r9c_"))
        self.addCleanup(shutil.rmtree, self.d, True)

    def put(self, name, text):
        p = os.path.join(self.d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p

    def runs(self, base=None):
        d = os.path.join(base or self.d, ".sipar", "runs")
        return sorted(os.path.join(d, n) for n in os.listdir(d)) if os.path.isdir(d) else []


# ====================================================================== M1. sipar.load reads safely
class T_M1_Load(Tmp):
    def test_device_is_an_io_error(self):
        with self.assertRaises(sipar.SiparError) as cm:         # was: a Program with no functions
            sipar.load(os.devnull)
        self.assertEqual((cm.exception.kind, cm.exception.message), ("io", f"cannot read {os.devnull}: not a regular file"))
        self.assertIsNone(cm.exception.__context__)

    def test_too_large_is_an_io_error(self):
        p = os.path.join(self.d, "big.sipar")
        with open(p, "wb") as f:
            f.truncate(256 * 1024 * 1024 + 1)                   # sparse: no real 256 MB written
        with self.assertRaises(sipar.SiparError) as cm:         # was: read it all, then a CheckError
            sipar.load(p)
        self.assertEqual(cm.exception.kind, "io")
        self.assertIn("too large (268,435,457 bytes; the limit is 256 MB)", cm.exception.message)

    def test_fifo_without_writer_does_not_hang(self):
        fifo = os.path.join(self.d, "f.sipar")
        os.mkfifo(fifo)
        code = "import sipar,sys; p = sipar.load(sys.argv[1]); print(sorted(p.functions))"
        r = subprocess.run([sys.executable, "-c", code, fifo], env=env(), capture_output=True, text=True, timeout=30)
        self.assertEqual((r.returncode, r.stdout), (0, "[]\n"))         # was: hung (like `sipar check`: empty)

    def test_dev_zero_does_not_fill_memory(self):
        code = ("import sipar\ntry:\n    sipar.load('/dev/zero')\nexcept sipar.SiparError as e:\n"
                "    print(e.kind, e.message)\n")
        r = subprocess.run([sys.executable, "-c", code], env=env(), capture_output=True, text=True, timeout=30)
        self.assertEqual(r.stdout, "io cannot read /dev/zero: not a regular file\n")

    def test_pipe_and_pathlike_and_missing(self):                  # guard
        p = self.put("ok.sipar", OK)
        self.assertEqual(sorted(sipar.load(pathlib.Path(p)).functions), ["main"])
        r = subprocess.run(["bash", "-c", '"$1" -c "import sipar,sys; print(sorted(sipar.load(sys.argv[1]).functions))" '
                            '<(cat "$2")', "sh", sys.executable, p], env=env(), capture_output=True, text=True, timeout=30)
        self.assertEqual(r.stdout, "['main']\n")
        with self.assertRaises(FileNotFoundError):              # SPEC §10: a missing file is the usual OSError
            sipar.load(os.path.join(self.d, "missing.sipar"))
        with self.assertRaises(IsADirectoryError):
            sipar.load(self.d)


# ====================================================================== M2 / M3. closed standard streams
CMDS = (["run", "ok.sipar"], ["check", "ok.sipar"], ["check", "--json", "ok.sipar"], ["check", "--json", "bad.sipar"],
        ["spec"], ["test", "t.sipar"], ["trace", "j.jsonl"], ["trace", "--json", "j.jsonl"], ["--version"],
        ["--help"], ["lsp"])


class T_M2_ClosedStdout(Tmp):
    def setUp(self):
        super().setUp()
        self.put("ok.sipar", OK)
        self.put("bad.sipar", "fn main() { x }\n")
        self.put("t.sipar", 'fn f() -> Int { 1 }\ntest "t" { assert f() == 1 }\n')
        self.put("j.jsonl", "")

    def test_every_command_exits_141_quietly(self):
        for argv in CMDS:
            with self.subTest(argv=argv):
                rc, out, err = sh('"$1" -m sipar "${@:2}" >&-', *argv, cwd=self.d)
                self.assertEqual((rc, err), (141, ""))         # was: internal error (AttributeError), exit 1

    def test_closed_stdout_holds_fd_1(self):
        code = ("import os, sys\nfrom sipar import cli\ncli._closed_streams()\nos.fstat(1)\n"
                "fd = os.open(os.devnull, os.O_RDONLY)\nsys.stderr.write(f'{fd >= 3} {type(sys.stdout).__name__}')\n")
        rc, out, err = sh('"$1" -c "$2" >&-', code, cwd=self.d)
        self.assertEqual((rc, err), (0, "True _ClosedOut"))

    def test_closed_stdin_reads_as_empty(self):
        rc, out, err = sh('"$1" -m sipar run ok.sipar <&-', cwd=self.d)
        self.assertEqual((rc, out, err), (0, "hi\n", ""))
        rc, out, err = sh('"$1" -m sipar lsp <&-', cwd=self.d)       # end of input before `exit`: 1 (SPEC §9)
        self.assertEqual((rc, out), (1, ""))
        self.assertNotIn("internal error", err)                 # was: internal error (AttributeError)


class T_M3_ClosedStderr(Tmp):
    def setUp(self):
        super().setUp()
        self.put("ok.sipar", OK)
        self.put("bad.sipar", "fn main() { x }\n")

    def test_exit_codes_do_not_depend_on_stderr(self):
        for argv, code in ((["run", "nofile.sipar"], 2), (["check", "a", "b"], 2), (["check", "bad.sipar"], 1),
                           (["run", "bad.sipar"], 1), (["run", "ok.sipar"], 0), (["trace", "nope.jsonl"], 2), ([], 2)):
            with self.subTest(argv=argv):
                open_rc = sh('"$1" -m sipar "${@:2}"', *argv, cwd=self.d)[0]
                self.assertEqual(open_rc, code)
                self.assertEqual(sh('"$1" -m sipar "${@:2}" 2>&-', *argv, cwd=self.d)[0], code)   # was: 1
                self.assertEqual(sh('"$1" -m sipar "${@:2}" >&- 2>&-', *argv, cwd=self.d)[0],
                                 141 if argv == ["run", "ok.sipar"] or argv == ["check", "bad.sipar"] else code)

    def test_broken_stderr_pipe(self):
        r, w = os.pipe()
        os.close(r)                                             # the reader of stderr is gone
        try:
            p = subprocess.run([sys.executable, "-m", "sipar", "run", "nofile.sipar"], cwd=self.d, env=env(),
                               stdout=subprocess.PIPE, stderr=w, timeout=30)
        finally:
            os.close(w)
        self.assertEqual(p.returncode, 2)                       # was: 1 with a traceback (BrokenPipeError)

    def test_stderr_closed_journal_stays_clean(self):              # guard: no message lands in the journal
        self.put("f.sipar", 'allow io\nfn main() uses io {\n print("a")\n fail("value", "boom")\n}\n')
        rc, out, err = sh('"$1" -m sipar run f.sipar 2>&-', cwd=self.d)
        self.assertEqual((rc, out), (1, "a\n"))
        (j,) = self.runs()
        with open(j, encoding="utf-8") as f:
            for line in f:
                json.loads(line)


# ====================================================================== M4. a program read from a pipe
class T_M4_PipeProgram(Tmp):
    def test_process_substitution(self):
        src = self.put("src/ok.sipar", OK)
        rc, out, err = sh('"$1" -m sipar run <(cat "$2")', src, cwd=self.d)
        self.assertEqual((rc, out, err), (0, "hi\n", ""))       # was: cannot write journal /dev/fd/.sipar/...
        (j,) = self.runs()                                      # in the current folder, not next to src/
        self.assertEqual(self.runs(os.path.join(self.d, "src")), [])
        copy = self.put("copy.sipar", OK)
        rc, out, err = sh('"$1" -m sipar replay "$2" "$3"', copy, j, cwd=self.d)
        self.assertEqual((rc, out, err), (0, "hi\n", ""))

    def test_dev_stdin(self):
        r = subprocess.run([sys.executable, "-m", "sipar", "run", "/dev/stdin"], cwd=self.d, env=env(),
                           input=OK.encode(), capture_output=True, timeout=30)
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, b"hi\n", b""))  # was: permission denied /dev/.sipar
        self.assertEqual(len(self.runs()), 1)

    def test_memory_and_relative_fs_follow_the_current_folder(self):
        self.put("data/x.txt", "from-cwd")
        src = ('allow io\nallow memory\nallow fs.read ["./data"]\nfn main() uses io, memory, fs.read {\n'
               ' memory.save("k", 7)\n print(fs.read("data/x.txt"))\n}\n')
        r = subprocess.run([sys.executable, "-m", "sipar", "run", "/dev/stdin"], cwd=self.d, env=env(),
                           input=src.encode(), capture_output=True, timeout=30)
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, b"from-cwd\n", b""))
        with open(os.path.join(self.d, ".sipar", "memory", "stdin.json"), encoding="utf-8") as f:
            self.assertIn('"k"', f.read())

    def test_program_dir(self):
        from sipar.fileread import program_dir
        p = self.put("sub/a.sipar", OK)
        self.assertEqual(program_dir(p), os.path.join(self.d, "sub"))
        self.assertEqual(program_dir(os.path.join(self.d, "sub", "missing.sipar")), os.path.join(self.d, "sub"))
        fifo = os.path.join(self.d, "sub", "f.sipar")
        os.mkfifo(fifo)
        self.assertEqual(program_dir(fifo), os.getcwd())
        from sipar.runtime import journal as J, mcp as MCP, memory as MEM
        cwd = os.getcwd()
        self.assertEqual(MEM.store_path(fifo), os.path.join(cwd, ".sipar", "memory", "f.json"))
        self.assertEqual(MCP.pin_path(fifo), os.path.join(cwd, ".sipar", "mcp", "f.pins.json"))
        self.assertEqual(os.path.dirname(J.new_run_path(fifo)), os.path.join(cwd, ".sipar", "runs"))
        self.assertEqual(MCP.pin_path(p), os.path.join(self.d, "sub", ".sipar", "mcp", "a.pins.json"))  # guard
        link = os.path.join(self.d, "link.sipar")
        os.symlink(p, link)
        self.assertEqual(program_dir(link), self.d)           # guard: a symlink keeps its own folder

    def test_test_fixtures_follow_the_current_folder(self):
        src = 'allow ai\nai fn f(x: Str) -> Str { "say {x}" }\ntest "t" { assert f("a") == "ok" }\n'
        r = subprocess.run([sys.executable, "-m", "sipar", "test", "--record", "/dev/stdin"], cwd=self.d,
                           env=dict(env(), SIPAR_MOCK_SCRIPT=self.put("m.json", '["ok"]')), input=src.encode(),
                           capture_output=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(os.listdir(os.path.join(self.d, ".sipar", "fixtures")))     # was: in /dev/.sipar/


# ====================================================================== F4. a directory as the program
class T_F4_Directory(Tmp):
    def test_run_and_check_a_directory(self):
        for cmd in ("run", "check", "test"):
            with self.subTest(cmd=cmd):
                out, err = io.StringIO(), io.StringIO()
                self.assertEqual(CLI.main([cmd, self.d], out, err), 2)
                self.assertEqual(err.getvalue(), f"sipar: cannot read {self.d}: is a directory\n")
        out, err = io.StringIO(), io.StringIO()
        self.assertEqual(CLI.main(["check", "--json", self.d], out, err), 2)
        self.assertEqual(json.loads(out.getvalue())[0]["message"], f"cannot read {self.d}: is a directory")


# ====================================================================== M5. signals ignored at start
SLEEPER = 'allow io\nallow time\nfn main() uses io, time {\n print("ready")\n sleep(30)\n print("never")\n}\n'


class T_M5_IgnoredSignals(Tmp):
    def spawn(self, ignore):
        p = self.put("s.sipar", SLEEPER)

        def pre():
            for s in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM):
                signal.signal(s, signal.SIG_IGN if s in ignore else signal.SIG_DFL)
        proc = subprocess.Popen([sys.executable, "-m", "sipar", "run", p], cwd=self.d, env=env(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=pre,
                                start_new_session=True)
        self.addCleanup(lambda: proc.poll() is None and (proc.kill(), proc.wait()))
        self.addCleanup(proc.stdout.close)
        self.addCleanup(proc.stderr.close)
        self.assertEqual(proc.stdout.readline(), b"ready\n")
        return proc

    def test_ignored_sigint_and_sighup_stay_ignored(self):         # guard: SPEC §9, like any Unix program
        p = self.spawn({signal.SIGINT, signal.SIGHUP})
        os.kill(p.pid, signal.SIGINT)
        os.kill(p.pid, signal.SIGHUP)
        time.sleep(1.0)
        self.assertIsNone(p.poll())
        os.kill(p.pid, signal.SIGTERM)                          # not ignored: still stops it
        self.assertEqual(p.wait(10), 128 + signal.SIGTERM)

    def test_default_signals_stop_the_run(self):                   # guard
        p = self.spawn(set())
        os.kill(p.pid, signal.SIGINT)
        self.assertEqual(p.wait(10), 1)
        self.assertIn(b"interrupted", p.stderr.read())

    def test_round6_signal_tests_pass_with_signals_ignored(self):
        def pre():
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
        r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_round6.py",
                            "-k", "*.T_R6unit.*", "-k", "*.T_R6.test_ctrl_c*", "-k", "*.T_R5.test_sig*"],
                           cwd=ROOT, env=env(), capture_output=True, text=True, preexec_fn=pre, timeout=240)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])     # was: FAILED (failures=8)
        self.assertRegex(r.stderr, r"Ran ([6-9]|\d\d) tests")


# ====================================================================== L1-L5. Python API
class T_L_Api(Tmp):
    def prog(self, src):
        return sipar.load(self.put("p.sipar", src))

    def test_optional_int_rejects_bool(self):                      # kills the api.py mutant (passed before)
        p = self.prog("fn o(x: Int?) -> Int? { x }\n")
        self.assertIsNone(p.call("o", None))
        self.assertEqual(p.call("o", 5), 5)
        for b in (True, False):
            with self.assertRaises(sipar.SiparError) as cm:     # mutant `x is True` made True a silent none
                p.call("o", b)
            self.assertEqual(cm.exception.kind, "decode")
            self.assertIn("expected Int, got boolean", cm.exception.message)

    def test_spec_section_10_example_runs(self):
        spec = spec_text()
        block = re.search(r"## 10\. Python embedding\n```python\n(.*?)```", spec, re.S).group(1)
        import ast
        tree = ast.parse(block)                 # our own SPEC.md example, run the way the docs tell a user to
        results, ns = [], {}
        old = os.getcwd()
        os.chdir(os.path.join(ROOT, "examples"))
        try:
            for stmt in tree.body:
                if isinstance(stmt, ast.Expr):
                    results.append(eval(compile(ast.Expression(stmt.value), "SPEC", "eval"), ns))
                else:
                    exec(compile(ast.Module([stmt], []), "SPEC", "exec"), ns)
        finally:
            os.chdir(old)
        self.assertEqual(results[0], "tech")
        self.assertEqual(results[1], {"team": "spam", "urgent": False, "summary": "an ad"})
        self.assertEqual(results[2][0]["code"], "E203")
        api_doc = sipar.api.__doc__
        self.assertIn('prog.call("route", "tech")', api_doc)
        self.assertNotIn('"add"', api_doc)

    def test_journal_pathlike(self):
        p = self.prog(OK)
        j = pathlib.Path(self.d) / "j.jsonl"
        p.call("main", out=io.StringIO(), journal=j)
        self.assertTrue(j.exists())
        with self.assertRaisesRegex(TypeError, r"^call: journal must be a path \(str or os\.PathLike\) or None, got int$"):
            p.call("main", journal=3)
        spec = spec_text()
        self.assertIn("a `journal` that is not a str or `os.PathLike` path", spec)

    def test_journal_bad_characters(self):
        p = self.prog(OK)
        for bad in ("j\ud800.jsonl", "j\0.jsonl"):
            with self.subTest(bad=ascii(bad)):
                out = io.StringIO()
                with self.assertRaises(ValueError) as cm:       # was: UnicodeEncodeError / embedded null byte
                    p.call("main", out=out, journal=os.path.join(self.d, bad))
                self.assertEqual(str(cm.exception),
                                 "call: journal must be a usable file path (no NUL, no lone surrogate)")
                self.assertIs(type(cm.exception), ValueError)
                self.assertEqual(out.getvalue(), "")            # before the run
        self.assertEqual(sorted(os.listdir(self.d)), ["p.sipar"])

    def test_journal_folder_is_a_file(self):
        p = self.prog(OK)
        self.put("afile", "x")
        for j in ("afile/j.jsonl", "afile/sub/j.jsonl"):
            with self.subTest(j=j):
                path = os.path.join(self.d, j)
                with self.assertRaises(sipar.SiparError) as cm:
                    p.call("main", out=io.StringIO(), journal=path)
                self.assertEqual((cm.exception.kind, cm.exception.message),
                                 ("io", f"cannot write journal {path}: {os.path.join(self.d, 'afile')} is not a folder"))
        d = os.path.join(self.d, "adir")
        os.mkdir(d)
        with self.assertRaises(sipar.SiparError) as cm:         # guard: the round-8 wording for a directory
            p.call("main", out=io.StringIO(), journal=d)
        self.assertEqual(cm.exception.message, f"cannot write journal {d}: is a directory")


if __name__ == "__main__":
    unittest.main()
