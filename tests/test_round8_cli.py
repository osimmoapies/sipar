"""Round-8 CLI / docs / API / test-strength fixes. Each test failed before the fix unless
marked *guard*. Fake secrets only (hunter2xyz, ...).

R8C-1  env.get journaled a mixed-case copy of a secret in clear when the variable also held a registered form
R8C-2  tests/test_round6.py T_R2.test_read_ahead_is_capped was flaky (fixed there; no test here)
R8C-3  shell.run with an allowed env name that is not set (mutant `v is None` survived)
R8C-4  the journal kind of env.get was untested
R8C-5  memory: the cache must be dropped after a failed write (BaseException path)
R8C-6  LSP: an endless header line made of spaces
R8C-7  SIPAR_MOCK_SCRIPT nested too deeply: "recursion too deep" at the call site, not the load error
R8C-8  write errors said Python's capitalised strerror (journal, memory, fs.read/fs.write, shell, MCP)
R8C-9  Python API: an exception from the host's out.write() escaped raw
R8C-10 docs: SPEC §10 Int-from-float rule, `sipar spec` is not compact, the API journal creates its folder
"""

import io
import json
import os
import shutil
import stat
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from rt_helpers import Prog  # noqa: E402
import sipar  # noqa: E402
from sipar import ast as A  # noqa: E402
from sipar import lsp  # noqa: E402
from sipar.checker import check_source  # noqa: E402
from sipar.errors import SiparRuntimeError  # noqa: E402
from sipar.runtime import effects as E  # noqa: E402
from sipar.runtime import memory as MEM  # noqa: E402
from sipar.runtime import providers as PR  # noqa: E402
from sipar.runtime.journal import Journal  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET = "hunter2xyz"
MARK = "«secret:KEY»"
HEAD = 'allow secret ["KEY"]\nallow env ["MYV"]\nallow io\n'


def prog(test, src, files=None):
    p = Prog(src, files)
    test.addCleanup(p.cleanup)
    program, d = check_source(src, p.path)
    test.assertEqual([(x.code, x.message) for x in d if x.severity == "error"], [])
    p.program = program
    return p


def tmpdir(test):
    d = os.path.realpath(tempfile.mkdtemp(prefix="sipar_r8c_"))
    test.addCleanup(shutil.rmtree, d, True)
    return d


# ====================================================================== R8C-1. env.get mixed-case copy

class T_R8C_1_EnvGetMixedCase(unittest.TestCase):
    def env_get(self, token, myv):
        """(output, journal entries): the program prints the error kind or the length of the value."""
        p = prog(self, HEAD + 'fn main() uses env, io {\n  try { let v = env.get("MYV") ?? "none"\n'
                              '    print(v.len()) } catch e { print(e.kind) }\n}\n')
        path = os.path.join(p.dir, "j.jsonl")
        j = Journal(path)
        try:
            out = p.run(env={"KEY": token, "MYV": myv}, journal=j)
        finally:
            j.close()
        with open(path, encoding="utf-8") as f:
            text = f.read()
        return out, text, [json.loads(x) for x in text.splitlines()]

    def assertRefused(self, token, myv, *clear):
        out, text, entries = self.env_get(token, myv)
        self.assertEqual(out, "taint\n")
        self.assertEqual([e for e in entries if e.get("kind") == "env.get"], [])   # not read, not journaled
        for c in clear:
            self.assertNotIn(c, text)

    def test_exact_and_mixed_case_copy_is_refused(self):           # the critic's repro
        self.assertRefused(SECRET, f"a {SECRET} b HuNtEr2XyZ", "HuNtEr2XyZ", SECRET)

    def test_upper_and_mixed_case_copy_is_refused(self):
        self.assertRefused(SECRET, "HUNTER2XYZ and hUnTeR2xYz", "hUnTeR2xYz")

    def test_lower_copy_of_upper_secret_and_mixed(self):
        self.assertRefused("HUNTER2XYZ", "hunter2xyz/HunTer2XYZ", "HunTer2XYZ")

    def test_escaped_form_and_mixed_case_copy_is_refused(self):
        # the percent-encoded form is registered; the mixed-case plain copy is not
        self.assertRefused("abc/123-zz", "u=abc%2F123-zz v=ABC/123-Zz", "ABC/123-Zz")

    def test_trailing_space_secret_and_mixed_case_copy(self):
        self.assertRefused(SECRET + " ", f"{SECRET} HuNtEr2XyZ", "HuNtEr2XyZ")

    def test_sharp_s_secret_and_mixed_case_copy(self):
        self.assertRefused("ßtok-1", "ßtok-1 SStOK-1", "SStOK-1")

    def test_registered_forms_only_are_labelled_not_refused(self):   # guard: R4 behaviour kept
        out, text, entries = self.env_get(SECRET, f"a {SECRET} b HUNTER2XYZ")
        self.assertEqual(out, "taint\n")                               # print of a secret-labelled value
        got = [e for e in entries if e.get("kind") == "env.get"]
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["response"], f"a {MARK} b {MARK}")
        self.assertNotIn(SECRET, text.lower())

    def test_two_occurrences_of_registered_forms_with_text_between(self):   # guard: no false refusal
        out, text, entries = self.env_get(SECRET, f"{SECRET}{SECRET}")
        self.assertEqual([e["response"] for e in entries if e.get("kind") == "env.get"], [MARK + MARK])

    def test_public_value_passes(self):                                     # guard
        self.assertEqual(self.env_get(SECRET, "plain")[0], "5\n")

    def test_cli_journal_has_no_mixed_case_copy(self):                      # end to end, as the critic ran it
        import subprocess
        d = tmpdir(self)
        with open(os.path.join(d, "envmix.sipar"), "w", encoding="utf-8") as f:
            f.write('allow secret ["KEY"]\nallow env ["FOO"]\nallow io\nfn main() uses env, io { '
                    'let v = env.get("FOO") ?? "none"; print(v.len()) }\n')
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": ROOT, "KEY": SECRET,
               "FOO": f"a {SECRET} b HuNtEr2XyZ"}
        r = subprocess.run([sys.executable, "-m", "sipar", "run", "envmix.sipar"], cwd=d, env=env,
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 1)
        self.assertIn("runtime error[taint]: env.get('FOO')", r.stderr)
        runs = os.path.join(d, ".sipar", "runs")
        for name in os.listdir(runs):
            with open(os.path.join(runs, name), encoding="utf-8") as f:
                self.assertNotIn("hunter2xyz", f.read().lower())


# ====================================================================== R8C-3 / R8C-4. shell env, journal kind

class T_R8C_3_ShellEnvUnset(unittest.TestCase):
    def test_unset_allowed_name_is_skipped(self):
        p = prog(self, 'allow env ["R8C_UNSET"]\nallow shell ["env"]\nallow io\n'
                       'fn main() uses shell, io { let o = shell.run("env")\n'
                       '  print(o.contains("R8C_UNSET=")) }\n')
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("R8C_UNSET", None)
            os.environ.pop("LANG", None)                 # a base name missing too (CI)
            self.assertEqual(p.run(), "false\n")

    def test_shell_env_unit(self):
        p = prog(self, 'allow env ["R8C_UNSET", "R8C_SET"]\nfn main() {}\n')
        allows = [x for x in p.program.items if isinstance(x, A.Allow)]
        caps = E.Caps(allows, p.dir)
        with mock.patch.dict(os.environ, {"R8C_SET": "yes"}, clear=False):
            os.environ.pop("R8C_UNSET", None)
            env = E.shell_env(caps)
        self.assertEqual(env.get("R8C_SET"), "yes")
        self.assertNotIn("R8C_UNSET", env)


class T_R8C_4_EnvGetJournalKind(unittest.TestCase):
    def test_env_get_entry_kind_and_request(self):
        p = prog(self, 'allow env ["MYV"]\nallow io\nfn main() uses env, io { print(env.get("MYV") ?? "-") }\n')
        j = Journal()
        try:
            self.assertEqual(p.run(env={"MYV": "val"}, journal=j), "val\n")
        finally:
            j.close()
        got = [(e["kind"], e["request"], e["response"]) for e in j.entries if e.get("kind") != "meta"]
        self.assertIn(("env.get", {"name": "MYV"}, "val"), got)


# ====================================================================== R8C-5. memory cache after a failed write

class T_R8C_5_MemoryCacheDrop(unittest.TestCase):
    def test_cache_dropped_after_interrupted_write(self):
        d = tmpdir(self)
        s = MEM.FileStore(os.path.join(d, "m.json"))
        s.put("a", {"value": 1})
        with mock.patch("os.replace", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                s.put("b", {"value": 2})
        self.assertIsNone(s._entries)
        self.assertEqual(s.keys(), ["a"])            # the failed save does not show up from the cache

    def test_cache_dropped_after_os_error(self):    # guard: the OSError path
        d = tmpdir(self)
        s = MEM.FileStore(os.path.join(d, "m.json"))
        s.put("a", {"value": 1})
        with mock.patch("os.replace", side_effect=OSError(28, "No space left on device")):
            with self.assertRaises(SiparRuntimeError) as cm:
                s.put("b", {"value": 2})
        self.assertEqual(cm.exception.message, f"cannot write memory store {s.path}: no space left on device")
        self.assertEqual(s.keys(), ["a"])


# ====================================================================== R8C-6. LSP endless header of spaces

class T_R8C_6_LspEndlessHeader(unittest.TestCase):
    def test_long_space_header_line_is_skipped(self):
        body = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "shutdown"}).encode()
        data = b"X-Pad: " + b" " * 200_000 + b"x\r\nContent-Length: %d\r\n\r\n" % len(body) + body
        self.assertEqual(lsp.read_message(io.BytesIO(data)), body)

    def test_header_text_past_the_cut_is_not_read_as_a_header(self):
        # the tail of a long line after the first MAX_HEADER_LINE bytes looks like a header: it must be skipped
        body = b'{"jsonrpc":"2.0","id":1}'
        pad = b"X-Pad: " + b"a" * (lsp.MAX_HEADER_LINE - 7) + b"Content-Length: 3\r\n"
        data = b"Content-Length: %d\r\n" % len(body) + pad + b"\r\n" + body    # the last header wins
        self.assertEqual(lsp.read_message(io.BytesIO(data)), body)

    def test_long_header_line_at_end_of_input(self):          # guard
        self.assertIsNone(lsp.read_message(io.BytesIO(b"X-Pad: " + b"y" * 200_000)))


# ====================================================================== R8C-7. mock script nested too deeply

DEEP = 3_000_000


class T_R8C_7_MockScriptTooDeep(unittest.TestCase):
    def deep_file(self, depth):
        path = os.path.join(tmpdir(self), "deep.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write("[" * depth + "]" * depth)
        return path

    def test_load_script_unit(self):
        path = self.deep_file(DEEP)
        with self.assertRaises(SiparRuntimeError) as cm:
            PR.load_script(path)
        self.assertEqual((cm.exception.kind, cm.exception.message),
                         ("ai", f"cannot load SIPAR_MOCK_SCRIPT {path}: nested too deeply (more than 20,000 levels)"))

    def test_in_a_run(self):
        path = self.deep_file(DEEP)
        p = prog(self, 'allow ai\nallow io\nai fn hi() -> Str { "say hi" }\nfn main() uses ai, io { print(hi()) }\n')
        e = p.error(env={"SIPAR_MOCK_SCRIPT": path})
        self.assertEqual(e.kind, "ai")
        self.assertIn("cannot load SIPAR_MOCK_SCRIPT", e.message)
        self.assertIn("nested too deeply", e.message)

    def test_just_over_the_limit_in_a_run(self):
        path = self.deep_file(20_001)
        p = prog(self, 'allow ai\nallow io\nai fn hi() -> Str { "say hi" }\nfn main() uses ai, io { print(hi()) }\n')
        e = p.error(env={"SIPAR_MOCK_SCRIPT": path})
        self.assertEqual(e.kind, "ai")
        self.assertIn("nested too deeply (more than 20,000 levels)", e.message)

    def test_at_the_limit_loads_in_a_run(self):                     # guard: loaded on the run's deep stack
        path = os.path.join(tmpdir(self), "ok.json")
        d = 19_998
        with open(path, "w", encoding="utf-8") as f:
            f.write('["hello", ' + "[" * d + "]" * d + "]")
        p = prog(self, 'allow ai\nallow io\nai fn hi() -> Str { "say hi" }\nfn main() uses ai, io { print(hi()) }\n')
        self.assertEqual(p.run(env={"SIPAR_MOCK_SCRIPT": path}), "hello\n")


# ====================================================================== R8C-8. lowercase write errors

class T_R8C_8_Wording(unittest.TestCase):
    def test_journal_is_a_directory(self):
        d = tmpdir(self)
        with self.assertRaises(SiparRuntimeError) as cm:
            Journal(d)
        self.assertEqual(cm.exception.message, f"cannot write journal {d}: is a directory")

    def test_memory_open_not_a_directory(self):
        d = tmpdir(self)
        open(os.path.join(d, "file"), "w").close()
        p = os.path.join(d, "file", "sub", "m.json")
        with self.assertRaises(SiparRuntimeError) as cm:
            MEM.FileStore(p).put("a", {"value": 1})
        self.assertEqual(cm.exception.message, f"cannot open memory store {p}: not a directory")

    def test_memory_write_permission_denied(self):
        d = tmpdir(self)
        s = MEM.FileStore(os.path.join(d, "m.json"))
        with mock.patch("os.replace", side_effect=PermissionError(13, "Permission denied")):
            with self.assertRaises(SiparRuntimeError) as cm:
                s.put("b", {"value": 2})
        self.assertEqual(cm.exception.message, f"cannot write memory store {s.path}: permission denied")

    def test_fs_read_and_write_of_a_directory(self):
        p = prog(self, 'allow fs.read ["."]\nallow fs.write ["."]\nallow io\n'
                       'fn main() uses fs.read, fs.write, io {\n'
                       '  try { print(fs.read("adir")) } catch e { print(e.message) }\n'
                       '  try { fs.write("adir", "x") } catch e { print(e.message) }\n}\n',
                 files={"adir/keep": ""})
        self.assertEqual(p.run(), "cannot read 'adir': is a directory\ncannot write 'adir': is a directory\n")

    def test_shell_not_executable(self):
        p = prog(self, 'allow shell ["./x.sh"]\nallow io\nfn main() uses shell, io {\n'
                       '  try { print(shell.run("./x.sh")) } catch e { print(e.message) }\n}\n',
                 files={"x.sh": "echo hi\n"})
        os.chmod(os.path.join(p.dir, "x.sh"), stat.S_IRUSR | stat.S_IWUSR)
        self.assertEqual(p.run(), "cannot run './x.sh': permission denied\n")

    def test_mcp_command_not_executable(self):
        import test_mcp as TM
        d = tmpdir(self)
        path = os.path.join(d, "not_exec.sh")
        with open(path, "w") as f:
            f.write("#!/bin/sh\n")
        p = TM.prog('print(mcp.fs.read_notes())', command=[path])
        self.addCleanup(p.cleanup)
        e = TM.error(p)
        self.assertEqual(e.kind, "mcp")
        self.assertIn(f"cannot run {path!r}: permission denied", e.message)


# ====================================================================== R8C-9. API host out.write errors

API_SRC = textwrap.dedent('''\
    fn main() { print("hi") }
    fn echo(s: Str) { print(s) }
    fn safe() -> Str {
      try { print("x") } catch e { return e.kind }
      "printed"
    }
    fn f(x: Int) -> Int { x }
    ''')


class BadOut:
    def __init__(self, exc):
        self.exc = exc

    def write(self, text):
        raise self.exc


class T_R8C_9_ApiHostOut(unittest.TestCase):
    def setUp(self):
        d = tmpdir(self)
        self.dir = d
        self.path = os.path.join(d, "api.sipar")
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(API_SRC)
        self.p = sipar.load(self.path)

    def test_value_error_is_a_sipar_error(self):
        with self.assertRaises(sipar.SiparError) as cm:
            self.p.call("main", out=BadOut(ValueError("host boom")))
        e = cm.exception
        self.assertEqual((e.kind, e.message), ("io", "the host's out.write() raised ValueError: host boom"))
        self.assertIsNone(e.__context__)
        self.assertIsNone(e.__cause__)

    def test_program_catch_sees_io(self):
        self.assertEqual(self.p.call("safe", out=BadOut(OSError("disk"))), "io")

    def test_flush_error(self):
        class W(io.StringIO):
            def flush(self):
                raise RuntimeError("no flush")
        with self.assertRaises(sipar.SiparError) as cm:
            self.p.call("main", out=W())
        self.assertEqual(cm.exception.message, "the host's out.flush() raised RuntimeError: no flush")

    def test_keyboard_interrupt_passes(self):                        # guard: not swallowed
        with self.assertRaises(KeyboardInterrupt):
            self.p.call("main", out=BadOut(KeyboardInterrupt()))

    def test_good_writer_and_tty_flag(self):                         # guard
        class TTY(io.StringIO):
            def isatty(self):
                return True
        w = TTY()
        self.assertIsNone(self.p.call("main", out=w))
        self.assertEqual(w.getvalue(), "hi\n")

    def test_long_message_is_clipped(self):
        with self.assertRaises(sipar.SiparError) as cm:
            self.p.call("main", out=BadOut(ValueError("x" * 1000)))
        self.assertEqual(cm.exception.message, ("the host's out.write() raised ValueError: " + "x" * 1000)[:300])

    def test_sipar_error_from_the_host_is_kept(self):               # a host writer that runs Sipar itself
        with self.assertRaises(sipar.SiparError) as cm:
            self.p.call("main", out=BadOut(sipar.SiparError("budget", "inner budget")))
        self.assertEqual((cm.exception.kind, cm.exception.message), ("budget", "inner budget"))

    def test_write_only_writer(self):                                # guard: SPEC §10 needs only write()
        class W:
            def __init__(self):
                self.parts = []

            def write(self, text):
                self.parts.append(text)
        w = W()
        self.assertIsNone(self.p.call("main", out=w))
        self.assertEqual("".join(w.parts), "hi\n")

    def test_tty_writer_still_gets_escaped_output(self):            # S3 (round 5) kept through the wrapper
        class TTY(io.StringIO):
            def isatty(self):
                return True
        w, plain = TTY(), io.StringIO()
        self.p.call("echo", "a\x1b[31mb", out=w)
        self.p.call("echo", "a\x1b[31mb", out=plain)
        self.assertNotIn("\x1b", w.getvalue())
        self.assertEqual(plain.getvalue(), "a\x1b[31mb\n")

    # R8C-10: SPEC §10 conversion of floats to Int (documented now)
    def test_int_from_float_rule(self):
        self.assertEqual(self.p.call("f", 2.0), 2)
        self.assertEqual(self.p.call("f", 1e18), 10 ** 18)
        for v, msg in ((2.5, "f.x: expected Int, got number"), (1.5e18, "f.x: number too large for Int"),
                       (-1e19, "f.x: number too large for Int")):
            with self.assertRaises(sipar.SiparError) as cm:
                self.p.call("f", v)
            self.assertEqual((cm.exception.kind, cm.exception.message), ("decode", msg))
        with self.assertRaises(sipar.SiparError) as cm:
            self.p.call("f", 10 ** 4300)
        self.assertEqual(cm.exception.kind, "value")

    # R8C-10: the journal option creates a missing folder (documented)
    def test_journal_creates_missing_folder(self):
        j = os.path.join(self.dir, "nodir", "sub", "x.jsonl")
        self.assertIsNone(self.p.call("main", out=io.StringIO(), journal=j))
        self.assertTrue(os.path.isfile(j))


# ====================================================================== R8C-10. docs

def read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as f:
        return f.read()


class T_R8C_10_Docs(unittest.TestCase):
    def test_spec_10_int_from_float(self):
        s10 = read("SPEC.md").split("## 10. Python embedding", 1)[1]
        for frag in ("whole-number float", "`2.0`", "1e18", "`number too large for Int`", "about 4200 digits"):
            self.assertIn(frag, s10)

    def test_spec_10_journal_folder_and_out_errors(self):
        s10 = " ".join(read("SPEC.md").split("## 10. Python embedding", 1)[1].split())
        self.assertIn("a missing folder on the path is created", s10)
        self.assertIn("the host's out.write() raised ValueError", s10)

    def test_spec_is_not_called_compact(self):
        import subprocess
        self.assertNotIn("compact", read("README.md"))
        self.assertRegex(read("README.md"), r"about \d+ KB")      # the number: test_round10_cli (LOW4)
        r = subprocess.run([sys.executable, "-m", "sipar", "spec"], capture_output=True, text=True, timeout=60,
                           env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": ROOT})
        self.assertGreater(len(r.stdout.encode()), 45_000)
        self.assertLess(len(r.stdout.encode()), 100_000)     # a sanity bound; README's number: test_round10_cli
        h = subprocess.run([sys.executable, "-m", "sipar", "--help"], capture_output=True, text=True, timeout=60,
                           env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": ROOT})
        self.assertNotIn("compact", h.stdout)

    def test_spec_mock_script_depth(self):
        self.assertIn("nested more than 20,000 levels deep", " ".join(read("SPEC.md").split()))


if __name__ == "__main__":
    unittest.main()
