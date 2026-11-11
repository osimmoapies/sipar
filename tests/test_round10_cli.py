"""Round-10 CLI / Python API / docs fixes. Each test failed before the fix unless marked *guard*.

MED1  sipar.load(pathlib.Path(...)).call(...) crashed (AttributeError in Interp); a bytes path gave a raw TypeError
MED2  CheckError.diagnostics held a PosixPath "file" (not JSON) when load() got a Path
MED3  no Python version check: Python 3.9 / 3.11 ran Sipar quietly with other limits
LOW1  editors/vscode: no `repository`, no LICENSE file, a relative README link (vsce package aborts)
LOW2  README / package.json said "MIT"; the repo is MIT OR Apache-2.0
LOW3  README test count was stale (1525)
LOW4  README said `sipar spec` is about 55 KB (it is ~63 KB)
LOW5  `sipar test --help` named the fixture `<test>.jsonl` (it is `<name>-<hash>.jsonl`, SPEC §9)
LOW6  README and examples/mcp/reader.sipar said `sipar run`, but Quick start never put `sipar` on PATH
T1    `sipar --foo check a.sipar` showed the usage of `check`; T2 the cli.py docstring did not list `lsp`
"""

import ast
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import tokenize
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sipar  # noqa: E402
from sipar import cli as CLI  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRIAGE = os.path.join(ROOT, "examples", "triage.sipar")
OLD_LINE = re.compile(r"\Asipar: needs Python 3\.12 or newer \(this is \d+\.\d+\.\d+\)\n\Z")


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def env(**extra):
    e = {k: v for k, v in os.environ.items() if not k.startswith("SIPAR_")}
    e["PYTHONPATH"] = ROOT
    e.update(extra)
    return e


def run_py(code, *args, exe=None, cwd=None, **kw):
    return subprocess.run([exe or sys.executable, "-c", code, *args], env=env(**kw), cwd=cwd,
                          capture_output=True, text=True, timeout=60)


class Tmp(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="sipar_r10cli_")
        self.addCleanup(shutil.rmtree, self.d, True)

    def put(self, name, text):
        p = os.path.join(self.d, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p


# ====================================================================== MED1. load() takes a Path, and call() works
class T_MED1_PathLoad(Tmp):
    def test_pathlib_load_then_call(self):
        prog = sipar.load(pathlib.Path(TRIAGE))
        self.assertEqual(prog.call("route", "tech"), "tech")            # was: AttributeError 'PosixPath'...
        self.assertIs(type(prog.path), str)
        self.assertEqual(prog.path, TRIAGE)

    def test_relative_pathlib_in_a_subprocess(self):        # the critic's repro, word for word
        r = run_py("import sipar,pathlib; print(sipar.load(pathlib.Path('triage.sipar')).call('route','tech'))",
                   cwd=os.path.join(ROOT, "examples"))
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "tech\n", ""))

    def test_pathlib_with_journal_and_print(self):          # the program's folder comes from the Path too
        p = pathlib.Path(self.put("hi.sipar", 'allow io\nfn main() uses io { print("hi") }\n'))
        out = io.StringIO()
        sipar.load(p).call("main", out=out, journal=os.path.join(self.d, "j.jsonl"))
        self.assertEqual(out.getvalue(), "hi\n")
        self.assertTrue(os.path.isfile(os.path.join(self.d, "j.jsonl")))

    def test_bytes_path_is_a_clear_type_error(self):
        with self.assertRaises(TypeError) as c:
            sipar.load(TRIAGE.encode())                     # was: a raw TypeError from str.startswith later
        self.assertEqual(str(c.exception), "load: path must be a str or os.PathLike of str, got bytes "
                                           "(decode it first)")
        with self.assertRaises(TypeError) as c:
            sipar.load(bytearray(TRIAGE.encode()))
        self.assertIn("got bytearray (decode it first)", str(c.exception))

    def test_pathlike_giving_bytes_is_a_type_error(self):
        class BP:
            def __fspath__(self):
                return TRIAGE.encode()
        with self.assertRaises(TypeError) as c:
            sipar.load(BP())
        self.assertIn("got bytes (decode it first)", str(c.exception))

    def test_custom_pathlike_giving_str(self):
        class SP:
            def __fspath__(self):
                return TRIAGE
        prog = sipar.load(SP())
        self.assertEqual((prog.path, prog.call("route", "billing")), (TRIAGE, "billing"))

    def test_not_a_path_is_a_type_error(self):
        for bad, name in ((None, "NoneType"), (0, "int"), (3.5, "float"), (["a.sipar"], "list")):
            with self.subTest(bad=bad), self.assertRaises(TypeError) as c:
                sipar.load(bad)
            self.assertEqual(str(c.exception), f"load: path must be a str or os.PathLike, got {name}")

    def test_nul_and_lone_surrogate_are_value_errors(self):
        for bad in ("a\0b.sipar", "a\ud800.sipar", pathlib.PurePosixPath("x\0.sipar")):
            with self.subTest(bad=bad), self.assertRaises(ValueError) as c:
                sipar.load(bad)
            self.assertEqual(str(c.exception), "load: path must be a usable file path (no NUL, no lone surrogate)")

    def test_str_paths_unchanged(self):                     # guard
        self.assertEqual(sipar.load(TRIAGE).call("route", "spam"), "spam")
        with self.assertRaises(FileNotFoundError):
            sipar.load("")
        with self.assertRaises(FileNotFoundError):
            sipar.load(pathlib.Path(self.d) / "missing.sipar")
        p = self.put("ünï cödé.sipar", 'fn f() -> Int { 1 }\n')      # non-ASCII and a space
        self.assertEqual(sipar.load(p).call("f"), 1)

    def test_pathlib_non_ascii_name(self):
        p = self.put("ünï cödé.sipar", 'fn f() -> Int { 1 }\n')
        self.assertEqual(sipar.load(pathlib.Path(p)).call("f"), 1)

    def test_program_built_by_hand_with_a_path(self):
        prog = sipar.load(TRIAGE)
        p2 = sipar.Program(prog.program, pathlib.Path(TRIAGE), [])
        self.assertIs(type(p2.path), str)
        self.assertEqual(p2.call("route", "tech"), "tech")


# ====================================================================== MED2. diagnostics are `check --json` dicts
class T_MED2_Diagnostics(Tmp):
    def cli_json(self, path):
        r = subprocess.run([sys.executable, "-m", "sipar", "check", "--json", path], env=env(),
                           capture_output=True, text=True, timeout=60)
        return json.loads(r.stdout)

    def check(self, src):
        p = self.put("bad.sipar", src)
        with self.assertRaises(sipar.CheckError) as c:
            sipar.load(pathlib.Path(p))
        diags = c.exception.diagnostics
        self.assertIs(type(diags[0]["file"]), str)                      # was: PosixPath
        self.assertEqual(json.loads(json.dumps(diags)), self.cli_json(p))  # was: TypeError not JSON serializable
        self.assertTrue(str(c.exception).startswith(p + ":"))

    def test_type_error(self):
        self.check("fn main() { x }\n")

    def test_syntax_error(self):
        self.check("fn main( {\n")

    def test_warnings_on_success_are_json(self):
        p = pathlib.Path(self.put("w.sipar", 'allow net ["*"]\nfn main() { }\n'))       # E311 warning
        prog = sipar.load(p)
        self.assertEqual([w["code"] for w in prog.warnings], ["E311"])
        json.dumps(prog.warnings)                                       # was: TypeError (PosixPath)
        self.assertTrue(all(type(w["file"]) is str for w in prog.warnings))


# ====================================================================== MED3. an old Python stops with one line
SHIM_CLI = ("import sys, runpy\nsys.version_info = (3, 9, 6, 'final', 0)\n"
            "runpy.run_module('sipar', run_name='__main__', alter_sys=True)\n")
SHIM_IMPORT = ("import sys\nsys.version_info = (3, 11, 16, 'final', 0)\n"
               "try:\n    import sipar\nexcept ImportError as e:\n    print('ImportError', e)\n")
SHIM_MAIN = ("import sys, runpy, sipar\nsys.version_info = (3, 8, 0, 'final', 0)\n"
             "runpy.run_module('sipar.__main__', run_name='__main__', alter_sys=True)\n")


def old_pythons():
    found = []
    for exe in ["/usr/bin/python3", *sorted(
            str(p) for p in pathlib.Path.home().glob(".local/share/uv/python/cpython-3.1[01]*/bin/python3.1[01]"))]:
        if os.path.isfile(exe) and os.access(exe, os.X_OK):
            v = subprocess.run([exe, "-c", "import sys; print(sys.version_info[:2] < (3, 12))"],
                               capture_output=True, text=True, timeout=30).stdout.strip()
            if v == "True":
                found.append(exe)
    return found


class T_MED3_PythonVersion(unittest.TestCase):
    def test_message(self):
        m = sipar._old_python_message
        self.assertEqual(m((3, 9, 6, "final", 0)), "sipar: needs Python 3.12 or newer (this is 3.9.6)")
        self.assertEqual(m((3, 11, 16)), "sipar: needs Python 3.12 or newer (this is 3.11.16)")
        self.assertEqual(m((2, 7, 18)), "sipar: needs Python 3.12 or newer (this is 2.7.18)")
        for ok in ((3, 12, 0), (3, 12, 8), (3, 13, 1), (3, 14, 7), (4, 0, 0)):
            self.assertIsNone(m(ok), ok)
        self.assertIsNone(m())                              # this Python runs the suite: it is new enough

    def test_cli_on_a_faked_old_python(self):
        r = run_py(SHIM_CLI, "--version")
        self.assertEqual((r.returncode, r.stdout), (2, ""))                # was: "sipar 0.1.0", exit 0
        self.assertEqual(r.stderr, "sipar: needs Python 3.12 or newer (this is 3.9.6)\n")
        r = run_py(SHIM_CLI, "check", TRIAGE)
        self.assertEqual((r.returncode, r.stdout, r.stderr),
                         (2, "", "sipar: needs Python 3.12 or newer (this is 3.9.6)\n"))

    def test_import_on_a_faked_old_python(self):
        r = run_py(SHIM_IMPORT)
        self.assertEqual(r.stdout, "ImportError sipar: needs Python 3.12 or newer (this is 3.11.16)\n")
        self.assertEqual(r.returncode, 0)

    def test_host_import_is_not_mistaken_for_the_cli(self):
        # a host function with a local `mod_name` (even one named like runpy's) must get ImportError, not exit 2
        code = ("import sys\nsys.version_info = (3, 10, 1, 'final', 0)\n"
                "def _get_module_details(mod_name='sipar.__main__'):\n    import sipar\n"
                "def _run_module_as_main(mod_name='sipar'):\n    import sipar\n"
                "for fn in (_get_module_details, _run_module_as_main):\n"
                "    try:\n        fn()\n    except ImportError as e:\n        print(fn.__name__, e)\n"
                "    sys.modules.pop('sipar', None)\n")
        r = run_py(code)
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertEqual(r.stdout, "_get_module_details sipar: needs Python 3.12 or newer (this is 3.10.1)\n"
                                   "_run_module_as_main sipar: needs Python 3.12 or newer (this is 3.10.1)\n")

    def test_dir_still_lists_the_api(self):
        names = dir(sipar)
        for n in ("load", "check_source", "CheckError", "SiparError", "Program", "__version__"):
            self.assertIn(n, names)

    def test_main_module_checks_too(self):
        r = run_py(SHIM_MAIN, "--version")
        self.assertEqual((r.returncode, r.stdout, r.stderr),
                         (2, "", "sipar: needs Python 3.12 or newer (this is 3.8.0)\n"))

    def test_real_old_pythons(self):
        olds = old_pythons()
        if not olds:
            self.skipTest("no Python older than 3.12 on this machine")
        for exe in olds:
            with self.subTest(exe=exe):
                r = subprocess.run([exe, "-m", "sipar", "--version"], env=env(), capture_output=True, text=True,
                                   timeout=60)
                self.assertEqual((r.returncode, r.stdout), (2, ""))
                self.assertRegex(r.stderr, OLD_LINE)
                r = subprocess.run([exe, "-c", "import sipar"], env=env(), capture_output=True, text=True,
                                   timeout=60)
                self.assertEqual(r.returncode, 1)
                self.assertRegex(r.stderr.splitlines()[-1],
                                 r"\AImportError: sipar: needs Python 3\.12 or newer \(this is \d+\.\d+\.\d+\)\Z")

    def test_bin_sipar_with_an_old_python3_on_path(self):
        olds = old_pythons()
        if not olds:
            self.skipTest("no Python older than 3.12 on this machine")
        d = tempfile.mkdtemp(prefix="sipar_r10py_")
        self.addCleanup(shutil.rmtree, d, True)
        os.symlink(olds[0], os.path.join(d, "python3"))
        r = subprocess.run([os.path.join(ROOT, "bin", "sipar"), "check", TRIAGE], capture_output=True, text=True,
                           timeout=60, env={"PATH": d + ":/usr/bin:/bin"})
        self.assertEqual((r.returncode, r.stdout), (2, ""))
        self.assertRegex(r.stderr, OLD_LINE)

    def test_gate_files_use_only_old_syntax(self):
        for rel in ("sipar/__init__.py", "sipar/__main__.py"):
            src = read(rel)
            ast.parse(src, feature_version=(3, 4))            # no walrus, match, positional-only, ...
            with open(os.path.join(ROOT, rel), "rb") as f:   # and no f-strings (3.6+)
                kinds = {tokenize.tok_name[t.type] for t in tokenize.tokenize(f.readline)}
            self.assertNotIn("FSTRING_START", kinds, rel)
            self.assertNotRegex(src, r"(?m)^\s*from __future__ import annotations", rel)

    def test_gate_is_before_the_cli_import(self):
        src = read("sipar/__main__.py")
        self.assertLess(src.index("_old_python_message()"), src.index("from .cli import"))


# ====================================================================== LOW1 / LOW2. packaging and license
class T_LOW1_LOW2_Packaging(unittest.TestCase):
    def test_vscode_package_json(self):
        pkg = json.loads(read("editors/vscode/package.json"))
        self.assertEqual(pkg["repository"], {"type": "git", "url": "https://github.com/osimmoapies/sipar",
                                             "directory": "editors/vscode"})
        self.assertEqual(pkg["license"], "MIT OR Apache-2.0")
        lock = json.loads(read("editors/vscode/package-lock.json"))
        self.assertEqual(lock["packages"][""]["license"], "MIT OR Apache-2.0")

    def test_vscode_readme_has_no_relative_links(self):
        text = read("editors/vscode/README.md")
        links = re.findall(r"\]\(([^)]*)\)", text) + re.findall(r'(?:src|href)="([^"]*)"', text)
        rel = [u for u in links if not re.match(r"(https?://|#|mailto:)", u)]
        self.assertEqual(rel, [])
        self.assertIn("https://github.com/osimmoapies/sipar", text)

    def test_vscode_license_file(self):          # vsce looks for LICENSE / LICENSE.md / LICENSE.txt in the extension
        text = read("editors/vscode/LICENSE")
        self.assertIn(read("LICENSE-MIT").strip(), text)
        self.assertIn(read("LICENSE-APACHE").strip(), text)
        self.assertIn("MIT OR Apache-2.0", text)

    def test_readme_license_section(self):
        sec = read("README.md").split("## License", 1)[1]
        for frag in ("[MIT](LICENSE-MIT)", "[Apache-2.0](LICENSE-APACHE)", "`MIT OR Apache-2.0`"):
            self.assertIn(frag, sec)
        for f in ("LICENSE-MIT", "LICENSE-APACHE"):
            self.assertTrue(os.path.isfile(os.path.join(ROOT, f)), f)

    def test_no_plain_mit_left(self):
        self.assertNotRegex(read("README.md").split("## License", 1)[1], r"\A\s*MIT\s*\Z")
        self.assertNotIn('"license": "MIT"', read("editors/vscode/package.json"))


# ====================================================================== LOW3 / LOW4. numbers in README
class T_LOW3_LOW4_Numbers(unittest.TestCase):
    def test_test_count(self):
        m = re.search(r"([\d,]+)(\+?) tests \(unit", read("README.md"))
        self.assertIsNotNone(m)
        n = int(m.group(1).replace(",", ""))
        code = "import unittest; print(unittest.defaultTestLoader.discover('tests').countTestCases())"
        r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env(), capture_output=True, text=True,
                           timeout=120)
        real = int(r.stdout.strip().splitlines()[-1])
        self.assertLessEqual(n, real)                 # never more than there are
        self.assertLess(real - n, 100, (n, real))     # and not stale by a whole round

    def test_spec_size(self):
        m = re.search(r"about (\d+) KB\) to put into an LLM prompt", read("README.md"))
        self.assertIsNotNone(m)
        r = subprocess.run([sys.executable, "-m", "sipar", "spec"], env=env(), capture_output=True, timeout=60)
        real_kb = len(r.stdout) / 1000
        self.assertLess(abs(int(m.group(1)) - real_kb) / real_kb, 0.06, (m.group(1), real_kb))


# ====================================================================== LOW5. test --help fixture name
class T_LOW5_FixtureName(Tmp):
    def test_help_matches_spec_and_real_file(self):
        p = CLI.build_parser().subs["test"]
        h = p.format_help()
        self.assertIn(".sipar/fixtures/<name>-<hash>.jsonl", h)
        self.assertNotIn("<test>.jsonl", h)
        self.assertIn(".sipar/fixtures/<name>-<hash>.jsonl", read("SPEC.md"))
        src = ('allow ai\nai fn f(t: Str) -> Str { "say {t}" }\n'
               'test "my t" { let r = f("x")\n assert r == r }\n')
        prog = self.put("t2.sipar", src)
        r = subprocess.run([sys.executable, "-m", "sipar", "test", prog, "--record"], env=env(SIPAR_MODEL="mock"),
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        files = os.listdir(os.path.join(self.d, ".sipar", "fixtures"))
        self.assertEqual(len(files), 1, files)
        self.assertRegex(files[0], r"\Amy_t-[0-9a-f]{12}\.jsonl\Z")      # <name>-<hash>.jsonl


# ====================================================================== LOW6. `sipar run` works after Quick start
def quick_start_lines():
    block = read("README.md").split("## Quick start", 1)[1].split("```sh", 1)[1].split("```", 1)[0]
    return [ln.strip() for ln in block.splitlines() if ln.strip() and not ln.strip().startswith("#")]


class T_LOW6_SiparOnPath(Tmp):
    def path_after_quick_start(self):
        exports = [ln for ln in quick_start_lines() if ln.startswith("export PATH=")]
        self.assertEqual(len(exports), 1, quick_start_lines())             # was: no PATH step at all
        pydir = os.path.join(self.d, "py")                                  # bin/sipar runs `python3` from PATH
        os.mkdir(pydir)
        os.symlink(sys.executable, os.path.join(pydir, "python3"))
        cmd = exports[0].split("#", 1)[0] + '\nprintf %s "$PATH"'
        r = subprocess.run(["sh", "-c", cmd], cwd=ROOT, capture_output=True, text=True, timeout=30,
                           env={"PATH": pydir + ":/usr/bin:/bin"})
        return r.stdout

    def test_quick_start_puts_bin_sipar_on_path(self):
        path = self.path_after_quick_start()
        r = subprocess.run(["sh", "-c", "command -v sipar"], capture_output=True, text=True, timeout=30,
                           env={"PATH": path})
        self.assertEqual(os.path.realpath(r.stdout.strip()), os.path.realpath(os.path.join(ROOT, "bin", "sipar")))

    def test_every_sipar_run_comment_runs(self):
        path = self.path_after_quick_start()
        sources = {"README.md": read("README.md"), "examples/mcp/reader.sipar": read("examples/mcp/reader.sipar"),
                   "examples/injection/assistant.sipar": read("examples/injection/assistant.sipar")}
        cmds = []
        for name, text in sources.items():
            for ln in text.splitlines():
                m = re.search(r"//\s*(?:try it[^:]*:\s*)?(.*\bsipar run\b.*)", ln)
                if m:
                    cmds.append((name, m.group(1).strip()))
        self.assertEqual(len(cmds), 3, cmds)
        for name, cmd in cmds:
            with self.subTest(name=name, cmd=cmd):
                self.assertNotIn("python3 -m sipar", cmd)
                if name == "README.md":                     # the taste program, saved as taste.sipar
                    block = [b.split("```", 1)[0] for b in read("README.md").split("```rust")[1:] if cmd in b][0]
                    cwd = tempfile.mkdtemp(dir=self.d)
                    with open(os.path.join(cwd, "taste.sipar"), "w", encoding="utf-8") as f:
                        f.write(block)
                elif name.startswith("examples/mcp"):         # run in the example folder
                    cwd = os.path.join(self.d, "mcp")
                    shutil.copytree(os.path.join(ROOT, "examples", "mcp"), cwd,
                                    ignore=shutil.ignore_patterns(".sipar"))
                else:                                           # run from the repository root (a copy)
                    cwd = os.path.join(self.d, "repo")
                    os.mkdir(cwd)
                    shutil.copytree(os.path.join(ROOT, "examples"), os.path.join(cwd, "examples"),
                                    ignore=shutil.ignore_patterns(".sipar", "out"))
                e = {"PATH": path, "HOME": self.d, "LANG": "C.UTF-8"}
                r = subprocess.run(["sh", "-c", cmd], cwd=cwd, env=e, capture_output=True, text=True, timeout=90)
                self.assertNotIn("not found", r.stderr)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                if name != "README.md":
                    self.assertIn("BLOCKED (taint)", r.stdout + r.stderr)
                else:
                    self.assertTrue(os.listdir(os.path.join(cwd, "out")))


# ====================================================================== T1 / T2. usage and docstring
class T_Tiny(unittest.TestCase):
    def usage_of(self, *argv):
        r = subprocess.run([sys.executable, "-m", "sipar", *argv], env=env(), capture_output=True, text=True,
                           timeout=60)
        self.assertEqual(r.returncode, 2, r.stderr)
        return r.stderr.splitlines()[0]

    def test_option_before_command_shows_main_usage(self):
        self.assertEqual(self.usage_of("--foo", "check", "a.sipar"), "usage: sipar [-h] [--version] command ...")
        self.assertEqual(self.usage_of("--foo=check", "check", "a.sipar"), "usage: sipar [-h] [--version] command ...")
        self.assertEqual(self.usage_of("--foo", "--bar", "test", "a.sipar"),
                         "usage: sipar [-h] [--version] command ...")

    def test_option_after_command_shows_its_usage(self):            # guard
        self.assertEqual(self.usage_of("check", "a.sipar", "--foo"), "usage: sipar check [-h] [--json] file")
        self.assertEqual(self.usage_of("check", "--foo", "a.sipar"), "usage: sipar check [-h] [--json] file")
        self.assertEqual(self.usage_of("check", "a", "b"), "usage: sipar check [-h] [--json] file")
        self.assertEqual(self.usage_of("check", "check", "check"), "usage: sipar check [-h] [--json] file")
        self.assertEqual(self.usage_of("--foo"), "usage: sipar [-h] [--version] command ...")

    def test_before_command_helper(self):
        b = CLI._before_command
        self.assertTrue(b(["--foo", "check", "a"], "check", ["--foo"]))
        self.assertFalse(b(["check", "a", "--foo"], "check", ["--foo"]))
        self.assertFalse(b(["check", "--foo", "a"], "check", ["--foo"]))
        self.assertTrue(b(["--foo"], None, ["--foo"]))
        self.assertFalse(b(["check", "check"], "check", ["check"]))      # same token: after, not before

    def test_main_with_argv_shows_main_usage(self):
        err = io.StringIO()
        old = sys.stderr
        sys.stderr = err
        try:
            with self.assertRaises(SystemExit) as c:
                CLI.main(["--foo", "check", "a.sipar"], out=io.StringIO(), err=err)
        finally:
            sys.stderr = old
        self.assertEqual(c.exception.code, 2)
        self.assertTrue(err.getvalue().startswith("usage: sipar [-h] [--version] command ..."), err.getvalue())

    def test_docstring_lists_every_command(self):
        first = CLI.__doc__.splitlines()[0]
        listed = re.search(r"sipar (\S+)\.", first).group(1).split("|")
        self.assertEqual(sorted(x for x in listed if not x.startswith("--")), sorted(CLI.COMMANDS))
        self.assertIn("--version", listed)


# ====================================================================== the attacker's round (critic of this change)
SAVE_SIP = ('allow fs.write ["./out"]\n'
            'fn save(x: Str) uses fs.write {\n    fs.write("out/r.txt", x)\n}\n'
            'fn div(n: Int) -> Int {\n    10 / n\n}\n')


class T_Attack(Tmp):
    def test_cli_module_on_a_faked_old_python(self):        # A1: `python -m sipar.cli` is a CLI start too
        r = run_py("import sys, runpy\nsys.version_info = (3, 9, 6, 'final', 0)\n"
                   "runpy.run_module('sipar.cli', run_name='__main__', alter_sys=True)\n", "--version")
        self.assertEqual((r.returncode, r.stdout, r.stderr),
                         (2, "", "sipar: needs Python 3.12 or newer (this is 3.9.6)\n"))

    def test_cli_module_on_real_old_pythons(self):
        olds = old_pythons()
        if not olds:
            self.skipTest("no Python older than 3.12 here")
        for exe in olds:
            with self.subTest(exe=exe):
                r = subprocess.run([exe, "-m", "sipar.cli", "--version"], env=env(), capture_output=True,
                                   text=True, timeout=60)
                self.assertEqual((r.returncode, r.stdout), (2, ""))
                self.assertRegex(r.stderr, OLD_LINE)

    def test_stderr_that_cannot_be_written_still_exits_2(self):     # A3: closed stderr, a stderr that raises
        for setup in ("sys.stderr.close()",
                      "class E:\n    def write(self, s): raise OSError(5, 'EIO')\n    def flush(self): pass\nsys.stderr = E()"):
            with self.subTest(setup=setup.splitlines()[0]):
                r = run_py("import sys, runpy\nsys.version_info = (3, 9, 6, 'final', 0)\n" + setup +
                           "\nrunpy.run_module('sipar', run_name='__main__', alter_sys=True)\n", "--version")
                self.assertEqual((r.returncode, r.stdout), (2, ""), r.stderr)

    def test_program_built_by_hand_checks_its_path(self):    # A2: same rules as load()
        prog = sipar.load(TRIAGE)
        for bad, exc, text in ((b"triage.sipar", TypeError, "got bytes (decode it first)"),
                               (bytearray(b"t.sipar"), TypeError, "got bytearray"),
                               (5, TypeError, "got int"), (None, TypeError, "got NoneType"),
                               ("a\0b.sipar", ValueError, "usable file path"),
                               ("a\ud800.sipar", ValueError, "usable file path")):
            with self.subTest(bad=bad):
                with self.assertRaises(exc) as c:
                    sipar.Program(prog.program, bad, [])
                self.assertIn(text, str(c.exception))
                self.assertTrue(str(c.exception).startswith("Program: path must be"), str(c.exception))
        with self.assertRaises(TypeError) as c:
            sipar.load(b"x.sipar")
        self.assertTrue(str(c.exception).startswith("load: path must be"))      # load() keeps its own words
        self.assertEqual(sipar.Program(prog.program, TRIAGE, []).call("route", "tech"), "tech")

    def test_surrogate_escape_names_are_accepted_and_spec_says_so(self):    # A4
        with self.assertRaises(FileNotFoundError):
            sipar.load(os.path.join(self.d, "a\udc80.sipar"))            # a raw-byte stand-in: a usable name
        with self.assertRaises(ValueError):
            sipar.load(os.path.join(self.d, "a\ud800.sipar"))
        spec = read("SPEC.md")
        sec10 = spec[spec.index("`load` takes a str"):]
        sec10 = sec10[:sec10.index("It reads the file")]
        self.assertIn("os.listdir", sec10)
        self.assertNotRegex(sec10, r"or a lone surrogate raises")

    def test_relative_load_keeps_its_folder_after_chdir(self):     # A5
        proj = os.path.join(self.d, "proj")
        os.makedirs(os.path.join(proj, "out"))
        os.mkdir(os.path.join(self.d, "other"))
        with open(os.path.join(proj, "a.sipar"), "w", encoding="utf-8") as f:
            f.write(SAVE_SIP)
        code = ("import os, pathlib, sipar\n"
                "for p in (pathlib.Path('proj/a.sipar'), 'proj/a.sipar'):\n"
                "    prog = sipar.load(p)\n    os.chdir('other')\n"
                "    prog.call('save', 'hi')\n"
                "    try:\n        prog.call('div', 0)\n    except sipar.SiparError as e:\n"
                "        print(e.kind, e.file, prog.path)\n"
                "    os.chdir('..')\n")
        r = run_py(code, cwd=self.d)
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertEqual(r.stdout.splitlines(), ["zero proj/a.sipar proj/a.sipar"] * 2)   # the name as given
        with open(os.path.join(proj, "out", "r.txt"), encoding="utf-8") as f:
            self.assertEqual(f.read(), "hi")
        self.assertFalse(os.path.exists(os.path.join(self.d, "other", "out")))

    def test_bin_sipar_honours_SIPAR_PYTHON(self):        # A6: a way past an old python3
        pydir = os.path.join(self.d, "py")
        os.mkdir(pydir)
        fake = os.path.join(pydir, "python3")
        with open(fake, "w") as f:
            f.write("#!/bin/sh\necho 'sipar: needs Python 3.12 or newer (this is 3.9.6)' >&2\nexit 2\n")
        os.chmod(fake, 0o755)
        e = {"PATH": pydir + ":/usr/bin:/bin"}
        sip = os.path.join(ROOT, "bin", "sipar")
        r = subprocess.run([sip, "--version"], env=e, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 2)                                   # the old python3 still stops
        for cmd in ([sip, "--version"], ["env", "SIPAR_PYTHON=" + sys.executable, sip, "--version"]):
            with self.subTest(cmd=cmd[0]):
                ee = dict(e) if cmd[0] == "env" else dict(e, SIPAR_PYTHON=sys.executable)
                r = subprocess.run(cmd, env=ee, capture_output=True, text=True, timeout=60)
                self.assertEqual((r.returncode, r.stdout.startswith("sipar "), r.stderr), (0, True, ""))

    def test_docs_say_how_to_get_past_an_old_python(self):
        qs = "\n".join(quick_start_lines())
        readme = read("README.md")
        quick = readme[readme.index("## Quick start"):readme.index("Providers:")]
        for name, text in (("README Quick start", quick), ("editors/vscode/README.md", read("editors/vscode/README.md"))):
            with self.subTest(doc=name):
                self.assertIn("3.12", text)
                self.assertIn("SIPAR_PYTHON", text)
        self.assertIn("SIPAR_PYTHON", read("SPEC.md"))
        self.assertTrue(qs)


if __name__ == "__main__":
    unittest.main()
