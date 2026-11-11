"""Packaging: pyproject.toml, the copy of SPEC.md an installed wheel carries, the "standard library only" claim.

A real build (`uv build`, install the wheel, run `sipar spec`) needs the network for the build backend, so it is
a CI step (.github/workflows/ci.yml, job `package`), not a unit test. These tests pin everything that step
relies on."""
import ast
import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as f:
        return f.read()


class T_SpecFile(unittest.TestCase):
    """`sipar spec` printed only the generated tables when the package was installed: SPEC.md was looked for
    one folder above the package, where an installed package has nothing."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.pkg = os.path.join(self.dir, "site", "sipar")
        os.makedirs(self.pkg)

    def touch(self, *parts):
        path = os.path.join(self.dir, *parts)
        with open(path, "w", encoding="utf-8") as f:
            f.write("# x\n")
        return path

    def test_copy_inside_the_package_wins(self):
        from sipar.cli import spec_file
        inside = self.touch("site", "sipar", "SPEC.md")
        self.touch("site", "SPEC.md")
        self.assertEqual(spec_file(self.pkg), inside)

    def test_checkout_layout(self):
        from sipar.cli import spec_file
        above = self.touch("site", "SPEC.md")
        self.assertEqual(spec_file(self.pkg), above)

    def test_neither(self):
        from sipar.cli import spec_file
        self.assertIsNone(spec_file(self.pkg))

    def test_a_folder_named_spec_is_not_the_file(self):
        from sipar.cli import spec_file
        os.mkdir(os.path.join(self.pkg, "SPEC.md"))
        above = self.touch("site", "SPEC.md")
        self.assertEqual(spec_file(self.pkg), above)

    def test_this_checkout(self):                           # guard: the checkout has one SPEC.md, at the top
        from sipar.cli import spec_file
        self.assertEqual(spec_file(), os.path.join(ROOT, "SPEC.md"))
        self.assertFalse(os.path.exists(os.path.join(ROOT, "sipar", "SPEC.md")),
                         "a second copy in sipar/ would go stale; the wheel build makes its own")

    def copy_package(self, with_spec):
        shutil.rmtree(self.pkg)
        shutil.copytree(os.path.join(ROOT, "sipar"), self.pkg, ignore=shutil.ignore_patterns("__pycache__"))
        if with_spec:
            shutil.copy(os.path.join(ROOT, "SPEC.md"), os.path.join(self.pkg, "SPEC.md"))
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env["PYTHONPATH"] = os.path.join(self.dir, "site")
        return subprocess.run([sys.executable, "-m", "sipar", "spec"], capture_output=True, text=True,
                              encoding="utf-8", cwd=self.dir, env=env, timeout=60)

    def test_installed_layout_prints_the_whole_spec(self):
        here = subprocess.run([sys.executable, "-m", "sipar", "spec"], capture_output=True, text=True,
                              encoding="utf-8", cwd=ROOT, timeout=60)
        p = self.copy_package(with_spec=True)
        self.assertEqual((p.returncode, p.stderr), (0, ""))
        self.assertTrue(p.stdout.startswith("# Sipar "), p.stdout[:80])
        self.assertIn("## 6. Information-flow rules", p.stdout)
        self.assertEqual(p.stdout, here.stdout)

    def test_no_spec_at_all_still_prints_the_tables(self):  # guard: a broken install is no crash
        p = self.copy_package(with_spec=False)
        self.assertEqual((p.returncode, p.stderr), (0, ""))
        self.assertTrue(p.stdout.startswith("## Standard library"), p.stdout[:80])


class T_Pyproject(unittest.TestCase):
    def setUp(self):
        self.cfg = tomllib.loads(read("pyproject.toml"))
        self.project = self.cfg["project"]
        self.hatch = self.cfg["tool"]["hatch"]

    def test_version_is_read_from_the_package(self):
        import sipar
        self.assertEqual(self.project["dynamic"], ["version"])
        self.assertNotIn("version", self.project)
        self.assertEqual(self.hatch["version"], {"path": "sipar/__init__.py"})
        # hatchling's default pattern for that file
        m = re.search(r'(?m)^(?:__version__|VERSION)\s*=\s*["\']([^"\']+)["\']', read("sipar/__init__.py"))
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), sipar.__version__)
        self.assertRegex(sipar.__version__, r"^\d+\.\d+\.\d+$")

    def test_python_floor_is_the_one_the_package_enforces(self):
        import sipar
        floor = "%d.%d" % sipar._MIN_PYTHON
        self.assertEqual(self.project["requires-python"], ">=" + floor)
        listed = sorted(c.rsplit(" ", 1)[1] for c in self.project["classifiers"]
                        if re.fullmatch(r"Programming Language :: Python :: 3\.\d+", c))
        self.assertEqual(listed[0], floor)
        matrix = re.search(r'python: \[([^\]]+)\]', read(".github/workflows/ci.yml")).group(1)
        self.assertEqual(listed, sorted(v.strip().strip('"') for v in matrix.split(",")))

    def test_license_is_the_pair_of_files(self):
        self.assertEqual(self.project["license"], "MIT OR Apache-2.0")
        self.assertEqual(sorted(self.project["license-files"]), ["LICENSE-APACHE", "LICENSE-MIT"])
        for name in self.project["license-files"]:
            self.assertTrue(os.path.isfile(os.path.join(ROOT, name)), name)
        self.assertFalse([c for c in self.project["classifiers"] if c.startswith("License ::")],
                         "PEP 639: a license expression replaces the License classifiers")
        backend = self.cfg["build-system"]["requires"]
        self.assertEqual(backend, ["hatchling>=1.27"])      # 1.27 is the first with PEP 639 license-files

    def test_command_is_the_cli_main(self):
        self.assertEqual(self.project["scripts"], {"sipar": "sipar.cli:main"})
        import sipar
        from sipar.cli import main
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()) as shown, self.assertRaises(SystemExit) as cm:
            main(["--version"], out=out, err=err)           # argparse prints the version and exits 0
        self.assertEqual((cm.exception.code, shown.getvalue()), (0, f"sipar {sipar.__version__}\n"))
        self.assertIsInstance(main(["spec"], out=out, err=err), int)    # the wrapper does sys.exit(main())

    def test_wheel_is_the_package_plus_the_spec(self):
        wheel = self.hatch["build"]["targets"]["wheel"]
        self.assertEqual(wheel["packages"], ["sipar"])
        self.assertEqual(wheel["force-include"], {"SPEC.md": "sipar/SPEC.md"})

    def test_sdist_paths_exist(self):
        include = self.hatch["build"]["targets"]["sdist"]["include"]
        self.assertIn("/SPEC.md", include)                  # the wheel is built from the sdist: it needs the file
        for name in ("/sipar", "/tests", "/examples", "/editors", "/bin"):
            self.assertIn(name, include)                    # the tests read examples/, editors/ and bin/
        for path in include:
            self.assertTrue(path.startswith("/"), path)     # "/x" = only at the top, not any folder named x
            self.assertTrue(os.path.exists(os.path.join(ROOT, path.lstrip("/"))), path)

    def test_readme_and_links(self):
        self.assertEqual(self.project["readme"], "README.md")
        self.assertEqual(self.project["name"], "sipar")
        self.assertLessEqual(len(self.project["description"]), 200)
        for url in self.project["urls"].values():
            self.assertTrue(url.startswith("https://github.com/osimmoapies/sipar"), url)
        self.assertEqual(self.project["dependencies"], [])


class T_StdlibOnly(unittest.TestCase):
    """README and pyproject.toml say "standard library only": every import in sipar/ is checked."""

    def imports(self, path):
        with open(path, encoding="utf-8") as f:
            tree = ast.parse(f.read(), path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    yield a.name.split(".")[0], node.lineno
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                yield (node.module or "").split(".")[0], node.lineno

    def test_every_import_is_stdlib_or_sipar(self):
        allowed = set(sys.stdlib_module_names) | {"sipar"}
        seen, bad = 0, []
        for folder, _, files in os.walk(os.path.join(ROOT, "sipar")):
            for name in files:
                if name.endswith(".py"):
                    path = os.path.join(folder, name)
                    for mod, line in self.imports(path):
                        seen += 1
                        if mod not in allowed:
                            bad.append(f"{os.path.relpath(path, ROOT)}:{line}: {mod}")
        self.assertEqual(bad, [])
        self.assertGreater(seen, 100)                       # the walk really read the package

    def test_the_check_sees_a_third_party_import(self):     # the check itself: it is not blind
        path = os.path.join(tempfile.mkdtemp(), "m.py")
        self.addCleanup(shutil.rmtree, os.path.dirname(path), ignore_errors=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("import os\nimport requests.adapters\nfrom yaml import load\nfrom . import x\n")
        mods = [m for m, _ in self.imports(path)]
        self.assertEqual(mods, ["os", "requests", "yaml"])
        self.assertNotIn("requests", sys.stdlib_module_names)

    def test_no_data_files_besides_python(self):            # the wheel's `packages` takes sipar/ as it is
        extra = []
        for folder, dirs, files in os.walk(os.path.join(ROOT, "sipar")):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            extra += [os.path.join(folder, n) for n in files if not n.endswith(".py")]
        self.assertEqual(extra, [])


class T_Repo(unittest.TestCase):
    """What a visitor of the repository sees: the install line, fences GitHub can colour, no working notes."""

    def test_install_and_clone_lines_name_the_repository(self):
        home = tomllib.loads(read("pyproject.toml"))["project"]["urls"]["Homepage"]
        for name in ("README.md", "README.ru.md"):
            with self.subTest(doc=name):
                text = read(name)
                self.assertIn(f"pip install git+{home}", text)
                self.assertIn(f"git clone {home} && cd sipar", text)
                self.assertNotIn("<this repo>", text)

    def test_fences(self):
        # GitHub does not know `sipar`, so README programs use `rust` (the closest syntax it colours).
        # SPEC.md keeps `sipar`: `sipar spec` puts that text into model prompts.
        self.assertNotIn("```sipar", read("README.md"))
        self.assertGreaterEqual(read("README.md").count("```rust\n"), 3)
        self.assertNotIn("```rust", read("SPEC.md"))
        self.assertGreaterEqual(read("SPEC.md").count("```sipar\n"), 2)

    def test_gitattributes_marks_sipar_files(self):
        rules = [ln.split() for ln in read(".gitattributes").splitlines() if ln.strip() and not ln.startswith("#")]
        self.assertEqual(rules, [["*.sipar", "linguist-language=Rust", "-linguist-detectable"]])

    def test_working_notes_stay_out_of_the_repository(self):
        rules = read(".gitignore").split()
        for rule in ("CASES_*.md", "PROGRESS.md", "research/", "dist/", ".claude/"):
            self.assertIn(rule, rules)
        if not (os.path.isdir(os.path.join(ROOT, ".git")) and shutil.which("git")):
            self.skipTest("not a git checkout")
        p = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        tracked = p.stdout.split("\0")
        self.assertIn("README.md", tracked)                 # the listing is real
        self.assertEqual([n for n in tracked if n.startswith(("CASES_", "PROGRESS", "research/", ".claude/",
                                                              "dist/"))], [])

    def test_quick_start_attack_line_prints_blocked(self):
        [line] = [ln for ln in read("README.md").splitlines() if ln.startswith("(cd examples/injection")]
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        shutil.copytree(os.path.join(ROOT, "examples", "injection"), os.path.join(tmp, "examples", "injection"),
                        ignore=shutil.ignore_patterns(".sipar"))
        pydir = os.path.join(tmp, "py")                     # bin/sipar runs `python3` from PATH
        os.mkdir(pydir)
        os.symlink(sys.executable, os.path.join(pydir, "python3"))
        env = {"PATH": os.pathsep.join([os.path.join(ROOT, "bin"), pydir, "/usr/bin", "/bin"]), "HOME": tmp}
        p = subprocess.run(["sh", "-c", line], cwd=tmp, env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual((p.returncode, p.stderr), (0, ""))
        self.assertIn("BLOCKED (taint): untrusted data (untrusted:ai:assistant) cannot flow into shell.run(cmd)",
                      p.stdout)


class T_ReadmeWays(unittest.TestCase):
    """README "How you still get work done": what the text under the program says is what happens."""

    TRUST = 'trust(name, "a plain .md file name")'
    APPROVE = 'approve(cmd, "Run this command?")'

    def setUp(self):
        if not shutil.which("git"):
            self.skipTest("the program runs git")
        [self.src] = [b for b in re.findall(r"```rust\n(.*?)```", read("README.md"), re.S) if "enum Cmd" in b]
        self.assertEqual((self.src.count(self.TRUST), self.src.count(self.APPROVE)), (1, 1))
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        subprocess.run(["git", "init", "-q", self.dir], check=True, capture_output=True, timeout=30)
        self.notes = os.path.join(self.dir, "notes")
        os.mkdir(self.notes)

    def run_ways(self, src, suggest):
        with open(os.path.join(self.dir, "ways.sipar"), "w", encoding="utf-8") as f:
            f.write(src)
        with open(os.path.join(self.dir, "script.json"), "w", encoding="utf-8") as f:
            json.dump({"pick": ["status"], "suggest": suggest}, f)
        env = {k: v for k, v in os.environ.items() if not k.startswith("SIPAR_")}
        env.update(PYTHONPATH=ROOT, SIPAR_MODEL="mock", SIPAR_MOCK_SCRIPT="script.json")
        return subprocess.run([sys.executable, "-m", "sipar", "run", "ways.sipar"], cwd=self.dir, env=env,
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding="utf-8",
                              timeout=60)

    def test_choice_runs_trust_writes_and_approve_without_a_terminal_is_no(self):
        p = self.run_ways(self.src, ["today.md", "git branch --list"])
        self.assertIn("ways.sipar", p.stdout)               # 1. `git status --short` ran and listed the file
        with open(os.path.join(self.notes, "today.md"), encoding="utf-8") as f:
            self.assertEqual(f.read(), "# Notes\n")         # 2. checked, trusted, written
        self.assertIn("runtime error[denied]: not approved: Run this command?", p.stderr)    # 3.
        self.assertIn("not a terminal", p.stderr)
        self.assertEqual(p.returncode, 1)

    def test_a_name_that_fails_the_check_is_not_written(self):
        for bad in ("../x.md", "notes.txt", "a/b.md"):
            with self.subTest(name=bad):
                self.run_ways(self.src, [bad, "git branch --list"])
                self.assertEqual(os.listdir(self.notes), [])
                self.assertFalse(os.path.exists(os.path.join(self.dir, "x.md")))

    def test_without_trust_the_write_is_blocked(self):
        p = self.run_ways(self.src.replace(self.TRUST, "name"), ["today.md", "git branch --list"])
        self.assertIn("runtime error[taint]: untrusted data (untrusted:ai:suggest) cannot flow into fs.write(path)",
                      p.stderr)
        self.assertEqual((p.returncode, os.listdir(self.notes)), (1, []))

    def test_trust_does_not_widen_the_allow_list(self):
        p = self.run_ways(self.src.replace(self.APPROVE, 'trust(cmd, "test")'), ["today.md", "rm -r notes"])
        self.assertIn("runtime error[capability]", p.stderr)
        self.assertEqual((p.returncode, os.listdir(self.notes)), (1, ["today.md"]))


if __name__ == "__main__":
    unittest.main()
