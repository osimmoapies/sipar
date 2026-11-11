#!/usr/bin/env python3
"""Builds the playground site (GitHub Pages): the static page, the generated data and the Python runtime.

    python3 tools/build_site.py --out _site --fetch-pyodide

    scenarios.json      the scenarios of playground/scenarios with their files inside
    sipar_bundle.json   the interpreter itself: every .py of the sipar package, path -> source
    build.json          the versions shown in the footer
    pyodide/            CPython for the browser (Pyodide), taken from its npm package; the download is
                        checked against the sha512 written below, so the site serves exactly that release

Nothing generated is kept in the repository: the Pages workflow runs this on every push to main.
"""
import argparse
import base64
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tarfile
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = ["index.html", "style.css", "app.js", "worker.js", "glue.py", "og.png"]
SAFE_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\Z")

PYODIDE_VERSION = "314.0.7"
PYODIDE_URL = f"https://registry.npmjs.org/pyodide/-/pyodide-{PYODIDE_VERSION}.tgz"
PYODIDE_SHA512 = "0YvXxEhfEdpLfb/XkM2BFAeMROq0iMUX2bzzH9pOttyMcWkwq+HbE5uyuGD82LN7y2q+SNvi/6V5JEsOlD2R1A=="
PYODIDE_FILES = ["pyodide.mjs", "pyodide.asm.mjs", "pyodide.asm.wasm", "python_stdlib.zip", "pyodide-lock.json"]


def _read(*parts: str) -> str:
    with open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def load_scenarios(root: str = ROOT) -> list[dict]:
    """The scenarios in page order. Each file gets its text: from the scenario folder, or from `from` (a path
    inside the repository, so an example is shown as it is shipped, not as a copy)."""
    base = os.path.join(root, "playground", "scenarios")
    out = []
    for sid in json.loads(_read(base, "index.json")):
        if not SAFE_NAME.match(sid):
            raise ValueError(f"scenario id {sid!r}")
        s = json.loads(_read(base, sid, "scenario.json"))
        s["id"] = sid
        names = set()
        for f in s["files"]:
            if not SAFE_NAME.match(f["name"]) or f["name"] in names:
                raise ValueError(f"{sid}: file name {f['name']!r}")
            names.add(f["name"])
            src = f.pop("from", None)
            f["text"] = _read(root, *src.split("/")) if src else _read(base, sid, f["name"])
        for key in ("main", "model"):
            if s.get(key) is not None and s[key] not in names:
                raise ValueError(f"{sid}: {key} {s[key]!r} is not one of its files")
        for rule in s.get("web") or []:
            if "file" in rule and rule["file"] not in names:
                raise ValueError(f"{sid}: web file {rule['file']!r} is not one of its files")
        out.append(s)
    return out


def bundle(root: str = ROOT) -> dict[str, str]:
    """path -> source of every Python file of the package (sipar/cli.py, sipar/runtime/effects.py, ...)."""
    out = {}
    pkg = os.path.join(root, "sipar")
    for d, dirs, names in os.walk(pkg):
        dirs[:] = sorted(x for x in dirs if x != "__pycache__")
        for n in sorted(names):
            if n.endswith(".py"):
                p = os.path.join(d, n)
                out[os.path.relpath(p, root).replace(os.sep, "/")] = _read(p)
    return out


def version(root: str = ROOT) -> str:
    return re.search(r'__version__\s*=\s*"([^"]+)"', _read(root, "sipar", "__init__.py")).group(1)


def unpack_pyodide(tarball: bytes, dest: str, sha512: str = PYODIDE_SHA512) -> None:
    """Writes the five runtime files of the npm package into dest. Refuses any other tarball."""
    got = base64.b64encode(hashlib.sha512(tarball).digest()).decode("ascii")
    if got != sha512:
        raise ValueError(f"the Pyodide package has sha512 {got}, expected {sha512}; nothing was unpacked")
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as tar:
        for name in PYODIDE_FILES:
            with open(os.path.join(dest, name), "wb") as fh:        # the name is ours, not the archive's
                fh.write(tar.extractfile(f"package/{name}").read())


def build(out: str, root: str = ROOT, commit: str = "", pyodide: bytes | None = None) -> list[str]:
    """Writes the site into out. `pyodide`: the npm tarball; without it the page has no Python to run."""
    os.makedirs(out, exist_ok=True)
    for name in STATIC:
        shutil.copyfile(os.path.join(root, "playground", name), os.path.join(out, name))
    made = {"scenarios.json": load_scenarios(root), "sipar_bundle.json": bundle(root),
            "build.json": {"sipar": version(root), "commit": commit[:40], "pyodide": PYODIDE_VERSION}}
    for name, data in made.items():
        with open(os.path.join(out, name), "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, separators=(",", ":"))
    open(os.path.join(out, ".nojekyll"), "w").close()       # Pages: serve the files as they are
    names = [*STATIC, *made, ".nojekyll"]
    if pyodide is not None:
        unpack_pyodide(pyodide, os.path.join(out, "pyodide"))
        names += [f"pyodide/{n}" for n in PYODIDE_FILES]
    return sorted(names)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", required=True, help="folder to write the site into")
    ap.add_argument("--commit", default=os.environ.get("GITHUB_SHA", ""), help="commit shown in the footer")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pyodide", metavar="TGZ", help=f"the npm package pyodide-{PYODIDE_VERSION}.tgz on disk")
    src.add_argument("--fetch-pyodide", action="store_true", help=f"download it from {PYODIDE_URL}")
    a = ap.parse_args(argv)
    if a.pyodide:
        with open(a.pyodide, "rb") as fh:
            tarball = fh.read()
    else:
        with urllib.request.urlopen(PYODIDE_URL, timeout=120) as r:
            tarball = r.read()
    for name in build(a.out, commit=a.commit, pyodide=tarball):
        print(name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
