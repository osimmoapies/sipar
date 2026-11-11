"""Sipar — a safe, typed, replayable language for AI agents.

Python embedding (see sipar/api.py and SPEC.md §10): sipar.load(path).call(name, *args),
sipar.check_source(src), sipar.CheckError, sipar.SiparError.
"""
# This file and __main__.py must still parse and run on an old Python (no f-strings, no 3.8+ syntax), so that
# an old Python gets one clear line instead of a SyntaxError or wrong results (round 10, MED3).
import sys as _sys

__version__ = "0.1.1"
_MIN_PYTHON = (3, 12)


def _old_python_message(version_info=None):
    """The one-line error for a Python older than _MIN_PYTHON, or None when this Python is new enough."""
    v = _sys.version_info if version_info is None else version_info
    if tuple(v[:2]) >= _MIN_PYTHON:
        return None
    return "sipar: needs Python %d.%d or newer (this is %s)" % (
        _MIN_PYTHON[0], _MIN_PYTHON[1], ".".join(str(n) for n in tuple(v)[:3]))


_CLI_MODULES = (__name__, __name__ + ".__main__", __name__ + ".cli")    # `python -m` targets that start the CLI


def _imported_by_runpy():
    """True while `python -m sipar` / `-m sipar.cli` (or runpy.run_module("sipar")) imports this package: a
    runpy frame (runpy is frozen on 3.11+, so its module name is checked, not its file) is working on sipar."""
    f = _sys._getframe(1)
    while f is not None:
        if f.f_globals.get("__name__") == "runpy" and f.f_locals.get("mod_name") in _CLI_MODULES:
            return True
        f = f.f_back
    return False


_TOO_OLD = _old_python_message()
if _TOO_OLD is not None:
    if _imported_by_runpy():            # the command line: one line on stderr, exit 2 (SPEC §9)
        try:
            _sys.stderr.write(_TOO_OLD + "\n")
        except Exception:               # no stderr (`2>&-`: None), a closed or broken one: still exit 2
            pass
        raise SystemExit(2)
    raise ImportError(_TOO_OLD)         # `import sipar` from a host program

_API = ("load", "check_source", "CheckError", "SiparError", "Program")


def __getattr__(name):          # lazy, so `python -m sipar` does not import the whole runtime twice
    if name in _API:
        from . import api
        return getattr(api, name)
    raise AttributeError("module 'sipar' has no attribute %r" % (name,))


def __dir__():
    return sorted(list(globals()) + list(_API))
