"""Python embedding API (SPEC.md §10).

    import sipar
    prog = sipar.load("triage.sipar")            # parses and checks; raises sipar.CheckError
    prog.call("route", "tech")                 # -> "tech"
    prog.call("classify", "text", model="mock",
              mock_script=[{"team": "spam", "urgent": False, "summary": "an ad"}])   # one Verdict reply
    sipar.check_source(src)                    # -> [{"code": ..., "severity": ..., "line": ..., ...}]

Values cross the boundary as plain Python data: Int/Float/Str/Bool/none <-> int/float/str/bool/None,
List <-> list (tuples accepted), Map <-> dict with str keys, records <-> dict of fields, enums <->
"variant" (no fields) or {"variant": {fields}} ({"tag": "variant", ...} is also accepted going in, but only
for an enum that has no field named `tag`).
Labels are dropped at the boundary: Python receives plain values, and values passed in are trusted (the host
program is as trusted as the .sipar file). A result that contains a secret (in a value or a map key) raises
SiparError kind `taint`. Every attribute of a raised SiparError is redacted text.
"""
from __future__ import annotations

import io
import json
import os
from typing import Any

from . import ast as A
from .deep import call_deep
from .runtime import jsondeep
from .runtime.providers import check_script_names
from .errors import SecretRegistry, SiparRuntimeError, SiparSyntaxError, clip, is_tty, use_registry

SiparError = SiparRuntimeError


class CheckError(Exception):
    """The program has syntax/type/effect errors. `.diagnostics` is a list of dicts (as `sipar check --json`)."""

    def __init__(self, diagnostics: list[dict]):
        self.diagnostics = diagnostics
        first = diagnostics[0] if diagnostics else {}
        more = f" (+{len(diagnostics) - 1} more)" if len(diagnostics) > 1 else ""
        super().__init__(f"{first.get('file')}:{first.get('line')}:{first.get('col')}: [{first.get('code')}] "
                         f"{first.get('message')}{more}")


def check_source(src: str, file: str = "<input>") -> list[dict]:
    """Diagnostics (errors and warnings) for source text, as a list of dicts. Never raises for bad source;
    `src` that is not a str (bytes too: decode it first) raises TypeError."""
    from .checker import check_source as _check
    if not isinstance(src, str):
        raise TypeError(f"check_source: src must be str, got {type(src).__name__}")
    if not isinstance(file, str):
        raise TypeError(f"check_source: file must be str, got {type(file).__name__}")
    return [d.to_dict() for d in _check(src, file)[1]]


def load(path: str | os.PathLike) -> "Program":
    """Read, parse and check a .sipar file. OSError passes through (a missing file, no permission, a directory);
    any checker error raises CheckError. The file is read like `sipar check` reads it (round 9, M1): a pipe
    is read to its end, a FIFO with no writer reads as empty; a device (/dev/zero, /dev/null) or a file over
    256 MB raises SiparError kind `io` instead of hanging or filling memory."""
    from .checker import check
    from .fileread import MAX_FILE_BYTES, FileRefused, read_text
    from .parser import parse
    path = _source_path(path)
    failure: Exception | None = None         # raised outside the handler: no __context__ chain (SPEC §10)
    try:
        src = read_text(path, MAX_FILE_BYTES, allow_pipe=True)
    except UnicodeDecodeError:
        failure = SiparError("io", f"cannot read {path}: not UTF-8 text")
    except FileRefused as e:
        failure = SiparError("io", f"cannot read {path}: {e.strerror}")
    if failure is not None:
        raise failure
    try:
        program = parse(src, path)
    except SiparSyntaxError as e:
        failure = CheckError([e.diag.to_dict()])
    if failure is not None:
        raise failure
    diags = check(program, src)
    errors = [d.to_dict() for d in diags if d.severity == "error"]
    if errors:
        raise CheckError(errors)
    return Program(program, path, [d.to_dict() for d in diags])


def _source_path(path: Any, who: str = "load") -> str:
    """load()'s path as a str (round 10, MED1/MED2): an os.PathLike is turned into its str, so Program.path,
    the run and CheckError.diagnostics hold a str like `sipar check --json`. A bytes path (or a PathLike giving
    bytes) is a TypeError, and so is anything that is not a path; a NUL or a lone surrogate is a ValueError."""
    if isinstance(path, os.PathLike):
        path = os.fspath(path)
    if isinstance(path, (bytes, bytearray)):
        raise TypeError(f"{who}: path must be a str or os.PathLike of str, got {type(path).__name__} (decode it first)")
    if not isinstance(path, str):
        raise TypeError(f"{who}: path must be a str or os.PathLike, got {type(path).__name__}")
    try:
        if "\0" in path:
            raise ValueError
        os.fsencode(path)
    except (UnicodeError, ValueError):
        raise ValueError(f"{who}: path must be a usable file path (no NUL, no lone surrogate)") from None
    return path


class Program:
    def __init__(self, program: A.Program, path: str, warnings: list[dict]):
        self.program = program
        self.path = _source_path(path, "Program")      # built by hand: the same rules as load() (round 10)
        # the program's folder (.sipar/, memory, MCP pins, relative `allow fs` paths) is fixed now: a relative
        # path must not move with a later os.chdir() of the host. Errors still name the file as given.
        self._run_file = os.path.abspath(self.path) if self.path and not self.path.startswith("<") else self.path
        self.warnings = warnings
        self.functions = {it.name: it for it in program.items if isinstance(it, A.FnDecl)}

    def call(self, name: str, *args: Any, model: str | None = "mock", mock_script: Any = None,
             out=None, journal: str | None = None, **kwargs: Any) -> Any:
        """Call a Sipar function with Python values and return a Python value.

        model="mock" (the default) answers every ai/agent fn with the mock provider (no network);
        pass a model or chain ("openrouter/x | mock") to override @model, or model=None to use the
        program's own @model / SIPAR_MODEL. `out` receives print() output (default: sys.stdout).
        `journal` writes a run journal to that path. Errors raise SiparError (.kind, .message)."""
        from .runtime.decode import TOO_DEEP, from_json, too_deep
        from .runtime.interp import Interp
        from .runtime.journal import Journal
        from .runtime.values import EMPTY

        journal, mock_script = _check_call_options(model, mock_script, out, journal)
        decl = self.functions.get(name)
        if decl is None:
            raise SiparError("type", f"the program has no function '{name}'")
        params = decl.params
        if len(args) > len(params):
            raise SiparError("type", f"{name} takes {len(params)} argument(s), got {len(args)}")
        given = dict(zip((p.name for p in params), args))
        for k, v in kwargs.items():
            if k not in {p.name for p in params}:
                raise SiparError("type", f"{name} has no parameter '{k}'")
            if k in given:
                raise SiparError("type", f"{name}: parameter '{k}' given twice")
            given[k] = v
        failure: SiparError | None = None
        try:
            # M5 (round 6): every key of a {fn name: replies} script names an ai / agent fn
            check_script_names(mock_script, {n for n, d in self.functions.items() if d.kind in ("ai", "agent")})
            j = Journal(path=journal)
        except SiparRuntimeError as e:
            failure = _clean_error(e)
        if failure is not None:
            raise failure          # outside the handler: no __context__ chain
        it = Interp(self.program, self._run_file, journal=j, out=_HostOut(out) if out is not None else None, err_out=io.StringIO(), stdin=io.StringIO(""),
                    mock_script=mock_script, model_override=model)
        scope = use_registry(SecretRegistry())     # this call's secrets only (round 5, C1)
        scope.__enter__()
        try:
            # all of it on the big-stack thread, like `sipar run` (round 5, F5): the arguments and the result
            # are converted there too, since the host's recursion limit is its own again (L6, round 6)
            def body():
                vals = {}
                for p in params:
                    if p.name in given:
                        if too_deep(given[p.name]):
                            raise SiparRuntimeError("value", f"{name}.{p.name}: an argument is {TOO_DEEP}")
                        vals[p.name] = from_json(_py_in(given[p.name], p.type, it.tenv, f"{name}.{p.name}"),
                                                 p.type, it.tenv, EMPTY, f"{name}.{p.name}")
                it.init_globals()
                return _py_out(it.call_fn(decl, [], vals), f"{name}()")
            return call_deep(body)
        except SiparRuntimeError as e:
            if e.file == self._run_file:
                e.file = self.path          # the name the host gave, not the absolute one used for the folder
            failure = _clean_error(e)
        except RecursionError:
            # reachable: call_deep runs fn on this (small-stack) thread when the platform refuses a big-stack
            # thread, and deep.py notes a RecursionError is still possible for absurd inputs (round 7, test)
            failure = SiparError("value", f"{name}: an argument or value is nested too deeply")
        finally:
            j.close()
            scope.__exit__(None, None, None)
        raise failure          # raised outside the handler: no __context__ chain back to the raw error


def _check_call_options(model: Any, mock_script: Any, out: Any, journal: Any) -> tuple[str | None, Any]:
    """Host mistakes in call() options raise TypeError / ValueError up front (round 5, C7/C8), never a raw
    AttributeError from deep inside the run or a silent fallback. Returns (journal path or None, script)."""
    if model is not None:
        if not isinstance(model, str):
            raise TypeError(f"call: model must be a str (a model or chain) or None, got {type(model).__name__}")
        if not model.strip():
            raise ValueError("call: model is empty; pass a model or chain such as \"mock\", or None")
    if mock_script is not None:
        if not isinstance(mock_script, (list, tuple, dict)):
            raise TypeError(f"call: mock_script must be a list of replies or a dict {{fn name: replies}}, "
                            f"got {type(mock_script).__name__}")
        if isinstance(mock_script, dict) and not all(isinstance(k, str) for k in mock_script):
            raise TypeError("call: mock_script dict keys must be function names (str)")
        try:
            jsondeep.dumps(mock_script, allow_nan=False)
        except (TypeError, ValueError, RecursionError):
            raise TypeError("call: mock_script replies must be JSON data (str, int, float, bool, None, "
                            "list, dict)") from None
    if out is not None and not callable(getattr(out, "write", None)):
        raise TypeError(f"call: out must have a write() method, got {type(out).__name__}")
    if isinstance(mock_script, tuple):
        mock_script = list(mock_script)
    if journal is None:
        return None, mock_script
    if not isinstance(journal, (str, os.PathLike)):
        raise TypeError(f"call: journal must be a path (str or os.PathLike) or None, got {type(journal).__name__}")
    path = os.fspath(journal)
    if not isinstance(path, str) or not path:
        raise ValueError("call: journal must be a non-empty str path")
    try:                    # round 9 (L4): not a raw "embedded null byte" / UnicodeEncodeError from open()
        if "\0" in path:
            raise ValueError
        os.fsencode(path)
    except (UnicodeError, ValueError):
        raise ValueError("call: journal must be a usable file path (no NUL, no lone surrogate)") from None
    return path, mock_script


class _HostOut:
    """The host's `out` for one call (R8C-9, round 8): an exception from its write() or flush() is a Sipar
    error kind `io`, like any failed write, instead of a raw ValueError from deep inside the run."""
    __slots__ = ("_out",)

    def __init__(self, out: Any) -> None:
        self._out = out

    def _do(self, what: str, *args: Any) -> Any:
        try:
            return getattr(self._out, what)(*args)
        except SiparRuntimeError:
            raise
        except Exception as e:
            raise SiparRuntimeError("io", clip(f"the host's out.{what}() raised {type(e).__name__}"
                                               + (f": {e}" if str(e) else ""), 300)) from None

    def write(self, text: str) -> Any:
        return self._do("write", text)

    def flush(self) -> None:
        if callable(getattr(self._out, "flush", None)):
            self._do("flush")

    def isatty(self) -> bool:
        return is_tty(self._out)


def _clean_error(e: SiparRuntimeError) -> SiparError:
    """A fresh SiparError for the host: every attribute is redacted text. fail() keeps the labelled message in
    .value and the kind argument in .kind_value for `catch e` inside Sipar; neither must reach Python raw."""
    from .errors import redact_text
    err = SiparError(e.kind, e.message, e.line, e.col, redact_text(e.file))
    err.value = err.message
    err.kind_value = err.kind
    return err


# ------------------------------------------------------------------ conversion

def _py_in(x: Any, t: A.TypeExpr | None, tenv, path: Any) -> Any:
    """Python value -> the JSON shape decode.from_json expects for type t (validation happens there).
    The caller has checked decode.too_deep(x); `path` is a lazy decode.Path, formatted only for an error."""
    from .runtime.decode import Path, tag_field_enum
    if isinstance(t, A.TOptional):
        return None if x is None else _py_in(x, t.inner, tenv, path)
    if not isinstance(t, A.TName):
        return x
    if isinstance(x, tuple):
        x = list(x)
    n = t.name
    if n == "List" and isinstance(x, list):
        return [_py_in(y, t.args[0] if t.args else None, tenv, Path(path, f"[{i}]")) for i, y in enumerate(x)]
    if n == "Map" and isinstance(x, dict):
        for k in x:
            if not isinstance(k, str):
                raise SiparError("decode", f"{path}: Map keys must be str, got {type(k).__name__}")
        return {k: _py_in(y, t.args[0] if t.args else None, tenv, Path(path, f".{k}")) for k, y in x.items()}
    if n in tenv.records and isinstance(x, dict):
        types = dict(tenv.records[n])
        return {k: _py_in(y, types.get(k), tenv, Path(path, f".{k}")) for k, y in x.items()}
    if n in tenv.enums and isinstance(x, dict):
        variants = {v.name: v for v in tenv.enums[n]}
        if len(x) == 1:
            (tag, fields), = x.items()
            if tag in variants and isinstance(fields, dict):     # {"variant": {fields}}: stays in that form
                types = dict(variants[tag].fields)
                return {tag: {k: _py_in(v, types.get(k), tenv, Path(path, f".{k}")) for k, v in fields.items()}}
        tag = x.get("tag")
        if tag in variants and not tag_field_enum(variants.values()):
            # {"tag": "variant", ...} only for an enum without a field named `tag` (else it is ambiguous and
            # from_json rejects it with a decode error naming the {"variant": {fields}} form)
            types = dict(variants[tag].fields)
            return {k: (v if k == "tag" else _py_in(v, types.get(k), tenv, Path(path, f".{k}"))) for k, v in x.items()}
    return x


def _py_out(v: Any, path: str) -> Any:
    """Sipar value -> plain Python data. Linear: one shared set of the containers on the current path (a
    cycle check, not a copy per level) and the error path is built only when an error is raised. A secret in
    any leaf or map key, or in the own labels of a picked container (SPEC §6), raises `taint`; nesting deeper than decode.MAX_VALUE_DEPTH raises `value`."""
    from .runtime.decode import MAX_VALUE_DEPTH
    from .runtime.values import EnumVal, LDict, LFloat, LFn, LInt, LList, LRecord, LStr, RangeVal, Record

    on_path: set[int] = set()
    trail: list[Any] = []                      # keys / indexes of the current position, for error paths only

    def where() -> str:
        return path + "".join(f"[{t}]" if isinstance(t, int) else f".{t}" for t in trail)

    def secret(x: Any) -> bool:      # a secret leaf, or a list/map/record/function/range picked or built with
        return (isinstance(x, (LStr, LInt, LFloat, RangeVal, LList, LDict, LRecord, LFn))    # a secret (SPEC §6)
                and any(l.startswith("secret:") for l in x.labels))

    def step(t: Any, y: Any) -> Any:
        if len(trail) >= MAX_VALUE_DEPTH:      # a fixed limit, not the stack: the host must be able to walk it
            raise SiparError("value", f"{path}: the result is nested too deeply to return to Python (more than "
                                      f"{MAX_VALUE_DEPTH:,} levels)")
        trail.append(t)
        r = walk(y)
        trail.pop()
        return r

    def walk(x: Any) -> Any:
        if x is None or x is True or x is False:
            return x
        if secret(x):
            raise SiparError("taint", f"{where()}: the result contains a secret; it cannot be returned to Python")
        if isinstance(x, str):
            return str.__str__(x)
        if isinstance(x, int):
            return int(x)
        if isinstance(x, float):
            return float(x)
        if isinstance(x, RangeVal):
            return list(range(x.start, x.end))
        if isinstance(x, (list, dict, Record, EnumVal)):
            if id(x) in on_path:
                raise SiparError("value", f"{where()}: the result contains itself (a cycle)")
            on_path.add(id(x))
            if isinstance(x, list):
                out: Any = [step(i, y) for i, y in enumerate(x)]
            elif isinstance(x, dict):
                out = {}
                for k, y in x.items():
                    if secret(k):
                        raise SiparError("taint", f"{where()}: a map key of the result is a secret; it cannot be "
                                                  f"returned to Python")
                    ks = str.__str__(k) if isinstance(k, str) else str(k)
                    out[ks] = step(ks, y)
            elif isinstance(x, Record):
                out = {k: step(k, y) for k, y in x.fields.items()}
            elif not x.fields:
                out = x.variant
            else:
                out = {x.variant: {k: step(k, y) for k, y in x.fields.items()}}
            on_path.discard(id(x))
            return out
        raise SiparError("type", f"{where()}: a function value cannot be returned to Python")

    try:
        return walk(v)
    except RecursionError:
        pass
    raise SiparError("value", f"{path}: the result is nested too deeply to return to Python")
