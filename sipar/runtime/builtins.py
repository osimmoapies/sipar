"""Pure standard library: global functions and methods on Str / List / Map (see sipar/stdlib.py)."""
from __future__ import annotations

import json
import math
from typing import Any

from ..errors import SiparRuntimeError, flush as _flush
from ..lexer import normalize_newlines
from . import effects as E
from . import jsondeep
from . import memory as M
from .values import (EMPTY, MAX_STR, STR_TOO_LARGE, RangeVal, check_int, check_mutable, dumps, equal, has_function, is_num, kind_of, label_written, labels_of,
                     mutated, new_list, own_labels, render, select, to_json, with_labels)

MAX_ITEMS = 10_000_000


def lab(v: Any, *srcs: Any) -> Any:
    ls: set = set()
    for s in srcs:
        ls |= labels_of(s)
    return with_labels(v, ls) if ls else with_labels(v, EMPTY)


def _num(v: Any, fname: str) -> Any:
    if not is_num(v):
        raise SiparRuntimeError("type", f"{fname}: expected a number, got {kind_of(v)}")
    return v


def _int(v: Any, fname: str) -> int:
    if not isinstance(v, int) or isinstance(v, bool):
        raise SiparRuntimeError("type", f"{fname}: expected Int, got {kind_of(v)}")
    return int(v)


def _str(v: Any, fname: str) -> str:
    if not isinstance(v, str):
        raise SiparRuntimeError("type", f"{fname}: expected Str, got {kind_of(v)}")
    return str.__str__(v)


# ------------------------------------------------------------------ global functions
# Each takes (rt, a: dict[param -> value]).

def f_print(rt, a):
    v = a["value"]
    E.check_sinks("print", {"value": v})
    text = render(v)
    if E.is_tty(rt.out):        # a terminal: escape control chars so data cannot drive it (S3, round 5, SPEC §5)
        text = E.escape_controls(text)
    rt.out.write(text + "\n")
    _flush(rt.out)
    return None


def _minmax(a, fname, pick):
    x, y = _num(a["a"], fname), _num(a["b"], fname)
    if isinstance(x, float) or isinstance(y, float):
        fx, fy = float(x), float(y)
        if math.isnan(fx) or math.isnan(fy):      # NaN in -> NaN out, whatever the order (SPEC §5, round 5)
            r = math.nan
        elif fx == fy == 0.0:                      # -0.0 < 0.0 here, so min/max do not depend on the order
            neg = math.copysign(1.0, fx) < 0 or math.copysign(1.0, fy) < 0
            pos = math.copysign(1.0, fx) > 0 or math.copysign(1.0, fy) > 0
            r = -0.0 if (neg if pick is min else not pos) else 0.0
        else:
            r = float(pick(fx, fy))
    else:
        r = int(pick(x, y))
    return lab(r, x, y)


def f_abs(rt, a):
    x = _num(a["x"], "abs")
    return lab(abs(float(x)) if isinstance(x, float) else abs(int(x)), x)


def f_round(rt, a):
    x = _num(a["x"], "round")
    if isinstance(x, int):
        return lab(int(x), x)
    if math.isnan(x) or math.isinf(x):
        raise SiparRuntimeError("value", f"round: cannot round {render(a['x'], redact=True)}")
    a = abs(float(x))
    f = math.floor(a)                   # exact; a - f is exact too, so no `+ 0.5` rounding error
    r = f + (1 if a - f >= 0.5 else 0)  # half away from zero: 2.5 -> 3, -2.5 -> -3
    return lab(int(r if x >= 0 else -r), x)


def f_floor(rt, a):
    x = _num(a["x"], "floor")
    if isinstance(x, float) and (math.isnan(x) or math.isinf(x)):
        raise SiparRuntimeError("value", f"floor: cannot floor {render(a['x'], redact=True)}")
    return lab(int(math.floor(x)), x)


def f_range(rt, a):
    s, e = _int(a["start"], "range"), _int(a["end"], "range")
    if e - s > MAX_ITEMS:
        raise SiparRuntimeError("value", f"range({render(a['start'], redact=True)}, {render(a['end'], redact=True)}) is too large (max {MAX_ITEMS} items)")
    ls = labels_of(a["start"]) | labels_of(a["end"])
    return [with_labels(i, ls) for i in range(s, e)]


def f_fail(rt, a):
    _str(a["kind"], "fail")
    # R7-1/R7-2: the kind leaves the runtime as text (stderr, Python API, tool-error feedback to a model, journal).
    # A secret-labelled kind (any form: transformed, short, built from a secret) is shown as «secret:NAME» -- by
    # its labels, not only by matching registered values. An untrusted kind is shown as is (escaped on a
    # terminal). `catch e` still gets the labelled kind through kind_value.
    kind, kind_value = render(a["kind"], redact=True), a["kind"]
    if not kind.strip():                # an empty kind used to print as "runtime error[]" (round 11)
        kind, kind_value = "fail", with_labels("fail", labels_of(a["kind"]))
    err = SiparRuntimeError(kind, render(a["message"], redact=True))
    err.value = a["message"]            # keeps labels (secret-safe rendering in the CLI)
    err.kind_value = kind_value         # `catch e` gives e.kind with the labels of the kind argument
    raise err


def f_json_encode(rt, a):
    v = a["value"]
    E.check_sinks("json.encode", {"value": v})
    if has_function(v):             # a function has no JSON form (it used to be written as a string)
        raise SiparRuntimeError("value", "json.encode: a function value cannot be encoded as JSON")
    try:
        data = to_json(v)
        if _non_finite(data):       # JSON has no NaN/Infinity (SPEC §5): never emit them
            raise SiparRuntimeError("value", "json.encode: NaN and infinite numbers are not valid JSON")
        return lab(jsondeep.dumps(data, ensure_ascii=False, allow_nan=False), v)
    except (ValueError, RecursionError) as e:
        raise SiparRuntimeError("value", f"json.encode: {e}")


def _non_finite(d: Any) -> bool:
    stack = [d]
    while stack:
        x = stack.pop()
        if isinstance(x, float) and not math.isfinite(x):
            return True
        if isinstance(x, dict):
            stack.extend(x.values())
        elif isinstance(x, list):
            stack.extend(x)
    return False


FUNCS = {
    "print": f_print,
    "input": lambda rt, a: E.input_line(rt, a["prompt"]),
    "min": lambda rt, a: _minmax(a, "min", min),
    "max": lambda rt, a: _minmax(a, "max", max),
    "abs": f_abs,
    "round": f_round,
    "floor": f_floor,
    "range": f_range,
    "trust": lambda rt, a: E.trust(rt, a["value"], a["reason"]),
    "approve": lambda rt, a: E.approve(rt, a["value"], a["question"]),
    "fail": f_fail,
    "sleep": lambda rt, a: E.sleep(rt, _num(a["seconds"], "sleep")),
    "http.get": lambda rt, a: E.http_request(rt, "GET", a["url"], None, a.get("headers")),
    "http.post": lambda rt, a: E.http_request(rt, "POST", a["url"], a["body"], a.get("headers")),
    "fs.read": lambda rt, a: E.fs_read(rt, a["path"]),
    "fs.write": lambda rt, a: E.fs_write(rt, a["path"], a["text"]),
    "fs.exists": lambda rt, a: E.fs_exists(rt, a["path"]),
    "shell.run": lambda rt, a: E.shell_run(rt, a["cmd"]),
    "env.get": lambda rt, a: E.env_get(rt, a["name"]),
    "env.secret": lambda rt, a: E.env_secret(rt, a["name"]),
    "time.now": lambda rt, a: E.time_now(rt),
    "random.int": lambda rt, a: E.random_int(rt, _int(a["lo"], "random.int"), _int(a["hi"], "random.int")),
    "memory.save": lambda rt, a: M.save(rt, a["key"], a["value"]),
    "memory.load": lambda rt, a: M.load(rt, a["key"], a.get("<type>")),
    "memory.delete": lambda rt, a: M.delete(rt, a["key"]),
    "memory.keys": lambda rt, a: M.keys(rt),
    "json.encode": f_json_encode,
}


# ------------------------------------------------------------------ Str methods

def _check_size(n: int, what: str) -> None:
    if n > MAX_ITEMS:
        raise SiparRuntimeError("value", f"{what}: result too large ({n} > {MAX_ITEMS})")


def _case_len(raw: str, name: str) -> int:
    """len(raw.upper()) / len(raw.lower()) without building it: counted in pieces, stopping past the Str
    limit. Exact, as no case mapping changes length by context (final sigma is one char either way)."""
    n, step = 0, 1 << 20
    for i in range(0, len(raw), step):
        piece = raw[i:i + step]
        n += len(piece.upper() if name == "upper" else piece.lower())
        if n > MAX_STR:
            break
    return n


def m_str(rt, s: Any, name: str, args: list) -> Any:
    raw = str.__str__(s)
    if name == "len":
        return lab(len(raw), s)
    if name in ("upper", "lower"):     # a case change can make a Str longer ("ß" -> "SS"), up to 3 times
        if len(raw) > MAX_STR // 3 and not raw.isascii() and _case_len(raw, name) > MAX_STR:
            raise SiparRuntimeError("value", f"{name}: {STR_TOO_LARGE}")    # before the result is built (F3)
        return lab(raw.upper() if name == "upper" else raw.lower(), s)
    if name == "trim":
        return lab(raw.strip(), s)
    if name == "split":
        sep = _str(args[0], "split")
        _check_size(len(raw) if sep == "" else raw.count(sep) + 1, "split")      # the list cap (F9, round 6)
        parts = list(raw) if sep == "" else raw.split(sep)
        return [lab(p, s, args[0]) for p in parts]
    if name == "lines":
        # only \n, \r\n and \r end a line (not VT, FF, U+001C..U+001E, U+0085, U+2028/9 as str.splitlines does);
        # a final line break does not start another line (F9 and trivia, round 6)
        text = normalize_newlines(raw)
        _check_size(text.count("\n") + (1 if text and not text.endswith("\n") else 0), "lines")
        parts = text.split("\n")
        if parts[-1] == "":
            parts.pop()
        return [lab(p, s) for p in parts]
    if name == "contains":
        return _str(args[0], "contains") in raw
    if name == "starts_with":
        return raw.startswith(_str(args[0], "starts_with"))
    if name == "ends_with":
        return raw.endswith(_str(args[0], "ends_with"))
    if name == "replace":
        old, new = _str(args[0], "replace"), _str(args[1], "replace")
        if old == "":
            return lab(raw, s, args[0], args[1])
        _check_size(len(raw) + raw.count(old) * max(0, len(new) - len(old)), "replace")
        return lab(raw.replace(old, new), s, args[0], args[1])
    if name == "find":
        i = raw.find(_str(args[0], "find"))
        return None if i < 0 else lab(i, s, args[0])
    if name == "repeat":
        n = _int(args[0], "repeat")
        _check_size(len(raw) * max(n, 0), "repeat")
        return lab(raw * max(n, 0), s, args[0])
    raise SiparRuntimeError("type", f"Str has no method '{name}'")


# ------------------------------------------------------------------ List methods

def _sort_key_check(items: list, what: str) -> None:
    kinds = {kind_of(x) for x in items}
    if kinds - {"Int", "Float", "Str"} or ("Str" in kinds and len(kinds) > 1):
        raise SiparRuntimeError("type", f"{what}: items must all be numbers or all Str, got {sorted(kinds)}")


def _nan_last(x: Any) -> tuple:
    """Sort key: NaN after every number, NaNs keep their order (F10, round 6: NaN compares false both ways,
    so plain sorted() gave an order that depended on where the NaN stood)."""
    return (x != x, x)


def m_list(rt, xs: list, name: str, args: list) -> Any:
    """SPEC §6 selection: what is pulled out of xs carries xs's own labels (`own`); a new list made from xs
    keeps them; a count or sort keys that are labelled label the new list."""
    call = rt.call_value
    own = own_labels(xs)

    def items() -> list:            # the items as pulled out of xs (own labels added)
        return [select(x, own) for x in xs] if own else list(xs)

    if name == "len":
        return lab(len(xs), xs)
    if name == "push":
        check_mutable(xs)
        _check_size(len(xs) + 1, "push")
        x = label_written(args[0], own)
        xs.append(x)
        mutated(xs, labels_of(x))
        return None
    if name == "pop":
        check_mutable(xs)
        if not xs:
            return None
        x = xs.pop()
        mutated(xs, EMPTY, (x,))
        return select(x, own)
    if name == "map":
        return new_list((call(args[0], [x]) for x in items()), own)
    if name == "filter":
        out = []
        for x in items():
            r = call(args[0], [x])
            if r is not True and r is not False:
                raise SiparRuntimeError("type", "filter: the function must return Bool")
            if r:
                out.append(x)
        return new_list(out, own)
    if name == "reduce":
        acc = args[0]
        for x in items():
            acc = call(args[1], [acc, x])
        return select(acc, own)
    if name in ("any", "all"):
        for x in items():
            r = call(args[0], [x])
            if r is not True and r is not False:
                raise SiparRuntimeError("type", f"{name}: the function must return Bool")
            if name == "any" and r:
                return True
            if name == "all" and not r:
                return False
        return name == "all"
    if name == "join":
        sep = _str(args[0], "join")
        texts, total = [], 0
        for x in xs:                # the Str limit is checked as the pieces come, before the join (round 10, F3)
            t = render(x)
            total += len(t) + (len(sep) if texts else 0)
            if total > MAX_STR:
                raise SiparRuntimeError("value", f"join: {STR_TOO_LARGE}")
            texts.append(t)
        return lab(sep.join(texts), xs, args[0])
    if name == "sort":
        _sort_key_check(xs, "sort")
        return new_list(sorted(xs, key=_nan_last), labels_of(xs))     # the order depends on every item
    if name == "sort_by":
        pulled = items()
        keys = [call(args[0], [x]) for x in pulled]
        _sort_key_check(keys, "sort_by")
        order = sorted(range(len(xs)), key=lambda i: _nan_last(keys[i]))
        return new_list((xs[i] for i in order), own | labels_of(keys))
    if name == "reverse":
        return new_list(reversed(xs), own)
    if name == "contains":
        return any(equal(x, args[0]) for x in xs)
    if name == "index_of":
        for i, x in enumerate(xs):
            if equal(x, args[0]):
                return lab(i, xs, args[0])
        return None
    if name in ("first", "last"):
        if not xs:
            return None
        x = xs[0] if name == "first" else xs[-1]
        return lab(x, xs) if isinstance(x, (str, int, float)) else select(x, own)
    if name == "sum":
        total: Any = 0
        for x in xs:
            _num(x, "sum")
            try:
                total = total + (float(x) if isinstance(x, float) else int(x))
            except OverflowError:           # an Int too large to mix with a Float, as `+` says
                raise SiparRuntimeError("value", "sum: number too large for '+'") from None
            if isinstance(total, int):
                check_int(total)            # the Int limit of `+` (round 10, F4), at the first sum over it
        return lab(total, xs)
    if name in ("take", "skip"):
        n = max(_int(args[0], name), 0)
        return new_list(xs[:n] if name == "take" else xs[n:], own | labels_of(args[0]))
    raise SiparRuntimeError("type", f"List has no method '{name}'")


# ------------------------------------------------------------------ Map methods

def m_map(rt, m: dict, name: str, args: list) -> Any:
    own = own_labels(m)
    if name == "len":
        return lab(len(m), m)
    if name == "keys":
        return new_list(m.keys(), own)
    if name == "values":
        return new_list(m.values(), own)
    if name == "has":
        return _str(args[0], "has") in m
    if name == "get":
        return select(m.get(_str(args[0], "get")), own | labels_of(args[0]))
    if name == "remove":
        check_mutable(m)
        x = m.pop(_str(args[0], "remove"), None)
        mutated(m, EMPTY, None)
        return select(x, own | labels_of(args[0]))
    raise SiparRuntimeError("type", f"Map has no method '{name}'")


def call_method(rt, recv: Any, name: str, args: list) -> Any:
    if isinstance(recv, RangeVal):        # same size limit and labels as everywhere else a range is used
        if recv.end - recv.start > MAX_ITEMS:
            raise SiparRuntimeError("value", f"range is too large (max {MAX_ITEMS} items)")
        recv = new_list((with_labels(i, recv.labels) for i in range(recv.start, recv.end)), recv.labels)
    if isinstance(recv, str):
        return m_str(rt, recv, name, args)
    if isinstance(recv, list):
        return m_list(rt, recv, name, args)
    if isinstance(recv, dict):
        return m_map(rt, recv, name, args)
    raise SiparRuntimeError("type", f"{kind_of(recv)} has no method '{name}'")
