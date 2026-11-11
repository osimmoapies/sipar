"""json.loads / json.dumps that also handle values nested up to MAX_VALUE_DEPTH on every supported Python.

Python 3.12's C json codec stops at a fixed depth of about 10,000 levels, whatever the stack size, while Sipar
promises 20,000 (decode.MAX_VALUE_DEPTH, SPEC §5; README: Python 3.12+). The first attempt is always the C
codec, so normal values cost nothing extra. Only when it raises RecursionError:
- loads retries with the standard library's pure-Python scanner (plain recursion, bounded by the Python
  recursion limit, which sipar.deep.call_deep raises);
- dumps retries with the iterative encoder below (the standard pure-Python encoder nests one generator per
  level, so a deep value would cost depth² steps). Its output is the same text as json.dumps (round 5, D3).
"""
from __future__ import annotations

import json
import json.encoder
import json.scanner
import sys
from typing import Any

_INF = float("inf")


class PyDecoder(json.JSONDecoder):
    """json.JSONDecoder that scans with the pure-Python scanner (no fixed C depth limit)."""

    def __init__(self, **kw: Any) -> None:
        super().__init__(**kw)
        self.scan_once = json.scanner.py_make_scanner(self)


class NumberTooLarge(ValueError):
    """Valid JSON holding an integer with more digits than Python converts (sys.get_int_max_str_digits(),
    4300 by default). A ValueError like any bad JSON, but callers can say what is wrong (round 6)."""


def _int(s: str) -> int:
    try:
        return int(s)
    except ValueError:              # the scanner only passes well-formed integers: this is the digit limit
        raise NumberTooLarge(f"a number too large to read ({len(s.lstrip('-')):,} digits; the limit is "
                             f"{sys.get_int_max_str_digits():,})") from None


def loads(text: str, **kw: Any) -> Any:
    """json.loads that retries past the C codec's depth limit; a huge integer raises NumberTooLarge
    (unless the caller passes its own parse_int)."""
    kw.setdefault("parse_int", _int)
    try:
        return json.loads(text, **kw)
    except RecursionError:
        pass
    return json.loads(text, cls=PyDecoder, **kw)     # outside the handler: no chained RecursionError


def dumps(obj: Any, *, ensure_ascii: bool = True, sort_keys: bool = False, allow_nan: bool = True) -> str:
    try:
        return json.dumps(obj, ensure_ascii=ensure_ascii, sort_keys=sort_keys, allow_nan=allow_nan)
    except RecursionError:
        pass
    return _dumps_iter(obj, ensure_ascii, sort_keys, allow_nan)


# str.splitlines() (and so many JSON-lines readers) also breaks a line on these; JSON allows them raw inside a
# string, so a JSON-lines writer escapes them (F1, round 6). They never occur outside a string in JSON text.
_LINE_SAFE = str.maketrans({"\u2028": "\\u2028", "\u2029": "\\u2029", "\u0085": "\\u0085"})


def dumps_line(obj: Any) -> str:
    """One line of a JSON-lines file: dumps(obj, ensure_ascii=False) with U+2028, U+2029, U+0085 escaped."""
    return dumps(obj, ensure_ascii=False).translate(_LINE_SAFE)


def _float(o: float, allow_nan: bool) -> str:
    if o != o:
        text = "NaN"
    elif o == _INF:
        text = "Infinity"
    elif o == -_INF:
        text = "-Infinity"
    else:
        return float.__repr__(o)
    if not allow_nan:
        raise ValueError("Out of range float values are not JSON compliant: " + repr(o))
    return text


def _key(k: Any, allow_nan: bool) -> str:
    if isinstance(k, str):
        return k
    if isinstance(k, float):
        return _float(k, allow_nan)
    if k is True:
        return "true"
    if k is False:
        return "false"
    if k is None:
        return "null"
    if isinstance(k, int):
        return int.__repr__(k)
    raise TypeError(f"keys must be str, int, float, bool or None, not {type(k).__name__}")


_TEXT, _KEY, _VALUE, _LEAVE = 0, 1, 2, 3


def _dumps_iter(obj: Any, ensure_ascii: bool, sort_keys: bool, allow_nan: bool) -> str:
    """json.dumps(obj) (default separators, no indent, check_circular) with an explicit stack instead of
    recursion: linear time at any depth."""
    enc = json.encoder.encode_basestring_ascii if ensure_ascii else json.encoder.encode_basestring
    out: list[str] = []
    on_path: set[int] = set()           # containers being written (a cycle check, like json's)
    todo: list[tuple[int, Any]] = [(_VALUE, obj)]
    while todo:
        tag, x = todo.pop()
        if tag == _TEXT:
            out.append(x)
            continue
        if tag == _LEAVE:
            on_path.discard(x)
            continue
        if tag == _KEY:                 # a key is checked in output order, as json does
            out.append(enc(_key(x, allow_nan)) + ": ")
            continue
        if isinstance(x, str):
            out.append(enc(x))
        elif x is None:
            out.append("null")
        elif x is True:
            out.append("true")
        elif x is False:
            out.append("false")
        elif isinstance(x, int):
            out.append(int.__repr__(x))
        elif isinstance(x, float):
            out.append(_float(x, allow_nan))
        elif isinstance(x, (list, tuple, dict)):
            if not x:
                out.append("{}" if isinstance(x, dict) else "[]")
                continue
            if id(x) in on_path:
                raise ValueError("Circular reference detected")
            on_path.add(id(x))
            todo.append((_LEAVE, id(x)))
            if isinstance(x, dict):
                items = sorted(x.items()) if sort_keys else list(x.items())
                out.append("{")
                todo.append((_TEXT, "}"))
                for j in range(len(items) - 1, -1, -1):
                    todo.append((_VALUE, items[j][1]))
                    todo.append((_KEY, items[j][0]))
                    if j:
                        todo.append((_TEXT, ", "))
            else:
                out.append("[")
                todo.append((_TEXT, "]"))
                for j in range(len(x) - 1, -1, -1):
                    todo.append((_VALUE, x[j]))
                    if j:
                        todo.append((_TEXT, ", "))
        else:
            raise TypeError(f"Object of type {type(x).__name__} is not JSON serializable")
    return "".join(out)
