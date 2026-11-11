"""Runtime view of Sipar types: JSON schema generation, JSON -> value decoding with validation, coercion."""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any

from .. import ast as A
from ..errors import SiparRuntimeError
from . import jsondeep
from .values import (EMPTY, INT_TOO_LARGE, LONE_SURROGATE, MAX_INT_BITS, EnumVal, LDict, Record, has_lone_surrogate,
                     new_list, with_labels, kind_of, is_num)

PRIMS = {"Int", "Float", "Str", "Bool", "None"}
ERROR_FIELDS = [("kind", A.TName(0, 0, "Str")), ("message", A.TName(0, 0, "Str"))]


class TypeEnv:
    def __init__(self, records: dict | None = None, enums: dict | None = None):
        self.records: dict[str, list[tuple[str, A.TypeExpr]]] = {"Error": ERROR_FIELDS}
        self.records.update(records or {})
        self.enums: dict[str, list[A.Variant]] = dict(enums or {})


def type_str(t: A.TypeExpr | None) -> str:
    if t is None:
        return "None"
    if isinstance(t, A.TOptional):
        return type_str(t.inner) + "?"
    if isinstance(t, A.TFn):
        return "fn(" + ", ".join(type_str(p) for p in t.params) + ") -> " + type_str(t.ret)
    if t.args:
        return t.name + "[" + ", ".join(type_str(a) for a in t.args) + "]"
    return t.name


def _arg(t: A.TName, i: int = 0) -> A.TypeExpr:
    if t.name == "Map" and t.args:
        return t.args[-1]          # Map[V] per SPEC; Map[Str, V] tolerated: the value type is the last argument
    return t.args[i] if len(t.args) > i else A.TName(t.line, t.col, "Any")


# ------------------------------------------------------------------ schema

def schema(t: A.TypeExpr | None, tenv: TypeEnv, _stack: tuple = ()) -> dict:
    if t is None:
        return {"type": "null"}
    if isinstance(t, A.TOptional):
        return {"anyOf": [schema(t.inner, tenv, _stack), {"type": "null"}]}
    if isinstance(t, A.TFn):
        raise SiparRuntimeError("type", "function types cannot be produced by a model")
    n = t.name
    if n == "Int":
        return {"type": "integer"}
    if n == "Float":
        return {"type": "number"}
    if n == "Str":
        return {"type": "string"}
    if n == "Bool":
        return {"type": "boolean"}
    if n == "None":
        return {"type": "null"}
    if n == "Any":
        return {}
    if n == "List":
        return {"type": "array", "items": schema(_arg(t), tenv, _stack)}
    if n == "Map":
        return {"type": "object", "additionalProperties": schema(_arg(t), tenv, _stack)}
    if n in _stack:
        return {}          # recursive type: leave open
    st = _stack + (n,)
    if n in tenv.records:
        fields = tenv.records[n]
        return {"type": "object",
                "properties": {f: schema(ft, tenv, st) for f, ft in fields},
                "required": [f for f, _ in fields],
                "additionalProperties": False}
    if n in tenv.enums:
        vs = tenv.enums[n]
        if all(not v.fields for v in vs):
            return {"type": "string", "enum": [v.name for v in vs]}
        alts = []
        if tag_field_enum(vs):                  # a field named `tag` would collide with the tagged form
            for v in vs:
                if not v.fields:
                    alts.append({"type": "string", "const": v.name})
                    continue
                inner = {"type": "object", "properties": {f: schema(ft, tenv, st) for f, ft in v.fields},
                         "required": [f for f, _ in v.fields], "additionalProperties": False}
                alts.append({"type": "object", "properties": {v.name: inner}, "required": [v.name],
                             "additionalProperties": False})
            return {"anyOf": alts}
        for v in vs:
            props: dict = {"tag": {"const": v.name}}
            props.update({f: schema(ft, tenv, st) for f, ft in v.fields})
            alts.append({"type": "object", "properties": props,
                         "required": ["tag"] + [f for f, _ in v.fields], "additionalProperties": False})
        return {"anyOf": alts}
    raise SiparRuntimeError("type", f"unknown type {n}")


# ------------------------------------------------------------------ JSON -> value

@dataclass(frozen=True)
class HugeInt:
    """A JSON integer with more digits than Python converts (4300). Kept as text so that the target type
    decides the error: Int -> `value` (too large), Float -> `decode` (overflow), other types -> wrong type."""
    text: str


def _parse_int(s: str) -> Any:
    try:
        return int(s)
    except ValueError:              # Python's int-digit limit: not a malformed number, just a huge one
        return HugeInt(s)


def json_loads(text: str) -> Any:
    """json.loads() that never fails on a huge integer (see HugeInt); other bad JSON is a ValueError."""
    return jsondeep.loads(text, parse_int=_parse_int)


DECODER = json.JSONDecoder(parse_int=_parse_int)    # for raw_decode() scans of model replies
PY_DECODER = jsondeep.PyDecoder(parse_int=_parse_int)    # its retry past Python 3.12's C depth limit (D3)


def _too_large(d: Any) -> bool:
    return isinstance(d, HugeInt) or (isinstance(d, int) and not isinstance(d, bool)
                                      and int.bit_length(d) > MAX_INT_BITS)


def _jtype(d: Any) -> str:
    if d is None:
        return "null"
    if isinstance(d, bool):
        return "boolean"
    if isinstance(d, (int, HugeInt)):
        return "integer"
    if isinstance(d, float):
        return "number"
    if isinstance(d, str):
        return "string"
    if isinstance(d, list):
        return "array"
    return "object"


def _fail(path: Any, msg: str):
    raise SiparRuntimeError("decode", f"{path}: {msg}")


def tag_field_enum(variants) -> bool:
    """True when some variant of the enum has a payload field named `tag` (SPEC §10: such an enum is only
    ever encoded as {"variant": {fields}}, because the tagged form {"tag": "variant", ...} is ambiguous)."""
    return any(f == "tag" for v in variants for f, _ in v.fields)


MAX_VALUE_DEPTH = 20_000      # JSON data and values crossing to/from Python nest at most this deep (SPEC §5)
TOO_DEEP = f"nested too deeply (more than {MAX_VALUE_DEPTH:,} levels)"


class Path:
    """An error path ("$.a[0].b") built only when an error needs it: a path string per level would make deep
    data quadratic in time and memory."""
    __slots__ = ("parent", "seg")

    def __init__(self, parent: Any, seg: str):
        self.parent, self.seg = parent, seg

    def __str__(self) -> str:
        segs, p = [], self
        while isinstance(p, Path):
            segs.append(p.seg)
            p = p.parent
        return str(p) + "".join(reversed(segs))

    def __format__(self, spec: str) -> str:
        return format(str(self), spec)


def too_deep(d: Any, limit: int = MAX_VALUE_DEPTH) -> bool:
    """True when JSON-like data (lists, tuples, dicts) nests more than `limit` levels. Iterative and linear."""
    todo = [(d, 1)]
    while todo:
        x, n = todo.pop()
        if isinstance(x, (list, tuple, dict)):
            if n > limit:
                return True
            todo.extend((y, n + 1) for y in (x.values() if isinstance(x, dict) else x))
    return False


def from_json(d: Any, t: A.TypeExpr | None, tenv: TypeEnv, labels: frozenset = EMPTY, path: str = "$",
              form: str = "any") -> Any:
    """Validate JSON data `d` against type `t` and build a Sipar value whose leaves carry `labels`.
    Enums with payload accept {"variant": {fields}} and, unless a variant has a field named `tag`, the
    tagged form {"tag": "variant", ...fields}. form="legacy" (memory entries written before the wrapped
    form existed): an enum with a field named `tag` is an `io` error, never a guess. Data nested deeper than
    MAX_VALUE_DEPTH is a `decode` error, whatever stack the caller runs on."""
    if too_deep(d):
        _fail(path, TOO_DEEP)
    return _from_json(d, t, tenv, labels, path, form)


def _from_json(d: Any, t: A.TypeExpr | None, tenv: TypeEnv, labels: frozenset, path: Any, form: str) -> Any:
    if t is None:
        if d is not None:
            _fail(path, f"expected null, got {_jtype(d)}")
        return None
    if isinstance(t, A.TOptional):
        if d is None:
            return None
        return _from_json(d, t.inner, tenv, labels, path, form)
    if isinstance(t, A.TFn):
        _fail(path, "cannot decode a function")
    n = t.name
    if n in ("Int", "Float") and type(d) not in (int, float, bool) and isinstance(d, (int, float)):
        # a number subclass from the Python host (IntEnum, a class overriding __int__ / __float__ / __abs__ /
        # bit_length...): read by its stored value, never by its own methods (round 10, F5)
        d = int.__int__(d) if isinstance(d, int) else float.__float__(d)
    if n == "Int":
        if _too_large(d):
            raise SiparRuntimeError("value", f"{path}: {INT_TOO_LARGE}")
        if isinstance(d, float) and d != d:
            _fail(path, "expected Int, got NaN")
        if isinstance(d, float) and math.isinf(d):         # 1e400 (round 9, F3: "expected Int, got number")
            _fail(path, "number too large for Int")
        if isinstance(d, bool) or not isinstance(d, (int, float)) or (isinstance(d, float) and not d.is_integer()):
            _fail(path, f"expected Int, got {_jtype(d)}")
        if not isinstance(d, int) and abs(d) > 1e18:       # 1e300 is "integer-valued" but not a sensible Int
            _fail(path, "number too large for Int")
        return with_labels(int(d), labels)
    if n == "Float":
        if isinstance(d, HugeInt):
            _fail(path, "number too large for Float")
        if isinstance(d, bool) or not isinstance(d, (int, float)):
            _fail(path, f"expected Float, got {_jtype(d)}")
        try:
            f = float(d)
        except OverflowError:
            _fail(path, "number too large for Float")
        if not math.isfinite(f):
            _fail(path, "expected a finite Float (no NaN or Infinity)")
        return with_labels(f, labels)
    if n == "Str":
        if not isinstance(d, str):
            _fail(path, f"expected Str, got {_jtype(d)}")
        if has_lone_surrogate(d):
            _fail(path, LONE_SURROGATE)
        return with_labels(d, labels)
    if n == "Bool":
        if not isinstance(d, bool):
            _fail(path, f"expected Bool, got {_jtype(d)}")
        return d
    if n == "None":
        if d is not None:
            _fail(path, f"expected none, got {_jtype(d)}")
        return None
    if n == "Any":
        return _any(d, labels)
    if n == "List":
        if not isinstance(d, list):
            _fail(path, f"expected List, got {_jtype(d)}")
        # R7 (round 6): a decoded list or map carries the labels itself, so its length and keys are labelled
        # even when its items are Bool, none or plain enums (which never are; SPEC §6)
        return new_list([_from_json(x, _arg(t), tenv, labels, Path(path, f"[{i}]"), form)
                         for i, x in enumerate(d)], labels)
    if n == "Map":
        if not isinstance(d, dict):
            _fail(path, f"expected Map (JSON object), got {_jtype(d)}")
        if any(has_lone_surrogate(k) for k in d):
            _fail(path, "a key " + LONE_SURROGATE)
        return new_map({with_labels(k, labels): _from_json(x, _arg(t), tenv, labels, Path(path, f".{k}"), form)
                        for k, x in d.items()}, labels)
    if n in tenv.records:
        if not isinstance(d, dict):
            _fail(path, f"expected {n} (JSON object), got {_jtype(d)}")
        out = {}
        for f, ft in tenv.records[n]:
            if f not in d:
                if isinstance(ft, A.TOptional):
                    out[f] = None
                    continue
                _fail(path, f"missing field '{f}' of {n}")
            out[f] = _from_json(d[f], ft, tenv, labels, Path(path, f".{f}"), form)
        return Record(n, out)
    if n in tenv.enums:
        variants = {v.name: v for v in tenv.enums[n]}
        names = ", ".join(variants)
        if isinstance(d, str):
            v = variants.get(d)
            if v is None:
                _fail(path, f"{d[:40]!r} is not a variant of {n} ({names})")
            if v.fields:
                _fail(path, f"variant {n}.{d} needs fields {[f for f, _ in v.fields]}")
            return EnumVal(n, d)
        if isinstance(d, dict):
            ambiguous = tag_field_enum(variants.values())
            if ambiguous and form == "legacy":
                raise SiparRuntimeError("io", f"{path}: stored in an older format that is ambiguous for {n} (a "
                                              f"variant has a field named 'tag'); delete the entry and save it "
                                              f"again")
            if len(d) == 1 and next(iter(d)) in variants and isinstance(next(iter(d.values())), dict):
                (tag, body), = d.items()                       # wrapped form {"variant": {fields}}
            elif ambiguous:
                _fail(path, f"expected {{\"variant\": {{fields}}}} with variant one of {names} ({n} has a field "
                            f"named 'tag', so the {{\"tag\": ...}} form is not accepted)")
            else:
                tag, body = d.get("tag"), d
                if not isinstance(tag, str) or tag not in variants:
                    _fail(path, f"expected an object with \"tag\" one of {names}")
            v = variants[tag]
            fields = {}
            for f, ft in v.fields:
                if f not in body:
                    if isinstance(ft, A.TOptional):
                        fields[f] = None
                        continue
                    _fail(path, f"missing field '{f}' of {n}.{tag}")
                fields[f] = _from_json(body[f], ft, tenv, labels, Path(path, f".{f}"), form)
            return EnumVal(n, tag, fields, ambiguous)
        _fail(path, f"expected {n} variant, got {_jtype(d)}")
    raise SiparRuntimeError("type", f"unknown type {n}")


def _any(d: Any, labels: frozenset) -> Any:
    if _too_large(d):
        raise SiparRuntimeError("value", INT_TOO_LARGE)
    if has_lone_surrogate(d) or isinstance(d, dict) and any(has_lone_surrogate(k) for k in d):
        raise SiparRuntimeError("decode", LONE_SURROGATE)
    if isinstance(d, list):
        return new_list([_any(x, labels) for x in d], labels)
    if isinstance(d, dict):
        return new_map({with_labels(k, labels): _any(x, labels) for k, x in d.items()}, labels)
    return with_labels(d, labels)


def new_map(items: dict, labels: frozenset) -> dict:
    return LDict(items, labels) if labels else items


# ------------------------------------------------------------------ coercion / runtime type test

def coerce(v: Any, t: A.TypeExpr | None) -> Any:
    """Implicit Int -> Float widening at a typed boundary (top level only)."""
    if t is None:
        return v
    if isinstance(t, A.TOptional):
        return None if v is None else coerce(v, t.inner)
    if isinstance(t, A.TName) and t.name == "Float" and isinstance(v, int) and not isinstance(v, bool):
        try:
            f = float(v)
        except OverflowError:
            raise SiparRuntimeError("value", "number too large to use as a Float") from None
        return with_labels(f, getattr(v, "labels", EMPTY))
    return v


def conforms(v: Any, t: A.TypeExpr | None, tenv: TypeEnv) -> bool:
    """Shallow runtime check used for mock/tool results and decoded arguments."""
    if t is None:
        return v is None
    if isinstance(t, A.TOptional):
        return v is None or conforms(v, t.inner, tenv)
    if isinstance(t, A.TFn):
        return kind_of(v) == "fn"
    n = t.name
    k = kind_of(v)
    if n == "Any":
        return True
    if n == "Float":
        return is_num(v)
    return k == n
