"""Sipar runtime values and information-flow labels.

Value representation (decided here, used by the whole runtime)
-------------------------------------------------------------
Sipar type      Python representation
Int             ``int``   or ``LInt(int)``    (``LInt`` carries ``.labels``)
Float           ``float`` or ``LFloat(float)``
Str             ``str``   or ``LStr(str)``
Bool            ``bool``  (never labelled — choice declassification, SPEC §6)
None            ``None``  (never labelled)
List[T]         ``list``  (reference semantics come for free)
Map[T]          ``dict``  with ``str``/``LStr`` keys, insertion ordered
record          ``Record(type_name, fields: dict)``  (mutable, reference semantics)
enum            ``EnumVal(enum, variant, fields: dict)``; payload-free values are never labelled
fn values       ``Closure`` / ``FnRef`` / ``Builtin``

Labels are ``frozenset[str]`` such as ``"untrusted:net:example.com"`` or ``"secret:API_KEY"``. They live on
*leaves* only (Str/Int/Float). The label set of a container is the union of the labels of everything inside it
(``labels_of`` walks it). Every operation that creates a new leaf from other values gives it the union of the
inputs' labels (``with_labels``). Operations that return an *existing* element of a container (``first``,
``xs[i]``) return that element unchanged; when the result is a leaf, the labels of the receiver/index are added.
"""
from __future__ import annotations

import json
import math
import re
import threading
from typing import Any, Iterable

from ..errors import SiparRuntimeError, has_secrets, secret_labels_in
from . import jsondeep

EMPTY: frozenset = frozenset()


class LStr(str):
    labels: frozenset = EMPTY


class LInt(int):
    labels: frozenset = EMPTY


class LFloat(float):
    labels: frozenset = EMPTY


class Record:
    __slots__ = ("type_name", "fields")

    def __init__(self, type_name: str, fields: dict):
        self.type_name = type_name
        self.fields = fields

    def __eq__(self, other):
        return isinstance(other, Record) and other.type_name == self.type_name and equal(self.fields, other.fields)

    __hash__ = None  # mutable

    def __repr__(self):
        return f"Record({self.type_name}, {self.fields!r})"


class EnumVal:
    __slots__ = ("enum", "variant", "fields", "wrapped")

    def __init__(self, enum: str, variant: str, fields: dict | None = None, wrapped: bool = False):
        self.enum = enum
        self.variant = variant
        self.fields = fields or {}
        self.wrapped = wrapped          # the enum has a field named `tag`: JSON form is {"variant": {fields}}

    def __eq__(self, other):
        return (isinstance(other, EnumVal) and other.enum == self.enum and other.variant == self.variant
                and equal(self.fields, other.fields))

    def __hash__(self):
        return hash((self.enum, self.variant))

    def __repr__(self):
        return f"EnumVal({self.enum}.{self.variant}, {self.fields!r})"


class LList(list):
    """A list with labels of its own (SPEC §6 selection): the result of a pick made with a labelled count,
    bounds or sort keys (``take``, ``skip``, ``xs[a..b]``, ``sort_by``...), or a list element picked with a
    labelled index/key. Everything pulled out of it gets these labels too. ``frozen`` marks a copy that stands
    in for an element of another container: changing it would silently not change the original, so it is
    refused (change it through the container instead)."""
    __slots__ = ("labels", "frozen")

    def __init__(self, items=(), labels: frozenset = EMPTY, frozen: bool = False):
        super().__init__(items)
        self.labels = labels
        self.frozen = frozen


class LDict(dict):
    """A map with labels of its own (see LList)."""
    __slots__ = ("labels", "frozen")

    def __init__(self, items=(), labels: frozenset = EMPTY, frozen: bool = False):
        super().__init__(items)
        self.labels = labels
        self.frozen = frozen


class LRecord(Record):
    """A view of a record picked with a labelled index/key: it shares the original's fields (so assignments
    reach the original) and adds its labels to every field read through it."""
    __slots__ = ("labels",)

    def __init__(self, type_name: str, fields: dict, labels: frozenset = EMPTY):
        super().__init__(type_name, fields)
        self.labels = labels


class LFn:
    """A function value picked with a labelled index/key: calling it labels the result."""
    __slots__ = ("fn", "labels")

    def __init__(self, fn: Any, labels: frozenset):
        self.fn, self.labels = fn, labels


class RangeVal:
    """Lazy `a..b` used directly by `for` and slicing."""
    __slots__ = ("start", "end", "labels")

    def __init__(self, start: int, end: int, labels: frozenset = EMPTY):
        self.start, self.end, self.labels = start, end, labels


# ------------------------------------------------------------------ kinds

def kind_of(v: Any) -> str:
    if v is None:
        return "None"
    if v is True or v is False:
        return "Bool"
    if isinstance(v, int):
        return "Int"
    if isinstance(v, float):
        return "Float"
    if isinstance(v, str):
        return "Str"
    if isinstance(v, list):
        return "List"
    if isinstance(v, dict):
        return "Map"
    if isinstance(v, Record):
        return v.type_name
    if isinstance(v, EnumVal):
        return v.enum
    if isinstance(v, RangeVal):
        return "List"
    return "fn"


def is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


# ------------------------------------------------------------------ labels

def leaf_labels(v: Any) -> frozenset:
    return getattr(v, "labels", EMPTY) if isinstance(v, (LStr, LInt, LFloat, RangeVal)) else EMPTY


def own_labels(v: Any) -> frozenset:
    """Labels a container carries itself (not those of its items)."""
    return v.labels if isinstance(v, (LList, LDict, LRecord, LFn)) else EMPTY


# L (round 6): labels_of is memoized, so a check on every level of a deep value is linear, not quadratic.
# A cached entry holds the container itself (its id cannot be reused) and the mutation epoch it was computed
# in; every in-place change of a container a program can see calls mutated() (interp: field and index
# assignment; builtins: push, pop, remove; memory: stored labels), so a stale entry is never used.
_EPOCH = [0]
_MEMO = threading.local()
MEMO_MAX = 200_000


def mutated(container: Any = None, added: frozenset | None = None, dropped: tuple | None = ()) -> None:
    """Call after changing a list, map, record or enum value in place: drops every cached labels_of result.
    With `container` and `added` (labels_of of each new key and item, joined) the cache is kept when no cached
    union can change (F2, round 6: `xs.push(i); xs.len()` in a loop was quadratic): every `dropped` item (an
    item removed or overwritten; None = not known) carries no label, and `added` is already inside the
    container's labels (its own, or its cached labels_of). Any container whose cached union holds `container`
    holds those too, so it stays right as well."""
    if container is not None and added is not None:
        hit = _memo().get(id(container))
        cached = hit[1] if hit is not None and hit[0] is container else None
        if dropped is None:                     # not known (a map key that was removed): only if nothing inside
            clean = cached is not None and not cached       # was labelled, the removed item was not either
        else:
            clean = not any(labels_of(x) for x in dropped)
        if clean and not added:
            return
        # a list or map has one owner of its items; a record view (LRecord from a labelled pick) shares its
        # fields with the original, whose cached union may lack the view's own labels: records stop above
        if clean and isinstance(container, (list, dict)) and (added <= own_labels(container)
                                                             or cached is not None and added <= cached):
            return
    _EPOCH[0] += 1


class _Cycle(Exception):
    pass


def _memo() -> dict:
    d = getattr(_MEMO, "d", None)
    if d is None or len(d) > MEMO_MAX or getattr(_MEMO, "epoch", None) != _EPOCH[0]:
        d = _MEMO.d = {}
        _MEMO.epoch = _EPOCH[0]
    return d


def _items(v: Any) -> Iterable:
    if isinstance(v, list):
        return v
    if isinstance(v, dict):
        return list(v.keys()) + list(v.values())
    return v.fields.values()


def labels_of(v: Any, _seen: set | None = None) -> frozenset:
    """Union of all labels inside v (deep), container labels included."""
    if isinstance(v, (LStr, LInt, LFloat, RangeVal, LFn)):
        return v.labels
    if not isinstance(v, (list, dict, Record, EnumVal)):
        return EMPTY
    if _seen is not None:                       # the visit-once walk of a value with a cycle
        return _labels_seen(v, _seen)
    memo = _memo()
    hit = memo.get(id(v))
    if hit is not None and hit[0] is v:
        return hit[1]
    try:
        return _labels_memo(v, memo, set())
    except _Cycle:
        return _labels_seen(v, set())


def _labels_memo(v: Any, memo: dict, path: set) -> frozenset:
    """Every container met is finished (its whole inside walked) before it is cached; a cycle is given up."""
    hit = memo.get(id(v))
    if hit is not None and hit[0] is v:
        return hit[1]
    if id(v) in path:
        raise _Cycle
    path.add(id(v))
    out: set = set(own_labels(v))
    for x in _items(v):
        if isinstance(x, (LStr, LInt, LFloat, RangeVal, LFn)):
            out |= x.labels
        elif isinstance(x, (list, dict, Record, EnumVal)):
            out |= _labels_memo(x, memo, path)
    path.discard(id(v))
    r = frozenset(out)
    memo[id(v)] = (v, r)
    return r


def _labels_seen(v: Any, seen: set) -> frozenset:
    if id(v) in seen:
        return EMPTY
    seen.add(id(v))
    out: set = set(own_labels(v))
    for x in _items(v):
        out |= labels_of(x, seen)
    return frozenset(out)


def with_labels(v: Any, labels: Iterable[str]) -> Any:
    """Return leaf v carrying (its labels ∪ labels). Containers/Bool/None/enums are returned unchanged."""
    labels = frozenset(labels)
    if v is None or v is True or v is False:
        return v
    # A subclass from the Python host (a (str, Enum) member, an IntEnum, a class overriding __str__ / __int__ /
    # __float__) is read by its stored value, never by its own conversion method (round 10, F5): str.__str__,
    # int.__int__ and float.__float__ return the plain built-in value.
    if isinstance(v, str):
        new = leaf_labels(v) | labels
        if not new:
            return str.__str__(v)
        r = LStr(str.__str__(v))
        r.labels = new
        return r
    if isinstance(v, int):
        new = leaf_labels(v) | labels
        if not new:
            return int.__int__(v)
        r = LInt(int.__int__(v))
        r.labels = new
        return r
    if isinstance(v, float):
        new = leaf_labels(v) | labels
        if not new:
            return float.__float__(v)
        r = LFloat(float.__float__(v))
        r.labels = new
        return r
    return v


def set_labels(v: Any, labels: frozenset) -> Any:
    """Leaf v with exactly `labels`."""
    if isinstance(v, str):
        v = str.__str__(v)
    elif isinstance(v, int) and not isinstance(v, bool):
        v = int.__int__(v)
    elif isinstance(v, float):
        v = float.__float__(v)
    return with_labels(v, labels)


def new_list(items: Iterable, labels: frozenset = EMPTY) -> list:
    """A fresh list; an LList when it must carry labels of its own."""
    return LList(items, labels) if labels else list(items)


def select(v: Any, labels: frozenset) -> Any:
    """The value v as picked by a selection whose index/key/count/container carries `labels` (SPEC §6).
    Leaves get the labels; Bool, none and payload-free enum values stay unlabelled (choice declassification);
    a record becomes a view sharing the original's fields; a list or map becomes a read-only copy with
    labels of its own (its items are labelled when pulled out); an enum payload is labelled the same way; a
    function value labels what it returns."""
    if not labels or v is None or v is True or v is False:
        return v
    if isinstance(v, (str, int, float)):
        return with_labels(v, labels)
    if isinstance(v, RangeVal):
        return RangeVal(v.start, v.end, v.labels | labels)
    if isinstance(v, Record):
        return LRecord(v.type_name, v.fields, own_labels(v) | labels)
    if isinstance(v, list):
        return LList(v, own_labels(v) | labels, frozen=True)
    if isinstance(v, dict):
        return LDict(v, own_labels(v) | labels, frozen=True)
    if isinstance(v, EnumVal):
        if not v.fields:
            return v
        return EnumVal(v.enum, v.variant, {k: select(x, labels) for k, x in v.fields.items()}, v.wrapped)
    if isinstance(v, LFn):
        return LFn(v.fn, v.labels | labels)
    return LFn(v, labels)


def label_written(v: Any, labels: frozenset) -> Any:
    """A value stored at a position chosen with labelled data (`xs[i] = v`, `m[k] = v`, `rec.f = v` through a
    labelled pick, push into a labelled pick): leaves and records carry the labels; a list, map or enum with a
    payload is stored as a copy whose leaves carry them; Bool, none and plain enum values are stored as they are
    (structure is not labelled, SPEC §6)."""
    if not labels or v is None or v is True or v is False:
        return v
    if isinstance(v, (str, int, float)):
        return with_labels(v, labels)
    if isinstance(v, Record):
        return LRecord(v.type_name, v.fields, own_labels(v) | labels)
    if isinstance(v, (list, dict, EnumVal)):     # its items: a labelled key must not pick a whole command (round 10, S2)
        return deep_label(v, labels)
    return v


def check_mutable(v: Any) -> None:
    if getattr(v, "frozen", False):
        raise SiparRuntimeError("value", f"cannot change this {kind_of(v)}: it was picked with a labelled index or "
                                         "key and is a read-only copy (SPEC §6); change it through its "
                                         "container (xs[i].push(v), m[k][j] = v) or copy it with .take(n)")


def deep_label(v: Any, labels: frozenset, _seen: dict | None = None) -> Any:
    """New value: every leaf inside v gets `labels` added (containers are copied)."""
    if not labels:
        return v
    if _seen is None:
        _seen = {}
    if isinstance(v, (list, dict, Record, EnumVal)):
        if id(v) in _seen:
            return _seen[id(v)]
    if isinstance(v, list):
        out: list = LList((), own_labels(v)) if own_labels(v) else []
        _seen[id(v)] = out
        out.extend([deep_label(x, labels, _seen) for x in v])     # a list, not a generator: no C recursion (D3)
        return out
    if isinstance(v, dict):
        d: dict = LDict((), own_labels(v)) if own_labels(v) else {}
        _seen[id(v)] = d
        for k, x in v.items():
            d[deep_label(k, labels, _seen)] = deep_label(x, labels, _seen)
        return d
    if isinstance(v, Record):
        r = LRecord(v.type_name, {}, own_labels(v)) if own_labels(v) else Record(v.type_name, {})
        _seen[id(v)] = r
        r.fields = {k: deep_label(x, labels, _seen) for k, x in v.fields.items()}
        return r
    if isinstance(v, EnumVal):
        if not v.fields:
            return v
        e = EnumVal(v.enum, v.variant, {}, v.wrapped)
        _seen[id(v)] = e
        e.fields = {k: deep_label(x, labels, _seen) for k, x in v.fields.items()}
        return e
    return with_labels(v, labels)


def mark_secrets(v: Any, _seen: dict | None = None) -> Any:
    """Source labelling (SPEC §6): every Str leaf (map keys included) that contains a live secret value (any
    registered form) or its «secret:NAME» marker gets that `secret:NAME` label added; so does an Int / Float
    whose decimal digits contain one. Returns v itself when
    no secret is registered; otherwise a copy of the containers."""
    if not has_secrets():
        return v
    if _seen is None:
        _seen = {}
    if isinstance(v, str):
        found = secret_labels_in(v)
        return with_labels(v, found) if found else v
    if isinstance(v, (int, float)) and not isinstance(v, bool):    # a number whose digits hold a secret (round 10, S1)
        try:
            found = secret_labels_in(int.__repr__(v) if isinstance(v, int) else float.__repr__(v))
        except ValueError:          # more digits than Python will print: it cannot be printed either
            return v
        return with_labels(v, found) if found else v
    if isinstance(v, (list, dict, Record, EnumVal)):
        if id(v) in _seen:
            return _seen[id(v)]
    if isinstance(v, list):
        out: list = LList((), own_labels(v)) if own_labels(v) else []
        _seen[id(v)] = out
        out.extend([mark_secrets(x, _seen) for x in v])     # a list, not a generator: no C recursion (D3)
        return out
    if isinstance(v, dict):
        d: dict = LDict((), own_labels(v)) if own_labels(v) else {}
        _seen[id(v)] = d
        for k, x in v.items():
            d[mark_secrets(k, _seen)] = mark_secrets(x, _seen)
        return d
    if isinstance(v, Record):
        r = LRecord(v.type_name, {}, own_labels(v)) if own_labels(v) else Record(v.type_name, {})
        _seen[id(v)] = r
        r.fields = {k: mark_secrets(x, _seen) for k, x in v.fields.items()}
        return r
    if isinstance(v, EnumVal) and v.fields:
        e = EnumVal(v.enum, v.variant, {}, v.wrapped)
        _seen[id(v)] = e
        e.fields = {k: mark_secrets(x, _seen) for k, x in v.fields.items()}
        return e
    return v


def deep_strip(v: Any, keep, _seen: dict | None = None) -> Any:
    """New value with every leaf's labels filtered by predicate `keep(label) -> bool`."""
    if _seen is None:
        _seen = {}
    if isinstance(v, (list, dict, Record, EnumVal)) and id(v) in _seen:
        return _seen[id(v)]
    own = frozenset(l for l in own_labels(v) if keep(l))
    if isinstance(v, list):
        out: list = LList((), own) if own else []
        _seen[id(v)] = out
        out.extend([deep_strip(x, keep, _seen) for x in v])     # a list, not a generator: no C recursion (D3)
        return out
    if isinstance(v, dict):
        d: dict = LDict((), own) if own else {}
        _seen[id(v)] = d
        for k, x in v.items():
            d[deep_strip(k, keep, _seen)] = deep_strip(x, keep, _seen)
        return d
    if isinstance(v, Record):
        r = LRecord(v.type_name, {}, own) if own else Record(v.type_name, {})
        _seen[id(v)] = r
        r.fields = {k: deep_strip(x, keep, _seen) for k, x in v.fields.items()}
        return r
    if isinstance(v, EnumVal):
        if not v.fields:
            return v
        e = EnumVal(v.enum, v.variant, {}, v.wrapped)
        _seen[id(v)] = e
        e.fields = {k: deep_strip(x, keep, _seen) for k, x in v.fields.items()}
        return e
    if isinstance(v, (LStr, LInt, LFloat)):
        return set_labels(v, frozenset(l for l in v.labels if keep(l)))
    if isinstance(v, RangeVal):
        return RangeVal(v.start, v.end, frozenset(l for l in v.labels if keep(l)))
    if isinstance(v, LFn):
        own = frozenset(l for l in v.labels if keep(l))
        return LFn(v.fn, own) if own else v.fn
    return v


def secrets_in(v: Any) -> list[str]:
    return sorted(l for l in labels_of(v) if l.startswith("secret:"))


def untrusted_in(v: Any) -> list[str]:
    return sorted(l for l in labels_of(v) if l.startswith("untrusted:"))


# ------------------------------------------------------------------ equality

MAX_COMPARE_DEPTH = 400_000     # = sipar.deep.RECURSION_LIMIT: deeper (or a value containing itself) is an error


def _holds_nan(v: Any, memo: dict) -> bool:
    """True when a NaN Float is anywhere in v (list items, map values, record and enum fields). Iterative.
    memo (id -> answer) is shared by one equal() call: after a walk that met no NaN, every container it passed
    is known to hold none, so a part shared by many values is walked once, not once per value."""
    if isinstance(v, float):
        return v != v
    if not isinstance(v, (list, dict, Record, EnumVal)):
        return False
    known = memo.get(id(v))
    if known is not None:
        return known
    seen = {id(v)}
    stack = [v]
    while stack:
        x = stack.pop()
        for y in (x if isinstance(x, list) else x.values() if isinstance(x, dict) else x.fields.values()):
            if isinstance(y, float):
                if y != y:
                    memo[id(v)] = True
                    return True
            elif isinstance(y, (list, dict, Record, EnumVal)) and id(y) not in seen:
                known = memo.get(id(y))
                if known is True:
                    memo[id(v)] = True
                    return True
                if known is None:           # False: already walked, nothing below it is a NaN
                    seen.add(id(y))
                    stack.append(y)
    for i in seen:
        memo[i] = False
    return False


def equal(a: Any, b: Any) -> bool:
    """`a == b`: 1 == 1.0, map order does not matter, a Bool never equals a number at the top. A NaN equals
    nothing, itself included, wherever it stands (IEEE; round 10, F6): `[nan] == [nan]` is false even when both
    lists hold the same NaN, as `nan == nan`, `[nan].contains(nan)` and `nan in [nan]` are. The same object on
    both sides is equal at once unless it holds a NaN (a shared value is not walked twice). An explicit stack,
    not recursion: Python 3.12 stops C recursion (== of nested lists, maps and records) at about 10,000 levels,
    whatever the stack (round 5, D3)."""
    if (a is True or a is False) != (b is True or b is False):
        return False
    todo: list = [(a, b, 1)]
    memo: dict = {}
    while todo:
        x, y, depth = todo.pop()
        if x is y:
            if _holds_nan(x, memo):
                return False
            continue
        pairs: Any = None
        if isinstance(x, list) or isinstance(y, list):
            if not (isinstance(x, list) and isinstance(y, list)) or len(x) != len(y):
                return False
            pairs = zip(x, y)
        elif isinstance(x, (dict, Record, EnumVal)) or isinstance(y, (dict, Record, EnumVal)):
            if isinstance(x, Record) and isinstance(y, Record):
                if x.type_name != y.type_name:
                    return False
                x, y = x.fields, y.fields
            elif isinstance(x, EnumVal) and isinstance(y, EnumVal):
                if x.enum != y.enum or x.variant != y.variant:
                    return False
                x, y = x.fields, y.fields
            if not (type(x) in (dict, LDict) and type(y) in (dict, LDict)) or len(x) != len(y):
                return False
            pairs = []
            for k, xv in x.items():
                if k not in y:
                    return False
                pairs.append((xv, y[k]))
        elif not x == y:
            return False
        if pairs is not None:
            if depth >= MAX_COMPARE_DEPTH:
                raise SiparRuntimeError("value", "value too deeply nested to compare")
            todo.extend([(p, q, depth + 1) for p, q in reversed(list(pairs))])
    return True


# ------------------------------------------------------------------ JSON / rendering

MAX_STR = 100_000_000         # characters in a Str the program builds (+, interpolation, join, print of a value)
STR_TOO_LARGE = f"string too large (more than {MAX_STR:,} characters)"
VALUE_TOO_LARGE = f"value too large (its JSON text would pass {MAX_STR:,} characters)"

def _secret_mark(v: Any) -> str | None:
    """«secret:NAME» for a value whose own labels (a leaf's labels, or a picked container's / range's /
    function's own labels, SPEC §6) hold a secret; None otherwise. Items are not looked at."""
    if isinstance(v, (LStr, LInt, LFloat, RangeVal, LList, LDict, LRecord, LFn)):
        sec = sorted(l for l in v.labels if l.startswith("secret:"))
        if sec:
            return "«" + ",".join(sec) + "»"
    return None


def has_function(v: Any, _seen: set | None = None) -> bool:
    """True if a function value sits anywhere inside v."""
    if isinstance(v, (LFn, Closure, FnRef, Builtin, WidenFn)) or callable(v) and not isinstance(v, (str, int, float)):
        return True
    if isinstance(v, (list, dict, Record, EnumVal)):
        _seen = set() if _seen is None else _seen
        if id(v) in _seen:
            return False
        _seen.add(id(v))
        items = list(v) if isinstance(v, list) else list(v.values()) if isinstance(v, dict) else v.fields.values()
        for x in items:                 # a loop, not any(generator): no C recursion (round 5, D3)
            if has_function(x, _seen):
                return True
    return False


def _json_leaf_size(v: Any, redact: bool) -> int | None:
    """The size _json_size counts for a value with no items, None for a list/map/record/enum with fields."""
    if redact:
        mark = _secret_mark(v)
        if mark is not None:
            return len(mark) + 2
    if v is None or v is True or v is False or isinstance(v, (int, float)):
        return 1
    if isinstance(v, str):
        return len(v) + 2
    if isinstance(v, RangeVal):
        return max(v.end - v.start, 0) * 3 or 2       # "[0, 1]": a digit and ", " per item, at least
    if not isinstance(v, (list, dict, Record, EnumVal)):
        return 6
    if isinstance(v, EnumVal) and not v.fields:
        return len(v.variant) + 2
    return None


def _json_size(v: Any, redact: bool) -> int:
    """At most the number of characters of v's JSON text, each shared part counted every time it is written
    out, capped just past MAX_STR. Linear in the number of *distinct* values (one pass, no recursion)."""
    top = _json_leaf_size(v, redact)
    if top is not None:
        return top
    cap = MAX_STR + 1
    memo: dict = {}
    stack: list = [(v, False)]
    while stack:
        x, done = stack.pop()
        if not done:
            if id(x) in memo:
                continue
            memo[id(x)] = 7                       # in progress: met again only through a cycle, shown "[...]"
            stack.append((x, True))
            for c in _json_items(x):
                if _json_leaf_size(c, redact) is None and id(c) not in memo:
                    stack.append((c, False))
            continue
        items = _json_items(x)
        n = 2 + 2 * max(len(items) - 1, 0)        # brackets, ", " between items
        for c in items:
            k = _json_leaf_size(c, redact)
            n += k if k is not None else memo[id(c)]
        if isinstance(x, (dict, Record, EnumVal)):
            keys = x.keys() if isinstance(x, dict) else x.fields.keys()
            n += sum(len(k) + 4 if isinstance(k, str) else 1 for k in keys)     # "key": 
        memo[id(x)] = min(n, cap)
    return memo[id(v)]


def _json_items(x: Any) -> Any:
    if isinstance(x, list):
        return x
    if isinstance(x, dict):
        return list(x.values())
    return list(x.fields.values())


def to_json(v: Any, redact: bool = False, _seen: set | None = None) -> Any:
    """Plain JSON-able data. With redact=True every value whose own labels hold a secret (a secret leaf, or a
    container picked with a secret index/key, SPEC §6) becomes «secret:NAME». A value whose JSON text would
    pass MAX_STR characters is a `value` error, found before anything is copied (round 10, F2/F3 class: a
    value that shares a part many times, `t = T.node(t, t)` 60 times, or one labelled 10 MB Str in a long list,
    was copied out in full first: 4 GB and a killed process for print(t))."""
    if _seen is None and _json_leaf_size(v, redact) is None and _json_size(v, redact) > MAX_STR:
        raise SiparRuntimeError("value", VALUE_TOO_LARGE)
    if redact:
        mark = _secret_mark(v)
        if mark is not None:
            return mark
    if v is None or v is True or v is False:
        return v
    if isinstance(v, str):
        return str.__str__(v)
    if isinstance(v, int):
        return int(v)
    if isinstance(v, float):
        return float(v)
    if isinstance(v, RangeVal):
        return list(range(v.start, v.end))
    if not isinstance(v, (list, dict, Record, EnumVal)):
        return "<fn>"
    if isinstance(v, EnumVal) and not v.fields:
        return v.variant
    if _seen is None:
        _seen = set()
    if id(v) in _seen:
        return "[...]"
    # _seen holds the containers on the path from the root (a cycle check). One set for the whole walk, not a
    # copy per level: a copy made the walk quadratic in the depth (round 5, D3).
    _seen.add(id(v))
    if isinstance(v, list):
        out: Any = [to_json(x, redact, _seen) for x in v]
    elif isinstance(v, dict):
        out = {str(to_json(k, redact, _seen)): to_json(x, redact, _seen) for k, x in v.items()}
    elif isinstance(v, Record):
        out = {k: to_json(x, redact, _seen) for k, x in v.fields.items()}
    else:
        body = {k: to_json(x, redact, _seen) for k, x in v.fields.items()}
        if v.wrapped:
            out = {v.variant: body}
        else:
            out = {"tag": v.variant}
            out.update(body)
    _seen.discard(id(v))
    return out


MAX_INT_BITS = 14_000        # about 4200 decimal digits: larger Ints are a `value` error (Python prints at most 4300)


INT_TOO_LARGE = "number too large for Int (limit about 4200 digits)"   # one message for every source (F6)

# A Sipar Str never holds a lone surrogate (U+D800..U+DFFF): it is not Unicode text and cannot be printed or
# written as UTF-8 (round 5, C2). JSON decoded against a type (`as`, typed replies, memory, API arguments) that
# holds one (an unpaired "\ud800" escape) is error kind `decode`; text from the OS or the network (argv, env,
# stdin, model replies) gets U+FFFD instead, like any byte that is not UTF-8.
_LONE = re.compile("[\ud800-\udfff]")
LONE_SURROGATE = "text holds a lone surrogate (an unpaired \\ud800-\\udfff escape); it is not valid Unicode"


def has_lone_surrogate(s: Any) -> bool:
    return isinstance(s, str) and _LONE.search(s) is not None


def holds_lone_surrogate(data: Any) -> bool:
    """True when a string (or map key) anywhere in plain JSON data holds a lone surrogate. Iterative."""
    stack = [data]
    while stack:
        x = stack.pop()
        if isinstance(x, str):
            if _LONE.search(x):
                return True
        elif isinstance(x, list):
            stack.extend(x)
        elif isinstance(x, dict):
            stack.extend(x)
            stack.extend(x.values())
    return False


def scrub_text(x: Any) -> Any:
    """`x` with every lone surrogate in its strings (and map keys) replaced by U+FFFD. Plain JSON data only."""
    if isinstance(x, str):
        return _LONE.sub("\ufffd", x) if _LONE.search(x) else x
    if isinstance(x, list):
        return [scrub_text(y) for y in x]
    if isinstance(x, dict):
        return {scrub_text(k): scrub_text(y) for k, y in x.items()}
    return x


def check_int(r: int) -> None:
    if r.bit_length() > MAX_INT_BITS:
        raise SiparRuntimeError("value", INT_TOO_LARGE)


def _num_text(v: Any) -> str:
    if isinstance(v, float):
        if math.isnan(v):
            return "nan"
        if math.isinf(v):
            return "inf" if v > 0 else "-inf"
        return repr(float(v))
    try:
        return str(int(v))
    except ValueError:
        raise SiparRuntimeError("value", "Int too large to show (more than 4300 digits)")


def dumps(data: Any) -> str:
    return jsondeep.dumps(data, ensure_ascii=False)




def check_str_len(n: int) -> None:
    """A Str of n characters is about to be built: refuse it, before it is allocated, when it is over MAX_STR
    (round 10, F3: `+` was the only operation that checked)."""
    if n > MAX_STR:
        raise SiparRuntimeError("value", STR_TOO_LARGE)


_END = object()


def _json_text(d: Any) -> str:
    """json.dumps layout, but numbers are written as `print` writes them (inf, -inf, nan; SPEC §5).
    Round 10, F2: one pass with an explicit stack of open lists/maps, the pieces joined once at the end. It
    built each level's text from its items' texts, so a value N levels deep copied its text N times (quadratic:
    20 s for 160,000 levels). F3: stops with `value` "string too large" as soon as the text passes MAX_STR."""
    parts: list = []
    total = 0
    stack: list = []            # [iterator over items, closing bracket, is a map, first item still to come]
    x: Any = d
    while True:
        if isinstance(x, list):
            parts.append("[")
            stack.append([iter(x), "]", False, True])
            total += 1
        elif isinstance(x, dict):
            parts.append("{")
            stack.append([iter(x.items()), "}", True, True])
            total += 1
        else:
            if isinstance(x, str):
                check_str_len(total + len(x) + 2)      # before the quoted copy is made
                t = dumps(x)
            elif x is True:
                t = "true"
            elif x is False:
                t = "false"
            elif x is None:
                t = "null"
            elif isinstance(x, float):
                t = _num_text(x)
            elif type(x) is int:
                t = int.__repr__(x)                    # what json.dumps writes, without a call into json per number
            else:
                t = dumps(x)
            parts.append(t)
            total += len(t)
        check_str_len(total)
        while stack:
            top = stack[-1]
            nxt = next(top[0], _END)
            if nxt is _END:
                parts.append(top[1])
                total += 1
                stack.pop()
                continue
            if not top[3]:
                parts.append(", ")
                total += 2
            top[3] = False
            if top[2]:
                k, x = nxt
                check_str_len(total + len(k) + 4)
                kt = dumps(str(k)) + ": "
                parts.append(kt)
                total += len(kt)
            else:
                x = nxt
            break
        else:
            check_str_len(total)
            return "".join(parts)


def render(v: Any, redact: bool = False) -> str:
    """Text of a value as used by print/interpolation: Str raw, numbers plain, the rest JSON-ish."""
    if redact:
        mark = _secret_mark(v)
        if mark is not None:
            return mark
    if isinstance(v, str):
        return str.__str__(v)
    if v is None:
        return "none"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return _num_text(v)
    if isinstance(v, EnumVal) and not v.fields:
        return v.variant
    try:
        return _json_text(to_json(v, redact))
    except (ValueError, RecursionError):
        return "[...]"


def snippet(v: Any, limit: int = 60) -> str:
    """Short, secret-safe text of a value for error messages."""
    sec = secrets_in(v)
    if sec:
        return "«" + ",".join(sec) + "»"
    t = render(v)
    if isinstance(v, str):
        t = dumps(t)
    return t if len(t) <= limit else t[:limit] + "…"


def make_error(kind: str, message: Any) -> Record:
    return Record("Error", {"kind": kind, "message": message})


# ------------------------------------------------------------------ callables

class Closure:
    __slots__ = ("params", "body", "env", "name", "ret")

    def __init__(self, params, body, env, name="<lambda>", ret=None):
        self.params, self.body, self.env, self.name, self.ret = params, body, env, name, ret


class FnRef:
    __slots__ = ("decl",)

    def __init__(self, decl):
        self.decl = decl

    @property
    def name(self):
        return self.decl.name


class Builtin:
    __slots__ = ("name", "fn")

    def __init__(self, name, fn):
        self.name, self.fn = name, fn


class WidenFn:
    """A function value used where the checker expects a wider function type (e.g. fn() -> Int as
    fn() -> Float): arguments and result are widened by plan = ("fn", param_plans, ret_plan)."""
    __slots__ = ("fn", "plan")

    def __init__(self, fn, plan):
        self.fn, self.plan = fn, plan

    @property
    def name(self):
        return getattr(self.fn, "name", "<fn>")


def widen(v: Any, plan: Any) -> Any:
    """Apply a checker widening plan (types.widen_plan) to a runtime value. Labels are kept."""
    if plan is None or v is None:
        return v
    if plan == "F":
        if isinstance(v, int) and not isinstance(v, bool):
            try:
                f = float(v)
            except OverflowError:
                raise SiparRuntimeError("value", "number too large to use as a Float") from None
            return with_labels(f, getattr(v, "labels", EMPTY))
        return v
    if isinstance(plan, tuple) and plan and plan[0] == "fn":
        if isinstance(v, LFn):
            return LFn(widen(v.fn, plan), v.labels)
        if isinstance(v, (Closure, FnRef, Builtin, WidenFn)):
            return WidenFn(v, plan)
    return v
