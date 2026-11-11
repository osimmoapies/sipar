"""Sipar static types used by the checker.

Types are immutable values. Special pseudo-types:
  Unknown — the type of an expression that already produced an error; accepted everywhere so that
            one mistake does not cause a cascade of follow-up diagnostics.
  Never   — the type of an expression that does not return (fail(...), a block ending in return).
  Any     — stdlib parameters that accept every type (print, json.encode).
  Num     — stdlib parameters that accept Int or Float.
  TVar    — stdlib generic variables T and U.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache


class Ty:
    __slots__ = ()


@dataclass(frozen=True)
class Prim(Ty):
    name: str           # Int Float Str Bool None  |  Unknown Never Any Num

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class ListT(Ty):
    elem: Ty

    def __str__(self) -> str:
        return f"List[{self.elem}]"


@dataclass(frozen=True)
class MapT(Ty):
    elem: Ty

    def __str__(self) -> str:
        return f"Map[{self.elem}]"


@dataclass(frozen=True)
class OptT(Ty):
    inner: Ty

    def __str__(self) -> str:
        s = str(self.inner)
        return f"({s})?" if isinstance(self.inner, FnT) else f"{s}?"


@dataclass(frozen=True)
class FnT(Ty):
    params: tuple
    ret: Ty

    def __str__(self) -> str:
        return f"fn({', '.join(str(p) for p in self.params)}) -> {self.ret}"


@dataclass(frozen=True)
class Named(Ty):
    name: str
    kind: str           # "record" | "enum"

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class TVar(Ty):
    name: str

    def __str__(self) -> str:
        return self.name


INT, FLOAT, STR, BOOL, NONE = Prim("Int"), Prim("Float"), Prim("Str"), Prim("Bool"), Prim("None")
UNKNOWN, NEVER, ANY, NUM = Prim("Unknown"), Prim("Never"), Prim("Any"), Prim("Num")
PRIMS = {"Int": INT, "Float": FLOAT, "Str": STR, "Bool": BOOL, "None": NONE}
NUMERIC = (INT, FLOAT)
ERROR = Named("Error", "record")


def opt(t: Ty) -> Ty:
    """T? — collapses T?? and None? ; Unknown stays Unknown."""
    if isinstance(t, OptT) or t in (NONE, UNKNOWN):
        return t
    return OptT(t)


def has_unknown(t: Ty) -> bool:
    if t == UNKNOWN:
        return True
    if isinstance(t, (ListT, MapT)):
        return has_unknown(t.elem)
    if isinstance(t, OptT):
        return has_unknown(t.inner)
    if isinstance(t, FnT):
        return any(has_unknown(p) for p in t.params) or has_unknown(t.ret)
    return False


def has_never_elem(t: Ty) -> bool:
    """True for the type of an empty literal that was never given an element type: List[Never]."""
    if isinstance(t, (ListT, MapT)):
        return t.elem == NEVER or has_never_elem(t.elem)
    if isinstance(t, OptT):
        return has_never_elem(t.inner)
    return False


def has_tvar(t: Ty) -> bool:
    if isinstance(t, TVar):
        return True
    if isinstance(t, (ListT, MapT)):
        return has_tvar(t.elem)
    if isinstance(t, OptT):
        return has_tvar(t.inner)
    if isinstance(t, FnT):
        return any(has_tvar(p) for p in t.params) or has_tvar(t.ret)
    return False


def subst(t: Ty, b: dict) -> Ty:
    if isinstance(t, TVar):
        return b.get(t.name, t)
    if isinstance(t, ListT):
        return ListT(subst(t.elem, b))
    if isinstance(t, MapT):
        return MapT(subst(t.elem, b))
    if isinstance(t, OptT):
        return opt(subst(t.inner, b))
    if isinstance(t, FnT):
        return FnT(tuple(subst(p, b) for p in t.params), subst(t.ret, b))
    return t


def erase_tvars(t: Ty) -> Ty:
    """Replace unbound type variables by Unknown (silences follow-ups)."""
    if isinstance(t, TVar):
        return UNKNOWN
    if isinstance(t, ListT):
        return ListT(erase_tvars(t.elem))
    if isinstance(t, MapT):
        return MapT(erase_tvars(t.elem))
    if isinstance(t, OptT):
        return opt(erase_tvars(t.inner))
    if isinstance(t, FnT):
        return FnT(tuple(erase_tvars(p) for p in t.params), erase_tvars(t.ret))
    return t


def assignable(src: Ty, dst: Ty) -> bool:
    """Can a value of type src be used where dst is expected?

    Rules: Unknown/Never/Any absorb; Int widens to Float; T, T? and none go to T?; containers are
    invariant (they are shared by reference) except that an empty literal's Never element fits any
    element type; fn types are contravariant in parameters and covariant in the result."""
    if src == UNKNOWN or dst == UNKNOWN or src == NEVER or dst == ANY:
        return True
    if src == dst:
        return True
    if src == INT and dst == FLOAT:
        return True
    if isinstance(dst, OptT):
        if src == NONE:
            return True
        if isinstance(src, OptT):
            return assignable(src.inner, dst.inner)
        return assignable(src, dst.inner)
    if isinstance(src, ListT) and isinstance(dst, ListT):
        return _same_elem(src.elem, dst.elem)
    if isinstance(src, MapT) and isinstance(dst, MapT):
        return _same_elem(src.elem, dst.elem)
    if isinstance(src, FnT) and isinstance(dst, FnT):
        return (len(src.params) == len(dst.params)
                and all(assignable(d, s) for s, d in zip(src.params, dst.params))
                and (dst.ret == NONE or assignable(src.ret, dst.ret)))
    return False


def widen_plan(src: Ty, dst: Ty):
    """How a value of type src must change at run time to be a dst (Int -> Float widening), or None.

    "F": an Int becomes a Float.  ("fn", param_plans, ret_plan): a function value whose arguments are widened
    by the param plans (dst -> src, contravariant) and whose result is widened by ret_plan.  Containers are
    invariant (no plan needed); an Optional widens its inner value, `none` passes through."""
    if src == INT and dst == FLOAT:
        return "F"
    if isinstance(dst, OptT):
        if src == NONE:
            return None
        return widen_plan(src.inner if isinstance(src, OptT) else src, dst.inner)
    if isinstance(src, FnT) and isinstance(dst, FnT) and len(src.params) == len(dst.params):
        ps = tuple(widen_plan(d, s) for s, d in zip(src.params, dst.params))
        r = None if dst.ret == NONE else widen_plan(src.ret, dst.ret)
        if r is None and all(p is None for p in ps):
            return None
        return ("fn", ps, r)
    return None


def _same_elem(s: Ty, d: Ty) -> bool:
    if s == NEVER or s == UNKNOWN or d == UNKNOWN or s == d:
        return True
    if isinstance(s, ListT) and isinstance(d, ListT):
        return _same_elem(s.elem, d.elem)
    if isinstance(s, MapT) and isinstance(d, MapT):
        return _same_elem(s.elem, d.elem)
    if isinstance(s, OptT) and isinstance(d, OptT):
        return _same_elem(s.inner, d.inner)
    if isinstance(s, FnT) and isinstance(d, FnT):
        return assignable(s, d) and assignable(d, s)
    return False


def _floated(t: Ty) -> Ty:
    if t == INT:
        return FLOAT
    if isinstance(t, ListT):
        return ListT(_floated(t.elem))
    if isinstance(t, MapT):
        return MapT(_floated(t.elem))
    if isinstance(t, OptT):
        return opt(_floated(t.inner))
    if isinstance(t, FnT):
        return FnT(tuple(_floated(p) for p in t.params), _floated(t.ret))
    return t


def int_float_only(a: Ty, b: Ty) -> bool:
    """True when a and b differ only by Int vs Float somewhere inside (List[Int] vs List[Float]): containers do
    not widen (SPEC §2), so the hint can say exactly what to write."""
    return a != b and _floated(a) == _floated(b)


NO_WIDEN_HINT = ("containers do not widen (SPEC §2): an existing List[Int] is not a List[Float]; "
                 "write the numbers as Floats, e.g. 3.0 instead of 3")


def join(a: Ty, b: Ty) -> Ty | None:
    """Smallest type both a and b fit into (for if/match branches and list items); None if none."""
    if a == NEVER:
        return b
    if b == NEVER:
        return a
    if a == UNKNOWN or b == UNKNOWN:
        return UNKNOWN
    if a == NONE and b != NONE:
        return opt(b) if not isinstance(b, OptT) else b
    if b == NONE and a != NONE:
        return opt(a) if not isinstance(a, OptT) else a
    if isinstance(a, OptT) and not isinstance(b, OptT):
        j = join(a.inner, b)
        return opt(j) if j is not None else None
    if isinstance(b, OptT) and not isinstance(a, OptT):
        j = join(a, b.inner)
        return opt(j) if j is not None else None
    if isinstance(a, OptT) and isinstance(b, OptT):
        j = join(a.inner, b.inner)
        return opt(j) if j is not None else None
    if isinstance(a, ListT) and isinstance(b, ListT):
        if a.elem == NEVER:
            return b
        if b.elem == NEVER:
            return a
    if isinstance(a, MapT) and isinstance(b, MapT):
        if a.elem == NEVER:
            return b
        if b.elem == NEVER:
            return a
    if assignable(a, b):
        return b
    if assignable(b, a):
        return a
    return None


def unify(p: Ty, a: Ty, b: dict, fixed: frozenset = frozenset(), contra: bool = False) -> bool:
    """Match argument type `a` against parameter type `p` (which may contain T/U/Num/Any),
    extending the bindings `b`. Variables in `fixed` (bound by the receiver) never change.
    contra: we are inside a function type's parameter list, where values flow the other way (from p into a):
    `[1, 2].map(half)` with half: fn(Float) -> Float fits fn(Int) -> U, as for user fns (SPEC §2, round 5 F4)."""
    if a == UNKNOWN or p == ANY or p == UNKNOWN:
        return True
    if isinstance(p, TVar):
        if p.name in b:
            bound = b[p.name]
            if assignable(bound, a) if contra else assignable(a, bound):
                return True
            if (not contra and p.name not in fixed and (bound == NEVER or has_never_elem(bound))
                    and join(bound, a) is not None):
                b[p.name] = join(bound, a)
                return True
            return False
        b[p.name] = a
        return True
    if p == NUM:
        return a in NUMERIC or a == NEVER
    if not has_tvar(p):
        return assignable(p, a) if contra else assignable(a, p)
    if a == NEVER:
        return True
    if isinstance(p, ListT) and isinstance(a, ListT):
        return unify(p.elem, a.elem, b, fixed, contra)
    if isinstance(p, MapT) and isinstance(a, MapT):
        return unify(p.elem, a.elem, b, fixed, contra)
    if isinstance(p, OptT):
        if contra:                      # the fn gets p's values, `none` included: its parameter must take none
            return isinstance(a, OptT) and unify(p.inner, a.inner, b, fixed, contra)
        if a == NONE:
            return True
        return unify(p.inner, a.inner if isinstance(a, OptT) else a, b, fixed)
    if isinstance(p, FnT) and isinstance(a, FnT):
        if len(p.params) != len(a.params):
            return False
        ok = all(unify(pp, ap, b, fixed, not contra) for pp, ap in zip(p.params, a.params))
        return unify(p.ret, a.ret, b, fixed, contra) and ok
    return False


def is_jsonable(t: Ty, records: dict, enums: dict, seen: frozenset = frozenset()) -> bool:
    """JSON-able = Int Float Str Bool None, List/Map/optional of JSON-able, records and enums whose
    fields are JSON-able. fn types are not. `records`: name -> {field: Ty}; `enums`: name -> {variant: [(f, Ty)]}."""
    if t in (INT, FLOAT, STR, BOOL, NONE, UNKNOWN):
        return True
    if isinstance(t, (ListT, MapT)):
        return is_jsonable(t.elem, records, enums, seen)
    if isinstance(t, OptT):
        return is_jsonable(t.inner, records, enums, seen)
    if isinstance(t, Named):
        if t.name in seen:
            return True
        seen = seen | {t.name}
        if t.kind == "record":
            fields = records.get(t.name, {})
            return all(is_jsonable(ft, records, enums, seen) for ft in fields.values())
        variants = enums.get(t.name, {})
        return all(is_jsonable(ft, records, enums, seen) for fs in variants.values() for _, ft in fs)
    return False


@lru_cache(maxsize=None)
def from_stdlib(text: str) -> Ty:
    """Parse a stdlib.py type string ("List[T]", "fn(U, T) -> U", "Str?", "Num") into a Ty."""
    from .lexer import Lexer
    from .parser import Parser
    te = Parser(Lexer(text, "<stdlib>").tokenize(), "<stdlib>").type_expr()
    return _from_te(te)


def _from_te(te) -> Ty:
    from . import ast as A
    if isinstance(te, A.TOptional):
        return opt(_from_te(te.inner))
    if isinstance(te, A.TFn):
        return FnT(tuple(_from_te(p) for p in te.params), _from_te(te.ret))
    special = {"T": TVar("T"), "U": TVar("U"), "Num": NUM, "Any": ANY, "Never": NEVER, **PRIMS}
    if te.name == "List":
        return ListT(_from_te(te.args[0]))
    if te.name == "Map":
        return MapT(_from_te(te.args[0]))
    if te.name in special:
        return special[te.name]
    raise ValueError(f"bad stdlib type {te.name}")


def ty_to_te(t: Ty):
    """A JSON-able checker type back to a type expression (the runtime decodes memory.load with it)."""
    from . import ast as A
    if isinstance(t, OptT):
        return A.TOptional(line=0, col=0, inner=ty_to_te(t.inner))
    if isinstance(t, ListT):
        return A.TName(line=0, col=0, name="List", args=[ty_to_te(t.elem)])
    if isinstance(t, MapT):
        return A.TName(line=0, col=0, name="Map", args=[ty_to_te(t.elem)])
    if isinstance(t, (Prim, Named)):
        return A.TName(line=0, col=0, name=str(t), args=[])
    raise ValueError(f"type {t} has no type expression")
