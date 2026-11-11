"""Sipar standard library *signatures* — the single contract shared by the checker and the runtime.

Type strings use Sipar type syntax plus three pseudo-types:
  T, U   — generic type variables (bound per call)
  Num    — Int or Float (result is Float if any Num argument is Float, else Int)
  Never  — the call does not return (fail)
  Any    — any type (print, json.encode); the checker accepts every argument type

Taint metadata (enforced by the runtime, see SPEC.md §6):
  source       — result gets label "untrusted:<source>:<detail>"
  secret       — result gets label "secret:<name>"
  sink         — parameter names that must not carry an untrusted label
  no_secret    — parameter names that must not carry a secret label
"""
from __future__ import annotations

from dataclasses import dataclass, replace, field


@dataclass(frozen=True)
class Sig:
    params: tuple[tuple[str, str], ...]         # (name, type)
    ret: str
    effects: tuple[str, ...] = ()
    defaults: tuple[str, ...] = ()              # parameter names that are optional (named-only default)
    source: str = ""
    secret: bool = False
    sink: tuple[str, ...] = ()
    no_secret: tuple[str, ...] = ()
    doc: str = ""


def S(sig: str, ret: str, **kw) -> Sig:
    params = []
    for part in [p.strip() for p in sig.split(";") if p.strip()]:
        name, ty = part.split(":", 1)
        params.append((name.strip(), ty.strip()))
    for k in ("effects", "defaults", "sink", "no_secret"):
        if k in kw and isinstance(kw[k], str):
            kw[k] = tuple(x for x in kw[k].split() if x)
    return Sig(tuple(params), ret, **kw)


# Global functions and module functions ("http.get").  Parameters separated by ';'.
FUNCTIONS: dict[str, Sig] = {
    "print": S("value: Any", "None", no_secret="value", doc="Print a value on its own line."),
    "input": S("prompt: Str", "Str", effects="io", source="input", doc="Read a line from the terminal."),
    "min": S("a: Num; b: Num", "Num"),
    "max": S("a: Num; b: Num", "Num"),
    "abs": S("x: Num", "Num"),
    "round": S("x: Num", "Int", doc="Round half away from zero."),
    "floor": S("x: Num", "Int"),
    "range": S("start: Int; end: Int", "List[Int]", doc="start..end, end exclusive."),
    "trust": S("value: T; reason: Str", "T", doc="Declassify: remove untrusted labels (journaled)."),
    "approve": S("value: T; question: Str", "T", effects="io",
                 doc="Ask a human; yes removes untrusted labels, no raises error kind 'denied'."),
    "fail": S("kind: Str; message: Str", "Never", doc="Raise an error."),
    "sleep": S("seconds: Num", "None", effects="time"),
    "http.get": S("url: Str; headers: Map[Str]", "Str", effects="net", defaults="headers",
                  source="net", sink="url headers", no_secret="url", doc="HTTP GET, returns the body."),
    "http.post": S("url: Str; body: Str; headers: Map[Str]", "Str", effects="net", defaults="headers",
                   source="net", sink="url body headers", no_secret="url body", doc="HTTP POST, returns the body."),
    "fs.read": S("path: Str", "Str", effects="fs.read", source="file"),
    "fs.write": S("path: Str; text: Str", "None", effects="fs.write", sink="path text", no_secret="path text"),
    "fs.exists": S("path: Str", "Bool", effects="fs.read"),
    "shell.run": S("cmd: Str", "Str", effects="shell", source="shell", sink="cmd", no_secret="cmd",
                   doc="Run a command (no shell expansion; split like a POSIX shell), return stdout."),
    "env.get": S("name: Str", "Str?", effects="env"),
    "env.secret": S("name: Str", "Str", effects="secret", secret=True,
                    doc="Read a secret (needs `allow secret [NAME]`); it can only flow into http headers."),
    "time.now": S("", "Float", effects="time", doc="Unix time in seconds."),
    "random.int": S("lo: Int; hi: Int", "Int", effects="random", doc="Uniform integer in [lo, hi]."),
    "json.encode": S("value: Any", "Str", no_secret="value"),
    "memory.save": S("key: Str; value: T", "None", effects="memory", sink="key", no_secret="key value",
                     doc="Store a JSON-able value under key; labels are stored with it (secrets: error)."),
    "memory.load": S("key: Str", "T?", effects="memory", no_secret="key",
                     doc="Stored value or none; T comes from the expected type; labels come back."),
    "memory.delete": S("key: Str", "Bool", effects="memory", sink="key", no_secret="key",
                       doc="Remove key; true if it existed."),
    "memory.keys": S("", "List[Str]", effects="memory", doc="All stored keys, sorted."),
    "mcp.call": S("server: Str; tool: Str; args: Map[Any]", "Str", effects="mcp",
                  source="mcp", sink="server tool", no_secret="server tool",
                  doc="Call a tool of an `allow mcp` server by its MCP name; the result is untrusted Str."),
}

# Default-deny for secrets: no parameter of an effectful function may carry a secret, except the values of
# http headers (the one place a secret is meant to go). Structural, so a new effectful function is covered.
FUNCTIONS = {name: (replace(sig, no_secret=tuple(sorted({p for p, _ in sig.params if p != "headers"})))
                    if sig.effects else sig) for name, sig in FUNCTIONS.items()}

# Methods by receiver kind.  T = element type of List/Map.
METHODS: dict[str, dict[str, Sig]] = {
    "Str": {
        "len": S("", "Int"),
        "upper": S("", "Str"),
        "lower": S("", "Str"),
        "trim": S("", "Str"),
        "split": S("sep: Str", "List[Str]"),
        "lines": S("", "List[Str]", doc="Split at \\n, \\r\\n or \\r only; a final line break adds no empty line."),
        "contains": S("s: Str", "Bool"),
        "starts_with": S("s: Str", "Bool"),
        "ends_with": S("s: Str", "Bool"),
        "replace": S("old: Str; new: Str", "Str"),
        "find": S("s: Str", "Int?"),
        "repeat": S("n: Int", "Str"),
    },
    "List": {
        "len": S("", "Int"),
        "push": S("item: T", "None", doc="Append in place."),
        "pop": S("", "T?", doc="Remove and return the last item."),
        "map": S("f: fn(T) -> U", "List[U]"),
        "filter": S("f: fn(T) -> Bool", "List[T]"),
        "reduce": S("init: U; f: fn(U, T) -> U", "U"),
        "any": S("f: fn(T) -> Bool", "Bool"),
        "all": S("f: fn(T) -> Bool", "Bool"),
        "join": S("sep: Str", "Str", doc="Render items as text and join."),
        "sort": S("", "List[T]", doc="New sorted list (T must be Int, Float or Str; NaN sorts last)."),
        "sort_by": S("key: fn(T) -> U", "List[T]", doc="New list sorted by key (Int, Float or Str; NaN sorts last)."),
        "reverse": S("", "List[T]", doc="New reversed list."),
        "contains": S("item: T", "Bool"),
        "index_of": S("item: T", "Int?"),
        "first": S("", "T?"),
        "last": S("", "T?"),
        "sum": S("", "T", doc="T must be Int or Float; sum of [] is 0 (0.0 for a List[Float])."),
        "take": S("n: Int", "List[T]"),
        "skip": S("n: Int", "List[T]"),
    },
    "Map": {
        "len": S("", "Int"),
        "keys": S("", "List[Str]", doc="Keys in insertion order."),
        "values": S("", "List[T]"),
        "has": S("key: Str", "Bool"),
        "get": S("key: Str", "T?"),
        "remove": S("key: Str", "T?", doc="Remove in place, return the old value."),
    },
}

# Built-in record type available in every program (the value bound by `catch e`).
BUILTIN_TYPES = {"Error": (("kind", "Str"), ("message", "Str"))}

MODULES = sorted({k.split(".")[0] for k in FUNCTIONS if "." in k})     # http fs shell env time random json

# Attributes allowed on ai fn / agent fn, with their literal type.
ATTRIBUTES = {
    "model": "Str", "retries": "Int", "temperature": "Float", "max_steps": "Int", "system": "Str",
}
AI_ATTRS = {"model", "retries", "temperature", "system"}
AGENT_ATTRS = AI_ATTRS | {"max_steps"}

BUDGET_LIMITS = {"ai_calls": "Int", "tokens": "Int", "usd": "Num", "seconds": "Num"}
