"""`sipar trace JOURNAL.jsonl`: cost, tokens, time and errors per function and per model (SPEC.md §9).

Reads a run journal (one JSON object per line). Works on journals from older versions too: a missing
"fn" falls back to the ai request's "fn" or "(top)", a missing "ms" counts as 0.
"""
from __future__ import annotations

import json
from typing import Any

from .errors import escape_text
from .runtime import jsondeep

AI_KINDS = ("ai", "agent")


# Sane ranges: a number outside its range (or not a finite non-negative number) counts as 0, so a hostile
# journal cannot overflow a sum or a float conversion (SPEC §9).
MAX_T = 1e11            # seconds since 1970 (year ~5100)
MAX_MS = 1e10           # one effect: ~115 days
MAX_TOKENS = 10_000_000  # one entry, same bound as provider usage (providers.MAX_USAGE)
MAX_USD = 1e9           # one entry


class TraceError(Exception):
    """The journal cannot be read (bad JSON line, not an object)."""


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def read_entries(text: str, name: str = "journal") -> list[dict]:
    out = []
    name = escape_text(name)
    for i, line in enumerate(text.split("\n"), 1):     # "\n" only: U+2028 etc. sit inside strings (F1)
        if not line.strip():
            continue
        try:
            e = jsondeep.loads(line, parse_constant=_no_constant)      # NaN / Infinity: a bad line
        except jsondeep.NumberTooLarge as x:
            raise TraceError(f"{name} line {i} holds {x}")
        except (ValueError, RecursionError):
            raise TraceError(f"{name} line {i} is not valid JSON")
        if not isinstance(e, dict) or not isinstance(e.get("kind"), str):
            raise TraceError(f"{name} line {i} is not a journal entry (no \"kind\")")
        out.append(e)
    return out


def _num(x: Any, top: float = MAX_MS) -> float:
    """x if it is a number in [0, top], else 0 (no float() of a huge int: it would overflow)."""
    if isinstance(x, bool) or not isinstance(x, (int, float)) or x != x or not 0 <= x <= top:
        return 0
    return x


def _row() -> dict:
    return {"effects": 0, "ai_calls": 0, "tokens_in": 0, "tokens_out": 0, "usd": None, "ms": 0.0, "errors": 0}


def _add(row: dict, e: dict) -> None:
    row["effects"] += 1
    row["ms"] += _num(e.get("ms"))
    if e.get("error"):
        row["errors"] += 1
    m0 = e.get("meta")
    if e.get("kind") in AI_KINDS and not (isinstance(m0, dict) and m0.get("setup") is True):
        row["ai_calls"] += 1        # a model setup failure (round 8, M1) sent no request: not a call
        resp = e.get("response")
        usage = resp.get("usage") if isinstance(resp, dict) else None
        meta = e.get("meta")
        if not isinstance(usage, dict) and isinstance(meta, dict):
            usage = meta.get("usage")        # a failed attempt that was charged (SPEC §7): same tokens as usd
        if isinstance(usage, dict):
            row["tokens_in"] += int(_num(usage.get("input"), MAX_TOKENS))
            row["tokens_out"] += int(_num(usage.get("output"), MAX_TOKENS))
    meta = e.get("meta")
    if isinstance(meta, dict) and "usd" in meta:
        row["usd"] = (row["usd"] or 0) + _num(meta.get("usd"), MAX_USD)


def _fn_of(e: dict) -> str:
    fn = e.get("fn")
    if isinstance(fn, str) and fn:
        return escape_text(fn)
    req = e.get("request")
    if e.get("kind") in AI_KINDS and isinstance(req, dict) and isinstance(req.get("fn"), str):
        return escape_text(req["fn"])
    return "(top)"


def summarize(entries: list[dict]) -> dict:
    fns: dict[str, dict] = {}
    models: dict[str, dict] = {}
    kinds: dict[str, int] = {}
    total = _row()
    ts = []
    for e in entries:
        kind = e["kind"]
        shown = escape_text(kind)              # names from the journal are printed: no ESC / bidi / newlines
        kinds[shown] = kinds.get(shown, 0) + 1
        _add(fns.setdefault(_fn_of(e), _row()), e)
        _add(total, e)
        meta = e.get("meta")
        if kind in AI_KINDS and isinstance(meta, dict) and isinstance(meta.get("model"), str):
            _add(models.setdefault(escape_text(meta["model"]), _row()), e)
        t = e.get("t")
        if isinstance(t, (int, float)) and not isinstance(t, bool) and 0 <= t <= MAX_T:
            ts.append((t, t + _num(e.get("ms")) / 1000))
    for r in [total, *fns.values(), *models.values()]:
        r["ms"] = round(r["ms"], 3)
        if r["usd"] is not None:
            r["usd"] = round(r["usd"], 9)
    span = round((max(b for _, b in ts) - min(a for a, _ in ts)) * 1000, 3) if ts else None
    return {"functions": fns, "models": models, "kinds": dict(sorted(kinds.items())),
            "totals": dict(total, span_ms=span)}


def _cell(v: Any) -> str:
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v:.9f}".rstrip("0").rstrip(".") if v < 1 else f"{v:.2f}"   # usd is kept to 9 places
    return str(v)


def _table(title: str, rows: dict[str, dict]) -> list[str]:
    head = [title, "effects", "ai calls", "tokens in", "tokens out", "usd", "ms", "errors"]
    body = [[name] + [_cell(r[k]) for k in ("effects", "ai_calls", "tokens_in", "tokens_out", "usd")]
            + [f"{r['ms']:.1f}", str(r["errors"])] for name, r in rows.items()]
    widths = [max(len(x[i]) for x in [head] + body) for i in range(len(head))]

    def fmt(cells):
        return "  ".join(c.ljust(w) if i == 0 else c.rjust(w) for i, (c, w) in enumerate(zip(cells, widths)))
    return [fmt(head), "  ".join("-" * w for w in widths)] + [fmt(b) for b in body]


def render(s: dict) -> str:
    t = s["totals"]
    if not t["effects"]:
        return "no entries\ntotal: 0 effects, 0 ai calls, 0 tokens, 0 errors\n"
    rows = dict(sorted(s["functions"].items()))
    rows["(total)"] = t                        # "(total)" cannot be a function name
    lines = _table("function", rows)
    lines.insert(len(lines) - 1, lines[1])     # rule above the totals row
    if s["models"]:
        lines += [""] + _table("model", dict(sorted(s["models"].items())))
    span = f", run span {t['span_ms'] / 1000:.3f} s" if t["span_ms"] is not None else ""
    lines.append("effects by kind: " + ", ".join(f"{k} {n}" for k, n in s["kinds"].items()) + span)
    if t["usd"] is None and t["ai_calls"]:
        lines.append("usd: no prices recorded (set SIPAR_PRICE_IN / SIPAR_PRICE_OUT, USD per 1M tokens)")
    return "\n".join(lines) + "\n"
