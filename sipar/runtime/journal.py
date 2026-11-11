"""Effect journal (record) and replay.

Each nondeterministic effect is one JSON line: {seq, kind, request, response, labels} (+ "error" when the effect
failed, + "meta" with non-compared details such as the model name, + timing fields "t" (unix start time), "ms"
(duration) and "fn" (the Sipar function that performed it), used by `sipar trace`). Requests and responses are
plain JSON data that has already been redacted (secrets appear as «secret:NAME»). In replay mode the journal
serves responses in order and never calls `perform`; only kind, request, response and error are compared/used.
"""
from __future__ import annotations

import json
import math
import os
import time
from typing import Any, Callable

from ..errors import SiparRuntimeError, current_registry, redact_spans, redact_text, register_secret
from ..fileread import open_regular, program_dir, why_unreadable
from . import jsondeep
from .values import holds_lone_surrogate


def canon(x: Any) -> str:
    """Canonical JSON text; a value JSON cannot hold (a tampered journal) gets a marker that equals nothing valid."""
    try:
        return jsondeep.dumps(x, sort_keys=True, ensure_ascii=False)
    except (ValueError, TypeError, RecursionError):
        return f"\0not-json:{type(x).__name__}"


def _short(x: Any, n: int = 120) -> str:
    s = canon(x)
    return s if len(s) <= n else s[:n] + "…"


def first_diff(a: Any, b: Any, path: str = "") -> str:
    """Human-readable first difference between two JSON values."""
    if type(a) is not type(b):
        return f"{path or '$'}: journal {_short(a)} vs program {_short(b)}"
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                return f"{path}.{k}: not in journal, program has {_short(b[k])}"
            if k not in b:
                return f"{path}.{k}: journal has {_short(a[k])}, program has nothing"
            if canon(a[k]) != canon(b[k]):
                return first_diff(a[k], b[k], f"{path}.{k}")
    if isinstance(a, list):
        for i, (x, y) in enumerate(zip(a, b)):
            if canon(x) != canon(y):
                return first_diff(x, y, f"{path}[{i}]")
        if len(a) != len(b):
            return f"{path or '$'}: journal has {len(a)} items, program has {len(b)}"
    if isinstance(a, str) and isinstance(b, str):
        i = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
        lo = max(0, i - 20)
        ja, pb = a[lo:i + 40], b[lo:i + 40]
        why = ""
        if redact_text(ja) == redact_text(pb):         # R9-2: never two identical-looking strings without a reason
            why = " (they differ inside text that matches a secret value, which is not shown)"
        return f"{path or '$'} differs at char {i}: journal {ja!r} vs program {pb!r}{why}"
    return f"{path or '$'}: journal {_short(a)} vs program {_short(b)}"


def _num(r: Any) -> bool:
    try:
        return type(r) in (int, float) and math.isfinite(r)
    except OverflowError:                      # an int too large for a float
        return False


def _random_ok(r: Any, req: Any) -> bool:
    return (type(r) is int and isinstance(req, dict) and type(req.get("lo")) is int
            and type(req.get("hi")) is int and req["lo"] <= r <= req["hi"])


def secret_record_ok(r: Any) -> bool:
    """Shape of an env.secret response: {salt, hash, len} (hex strings and a length, never the value)."""
    return (isinstance(r, dict) and isinstance(r.get("salt"), str) and isinstance(r.get("hash"), str)
            and type(r.get("len")) is int and r["len"] >= 0)


# What a served response must look like, per effect kind. A tampered or corrupt journal is a `replay` error,
# never a Python crash deeper in the interpreter. Kinds not listed are checked where they are used.
_VALID: dict[str, Callable[[Any, Any], bool]] = {
    "http": lambda r, q: isinstance(r, str),
    "fs.read": lambda r, q: isinstance(r, str),
    "shell": lambda r, q: isinstance(r, str),
    "input": lambda r, q: isinstance(r, str),
    "env.get": lambda r, q: r is None or isinstance(r, str),
    "env.secret": lambda r, q: secret_record_ok(r),
    "fs.exists": lambda r, q: type(r) is bool,
    "approve": lambda r, q: type(r) is bool,
    "memory.delete": lambda r, q: type(r) is bool,
    "time": lambda r, q: _num(r),
    "random": _random_ok,
    "memory.load": lambda r, q: r is None or (isinstance(r, dict) and "value" in r
                                              and isinstance(r.get("labels"), list)),
    "budget": lambda r, q: False,              # a budget entry only ever replays its recorded error
    "mcp": lambda r, q: isinstance(r, dict) and isinstance(r.get("text"), str),
    "mcp.connect": lambda r, q: isinstance(r, dict) and isinstance(r.get("version"), str)
                                 and isinstance(r.get("hash"), str) and isinstance(r.get("tools"), list)
                                 and all(isinstance(t, dict) and isinstance(t.get("name"), str) for t in r["tools"]),
}


class Journal:
    def __init__(self, path: str | None = None, replay: list[dict] | None = None, source: str = ""):
        self.path = path
        self.replaying = replay is not None
        self.entries: list[dict] = replay if replay is not None else []
        self.pos = 0
        self.seq = 0
        self.source = source
        self._fh = None
        self.secrets: dict[str, str] = {}          # secret value -> «secret:NAME», scrubbed from every entry
        self.fn: str | None = None                 # current Sipar function (set by the interpreter)
        self.last: dict | None = None              # the entry written or served by the latest effect()
        self.vclock = 0.0                          # replay: seconds of recorded effect time served so far
        self.on_close: list[Callable[[], None]] = []   # run when the run ends (MCP servers are stopped)
        if path and not self.replaying:
            try:
                if os.path.dirname(path):            # a bare file name lives in the current directory (C5)
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                # one run per journal: an old file is replaced. Never through a symbolic link, never a FIFO or
                # device (it would block or write elsewhere) — round 10, J1
                fd = open_regular(path, None, write=True, nofollow=True)
                try:
                    os.ftruncate(fd, 0)
                except BaseException:
                    os.close(fd)
                    raise
                self._fh = os.fdopen(fd, "w", encoding="utf-8")
            except OSError as e:
                why = why_unreadable(e)
                if isinstance(e, (FileExistsError, NotADirectoryError)):    # a file where a folder must be (round 9, L5)
                    d = os.path.dirname(path)
                    while d and not os.path.exists(d) and os.path.dirname(d) != d:
                        d = os.path.dirname(d)
                    if d and os.path.exists(d) and not os.path.isdir(d):
                        why = f"{d} is not a folder"
                raise SiparRuntimeError("io", f"cannot write journal {path}: {why}") from None

    # -------------------------------------------------------------- loading
    @staticmethod
    def load(path: str) -> list[dict]:
        name = os.path.basename(path)
        if os.path.isdir(path):
            raise SiparRuntimeError("replay", f"cannot read journal {path}: is a directory")
        try:            # round 8: opened without blocking, a regular file only (a FIFO hung, /dev/zero never ended)
            with open(open_regular(path, None), encoding="utf-8", newline="") as fh:
                lines = fh.read().split("\n")   # JSON lines end at "\n" only; "\r" before it is JSON space (F1)
        except (OSError, UnicodeDecodeError) as e:     # not text at all, or unreadable: one wording (round 7)
            raise SiparRuntimeError("replay", f"cannot read journal {path}: {why_unreadable(e)}") from None
        out = []
        for i, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                e = jsondeep.loads(line)
            except jsondeep.NumberTooLarge as x:
                raise SiparRuntimeError("replay", f"journal {name} line {i} holds {x}") from None
            except ValueError:
                raise SiparRuntimeError("replay", f"journal {name} line {i} is not valid JSON") from None
            except RecursionError:              # [[[[... a million deep
                raise SiparRuntimeError("replay", f"journal {name} line {i} is nested too deeply") from None
            if not isinstance(e, dict) or "kind" not in e or "request" not in e:
                raise SiparRuntimeError("replay", f"journal {name} line {i} lacks 'kind'/'request'")
            if "\\u" in line and holds_lone_surrogate(e):      # round 5, C2: never a Sipar Str
                raise SiparRuntimeError("replay", f"journal {name} line {i} holds text that is not valid Unicode "
                                                  f"(a lone surrogate)")
            out.append(e)
        return out

    # -------------------------------------------------------------- core
    def effect(self, kind: str, request: Any, perform: Callable[[], Any], labels: list[str] | None = None,
               meta: dict | None = None, raw: bool = False) -> Any:
        """Record (or, in replay, serve) one effect. raw=True keeps the response out of secret scrubbing; it is
        for responses the runtime computes itself that never contain secret text (the env.secret hash)."""
        self.seq += 1
        if self.replaying:
            return self._serve(kind, request)
        entry: dict = {"seq": self.seq, "kind": kind, "request": request}
        t0 = time.time()
        p0 = time.perf_counter()

        def stamp() -> None:
            if meta:
                entry["meta"] = meta
            entry["t"] = round(t0, 3)
            entry["ms"] = round((time.perf_counter() - p0) * 1000, 3)
            if self.fn:
                entry["fn"] = self.fn

        try:
            response = perform()
        except SiparRuntimeError as e:
            entry.update(response=None, labels=[], error={"kind": e.kind, "message": e.message})
            stamp()
            self._write(entry)
            raise
        entry.update(response=response, labels=sorted(labels or []))
        stamp()
        self._write(entry, raw)
        return response

    def peek(self) -> dict | None:
        """Replay: the next entry, not consumed."""
        return self.entries[self.pos] if self.replaying and self.pos < len(self.entries) else None

    def _serve(self, kind: str, request: Any) -> Any:
        if self.pos >= len(self.entries):
            raise SiparRuntimeError("replay", f"replay diverged at effect #{self.seq}: the program performs "
                                              f"{kind} {_short(request, 80)} but the journal has no more entries")
        e = self.entries[self.pos]
        self.pos += 1
        self.last = e
        if e.get("kind") != kind:
            raise SiparRuntimeError("replay", f"replay diverged at effect #{self.seq}: journal has {e.get('kind')} "
                                              f"{_short(e.get('request'), 80)}, program performs {kind} "
                                              f"{_short(request, 80)}")
        # R9-2 (round 9): the journal holds the request as recorded, scrubbed; compare the program's request
        # scrubbed the same way, so public text that contains a secret value ("?order=12345" with secret 2345)
        # does not diverge
        if canon(e.get("request")) != canon(request):
            live = self.scrub(request)
            if canon(e.get("request")) != canon(live):
                raise SiparRuntimeError("replay", f"replay diverged at effect #{self.seq} ({kind}): "
                                                  + first_diff(e.get("request"), live))
        ms = e.get("ms")
        if _num(ms) and ms >= 0:
            self.vclock += ms / 1000
        where = f"journal entry #{self.seq} ({kind})"
        if e.get("error") is not None:
            err = e["error"]
            if (not isinstance(err, dict) or err.get("kind") not in SiparRuntimeError.KINDS
                    or not isinstance(err.get("message"), str)):
                raise SiparRuntimeError("replay", f"{where}: the recorded error is malformed")
            raise SiparRuntimeError(err["kind"], err["message"])
        restore = e.get("restore")
        resp = self._restore(e.get("response"), restore.get("response") if isinstance(restore, dict) else None)
        check = _VALID.get(kind)
        if check is not None and not check(resp, request):
            raise SiparRuntimeError("replay", f"{where}: the recorded response {_short(resp, 60)} is not valid "
                                              f"for this effect")
        return resp

    def add_secret(self, value: str, label: str) -> None:
        """Remember a secret value so that it never reaches the journal, even if a server echoes it back."""
        if isinstance(value, str) and len(value) >= 4:
            self.secrets[str(value)] = f"«{label}»"
            register_secret(value, label)

    def scrub(self, x: Any) -> Any:
        if isinstance(x, str):
            return redact_text(x, extra=self.secrets)        # R9-4: one pass over the union of all matches
        if isinstance(x, list):
            return [self.scrub(i) for i in x]
        if isinstance(x, dict):
            return {self.scrub(k): self.scrub(v) for k, v in x.items()}
        return x

    # ---------------------------------------------- secrets in responses (round 10, R1)
    # A response that holds a secret is journaled with the «secret:NAME» marker in its place, so a journal never
    # holds a secret. Replay must still see what the run saw: a model reply "482913" equal to the PIN decoded to
    # an Int in the run but "«secret:PIN»" failed to decode in replay, so replay retried the call and diverged.
    # The entry therefore keeps, for every marker it put in, *where* it is and *which* registered form of the
    # secret it replaced (an index, never the text). Replay re-reads the secret itself (env.secret checks it
    # against the recorded hash) and puts the same form back. A marker that was already in the text, a merged
    # span of two secrets, or a form replay does not know stays a marker, as before.

    def _forms(self, mark: str) -> list[str]:
        """The registered forms of the secret behind `mark`, in registration order (the same in a replay that
        registers the same secrets in the same order)."""
        out: list[str] = []
        seen: set[str] = set()
        for table in (self.secrets, current_registry().secrets):
            for form, m in table.items():
                if m == mark and form not in seen:
                    seen.add(form)
                    out.append(form)
        return out

    def _plan_text(self, text: str) -> list:
        """[[start, end, form index], ...] in the redacted text, for the markers that replaced one known form."""
        items, shift, cache = [], 0, {}
        for s, e, marks in redact_spans(text, extra=self.secrets):
            mark = "".join(marks)
            at = s + shift
            if len(marks) == 1:
                forms = cache.get(mark)
                if forms is None:
                    forms = cache[mark] = self._forms(mark)
                orig = text[s:e]
                if orig in forms:
                    items.append([at, at + len(mark), forms.index(orig)])
            shift += len(mark) - (e - s)
        return items

    def _plan(self, orig: Any, scrubbed: Any) -> list:
        """Restore items for every string (dict keys first, depth first) of `scrubbed` that holds a marker:
        [[string number, [[start, end, form index], ...]], ...]. Empty when the two shapes differ (two map keys
        that became one marker)."""
        plan: list = []
        n = 0
        todo = [(orig, scrubbed)]
        while todo:
            o, sc = todo.pop()
            if isinstance(o, str):
                if isinstance(sc, str) and sc != o:
                    items = self._plan_text(o)
                    if items:
                        plan.append([n, items])
                n += 1
            elif isinstance(o, list):
                if not isinstance(sc, list) or len(sc) != len(o):
                    return []
                todo.extend(reversed(list(zip(o, sc))))
            elif isinstance(o, dict):
                if not isinstance(sc, dict) or len(sc) != len(o):
                    return []
                pairs = []
                for (ko, vo), (ks, vs) in zip(o.items(), sc.items()):
                    pairs += [(ko, ks), (vo, vs)]
                todo.extend(reversed(pairs))
        return plan

    def _restore_text(self, text: str, items: Any) -> str:
        if not isinstance(items, list):
            return text
        out, end = text, len(text) + 1
        for it in reversed(items):              # from the end, so earlier positions stay valid
            if not (isinstance(it, list) and len(it) == 3 and all(type(x) is int for x in it)):
                continue
            s, e, i = it
            mark = out[s:e] if 0 <= s < e <= len(out) and e <= end else ""
            if not (mark.startswith("«secret:") and mark.endswith("»") and mark.count("«") == 1):
                continue
            forms = self._forms(mark)
            if 0 <= i < len(forms):
                out = out[:s] + forms[i] + out[e:]
                end = s
        return out

    def _restore(self, x: Any, plan: Any) -> Any:
        """x with the recorded markers turned back into the secret forms they replaced (see _plan)."""
        if not isinstance(plan, list) or not plan or not self.secrets:
            return x
        want = {p[0]: p[1] for p in plan if isinstance(p, list) and len(p) == 2 and type(p[0]) is int}
        if not want:
            return x
        n = 0

        def fix(s: str) -> str:
            nonlocal n
            items = want.get(n)
            n += 1
            return s if items is None else self._restore_text(s, items)

        if isinstance(x, str):
            return fix(x)
        root: list = [None]
        todo: list = [(x, root, 0)]           # (journal value, parent container, key/index in it)
        while todo:
            v, parent, slot = todo.pop()
            if isinstance(v, str):
                v = fix(v)
                parent[slot] = v
            elif isinstance(v, list):
                new: list = [None] * len(v)
                parent[slot] = new
                todo.extend(reversed([(item, new, i) for i, item in enumerate(v)]))
            elif isinstance(v, dict):
                pending = []
                for k, val in v.items():
                    pending.append(k)
                    pending.append(val)
                holder: list = [None] * len(pending)
                parent[slot] = _DictBuild(holder)
                todo.extend(reversed([(item, holder, i) for i, item in enumerate(pending)]))
            else:
                parent[slot] = v
        return _finish(root[0])

    def unused(self) -> int:
        return len(self.entries) - self.pos if self.replaying else 0

    def _write(self, entry: dict, raw: bool = False) -> None:
        resp = entry.get("response")
        entry = self.scrub(entry)
        if raw:
            entry["response"] = resp
        elif self.secrets or current_registry().secrets:
            # an error message needs nothing: SiparRuntimeError.message is redacted for the program too
            plan = self._plan(resp, entry.get("response"))
            if plan:
                entry["restore"] = {"response": plan}
        self.last = entry
        self.entries.append(entry)                 # in-memory copy (used by tests and `sipar test --record`)
        if self._fh is None:
            return
        try:
            self._fh.write(jsondeep.dumps_line(entry) + "\n")
            self._fh.flush()
        except (OSError, TypeError, ValueError) as e:
            raise SiparRuntimeError("io", f"cannot write journal entry: {e}")

    def close(self) -> None:
        while self.on_close:
            self.on_close.pop()()
        if self._fh is not None:
            self._fh.close()
            self._fh = None


class _DictBuild:
    """A map being rebuilt by Journal._restore: its keys and values in order, filled in place."""
    __slots__ = ("items",)

    def __init__(self, items: list):
        self.items = items


def _finish(x: Any) -> Any:
    """Turn the _DictBuild placeholders left by Journal._restore into dicts (inner ones first, no recursion)."""
    if not isinstance(x, (list, _DictBuild)):
        return x
    order, todo, seen = [], [x], set()
    while todo:
        v = todo.pop()
        if id(v) in seen:
            continue
        seen.add(id(v))
        order.append(v)
        for c in (v.items if isinstance(v, _DictBuild) else v):
            if isinstance(c, (list, _DictBuild)):
                todo.append(c)
    done: dict = {}
    for v in reversed(order):              # children before parents
        items = v.items if isinstance(v, _DictBuild) else v
        for i, c in enumerate(items):
            if isinstance(c, (list, _DictBuild)) and id(c) in done:
                items[i] = done[id(c)]
        if isinstance(v, _DictBuild):
            done[id(v)] = {v.items[i]: v.items[i + 1] for i in range(0, len(v.items), 2)}
        else:
            done[id(v)] = v
    return done[id(x)]


def new_run_path(program_file: str) -> str:
    base = os.path.join(program_dir(program_file), ".sipar", "runs")      # a pipe: the current folder (M4)
    stamp = time.strftime("%Y%m%d-%H%M%SZ", time.gmtime())   # UTC, marked with Z
    name = f"{stamp}-{os.getpid()}-{time.time_ns() % 1_000_000_000:09d}.jsonl"
    path = os.path.join(base, name)
    n = 1
    while os.path.exists(path):
        n += 1
        path = os.path.join(base, name.replace(".jsonl", f"-{n}.jsonl"))
    return path
