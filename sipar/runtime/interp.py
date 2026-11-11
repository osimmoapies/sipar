"""Tree-walking interpreter for Sipar programs."""
from __future__ import annotations

import hashlib
import math
import os
import re
import sys
import time
from typing import Any

from .. import ast as A
from ..deep import call_deep
from ..errors import SecretRegistry, SiparRuntimeError, escape_controls, use_registry
from ..errors import flush as _flush
from ..fileread import program_dir
from ..stdlib import BUDGET_LIMITS, FUNCTIONS, METHODS, MODULES
from . import ai as AI
from . import mcp as MCP
from .builtins import FUNCS, MAX_ITEMS, call_method, lab
from .decode import TypeEnv, coerce, from_json, json_loads, tag_field_enum, type_str
from .effects import Caps, check_sinks
from .journal import Journal
from .netio import env_seconds
from .providers import (MockProvider, check_script_names, clean_usage, estimate_tokens, make_provider, parse_chain,
                        parse_model, prompt_text, valid_count)
from .values import (EMPTY, Builtin, Closure, EnumVal, FnRef, LFn, LStr, RangeVal, Record, check_mutable,
                     deep_label, dumps, check_int, INT_TOO_LARGE, MAX_STR, STR_TOO_LARGE, equal, is_num, kind_of, label_written, labels_of, make_error,
                     mutated, new_list, own_labels, render, scrub_text, secrets_in, select, snippet, with_labels, WidenFn, widen)

INT_TEXT = re.compile(r"[+-]?[0-9]+(?:_[0-9]+)*")   # what int() accepts after strip(), ASCII only
# Str -> Float text: a sign, then a number as in a literal ('_' only between digits, never in the exponent);
# ".5" and "5." are accepted too, as data often has them (SPEC §5, round 5)
FLOAT_TEXT = re.compile(r"[+-]?(?:[0-9]+(?:_[0-9]+)*(?:\.(?:[0-9]+(?:_[0-9]+)*)?)?|\.[0-9]+(?:_[0-9]+)*)"
                        r"(?:[eE][+-]?[0-9]+)?")
MUTATORS = frozenset({"push", "pop", "remove"})     # methods that change their receiver in place
MAX_PRICE = 1e9          # USD per 1M tokens; above it (or NaN / inf) the price is not believed


def _max_depth() -> int:
    """SIPAR_MAX_DEPTH: an Int in [1, 20000]; anything else (text, 0, negative, huge) -> 800, never an import
    error."""
    try:
        n = int(os.environ.get("SIPAR_MAX_DEPTH", "800").strip() or 800)
    except ValueError:
        return 800
    return n if 1 <= n <= 20_000 else 800


MAX_DEPTH = _max_depth()


class ReturnSig(Exception):
    def __init__(self, value):
        self.value = value


class BreakSig(Exception):
    pass


class ContinueSig(Exception):
    pass


def tag(e: SiparRuntimeError, *vals: Any) -> SiparRuntimeError:
    """S1 (round 5): an error raised by an operation carries the labels of every operand the operation was given,
    because its message may quote a size, index or bound computed from them ("index 50 out of range (length
    6)"). `catch e` labels e.message with them and the outward text masks its numbers (errors.py). Exempt: the
    program's own fail()/assert (they carry their message's labels), taint errors (they name labels, never
    values) and replay errors."""
    if e.kind in ("taint", "replay") or getattr(e, "value", None) is not None:
        return e
    ls: frozenset = EMPTY
    for v in vals:      # a value, or a frozenset of labels (a pick's own labels)
        ls = ls | (v if isinstance(v, frozenset) else labels_of(v))
    if ls:
        e.labels = e.labels | ls
    return e


def err(kind: str, msg: str, node: A.Node | None = None) -> SiparRuntimeError:
    e = SiparRuntimeError(kind, msg)
    if node is not None:
        e.line, e.col = node.line, node.col
    return e


class Env:
    __slots__ = ("vars", "frozen", "parent")

    def __init__(self, parent: "Env | None" = None):
        self.vars: dict[str, Any] = {}
        self.frozen: set[str] = set()
        self.parent = parent

    def find(self, name: str) -> "Env | None":
        e = self
        while e is not None:
            if name in e.vars:
                return e
            e = e.parent
        return None

    def define(self, name: str, value: Any, mutable: bool = False) -> None:
        self.vars[name] = value
        if mutable:
            self.frozen.discard(name)
        else:
            self.frozen.add(name)


class BudgetFrame:
    def __init__(self, limits: dict, node: A.Node, start: float, labels: frozenset = EMPTY):
        self.limits = limits
        self.labels = labels            # labels of the limit values: a message quoting a limit carries them
        self.node = node
        self.start = start
        self.ai_calls = 0
        self.tokens = 0
        self.usd = 0.0

    def where(self) -> str:
        return f"budget at line {self.node.line}"


class Interp:
    def __init__(self, program: A.Program, file: str | None = None, *, journal: Journal | None = None,
                 out=None, err_out=None, stdin=None, test_mode: bool = False, live: bool = False,
                 mock_script: Any = None, providers: dict | None = None, model_override: str | None = None):
        mutated()                       # L (round 6): a host may have changed values between runs
        self.program = program
        self.model_override = model_override       # Python API: replaces @model and SIPAR_MODEL
        self.file = file or program.file
        base = program_dir(self.file) if self.file and not self.file.startswith("<") \
            else os.getcwd()
        self.out = out or sys.stdout
        self.err = err_out or sys.stderr
        self.stdin = stdin if stdin is not None else sys.stdin
        self.journal = journal or Journal()
        self.test_mode = test_mode
        self.live = live
        self.mock_script = mock_script
        self.providers: dict = dict(providers or {})
        self.budgets: list[BudgetFrame] = []
        self.ticks = 0                              # evaluation steps; names the moment a time budget ran out
        self.mocks: dict[str, tuple[A.Mock, Env]] = {}
        self.depth = 0
        records, enums = {}, {}
        self.fns: dict[str, A.FnDecl] = {}
        self.consts: list[A.ConstDecl] = []
        self.tests: list[A.TestDecl] = []
        allows = []
        for it in program.items:
            if isinstance(it, A.Allow):
                allows.append(it)
            elif isinstance(it, A.TypeDecl):
                records[it.name] = it.fields
            elif isinstance(it, A.EnumDecl):
                enums[it.name] = it.variants
            elif isinstance(it, A.FnDecl):
                self.fns[it.name] = it
            elif isinstance(it, A.ConstDecl):
                self.consts.append(it)
            elif isinstance(it, A.TestDecl):
                self.tests.append(it)
        self.tenv = TypeEnv(records, enums)
        self.caps = Caps(allows, base)
        self.globals = Env()
        self._globals_ready = False
        self.EVAL = {
            A.IntLit: lambda n, env: n.value, A.FloatLit: lambda n, env: n.value,
            A.BoolLit: lambda n, env: n.value, A.NoneLit: lambda n, env: None,
            A.StrLit: self.e_str, A.Name: self.e_name, A.ListLit: self.e_list, A.MapLit: self.e_map,
            A.RecordLit: self.e_record, A.Call: self.e_call, A.Field: self.e_field, A.Index: self.e_index,
            A.Unary: self.e_unary, A.Binary: self.e_binary, A.As: self.e_as, A.Lambda: self.e_lambda,
            A.Block: self.e_block, A.If: self.e_if, A.Match: self.e_match, A.Try: self.e_try,
            A.Budget: self.e_budget,
        }

    # ================================================================ entry points
    def init_globals(self) -> None:
        if self._globals_ready:
            return
        self._globals_ready = True
        for c in self.consts:
            v = coerce(self.eval(c.value, self.globals), c.type)
            self.globals.define(c.name, v)

    def run_main(self, argv: list[str] | None = None) -> Any:
        """Run main() on a big-stack thread, so SIPAR_MAX_DEPTH up to 20000 really works (round 5, F5)."""
        with use_registry(SecretRegistry()):       # secrets of this run only (round 5, C1)
            return call_deep(self._run_main, argv)

    def _run_main(self, argv: list[str] | None) -> Any:
        self.init_globals()
        main = self.fns.get("main")
        if main is None or main.kind != "fn":
            raise SiparRuntimeError("type", "the program has no 'fn main()'")
        if not main.params:
            return self.call_fn(main, [], {})
        # program arguments are journaled so that `sipar replay` re-runs with the same ones
        given = [scrub_text(a) for a in argv or []]     # an undecodable byte (surrogateescape) is U+FFFD (C2)
        args = self.journal.effect("args", {}, lambda: given)
        if not isinstance(args, list) or not all(isinstance(x, str) for x in args):
            raise SiparRuntimeError("replay", "journal entry for the program arguments is invalid")
        return self.call_fn(main, [list(args)], {})

    # ================================================================ helpers
    def located(self, e: SiparRuntimeError, node: A.Node) -> SiparRuntimeError:
        if not e.line:
            e.line, e.col = node.line, node.col
        if not e.file:
            e.file = self.file
        return e

    def eval(self, node: A.Node, env: Env) -> Any:
        try:
            f = self.EVAL[type(node)]
        except KeyError:
            raise err("type", f"cannot evaluate {type(node).__name__}", node)
        v = f(node, env)
        if node.widen is not None:          # the checker accepted an Int where a Float is expected (SPEC §2)
            try:
                v = widen(v, node.widen)
            except SiparRuntimeError as e:
                raise self.located(tag(e, v), node)
        return v

    def now(self) -> float:
        """Seconds for time budgets: the wall clock when running, the recorded effect time when replaying."""
        return self.journal.vclock if self.journal.replaying else time.monotonic()

    def time_over(self, message: str, extra: dict | None = None) -> None:
        """A seconds budget ran out. The moment is journaled (as the step count) so that replay raises the same
        error at the same step, however fast or slow the replaying machine is."""
        def perform():
            raise tag(SiparRuntimeError("budget", message), self.budget_labels())
        self.journal.effect("budget", dict({"at": self.ticks}, **(extra or {})), perform)

    def replay_time_over(self, extra: dict | None = None) -> None:
        """Replay: raise the recorded seconds-budget error if the journal has one for this step."""
        e = self.journal.peek()
        req = dict({"at": self.ticks}, **(extra or {}))
        if e is not None and e.get("kind") == "budget" and e.get("request") == req:
            self.journal.effect("budget", req, lambda: None)       # serves the recorded error (or a replay error)

    def tick(self) -> None:
        self.ticks += 1
        if not self.budgets:
            return
        if self.journal.replaying:
            self.replay_time_over()
            return
        now = time.monotonic()
        for b in reversed(self.budgets):
            lim = b.limits.get("seconds")
            if lim is not None and now - b.start > lim:
                self.time_over(f"time budget exceeded: {now - b.start:.2f}s > {lim:g}s ({b.where()})")

    def budget_labels(self) -> frozenset:
        """Labels of every active budget limit: a budget message may quote a limit or the time left."""
        return frozenset().union(*(b.labels for b in self.budgets))

    def budget_remaining_seconds(self) -> float | None:
        rem = None
        now = self.now()
        for b in self.budgets:
            lim = b.limits.get("seconds")
            if lim is not None:
                r = lim - (now - b.start)
                rem = r if rem is None else min(rem, r)
        return rem

    # ================================================================ statements
    def exec_block(self, block: A.Block, env: Env) -> Any:
        local = Env(env)
        val = None
        n = len(block.stmts)
        for i, s in enumerate(block.stmts):
            v = self.exec_stmt(s, local)
            if i == n - 1 and isinstance(s, A.ExprStmt):
                val = v
        return val

    def exec_stmt(self, s: A.Node, env: Env) -> Any:
        try:
            t = type(s)
            if t is A.ExprStmt:
                return self.eval(s.expr, env)
            if t is A.Let:
                v = self.eval(s.value, env)
                try:
                    v = coerce(v, s.type)
                except SiparRuntimeError as e:
                    raise tag(e, v)
                if isinstance(v, RangeVal):
                    v = self.materialize(v)
                env.define(s.name, v, s.mutable)
                return None
            if t is A.Assign:
                self.assign(s.target, self.eval(s.value, env), env)
                return None
            if t is A.While:
                while True:
                    self.tick()
                    c = self.eval(s.cond, env)
                    if c is not True and c is not False:
                        raise err("type", f"while condition must be Bool, got {kind_of(c)}", s.cond)
                    if not c:
                        break
                    try:
                        self.exec_block(s.body, env)
                    except BreakSig:
                        break
                    except ContinueSig:
                        continue
                return None
            if t is A.For:
                self.exec_for(s, env)
                return None
            if t is A.Return:
                raise ReturnSig(None if s.value is None else self.eval(s.value, env))
            if t is A.Break:
                raise BreakSig()
            if t is A.Continue:
                raise ContinueSig()
            if t is A.Assert:
                c = self.eval(s.cond, env)
                if c is not True:
                    msg, labels = "assertion failed", EMPTY
                    if s.message is not None:
                        mv = self.eval(s.message, env)
                        msg, labels = render(mv, redact=True), labels_of(mv)
                    e = err("assert", msg, s)
                    e.value = with_labels(msg, labels)      # own words: keep only the message's labels
                    raise e
                return None
            if t is A.Mock:
                if not self.test_mode:
                    raise err("type", "'mock' is only allowed inside test blocks", s)
                if s.fn_name not in self.fns:
                    raise err("type", f"mock of unknown function {s.fn_name!r}", s)
                self.mocks[s.fn_name] = (s, env)
                return None
            raise err("type", f"unknown statement {t.__name__}", s)
        except SiparRuntimeError as e:
            raise self.located(e, s)

    def exec_for(self, s: A.For, env: Env) -> None:
        it = self.eval_range_aware(s.iter, env)
        if isinstance(it, RangeVal):
            seq: Any = (with_labels(i, it.labels) for i in range(it.start, it.end))
        elif isinstance(it, list):
            own = own_labels(it)
            seq = [select(x, own) for x in it] if own else list(it)
        elif isinstance(it, dict):
            own = own_labels(it)
            seq = [select(x, own) for x in it.keys()] if own else list(it.keys())
        elif isinstance(it, str):
            seq = [lab(ch, it) for ch in str.__str__(it)]
        else:
            raise err("type", f"cannot iterate over {kind_of(it)}", s.iter)
        for x in seq:
            self.tick()
            local = Env(env)
            local.define(s.var, x)
            try:
                self.exec_block(s.body, local)
            except BreakSig:
                break
            except ContinueSig:
                continue

    def assign(self, target: A.Node, value: Any, env: Env) -> None:
        if isinstance(value, RangeVal):
            value = self.materialize(value)
        if isinstance(target, A.Name):
            e = env.find(target.name)
            if e is None:
                raise err("type", f"assignment to undeclared variable '{target.name}'", target)
            if target.name in e.frozen:
                raise err("type", f"cannot assign to '{target.name}': it is declared with 'let' (use 'var')", target)
            e.vars[target.name] = value
            return
        if isinstance(target, A.Field):
            obj, ls = self.place(target.obj, env)
            if not isinstance(obj, Record):
                raise err("type", f"cannot set field '{target.name}' on {kind_of(obj)}", target)
            if target.name not in obj.fields:
                raise err("type", f"{obj.type_name} has no field '{target.name}'", target)
            ftype = dict(self.tenv.records.get(obj.type_name, [])).get(target.name)
            new = label_written(coerce(value, ftype), ls | own_labels(obj))
            old = obj.fields[target.name]
            obj.fields[target.name] = new
            mutated(obj, labels_of(new), (old,))
            return
        if isinstance(target, A.Index):
            obj, ls = self.place(target.obj, env)
            idx = self.eval(target.index, env)
            if isinstance(obj, (list, dict)):
                check_mutable(obj)
                ls = ls | own_labels(obj) | labels_of(idx)    # a write at a labelled position (SPEC §6)
            if isinstance(obj, list):
                try:
                    i = self.check_index(idx, obj, target)
                except SiparRuntimeError as e:
                    raise tag(e, idx, ls)
                new, old = label_written(value, ls), obj[i]
                obj[i] = new
                mutated(obj, labels_of(new), (old,))
                return
            if isinstance(obj, dict):
                if not isinstance(idx, str):
                    raise err("type", f"map keys are Str, got {kind_of(idx)}", target)
                new, old = label_written(value, ls), obj.get(idx)
                obj[idx] = new          # a key already there keeps its old (stored) key object
                mutated(obj, labels_of(idx) | labels_of(new), (old,))
                return
            raise err("type", f"cannot assign by index into {kind_of(obj)}", target)
        raise err("type", "invalid assignment target", target)

    # ================================================================ expressions
    def e_str(self, n: A.StrLit, env: Env) -> Any:
        if len(n.parts) == 1 and isinstance(n.parts[0], str):
            return n.parts[0]
        out = []
        labels: set = set()
        total = 0
        for p in n.parts:
            if isinstance(p, str):
                out.append(p)
            else:
                v = self.eval(p, env)
                if isinstance(v, RangeVal):
                    v = self.materialize(v)
                labels |= labels_of(v)
                try:
                    out.append(render(v))
                except SiparRuntimeError as e:
                    raise tag(e, v)
            total += len(out[-1])
            if total > MAX_STR:             # the same limit as `+`, before the joined text is made (round 10, F3)
                raise err("value", STR_TOO_LARGE, n)
        return with_labels("".join(out), labels)

    def e_name(self, n: A.Name, env: Env) -> Any:
        e = env.find(n.name)
        if e is not None:
            return e.vars[n.name]
        if n.name in self.fns:
            return FnRef(self.fns[n.name])
        g = self.globals.find(n.name)
        if g is not None:
            return g.vars[n.name]
        if n.name in FUNCS and "." not in n.name:
            return Builtin(n.name, FUNCS[n.name])
        raise err("type", f"unknown name '{n.name}'", n)

    def e_list(self, n: A.ListLit, env: Env) -> Any:
        out = []
        for x in n.items:
            v = self.eval(x, env)
            out.append(self.materialize(v) if isinstance(v, RangeVal) else v)
        if len(out) > MAX_ITEMS:
            raise err("value", "list too large", n)
        return out

    def e_map(self, n: A.MapLit, env: Env) -> Any:
        d = {}
        for k, v in n.entries:
            kv = self.eval(k, env)
            if not isinstance(kv, str):
                raise err("type", f"map keys must be Str, got {kind_of(kv)}", k)
            # a labelled key is a labelled position, as in `m[k] = v` (SPEC §6): without this `["safe": "ls", k: "id"]`
            # let a model-chosen key replace the value under a fixed key with an unlabelled one (round 13)
            d[kv] = label_written(self.eval(v, env), labels_of(kv))
        return d

    def e_record(self, n: A.RecordLit, env: Env) -> Any:
        fields = self.tenv.records.get(n.type_name)
        if fields is None:
            raise err("type", f"unknown record type '{n.type_name}'", n)
        given = {}
        for name, ex in n.fields:
            given[name] = self.eval(ex, env)
        out = {}
        for fname, ftype in fields:
            if fname in given:
                out[fname] = coerce(given.pop(fname), ftype)
            elif isinstance(ftype, A.TOptional):
                out[fname] = None
            else:
                raise err("type", f"{n.type_name} literal is missing field '{fname}'", n)
        if given:
            raise err("type", f"{n.type_name} has no field(s) {sorted(given)}", n)
        return Record(n.type_name, out)

    def e_lambda(self, n: A.Lambda, env: Env) -> Any:
        return Closure(n.params, n.body, env, "<lambda>", n.ret)

    def e_block(self, n: A.Block, env: Env) -> Any:
        return self.exec_block(n, env)

    def e_if(self, n: A.If, env: Env) -> Any:
        c = self.eval(n.cond, env)
        if c is not True and c is not False:
            raise err("type", f"if condition must be Bool, got {kind_of(c)}", n.cond)
        if c:
            return self.exec_block(n.then, env)
        if n.else_ is None:
            return None
        return self.eval(n.else_, env)

    def e_match(self, n: A.Match, env: Env) -> Any:
        v = self.eval(n.subject, env)
        for arm in n.arms:
            binds: dict = {}
            if self.match_pattern(arm.pattern, v, binds, env):
                local = Env(env)
                for k, x in binds.items():
                    local.define(k, x)
                return self.eval(arm.body, local)
        raise tag(err("value", f"no match arm for {snippet(v)}", n), v)

    def match_pattern(self, p: A.Node, v: Any, binds: dict, env: Env) -> bool:
        if isinstance(p, A.PWild):
            return True
        if isinstance(p, A.PBind):
            binds[p.name] = v
            return True
        if isinstance(p, A.PLit):
            return equal(self.eval(p.value, env), v)
        if isinstance(p, A.PVariant):
            if not isinstance(v, EnumVal) or v.enum != p.enum or v.variant != p.variant:
                if p.enum not in self.tenv.enums:
                    raise err("type", f"unknown enum '{p.enum}' in pattern", p)
                return False
            if p.args is None:
                return True
            vals = list(v.fields.values())
            if len(p.args) != len(vals):
                raise err("type", f"pattern {p.enum}.{p.variant} has {len(p.args)} sub-patterns, "
                                  f"the variant has {len(vals)} fields", p)
            return all(self.match_pattern(sp, x, binds, env) for sp, x in zip(p.args, vals))
        raise err("type", "invalid pattern", p)

    def e_try(self, n: A.Try, env: Env) -> Any:
        saved_budgets = len(self.budgets)
        saved_depth = self.depth
        try:
            return self.exec_block(n.body, env)
        except SiparRuntimeError as e:
            if e.kind == "replay" or getattr(e, "fatal", False):
                raise
            if e.kind == "budget":
                tag(e, self.budget_labels())
            del self.budgets[saved_budgets:]
            self.depth = saved_depth
            local = Env(env)
            local.define(n.err_name, self.error_value(e))
            return self.exec_block(n.handler, local)

    @staticmethod
    def error_value(e: SiparRuntimeError) -> Any:
        """The Error record bound by `catch e`. The message of every error is labelled untrusted:error (it may
        quote model text, a server's reply, stderr...) unless the program raised it itself with fail()/assert:
        then the message keeps its own labels. A built-in kind is a plain word; fail(kind) keeps kind's labels."""
        kind = getattr(e, "kind_value", None)
        if kind is None:
            kind = e.kind
        msg = getattr(e, "value", None)
        if msg is None:
            msg = with_labels(e.message, {"untrusted:error"} | e.labels)   # masked text: same in run and replay
        return make_error(kind, msg)

    def e_budget(self, n: A.Budget, env: Env) -> Any:
        limits: dict = {}
        for a in n.limits:
            if a.name not in BUDGET_LIMITS:
                raise err("type", f"unknown budget limit '{a.name}' (use {', '.join(BUDGET_LIMITS)})", a)
            v = self.eval(a.value, env)
            if not is_num(v) or not math.isfinite(v) or v < 0:
                raise err("type", f"budget limit '{a.name}' must be a finite non-negative number", a)
            if BUDGET_LIMITS[a.name] == "Int" and not isinstance(v, int):
                raise err("type", f"budget limit '{a.name}' must be an Int", a)
            limits[a.name] = v
        frame = BudgetFrame(limits, n, self.now(), frozenset().union(*(labels_of(v) for v in limits.values())))
        self.budgets.append(frame)
        try:
            r = self.exec_block(n.body, env)
            self.tick()                         # the block's last step may have run past the time limit
            return r
        except SiparRuntimeError as e:
            if e.kind == "budget":              # replay serves the journaled text: add the labels the same way
                tag(e, frame.labels)
            raise
        finally:
            if frame in self.budgets:
                self.budgets.remove(frame)

    # ---------------------------------------------------------------- field / index
    def e_field(self, n: A.Field, env: Env) -> Any:
        if isinstance(n.obj, A.Name) and env.find(n.obj.name) is None and self.globals.find(n.obj.name) is None:
            qn = f"{n.obj.name}.{n.name}"
            if n.obj.name in self.tenv.enums:
                return self.make_variant(n.obj.name, n.name, [], {}, n)
            if qn in FUNCS:
                return Builtin(qn, FUNCS[qn])
            if n.obj.name in MODULES:
                raise err("type", f"unknown function {qn}", n)
        return self.field_value(self.eval(n.obj, env), n)

    def field_value(self, obj: Any, n: A.Field, raw: bool = False) -> Any:
        """obj.name; through a labelled pick (LRecord view) the field carries the view's labels unless raw."""
        if isinstance(obj, Record):
            if n.name not in obj.fields:
                raise err("type", f"{obj.type_name} has no field '{n.name}'", n)
            v = obj.fields[n.name]
            return v if raw else select(v, own_labels(obj))
        if isinstance(obj, EnumVal) and n.name in obj.fields:
            return obj.fields[n.name]
        raise err("type", f"{kind_of(obj)} has no field '{n.name}'", n)

    def place(self, node: A.Node, env: Env) -> tuple[Any, frozenset]:
        """The container a mutation acts on (`a[i].f = v`, `m[k].push(v)`), as the original object (never a
        labelled copy) plus the labels of the picks that led to it (SPEC §6: a write at a position chosen with
        labelled data is labelled)."""
        if isinstance(node, A.Index) and not (isinstance(node.index, A.Binary) and node.index.op == ".."):
            obj, ls = self.place(node.obj, env)
            idx = self.eval(node.index, env)
            if isinstance(obj, (list, dict)):
                try:
                    return self.pick(obj, idx, node), ls | own_labels(obj) | labels_of(idx)
                except SiparRuntimeError as e:
                    raise self.located(tag(e, idx, ls, own_labels(obj)), node)
            return self.index_value(obj, idx, node), EMPTY
        if isinstance(node, A.Field) and not (isinstance(node.obj, A.Name) and env.find(node.obj.name) is None
                                              and self.globals.find(node.obj.name) is None):
            obj, ls = self.place(node.obj, env)
            return self.field_value(obj, node, raw=True), ls | own_labels(obj)
        return self.eval(node, env), EMPTY

    def check_index(self, idx: Any, obj: Any, node: A.Node) -> int:
        """R7-4: the out-of-range message quotes the length, so the error carries the labels `obj.len()` would
        have (labels_of the whole list or Str, items included) and the index's labels: a secret's length is
        masked as «secret:NAME» and `catch e` gets a labelled message."""
        if not isinstance(idx, int) or isinstance(idx, bool):
            raise err("type", f"index must be Int, got {kind_of(idx)}", node)
        i, size = int(idx), len(obj)
        if i < 0 or i >= size:
            raise tag(err("index", f"index {render(idx, redact=True)} out of range (length {size})", node), idx, obj)
        return i

    def eval_range_aware(self, node: A.Node, env: Env) -> Any:
        if isinstance(node, A.Binary) and node.op == "..":
            a, b = self.eval(node.left, env), self.eval(node.right, env)
            for x in (a, b):
                if not isinstance(x, int) or isinstance(x, bool):
                    raise err("type", f"range bounds must be Int, got {kind_of(x)}", node)
            return RangeVal(int(a), int(b), labels_of(a) | labels_of(b))
        return self.eval(node, env)

    def materialize(self, r: RangeVal) -> list:
        if r.end - r.start > MAX_ITEMS:
            raise tag(SiparRuntimeError("value", f"range {r.start}..{r.end} is too large (max {MAX_ITEMS} items)"), r)
        return [with_labels(i, r.labels) for i in range(r.start, r.end)]

    def e_index(self, n: A.Index, env: Env) -> Any:
        try:
            obj = self.eval(n.obj, env)
            idx = self.eval_range_aware(n.index, env)
            try:
                return self.index_value(obj, idx, n)
            except SiparRuntimeError as e:
                raise tag(e, idx, own_labels(obj), labels_of(obj) if isinstance(obj, str) else EMPTY)
        except SiparRuntimeError as e:
            raise self.located(e, n)

    def pick(self, obj: Any, idx: Any, n: A.Node) -> Any:
        """The element itself (no labels added) of a list or map."""
        if isinstance(obj, list):
            return obj[self.check_index(idx, obj, n)]
        if not isinstance(idx, str):
            raise err("type", f"map keys are Str, got {kind_of(idx)}", n)
        if idx not in obj:
            raise err("key", f"key {snippet(idx)} not found in map", n)
        return obj[idx]

    def index_value(self, obj: Any, idx: Any, n: A.Node) -> Any:
        """obj[idx] / obj[a..b]. SPEC §6 selection: the result carries the labels of the index, key or bounds
        and the container's own labels (a string's labels too)."""
        if isinstance(obj, RangeVal):
            obj = new_list(self.materialize(obj), obj.labels)
        if isinstance(idx, RangeVal):
            if isinstance(obj, (list, str)):
                size = len(obj)
                a = min(max(idx.start, 0), size)
                b = min(max(idx.end, a), size)
                if isinstance(obj, str):
                    return with_labels(str.__str__(obj)[a:b], labels_of(obj) | idx.labels)
                return new_list(obj[a:b], own_labels(obj) | idx.labels)
            raise err("type", f"cannot slice {kind_of(obj)}", n)
        if isinstance(obj, str):
            i = self.check_index(idx, obj, n)
            return lab(str.__str__(obj)[i], obj, idx)
        if isinstance(obj, (list, dict)):
            return select(self.pick(obj, idx, n), own_labels(obj) | labels_of(idx))
        raise err("type", f"cannot index {kind_of(obj)}", n)

    # ---------------------------------------------------------------- operators
    def e_unary(self, n: A.Unary, env: Env) -> Any:
        v = self.eval(n.operand, env)
        try:
            return self._unary(n, v)
        except SiparRuntimeError as e:
            raise tag(e, v)

    def _unary(self, n: A.Unary, v: Any) -> Any:
        if n.op == "not":
            if v is not True and v is not False:
                raise err("type", f"'not' needs Bool, got {kind_of(v)}", n)
            return not v
        if n.op == "-":
            if not is_num(v):
                raise err("type", f"unary '-' needs a number, got {kind_of(v)}", n)
            return lab(-(float(v) if isinstance(v, float) else int(v)), v)
        raise err("type", f"unknown operator {n.op}", n)

    def e_binary(self, n: A.Binary, env: Env) -> Any:
        op = n.op
        if op in ("and", "or"):
            a = self.eval(n.left, env)
            if a is not True and a is not False:
                raise err("type", f"'{op}' needs Bool, got {kind_of(a)}", n.left)
            if (op == "and" and not a) or (op == "or" and a):
                return a
            b = self.eval(n.right, env)
            if b is not True and b is not False:
                raise err("type", f"'{op}' needs Bool, got {kind_of(b)}", n.right)
            return b
        if op == "??":
            a = self.eval(n.left, env)
            return self.eval(n.right, env) if a is None else a
        if op == "..":
            r = self.eval_range_aware(n, env)
            try:
                return self.materialize(r)
            except SiparRuntimeError as e:
                raise self.located(tag(e, r), n)
        a = self.eval(n.left, env)
        b = self.eval(n.right, env)
        try:
            return self._binop(n, op, a, b)
        except SiparRuntimeError as e:
            raise tag(e, a, b)

    def _binop(self, n: A.Binary, op: str, a: Any, b: Any) -> Any:
        if isinstance(a, RangeVal):
            a = self.materialize(a)
        if isinstance(b, RangeVal):
            b = self.materialize(b)
        if op == "==":
            return equal(a, b)
        if op == "!=":
            return not equal(a, b)
        if op == "in":
            if isinstance(b, list):
                return any(equal(a, x) for x in b)
            if isinstance(b, dict):
                return isinstance(a, str) and a in b
            if isinstance(b, str) and isinstance(a, str):
                return str.__str__(a) in str.__str__(b)
            raise err("type", f"'in' needs a List, Map or Str on the right, got {kind_of(b)}", n)
        if op in ("<", "<=", ">", ">="):
            if not ((is_num(a) and is_num(b)) or (isinstance(a, str) and isinstance(b, str))):
                raise err("type", f"cannot compare {kind_of(a)} {op} {kind_of(b)}", n)
            x, y = (str.__str__(a), str.__str__(b)) if isinstance(a, str) else (a, b)
            return {"<": x < y, "<=": x <= y, ">": x > y, ">=": x >= y}[op]
        if op == "+":
            if isinstance(a, str) and isinstance(b, str):
                if len(a) + len(b) > MAX_STR:
                    raise err("value", STR_TOO_LARGE, n)
                return with_labels(str.__str__(a) + str.__str__(b), labels_of(a) | labels_of(b))
            if isinstance(a, list) and isinstance(b, list):
                if len(a) + len(b) > MAX_ITEMS:
                    raise err("value", f"list too large ({len(a) + len(b)} > {MAX_ITEMS} items)", n)
                return new_list(a + b, own_labels(a) | own_labels(b))
        if op in ("+", "-", "*", "/", "%"):
            if not (is_num(a) and is_num(b)):
                raise err("type", f"cannot apply '{op}' to {kind_of(a)} and {kind_of(b)}", n)
            ls = labels_of(a) | labels_of(b)
            both_int = isinstance(a, int) and isinstance(b, int)
            x = int(a) if isinstance(a, int) else float(a)
            y = int(b) if isinstance(b, int) else float(b)
            if op in ("/", "%") and y == 0:
                raise err("zero", "division by zero" if op == "/" else "modulo by zero", n)
            try:
                if op == "+":
                    r = x + y
                elif op == "-":
                    r = x - y
                elif op == "*":
                    r = x * y
                elif op == "/":
                    r = x // y if both_int else x / y
                else:
                    r = x % y
            except OverflowError:               # an Int too large to mix with a Float
                raise err("value", f"number too large for '{op}'", n)
            if both_int:
                try:
                    check_int(r)
                except SiparRuntimeError as e:
                    raise self.located(e, n)
            return with_labels(r, ls)
        raise err("type", f"unknown operator {op}", n)

    # ---------------------------------------------------------------- as
    def e_as(self, n: A.As, env: Env) -> Any:
        v = self.eval(n.expr, env)
        if isinstance(v, RangeVal):
            v = self.materialize(v)
        try:
            return self.convert(v, n.type)
        except SiparRuntimeError as e:
            sec = secrets_in(v)
            if sec:     # the detailed message could quote or measure the secret: replace it with a generic one
                e = SiparRuntimeError(e.kind, f"cannot convert «{','.join(sorted(set(sec)))}» to {type_str(n.type)} "
                                              "(details hidden: the value is secret)")
            raise self.located(tag(e, v), n)

    def convert(self, v: Any, t: A.TypeExpr) -> Any:
        if isinstance(t, A.TOptional):
            if v is None:
                return None
            if isinstance(v, str) and str.__str__(v).strip() in ("null", "none", ""):
                return None
            return self.convert(v, t.inner)
        if isinstance(t, A.TFn):
            raise SiparRuntimeError("type", "cannot convert to a function type")
        name = t.name
        ls = labels_of(v)
        if name == "Str":
            return with_labels(render(v), ls)
        if name == "Int":
            if isinstance(v, bool):
                raise SiparRuntimeError("type", "cannot convert Bool to Int")
            if isinstance(v, int):
                return v
            if isinstance(v, float):
                if v != v or v in (float("inf"), float("-inf")):
                    raise SiparRuntimeError("value", f"cannot convert {render(v, redact=True)} to Int")
                return with_labels(int(v), ls)
            if isinstance(v, str):
                s = str.__str__(v).strip()
                try:
                    if not s.isascii():         # int() would read Arabic-Indic digits as 12
                        raise ValueError
                    r = int(s)
                except ValueError:
                    if INT_TEXT.fullmatch(s):   # well-formed but past Python's 4300-digit limit: too large (F6)
                        raise SiparRuntimeError("value", INT_TOO_LARGE)
                    raise SiparRuntimeError("decode", f"cannot parse {snippet(v)} as Int")
                check_int(r)
                return with_labels(r, ls)
        if name == "Float":
            if isinstance(v, bool):
                raise SiparRuntimeError("type", "cannot convert Bool to Float")
            if isinstance(v, (int, float)):
                try:
                    return with_labels(float(v), ls)
                except OverflowError:
                    raise SiparRuntimeError("value", "number too large for Float")
            if isinstance(v, str):
                s = str.__str__(v).strip()
                try:
                    if not s.isascii():         # same rules as Int: ASCII digits, '_' only between digits
                        raise ValueError
                    f = float(s)
                except ValueError:
                    raise SiparRuntimeError("decode", f"cannot parse {snippet(v)} as Float")
                if math.isfinite(f) and not FLOAT_TEXT.fullmatch(s):    # "1_0e1_0": '_' in the exponent
                    raise SiparRuntimeError("decode", f"cannot parse {snippet(v)} as Float")
                if not math.isfinite(f):     # "nan", "inf", "1e400": same rule as JSON decoding (SPEC §5)
                    raise SiparRuntimeError("decode", f"cannot parse {snippet(v)} as Float: not a finite number")
                return with_labels(f, ls)
        if name == "Bool":
            if v is True or v is False:
                return v
            if isinstance(v, str):
                s = str.__str__(v).strip().lower()
                if s in ("true", "false"):
                    return s == "true"
                raise SiparRuntimeError("decode", f"cannot parse {snippet(v)} as Bool (use true/false)")
        if name in ("List", "Map") or name in self.tenv.records or name in self.tenv.enums:
            if isinstance(v, str):
                import json
                try:
                    data = json_loads(str.__str__(v).strip())
                except json.JSONDecodeError as e:
                    raise SiparRuntimeError("decode", f"not valid JSON for {type_str(t)}: {e.msg} "
                                                      f"(line {e.lineno} col {e.colno})")
                except ValueError:              # any other parse failure is still bad input, never a crash
                    raise SiparRuntimeError("decode", f"not valid JSON for {type_str(t)}")
                except RecursionError:
                    raise SiparRuntimeError("decode", "JSON nested too deeply")
                return from_json(data, t, self.tenv, ls)
            k = kind_of(v)
            if k == name:
                return v
        if name == "None" and v is None:
            return None
        raise SiparRuntimeError("type", f"cannot convert {kind_of(v)} to {type_str(t)}")

    # ================================================================ calls
    def eval_args(self, args: list[A.Arg], env: Env) -> tuple[list, dict]:
        pos, named = [], {}
        for a in args:
            v = self.eval(a.value, env)
            if isinstance(v, RangeVal):
                v = self.materialize(v)
            if a.name is None:
                pos.append(v)
            else:
                named[a.name] = v
        return pos, named

    def e_call(self, n: A.Call, env: Env) -> Any:
        try:
            return self._call(n, env)
        except SiparRuntimeError as e:
            raise self.located(e, n)

    def _call(self, n: A.Call, env: Env) -> Any:
        c = n.callee
        if MCP.dotted(c) and env.find("mcp") is None and self.globals.find("mcp") is None:
            return MCP.call_dotted(self, n, env)
        if isinstance(c, A.Name):
            e = env.find(c.name)
            if e is None and c.name in self.fns:
                pos, named = self.eval_args(n.args, env)
                return self.call_fn(self.fns[c.name], pos, named)
            if e is None and self.globals.find(c.name) is None and c.name in FUNCS:
                pos, named = self.eval_args(n.args, env)
                return self.call_builtin(c.name, pos, named)
        if isinstance(c, A.Field):
            o = c.obj
            if isinstance(o, A.Name) and env.find(o.name) is None and self.globals.find(o.name) is None:
                qn = f"{o.name}.{c.name}"
                if qn in FUNCS:
                    pos, named = self.eval_args(n.args, env)
                    if qn == "memory.load":          # T is resolved by the checker (SPEC.md §5 memory)
                        named = dict(named, **{"<type>": getattr(n, "mem_type", None)})
                    return self.call_builtin(qn, pos, named)
                if o.name in self.tenv.enums:
                    pos, named = self.eval_args(n.args, env)
                    return self.make_variant(o.name, c.name, pos, named, n)
                if o.name in MODULES:
                    raise err("type", f"unknown function {qn}", n)
            if c.name in MUTATORS:      # change the original container, never a labelled copy (SPEC §6)
                recv, pls = self.place(o, env)
            else:
                recv, pls = self.eval(o, env), EMPTY
            if isinstance(recv, Record) and c.name in recv.fields:
                pos, named = self.eval_args(n.args, env)
                return self.call_value(select(recv.fields[c.name], pls | own_labels(recv)), pos, named)
            pos, named = self.eval_args(n.args, env)
            if pls and c.name == "push" and isinstance(recv, list):
                pos = [label_written(x, pls) for x in pos]
                named = {k: label_written(x, pls) for k, x in named.items()}
            return select(self.call_method_named(recv, c.name, pos, named), pls)
        f = self.eval(c, env)
        pos, named = self.eval_args(n.args, env)
        return self.call_value(f, pos, named)

    def call_method_named(self, recv: Any, name: str, pos: list, named: dict) -> Any:
        k = "Str" if isinstance(recv, str) else "List" if isinstance(recv, (list, RangeVal)) else \
            "Map" if isinstance(recv, dict) else kind_of(recv)
        sig = METHODS.get(k, {}).get(name)
        if sig is None:
            raise SiparRuntimeError("type", f"{k} has no method '{name}'")
        args = self.bind_sig(f"{k}.{name}", sig, pos, named)
        try:
            r = call_method(self, recv, name, [args[p] for p, _ in sig.params])
        except OverflowError:
            raise tag(SiparRuntimeError("value", f"{k}.{name}: number too large"), recv, *args.values())
        except SiparRuntimeError as e:
            raise tag(e, recv, *args.values())
        self.tick()                             # a long method (sort, join...) counts against budget(seconds)
        return r

    def bind_sig(self, fname: str, sig, pos: list, named: dict) -> dict:
        names = [p for p, _ in sig.params]
        if len(pos) > len(names):
            raise SiparRuntimeError("type", f"{fname} takes {len(names)} argument(s), got {len(pos)}")
        out = dict(zip(names, pos))
        for k, v in named.items():
            if k not in names:
                raise SiparRuntimeError("type", f"{fname} has no parameter '{k}'")
            if k in out:
                raise SiparRuntimeError("type", f"{fname}: parameter '{k}' given twice")
            out[k] = v
        for p in names:
            if p not in out and p not in sig.defaults:
                raise SiparRuntimeError("type", f"{fname}: missing argument '{p}'")
        return out

    def call_builtin(self, name: str, pos: list, named: dict) -> Any:
        sig = FUNCTIONS[name]
        hidden = {"<type>": named.pop("<type>")} if "<type>" in named else {}
        args = self.bind_sig(name, sig, pos, named)
        args.update(hidden)
        check_sinks(name, args)                 # labels first: no effect and no capability lookup with a secret
        for eff in sig.effects:
            self.caps.require(eff)
        try:
            r = FUNCS[name](self, args)
        except OverflowError:
            raise tag(SiparRuntimeError("value", f"{name}: number too large"), *args.values())
        except SiparRuntimeError as e:
            # a server's or command's answer is untrusted, not secret (SPEC §6): the headers: values (the one
            # place a secret may go) label only the header-validation errors, not the effect's outcome
            raise tag(e, *(v for k, v in args.items() if k != "headers" or e.kind == "value"))
        self.tick()                             # a long builtin counts against budget(seconds), journaled
        return r

    def make_variant(self, enum: str, variant: str, pos: list, named: dict, node: A.Node) -> Any:
        vs = {v.name: v for v in self.tenv.enums[enum]}
        if variant not in vs:
            raise err("type", f"enum {enum} has no variant '{variant}'", node)
        v = vs[variant]
        if not v.fields:
            if pos or named:
                raise err("type", f"{enum}.{variant} takes no arguments", node)
            return EnumVal(enum, variant)
        names = [f for f, _ in v.fields]
        if not pos and not named and not isinstance(node, A.Call):
            raise err("type", f"{enum}.{variant} needs arguments: {', '.join(names)}", node)
        if len(pos) > len(names):
            raise err("type", f"{enum}.{variant} takes {len(names)} argument(s)", node)
        vals = dict(zip(names, pos))
        for k, x in named.items():
            if k not in names or k in vals:
                raise err("type", f"{enum}.{variant}: bad argument '{k}'", node)
            vals[k] = x
        fields = {}
        for f, ft in v.fields:
            if f not in vals:
                if isinstance(ft, A.TOptional):
                    fields[f] = None
                    continue
                raise err("type", f"{enum}.{variant}: missing '{f}'", node)
            fields[f] = coerce(vals[f], ft)
        return EnumVal(enum, variant, fields, tag_field_enum(vs.values()))

    def bind_params(self, fname: str, params: list[A.Param], pos: list, named: dict) -> dict:
        names = [p.name for p in params]
        if len(pos) > len(names):
            raise SiparRuntimeError("type", f"{fname} takes {len(names)} argument(s), got {len(pos)}")
        vals = dict(zip(names, pos))
        for k, v in named.items():
            if k not in names:
                raise SiparRuntimeError("type", f"{fname} has no parameter '{k}'")
            if k in vals:
                raise SiparRuntimeError("type", f"{fname}: parameter '{k}' given twice")
            vals[k] = v
        for p in params:
            if p.name not in vals:
                if isinstance(p.type, A.TOptional):
                    vals[p.name] = None
                else:
                    raise SiparRuntimeError("type", f"{fname}: missing argument '{p.name}'")
            vals[p.name] = coerce(vals[p.name], p.type)
        return vals

    def enter(self) -> None:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            self.depth -= 1
            raise SiparRuntimeError("value", f"maximum call depth ({MAX_DEPTH}) exceeded — infinite recursion?")
        self.tick()

    def call_value(self, f: Any, pos: list, named: dict | None = None) -> Any:
        named = named or {}
        if isinstance(f, LFn):                  # a function picked with a labelled index labels its result
            return select(self.call_value(f.fn, pos, named), f.labels)
        if isinstance(f, WidenFn):              # used as a wider fn type: widen the arguments and the result
            _, pplans, rplan = f.plan
            pos = [widen(x, p) for x, p in zip(pos, pplans)] + pos[len(pplans):]
            return widen(self.call_value(f.fn, pos, named), rplan)
        if isinstance(f, FnRef):
            return self.call_fn(f.decl, pos, named)
        if isinstance(f, Builtin):
            return self.call_builtin(f.name, pos, named)
        if isinstance(f, Closure):
            vals = self.bind_params(f.name, f.params, pos, named)
            local = Env(f.env)
            for k, v in vals.items():
                local.define(k, v)
            self.enter()
            try:
                r = self.eval(f.body, local)
            except ReturnSig as r_:
                r = r_.value
            finally:
                self.depth -= 1
            return coerce(r, f.ret)
        raise SiparRuntimeError("type", f"{kind_of(f)} is not callable")

    def call_fn(self, decl: A.FnDecl, pos: list, named: dict) -> Any:
        if decl.name in self.mocks:
            return self.call_mock(decl, pos, named)
        vals = self.bind_params(decl.name, decl.params, pos, named)
        self.enter()
        prev_fn, self.journal.fn = self.journal.fn, decl.name
        try:
            local = Env(self.globals)
            for k, v in vals.items():
                local.define(k, v)
            if decl.kind == "fn":
                try:
                    r = self.exec_block(decl.body, local)
                except ReturnSig as r_:
                    r = r_.value
                if isinstance(r, RangeVal):
                    r = self.materialize(r)
                return coerce(r, decl.ret) if decl.ret is not None else None
            prompt = self.eval(decl.prompt, local)
            if decl.kind == "ai":
                return AI.run_ai(self, decl, prompt)
            return AI.run_agent(self, decl, prompt)
        except (BreakSig, ContinueSig):
            raise SiparRuntimeError("type", "break/continue outside a loop")
        except RecursionError:
            raise SiparRuntimeError("value", "recursion too deep (Python stack exhausted)")
        finally:
            self.depth -= 1
            self.journal.fn = prev_fn

    def call_mock(self, decl: A.FnDecl, pos: list, named: dict) -> Any:
        mock, env = self.mocks[decl.name]
        vals = self.bind_params(decl.name, decl.params, pos, named)
        local = Env(env)
        ordered = [vals[p.name] for p in decl.params]
        for name, v in zip(mock.params, ordered):
            local.define(name, v)
        self.enter()
        try:
            r = self.eval(mock.body, local)
        except ReturnSig as r_:
            r = r_.value
        finally:
            self.depth -= 1
        r = coerce(r, decl.ret)
        if decl.kind in ("ai", "agent"):
            r = deep_label(r, frozenset({f"untrusted:ai:{decl.name}"}))
        return r

    # ================================================================ AI plumbing
    def model_spec(self, decl: A.FnDecl) -> str | None:
        if self.model_override:
            return self.model_override
        m = AI.attr_values(decl).get("model")
        if isinstance(m, str) and m.strip():
            return m.strip()
        env = os.environ.get("SIPAR_MODEL", "").strip()
        return env or None

    def provider_for(self, name: str):
        if name not in self.providers:
            prov = make_provider(name, self.mock_script)
            if isinstance(prov, MockProvider):      # M5 (round 6): a script key must name an ai / agent fn
                check_script_names(prov.by_fn, {n for n, d in self.fns.items() if d.kind in ("ai", "agent")})
            self.providers[name] = prov
        return self.providers[name]

    def setup_failed(self, kind: str, request: dict, mspec: str | None, e: SiparRuntimeError | None) -> None:
        """M1 (round 8): the model could not be set up (no model, a bad model name or chain, a bad mock script).
        No request was sent and no budget is charged, but the failure is journaled as the outcome of this ai
        effect (meta "setup": true), so a caught error replays the same without the model environment.
        Running: records `e` and raises it. Replay (e None): serves the recorded error."""
        meta: dict = {"setup": True}
        if isinstance(mspec, str):
            meta["model"] = mspec

        def perform():
            raise e

        self.journal.effect(kind, request, perform, meta=meta)
        raise SiparRuntimeError("replay", f"journal entry #{self.journal.seq} ({kind}): a model setup entry "
                                          "must hold an error")

    def setup_entry_next(self, kind: str) -> bool:
        """Replay: the next journal entry is a model setup failure of this kind (see setup_failed)."""
        e = self.journal.peek()
        m = e.get("meta") if isinstance(e, dict) else None
        return isinstance(e, dict) and e.get("kind") == kind and isinstance(m, dict) and m.get("setup") is True

    def budget_before(self) -> None:
        self.tick()
        for b in reversed(self.budgets):
            lim = b.limits.get("ai_calls")
            if lim is not None and b.ai_calls + 1 > lim:
                raise tag(SiparRuntimeError("budget", f"ai_calls budget exhausted: {b.ai_calls} of {lim} used "
                                                  f"({b.where()})"), self.budget_labels())
            lim = b.limits.get("tokens")
            if lim is not None and b.tokens >= lim:
                raise tag(SiparRuntimeError("budget", f"token budget exhausted: {b.tokens} of {lim} ({b.where()})"), self.budget_labels())
            lim = b.limits.get("usd")
            if lim is not None and not self.price_known():
                raise tag(SiparRuntimeError("budget", f"budget(usd: {lim:g}) needs the model's price: set SIPAR_PRICE_IN "
                                                  f"and SIPAR_PRICE_OUT (USD per 1M input / output tokens; 0 is "
                                                  f"allowed) ({b.where()})"), self.budget_labels())
            if lim is not None and b.usd >= lim:
                raise tag(SiparRuntimeError("budget", f"usd budget exhausted: ${b.usd:.6f} of ${lim:g} ({b.where()})"), self.budget_labels())
        for b in self.budgets:
            b.ai_calls += 1

    @staticmethod
    def prices() -> tuple[float, float] | None:
        """USD per 1M input / output tokens from SIPAR_PRICE_IN / SIPAR_PRICE_OUT; None unless both are set to
        numbers in [0, MAX_PRICE] (a usd budget then fails closed)."""
        try:
            pin = float(os.environ["SIPAR_PRICE_IN"])
            pout = float(os.environ["SIPAR_PRICE_OUT"])
        except (KeyError, ValueError):
            return None
        if not (0 <= pin <= MAX_PRICE and 0 <= pout <= MAX_PRICE):     # also NaN / inf: a cost must stay finite
            return None
        return pin, pout

    @staticmethod
    def _usd_ok(v: Any) -> bool:
        return type(v) in (int, float) and 0 <= v < float("inf")

    def price_known(self) -> bool:
        """Running: both prices are set. Replay: the next recorded ai entry has its cost (as the run had)."""
        if self.journal.replaying:
            e = self.journal.peek()
            m = e.get("meta") if isinstance(e, dict) else None
            return isinstance(m, dict) and self._usd_ok(m.get("usd"))
        return self.prices() is not None

    def budget_after(self, usage: dict, usd: float) -> None:
        tin = int(usage.get("input", 0) or 0)
        tout = int(usage.get("output", 0) or 0)
        for b in self.budgets:
            b.tokens += tin + tout
            b.usd += usd
        for b in reversed(self.budgets):
            lim = b.limits.get("tokens")
            if lim is not None and b.tokens > lim:
                raise tag(SiparRuntimeError("budget", f"token budget exceeded: {b.tokens} > {lim} ({b.where()})"), self.budget_labels())
            lim = b.limits.get("usd")
            if lim is not None and b.usd > lim:
                raise tag(SiparRuntimeError("budget", f"usd budget exceeded: ${b.usd:.6f} > ${lim:g} ({b.where()})"), self.budget_labels())
        self.tick()

    def failed_charge(self, meta: dict, reported: Any, messages: list[dict]) -> None:
        """A failed attempt after the request may have reached the provider: record in meta what it counts as
        (reported usage if sane, else the prompt estimate chars/4 and 0 output) and its USD cost if priced."""
        usage = reported if isinstance(reported, dict) and all(valid_count(reported.get(k))
                                                               for k in ("input", "output")) else None
        if usage is None:
            usage = {"input": estimate_tokens(prompt_text(messages)), "output": 0}
        meta["usage"] = {"input": usage["input"], "output": usage["output"]}
        pr = self.prices()
        if pr is not None:
            meta["usd"] = round(usage["input"] * pr[0] / 1e6 + usage["output"] * pr[1] / 1e6, 9)

    def ai_call(self, kind: str, decl: A.FnDecl, messages: list[dict], temperature: Any, hint: dict) -> str:
        """One model reply. With a chain `@model("a | b | mock")` a provider-level failure (error kind `ai`:
        HTTP error, timeout, network, missing key, malformed provider response) moves on to the next model.
        Every attempt is its own journal entry and counts against the budget; replay follows the journal."""
        self.caps.require("ai")
        replaying = self.journal.replaying
        if self.test_mode and not self.live and not replaying:
            raise SiparRuntimeError("ai", f"unmocked call to {decl.kind} fn {decl.name}() in a test: add "
                                          f"`mock {decl.name}(...) => value`, or run with --live / --record")
        spec = self.model_spec(decl)
        chain: list[str] = []
        request = {"fn": decl.name, "messages": messages, "temperature": temperature}
        if not replaying:
            try:
                if spec is None:
                    raise SiparRuntimeError("ai", f"no model for {decl.name}(): add @model(\"provider/model\") or set "
                                                  "SIPAR_MODEL (e.g. SIPAR_MODEL=mock, SIPAR_MODEL=openrouter/qwen/qwen3-coder)")
                chain = parse_chain(spec)
            except SiparRuntimeError as e:
                self.setup_failed(kind, request, spec, e)
        failures: list[str] = []
        attempt = 0
        while True:
            attempt += 1
            mspec = chain[attempt - 1] if chain else spec
            provider = model = None
            if not replaying:
                try:
                    pname, model = parse_model(mspec)
                    provider = self.provider_for(pname)
                except SiparRuntimeError as e:
                    self.setup_failed(kind, request, mspec, e)
            elif self.setup_entry_next(kind):
                self.setup_failed(kind, request, None, None)
            self.budget_before()
            timeout = env_seconds("SIPAR_AI_TIMEOUT", 120.0)
            rem = self.budget_remaining_seconds()
            by_budget = rem is not None and rem <= timeout
            if rem is not None:
                timeout = max(0.05, min(timeout, rem))
            meta: dict = {"model": mspec}
            if self.prices() is not None:
                meta["usd"] = 0.0           # priced run: replay sees the price (a failed attempt sets its cost)
            if len(chain) > 1:
                meta.update(attempt=attempt, of=len(chain))

            def perform(provider=provider, model=model, timeout=timeout, meta=meta, mspec=mspec,
                        by_budget=by_budget):
                try:
                    text, usage = provider.complete(messages, model, temperature, timeout, hint)
                except SiparRuntimeError as e:
                    if e.kind == "ai" and not getattr(e, "no_request", False):
                        self.failed_charge(meta, getattr(e, "usage", None), messages)
                    rem_now = self.budget_remaining_seconds()
                    if by_budget and e.kind == "ai" and rem_now is not None and rem_now <= 0.05:
                        # the time budget, not the model, ran out: no fallback, a budget error
                        raise tag(SiparRuntimeError("budget", f"time budget exceeded: the call to {mspec} did not "
                                                          f"finish within the remaining {timeout:.2f}s"), self.budget_labels())
                    raise
                except Exception as e:      # a custom provider's bug or malformed reply: catchable, not internal
                    self.failed_charge(meta, None, messages)
                    raise SiparRuntimeError("ai", f"{mspec}: the provider failed ({type(e).__name__})")
                if not isinstance(text, str):
                    raise SiparRuntimeError("ai", f"{mspec}: the provider returned no text")
                usage = clean_usage(usage, prompt_text(messages), text)
                pr = self.prices()
                if pr is not None:
                    pin, pout = pr
                    meta["usd"] = round(usage["input"] * pin / 1e6 + usage["output"] * pout / 1e6, 9)
                return {"text": text, "usage": usage}

            try:
                resp = self.journal.effect(kind, request, perform, [f"untrusted:ai:{decl.name}"], meta=meta)
            except SiparRuntimeError as e:
                if e.kind != "ai":
                    raise
                if replaying:
                    m = (self.journal.last or {}).get("meta") or {}
                    more = isinstance(m.get("attempt"), int) and isinstance(m.get("of"), int) \
                        and m["attempt"] < m["of"]
                    mname = str(m.get("model", "?"))
                else:
                    m = meta
                    more = attempt < len(chain)
                    mname = mspec
                failures.append(f"{mname}: {e.message}")
                fu = m.get("usage") if isinstance(m, dict) else None
                if isinstance(fu, dict) and all(valid_count(fu.get(k)) for k in ("input", "output")):
                    # a failed attempt that may have been billed counts against the budget (SPEC §7)
                    self.budget_after(fu, m["usd"] if self._usd_ok(m.get("usd")) else 0.0)
                if more:
                    continue
                if len(failures) > 1:
                    raise SiparRuntimeError("ai", f"{decl.name}: every model in the chain failed: "
                                                  + "; ".join(failures))
                raise
            break
        if not isinstance(resp, dict) or not isinstance(resp.get("text"), str):
            raise SiparRuntimeError("replay", f"journal entry for {decl.name} has no text")
        usage = resp.get("usage")
        if not isinstance(usage, dict) or not all(valid_count(usage.get(k)) for k in ("input", "output")):
            raise SiparRuntimeError("replay", f"journal entry for {decl.name} has no valid token usage")
        m = (self.journal.last or {}).get("meta")
        usd = m.get("usd") if isinstance(m, dict) else None
        self.budget_after(usage, usd if self._usd_ok(usd) else 0.0)
        return resp["text"]


# ==================================================================== tests

def _old_fixture_name(name: str) -> str:
    """Fixture file name used before round 3; "a b" and "a_b" collided. Only read, never written."""
    import re
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("_") or "test"


def _fixture_name(name: str) -> str:
    """Readable part (at most 60 chars) plus 12 hex chars of sha256 of the exact test name: unique per name."""
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]
    return f"{_old_fixture_name(name)[:60].lstrip('.') or 'test'}-{digest}"     # never a hidden file


def _fixture_path(fix_dir: str, name: str, all_names: list[str]) -> str:
    """Path of the fixture to replay. A fixture recorded under the old name is still used when no fixture
    exists under the new name and no other test in the file maps to the same old name."""
    new = os.path.join(fix_dir, _fixture_name(name) + ".jsonl")
    if os.path.exists(new):
        return new
    old_name = _old_fixture_name(name)
    old = os.path.join(fix_dir, old_name + ".jsonl")
    if os.path.exists(old) and sum(_old_fixture_name(x) == old_name for x in all_names) == 1:
        return old
    return new


def run_tests(program: A.Program, file: str, **kw: Any) -> tuple[int, int]:
    """Run every test block on a big-stack thread (see run_main; round 5, F5)."""
    return call_deep(_run_tests, program, file, **kw)


def _run_tests(program: A.Program, file: str, *, live: bool = False, record: bool = False, out=None,
               err_out=None, stdin=None, mock_script: Any = None, providers: dict | None = None) -> tuple[int, int]:
    out = out or sys.stdout
    base = program_dir(file)
    fix_dir = os.path.join(base, ".sipar", "fixtures")
    passed = failed = 0
    tests = [it for it in program.items if isinstance(it, A.TestDecl)]
    names = [t.name for t in tests]
    for t in tests:
        with use_registry(SecretRegistry()):     # each test block has its own secrets (round 5, C1)
            fpath = os.path.join(fix_dir, _fixture_name(t.name) + ".jsonl")
            try:
                if not record:
                    fpath = _fixture_path(fix_dir, t.name, names)
                if record:
                    if os.path.exists(fpath):
                        os.remove(fpath)
                    journal = Journal(path=fpath)
                elif os.path.exists(fpath):
                    journal = Journal(replay=Journal.load(fpath))
                else:
                    journal = Journal()
                it = Interp(program, file, journal=journal, out=out, err_out=err_out, stdin=stdin, test_mode=True,
                            live=live or record, mock_script=mock_script, providers=providers)
                try:
                    it.init_globals()
                    try:
                        it.exec_block(t.body, Env(it.globals))
                    except (ReturnSig, BreakSig, ContinueSig):
                        pass                  # `return` ends the test early: the fixture check below still runs
                    if journal.unused():
                        raise SiparRuntimeError("replay", f"fixture {os.path.basename(fpath)} has {journal.unused()} "
                                                          "unused entr(ies); re-record with --record",
                                                t.line, t.col, file)
                finally:
                    journal.close()
                passed += 1
                out.write(f"PASS {escape_controls(t.name)}\n")
            except SiparRuntimeError as e:
                if record and os.path.exists(fpath):
                    os.remove(fpath)          # never keep a half-recorded fixture
                if not e.file:
                    e.file = file
                failed += 1
                out.write(f"FAIL {escape_controls(t.name)}\n  {safe_render_error(e)}\n")
            except BaseException as e:        # Ctrl-C, or a bug in Sipar itself: still no half-recorded fixture
                if record and os.path.exists(fpath):
                    os.remove(fpath)
                if not isinstance(e, Exception):
                    raise                     # KeyboardInterrupt / SystemExit stop the run (the fixture is gone)
                from ..errors import clip
                failed += 1                   # the other tests still run; this one is reported, never skipped
                out.write(f"FAIL {escape_controls(t.name)}\n  {escape_controls(file)}:{t.line}:{t.col}: error[internal]: "
                          f"{type(e).__name__}: {escape_controls(clip(str(e), 200))}\n")
    out.write(f"{passed} passed, {failed} failed\n")
    _flush(out)
    return passed, failed


def safe_render_error(e: SiparRuntimeError) -> str:
    v = getattr(e, "value", None)
    if v is not None:
        e = SiparRuntimeError(e.kind, render(v, redact=True), e.line, e.col, e.file)
    return e.render()
