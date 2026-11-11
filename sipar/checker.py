"""Sipar static checker: names, types, effects/capabilities, match exhaustiveness and control flow.

Entry points:
  check(program, src=None) -> list[Diagnostic]        errors + warnings, sorted by position
  check_source(src, file)  -> (Program | None, list[Diagnostic])   syntax errors become diagnostics

The checker keeps going after an error. An expression that already produced an error gets the type
Unknown, which every later check accepts silently, so one mistake gives one diagnostic.
Every code is listed with an example in docs/ERRORS.md.
"""
from __future__ import annotations

import os
import re
import shlex

import dataclasses
import difflib
from dataclasses import dataclass, field
from typing import Optional

from . import ast as A
from . import mcp_check as MC
from . import netscope
from .deep import call_deep
from .errors import Diagnostic, SiparSyntaxError
from .parser import parse
from .stdlib import (AGENT_ATTRS, AI_ATTRS, ATTRIBUTES, BUDGET_LIMITS, BUILTIN_TYPES, FUNCTIONS, METHODS,
                     MODULES)
from .types import (ANY, BOOL, FLOAT, INT, NEVER, NONE, NUM, NUMERIC, STR, UNKNOWN, FnT, ListT, MapT,
                    Named, OptT, Prim, Ty, TVar, assignable, erase_tvars, from_stdlib, has_never_elem,
                    has_tvar, has_unknown, int_float_only, is_jsonable, join, NO_WIDEN_HINT, opt, subst, ty_to_te, unify, widen_plan)

SCOPED_CAPS = {"net": '["example.com"]', "fs.read": '["./data"]', "fs.write": '["./out"]',
               "shell": '["ls"]', "env": '["HOME"]',
               "secret": '["API_KEY"]'}
GLOBAL_FUNCS = {k for k in FUNCTIONS if "." not in k}
RESERVED_TYPES = {"Int", "Float", "Str", "Bool", "None", "List", "Map"}
KIND_WORD = {"fn": "fn", "ai": "ai fn", "agent": "agent fn"}


ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SECRET_LIKE = re.compile(r"KEY|TOKEN|SECRET|PASS|CREDENTIAL|PRIVATE|AUTH", re.I)


@dataclass
class Var:
    ty: Ty
    kind: str               # let var param loop bind catch const
    node: A.Node


@dataclass
class FnInfo:
    decl: A.FnDecl
    params: list            # [(name, Ty)]
    ret: Ty
    effects: set            # what a caller (or a reference) gets

    @property
    def fnt(self) -> FnT:
        return FnT(tuple(t for _, t in self.params), self.ret)

    @property
    def title(self) -> str:
        return f"{KIND_WORD[self.decl.kind]} {self.decl.name}"


@dataclass
class Ctx:                  # effect context: one per fn / test / const / prompt
    kind: str               # fn ai agent test const prompt
    title: str
    declared: set
    decl: Optional[A.Node] = None
    in_test: bool = False
    effects: dict = field(default_factory=dict)     # effect -> (node, what) of first use


@dataclass
class Frame:                # return / loop context: a fn body, test body or lambda
    ret: Optional[Ty]       # None = infer (lambda without known result type)
    title: str
    loops: int = 0
    returns: list = field(default_factory=list)
    ret_nodes: list = field(default_factory=list)   # (value node, type) of each `return` when inferring


@dataclass
class Cov:                  # match coverage
    full: bool = False
    none: bool = False
    variants: set = field(default_factory=set)
    lits: set = field(default_factory=set)


def ts(t: Ty) -> str:
    return "Int or Float" if t == NUM else str(t)


def similar(name: str, candidates) -> str:
    m = difflib.get_close_matches(name, sorted(set(candidates)), n=1, cutoff=0.6)
    return f"did you mean `{m[0]}`?" if m else ""


def _has_break(node) -> bool:
    """A `break` that targets the loop whose body is `node` (not one in a nested loop or lambda)."""
    if isinstance(node, A.Break):
        return True
    if isinstance(node, (A.While, A.For, A.Lambda)):
        return False
    if isinstance(node, A.Node):
        return any(_has_break(getattr(node, f.name)) for f in dataclasses.fields(node))
    if isinstance(node, (list, tuple)):
        return any(_has_break(x) for x in node)
    return False


def lit_type(e: A.Expr) -> Ty:
    if isinstance(e, A.IntLit):
        return INT
    if isinstance(e, A.FloatLit):
        return FLOAT
    if isinstance(e, A.BoolLit):
        return BOOL
    if isinstance(e, A.StrLit):
        return STR
    return NONE


MATCH_WORK = 200_000        # _uncovered calls per match before the exhaustiveness check gives up (F3)


class _TooComplex(Exception):
    """The exhaustiveness check ran out of its work budget."""


def _p_wild(p) -> bool:
    return isinstance(p, (A.PWild, A.PBind))


def _p_none(p) -> bool:
    return isinstance(p, A.PLit) and isinstance(p.value, A.NoneLit)


def _p_ctor(p) -> Optional[str]:
    """The shape a pattern names: "true"/"false" for Bool literals, "Enum.variant" for variants."""
    if isinstance(p, A.PLit) and isinstance(p.value, A.BoolLit):
        return "true" if p.value.value else "false"
    if isinstance(p, A.PVariant):
        return f"{p.enum}.{p.variant}"
    return None


def lit_key(e: A.Expr):
    if isinstance(e, A.StrLit):
        return ("s", "".join(p for p in e.parts if isinstance(p, str)))
    return (type(e).__name__, getattr(e, "value", None))


class Checker:
    def __init__(self, program: A.Program):
        self.p = program
        self.file = program.file
        self.diags: list[Diagnostic] = []
        self.records: dict[str, dict[str, Ty]] = {n: {f: from_stdlib(t) for f, t in fs}
                                                   for n, fs in BUILTIN_TYPES.items()}
        self.enums: dict[str, dict[str, list]] = {}
        self.fns: dict[str, FnInfo] = {}
        self.consts: dict[str, Var] = {}
        self.const_decls: dict[str, A.ConstDecl] = {}
        self.allowed: dict[str, A.Allow] = {}
        self.scopes: list[dict[str, Var]] = []
        self.ctx = Ctx("fn", "program", set())
        self.frame: Optional[Frame] = None

    # ------------------------------------------------------------ diagnostics
    def err(self, code: str, node: A.Node, msg: str, hint: str = "", severity: str = "error") -> None:
        self.diags.append(Diagnostic(code, severity, self.file, node.line, node.col, msg, hint))

    def warn(self, code: str, node: A.Node, msg: str, hint: str = "") -> None:
        self.err(code, node, msg, hint, "warning")

    # ------------------------------------------------------------ scopes
    def push(self) -> None:
        self.scopes.append({})

    def pop(self) -> None:
        self.scopes.pop()

    def declare(self, name: str, ty: Ty, kind: str, node: A.Node) -> None:
        if name in MODULES:
            self.err("E202", node, f"`{name}` is the name of a built-in module and cannot be a variable",
                     f"choose another name, e.g. `{name}_value`")
        elif name in self.scopes[-1] and name != "_":
            self.err("E202", node, f"`{name}` is already defined in this block",
                     "choose another name" + (f", or assign with `{name} = ...`"
                                              if self.scopes[-1][name].kind == "var" else ""))
        self.scopes[-1][name] = Var(ty, kind, node)

    def bind_params(self, info: FnInfo, d: A.FnDecl) -> None:
        for (n, t), p in zip(info.params, d.params):
            if n in MODULES:    # E202 is already reported; still bind it, so `mcp.call(...)` in the body is not
                self.scopes[-1][n] = Var(t, "param", p)     # checked as the module too (L17, round 6)
            else:
                self.declare(n, t, "param", p)

    def lookup_var(self, name: str) -> Optional[Var]:
        for sc in reversed(self.scopes):
            if name in sc:
                return sc[name]
        return self.consts.get(name)

    def visible_names(self) -> list[str]:
        names = set(self.consts) | set(self.fns) | GLOBAL_FUNCS
        for sc in self.scopes:
            names |= set(sc)
        return sorted(names)

    # ------------------------------------------------------------ types
    def type_names(self) -> list[str]:
        return sorted(RESERVED_TYPES | set(self.records) | set(self.enums))

    def resolve(self, te: A.TypeExpr) -> Ty:
        if isinstance(te, A.TOptional):
            return opt(self.resolve(te.inner))
        if isinstance(te, A.TFn):
            return FnT(tuple(self.resolve(p) for p in te.params), self.resolve(te.ret))
        n = te.name
        if n in ("List", "Map"):
            if len(te.args) != 1:
                if n == "Map" and len(te.args) == 2:
                    self.err("E204", te, "Map takes one type: the value type (keys are always Str)",
                             f"write Map[{self.texpr(te.args[1])}]")
                else:
                    self.err("E204", te, f"{n} needs exactly one element type", f"write {n}[Str]")
                for a in te.args:
                    self.resolve(a)
                return UNKNOWN
            inner = self.resolve(te.args[0])
            if inner == UNKNOWN:
                return UNKNOWN
            return ListT(inner) if n == "List" else MapT(inner)
        if te.args:
            self.err("E204", te, f"type `{n}` takes no type arguments", f"write {n}")
            return UNKNOWN
        if n in ("Int", "Float", "Str", "Bool", "None"):
            return Prim(n)
        if n in self.records:
            return Named(n, "record")
        if n in self.enums:
            return Named(n, "enum")
        self.err("E204", te, f"unknown type `{n}`", similar(n, self.type_names()))
        return UNKNOWN

    def texpr(self, te: A.TypeExpr) -> str:
        if isinstance(te, A.TOptional):
            return self.texpr(te.inner) + "?"
        if isinstance(te, A.TFn):
            return f"fn({', '.join(self.texpr(p) for p in te.params)}) -> {self.texpr(te.ret)}"
        return te.name + (f"[{', '.join(self.texpr(a) for a in te.args)}]" if te.args else "")

    def jsonable(self, t: Ty) -> bool:
        return is_jsonable(t, self.records, self.enums)

    # ------------------------------------------------------------ effects
    def use_effect(self, eff: str, node: A.Node, what: str) -> None:
        self.ctx.effects.setdefault(eff, (node, what))

    def finish_ctx(self, ctx: Ctx, uses: list[str] | None = None) -> None:
        for eff, (node, what) in ctx.effects.items():
            if eff in ctx.declared:
                continue
            if ctx.kind in ("fn", "ai", "agent"):
                hint = f"add `uses {eff}` to {ctx.title}"
                if uses:
                    hint += f": `uses {', '.join(list(uses) + [eff])}`"
                self.err("E301", node, f"{ctx.title} uses `{eff}` ({what}) but does not declare it", hint)
            elif ctx.kind == "test":
                self.err("E302", node, f"{ctx.title} uses `{eff}` ({what}), but the program has no `allow {eff}` line",
                         self.allow_hint(eff))
            else:
                self.err("E304", node, f"{ctx.title} must be pure, but it uses `{eff}` ({what})",
                         "move this into a function that declares the effect")

    def allow_hint(self, eff: str) -> str:
        return f"add at the top of the file: allow {eff}" + (f" {SCOPED_CAPS[eff]}" if eff in SCOPED_CAPS else "")

    # ------------------------------------------------------------ driver
    def run(self) -> list[Diagnostic]:
        items = self.p.items
        self.collect(items)
        for it in items:
            if isinstance(it, A.ConstDecl):
                self.check_const(it)
        for it in items:
            if isinstance(it, A.FnDecl) and self.fns.get(it.name) and self.fns[it.name].decl is it:
                info = self.fns[it.name]
                if it.kind == "fn":
                    self.check_fn(info)
                else:
                    self.check_ai(info)
                for eff in sorted(info.effects):
                    if eff not in self.allowed:
                        self.err("E302", it, f"{info.title} uses `{eff}`, but the program has no `allow {eff}` line",
                                 self.allow_hint(eff))
        seen_tests: set[str] = set()
        for it in items:
            if isinstance(it, A.TestDecl):
                if it.name in seen_tests:
                    self.err("E202", it, f"there is already a test named \"{it.name}\"", "give each test its own name")
                seen_tests.add(it.name)
                self.check_test(it)
        uniq = {(d.line, d.col, d.code, d.message): d for d in self.diags}
        return sorted(uniq.values(), key=lambda d: (d.line, d.col, d.code, d.message))

    # ------------------------------------------------------------ declarations
    def collect(self, items: list) -> None:
        type_decls: list = []
        for it in items:
            if isinstance(it, A.Allow):
                self.check_allow(it)
            elif isinstance(it, (A.TypeDecl, A.EnumDecl)):
                if it.name in RESERVED_TYPES or it.name in BUILTIN_TYPES:
                    self.err("E202", it, f"`{it.name}` is a built-in type and cannot be redefined", "choose another name")
                    continue
                if it.name in MODULES:      # `enum shell {...}` would shadow shell.run(...) for the reader
                    self.err("E202", it, f"`{it.name}` is the name of a built-in module and cannot be "
                             f"{'an enum' if isinstance(it, A.EnumDecl) else 'a type'} name",
                             f"choose another name, e.g. `{it.name.capitalize()}Kind`")
                    continue
                if it.name in self.records or it.name in self.enums:
                    self.err("E202", it, f"type `{it.name}` is already defined", "choose another name")
                    continue
                if isinstance(it, A.TypeDecl):
                    self.records[it.name] = {}
                else:
                    self.enums[it.name] = {}
                type_decls.append(it)
        for it in type_decls:
            if isinstance(it, A.TypeDecl):
                self.records[it.name] = {f: self.resolve(t) for f, t in it.fields}
            else:
                self.enums[it.name] = {v.name: [(f, self.resolve(t)) for f, t in v.fields] for v in it.variants}
        for it in items:
            if isinstance(it, (A.FnDecl, A.ConstDecl)):
                n = it.name
                if n in self.fns or n in self.const_decls:
                    self.err("E202", it, f"`{n}` is already defined", "choose another name")
                    continue
                if n in GLOBAL_FUNCS or n in MODULES:
                    what = "module" if n in MODULES else "function"
                    self.err("E202", it, f"`{n}` is a built-in {what} and cannot be redefined", "choose another name")
                    continue
                if isinstance(it, A.ConstDecl):
                    self.const_decls[n] = it
                    continue
                params = [(p.name, self.resolve(p.type) if p.type else UNKNOWN) for p in it.params]
                for p in it.params:
                    if p.name in MODULES:
                        self.err("E202", p, f"`{p.name}` is the name of a built-in module and cannot be a parameter",
                                 f"choose another name, e.g. `{p.name}_value`")
                ret = self.resolve(it.ret) if it.ret else NONE
                effects = set(it.uses) | ({"ai"} if it.kind != "fn" else set())
                self.fns[n] = FnInfo(it, params, ret, effects)
        main = self.fns.get("main")
        if main:
            d = main.decl
            if d.kind != "fn":
                self.err("E243", d, "`main` must be a plain `fn`", "fn main() { ... }")
            elif main.params and not (len(main.params) == 1 and main.params[0][1] in (ListT(STR), UNKNOWN)):
                self.err("E243", d, "`main` takes no parameters or exactly `args: List[Str]`",
                         "fn main() { ... }  or  fn main(args: List[Str]) { ... }")

    def check_scope(self, it: A.Allow, s: str) -> None:
        """One entry of an `allow` list (SPEC §8): E310 when it can never mean what it says, E311 when it grants
        far more than a program should need."""
        cap = it.cap

        def bad(why: str, hint: str) -> None:
            self.err("E310", it, f"`allow {cap}` entry {s!r} {why}", hint)

        if not s.strip():
            return bad("is empty", "remove it or write what it grants, e.g. " + SCOPED_CAPS.get(cap, '["..."]'))
        if cap == "net":
            try:
                host, _ = netscope.parse(s)
            except netscope.ScopeError as e:
                return bad(e.why, e.hint)
            if host == "*":
                self.warn("E311", it, "`allow net [\"*\"]` is not a wildcard: it matches no host",
                          "list the hosts the program needs, e.g. allow net [\"api.example.com\"]")
            else:
                why = netscope.broad_wildcard(host)
                if why:
                    self.warn("E311", it, f"`allow net` entry {s!r} {why}", 'name the site, e.g. "*.example.com"')
        elif cap in ("fs.read", "fs.write"):
            if "\x00" in s:
                return bad("contains a NUL character", SCOPED_CAPS[cap])
            if s.strip().startswith("~"):
                self.warn("E311", it, f"`allow {cap}` entry {s!r}: `~` is not expanded; paths are relative to "
                          "the program's folder", f'allow {cap} {SCOPED_CAPS[cap]}')
            else:
                why = self.broad_path(s)
                if why:
                    self.warn("E311", it, f"`allow {cap}` entry {s!r} {why}",
                              f"name the folder the program needs, e.g. allow {cap} {SCOPED_CAPS[cap]}")
        elif cap == "shell":
            try:
                toks = shlex.split(s, posix=True)
            except ValueError as e:
                return bad(f"cannot be parsed as a command ({e})", 'allow shell ["git status"]')
            if not toks:
                return bad("is empty", 'allow shell ["ls"]')
        elif cap in ("env", "secret"):
            if not ENV_NAME.match(s):
                return bad("is not an environment variable name (letters, digits and _; no wildcards)",
                           f"allow {cap} {SCOPED_CAPS[cap]}")

    def broad_path(self, entry: str) -> Optional[str]:
        """Why an fs entry grants too much (E311): it resolves, as the runtime resolves it (realpath against the
        program's folder), to the root, the home folder, or a folder above the program."""
        base = os.path.realpath(os.path.dirname(os.path.abspath(self.file)) if not self.file.startswith("<")
                                else os.getcwd())
        full = os.path.realpath(os.path.join(base, entry))
        if full == os.path.realpath(os.sep):
            return "grants the whole file system"
        if full == os.path.realpath(os.path.expanduser("~")):
            return "grants your whole home folder"
        if base.startswith(full.rstrip(os.sep) + os.sep):
            return "grants a folder above the program's folder"
        return None

    def check_allow(self, it: A.Allow) -> None:
        if it.cap == "mcp":
            return MC.check_allow(self, it)
        if it.cap in self.allowed:
            self.warn("E303", it, f"`allow {it.cap}` appears more than once",
                      "merge them into one line: " + f"allow {it.cap}" + (" [...]" if it.cap in SCOPED_CAPS else ""))
        else:
            self.allowed[it.cap] = it
        if it.cap in SCOPED_CAPS and it.scopes is None:
            self.err("E306", it, f"`allow {it.cap}` needs a list of what it grants",
                     f"allow {it.cap} {SCOPED_CAPS[it.cap]}")
        elif it.cap not in SCOPED_CAPS and it.scopes is not None:
            self.err("E306", it, f"`allow {it.cap}` takes no list", f"allow {it.cap}")
        elif it.scopes == []:
            self.warn("E307", it, f"`allow {it.cap} []` grants nothing", "list at least one entry or remove the line")
        for scope in it.scopes or []:
            self.check_scope(it, str(scope))
        if it.cap == "env" and it.scopes:
            for name in it.scopes:
                if SECRET_LIKE.search(str(name)):
                    self.warn("E309", it, f"`allow env` lists {name!r}, which looks like a secret; "
                              "env.get returns it as plain text that can be printed or logged",
                              f'move it to `allow secret ["{name}"]` and read it with env.secret("{name}")')

    def check_const(self, c: A.ConstDecl) -> None:
        if self.const_decls.get(c.name) is not c:
            return
        self.ctx = Ctx("const", f"constant `{c.name}`", set(), c)
        self.frame = Frame(NONE, f"constant `{c.name}`")
        self.scopes = [{}]
        ty = self.let_type(c.name, c.type, c.value, c)
        self.finish_ctx(self.ctx)
        self.consts[c.name] = Var(ty, "const", c)

    def check_fn(self, info: FnInfo) -> None:
        d = info.decl
        self.ctx = Ctx("fn", info.title, set(d.uses), d)
        self.frame = Frame(info.ret, info.title)
        self.scopes = [{}]
        self.bind_params(info, d)
        ret = info.ret
        t = self.block(d.body, ret if ret != NONE else None, ret != NONE)
        if ret != NONE and t != NEVER:
            last = d.body.stmts[-1] if d.body.stmts else None
            no_value = not isinstance(last, A.ExprStmt) or (isinstance(last.expr, A.If) and last.expr.else_ is None)
            if t == NONE and no_value:
                self.err("E402", last or d.body, f"{info.title} must return {ret} on every path, but the end of "
                         "its body can be reached without a value",
                         "end the body with a value expression or add `return ...` on every path")
            elif not assignable(t, ret):
                self.err("E210", last.expr if last else d.body,
                         f"{info.title} must return {ret}, but its last expression is {ts(t)}",
                         "return a value of the declared type")
            else:
                self.fit(d.body, t, ret)
        self.finish_ctx(self.ctx, d.uses)

    def check_test(self, t: A.TestDecl) -> None:
        self.ctx = Ctx("test", f"test \"{t.name}\"", set(self.allowed), t, in_test=True)
        self.frame = Frame(NONE, f"test \"{t.name}\"")
        self.scopes = [{}]
        self.block(t.body, None, False)
        self.finish_ctx(self.ctx)

    def check_ai(self, info: FnInfo) -> None:
        d = info.decl
        title = info.title
        for (n, t), p in zip(info.params, d.params):
            if not self.jsonable(t):
                self.err("E230", p, f"parameter `{n}` of {title} has type {t}, which cannot be sent to a model",
                         "use JSON-able types: Int, Float, Str, Bool, List, Map, optionals, records, enums")
        if not self.jsonable(info.ret):
            self.err("E230", d.ret or d, f"{title} returns {info.ret}, which a model cannot produce",
                     "use JSON-able types: Int, Float, Str, Bool, List, Map, optionals, records, enums")
        self.check_attrs(d)
        # prompt: only parameters and constants, and pure
        self.ctx = Ctx("prompt", f"the prompt of {title}", set(), d)
        self.frame = Frame(NONE, title)
        self.scopes = [{}]
        self.bind_params(info, d)
        self.expr(d.prompt)
        self.finish_ctx(self.ctx)
        if d.kind == "agent":
            self.check_tools(info)

    def check_attrs(self, d: A.FnDecl) -> None:
        seen: set[str] = set()
        allowed = AI_ATTRS if d.kind == "ai" else AGENT_ATTRS
        for a in d.attrs:
            if a.name in seen:
                self.err("E231", a, f"attribute @{a.name} is given twice", "keep one")
                continue
            seen.add(a.name)
            if a.name not in ATTRIBUTES:
                self.err("E231", a, f"unknown attribute @{a.name}",
                         similar(a.name, ATTRIBUTES) or "attributes: " + ", ".join(f"@{k}" for k in ATTRIBUTES))
                continue
            if a.name not in allowed:
                self.err("E231", a, f"@{a.name} is only allowed on `agent fn`", "remove it from this ai fn")
                continue
            want = ATTRIBUTES[a.name]
            got = lit_type(a.value)
            if not (str(got) == want or (want == "Float" and got == INT)):
                self.err("E231", a, f"@{a.name} needs a {want} literal, found {got}",
                         {"Str": f'@{a.name}("...")', "Int": f"@{a.name}(3)", "Float": f"@{a.name}(0.2)"}[want])
                continue
            v = a.value.value if not isinstance(a.value, A.StrLit) else None
            if (a.name == "retries" and v < 0) or (a.name == "max_steps" and v < 1) or (
                    a.name == "temperature" and v < 0):
                low = 1 if a.name == "max_steps" else 0
                self.err("E231", a, f"@{a.name} must be at least {low}, found {v}", f"@{a.name}({low})")
            if a.name == "model" and isinstance(a.value, A.StrLit) and all(isinstance(p, str) for p in a.value.parts):
                from .runtime.providers import parse_chain   # one source of truth for model names
                from .errors import SiparRuntimeError
                try:
                    parse_chain("".join(a.value.parts))
                except SiparRuntimeError as e:
                    self.err("E231", a, f"bad @model: {e.message}",
                             '@model("openrouter/qwen/qwen3-coder | gemini/gemini-2.5-flash | mock")')

    def check_tools(self, info: FnInfo) -> None:
        d = info.decl
        declared = info.effects
        seen: set[str] = set()
        for name in d.tools:
            if name in seen:
                self.err("E202", d, f"tool `{name}` is listed twice in {info.title}", "list each tool once")
                continue
            seen.add(name)
            if name.startswith("mcp."):
                MC.check_tool(self, info, name)
                continue
            tool = self.fns.get(name)
            if tool is None:
                if name in FUNCTIONS:
                    self.err("E232", d, f"`{name}` is a built-in function and cannot be a tool",
                             f"wrap it in your own fn with a /// doc comment and list that")
                else:
                    self.err("E203", d, f"unknown tool `{name}` in {info.title}", similar(name, self.fns))
                continue
            if tool.decl.kind == "agent":
                self.err("E232", d, f"tool `{name}` is an agent fn; tools must be a `fn` or an `ai fn`",
                         "call the agent from a plain fn and list that fn")
                continue
            for (pn, pt) in tool.params:
                if not self.jsonable(pt):
                    self.err("E232", d, f"tool `{name}` has parameter `{pn}` of type {pt}, which a model cannot "
                             "provide", "tools need JSON-able parameter types (no fn types)")
            if not self.jsonable(tool.ret):
                self.err("E232", d, f"tool `{name}` returns {tool.ret}, which cannot be sent back to the model",
                         "tools need a JSON-able return type (no fn types)")
            if not tool.decl.doc:
                self.warn("E308", tool.decl, f"tool `{name}` has no /// doc comment, so the model gets no description",
                          f"add a line above it: /// What {name} does.")
            for eff in sorted(tool.effects - declared):
                self.err("E301", d, f"{info.title} uses `{eff}` through its tool `{name}` but does not declare it",
                         f"add `uses {eff}` to {info.title}")

    # ------------------------------------------------------------ statements
    def block(self, b: A.Block, exp: Optional[Ty], used: bool, binds: list | None = None) -> Ty:
        """Check a block; returns its value type, Never if it never falls through."""
        if binds:                       # loop / catch variables live in their own scope (may be shadowed)
            self.push()
            for n, t, k, node in binds:
                self.declare(n, t, k, node)
        self.push()
        term = warned = False
        value: Ty = NONE
        last = len(b.stmts) - 1
        for i, s in enumerate(b.stmts):
            if term and not warned:
                self.warn("E404", s, "this code is never reached", "remove it, or move it before the return/break")
                warned = True
            if i == last and isinstance(s, A.ExprStmt):
                value = self.expr(s.expr, exp, used)
                term = term or value == NEVER
            elif self.stmt(s):
                term = True
        self.pop()
        if binds:
            self.pop()
        if term:
            return NEVER
        return value if b.stmts and isinstance(b.stmts[-1], A.ExprStmt) else NONE

    def stmt(self, s: A.Stmt) -> bool:
        """Check a statement; returns True if control never continues after it."""
        if isinstance(s, A.ExprStmt):
            return self.expr(s.expr, None, False) == NEVER
        if isinstance(s, A.Let):
            ty = self.let_type(s.name, s.type, s.value, s)
            self.declare(s.name, ty, "var" if s.mutable else "let", s)
            return ty == NEVER
        if isinstance(s, A.Assign):
            self.assign(s)
            return False
        if isinstance(s, A.While):
            self.cond(s.cond, "while")
            self.frame.loops += 1
            self.block(s.body, None, False)
            self.frame.loops -= 1
            return isinstance(s.cond, A.BoolLit) and s.cond.value and not _has_break(s.body)
        if isinstance(s, A.For):
            it = self.expr(s.iter)
            if isinstance(it, ListT):
                vt = it.elem
            elif isinstance(it, MapT):
                vt = STR
            elif it in (UNKNOWN, NEVER):
                vt = UNKNOWN
            elif it == STR:
                self.err("E220", s.iter, "cannot loop over a Str directly",
                         'loop over its lines or characters: for line in s.lines() { } or for ch in s.split("") { }')
                vt = UNKNOWN
            elif isinstance(it, OptT):
                self.err("E219", s.iter, f"cannot loop over a value that may be none ({it})",
                         "unwrap it first: for x in xs ?? [] { }")
                vt = UNKNOWN
            else:
                self.err("E220", s.iter, f"cannot loop over a value of type {it}",
                         "`for` works on List, Map (keys) and ranges a..b")
                vt = UNKNOWN
            self.frame.loops += 1
            self.block(s.body, None, False, [(s.var, vt, "loop", s)])
            self.frame.loops -= 1
            return False
        if isinstance(s, A.Return):
            self.ret(s)
            return True
        if isinstance(s, (A.Break, A.Continue)):
            if self.frame.loops == 0:
                w = "break" if isinstance(s, A.Break) else "continue"
                self.err("E403", s, f"`{w}` can only be used inside a `while` or `for` loop",
                         "use `return` to leave a function")
            return True
        if isinstance(s, A.Assert):
            self.cond(s.cond, "assert")
            if s.message is not None:
                mt = self.expr(s.message, STR)
                if not assignable(mt, STR):
                    self.err("E210", s.message, f"the assert message must be Str, found {mt}",
                             'write a string, e.g. assert x > 0, "x must be positive"')
            return False
        if isinstance(s, A.Mock):
            self.mock(s)
            return False
        raise TypeError(f"unknown statement {type(s).__name__}")  # pragma: no cover

    def let_type(self, name: str, te: Optional[A.TypeExpr], value: A.Expr, node: A.Node) -> Ty:
        if te is not None:
            dt = self.resolve(te)
            t = self.expr(value, dt)
            if not assignable(t, dt):
                self.mismatch(value, t, dt, f"`{name}` is declared as {dt}, but the value is {ts(t)}")
            else:
                self.fit(value, t, dt)
            return dt
        t = self.expr(value)
        if t == NONE:
            if isinstance(value, A.NoneLit):
                self.err("E211", value, f"cannot infer the type of `{name}` from `none`",
                         f"write the type: let {name}: Str? = none")
            else:
                self.err("E210", value, f"this expression has no value, so `{name}` would always be none",
                         "only bind expressions that produce a value")
            return UNKNOWN
        if has_never_elem(t):
            kind = "list" if isinstance(t, ListT) else "map"
            ex = "List[Str] = []" if kind == "list" else "Map[Int] = [:]"
            self.err("E211", value, f"cannot infer the element type of an empty {kind}",
                     f"write the type: let {name}: {ex}")
            return UNKNOWN
        return t

    def assign(self, s: A.Assign) -> None:
        tgt = s.target
        dt: Ty = UNKNOWN
        if isinstance(tgt, A.Name):
            v = self.lookup_var(tgt.name)
            if v is None:
                if tgt.name in self.fns:
                    self.err("E207", tgt, f"cannot assign to `{tgt.name}`: it is a function")
                else:
                    self.err("E203", tgt, f"unknown variable `{tgt.name}`",
                             similar(tgt.name, self.visible_names()) or f"declare it first: var {tgt.name} = ...")
            elif v.kind != "var":
                why, hint = {
                    "let": ("it was declared with `let`", f"declare it with `var {tgt.name} = ...` to change it"),
                    "param": ("it is a parameter", f"copy it into a variable: var {tgt.name}2 = {tgt.name}"),
                    "loop": ("it is a loop variable", "use a separate `var` declared before the loop"),
                    "const": ("it is a constant", "constants never change; use a `var` inside a function"),
                }.get(v.kind, ("it is a pattern or catch binding", "copy it into a `var`"))
                self.err("E207", tgt, f"cannot assign to `{tgt.name}`: {why}", hint)
            else:
                dt = v.ty
        elif isinstance(tgt, A.Field):
            dt = self.e_Field(tgt, None, True)
        elif isinstance(tgt, A.Index):
            ot = self.expr(tgt.obj)
            if ot == STR:
                self.err("E220", tgt, "strings cannot be changed in place", "build a new string instead")
                self.expr(tgt.index)
            elif isinstance(tgt.index, A.Binary) and tgt.index.op == "..":
                self.err("E220", tgt, "cannot assign to a slice", "assign single elements: xs[i] = v")
            else:
                dt = self.index_type(tgt, ot)
        t = self.expr(s.value, dt if dt != UNKNOWN else None)
        if not assignable(t, dt):
            self.mismatch(s.value, t, dt, f"cannot assign {ts(t)} to a target of type {dt}")
        else:
            self.fit(s.value, t, dt)

    def ret(self, s: A.Return) -> None:
        f = self.frame
        t = NONE if s.value is None else self.expr(s.value, f.ret if f.ret not in (None, NONE) else None)
        if f.ret is None:
            f.returns.append(t)
            f.ret_nodes.append((s.value, t))
        elif f.ret == NONE:
            if s.value is not None and t not in (NONE, NEVER):
                self.err("E221", s.value, f"{f.title} does not return a value",
                         "remove the value, or declare a return type: fn name(...) -> Type")
        elif not assignable(t, f.ret):
            if s.value is None:
                self.err("E210", s, f"{f.title} must return {f.ret}, but this `return` has no value",
                         "write return <value>")
            else:
                self.mismatch(s.value, t, f.ret, f"{f.title} must return {f.ret}, found {ts(t)}")
        else:
            self.fit(s.value, t, f.ret)

    def mock(self, s: A.Mock) -> None:
        if not self.ctx.in_test:
            self.err("E240", s, "`mock` can only be used inside a `test` block",
                     "move it into test \"...\" { mock f(x) => ... }")
            return
        info = self.fns.get(s.fn_name)
        if info is None:
            if s.fn_name in FUNCTIONS:
                self.err("E241", s, f"`{s.fn_name}` is built in; only your own fn, ai fn and agent fn can be mocked",
                         "wrap it in your own fn and mock that")
            else:
                self.err("E203", s, f"unknown function `{s.fn_name}` in mock", similar(s.fn_name, self.fns))
            return
        if len(s.params) != len(info.params):
            self.err("E241", s, f"{info.title} takes {len(info.params)} parameter(s), but the mock has {len(s.params)}",
                     f"mock {s.fn_name}({', '.join(n for n, _ in info.params)}) => ...")
            binds = [(m, UNKNOWN, "param", s) for m in s.params]    # still declared: no "unknown name" follow-ups
        else:
            binds = [(m, t, "param", s) for m, (_, t) in zip(s.params, info.params)]
        self.push()
        for n, t, k, node in binds:
            self.declare(n, t, k, node)
        saved, self.frame = self.frame, Frame(info.ret if info.ret != NONE else None, f"the mock of {info.title}")
        t = self.expr(s.body, info.ret if info.ret != NONE else None)
        self.frame = saved
        self.pop()
        if info.ret != NONE and not assignable(t, info.ret):
            self.mismatch(s.body, t, info.ret, f"the mock must return {info.ret} like {info.title}, found {ts(t)}")
        elif info.ret != NONE:
            self.fit(s.body, t, info.ret)

    def cond(self, e: A.Expr, what: str) -> None:
        t = self.expr(e)
        if t in (BOOL, UNKNOWN, NEVER):
            return
        hint = "write a comparison, e.g. x > 0"
        if isinstance(t, OptT):
            hint = "compare explicitly: x != none"
        elif t in NUMERIC:
            hint = "compare explicitly: x != 0"
        elif t == STR:
            hint = 'compare explicitly: s != ""'
        elif isinstance(t, ListT):
            hint = "compare explicitly: xs.len() > 0"
        self.err("E215", e, f"the condition of `{what}` must be Bool, found {t}", hint)

    def fit(self, node: Optional[A.Node], src: Ty, dst: Optional[Ty]) -> None:
        """Mark node so the runtime widens its value from src to dst (Int -> Float, also inside optionals and
        function values). Blocks pass the mark to their value expression."""
        if node is None or dst is None:
            return
        while isinstance(node, A.Block):
            if not node.stmts or not isinstance(node.stmts[-1], A.ExprStmt):
                return
            node = node.stmts[-1].expr
        plan = widen_plan(src, dst)
        if plan is not None:
            node.widen = plan

    def mismatch(self, node: A.Node, got: Ty, want: Ty, msg: str) -> None:
        hint = ""
        if got == NONE and not isinstance(want, OptT):
            self.err("E219", node, f"`none` cannot be used here: {want} is not optional",
                     f"make the type optional ({want}?) or use a real value")
            return
        if isinstance(got, OptT) and assignable(got.inner, want):
            hint = "the value may be none; unwrap it with `?? default` or `match`"
        elif got == FLOAT and want == INT:
            hint = "convert explicitly: x as Int, round(x) or floor(x)"
        elif want == STR:
            hint = "convert with `as Str` or use interpolation \"{x}\""
        self.err("E210", node, msg, hint)

    # ------------------------------------------------------------ expressions
    def expr(self, e: A.Expr, exp: Optional[Ty] = None, used: bool = True) -> Ty:
        return getattr(self, "e_" + type(e).__name__)(e, exp, used)

    def e_IntLit(self, e, exp, used):
        return INT

    def e_FloatLit(self, e, exp, used):
        return FLOAT

    def e_BoolLit(self, e, exp, used):
        return BOOL

    def e_NoneLit(self, e, exp, used):
        return NONE

    def e_StrLit(self, e, exp, used):
        for p in e.parts:
            if not isinstance(p, str):
                self.expr(p)
        return STR

    def e_Name(self, e, exp, used):
        v = self.lookup_var(e.name)
        if v is not None:
            return v.ty
        if e.name in self.fns:
            return self.ref_fn(e.name, e, "uses it as a value")
        if e.name in GLOBAL_FUNCS:
            self.err("E206", e, f"built-in function `{e.name}` cannot be used as a value",
                     f"wrap it in a lambda: fn(x) => {e.name}(x)")
        elif e.name in MODULES:
            fs = [k for k in FUNCTIONS if k.startswith(e.name + ".")]
            self.err("E206", e, f"`{e.name}` is a module; it can only be used to call its functions",
                     f"e.g. {fs[0]}(...)")
        elif e.name in self.enums:
            self.err("E206", e, f"`{e.name}` is an enum type, not a value",
                     f"use one of its variants, e.g. {e.name}.{next(iter(self.enums[e.name]))}")
        elif e.name in self.records:
            self.err("E206", e, f"`{e.name}` is a record type, not a value", f"build one: {e.name} {{ ... }}")
        elif self.ctx.kind == "const" and e.name in self.const_decls:
            self.err("E305", e, f"constant `{e.name}` is used before its definition",
                     f"move `let {e.name}` above {self.ctx.title}")
        else:
            self.err("E203", e, f"unknown name `{e.name}`", similar(e.name, self.visible_names()))
        return UNKNOWN

    def ref_fn(self, name: str, node: A.Node, how: str) -> Ty:
        info = self.fns[name]
        if self.ctx.kind == "const":
            self.err("E305", node, f"{self.ctx.title} cannot call or reference {info.title}",
                     "constants are computed before anything runs; compute this value inside a function")
            return UNKNOWN
        if self.ctx.kind == "prompt":
            self.err("E230", node, f"{self.ctx.title} can only use its parameters and constants, not {info.title}",
                     "compute the value in a normal fn and pass it to the ai fn as a parameter")
            return UNKNOWN
        for eff in sorted(info.effects):
            self.use_effect(eff, node, f"{how}: {info.title}")
        return info.fnt

    def e_ListLit(self, e, exp, used):
        if isinstance(exp, OptT):
            exp = exp.inner
        ee = exp.elem if isinstance(exp, ListT) else None
        if not e.items:
            return ListT(ee if ee is not None else NEVER)
        acc: Optional[Ty] = None
        seen: list = []
        for it in e.items:
            t = self.expr(it, ee)
            seen.append((it, t))
            if ee is not None:
                if not assignable(t, ee):
                    self.mismatch(it, t, ee, f"list item must be {ee}, found {ts(t)}")
                continue
            if acc is None:
                acc = t
                continue
            j = join(acc, t)
            if j is None:
                self.err("E218", it, f"list items must all have the same type, found {acc} and {ts(t)}",
                         NO_WIDEN_HINT if int_float_only(acc, t) else "convert them to one type, e.g. with `as Str`")
                acc = UNKNOWN
            else:
                acc = j
        for it, t in seen:
            self.fit(it, t, ee if ee is not None else acc)
        return ListT(ee if ee is not None else acc)

    def e_MapLit(self, e, exp, used):
        if isinstance(exp, OptT):
            exp = exp.inner
        ee = exp.elem if isinstance(exp, MapT) else None
        acc: Optional[Ty] = None
        seen: list = []
        for k, v in e.entries:
            kt = self.expr(k, STR)
            if not assignable(kt, STR):
                self.err("E210", k, f"map keys must be Str, found {kt}", 'convert it: "{k}" or k as Str')
            t = self.expr(v, ee)
            seen.append((v, t))
            if ee is not None:
                if not assignable(t, ee):
                    self.mismatch(v, t, ee, f"map value must be {ee}, found {ts(t)}")
                continue
            if acc is None:
                acc = t
                continue
            j = join(acc, t)
            if j is None:
                self.err("E218", v, f"map values must all have the same type, found {acc} and {ts(t)}",
                         NO_WIDEN_HINT if int_float_only(acc, t) else "convert them to one type, e.g. with `as Str`")
                acc = UNKNOWN
            else:
                acc = j
        for v, t in seen:
            self.fit(v, t, ee if ee is not None else acc)
        return MapT(ee if ee is not None else (acc if acc is not None else NEVER))

    def e_RecordLit(self, e, exp, used):
        n = e.type_name
        if n not in self.records:
            if n in self.enums:
                self.err("E206", e, f"`{n}` is an enum, not a record",
                         f"build a value with a variant: {n}.{next(iter(self.enums[n]))}")
            else:
                self.err("E204", e, f"unknown record type `{n}`", similar(n, self.type_names()))
            for _, v in e.fields:
                self.expr(v)
            return UNKNOWN
        fields = self.records[n]
        for fname, v in e.fields:
            if fname not in fields:
                self.err("E205", v, f"record `{n}` has no field `{fname}`",
                         similar(fname, fields) or f"fields of {n}: {', '.join(fields)}")
                self.expr(v)
                continue
            ft = fields[fname]
            t = self.expr(v, ft)
            if not assignable(t, ft):
                self.mismatch(v, t, ft, f"field `{fname}` of {n} must be {ft}, found {ts(t)}")
            else:
                self.fit(v, t, ft)
        given = {f for f, _ in e.fields}
        missing = [f for f in fields if f not in given]
        if missing:
            self.err("E217", e, f"`{n}` is missing field(s): {', '.join(missing)}",
                     f"every field must be given: {n} {{ {', '.join(f + ': ...' for f in fields)} }}")
        return Named(n, "record")

    def e_Field(self, e, exp, used):
        o = e.obj
        if isinstance(o, A.Name) and self.lookup_var(o.name) is None:
            if o.name in MODULES:
                full = f"{o.name}.{e.name}"
                if full in FUNCTIONS:
                    self.err("E206", e, f"`{full}` is a function; call it", f"{full}(...)")
                else:
                    self.unknown_module_fn(o.name, e.name, e)
                return UNKNOWN
            if o.name in self.enums:
                return self.variant_value(o.name, e.name, e, None)
            if o.name in self.records:
                self.err("E206", e, f"`{o.name}` is a record type; read fields from a value, not from the type",
                         f"e.g. let r = {o.name} {{ ... }} then r.{e.name}")
                return UNKNOWN
        t = self.expr(o)
        return self.field_of(t, e)

    def unknown_module_fn(self, mod: str, name: str, node: A.Node) -> None:
        fs = [k.split(".")[1] for k in FUNCTIONS if k.startswith(mod + ".")]
        self.err("E205", node, f"module `{mod}` has no function `{name}`",
                 similar(name, fs) or f"{mod} functions: {', '.join(fs)}")

    def field_of(self, t: Ty, e: A.Field) -> Ty:
        if t in (UNKNOWN, NEVER):
            return UNKNOWN
        if isinstance(t, Named) and t.kind == "record":
            fields = self.records.get(t.name, {})
            if e.name in fields:
                return fields[e.name]
            self.err("E205", e, f"record `{t.name}` has no field `{e.name}`",
                     similar(e.name, fields) or f"fields of {t.name}: {', '.join(fields)}")
            return UNKNOWN
        if isinstance(t, Named):
            self.err("E205", e, f"enum `{t.name}` values have no fields", "read the payload with match")
            return UNKNOWN
        if isinstance(t, OptT):
            self.err("E219", e, f"cannot read `.{e.name}`: the value may be none ({t})",
                     "unwrap it first with `?? default` or `match v { none => ..., x => x." + e.name + " }`")
            return UNKNOWN
        kind = self.method_kind(t)
        if kind and e.name in METHODS[kind]:
            self.err("E206", e, f"`{e.name}` is a method of {kind}; call it", f".{e.name}()")
            return UNKNOWN
        self.err("E205", e, f"a value of type {t} has no field `{e.name}`",
                 similar(e.name, METHODS[kind]) if kind else "")
        return UNKNOWN

    def method_kind(self, t: Ty) -> Optional[str]:
        if t == STR:
            return "Str"
        if isinstance(t, ListT):
            return "List"
        if isinstance(t, MapT):
            return "Map"
        return None

    def variant_value(self, enum: str, vname: str, node: A.Node, call: Optional[A.Call]) -> Ty:
        variants = self.enums[enum]
        res = Named(enum, "enum")
        if vname not in variants:
            self.err("E205", node, f"enum `{enum}` has no variant `{vname}`",
                     similar(vname, variants) or f"variants: {', '.join(variants)}")
            if call:
                self.loose_args(call.args)
            return UNKNOWN
        fields = variants[vname]
        if call is None:
            if fields:
                self.err("E212", node, f"`{enum}.{vname}` carries data and needs it",
                         f"{enum}.{vname}({', '.join(f + ': ...' for f, _ in fields)})")
            return res
        if not fields:
            self.err("E212", node, f"`{enum}.{vname}` has no data; write it without parentheses", f"{enum}.{vname}")
            self.loose_args(call.args)
            return res
        self.bind_call(f"{enum}.{vname}", fields, call.args, node)
        return res

    def e_Index(self, e, exp, used):
        return self.index_type(e, self.expr(e.obj))

    def index_type(self, e: A.Index, ot: Ty) -> Ty:
        idx = e.index
        if isinstance(idx, A.Binary) and idx.op == "..":
            for side in (idx.left, idx.right):
                st = self.expr(side)
                if not assignable(st, INT):
                    self.err("E210", side, f"slice bounds must be Int, found {st}")
            if ot in (UNKNOWN, NEVER):
                return UNKNOWN
            if isinstance(ot, ListT) or ot == STR:
                return ot
            if isinstance(ot, OptT):
                self.err("E219", e, f"cannot slice a value that may be none ({ot})", "unwrap it first with ?? or match")
            else:
                self.err("E220", e, f"cannot slice a value of type {ot}", "slicing works on List and Str: xs[a..b]")
            return UNKNOWN
        it = self.expr(idx)
        if ot in (UNKNOWN, NEVER):
            return UNKNOWN
        if isinstance(ot, ListT) or ot == STR:
            if not assignable(it, INT):
                self.err("E210", idx, f"a {'list' if ot != STR else 'string'} index must be Int, found {it}")
            return ot.elem if isinstance(ot, ListT) else STR
        if isinstance(ot, MapT):
            if not assignable(it, STR):
                self.err("E210", idx, f"a map key must be Str, found {it}")
            return ot.elem
        if isinstance(ot, OptT):
            self.err("E219", e, f"cannot index a value that may be none ({ot})", "unwrap it first with ?? or match")
            return UNKNOWN
        self.err("E220", e, f"cannot index a value of type {ot}", "indexing works on List, Map and Str")
        return UNKNOWN

    def e_Unary(self, e, exp, used):
        t = self.expr(e.operand)
        if t in (UNKNOWN, NEVER):
            return UNKNOWN if e.op == "-" else BOOL
        if e.op == "-":
            if t in NUMERIC:
                return t
            self.err("E214", e, f"cannot negate a value of type {t}", "`-` works on Int and Float")
            return UNKNOWN
        if t != BOOL:
            self.err("E214", e, f"`not` needs a Bool, found {t}", "compare first, e.g. not (x == 0)")
        return BOOL

    def e_Binary(self, e, exp, used):
        op = e.op
        if op == "??":
            pre = None
            if self.is_memory_load(e.left) and self.lookup_var("memory") is None:
                if exp is not None and exp not in (ANY, NUM):
                    lt = self.expr(e.left, opt(exp))
                else:                       # memory.load(k) ?? default: T comes from the default
                    pre = self.expr(e.right)
                    lt = self.expr(e.left, None if pre == NEVER else opt(pre))
            else:
                lt = self.expr(e.left)
            if isinstance(lt, OptT):
                rt = pre if pre is not None else self.expr(e.right, exp if exp is not None else lt.inner)
                j = join(lt.inner, rt)
                if j is None:
                    self.err("E210", e.right, f"the default after `??` must be {lt.inner}, found {ts(rt)}",
                             f"give a {lt.inner} value")
                    return lt.inner
                self.fit(e.left, lt, opt(j))
                self.fit(e.right, rt, j)
                return j
            rt = pre if pre is not None else self.expr(e.right, exp)
            if lt in (UNKNOWN, NEVER):
                return UNKNOWN
            if lt == NONE:
                return rt
            self.warn("E250", e, f"the left side of `??` is {lt}, which is never none, so `??` does nothing",
                      "remove `?? ...`")
            return lt
        lt = self.expr(e.left)
        rt = self.expr(e.right)
        unknown = UNKNOWN in (lt, rt) or NEVER in (lt, rt)
        if op in ("and", "or"):
            for side, t in ((e.left, lt), (e.right, rt)):
                if t not in (BOOL, UNKNOWN, NEVER):
                    self.err("E214", side, f"`{op}` needs Bool operands, found {t}", "compare first, e.g. x > 0")
            return BOOL
        if op in ("==", "!="):
            if not unknown and not (assignable(lt, rt) or assignable(rt, lt)):
                if NONE in (lt, rt):
                    other = rt if lt == NONE else lt
                    self.err("E214", e, f"a value of type {other} is never none, so this comparison is always "
                             f"{'false' if op == '==' else 'true'}", "only optional values (T?) can be none")
                else:
                    self.err("E214", e, f"cannot compare {lt} with {rt}", "convert one side, e.g. with `as Str`")
            elif not unknown and (isinstance(lt, FnT) or isinstance(rt, FnT)):
                self.err("E214", e, "functions cannot be compared", "compare their results instead")
            return BOOL
        if op in ("<", "<=", ">", ">="):
            if not unknown and not ((lt in NUMERIC and rt in NUMERIC) or (lt == STR and rt == STR)):
                self.err("E214", e, f"`{op}` compares two numbers or two strings, found {lt} and {rt}",
                         "convert one side, e.g. s as Int")
            return BOOL
        if op == "in":
            if unknown:
                return BOOL
            if rt == STR:
                if lt != STR:
                    self.err("E214", e.left, f"`in` on a Str looks for a Str, found {lt}", "convert it: x as Str")
            elif isinstance(rt, ListT):
                if not (assignable(lt, rt.elem) or assignable(rt.elem, lt)):
                    self.err("E214", e.left, f"`in` on {rt} looks for a {rt.elem}, found {lt}")
            elif isinstance(rt, MapT):
                if lt != STR:
                    self.err("E214", e.left, f"`in` on a Map looks for a Str key, found {lt}")
            else:
                self.err("E214", e.right, f"`in` needs a Str, List or Map on the right, found {rt}")
            return BOOL
        if op == "..":
            for side, t in ((e.left, lt), (e.right, rt)):
                if t not in (INT, UNKNOWN, NEVER):
                    self.err("E214", side, f"range bounds must be Int, found {t}", "convert it: x as Int")
            return ListT(INT)
        # arithmetic
        if unknown:
            return UNKNOWN
        if lt in NUMERIC and rt in NUMERIC:
            return INT if lt == rt == INT else FLOAT
        if op == "+":
            if lt == STR and rt == STR:
                return STR
            if lt == STR or rt == STR:
                self.err("E214", e, f"cannot add {lt} and {rt}: `+` joins two strings only",
                         'use interpolation, e.g. "{a}{b}", or convert with `as Str`')
                return UNKNOWN
            if isinstance(lt, ListT) and isinstance(rt, ListT):
                j = join(lt, rt)
                if j is None or j != lt and j != rt:
                    self.err("E214", e, f"cannot join {lt} and {rt}: both lists need the same element type",
                             NO_WIDEN_HINT if int_float_only(lt, rt) else "")
                    return UNKNOWN
                return j
        self.err("E214", e, f"`{op}` needs two numbers, found {lt} and {rt}",
                 "arithmetic works on Int and Float; `+` also joins Str and List values")
        return UNKNOWN

    def e_As(self, e, exp, used):
        st = self.expr(e.expr)
        tt = self.resolve(e.type)
        if UNKNOWN in (st, tt) or st == NEVER or has_unknown(tt):
            return tt
        ok = (tt == STR or st == tt or (st == STR and tt in (INT, FLOAT, BOOL))
              or (st in NUMERIC and tt in NUMERIC)
              or (st == STR and isinstance(tt, (Named, ListT, MapT)) and self.jsonable(tt)))
        if not ok:
            self.err("E216", e, f"cannot convert {st} to {tt}",
                     "conversions: Str -> Int/Float/Bool, Int <-> Float, anything -> Str, "
                     "Str (JSON) -> record/enum/List/Map")
        return tt

    def e_Lambda(self, e, exp, used):
        eft = exp if isinstance(exp, FnT) else None
        if eft is not None and len(eft.params) != len(e.params):
            self.err("E212", e, f"a function with {len(eft.params)} parameter(s) is expected here, "
                     f"but this lambda has {len(e.params)}")
            eft = None
            reported = True     # the result is Unknown, so the caller does not report the same mismatch again
        else:
            reported = False
        binds = []
        ptys = []
        for i, p in enumerate(e.params):
            if p.type is not None:
                t = self.resolve(p.type)
                if eft is not None and not has_tvar(eft.params[i]) and not assignable(eft.params[i], t):
                    self.err("E210", p, f"parameter `{p.name}` is {t}, but this lambda is given {eft.params[i]}")
                    reported = True
            elif eft is not None and not has_tvar(eft.params[i]):
                t = eft.params[i]
            else:
                self.err("E211", p, f"cannot infer the type of lambda parameter `{p.name}`",
                         f"annotate it: fn({p.name}: Int) => ...")
                t = UNKNOWN
            ptys.append(t)
            binds.append((p.name, t, "param", p))
        if e.ret is not None:
            ret: Optional[Ty] = self.resolve(e.ret)
        elif eft is not None and not has_tvar(eft.ret) and eft.ret != NONE:
            ret = eft.ret
        else:
            ret = None
        saved = self.frame
        self.frame = Frame(ret, "this lambda")
        self.push()
        for n, t, k, node in binds:
            self.declare(n, t, k, node)
        bt = self.expr(e.body, ret, True)
        self.pop()
        frame, self.frame = self.frame, saved
        if ret is not None:
            if not assignable(bt, ret):
                self.mismatch(e.body, bt, ret, f"this lambda must return {ret}, found {ts(bt)}")
            else:
                self.fit(e.body, bt, ret)
            rt = ret
        else:
            rt = bt
            for r in frame.returns:
                j = join(rt, r)
                if j is None:
                    self.err("E218", e, f"this lambda returns both {rt} and {r}", "annotate the return type: fn(x) -> T => ...")
                    rt = UNKNOWN
                    break
                rt = j
            if rt not in (UNKNOWN, NEVER):
                self.fit(e.body, bt, rt)
                for node, r in frame.ret_nodes:
                    self.fit(node, r, rt)
        return UNKNOWN if reported else FnT(tuple(ptys), rt)

    def e_Block(self, e, exp, used):
        return self.block(e, exp, used)

    def e_If(self, e, exp, used):
        self.cond(e.cond, "if")
        tt = self.block(e.then, exp, used)
        if e.else_ is None:
            if used and tt not in (NONE, NEVER, UNKNOWN):
                self.err("E218", e, "this `if` has no `else`, so it has no value when the condition is false",
                         "add an else branch: if c { a } else { b }")
                return UNKNOWN      # the E218 explains it; no follow-up "none is not Int" errors
            return NONE
        et = self.expr(e.else_, exp, used)
        return self.join_branches(e, [tt, et], used, "if", [e.then, e.else_])

    def join_branches(self, node: A.Node, types: list, used: bool, what: str, nodes: list | None = None) -> Ty:
        if all(t == NEVER for t in types):
            return NEVER
        if not used:
            return NONE
        acc = types[0]
        for t in types[1:]:
            j = join(acc, t)
            if j is None:
                self.err("E218", node, f"the branches of this {what} have different types: {acc} and {t}",
                         NO_WIDEN_HINT if int_float_only(acc, t) else "make every branch produce the same type")
                return UNKNOWN
            acc = j
        for n, t in zip(nodes or [], types):
            self.fit(n, t, acc)
        return acc

    def e_Try(self, e, exp, used):
        bt = self.block(e.body, exp, used)
        ht = self.block(e.handler, exp, used, [(e.err_name, Named("Error", "record"), "catch", e)])
        return self.join_branches(e, [bt, ht], used, "try/catch", [e.body, e.handler])

    def e_Budget(self, e, exp, used):
        for a in e.limits:
            want = BUDGET_LIMITS.get(a.name)
            if want is None:
                self.err("E242", a, f"unknown budget limit `{a.name}`",
                         similar(a.name, BUDGET_LIMITS) or "limits: " + ", ".join(BUDGET_LIMITS))
                self.expr(a.value)
                continue
            t = self.expr(a.value)
            if t in (UNKNOWN, NEVER):
                continue
            if want == "Int" and t != INT:
                self.err("E242", a.value, f"budget limit `{a.name}` must be an Int, found {t}", f"{a.name}: 5")
            elif want == "Num" and t not in NUMERIC:
                self.err("E242", a.value, f"budget limit `{a.name}` must be a number, found {t}", f"{a.name}: 1.5")
        return self.block(e.body, exp, used)

    # ------------------------------------------------------------ match
    def e_Match(self, e, exp, used):
        st = self.expr(e.subject)
        cov = Cov()
        types = []
        for arm in e.arms:
            if cov.full:
                self.warn("E405", arm, "this arm is never reached: an earlier arm matches every value",
                          "remove it or move it above the catch-all arm")
            self.push()
            self.top_pattern(arm.pattern, st, cov)
            types.append(self.expr(arm.body, exp, used))
            self.pop()
        self.exhaustive(e, st, cov)
        return self.join_branches(e, types, used, "match", [arm.body for arm in e.arms])

    def top_pattern(self, p: A.Pattern, st: Ty, cov: Cov) -> None:
        inner = st.inner if isinstance(st, OptT) else st
        if isinstance(p, A.PWild):
            cov.full = True
        elif isinstance(p, A.PBind):
            ty = inner if isinstance(st, OptT) and cov.none else st
            self.bind_pattern(p, ty)
            cov.full = True
        elif isinstance(p, A.PLit) and isinstance(p.value, A.NoneLit):
            if st not in (UNKNOWN, NEVER) and not isinstance(st, OptT):
                self.err("E406", p, f"the value is {st}, which is never none, so this arm never matches",
                         "remove this arm")
            elif cov.none:
                self.warn("E405", p, "`none` is already matched by an earlier arm", "remove this arm")
            cov.none = True
        elif isinstance(p, A.PLit):
            if self.sub_pattern(p, inner):
                key = lit_key(p.value)
                if key in cov.lits:
                    self.warn("E405", p, "this value is already matched by an earlier arm", "remove this arm")
                cov.lits.add(key)
        else:
            fields = self.variant_pattern(p, inner)
            if fields is None:
                return
            irrefutable = p.args is None or all(isinstance(a, (A.PWild, A.PBind)) for a in p.args)
            if irrefutable:
                if p.variant in cov.variants:
                    self.warn("E405", p, f"`{p.enum}.{p.variant}` is already matched by an earlier arm",
                              "remove this arm")
                cov.variants.add(p.variant)

    def bind_pattern(self, p: A.PBind, ty: Ty) -> None:
        if p.name in self.consts or p.name in self.const_decls:
            self.warn("E407", p, f"this arm binds a new variable `{p.name}` and matches every value; "
                      f"it does not compare with the constant `{p.name}`",
                      f"to compare with the constant, use a literal pattern or `if v == {p.name} {{ ... }}`")
        elif isinstance(ty, Named) and ty.kind == "enum" and p.name in self.enums.get(ty.name, {}):
            self.warn("E407", p, f"this arm binds a new variable `{p.name}` and matches every value",
                      f"to match the variant write {ty.name}.{p.name}")
        if p.name != "_":
            self.declare(p.name, ty, "bind", p)

    def sub_pattern(self, p: A.Pattern, ty: Ty) -> bool:
        """Type-check a pattern against ty; returns False if it reported an error."""
        if isinstance(p, A.PWild):
            return True
        if isinstance(p, A.PBind):
            self.bind_pattern(p, ty)
            return True
        if isinstance(p, A.PLit):
            if isinstance(p.value, A.NoneLit):
                if ty not in (UNKNOWN, NEVER) and not isinstance(ty, OptT):
                    self.err("E406", p, f"the value is {ty}, which is never none", "remove this pattern")
                    return False
                return True
            lt = lit_type(p.value)
            inner = ty.inner if isinstance(ty, OptT) else ty
            if inner in (UNKNOWN, NEVER) or lt == inner or (lt == INT and inner == FLOAT):
                return True
            self.err("E406", p, f"this pattern is a {lt}, but the value is {ty}", "use a pattern of the value's type")
            return False
        inner = ty.inner if isinstance(ty, OptT) else ty
        return self.variant_pattern(p, inner) is not None

    def variant_pattern(self, p: A.PVariant, ty: Ty) -> Optional[list]:
        if p.enum not in self.enums:
            if p.enum in self.records:
                self.err("E406", p, f"`{p.enum}` is a record; patterns of the form X.y are enum variants",
                         "bind the record with a name and read its fields")
            else:
                self.err("E204", p, f"unknown enum `{p.enum}`", similar(p.enum, list(self.enums)))
            self.bind_sub_args(p, None)
            return None
        if ty not in (UNKNOWN, NEVER) and ty != Named(p.enum, "enum"):
            self.err("E406", p, f"pattern `{p.enum}.{p.variant}` is a {p.enum}, but the value is {ty}",
                     "match only variants of the value's own enum")
            self.bind_sub_args(p, None)
            return None
        variants = self.enums[p.enum]
        if p.variant not in variants:
            self.err("E205", p, f"enum `{p.enum}` has no variant `{p.variant}`",
                     similar(p.variant, variants) or f"variants: {', '.join(variants)}")
            self.bind_sub_args(p, None)
            return None
        fields = variants[p.variant]
        if p.args is not None and len(p.args) != len(fields):
            names = ", ".join(f for f, _ in fields)
            self.err("E406", p, f"`{p.enum}.{p.variant}` has {len(fields)} field(s) ({names or 'none'}), "
                     f"but the pattern has {len(p.args)}",
                     f"{p.enum}.{p.variant}({names})" if fields else f"{p.enum}.{p.variant}")
            self.bind_sub_args(p, None)
            return None
        self.bind_sub_args(p, fields)
        return fields

    def bind_sub_args(self, p: A.PVariant, fields: Optional[list]) -> None:
        for i, a in enumerate(p.args or []):
            self.sub_pattern(a, fields[i][1] if fields else UNKNOWN)

    def exhaustive(self, e: A.Match, st: Ty, cov: Cov) -> None:
        """E401 unless every value of st is matched by some arm. Sub-patterns count (SPEC §4): E.b(true) and
        E.b(false) together cover E.b(flag: Bool); a literal payload like E.s("x") does not cover E.s."""
        if cov.full or st in (UNKNOWN, NEVER):
            return
        rows = [[arm.pattern] for arm in e.arms]
        missing = []
        t = st
        if isinstance(st, OptT):
            if not any(_p_wild(r[0]) or _p_none(r[0]) for r in rows):
                missing.append("none")
            rows = [r for r in rows if not _p_none(r[0])]
            t = st.inner
        ctors = self._ctors(t)
        self._match_work = 0
        if ctors is None:
            if not any(_p_wild(r[0]) for r in rows):
                missing.append(f"other {t} values")
        else:
            try:
                groups = self._by_head(rows)
                for name, ftys in ctors:
                    sub = self._specialize(rows, name, ftys, groups)
                    w = self._uncovered(sub, ftys)
                    if w is not None:
                        missing.append(f"{name}({', '.join(w)})" if sub and ftys else name)
            except _TooComplex:         # sound fallback: say so; a value no arm matches still fails at run time
                self.warn("E408", e, f"this match is too complex to prove exhaustive (more than {MATCH_WORK:,} "
                                     "steps); it may miss a case",
                          "add a catch-all arm `_ => ...`, or split the match into nested matches")
                return
        if missing:
            self.err("E401", e, f"this match is not exhaustive: missing {', '.join(missing)}",
                     "add arms for them, or a catch-all arm `_ => ...`")

    def _ctors(self, t: Ty) -> Optional[list]:
        """The finite shapes of t as [(name, field types)], or None when t has too many values to list."""
        if t == BOOL:
            return [("true", []), ("false", [])]
        if isinstance(t, Named) and t.kind == "enum" and t.name in self.enums:
            return [(f"{t.name}.{v}", [ft for _, ft in fs]) for v, fs in self.enums[t.name].items()]
        return None

    @staticmethod
    def _by_head(rows: list) -> tuple:
        """({shape name: indices of the rows with that head}, indices of the rows with a wildcard head), so
        specializing for every shape of an n-variant enum is linear, not n x rows (F11, round 6)."""
        groups: dict = {}
        wild = []
        for i, r in enumerate(rows):
            if _p_wild(r[0]):
                wild.append(i)
            else:
                groups.setdefault(_p_ctor(r[0]), []).append(i)
        return groups, wild

    @staticmethod
    def _specialize(rows: list, name: str, ftys: list, groups: tuple) -> list:
        """Rows that can match shape `name` (in their order), with the shape's fields as new leading columns."""
        named, wild = groups
        out = []
        for i in sorted(named.get(name, []) + wild) if wild else named.get(name, []):
            r = rows[i]
            p = r[0]
            if _p_wild(p):
                out.append([p] * len(ftys) + r[1:])
            elif _p_ctor(p) == name:
                args = p.args if isinstance(p, A.PVariant) and p.args is not None else [A.PWild(p.line, p.col)] * len(ftys)
                if len(args) == len(ftys):
                    out.append(list(args) + r[1:])
        return out

    def _uncovered(self, rows: list, tys: list) -> Optional[list]:
        """A witness (one text per column) of values no row matches, or None if the rows cover every value.
        Maranget's usefulness check ("Warnings for pattern matching", 2007): when the rows' head shapes do not
        cover every shape of the column, only the rows with a wildcard head need checking (the default matrix),
        once, instead of once per shape. Work is capped at MATCH_WORK calls (round 5, F3)."""
        self._match_work = getattr(self, "_match_work", 0) + 1
        if self._match_work > MATCH_WORK:
            raise _TooComplex()
        if not rows:
            return ["_"] * len(tys)
        if not tys:
            return None
        t, rest = tys[0], tys[1:]
        unknown = t in (UNKNOWN, NEVER, ANY)        # after an error: do not report follow-up gaps
        if unknown or all(_p_wild(r[0]) for r in rows):
            w = self._uncovered([r[1:] for r in rows if unknown or _p_wild(r[0])], rest)
            return None if w is None else ["_"] + w
        if isinstance(t, OptT):
            w = self._uncovered([r[1:] for r in rows if _p_wild(r[0]) or _p_none(r[0])], rest)
            if w is not None:
                return ["none"] + w
            return self._uncovered([r for r in rows if not _p_none(r[0])], [t.inner] + rest)
        ctors = self._ctors(t)
        if ctors is None:
            w = self._uncovered([r[1:] for r in rows if _p_wild(r[0])], rest)
            return None if w is None else ["_"] + w
        groups = self._by_head(rows)
        absent = [(name, ftys) for name, ftys in ctors if name not in groups[0]]
        if absent:                      # incomplete signature: the default matrix decides (Maranget)
            w = self._uncovered([r[1:] for r in rows if _p_wild(r[0])], rest)
            if w is None:
                return None
            name, ftys = absent[0]
            return [f"{name}({', '.join(['_'] * len(ftys))})" if ftys else name] + w
        for name, ftys in ctors:
            w = self._uncovered(self._specialize(rows, name, ftys, groups), ftys + rest)
            if w is not None:
                n = len(ftys)
                return [f"{name}({', '.join(w[:n])})" if n else name] + w[n:]
        return None

    # ------------------------------------------------------------ calls
    def e_Call(self, e, exp, used):
        c = e.callee
        if MC.is_dotted(self, c) or MC.is_call(self, c):
            return MC.check_call(self, e, exp)
        if isinstance(c, A.Field) and isinstance(c.obj, A.Name) and self.lookup_var(c.obj.name) is None:
            n = c.obj.name
            if n in MODULES:
                full = f"{n}.{c.name}"
                if full not in FUNCTIONS:
                    self.unknown_module_fn(n, c.name, c)
                    self.loose_args(e.args)
                    return UNKNOWN
                return self.call_builtin(full, e, exp)
            if n in self.enums:
                return self.variant_value(n, c.name, c, e)
        if isinstance(c, A.Name) and self.lookup_var(c.name) is None:
            if c.name in self.fns:
                info = self.fns[c.name]
                if self.ref_fn(c.name, c, "calls") == UNKNOWN:
                    self.loose_args(e.args)
                    return UNKNOWN
                self.bind_call(info.title, info.params, e.args, self.anchor(e))
                return info.ret
            if c.name in GLOBAL_FUNCS:
                return self.call_builtin(c.name, e)
        if isinstance(c, A.Field):
            rt = self.expr(c.obj)
            return self.call_method(rt, c, e)
        ft = self.expr(c)
        if ft in (UNKNOWN, NEVER):
            self.loose_args(e.args)
            return UNKNOWN
        if isinstance(ft, FnT):
            self.bind_call("this function", [(None, p) for p in ft.params], e.args, self.anchor(e), named_ok=False)
            return ft.ret
        self.loose_args(e.args)
        if isinstance(ft, OptT) and isinstance(ft.inner, FnT):
            self.err("E219", c, f"cannot call a function that may be none ({ft})", "unwrap it first with ?? or match")
        else:
            self.err("E213", c, f"a value of type {ft} cannot be called", "only functions can be called")
        return UNKNOWN

    def anchor(self, call: A.Call) -> A.Node:
        """Where to report a call problem: the callee name (`f`, `http`, `Enum`) or the `.method` part."""
        c = call.callee
        if isinstance(c, A.Name):
            return c
        if isinstance(c, A.Field) and isinstance(c.obj, A.Name) and self.lookup_var(c.obj.name) is None \
                and (c.obj.name in MODULES or c.obj.name in self.enums):
            return c.obj
        return c if isinstance(c, A.Field) else call

    def loose_args(self, args: list) -> None:
        for a in args:
            self.expr(a.value)

    def call_builtin(self, name: str, call: A.Call, exp: Optional[Ty] = None) -> Ty:
        sig = FUNCTIONS[name]
        for eff in sig.effects:
            self.use_effect(eff, self.anchor(call), name)
        params = [(n, from_stdlib(t)) for n, t in sig.params]
        if name == "memory.load":
            return self.memory_load(call, params, exp)
        if name == "memory.save":
            res = self.bind_call(name, params, call.args, self.anchor(call), set(), {}, frozenset())
            t = res[0].get("T") if res else None
            if t is not None and not isinstance(t, TVar) and not has_unknown(t) and not has_never_elem(t) and (
                    not self.jsonable(t) or t == ANY or has_tvar(t)):
                pos = [a for a in call.args if a.name is None]
                arg = next((a for a in call.args if a.name == "value"), pos[1] if len(pos) > 1 else None)
                self.err("E222", arg.value if arg else self.anchor(call), f"memory.save cannot store a value of type {t}",
                         "store JSON-able data: Int Float Str Bool, lists, maps, records and enums of those")
            return NONE
        return self.finish_sig(name, sig, params, call, {}, frozenset())

    @staticmethod
    def is_memory_load(e: A.Expr) -> bool:
        return isinstance(e, A.Call) and isinstance(e.callee, A.Field) and e.callee.name == "load" \
            and isinstance(e.callee.obj, A.Name) and e.callee.obj.name == "memory"

    def memory_load(self, call: A.Call, params: list, exp: Optional[Ty]) -> Ty:
        """memory.load(key) -> T?  where T is the expected type at the use site (SPEC.md §5 memory)."""
        self.bind_call("memory.load", params, call.args, self.anchor(call), set(), {}, frozenset())
        t = exp.inner if isinstance(exp, OptT) else exp
        if t is not None and has_unknown(t):
            return UNKNOWN
        if t is None or t in (ANY, NUM, NEVER, NONE) or isinstance(t, TVar) or has_tvar(t) \
                or has_never_elem(t) or not self.jsonable(t):
            what = "is not known here" if t is None else f"cannot be {t}"
            self.err("E222", self.anchor(call), f"the type of the value memory.load returns {what}",
                     'say which type you expect: let notes: List[Str]? = memory.load("notes")  or  '
                     'memory.load("count") ?? 0')
            return UNKNOWN
        call.mem_type = ty_to_te(t)
        return opt(t)

    def finish_sig(self, desc: str, sig, params: list, call: A.Call, b: dict, fixed: frozenset) -> Ty:
        res = self.bind_call(desc, params, call.args, self.anchor(call), set(sig.defaults), b, fixed)
        if res is None:
            ret = from_stdlib(sig.ret)
            return UNKNOWN if ret not in (NEVER, NONE) else ret
        b, num_float, num_unknown = res
        ret = subst(from_stdlib(sig.ret), b)
        if ret == NUM:
            ret = UNKNOWN if num_unknown else FLOAT if num_float else INT
        return erase_tvars(ret)

    def call_method(self, rt: Ty, c: A.Field, call: A.Call) -> Ty:
        if rt in (UNKNOWN, NEVER):
            self.loose_args(call.args)
            return UNKNOWN
        if isinstance(rt, Named) and rt.kind == "record":
            fields = self.records.get(rt.name, {})
            ft = fields.get(c.name)
            if isinstance(ft, FnT):
                self.bind_call(f"field `{c.name}`", [(None, p) for p in ft.params], call.args, c, named_ok=False)
                return ft.ret
            self.loose_args(call.args)
            if ft is not None:
                self.err("E213", c, f"field `{c.name}` of {rt.name} is {ft}, not a function", f"read it without (): x.{c.name}")
            else:
                self.err("E205", c, f"record `{rt.name}` has no method or field `{c.name}`",
                         similar(c.name, fields) or "records have fields only, no methods")
            return UNKNOWN
        if isinstance(rt, OptT):
            self.loose_args(call.args)
            self.err("E219", c, f"cannot call `.{c.name}()`: the value may be none ({rt})",
                     "unwrap it first with `?? default` or `match`")
            return UNKNOWN
        kind = self.method_kind(rt)
        if kind is None:
            self.loose_args(call.args)
            self.err("E205", c, f"a value of type {rt} has no method `{c.name}`",
                     "methods exist on Str, List and Map" + (f"; convert first: (x as Str).{c.name}()" if rt in NUMERIC else ""))
            return UNKNOWN
        sig = METHODS[kind].get(c.name)
        if sig is None:
            self.loose_args(call.args)
            self.err("E205", c, f"{kind} has no method `{c.name}`",
                     similar(c.name, METHODS[kind]) or f"{kind} methods: {', '.join(METHODS[kind])}")
            return UNKNOWN
        b = {"T": rt.elem} if isinstance(rt, (ListT, MapT)) else {}
        params = [(n, from_stdlib(t)) for n, t in sig.params]
        res = self.finish_sig(f"{kind}.{c.name}", sig, params, call, b, frozenset(b))
        # element-type constraints
        if c.name in ("sort", "sum", "sort_by") and isinstance(rt, ListT):
            okset = (INT, FLOAT, STR) if c.name != "sum" else (INT, FLOAT)
            t = rt.elem
            if c.name == "sort_by":
                t = b.get("U", UNKNOWN)
                t = t if not isinstance(t, TVar) else UNKNOWN
            if t not in okset and t not in (UNKNOWN, NEVER):
                what = "Int or Float" if c.name == "sum" else "Int, Float or Str"
                subj = "the key" if c.name == "sort_by" else "the list items"
                hint = {"sort": "use sort_by with a key, e.g. xs.sort_by(fn(x) => x.score)",
                        "sort_by": "return a field that is Int, Float or Str, e.g. xs.sort_by(fn(x) => x.name)",
                        "sum": "map the items to numbers first, e.g. xs.map(fn(x) => x.n).sum()"}[c.name]
                self.err("E214", c, f"`{c.name}` needs {subj} to be {what}, found {t}", hint)
        if c.name == "sum" and isinstance(rt, ListT) and rt.elem == FLOAT:
            call.widen = "F"            # [].sum() of a List[Float] is 0.0, not the Int 0 (round 5, F2)
        return res

    def bind_call(self, desc: str, params: list, args: list, node: A.Node, defaults: set | None = None,
                  b: dict | None = None, fixed: frozenset = frozenset(), named_ok: bool = True):
        """Match args to params [(name|None, Ty)] and type-check them.
        Returns (bindings, num_float, num_unknown), or None if the argument list itself is wrong."""
        defaults = defaults or set()
        b = {} if b is None else b
        names = [n for n, _ in params]
        slots: list = [None] * len(params)
        required = [i for i, n in enumerate(names) if n not in defaults]
        ok = True
        misnamed = False
        pos = [a for a in args if a.name is None]
        if len(pos) > len(required):
            extra = f" (optional ones must be named: {', '.join(f'{d}: ...' for d in names if d in defaults)})" \
                if defaults else ""
            self.err("E212", pos[len(required)], f"{desc} takes {len(required)} positional argument(s), "
                     f"but {len(pos)} {'was' if len(pos) == 1 else 'were'} given{extra}", "remove the extra arguments")
            ok = False
        for k, a in enumerate(pos[:len(required)]):
            slots[required[k]] = a
        for a in args:
            if a.name is None:
                continue
            if not named_ok:
                self.err("E212", a, f"{desc} takes positional arguments only", "remove the `name:` part")
                ok = False
                misnamed = True     # the argument was given, just with a name: no "missing" follow-up
                continue
            if a.name not in names:
                self.err("E212", a, f"{desc} has no parameter named `{a.name}`",
                         similar(a.name, [n for n in names if n]) or
                         (f"parameters: {', '.join(n for n in names if n)}" if any(names) else "it takes no parameters"))
                ok = False
                misnamed = True
                continue
            i = names.index(a.name)
            if slots[i] is not None:
                self.err("E212", a, f"argument `{a.name}` of {desc} is given twice", "give it once")
                ok = False
                continue
            slots[i] = a
        missing = [names[i] or f"#{i + 1}" for i in range(len(params)) if slots[i] is None and names[i] not in defaults]
        if missing and not misnamed:
            self.err("E212", node, f"{desc} is missing argument(s): {', '.join(missing)}",
                     f"it takes ({', '.join(f'{n}: {ts(t)}' if n else ts(t) for n, t in params)})")
            ok = False
        placed = {id(a) for a in slots if a is not None}
        for a in args:
            if id(a) not in placed:
                self.expr(a.value)
        num_float = num_unknown = False
        widen_to: list = []
        order = [i for i in range(len(params)) if slots[i] is not None and not isinstance(slots[i].value, A.Lambda)]
        order += [i for i in range(len(params)) if slots[i] is not None and isinstance(slots[i].value, A.Lambda)]
        for i in order:
            a = slots[i]
            pt = params[i][1]
            want = subst(pt, b)
            hint_t = want if (isinstance(a.value, A.Lambda) or not has_tvar(want)) and want not in (NUM, ANY) else None
            at = self.expr(a.value, hint_t)
            if pt == NUM:
                num_float = num_float or at == FLOAT
                num_unknown = num_unknown or at == UNKNOWN
            if not unify(pt, at, b, fixed):
                label = f"argument `{params[i][0]}`" if params[i][0] else f"argument {i + 1}"
                self.mismatch(a.value, at, erase_tvars(subst(pt, b)) if pt != NUM else NUM,
                              f"{label} of {desc} must be {ts(erase_tvars(subst(pt, b)))}, found {ts(at)}")
            else:
                widen_to.append((a.value, at, pt))
        for node, at, pt in widen_to:          # after all arguments: type variables are bound by now
            dt = subst(pt, b)
            if pt not in (NUM, ANY) and not has_tvar(dt):
                self.fit(node, at, dt)
        if not ok:
            return None
        return b, num_float, num_unknown


# ---------------------------------------------------------------- public API

def check(program: A.Program, src: str | None = None) -> list[Diagnostic]:
    """Type-, effect- and flow-check a parsed program. Returns errors and warnings sorted by position.
    Runs on a big-stack thread (sipar.deep) so it can walk everything parse() accepts (round 5, F1)."""
    try:
        return call_deep(lambda: Checker(program).run())
    except RecursionError:      # a program built by hand past parser.MAX_AST_DEPTH: a diagnostic, never a crash
        return [Diagnostic("E115", "error", getattr(program, "file", "") or "<input>", 1, 1,
                           "program nested too deeply to check",
                           "move inner parts into `let` names or small functions")]


def check_source(src: str, file: str = "<input>") -> tuple[Optional[A.Program], list[Diagnostic]]:
    """Parse and check source text. A syntax error is returned as a single diagnostic."""
    try:
        program = parse(src, file)
    except SiparSyntaxError as e:
        return None, [e.diag]
    return program, check(program, src)
