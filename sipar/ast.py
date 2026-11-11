"""Sipar abstract syntax tree. Every node carries `line` and `col` (1-based) of its first token."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Union


@dataclass
class Node:
    line: int
    col: int
    widen = None        # set by the checker: how the runtime widens this value (Int -> Float), see types.widen_plan


# ---------------------------------------------------------------- type expressions

@dataclass
class TName(Node):          # Int, Str, Review, List[Str], Map[Int]
    name: str
    args: list["TypeExpr"] = field(default_factory=list)


@dataclass
class TOptional(Node):      # T?
    inner: "TypeExpr"


@dataclass
class TFn(Node):            # fn(A, B) -> R
    params: list["TypeExpr"]
    ret: "TypeExpr"


TypeExpr = Union[TName, TOptional, TFn]


# ---------------------------------------------------------------- expressions

@dataclass
class IntLit(Node):
    value: int


@dataclass
class FloatLit(Node):
    value: float


@dataclass
class BoolLit(Node):
    value: bool


@dataclass
class NoneLit(Node):
    pass


@dataclass
class StrLit(Node):
    """String literal. `parts` alternates str chunks and Expr (interpolations)."""
    parts: list[Union[str, "Expr"]]


@dataclass
class Name(Node):
    name: str


@dataclass
class ListLit(Node):
    items: list["Expr"]


@dataclass
class MapLit(Node):         # ["a": 1]  or  [:]
    entries: list[tuple["Expr", "Expr"]]


@dataclass
class RecordLit(Node):      # Review { score: 1, verdict: "x" }
    type_name: str
    fields: list[tuple[str, "Expr"]]


@dataclass
class Arg(Node):
    name: Optional[str]     # None = positional
    value: "Expr"


@dataclass
class Call(Node):           # f(x), obj.method(x), Enum.variant(x), http.get(x)
    callee: "Expr"
    args: list[Arg]


@dataclass
class Field(Node):          # obj.name  (also Enum.variant, module.func)
    obj: "Expr"
    name: str


@dataclass
class Index(Node):          # xs[i], s[a..b], m["k"]
    obj: "Expr"
    index: "Expr"


@dataclass
class Unary(Node):          # -x, not x
    op: str
    operand: "Expr"


@dataclass
class Binary(Node):         # + - * / % == != < <= > >= and or in .. ??
    op: str
    left: "Expr"
    right: "Expr"


@dataclass
class As(Node):             # expr as T
    expr: "Expr"
    type: TypeExpr


@dataclass
class Param(Node):
    name: str
    type: Optional[TypeExpr]    # None only allowed in lambdas


@dataclass
class Lambda(Node):         # fn(x: Int) -> Int => x * 2
    params: list[Param]
    ret: Optional[TypeExpr]
    body: "Expr"


@dataclass
class Block(Node):          # { stmt* } ; value = last ExprStmt (if it is the final statement)
    stmts: list["Stmt"]


@dataclass
class If(Node):
    cond: "Expr"
    then: Block
    else_: Optional[Union[Block, "If"]]


@dataclass
class MatchArm(Node):
    pattern: "Pattern"
    body: "Expr"            # an Expr or a Block


@dataclass
class Match(Node):
    subject: "Expr"
    arms: list[MatchArm]


@dataclass
class Try(Node):
    body: Block
    err_name: str
    handler: Block


@dataclass
class Budget(Node):         # budget(ai_calls: 5, seconds: 30) { ... }
    limits: list[Arg]       # all named
    body: Block


Expr = Union[IntLit, FloatLit, BoolLit, NoneLit, StrLit, Name, ListLit, MapLit, RecordLit, Call,
             Field, Index, Unary, Binary, As, Lambda, Block, If, Match, Try, Budget]


# ---------------------------------------------------------------- patterns

@dataclass
class PWild(Node):          # _
    pass


@dataclass
class PLit(Node):           # 1, "x", true, none
    value: Expr


@dataclass
class PBind(Node):          # name
    name: str


@dataclass
class PVariant(Node):       # Enum.variant  /  Enum.variant(p1, p2)
    enum: str
    variant: str
    args: Optional[list["Pattern"]]     # None = no parentheses


Pattern = Union[PWild, PLit, PBind, PVariant]


# ---------------------------------------------------------------- statements

@dataclass
class Let(Node):
    name: str
    type: Optional[TypeExpr]
    value: Expr
    mutable: bool           # var


@dataclass
class Assign(Node):         # target = value ; target is Name, Field or Index
    target: Expr
    value: Expr


@dataclass
class ExprStmt(Node):
    expr: Expr


@dataclass
class While(Node):
    cond: Expr
    body: Block


@dataclass
class For(Node):
    var: str
    iter: Expr
    body: Block


@dataclass
class Return(Node):
    value: Optional[Expr]


@dataclass
class Break(Node):
    pass


@dataclass
class Continue(Node):
    pass


@dataclass
class Assert(Node):
    cond: Expr
    message: Optional[Expr]


@dataclass
class Mock(Node):           # mock review(code) => expr      (only inside test blocks)
    fn_name: str
    params: list[str]
    body: Expr


Stmt = Union[Let, Assign, ExprStmt, While, For, Return, Break, Continue, Assert, Mock]


# ---------------------------------------------------------------- items

@dataclass
class Attribute(Node):      # @retries(3)
    name: str
    value: Expr             # a literal


@dataclass
class Allow(Node):          # allow net ["a.com"]
    cap: str                # ai net fs.read fs.write shell env time random io
    scopes: Optional[list[str]]     # None = unrestricted (only meaningful for ai/time/random/io); mcp: the command
    server: Optional[str] = None    # allow mcp "fs" [cmd] tools [...] readonly [...] pin "sha256:..."
    tools: Optional[list[str]] = None
    readonly: Optional[list[str]] = None
    pin: Optional[str] = None


@dataclass
class TypeDecl(Node):
    name: str
    fields: list[tuple[str, TypeExpr]]
    doc: Optional[str] = None


@dataclass
class Variant(Node):
    name: str
    fields: list[tuple[str, TypeExpr]]  # empty = payload-free


@dataclass
class EnumDecl(Node):
    name: str
    variants: list[Variant]
    doc: Optional[str] = None


@dataclass
class FnDecl(Node):
    kind: str               # "fn" | "ai" | "agent"
    name: str
    params: list[Param]
    ret: Optional[TypeExpr]     # None = None type
    uses: list[str]
    body: Optional[Block]       # kind == "fn"
    prompt: Optional[StrLit]    # kind in ("ai", "agent")
    tools: list[str]            # kind == "agent"
    attrs: list[Attribute]
    doc: Optional[str] = None


@dataclass
class ConstDecl(Node):
    name: str
    type: Optional[TypeExpr]
    value: Expr


@dataclass
class TestDecl(Node):
    name: str
    body: Block


Item = Union[Allow, TypeDecl, EnumDecl, FnDecl, ConstDecl, TestDecl]


@dataclass
class Program(Node):
    items: list[Item]
    file: str = "<input>"
