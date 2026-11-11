"""Sipar parser: tokens -> ast.Program (recursive descent + precedence climbing)."""
from __future__ import annotations

from typing import Optional

from . import ast as A
from . import mcp_check as MC
from .errors import SiparSyntaxError
from .deep import call_deep
from .lexer import Lexer, Token

MAX_NESTING = 256        # ( [ { blocks, calls, types and patterns inside each other (E115, round 5 F1)
MAX_STR_NESTING = 16     # "{"{"..."}"}": each level re-lexes the rest, so the cost is levels x length (E115)
MAX_AST_DEPTH = 10_000   # longest chain in the tree, e.g. 1+1+...+1 or a.b.c...; walkers recurse that deep (E115)

CAPS = {"ai", "net", "fs.read", "fs.write", "shell", "env", "secret", "time", "random", "io", "memory", "mcp"}
COMPARE = {"==", "!=", "<", "<=", ">", ">=", "in"}


class Parser:
    def __init__(self, toks: list[Token], file: str = "<input>"):
        self.toks = toks
        self.i = 0
        self.file = file
        self.no_record = False      # True while parsing an if/while/for/match head: `X {` starts the block
        self.nesting = 0            # how many expr/type/pattern/block levels are open (MAX_NESTING)
        self.str_nesting = 0        # how many string interpolations this parser sits inside (MAX_STR_NESTING)

    def deeper(self, f):
        """Run f one nesting level deeper; past MAX_NESTING the program is rejected with E115 (round 5, F1)."""
        if self.nesting >= MAX_NESTING:
            raise self.err(f"nested too deeply (more than {MAX_NESTING} levels of brackets, blocks, calls, "
                           f"types or patterns)", code="E115",
                           hint="move inner parts into `let` names or small functions")
        self.nesting += 1
        try:
            return f()
        finally:
            self.nesting -= 1

    def head_expr(self) -> A.Expr:
        """Expression before a block (`if c {`): a Capitalized name followed by `{` is not a record literal."""
        old, self.no_record = self.no_record, True
        try:
            return self.expr()
        finally:
            self.no_record = old

    def nested(self, f):
        """Run f with record literals allowed again (inside ( ), [ ], { })."""
        old, self.no_record = self.no_record, False
        try:
            return f()
        finally:
            self.no_record = old

    # ------------------------------------------------------------ token helpers
    @property
    def tok(self) -> Token:
        return self.toks[self.i]

    def peek(self, k: int = 1) -> Token:
        j = min(self.i + k, len(self.toks) - 1)
        return self.toks[j]

    def at(self, *kinds: str) -> bool:
        return self.tok.kind in kinds

    def adv(self) -> Token:
        t = self.tok
        if t.kind != "eof":
            self.i += 1
        return t

    def err(self, msg: str, tok: Token | None = None, hint: str = "", code: str = "E110") -> SiparSyntaxError:
        t = tok or self.tok
        return SiparSyntaxError(code, msg, self.file, t.line, t.col, hint)

    def describe(self, t: Token) -> str:
        if t.kind == "newline":
            return "end of line"
        if t.kind == "eof":
            return "end of file"
        if t.kind == "str":
            return "string"
        if t.kind in ("int", "float", "ident"):
            return f"{t.kind} {t.value!r}"
        return repr(t.kind)

    def expect(self, kind: str, hint: str = "") -> Token:
        if self.tok.kind != kind:
            raise self.err(f"expected {kind!r}, found {self.describe(self.tok)}", hint=hint)
        return self.adv()

    def expect_ident(self, what: str = "name") -> Token:
        if self.tok.kind != "ident":
            extra = " (it is a keyword)" if self.tok.kind.isalpha() else ""
            raise self.err(f"expected {what}, found {self.describe(self.tok)}{extra}",
                           hint="names are letters, digits and _, starting with a letter or _"
                           + ("; rename it, keywords are reserved" if extra else ""))
        return self.adv()

    def skip_nl(self) -> None:
        while self.tok.kind in ("newline", ";"):
            self.adv()

    def end_stmt(self) -> None:
        if self.at("newline", ";"):
            self.skip_nl()
        elif self.at("}", "eof"):
            pass
        else:
            raise self.err(f"expected end of statement, found {self.describe(self.tok)}",
                           hint="put each statement on its own line or separate them with ';'")

    # ------------------------------------------------------------ program / items
    def parse_program(self) -> A.Program:
        items: list[A.Item] = []
        self.skip_nl()
        while not self.at("eof"):
            items.append(self.item())
            self.skip_nl()
        return A.Program(1, 1, items, self.file)

    def item(self) -> A.Item:
        t = self.tok
        doc = t.doc
        attrs: list[A.Attribute] = []
        while self.at("@"):
            at = self.adv()
            name = self.expect_ident("attribute name").value
            self.expect("(")
            vt = self.tok
            val = self.expr()
            if not isinstance(val, (A.IntLit, A.FloatLit, A.StrLit, A.BoolLit)) or (
                    isinstance(val, A.StrLit) and any(not isinstance(p, str) for p in val.parts)):
                raise self.err("attribute value must be a plain literal", vt, code="E111",
                               hint="write a number or a string, e.g. @max_steps(5) or @model(\"mock\")")
            self.expect(")")
            attrs.append(A.Attribute(at.line, at.col, name, val))
            self.skip_nl()
        if attrs:
            doc = doc or t.doc
        k = self.tok.kind
        if k == "allow":
            self._no_attrs(attrs)
            return self.allow()
        if k == "type":
            self._no_attrs(attrs)
            return self.type_decl(doc)
        if k == "enum":
            self._no_attrs(attrs)
            return self.enum_decl(doc)
        if k == "fn":
            if attrs:
                raise self.err("attributes are only allowed on 'ai fn' and 'agent fn'", attrs[0], code="E111",
                               hint="remove the attribute, or put it right before an `ai fn` or `agent fn`")
            return self.fn_decl("fn", attrs, doc)
        if k in ("ai", "agent"):
            kind = self.adv().kind
            if not self.at("fn"):
                raise self.err(f"expected 'fn' after '{kind}'", hint=f"write: {kind} fn name(...) -> Type {{ ... }}")
            return self.fn_decl(kind, attrs, doc, start=t)
        if k == "let":
            self._no_attrs(attrs)
            s = self.adv()
            name = self.expect_ident().value
            ty = None
            if self.at(":"):
                self.adv()
                ty = self.type_expr()
            self.expect("=")
            val = self.expr()
            self.end_stmt()
            return A.ConstDecl(s.line, s.col, name, ty, val)
        if k == "test":
            self._no_attrs(attrs)
            s = self.adv()
            if not self.at("str"):
                raise self.err("expected test name string", hint='test "name" { ... }')
            name = self.string_lit(self.adv())
            if any(not isinstance(p, str) for p in name.parts):
                raise self.err("test name cannot use interpolation", s)
            body = self.block()
            return A.TestDecl(s.line, s.col, "".join(name.parts), body)
        if k == "var":
            raise self.err("top-level 'var' is not allowed", hint="use 'let' for constants; mutable state lives in functions")
        raise self.err(f"expected an item (fn, ai fn, agent fn, type, enum, allow, let, test), found {self.describe(self.tok)}",
                       hint="statements must be inside a function, e.g. fn main() { ... }")

    def _no_attrs(self, attrs: list[A.Attribute]) -> None:
        if attrs:
            raise self.err("attributes are only allowed on 'ai fn' and 'agent fn'", attrs[0], code="E111",
                               hint="remove the attribute, or put it right before an `ai fn` or `agent fn`")

    def cap_name(self) -> str:
        t = self.tok
        if t.kind == "ai":
            self.adv()
            return "ai"
        name = self.expect_ident("capability").value
        if self.at(".") and self.peek().kind == "ident":
            self.adv()
            name += "." + self.adv().value
        if name not in CAPS:
            raise SiparSyntaxError("E112", f"unknown capability {name!r}", self.file, t.line, t.col,
                                   "capabilities: " + ", ".join(sorted(CAPS)))
        return name

    def allow(self) -> A.Allow:
        s = self.adv()
        cap = self.cap_name()
        if cap == "mcp":
            return MC.parse_allow(self, s)
        scopes = None
        if self.at("["):
            self.adv()
            scopes = []
            while not self.at("]"):
                if not self.at("str"):
                    raise self.err("allow scopes must be string literals", hint='allow net ["example.com"]')
                lit = self.string_lit(self.adv())
                if any(not isinstance(p, str) for p in lit.parts):
                    raise self.err("allow scopes cannot use interpolation")
                scopes.append("".join(lit.parts))
                if not self.at("]"):
                    self.expect(",")
            self.expect("]")
        self.end_stmt()
        return A.Allow(s.line, s.col, cap, scopes)

    def fields_block(self, what: str) -> list[tuple[str, A.TypeExpr]]:
        self.expect("{")
        self.skip_nl()
        fields: list[tuple[str, A.TypeExpr]] = []
        seen = set()
        while not self.at("}"):
            n = self.expect_ident(f"{what} name")
            if n.value in seen:
                raise self.err(f"duplicate {what} {n.value!r}", n, code="E201", hint=f"give each {what} its own name")
            seen.add(n.value)
            self.expect(":")
            fields.append((n.value, self.type_expr()))
            self.skip_nl()
            if not self.at("}"):
                self.expect(",")
                self.skip_nl()
        self.expect("}")
        return fields

    def type_decl(self, doc: Optional[str]) -> A.TypeDecl:
        s = self.adv()
        name = self.expect_ident("type name").value
        self.expect("=", hint="type Name = { field: Type, ... }")
        fields = self.fields_block("field")
        self.end_stmt()
        return A.TypeDecl(s.line, s.col, name, fields, doc)

    def enum_decl(self, doc: Optional[str]) -> A.EnumDecl:
        s = self.adv()
        name = self.expect_ident("enum name").value
        self.expect("{")
        self.skip_nl()
        variants: list[A.Variant] = []
        seen = set()
        while not self.at("}"):
            v = self.expect_ident("variant name")
            if v.value in seen:
                raise self.err(f"duplicate variant {v.value!r}", v, code="E201", hint="give each variant its own name")
            seen.add(v.value)
            fields: list[tuple[str, A.TypeExpr]] = []
            if self.at("("):
                self.adv()
                while not self.at(")"):
                    fn = self.expect_ident("field name").value
                    self.expect(":")
                    fields.append((fn, self.type_expr()))
                    if not self.at(")"):
                        self.expect(",")
                self.expect(")")
            variants.append(A.Variant(v.line, v.col, v.value, fields))
            self.skip_nl()
            if not self.at("}"):
                self.expect(",")
                self.skip_nl()
        self.expect("}")
        if not variants:
            raise self.err("enum needs at least one variant", s, code="E201", hint="enum Color { red, green }")
        self.end_stmt()
        return A.EnumDecl(s.line, s.col, name, variants, doc)

    def params(self, lambda_: bool = False) -> list[A.Param]:
        self.expect("(")
        ps: list[A.Param] = []
        seen = set()
        while not self.at(")"):
            n = self.expect_ident("parameter name")
            if n.value in seen:
                raise self.err(f"duplicate parameter {n.value!r}", n, code="E201", hint="give each parameter its own name")
            seen.add(n.value)
            ty = None
            if self.at(":"):
                self.adv()
                ty = self.type_expr()
            elif not lambda_:
                raise self.err(f"parameter {n.value!r} needs a type", n, hint=f"{n.value}: Str")
            ps.append(A.Param(n.line, n.col, n.value, ty))
            if not self.at(")"):
                self.expect(",")
        self.expect(")")
        return ps

    def fn_decl(self, kind: str, attrs: list[A.Attribute], doc: Optional[str], start: Token | None = None) -> A.FnDecl:
        s = start or self.tok
        self.expect("fn")
        name = self.expect_ident("function name").value
        ps = self.params()
        ret = None
        if self.at("->"):
            self.adv()
            ret = self.type_expr()
        elif kind != "fn":
            raise self.err(f"'{kind} fn' needs a return type", hint=f"{kind} fn {name}(...) -> Str {{ ... }}")
        uses: list[str] = []
        if self.at("uses"):
            self.adv()
            uses.append(self.cap_name())
            while self.at(","):
                self.adv()
                uses.append(self.cap_name())
        if kind == "fn":
            body = self.block()
            self.end_stmt()
            return A.FnDecl(s.line, s.col, "fn", name, ps, ret, uses, body, None, [], attrs, doc)
        self.expect("{")
        self.skip_nl()
        tools: list[str] = []
        if kind == "agent":
            if not self.at("tools"):
                raise self.err("agent fn body must start with 'tools [...]'", hint='tools [search, read_page]')
            self.adv()
            self.expect("[")
            while not self.at("]"):
                tools.append(MC.parse_tool(self, self.expect_ident("tool function name").value))
                if not self.at("]"):
                    self.expect(",")
            self.expect("]")
            self.skip_nl()
        if not self.at("str"):
            raise self.err(f"'{kind} fn' body must be a prompt string", hint='{ "Summarize: {text}" }')
        prompt = self.string_lit(self.adv())
        self.skip_nl()
        self.expect("}", hint=f"the body of '{kind} fn' contains only the prompt string")
        self.end_stmt()
        return A.FnDecl(s.line, s.col, kind, name, ps, ret, uses, None, prompt, tools, attrs, doc)

    # ------------------------------------------------------------ types
    def type_expr(self) -> A.TypeExpr:
        return self.deeper(self._type_expr)

    def _type_expr(self) -> A.TypeExpr:
        t = self.tok
        if self.at("fn"):
            self.adv()
            self.expect("(")
            ps = []
            while not self.at(")"):
                ps.append(self.type_expr())
                if not self.at(")"):
                    self.expect(",")
            self.expect(")")
            self.expect("->")
            ty: A.TypeExpr = A.TFn(t.line, t.col, ps, self.type_expr())
        elif self.at("("):          # parenthesised type, needed for optional fn types: (fn(Int) -> Int)?
            self.adv()
            ty = self.type_expr()
            self.expect(")")
        elif self.at("none"):
            self.adv()
            ty = A.TName(t.line, t.col, "None")
        else:
            name = self.expect_ident("type").value
            args = []
            if self.at("["):
                self.adv()
                while not self.at("]"):
                    args.append(self.type_expr())
                    if not self.at("]"):
                        self.expect(",")
                self.expect("]")
            ty = A.TName(t.line, t.col, name, args)
        if self.at("?"):
            q = self.adv()
            ty = A.TOptional(q.line, q.col, ty)
        return ty

    # ------------------------------------------------------------ blocks / statements
    def block(self) -> A.Block:
        return self.nested(self._block)

    def _block(self) -> A.Block:
        return self.deeper(self._block_body)

    def _block_body(self) -> A.Block:
        s = self.expect("{")
        self.skip_nl()
        stmts: list[A.Stmt] = []
        while not self.at("}"):
            if self.at("eof"):
                raise self.err("unclosed block: missing '}'", s, code="E104",
                               hint="add '}' to close the block opened here; check the braces above")
            stmts.append(self.stmt())
        self.expect("}")
        return A.Block(s.line, s.col, stmts)

    def stmt(self) -> A.Stmt:
        t = self.tok
        k = t.kind
        if k in ("let", "var"):
            self.adv()
            name = self.expect_ident().value
            ty = None
            if self.at(":"):
                self.adv()
                ty = self.type_expr()
            self.expect("=", hint=f"{k} {name} = value")
            val = self.expr()
            self.end_stmt()
            return A.Let(t.line, t.col, name, ty, val, k == "var")
        if k == "return":
            self.adv()
            val = None if self.at("newline", ";", "}") else self.expr()
            self.end_stmt()
            return A.Return(t.line, t.col, val)
        if k == "break":
            self.adv()
            self.end_stmt()
            return A.Break(t.line, t.col)
        if k == "continue":
            self.adv()
            self.end_stmt()
            return A.Continue(t.line, t.col)
        if k == "while":
            self.adv()
            cond = self.head_expr()
            body = self.block()
            self.end_stmt()
            return A.While(t.line, t.col, cond, body)
        if k == "for":
            self.adv()
            var = self.expect_ident("loop variable").value
            self.expect("in")
            it = self.head_expr()
            body = self.block()
            self.end_stmt()
            return A.For(t.line, t.col, var, it, body)
        if k == "assert":
            self.adv()
            cond = self.expr()
            msg = None
            if self.at(","):
                self.adv()
                msg = self.expr()
            self.end_stmt()
            return A.Assert(t.line, t.col, cond, msg)
        if k == "mock":
            self.adv()
            name = self.expect_ident("function name").value
            self.expect("(")
            ps = []
            while not self.at(")"):
                ps.append(self.expect_ident("parameter name").value)
                if not self.at(")"):
                    self.expect(",")
            self.expect(")")
            self.expect("=>")
            body = self.expr()
            self.end_stmt()
            return A.Mock(t.line, t.col, name, ps, body)
        if k in ("fn", "type", "enum", "allow", "test") and not (k == "fn" and self.peek().kind == "("):
            raise self.err(f"'{k}' declarations are only allowed at top level")
        e = self.expr()
        if self.at("="):
            eq = self.adv()
            if not isinstance(e, (A.Name, A.Field, A.Index)):
                raise self.err("cannot assign to this expression", eq, code="E113",
                               hint="assign to a variable, a field (p.x = 1) or an element (xs[0] = 1)")
            val = self.expr()
            self.end_stmt()
            return A.Assign(t.line, t.col, e, val)
        self.end_stmt()
        return A.ExprStmt(t.line, t.col, e)

    # ------------------------------------------------------------ expressions
    def expr(self) -> A.Expr:
        return self.deeper(self.coalesce)

    def coalesce(self) -> A.Expr:
        parts = [self.or_()]
        ops = []
        while self.at("??"):            # a loop, not recursion: a ?? b ?? ... of any length parses (F1)
            ops.append(self.adv())
            parts.append(self.or_())
        e = parts.pop()
        while ops:                      # right associative: a ?? (b ?? c)
            op = ops.pop()
            e = A.Binary(op.line, op.col, "??", parts.pop(), e)
        return e

    def or_(self) -> A.Expr:
        left = self.and_()
        while self.at("or"):
            op = self.adv()
            left = A.Binary(op.line, op.col, "or", left, self.and_())
        return left

    def and_(self) -> A.Expr:
        left = self.not_()
        while self.at("and"):
            op = self.adv()
            left = A.Binary(op.line, op.col, "and", left, self.not_())
        return left

    def not_(self) -> A.Expr:
        ops = []
        while self.at("not"):           # a loop, not recursion (F1)
            ops.append(self.adv())
        e = self.compare()
        while ops:
            op = ops.pop()
            e = A.Unary(op.line, op.col, "not", e)
        return e

    def compare(self) -> A.Expr:
        left = self.range_()
        if self.tok.kind in COMPARE:
            op = self.adv()
            left = A.Binary(op.line, op.col, op.kind, left, self.range_())
            if self.tok.kind in COMPARE:
                raise self.err("comparisons cannot be chained", hint="use 'and': a < b and b < c")
        return left

    def range_(self) -> A.Expr:
        left = self.additive()
        if self.at(".."):
            op = self.adv()
            left = A.Binary(op.line, op.col, "..", left, self.additive())
        return left

    def additive(self) -> A.Expr:
        left = self.mult()
        while self.at("+", "-"):
            op = self.adv()
            left = A.Binary(op.line, op.col, op.kind, left, self.mult())
        return left

    def mult(self) -> A.Expr:
        left = self.unary()
        while self.at("*", "/", "%"):
            op = self.adv()
            left = A.Binary(op.line, op.col, op.kind, left, self.unary())
        return left

    def unary(self) -> A.Expr:
        ops = []
        while self.at("-"):             # a loop, not recursion (F1)
            ops.append(self.adv())
        operand = self.cast()
        while ops:
            op = ops.pop()
            if isinstance(operand, A.IntLit):
                operand = A.IntLit(op.line, op.col, -operand.value)
            elif isinstance(operand, A.FloatLit):
                operand = A.FloatLit(op.line, op.col, -operand.value)
            else:
                operand = A.Unary(op.line, op.col, "-", operand)
        return operand

    def cast(self) -> A.Expr:
        e = self.postfix()
        while self.at("as"):
            op = self.adv()
            e = A.As(op.line, op.col, e, self.type_expr())
        return e

    def args(self) -> list[A.Arg]:
        self.expect("(")
        out: list[A.Arg] = []
        named = False
        while not self.at(")"):
            t = self.tok
            if t.kind == "ident" and self.peek().kind == ":":
                self.adv()
                self.adv()
                out.append(A.Arg(t.line, t.col, t.value, self.expr()))
                named = True
            else:
                if named:
                    raise self.err("positional argument after a named one", code="E114",
                                   hint="put positional arguments first: f(1, name: 2)")
                out.append(A.Arg(t.line, t.col, None, self.expr()))
            if not self.at(")"):
                self.expect(",", hint="separate arguments with ','")
        self.expect(")")
        names = [a.name for a in out if a.name]
        if len(names) != len(set(names)):
            raise self.err("duplicate named argument", code="E114", hint="pass each named argument once")
        return out

    def postfix(self) -> A.Expr:
        e = self.primary()
        while True:
            if self.at("("):
                t = self.tok
                e = A.Call(t.line, t.col, e, self.nested(self.args))
            elif self.at("["):
                t = self.adv()
                idx = self.nested(self.expr)
                self.expect("]")
                e = A.Index(t.line, t.col, e, idx)
            elif self.at("."):
                t = self.adv()
                name = self.tok
                if name.kind == "ident" or (name.kind.isalpha() and name.kind not in ("eof", "newline", "str", "int", "float")):
                    self.adv()
                    e = A.Field(t.line, t.col, e, str(name.value))
                else:
                    raise self.err(f"expected a field or method name after '.', found {self.describe(name)}")
            else:
                return e

    def looks_like_record(self) -> bool:
        """At '{' after a Capitalized name: record literal iff '{ }' or '{ ident :'."""
        j = self.i + 1
        while self.toks[j].kind == "newline":
            j += 1
        if self.toks[j].kind == "}":
            return True
        return self.toks[j].kind == "ident" and self.toks[j + 1].kind == ":"

    def primary(self) -> A.Expr:
        t = self.tok
        k = t.kind
        if k == "int":
            self.adv()
            return A.IntLit(t.line, t.col, t.value)
        if k == "float":
            self.adv()
            return A.FloatLit(t.line, t.col, t.value)
        if k in ("true", "false"):
            self.adv()
            return A.BoolLit(t.line, t.col, k == "true")
        if k == "none":
            self.adv()
            return A.NoneLit(t.line, t.col)
        if k == "str":
            self.adv()
            return self.string_lit(t)
        if k == "ident":
            self.adv()
            if self.at("{") and t.value[:1].isupper() and not self.no_record and self.looks_like_record():
                return self.record_lit(t)
            return A.Name(t.line, t.col, t.value)
        if k == "(":
            self.adv()
            e = self.nested(self.expr)
            self.expect(")")
            return e
        if k == "[":
            return self.nested(self.list_or_map)
        if k == "fn":
            return self.lambda_()
        if k == "{":
            return self.nested(self.block)
        if k == "if":
            return self.if_()
        if k == "match":
            return self.match()
        if k == "try":
            self.adv()
            body = self.block()
            self.skip_nl_before("catch")
            self.expect("catch", hint="try { ... } catch e { ... }")
            name = self.expect_ident("error variable").value
            handler = self.block()
            return A.Try(t.line, t.col, body, name, handler)
        if k == "budget":
            self.adv()
            args = self.args()
            for a in args:
                if a.name is None:
                    raise self.err("budget limits must be named", hint="budget(ai_calls: 5, seconds: 30) { ... }")
            body = self.block()
            return A.Budget(t.line, t.col, args, body)
        raise self.err(f"expected an expression, found {self.describe(t)}")

    def skip_nl_before(self, kind: str) -> None:
        j = self.i
        while self.toks[j].kind == "newline":
            j += 1
        if self.toks[j].kind == kind:
            self.i = j

    def record_lit(self, name_tok: Token) -> A.RecordLit:
        self.expect("{")
        self.skip_nl()
        fields: list[tuple[str, A.Expr]] = []
        seen = set()
        while not self.at("}"):
            f = self.expect_ident("field name")
            if f.value in seen:
                raise self.err(f"duplicate field {f.value!r}", f, code="E201", hint="set each field once")
            seen.add(f.value)
            self.expect(":")
            fields.append((f.value, self.expr()))
            self.skip_nl()
            if not self.at("}"):
                self.expect(",")
                self.skip_nl()
        self.expect("}")
        return A.RecordLit(name_tok.line, name_tok.col, name_tok.value, fields)

    def list_or_map(self) -> A.Expr:
        s = self.expect("[")
        if self.at(":"):
            self.adv()
            self.expect("]")
            return A.MapLit(s.line, s.col, [])
        if self.at("]"):
            self.adv()
            return A.ListLit(s.line, s.col, [])
        first = self.expr()
        if self.at(":"):
            self.adv()
            entries = [(first, self.expr())]
            while self.at(","):
                self.adv()
                if self.at("]"):
                    break
                k = self.expr()
                self.expect(":")
                entries.append((k, self.expr()))
            self.expect("]")
            return A.MapLit(s.line, s.col, entries)
        items = [first]
        while self.at(","):
            self.adv()
            if self.at("]"):
                break
            items.append(self.expr())
        self.expect("]")
        return A.ListLit(s.line, s.col, items)

    def lambda_(self) -> A.Lambda:
        s = self.expect("fn")
        ps = self.params(lambda_=True)
        ret = None
        if self.at("->"):
            self.adv()
            ret = self.type_expr()
        self.expect("=>", hint="fn(x: Int) => x * 2")
        body = self.expr()
        return A.Lambda(s.line, s.col, ps, ret, body)

    def if_(self) -> A.If:
        s = self.expect("if")
        cond = self.head_expr()
        then = self.block()
        else_ = None
        self.skip_nl_before("else")
        if self.at("else"):
            self.adv()
            else_ = self.if_() if self.at("if") else self.block()
        return A.If(s.line, s.col, cond, then, else_)

    def match(self) -> A.Match:
        s = self.expect("match")
        subj = self.head_expr()
        self.expect("{")
        self.skip_nl()
        arms: list[A.MatchArm] = []
        while not self.at("}"):
            pt = self.tok
            pat = self.pattern()
            self.expect("=>", hint="pattern => value")
            body = self.expr()
            arms.append(A.MatchArm(pt.line, pt.col, pat, body))
            if self.at(","):
                self.adv()
            elif not self.at("}", "newline", ";"):
                raise self.err(f"expected ',' or a new line between match arms, found {self.describe(self.tok)}")
            self.skip_nl()
        self.expect("}")
        if not arms:
            raise self.err("match needs at least one arm", s, code="E401")
        return A.Match(s.line, s.col, subj, arms)

    def pattern(self) -> A.Pattern:
        return self.deeper(self._pattern)

    def _pattern(self) -> A.Pattern:
        t = self.tok
        if t.kind == "ident" and t.value == "_":
            self.adv()
            return A.PWild(t.line, t.col)
        if t.kind in ("int", "float", "true", "false", "none", "-"):
            e = self.unary()
            if not isinstance(e, (A.IntLit, A.FloatLit, A.BoolLit, A.NoneLit)):
                raise self.err("invalid pattern", t)
            return A.PLit(t.line, t.col, e)
        if t.kind == "str":
            lit = self.string_lit(self.adv())
            if any(not isinstance(p, str) for p in lit.parts):
                raise self.err("string patterns cannot use interpolation", t)
            return A.PLit(t.line, t.col, lit)
        if t.kind == "ident":
            self.adv()
            if self.at("."):
                self.adv()
                v = self.expect_ident("variant name").value
                args = None
                if self.at("("):
                    self.adv()
                    args = []
                    while not self.at(")"):
                        args.append(self.pattern())
                        if not self.at(")"):
                            self.expect(",")
                    self.expect(")")
                return A.PVariant(t.line, t.col, t.value, v, args)
            return A.PBind(t.line, t.col, t.value)
        raise self.err(f"expected a pattern, found {self.describe(t)}",
                       hint="patterns: _, literal, none, name, Enum.variant, Enum.variant(a, b)")

    # ------------------------------------------------------------ strings
    def string_lit(self, t: Token) -> A.StrLit:
        parts: list = []
        for p in t.value:
            if p[0] == "text":
                parts.append(p[1])
            else:
                _, src, line, col = p
                if self.str_nesting >= MAX_STR_NESTING:
                    raise self.err(f"strings nested too deeply inside interpolations (more than {MAX_STR_NESTING} "
                                   "levels)", t, code="E115", hint="build the inner text with `let` first")
                sub = Lexer(src, self.file, line, col).tokenize()
                sp = Parser(sub, self.file)
                sp.nesting = self.nesting       # "{"{"{...}"}"}" nests too
                sp.str_nesting = self.str_nesting + 1
                sp.skip_nl()
                e = sp.expr()
                sp.skip_nl()
                if not sp.at("eof"):
                    raise sp.err(f"unexpected {sp.describe(sp.tok)} in string interpolation", code="E103")
                parts.append(e)
        return A.StrLit(t.line, t.col, parts)


def parse(src: str, file: str = "<input>") -> A.Program:
    """Source text -> Program, or SiparSyntaxError. Runs on a big-stack thread (sipar.deep): every program it
    accepts is within MAX_NESTING and MAX_AST_DEPTH, so the checker and interpreter can walk it (round 5, F1)."""
    return call_deep(_parse, src, file)


def _parse(src: str, file: str) -> A.Program:
    try:
        toks = Lexer(src, file).tokenize()
        program = Parser(toks, file).parse_program()
    except RecursionError:              # a path the limits above do not cover: still a syntax error, never a crash
        raise SiparSyntaxError("E115", "program nested too deeply to parse", file, 1, 1,
                               "move inner parts into `let` names or small functions")
    deep = deepest(program, MAX_AST_DEPTH)
    if deep is not None:
        raise SiparSyntaxError("E115", f"expression nested too deeply (a chain longer than {MAX_AST_DEPTH} "
                                       f"levels, e.g. a very long a + b + ...)", file, deep.line, deep.col,
                               "split it into several `let` steps")
    return program


def deepest(root: A.Node, limit: int) -> Optional[A.Node]:
    """The first node found deeper than `limit` levels below root, else None. Iterative: never recurses."""
    stack: list = [(root, 1)]
    while stack:
        obj, d = stack.pop()
        if isinstance(obj, A.Node):
            if d > limit:
                return obj
            for v in vars(obj).values():
                if isinstance(v, (A.Node, list, tuple)):
                    stack.append((v, d + 1))
        else:                           # list / tuple of children: they sit one level below the node holding it
            for v in obj:
                if isinstance(v, (A.Node, list, tuple)):
                    stack.append((v, d))
    return None
