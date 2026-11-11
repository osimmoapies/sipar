"""Sipar language server: LSP 3.17 over stdio, Python standard library only.  Run it with `sipar lsp`.

Layout (top to bottom):
  positions   1-based Sipar columns (code points) <-> 0-based LSP UTF-16 offsets
  transport   Content-Length framed JSON-RPC on binary streams
  Analysis    one checked snapshot of a document: diagnostics, expression types, bindings and scopes
  features    diagnostics, hover, definition, completion, documentSymbol — each one a function
              registered with @feature(method, capability); the initialize reply is built from the registry
  Server      lifecycle (initialize / shutdown / exit), dispatch, error isolation

Adding a feature (for example a formatter, once one exists) is one function:

    @feature("textDocument/formatting", "documentFormattingProvider")
    def formatting(server, params): ...   # return a list of TextEdit

The checker is used read-only: a subclass records the type of every expression it checks and every name it
declares; the diagnostics themselves come from `check_source`, unchanged.  A crash in any handler is logged
to stderr and answered with an error response; it never stops the server.
"""
from __future__ import annotations

import bisect
import dataclasses
import json
import re
import sys
import traceback
from dataclasses import dataclass
from typing import Any, Callable, Optional
from urllib.parse import unquote, urlparse

from . import __version__
from . import ast as A
from .errors import SiparSyntaxError
from .lexer import KEYWORDS, Lexer, normalize_newlines
from .stdlib import AGENT_ATTRS, AI_ATTRS, ATTRIBUTES, BUILTIN_TYPES, FUNCTIONS, METHODS, MODULES

try:                                    # the capability list lives in the parser
    from .parser import CAPS
except ImportError:                     # pragma: no cover
    CAPS = {"ai", "net", "fs.read", "fs.write", "shell", "env", "secret", "time", "random", "io", "memory"}

# JSON-RPC / LSP error codes
PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL_ERROR = -32700, -32600, -32601, -32602, -32603
SERVER_NOT_INITIALIZED = -32002

# LSP enums used here
SEV = {"error": 1, "warning": 2, "info": 3, "hint": 4}
CK = {"method": 2, "function": 3, "field": 5, "variable": 6, "class": 7, "module": 9, "keyword": 14,
      "enum_member": 20, "constant": 21, "struct": 22, "enum": 13, "type_param": 25}
SK = {"method": 6, "field": 8, "enum": 10, "function": 12, "constant": 14, "enum_member": 22, "struct": 23}

GLOBAL_FUNCS = sorted(k for k in FUNCTIONS if "." not in k)
BUILTIN_TYPE_DOCS = {
    "Int": "Whole number. Widens to Float implicitly.", "Float": "Finite floating-point number.",
    "Str": "Text.", "Bool": "true or false.", "None": "The type of `none`; `T?` is T or none.",
    "List": "List[T]: an ordered list.", "Map": "Map[T]: a map from Str keys to T.",
    "Error": "Error { kind: Str, message: Str } — the value bound by `catch e`.",
}
PLACEHOLDER = "__sipar_lsp_complete__"
EOF_POS = (10 ** 9, 1)


def log(err, msg: str) -> None:
    try:
        err.write(f"sipar lsp: {msg}\n")
        err.flush()
    except Exception:  # noqa: BLE001 — a broken log stream must not stop the server
        pass


# ====================================================================== positions
# Sipar: line 1-based, column 1-based in code points (the lexer counts one per Python character; CRLF is one
# line break).  LSP: line 0-based, character 0-based in UTF-16 code units.

def utf16_len(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def cp_to_utf16(text: str, cp: int) -> int:
    return utf16_len(text[:max(0, min(cp, len(text)))])


def utf16_to_cp(text: str, u: int) -> int:
    """UTF-16 offset -> code point index.  An offset inside a surrogate pair snaps to the start of the
    character; an offset past the end clamps to the end of the line."""
    n = 0
    for i, ch in enumerate(text):
        n += 2 if ord(ch) > 0xFFFF else 1
        if n > u:
            return i
    return len(text)


def split_lines(text: str) -> list[str]:
    return normalize_newlines(text).split("\n")


def is_word(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


CODE, TEXT, COMMENT, OPEN, CLOSE, INTERP = 0, 1, 2, 3, 4, 5


def text_mask(lines: list[str]) -> list[list[int]]:
    """Per character: CODE, TEXT (inside a string literal), COMMENT, OPEN / CLOSE (a string's quotes),
    INTERP (the `{` that opens an interpolation).
    Code inside `{...}` interpolation is CODE.  Mirrors the lexer's rules: `\\` escapes, `"..."` ends at the
    line, `\"\"\"...\"\"\"` spans lines, interpolation braces nest."""
    out = [[CODE] * len(l) for l in lines]
    stack: list = []            # entries: ["str", triple] or ["code", depth]
    for ln, text in enumerate(lines):
        row = out[ln]
        i, n = 0, len(text)
        while i < n:
            top = stack[-1] if stack else None
            if top is None or top[0] == "code":
                ch = text[i]
                if text.startswith("//", i):
                    for k in range(i, n):
                        row[k] = COMMENT
                    break
                if ch == '"':
                    triple = text.startswith('"""', i)
                    w = 3 if triple else 1
                    for k in range(i, i + w):
                        row[k] = OPEN
                    stack.append(["str", triple])
                    i += w
                    continue
                if top is not None:
                    if ch == "{":
                        top[1] += 1
                    elif ch == "}":
                        if top[1] == 0:
                            stack.pop()
                            row[i] = TEXT
                        else:
                            top[1] -= 1
                i += 1
                continue
            ch = text[i]
            if ch == "\\":
                row[i] = TEXT
                if i + 1 < n:
                    row[i + 1] = TEXT
                i += 2
                continue
            if ch == '"' and (not top[1] or text.startswith('"""', i)):
                w = 3 if top[1] else 1
                for k in range(i, min(i + w, n)):
                    row[k] = CLOSE
                stack.pop()
                i += w
                continue
            row[i] = TEXT
            if ch == "{":
                row[i] = INTERP
                stack.append(["code", 0])
            i += 1
        k = next((k for k, entry in enumerate(stack) if entry == ["str", False]), None)
        if k is not None:
            del stack[k:]           # a "..." string ends at the line, with any interpolation it left open
    return out


# ====================================================================== transport

MAX_BODY = 64 * 1024 * 1024         # a bigger frame is read past in chunks and skipped (F5, round 6)
MAX_HEADER_LINE = 64 * 1024
_CHUNK = 1024 * 1024


class Skipped(bytes):
    """An empty body (b"") that says why the frame was skipped; handle_bytes logs the reason."""
    reason = "skipped a message without a valid Content-Length header"


class _TooLarge(Skipped):
    reason = f"skipped a message larger than {MAX_BODY} bytes"


def read_message(inp) -> Optional[bytes]:
    """Read one framed message body.  None at end of input.  A header block without a usable
    Content-Length (ASCII digits only), or with a body over MAX_BODY, gives an empty Skipped body.
    "Content-Length: 0" gives a plain b"": an empty body, which handle_bytes answers as a parse error."""
    length: Optional[int] = None
    seen = False
    while True:
        line = inp.readline(MAX_HEADER_LINE)
        if not line:
            return None
        if len(line) >= MAX_HEADER_LINE and not line.endswith(b"\n"):
            while line and not line.endswith(b"\n"):    # an endless header line: read past it, in chunks
                line = inp.readline(MAX_HEADER_LINE)
            if not line:
                return None
            seen = True                 # ignored, like any header we do not know
            continue
        line = line.strip()
        if not line:
            if not seen:
                continue                # stray blank line between messages
            break
        seen = True
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            value = value.strip()
            if not value.isdigit():     # "+2", "1_7", " 1 2", "١٢" are not lengths
                length = -1
            else:                       # the value counts, not the digits: "0000000000054" is 54 (round 7)
                value = value.lstrip(b"0") or b"0"
                length = MAX_BODY + 1 if len(value) > 12 else int(value)    # int() of 5000 digits fails
    if length is None or length < 0:
        return Skipped()
    if length > MAX_BODY:
        left = length
        while left > 0:
            got = inp.read(min(left, _CHUNK))
            if not got:
                return None
            left -= len(got)
        return _TooLarge()
    body = inp.read(length)
    if body is None or len(body) < length:
        return None
    return body


def frame(obj: dict) -> bytes:
    body = json.dumps(obj, ensure_ascii=False, allow_nan=False).encode("utf-8", "surrogatepass")
    return b"Content-Length: %d\r\n\r\n" % len(body) + body


# ====================================================================== analysis

@dataclass
class Binding:
    name: str
    kind: str                       # fn type enum variant field const let var param loop bind catch
    pos: tuple                      # (line, col) of the name
    node: Any
    scope: Optional[tuple] = None   # (start, end) positions for local names; None = the whole file
    owner: str = ""                 # record / enum name for fields and variants


def _recorder_class():
    """A Checker subclass that remembers types; built lazily so a broken checker import degrades features."""
    from .checker import Checker

    class Recorder(Checker):
        def __init__(self, program):
            super().__init__(program)
            self.lsp_types: dict = {}       # id(expr) -> (expr, Ty)
            self.lsp_decls: dict = {}       # (id(node), name) -> Ty

        def expr(self, e, exp=None, used=True):
            t = super().expr(e, exp, used)
            self.lsp_types[id(e)] = (e, t)
            return t

        def declare(self, name, ty, kind, node):
            super().declare(name, ty, kind, node)
            self.lsp_decls[(id(node), name)] = ty

    return Recorder


class Analysis:
    def __init__(self, text: str, path: str, err=sys.stderr):
        self.text = text
        self.path = path
        self.lines = split_lines(text)
        self.program: Optional[A.Program] = None
        self.diags: list = []
        self.crash: Optional[str] = None
        self.checker = None
        self.types: dict = {}
        self.decl_types: dict = {}
        self.bindings: list[Binding] = []
        self.decl_at: dict = {}
        self.fields: dict = {}
        self.nodes_at: dict = {}
        self.toks: list = []
        self.tok_pos: list = []
        self.brackets: dict = {}
        self.limit = EOF_POS            # start of the next statement while one is walked (bounds lambdas)
        self.refs: dict = {}            # pos -> ("rec", type, field) | ("arg", Call, name): names that are not Name nodes
        self.mask = text_mask(self.lines)
        try:
            from .checker import check_source
            self.program, self.diags = check_source(text, path)
        except Exception as e:  # noqa: BLE001
            self.crash = f"{type(e).__name__}: {e}"
            log(err, f"checker crashed on {path}: {self.crash}\n{traceback.format_exc()}")
            try:
                from .parser import parse
                self.program = parse(text, path)
            except Exception:  # noqa: BLE001
                self.program = None
        if self.program is None:
            return
        for step in (self._scan_tokens, self._record, self._walk):
            try:
                step()
            except Exception:  # noqa: BLE001
                log(err, f"analysis step {step.__name__} failed on {path}:\n{traceback.format_exc()}")

    @property
    def ok(self) -> bool:
        return self.program is not None

    def line_text(self, line: int) -> str:
        return self.lines[line - 1] if 1 <= line <= len(self.lines) else ""

    # ------------------------------------------------------------ positions
    def lsp_pos(self, pos: tuple) -> dict:
        line, col = pos
        if line > len(self.lines):
            line = len(self.lines)
            col = len(self.lines[-1]) + 1
        line = max(line, 1)
        text = self.line_text(line)
        return {"line": line - 1, "character": cp_to_utf16(text, col - 1)}

    def lsp_range(self, start: tuple, end: tuple) -> dict:
        return {"start": self.lsp_pos(start), "end": self.lsp_pos(end)}

    def name_range(self, pos: tuple, name: str) -> dict:
        return self.lsp_range(pos, (pos[0], pos[1] + len(name)))

    def sipar_pos(self, p: dict) -> tuple:
        line = pos_int(p, "line") + 1
        text = self.line_text(line)
        return line, utf16_to_cp(text, pos_int(p, "character")) + 1

    # ------------------------------------------------------------ tokens
    def _scan_tokens(self) -> None:
        def scan(toks):
            stack = []
            for t in toks:
                if t.kind in ("newline", "eof"):
                    continue
                self.toks.append(t)
                if t.kind in ("(", "[", "{"):
                    stack.append(t)
                elif t.kind in (")", "]", "}") and stack:
                    o = stack.pop()
                    self.brackets[(o.line, o.col)] = (t.line, t.col)
                if t.kind == "str":
                    for part in t.value:
                        if part[0] == "expr":
                            try:
                                scan(Lexer(part[1], self.path, part[2], part[3]).tokenize())
                            except SiparSyntaxError:
                                pass
        scan(Lexer(self.text, self.path).tokenize())
        self.toks.sort(key=lambda t: (t.line, t.col))
        self.tok_pos = [(t.line, t.col) for t in self.toks]

    def tok_after(self, pos: tuple, kind: str, value: Any = None, strict: bool = False):
        i = bisect.bisect_right(self.tok_pos, pos) if strict else bisect.bisect_left(self.tok_pos, pos)
        for t in self.toks[i:]:
            if t.kind == kind and (value is None or t.value == value):
                return t
        return None

    def record_keys(self, pos: tuple) -> dict:
        """name -> position of each `name :` key at the top level of the record literal whose `{` is
        the first one at or after pos.  Keys of nested records, calls and lambdas are skipped."""
        keys: dict = {}
        o = self.tok_after(pos, "{")
        if o is None:
            return keys
        end = self.brackets.get((o.line, o.col), EOF_POS)
        i = bisect.bisect_right(self.tok_pos, (o.line, o.col))
        while i < len(self.toks) - 1 and self.tok_pos[i] < end:
            t = self.toks[i]
            if t.kind == "ident" and self.toks[i + 1].kind == ":":
                keys[t.value] = self.tok_pos[i]
            close = self.brackets.get(self.tok_pos[i])         # skip a nested bracket pair whole
            i = i + 1 if close is None else bisect.bisect_right(self.tok_pos, close)
        return keys

    def name_after(self, pos: tuple, name: str) -> tuple:
        """Position of the first `name` identifier strictly after pos (a declaration keyword or the
        previous name), or pos itself when there is none."""
        t = self.tok_after(pos, "ident", name, True)
        return (t.line, t.col) if t else pos

    def enclosing_close(self, pos: tuple) -> tuple:
        best = None
        for o, c in self.brackets.items():
            if o < pos < c and (best is None or o > best[0]):
                best = (o, c)
        return best[1] if best else EOF_POS

    def lambda_end(self, start: tuple) -> tuple:
        """End of an expression-bodied lambda: the first `,` or unmatched closing bracket after its `=>`,
        or the start of the next statement."""
        arrow = self.tok_after(start, "=>")
        if arrow is None:
            return min(self.enclosing_close(start), self.limit)
        depth = 0
        for t in self.toks[bisect.bisect_right(self.tok_pos, (arrow.line, arrow.col)):]:
            p = (t.line, t.col)
            if p >= self.limit:
                break
            if t.kind in ("(", "[", "{"):
                depth += 1
            elif t.kind in (")", "]", "}"):
                if depth == 0:
                    return p
                depth -= 1
            elif t.kind == "," and depth == 0:
                return p
        return self.limit

    # ------------------------------------------------------------ checker types
    def _record(self) -> None:
        rec = _recorder_class()(self.program)
        rec.run()
        self.checker = rec
        self.types = {k: t for k, (_, t) in rec.lsp_types.items()}
        self.decl_types = rec.lsp_decls
        for e, _ in rec.lsp_types.values():
            self.nodes_at.setdefault((e.line, e.col), []).append(e)

    def type_of(self, node) -> Optional[str]:
        t = self.types.get(id(node))
        return None if t is None or str(t) == "Unknown" else str(t)

    def binding_type(self, b: Binding) -> Optional[str]:
        if b.kind == "const" and self.checker is not None:
            v = self.checker.consts.get(b.name)
            t = v.ty if v else None
        elif b.kind in ("let", "var", "param", "loop", "bind", "catch"):
            t = self.decl_types.get((id(b.node), b.name))
            if t is None and isinstance(b.node, A.Param) and b.node.type is not None:
                return texpr(b.node.type)
        elif b.kind == "field" and self.checker is not None:
            t = self.checker.records.get(b.owner, {}).get(b.name)
            if t is None and isinstance(b.node, tuple):
                return texpr(b.node[1])
        else:
            return None
        return None if t is None or str(t) == "Unknown" else str(t)

    # ------------------------------------------------------------ bindings and scopes
    def _add(self, b: Binding) -> None:
        self.bindings.append(b)
        self.decl_at.setdefault(b.pos, b)

    def _walk(self) -> None:
        # type expressions and attribute literals hold no names, so only expressions and blocks are visited
        items = self.program.items
        starts = [(it.line, it.col) for it in items[1:]] + [EOF_POS]
        for it, nxt in zip(items, starts):
            self.limit = nxt
            if isinstance(it, A.FnDecl):
                self._walk_fn(it)
            elif isinstance(it, A.TypeDecl):
                npos = self.name_after((it.line, it.col), it.name)
                self._add(Binding(it.name, "type", npos, it))
                after = npos
                for fname, te in it.fields:
                    after = self.name_after(after, fname)
                    self._add(Binding(fname, "field", after, (fname, te), owner=it.name))
            elif isinstance(it, A.EnumDecl):
                self._add(Binding(it.name, "enum", self.name_after((it.line, it.col), it.name), it))
                for v in it.variants:
                    self._add(Binding(v.name, "variant", (v.line, v.col), v, owner=it.name))
                    after = (v.line, v.col)
                    for fname, te in v.fields:
                        after = self.name_after(after, fname)
                        self._add(Binding(fname, "field", after, (fname, te), owner=f"{it.name}.{v.name}"))
            elif isinstance(it, A.ConstDecl):
                self._add(Binding(it.name, "const", self.name_after((it.line, it.col), it.name), it))
                self._visit(it.value)
            elif isinstance(it, A.TestDecl):
                self._block(it.body)

    def _walk_fn(self, d: A.FnDecl) -> None:
        npos = self.name_after((d.line, d.col), d.name)
        self._add(Binding(d.name, "fn", npos, d))
        brace = self.tok_after(npos, "{")
        end = self.brackets.get((brace.line, brace.col), EOF_POS) if brace else EOF_POS
        for p in d.params:
            self._add(Binding(p.name, "param", (p.line, p.col), p, (npos, end)))
        if d.body is not None:
            self._block(d.body)
        self._visit(d.prompt)                       # None when there is no prompt

    def _block(self, b: A.Block) -> None:
        end = self.brackets.get((b.line, b.col), EOF_POS)
        stmts = b.stmts
        starts = [(s.line, s.col) for s in stmts[1:]] + [end]
        for s, nxt in zip(stmts, starts):
            outer, self.limit = self.limit, min(nxt, self.limit)
            try:
                self._stmt(s, nxt, end)
            finally:
                self.limit = outer

    def _stmt(self, s, nxt: tuple, end: tuple) -> None:
        if isinstance(s, A.Let):
            self._visit(s.value)
            pos = self.name_after((s.line, s.col), s.name)
            self._add(Binding(s.name, "var" if s.mutable else "let", pos, s, (nxt, end)))
        elif isinstance(s, A.For):
            self._visit(s.iter)
            body = (s.body.line, s.body.col)
            self._add(Binding(s.var, "loop", self.name_after((s.line, s.col), s.var), s,
                              (body, self.brackets.get(body, end))))
            self._block(s.body)
        elif isinstance(s, A.Mock):
            after = self.name_after((s.line, s.col), s.fn_name)
            for m in s.params:
                after = self.name_after(after, m)
                self._add(Binding(m, "param", after, s, (after, nxt)))
            self._visit(s.body)
        else:
            self._visit(s)

    def _visit(self, n) -> None:
        if isinstance(n, (list, tuple)):
            for x in n:
                self._visit(x)
        if not isinstance(n, A.Node):
            return
        if isinstance(n, A.Block):
            self._block(n)
            return
        if isinstance(n, A.Field):
            self.fields[(n.line, n.col)] = n
        if isinstance(n, A.Call):
            for arg in n.args:
                if arg.name is not None:
                    self.refs[(arg.line, arg.col)] = ("arg", n, arg.name)
        if isinstance(n, A.RecordLit):
            keys = self.record_keys((n.line, n.col))
            for fname, kpos in keys.items():
                self.refs[kpos] = ("rec", n.type_name, fname)
        if isinstance(n, A.Lambda):
            start = (n.line, n.col)
            if isinstance(n.body, A.Block):
                end = self.brackets.get((n.body.line, n.body.col), EOF_POS)
            else:
                end = self.lambda_end(start)
            for p in n.params:
                self._add(Binding(p.name, "param", (p.line, p.col), p, (start, end)))
            self._visit(n.body)
            return
        if isinstance(n, A.Try):
            self._block(n.body)
            body_end = self.brackets.get((n.body.line, n.body.col), (n.line, n.col))
            h = (n.handler.line, n.handler.col)
            self._add(Binding(n.err_name, "catch", self.name_after(body_end, n.err_name), n,
                              (h, self.brackets.get(h, EOF_POS))))
            self._block(n.handler)
            return
        if isinstance(n, A.Match):
            self._visit(n.subject)
            starts = [(x.line, x.col) for x in n.arms[1:]] + [None]
            for arm, nxt in zip(n.arms, starts):
                start = (arm.line, arm.col)
                end = nxt or self.enclosing_close(start)
                for pb in _pattern_binds(arm.pattern):
                    self._add(Binding(pb.name, "bind", (pb.line, pb.col), pb, (start, end)))
                self._visit(arm.body)
            return
        for f in dataclasses.fields(n):
            self._visit(getattr(n, f.name))

    # ------------------------------------------------------------ lookups
    def resolve(self, name: str, pos: tuple) -> Optional[Binding]:
        best = None
        for b in self.bindings:
            if b.scope is not None and b.name == name and b.scope[0] <= pos <= b.scope[1]:
                if best is None or b.scope[0] >= best.scope[0]:
                    best = b
        return best or self.global_binding(name)

    def global_binding(self, name: str, kinds=("fn", "type", "enum", "const")) -> Optional[Binding]:
        for b in self.bindings:
            if b.scope is None and b.name == name and b.kind in kinds:
                return b
        return None

    def is_local(self, name: str, pos: tuple) -> bool:
        b = self.resolve(name, pos)
        return b is not None and b.scope is not None

    def visible(self, pos: tuple) -> list[Binding]:
        best: dict[str, Binding] = {}
        for b in self.bindings:
            if b.scope is not None and b.scope[0] <= pos <= b.scope[1]:
                cur = best.get(b.name)
                if cur is None or b.scope[0] >= cur.scope[0]:
                    best[b.name] = b
        return list(best.values())

    def member(self, owner: str, name: str, kind: str) -> Optional[Binding]:
        for b in self.bindings:
            if b.kind == kind and b.owner == owner and b.name == name:
                return b
        return None


def _pattern_binds(p) -> list:
    if isinstance(p, A.PBind):
        return [p]
    if isinstance(p, A.PVariant) and p.args:
        return [b for a in p.args for b in _pattern_binds(a)]
    return []


# ====================================================================== rendering

def texpr(te) -> str:
    if te is None:
        return "None"
    if isinstance(te, A.TOptional):
        inner = texpr(te.inner)
        return f"({inner})?" if isinstance(te.inner, A.TFn) else f"{inner}?"
    if isinstance(te, A.TFn):
        return f"fn({', '.join(texpr(p) for p in te.params)}) -> {texpr(te.ret)}"
    if te.args:
        return f"{te.name}[{', '.join(texpr(a) for a in te.args)}]"
    return te.name


def lit(e) -> str:
    if isinstance(e, A.BoolLit):
        return "true" if e.value else "false"
    if isinstance(e, A.StrLit):
        return json.dumps("".join(p for p in e.parts if isinstance(p, str)), ensure_ascii=False)
    return repr(getattr(e, "value", None))


def fn_signature(d: A.FnDecl, attrs: bool = True) -> str:
    head = {"fn": "fn", "ai": "ai fn", "agent": "agent fn"}.get(d.kind, "fn")
    ps = ", ".join(f"{p.name}: {texpr(p.type)}" if p.type else p.name for p in d.params)
    s = f"{head} {d.name}({ps})"
    if d.ret is not None:
        s += f" -> {texpr(d.ret)}"
    if d.uses:
        s += " uses " + ", ".join(d.uses)
    if attrs and d.attrs:
        s = " ".join(f"@{a.name}({lit(a.value)})" for a in d.attrs) + "\n" + s
    if d.tools:
        s += f"\n    tools [{', '.join(d.tools)}]"
    return s


def type_decl_text(d) -> str:
    if isinstance(d, A.TypeDecl):
        body = ", ".join(f"{f}: {texpr(t)}" for f, t in d.fields)
        return f"type {d.name} = {{ {body} }}" if body else f"type {d.name} = {{}}"
    vs = [variant_text(v) for v in d.variants]
    one = f"enum {d.name} {{ {', '.join(vs)} }}"
    return one if len(one) <= 80 else f"enum {d.name} {{\n" + "".join(f"    {v},\n" for v in vs) + "}"


def variant_text(v: A.Variant) -> str:
    if not v.fields:
        return v.name
    return f"{v.name}({', '.join(f'{f}: {texpr(t)}' for f, t in v.fields)})"


def stdlib_signature(name: str) -> str:
    sig = FUNCTIONS[name]
    ps = ", ".join(f"{p}: {t}" for p, t in sig.params)
    s = f"fn {name}({ps}) -> {sig.ret}"
    if sig.effects:
        s += " uses " + ", ".join(sig.effects)
    return s


def stdlib_doc(name: str) -> str:
    sig = FUNCTIONS[name]
    out = [sig.doc] if sig.doc else []
    if sig.defaults:
        out.append("Optional named argument(s): " + ", ".join(f"`{d}`" for d in sig.defaults) + ".")
    if sig.source:
        out.append(f"Result is untrusted (`untrusted:{sig.source}`).")
    if sig.sink:
        out.append("Untrusted data is rejected in: " + ", ".join(f"`{p}`" for p in sig.sink) + ".")
    if sig.secret:
        out.append("Result is a secret (`secret:NAME`).")
    return "\n\n".join(out)


def method_kind(ty) -> Optional[str]:
    from .types import ListT, MapT, STR
    if ty == STR:
        return "Str"
    if isinstance(ty, ListT):
        return "List"
    if isinstance(ty, MapT):
        return "Map"
    return None


def method_signature(ty, kind: str, name: str) -> str:
    sig = METHODS[kind][name]
    elem = getattr(ty, "elem", None)
    sub = (lambda s: re.sub(r"\bT\b", str(elem), s)) if elem is not None and str(elem) != "Unknown" else (lambda s: s)
    ps = ", ".join(f"{p}: {sub(t)}" for p, t in sig.params)
    return f"{ty}.{name}({ps}) -> {sub(sig.ret)}"


def code_md(code: str, doc: str = "", extra: str = "") -> str:
    out = f"```sipar\n{code}\n```"
    for part in (doc, extra):
        if part:
            out += "\n\n" + part
    return out


# ====================================================================== documents

class Document:
    def __init__(self, uri: str, text: str, version: Any, err):
        self.uri = uri
        self.path = uri_to_path(uri)
        self.version = _version(version)
        self.err = err
        self.text = text
        self.analysis = Analysis(text, self.path, err)
        self.last_good = self.analysis if self.analysis.ok else None

    def update(self, text: str, version: Any) -> None:
        self.text = text
        self.version = _version(version)
        self.analysis = Analysis(text, self.path, self.err)
        if self.analysis.ok:
            self.last_good = self.analysis

    def best(self) -> Analysis:
        """The current analysis if it parsed, else the last one that did (positions may be a little stale)."""
        return self.analysis if self.analysis.ok or self.last_good is None else self.last_good


def uri_to_path(uri: str) -> str:
    u = urlparse(uri)
    if u.scheme != "file":
        return uri
    path = unquote(u.path)
    if re.match(r"^/[A-Za-z]:", path):      # file:///C:/x on Windows
        path = path[1:]
    return path


def line_starts(text: str) -> list[int]:
    """Offsets where LSP lines start (LSP treats \\r\\n, \\n and \\r as line breaks)."""
    starts = [0]
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "\r":
            i += 2 if i + 1 < n and text[i + 1] == "\n" else 1
            starts.append(i)
        elif ch == "\n":
            i += 1
            starts.append(i)
        else:
            i += 1
    return starts


def offset_at(text: str, starts: list[int], pos: Any) -> int:
    if not isinstance(pos, dict):
        raise ParamsError("a range needs start and end positions")
    line = pos_int(pos, "line")
    if line >= len(starts):
        return len(text)
    if line < 0:
        return 0
    s = starts[line]
    e = starts[line + 1] if line + 1 < len(starts) else len(text)
    content = text[s:e].rstrip("\r\n")
    return s + utf16_to_cp(content, pos_int(pos, "character"))


def apply_change(text: str, change: dict) -> str:
    if "range" not in change or change.get("range") is None:
        return change["text"]
    rng = change["range"]
    if not isinstance(rng, dict):
        raise ParamsError("a content change range must be an object")
    starts = line_starts(text)
    a = offset_at(text, starts, rng.get("start"))
    b = offset_at(text, starts, rng.get("end"))
    if b < a:
        a, b = b, a
    return text[:a] + change["text"] + text[b:]


# ====================================================================== feature registry

class ParamsError(Exception):
    pass


def pos_int(pos: dict, key: str) -> int:
    """A position's line or character: an integer (not a bool; LSP uinteger, a negative one is clamped).
    A missing one is an error too (round 7: {} was read as 0 and a didChange went in at the top)."""
    if key not in pos:
        raise ParamsError(f"position.{key} is missing")
    v = pos[key]
    if not isinstance(v, int) or isinstance(v, bool):
        raise ParamsError(f"position.{key} must be an integer, not {type(v).__name__}")
    return v


FEATURES: dict[str, tuple[Callable, Optional[str], Any]] = {}


def feature(method: str, capability: Optional[str] = None, value: Any = True):
    def deco(fn):
        FEATURES[method] = (fn, capability, value)
        return fn
    return deco


def need(params: Any, *keys: str) -> Any:
    cur = params
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            raise ParamsError(f"missing params.{'.'.join(keys)}")
        cur = cur[k]
    return cur


def need_uri(params: Any) -> str:
    uri = need(params, "textDocument", "uri")
    if not isinstance(uri, str):
        raise ParamsError("textDocument.uri must be a string")
    return uri


def _doc_and_pos(server, params):
    uri = need_uri(params)
    pos = need(params, "position")
    if not isinstance(uri, str) or not isinstance(pos, dict):
        raise ParamsError("bad textDocument or position")
    doc = server.document(uri)
    if doc is None:
        return None, None, None
    a = doc.best()
    return doc, a, a.sipar_pos(pos)


def word_at(text: str, cp: int) -> Optional[tuple]:
    """(start, end) code point span of the identifier under or just before cp."""
    if not (0 <= cp < len(text) and is_word(text[cp])) and not (0 < cp <= len(text) and is_word(text[cp - 1])):
        return None
    s = e = cp
    while s > 0 and is_word(text[s - 1]):
        s -= 1
    while e < len(text) and is_word(text[e]):
        e += 1
    return s, e


def dot_before(text: str, start: int) -> Optional[int]:
    """Index of a member-access '.' right before `start` (spaces allowed), not a range '..'."""
    j = len(text[:start].rstrip(" \t")) - 1
    if j >= 0 and text[j] == "." and not (j > 0 and text[j - 1] == "."):
        return j
    return None


@dataclass
class Target:
    """What the identifier under the cursor refers to."""
    kind: str               # binding | stdlib | method | module | builtin_type | keyword | none
    binding: Optional[Binding] = None
    name: str = ""
    ty: Optional[str] = None
    recv: Any = None


def classify(a: Analysis, line: int, cp: int) -> tuple[Optional[Target], Optional[tuple]]:
    text = a.line_text(line)
    span = word_at(text, cp)
    if span is None:
        return None, None
    s, e = span
    word = text[s:e]
    pos = (line, s + 1)
    if word[0].isdigit() or a.mask[line - 1][s] != CODE:
        return Target("none", name=word), span
    if s > 0 and text[s - 1] == "@" and word in ATTRIBUTES:
        return Target("attribute", name=word), span
    cap = _capability_at(text, s, e)
    if cap is not None:
        return Target("capability", name=cap[0]), cap[1]
    if word in KEYWORDS:
        return Target("keyword", name=word), span
    b = a.decl_at.get(pos)
    if b is not None and b.name == word:
        return Target("binding", b, word), span
    ref = a.refs.get(pos)
    if ref is not None:
        rb = _resolve_ref(a, ref)
        return (Target("binding", rb, word) if rb is not None else Target("none", name=word)), span
    d = dot_before(text, s)
    if d is not None:
        dpos = (line, d + 1)
        f = a.fields.get(dpos)
        recv_span = word_at(text, d)
        recv = text[recv_span[0]:recv_span[1]] if recv_span and recv_span[1] == d else None
        if f is not None and f.name == word:
            return _member(a, f.obj, word, f, dpos), span
        if recv is not None and not a.is_local(recv, dpos):     # pattern `Enum.variant`, or no analysis
            return _static_member(a, recv, word), span
        return Target("none", name=word), span
    b = a.resolve(word, pos)      # the innermost local, else a global fn / type / enum / const
    if b is not None:
        return Target("binding", b, word), span
    if word in FUNCTIONS:
        return Target("stdlib", name=word), span
    if word in MODULES:
        return Target("module", name=word), span
    if word in BUILTIN_TYPE_DOCS:
        return Target("builtin_type", name=word), span
    return Target("none", name=word), span


CAP_CONTEXT = re.compile(r"(?:^\s*allow\s+|\buses\s+(?:[\w.]+\s*,\s*)*)$")


def _capability_at(text: str, s: int, e: int) -> Optional[tuple]:
    """(capability, span) when [s, e) is part of a capability name after `allow` or `uses`."""
    while s > 0 and (is_word(text[s - 1]) or text[s - 1] == "."):
        s -= 1
    while e < len(text) and (is_word(text[e]) or (text[e] == "." and e + 1 < len(text) and is_word(text[e + 1]))):
        e += 1
    name = text[s:e]
    if name in CAPS and CAP_CONTEXT.search(text[:s]):
        return name, (s, e)
    return None


def _resolve_ref(a: Analysis, ref: tuple) -> Optional[Binding]:
    if ref[0] == "rec":
        return a.member(ref[1], ref[2], "field")
    call, name = ref[1], ref[2]
    callee = call.callee
    if isinstance(callee, A.Name):
        fb = a.resolve(callee.name, (callee.line, callee.col))
        if fb is not None and fb.kind == "fn":
            for b in a.bindings:
                if b.kind == "param" and b.name == name and any(b.node is p for p in fb.node.params):
                    return b
        return None
    if isinstance(callee, A.Field) and isinstance(callee.obj, A.Name) \
            and not a.is_local(callee.obj.name, (callee.line, callee.col)):
        return a.member(f"{callee.obj.name}.{callee.name}", name, "field")
    return None


def _static_member(a: Analysis, recv: str, word: str) -> Target:
    if recv in MODULES and f"{recv}.{word}" in FUNCTIONS:
        return Target("stdlib", name=f"{recv}.{word}")
    v = a.member(recv, word, "variant")
    if v is not None:
        return Target("binding", v, word)
    return Target("none", name=word)


def _member(a: Analysis, obj, word: str, f, dpos: tuple) -> Target:
    if isinstance(obj, A.Name) and not a.is_local(obj.name, dpos):
        t = _static_member(a, obj.name, word)
        if t.kind != "none":
            return t
    rt = a.types.get(id(obj))
    if rt is None:
        return Target("none", name=word)
    from .types import Named
    if isinstance(rt, Named) and rt.kind == "record":
        fb = a.member(rt.name, word, "field")
        ty = a.type_of(f) or (str(a.checker.records.get(rt.name, {}).get(word)) if a.checker else None)
        if fb is not None:
            return Target("binding", fb, word, ty, recv=rt)
        if rt.name in BUILTIN_TYPES:
            return Target("field", name=word, ty=ty, recv=rt)
    mk = method_kind(rt)
    if mk and word in METHODS[mk]:
        return Target("method", name=word, recv=rt)
    return Target("none", name=word)


def describe(a: Analysis, t: Target) -> Optional[str]:
    if t.kind == "binding":
        b = t.binding
        if b.kind == "fn":
            d = b.node
            extra = ""
            info = a.checker.fns.get(d.name) if a.checker else None
            if info is not None and sorted(info.effects) != sorted(d.uses):
                extra = "Effects: " + ", ".join(sorted(info.effects))
            return code_md(fn_signature(d), d.doc or "", extra)
        if b.kind in ("type", "enum"):
            return code_md(type_decl_text(b.node), b.node.doc or "")
        if b.kind == "variant":
            enum = a.global_binding(b.owner, ("enum",))
            return code_md(f"{b.owner}.{variant_text(b.node)}", (enum.node.doc or "") if enum else "",
                           f"variant of enum `{b.owner}`")
        if b.kind == "field":
            ty = t.ty or a.binding_type(b) or "?"
            return code_md(f"(field) {b.owner}.{b.name}: {ty}")
        ty = t.ty or a.binding_type(b)
        word = {"let": "let", "var": "var", "const": "let", "param": "(parameter)", "loop": "(loop variable)",
                "bind": "(match binding)", "catch": "(caught error)"}.get(b.kind, b.kind)
        extra = "top-level constant" if b.kind == "const" else ""
        return code_md(f"{word} {b.name}" + (f": {ty}" if ty else ""), "", extra)
    if t.kind == "stdlib":
        return code_md(stdlib_signature(t.name), stdlib_doc(t.name))
    if t.kind == "method":
        mk = method_kind(t.recv)
        return code_md(method_signature(t.recv, mk, t.name), METHODS[mk][t.name].doc)
    if t.kind == "field":
        return code_md(f"(field) {t.recv}.{t.name}: {t.ty or '?'}")
    if t.kind == "module":
        fns = sorted(k for k in FUNCTIONS if k.startswith(t.name + "."))
        return code_md(f"module {t.name}", "Functions: " + ", ".join(f"`{k}`" for k in fns))
    if t.kind == "builtin_type":
        return code_md(f"type {t.name}", BUILTIN_TYPE_DOCS[t.name])
    if t.kind == "attribute":
        on = ["ai fn"] * (t.name in AI_ATTRS) + ["agent fn"] * (t.name in AGENT_ATTRS)
        return code_md(f"@{t.name}({ATTRIBUTES[t.name]})", "Attribute of " + " and ".join(on) + ".")
    if t.kind == "capability":
        users = sorted(k for k, sig in FUNCTIONS.items() if t.name in sig.effects)
        doc = ("Needed by: " + ", ".join(f"`{u}`" for u in users) + ".") if users else ""
        if t.name == "ai":
            doc = "Needed by every `ai fn` and `agent fn` call."
        return code_md(f"capability {t.name}", doc)
    if t.kind == "keyword" and t.name in ("true", "false"):
        return code_md("Bool")
    if t.kind == "keyword" and t.name == "none":
        return code_md("None")
    return None


# ====================================================================== features

def diagnostics_for(a: Analysis) -> list[dict]:
    out = []
    for d in a.diags:
        line, col = max(int(d.line), 1), max(int(d.col), 1)
        if line > len(a.lines):
            line, col = len(a.lines), len(a.lines[-1]) + 1
        text = a.line_text(line)
        s = min(col - 1, len(text))
        e = s
        if s < len(text):
            if is_word(text[s]):
                while e < len(text) and is_word(text[e]):
                    e += 1
            else:
                e = s + 1
        msg = d.message + (f"\nhint: {d.hint}" if d.hint else "")
        out.append({"range": a.lsp_range((line, s + 1), (line, e + 1)), "severity": SEV.get(d.severity, 1),
                    "code": d.code, "source": "sipar", "message": msg})
    if a.crash:
        out.append({"range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 0}}, "severity": 2, "source": "sipar",
                    "message": f"the sipar checker crashed ({a.crash}); diagnostics may be incomplete"})
    return out


@feature("textDocument/hover", "hoverProvider")
def hover(server, params):
    doc, a, pos = _doc_and_pos(server, params)
    if doc is None:
        return None
    line, col = pos
    t, span = classify(a, line, col - 1)
    md = describe(a, t) if t is not None else None
    if md is None and t is not None and t.kind == "none":
        return None
    if md is None:
        node = _expr_at(a, line, col if span is None else span[0] + 1)
        ty = a.type_of(node) if node is not None else None
        if ty is None or (ty == "None" and t is not None and t.kind == "keyword"):
            return None
        md = code_md(ty, "", "expression type")
        if span is None:
            return {"contents": {"kind": "markdown", "value": md}}
    return {"contents": {"kind": "markdown", "value": md},
            "range": a.lsp_range((line, span[0] + 1), (line, span[1] + 1))}


def _expr_at(a: Analysis, line: int, col: int):
    nodes = a.nodes_at.get((line, col)) or []
    return next((n for n in nodes if not isinstance(n, A.Name)), None)


@feature("textDocument/definition", "definitionProvider")
def definition(server, params):
    doc, a, pos = _doc_and_pos(server, params)
    if doc is None:
        return None
    t, _ = classify(a, pos[0], pos[1] - 1)
    if t is None or t.binding is None:
        return None
    b = t.binding
    return [{"uri": doc.uri, "range": a.name_range(b.pos, b.name)}]


@feature("textDocument/documentSymbol", "documentSymbolProvider")
def document_symbol(server, params):
    uri = need_uri(params)
    doc = server.document(uri)
    if doc is None:
        return []
    a = doc.best()
    if not a.ok:
        return []
    return symbols(a)


def symbols(a: Analysis) -> list[dict]:
    out = []

    def sym(name, kind, start, end, sel, detail="", children=None):
        d = {"name": name, "kind": SK[kind], "range": a.lsp_range(start, end), "selectionRange": sel}
        if detail:
            d["detail"] = detail
        if children is not None:
            d["children"] = children
        return d

    def close_of(after: tuple, default: tuple) -> tuple:
        brace = a.tok_after(after, "{")
        if brace is None:
            return default
        c = a.brackets.get((brace.line, brace.col))
        return (c[0], c[1] + 1) if c else default

    def line_end(line: int) -> tuple:
        return line, len(a.line_text(line)) + 1

    for it in a.program.items:
        start = (it.line, it.col)
        if isinstance(it, A.FnDecl):
            npos = a.name_after(start, it.name)
            end = close_of(npos, line_end(npos[0]))
            out.append(sym(it.name, "function", start, end, a.name_range(npos, it.name),
                           fn_signature(it, attrs=False).split("\n")[0]))
        elif isinstance(it, (A.TypeDecl, A.EnumDecl)):
            npos = a.name_after(start, it.name)
            end = close_of(npos, line_end(npos[0]))
            kids = []
            if isinstance(it, A.TypeDecl):
                for b in a.bindings:
                    if b.kind == "field" and b.owner == it.name:
                        kids.append(sym(b.name, "field", b.pos, (b.pos[0], b.pos[1] + len(b.name)),
                                        a.name_range(b.pos, b.name), texpr(b.node[1])))
            else:
                for v in it.variants:
                    vpos = (v.line, v.col)
                    vend = (v.line, v.col + len(v.name))
                    kids.append(sym(v.name, "enum_member", vpos, vend, a.name_range(vpos, v.name),
                                    variant_text(v) if v.fields else ""))
            out.append(sym(it.name, "struct" if isinstance(it, A.TypeDecl) else "enum", start, end,
                           a.name_range(npos, it.name), "", kids))
        elif isinstance(it, A.ConstDecl):
            npos = a.name_after(start, it.name)
            out.append(sym(it.name, "constant", start, line_end(start[0]), a.name_range(npos, it.name),
                           texpr(it.type) if it.type else (a.binding_type(a.decl_at[npos]) or "")
                           if npos in a.decl_at else ""))
        elif isinstance(it, A.TestDecl):
            body = (it.body.line, it.body.col)
            c = a.brackets.get(body)
            end = (c[0], c[1] + 1) if c else line_end(start[0])
            out.append(sym(f'test "{it.name}"', "method", start, end, a.name_range(start, "test")))
    return out


# ------------------------------------------------------------------ completion

def _item(label: str, kind: str, detail: str = "", doc: str = "", sort: str = "5", edit: Optional[dict] = None) -> dict:
    d = {"label": label, "kind": CK[kind], "sortText": f"{sort}{label}"}
    if detail:
        d["detail"] = detail
    if doc:
        d["documentation"] = {"kind": "markdown", "value": doc}
    if edit is not None:
        d["textEdit"] = {"range": edit, "newText": label}
    return d


def _in_text(a: Analysis, line: int, cp: int) -> bool:
    """True when a cursor before character cp sits in a comment or inside string text."""
    row = a.mask[line - 1] if 1 <= line <= len(a.mask) else []
    if cp <= 0 or not row:
        return False
    prev = row[min(cp, len(row)) - 1]
    if prev == COMMENT:
        return True
    return prev in (TEXT, OPEN)


@feature("textDocument/completion", "completionProvider", {"triggerCharacters": [".", "@"], "resolveProvider": False})
def completion(server, params):
    doc, a, pos = _doc_and_pos(server, params)
    if doc is None:
        return []
    cur = doc.analysis
    line, col = pos
    text = cur.line_text(line)
    cp = min(col - 1, len(text))
    prefix = text[:cp]
    if _in_text(cur, line, cp):
        return []
    partial = re.search(r"\w*$", prefix).group(0)
    before = prefix[:len(prefix) - len(partial)]
    capm = re.search(r"^\s*allow\s+([\w.]*)$", prefix) or re.search(r"\buses\s+(?:[\w.]+\s*,\s*)*([\w.]*)$", prefix)
    if capm:
        rng = cur.lsp_range((line, capm.start(1) + 1), (line, cp + 1))
        return [_item(c, "keyword", "capability", edit=rng) for c in sorted(CAPS)]
    if before.endswith("@"):
        return [_item(n, "keyword", f"@{n}({ATTRIBUTES[n]})") for n in sorted(ATTRIBUTES)]
    if before.endswith(".") and not before.endswith(".."):
        return _members(doc, line, cp, before, partial)
    best = cur
    if not cur.ok:                      # e.g. `"{}"` while typing: try the text with a name at the cursor
        patched = _patched(doc, line, cp)
        best = patched if patched.ok else doc.best()
    return _general(best, (line, cp + 1))


def _member_candidates(doc: Document, line: int, cp: int, partial: str):
    """The analyses to ask, best first: the current one, the text patched with a name after the dot
    (only when nothing is typed after it yet), then the last one that parsed."""
    yield doc.analysis
    if not partial:
        yield _patched(doc, line, cp)
    if doc.last_good is not None and doc.last_good is not doc.analysis:
        yield doc.last_good


def _members(doc: Document, line: int, cp: int, before: str, partial: str) -> list:
    dpos = (line, len(before))
    m = re.search(r"(\w+)\s*$", before[:-1])
    recv = m.group(1) if m else None
    for a in _member_candidates(doc, line, cp, partial):
        if not a.ok:
            continue
        if recv and not a.is_local(recv, dpos):
            if recv in MODULES:
                return [_item(k[len(recv) + 1:], "function", stdlib_signature(k), stdlib_doc(k))
                        for k in sorted(FUNCTIONS) if k.startswith(recv + ".")]
            enum = a.global_binding(recv, ("enum",))
            if enum is not None:
                return [_item(v.name, "enum_member", f"{recv}.{variant_text(v)}") for v in enum.node.variants]
        f = a.fields.get(dpos)
        if f is not None and id(f.obj) in a.types:
            return _members_of(a, a.types[id(f.obj)])
        b = a.resolve(recv, dpos) if recv else None
        if b is not None and b.scope is not None:
            t = a.decl_types.get((id(b.node), b.name))
            if t is not None:
                return _members_of(a, t)
    return []


def _members_of(a: Analysis, rt) -> list:
    from .types import Named
    if isinstance(rt, Named) and rt.kind == "record" and a.checker is not None:
        return [_item(f, "field", str(t)) for f, t in a.checker.records.get(rt.name, {}).items()]
    mk = method_kind(rt)
    if mk is None:
        return []
    return [_item(n, "method", method_signature(rt, mk, n), METHODS[mk][n].doc) for n in sorted(METHODS[mk])]


def _patched(doc: Document, line: int, cp: int) -> Analysis:
    lines = split_lines(doc.text)
    if 1 <= line <= len(lines):
        lines[line - 1] = lines[line - 1][:cp] + PLACEHOLDER + lines[line - 1][cp:]
    return Analysis("\n".join(lines), doc.path, doc.err)


def _general(a: Analysis, pos: tuple) -> list:
    items = [_item(k, "keyword", sort="9") for k in sorted(KEYWORDS)]
    seen = set()
    if a.ok:
        for b in sorted(a.visible(pos), key=lambda b: b.name):
            if b.name == PLACEHOLDER or b.name in seen:
                continue
            seen.add(b.name)
            items.append(_item(b.name, "variable", a.binding_type(b) or "", sort="1"))
        for b in a.bindings:
            if b.scope is not None or b.name in seen:
                continue
            if b.kind == "fn":
                seen.add(b.name)
                items.append(_item(b.name, "function", fn_signature(b.node, attrs=False).split("\n")[0],
                                   b.node.doc or "", sort="2"))
            elif b.kind == "const":
                seen.add(b.name)
                items.append(_item(b.name, "constant", a.binding_type(b) or "", sort="2"))
            elif b.kind in ("type", "enum"):
                seen.add(b.name)
                items.append(_item(b.name, "struct" if b.kind == "type" else "enum",
                                   type_decl_text(b.node).split("\n")[0], b.node.doc or "", sort="3"))
    for n in GLOBAL_FUNCS:
        if n not in seen:
            items.append(_item(n, "function", stdlib_signature(n), stdlib_doc(n), sort="4"))
    for m in MODULES:
        if m not in seen:
            items.append(_item(m, "module", f"module {m}", sort="4"))
    for t in BUILTIN_TYPE_DOCS:
        if t not in seen:
            items.append(_item(t, "class", BUILTIN_TYPE_DOCS[t], sort="6"))
    return items


# ====================================================================== server

class Server:
    def __init__(self, out, err=None):
        self.out = out
        self.err = err if err is not None else sys.stderr
        self.docs: dict[str, Document] = {}
        self.state = "new"              # new -> running -> shutdown
        self.exit_code: Optional[int] = None
        self.lifecycle = {
            "initialize": self.initialize, "shutdown": self.shutdown,
            "initialized": _noop, "exit": self.exit,
            "textDocument/didOpen": self.did_open, "textDocument/didChange": self.did_change,
            "textDocument/didClose": self.did_close, "textDocument/didSave": _noop,
            "workspace/didChangeConfiguration": _noop, "workspace/didChangeWatchedFiles": _noop,
        }

    # ------------------------------------------------------------ output
    def send(self, obj: dict) -> None:
        self.out.write(frame(obj))
        self.out.flush()

    def respond(self, mid, result) -> None:
        try:
            data = frame({"jsonrpc": "2.0", "id": mid, "result": result})
        except (TypeError, ValueError) as e:
            log(self.err, f"cannot encode the result: {e}")
            self.error(mid, INTERNAL_ERROR, f"cannot encode the result: {type(e).__name__}")
            return
        self.out.write(data)
        self.out.flush()

    def error(self, mid, code: int, message: str) -> None:
        self.send({"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}})

    def notify(self, method: str, params: dict) -> None:
        self.send({"jsonrpc": "2.0", "method": method, "params": params})

    # ------------------------------------------------------------ input
    def handle_bytes(self, body: bytes) -> None:
        if isinstance(body, Skipped):       # a frame without a usable header: nothing to answer
            log(self.err, body.reason)
            return
        try:
            msg = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError) as e:
            log(self.err, f"malformed message: {type(e).__name__}: {e}")
            self.error(None, PARSE_ERROR, f"parse error: {type(e).__name__}")
            return
        self.handle(msg)

    def handle(self, msg: Any) -> None:
        if not isinstance(msg, dict):
            self.error(None, INVALID_REQUEST, "a message must be a JSON object")
            return
        method = msg.get("method")
        is_req = "id" in msg
        mid = msg.get("id")
        if not isinstance(method, str):
            if is_req and ("result" in msg or "error" in msg):
                return                      # a reply to a request we never send; ignore
            self.error(mid if _valid_id(mid) else None, INVALID_REQUEST, "missing method")
            return
        if is_req and not _valid_id(mid):
            self.error(None, INVALID_REQUEST, "id must be an integer or a string")
            return
        params = msg.get("params")
        if params is None:
            params = {}
        if method == "exit":
            self.exit(params)
            return
        if not is_req:
            if self.state != "running" and method != "initialized":
                return                      # notifications before initialize / after shutdown are dropped
            self._run(None, method, params)
            return
        if method == "initialize" and self.state != "new":
            self.error(mid, INVALID_REQUEST, "initialize may only be sent once")
            return
        if self.state == "new" and method != "initialize":
            self.error(mid, SERVER_NOT_INITIALIZED, "the server is not initialized")
            return
        if self.state == "shutdown":
            self.error(mid, INVALID_REQUEST, "the server is shutting down")
            return
        self._run(mid, method, params, request=True)

    def _run(self, mid, method: str, params, request: bool = False) -> None:
        fn = self.lifecycle.get(method)
        if fn is None and method in FEATURES:
            feat = FEATURES[method][0]
            fn = lambda p: feat(self, p)     # noqa: E731
        if fn is None:
            if request:
                self.error(mid, METHOD_NOT_FOUND, f"unknown method {method}")
            elif not method.startswith("$/"):
                log(self.err, f"ignored unknown notification {method}")
            return
        try:
            result = fn(params)
        except ParamsError as e:
            log(self.err, f"{method}: invalid params: {e}")
            if request:
                self.error(mid, INVALID_PARAMS, str(e))
            return
        except Exception as e:  # noqa: BLE001 — one bad request must never stop the server
            log(self.err, f"{method} failed: {type(e).__name__}: {e}\n{traceback.format_exc()}")
            if request:
                self.error(mid, INTERNAL_ERROR, f"internal error in {method}: {type(e).__name__}: {e}")
            return
        if request:
            self.respond(mid, result)

    # ------------------------------------------------------------ lifecycle
    def capabilities(self) -> dict:
        caps: dict = {"positionEncoding": "utf-16",
                      "textDocumentSync": {"openClose": True, "change": 1, "save": False}}
        for _, cap, value in FEATURES.values():
            caps[cap] = value
        return caps

    def initialize(self, params) -> dict:
        if not isinstance(params, dict):
            raise ParamsError("initialize params must be an object")
        self.state = "running"
        return {"capabilities": self.capabilities(), "serverInfo": {"name": "sipar", "version": __version__}}

    def shutdown(self, params) -> None:
        self.state = "shutdown"
        return None

    def exit(self, params) -> None:
        self.exit_code = 0 if self.state == "shutdown" else 1

    # ------------------------------------------------------------ documents
    def document(self, uri: str) -> Optional[Document]:
        return self.docs.get(uri)

    def publish(self, doc: Document) -> None:
        self.notify("textDocument/publishDiagnostics",
                    {"uri": doc.uri, "version": doc.version, "diagnostics": diagnostics_for(doc.analysis)})

    def did_open(self, params) -> None:
        td = need(params, "textDocument")
        uri, text = need(td, "uri"), need(td, "text")
        if not isinstance(uri, str) or not isinstance(text, str):
            raise ParamsError("textDocument.uri and textDocument.text must be strings")
        doc = Document(uri, text, td.get("version"), self.err)
        self.docs[uri] = doc
        self.publish(doc)

    def did_change(self, params) -> None:
        uri = need_uri(params)
        changes = need(params, "contentChanges")
        doc = self.docs.get(uri)
        if doc is None:
            raise ParamsError(f"didChange for a document that is not open: {uri}")
        if not isinstance(changes, list):
            raise ParamsError("contentChanges must be a list")
        text = doc.text
        for ch in changes:
            if not isinstance(ch, dict) or not isinstance(ch.get("text"), str):
                raise ParamsError("each content change needs a text")
            text = apply_change(text, ch)
        doc.update(text, params["textDocument"].get("version"))
        self.publish(doc)

    def did_close(self, params) -> None:
        uri = need_uri(params)
        doc = self.docs.pop(uri, None)
        if doc is not None:
            self.notify("textDocument/publishDiagnostics", {"uri": uri, "diagnostics": []})


def _noop(params) -> None:
    return None


def _version(v: Any) -> Optional[int]:
    """A document version as LSP defines it (an integer), else None.  A client that sends 1e400 (parsed as
    inf), NaN or 1.5 must not stop diagnostics: the version is echoed in publishDiagnostics, and a
    non-finite float there made every later publish fail to encode (round 10, F7)."""
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _valid_id(mid) -> bool:
    return isinstance(mid, (int, str)) and not isinstance(mid, bool)


def serve(inp, out, err=None) -> int:
    """Run the server until `exit` or end of input.  Returns the process exit code (0 after a clean
    shutdown + exit, 1 otherwise)."""
    err = err if err is not None else sys.stderr
    server = Server(out, err)
    while True:
        try:
            body = read_message(inp)
        except (OSError, ValueError) as e:
            log(err, f"cannot read input: {e}")
            break
        if body is None:
            break
        try:
            server.handle_bytes(body)
        except (BrokenPipeError, OSError) as e:
            log(err, f"cannot write output: {e}")
            break
        except Exception as e:  # noqa: BLE001 — last line of defence
            log(err, f"unexpected error: {type(e).__name__}: {e}\n{traceback.format_exc()}")
        if server.exit_code is not None:
            return server.exit_code
    return 0 if server.state == "shutdown" else 1


def main() -> int:
    out = sys.stdout.buffer
    sys.stdout = sys.stderr             # a stray print must never corrupt the protocol stream
    try:
        return serve(sys.stdin.buffer, out, sys.stderr)
    finally:
        sys.stdout = sys.__stdout__
