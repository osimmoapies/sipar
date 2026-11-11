"""Sipar lexer: source text -> list[Token]."""
from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from typing import Optional

from .errors import SiparSyntaxError

KEYWORDS = {
    "fn", "ai", "agent", "type", "enum", "let", "var", "if", "else", "while", "for", "in", "match",
    "return", "break", "continue", "try", "catch", "budget", "allow", "uses", "test", "mock", "assert",
    "and", "or", "not", "true", "false", "none", "as", "tools",
}

# longest first
PUNCT = ["...", "..", "??", "==", "!=", "<=", ">=", "=>", "->",
         "+", "-", "*", "/", "%", "<", ">", "=", "(", ")", "[", "]", "{", "}", ",", ":", ";", ".", "?", "@"]

# a NEWLINE right after one of these is not a statement end
CONTINUE_AFTER = {"+", "-", "*", "/", "%", "==", "!=", "<", "<=", ">", ">=", "=", "=>", "->", ",", "{",
                  "(", "[", ".", "..", "??", "and", "or", "not", "in", "as", ":", "@"}


@dataclass
class Token:
    kind: str           # "int" "float" "str" "ident" "newline" "eof", keyword text, or punctuation text
    value: object
    line: int
    col: int
    doc: Optional[str] = None
    # for "str": list of ("text", str) | ("expr", source, line, col)
    triple: bool = False

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Token({self.kind!r}, {self.value!r}, {self.line}:{self.col})"


MAX_INT_LITERAL_BITS = 14_000   # same limit as runtime Ints (values.MAX_INT_BITS, about 4200 digits)


def _digit(c: str) -> bool:     # ASCII only: SPEC §1 (str.isdigit() would accept '²' and '١')
    return len(c) == 1 and "0" <= c <= "9"


def _alpha(c: str) -> bool:
    return len(c) == 1 and ("a" <= c <= "z" or "A" <= c <= "Z")


def _alnum(c: str) -> bool:
    return _digit(c) or _alpha(c)


def normalize_newlines(src: str) -> str:
    """\r\n and a lone \r become \n: the line breaks of the LSP spec and of Python's universal newlines
    (F8, round 6: a CR-only file was one line to the lexer but many to the LSP)."""
    return src.replace("\r\n", "\n").replace("\r", "\n")


class Lexer:
    def __init__(self, src: str, file: str = "<input>", line: int = 1, col: int = 1):
        if src.startswith("\ufeff"):            # a UTF-8 byte order mark some editors write: ignore it
            src = src[1:]
        self.src = normalize_newlines(src)      # CRLF / CR files: no stray \r inside triple strings
        self.file = file
        self.i = 0
        self.line = line
        self.col = col
        self.toks: list[Token] = []
        self.brackets: list[str] = []   # open ( [ { ; a newline is ignored when the innermost is ( or [
        self.pending_doc: list[str] = []

    # ------------------------------------------------------------ helpers
    def err(self, msg: str, line: int | None = None, col: int | None = None, hint: str = "") -> SiparSyntaxError:
        return SiparSyntaxError("E101", msg, self.file, line or self.line, col or self.col, hint)

    def peek(self, k: int = 0) -> str:
        j = self.i + k
        return self.src[j] if j < len(self.src) else ""

    def adv(self, n: int = 1) -> str:
        out = self.src[self.i:self.i + n]
        for ch in out:
            if ch == "\n":
                self.line += 1
                self.col = 1
            else:
                self.col += 1
        self.i += n
        return out

    def add(self, kind: str, value: object, line: int, col: int, **kw) -> None:
        doc = None
        if self.pending_doc and kind not in ("newline",):
            doc = "\n".join(self.pending_doc)
            self.pending_doc = []
        self.toks.append(Token(kind, value, line, col, doc=doc, **kw))

    def last_kind(self) -> str:
        return self.toks[-1].kind if self.toks else "newline"

    def next_line_starts_with_dot(self) -> bool:
        j = self.i
        while j < len(self.src):
            ch = self.src[j]
            if ch in " \t\r\n":
                j += 1
                continue
            if self.src.startswith("//", j) and not self.src.startswith("///", j):
                while j < len(self.src) and self.src[j] != "\n":
                    j += 1
                continue
            return ch == "." and not self.src.startswith("..", j)
        return False

    # ------------------------------------------------------------ main loop
    def tokenize(self) -> list[Token]:
        while self.i < len(self.src):
            ch = self.peek()
            line, col = self.line, self.col
            if ch == "\n":
                self.adv()
                if self.brackets and self.brackets[-1] in "([":
                    continue
                lk = self.last_kind()
                if lk == "newline" or lk in CONTINUE_AFTER or self.next_line_starts_with_dot():
                    continue
                self.add("newline", None, line, col)
                continue
            if ch in " \t\r":
                self.adv()
                continue
            if self.src.startswith("///", self.i):
                self.adv(3)
                start = self.i
                while self.i < len(self.src) and self.peek() != "\n":
                    self.adv()
                self.pending_doc.append(self.src[start:self.i].strip())
                continue
            if self.src.startswith("//", self.i):
                while self.i < len(self.src) and self.peek() != "\n":
                    self.adv()
                continue
            if _digit(ch):
                self.number(line, col)
                continue
            if _alpha(ch) or ch == "_":
                start = self.i
                while self.peek() and (_alnum(self.peek()) or self.peek() == "_"):
                    self.adv()
                word = self.src[start:self.i]
                if word in KEYWORDS:
                    self.add(word, word, line, col)
                else:
                    self.add("ident", word, line, col)
                continue
            if ch == '"':
                self.string(line, col)
                continue
            for p in PUNCT:
                if self.src.startswith(p, self.i):
                    if p == "...":
                        raise self.err("unexpected '...'", hint="ranges use two dots: a..b")
                    self.adv(len(p))
                    if p in ("(", "[", "{"):
                        self.brackets.append(p)
                    elif p in (")", "]", "}") and self.brackets:
                        self.brackets.pop()
                    if p in (")", "]", "}") and self.toks and self.last_kind() == "newline" and p != "}":
                        self.toks.pop()
                    self.add(p, p, line, col)
                    break
            else:
                if ord(ch) > 127:
                    raise self.err(f"unexpected character {ch!r}: outside strings and comments, source is ASCII",
                                   hint="use ASCII letters and digits for names and numbers; put other text in a "
                                        "\"string\"")
                raise self.err(f"unexpected character {ch!r}",
                               hint="remove it; see `sipar spec` for the operators and punctuation Sipar uses")
        if self.last_kind() != "newline":
            self.add("newline", None, self.line, self.col)
        self.add("eof", None, self.line, self.col)
        return self.toks

    def number(self, line: int, col: int) -> None:
        start = self.i
        while _digit(self.peek()) or self.peek() == "_":
            self.adv()
        is_float = False
        if self.peek() == "." and _digit(self.peek(1)):
            is_float = True
            self.adv()
            while _digit(self.peek()) or self.peek() == "_":
                self.adv()
        if self.peek() in ("e", "E") and (_digit(self.peek(1)) or (self.peek(1) in "+-" and _digit(self.peek(2)))):
            is_float = True
            self.adv(2)
            while _digit(self.peek()):
                self.adv()
        raw = self.src[start:self.i]
        for k, c in enumerate(raw):     # '_' only between two digits: 1_000 ok, 1_ 1__0 1_.5 bad
            if c == "_" and not (k > 0 and _digit(raw[k - 1]) and k + 1 < len(raw) and _digit(raw[k + 1])):
                raise self.err(f"misplaced '_' in number literal {raw!r}", line, col,
                               hint="'_' may only stand between two digits, as in 1_000")
        text = raw.replace("_", "")
        if self.peek() and (_alpha(self.peek()) or self.peek() == "_" or (ord(self.peek()) > 127 and self.peek().isalnum())):
            raise self.err(f"invalid number literal {self.src[start:self.i + 1]!r}", line, col,
                           hint="a number is digits only (1_000, 3.14, 2e10); put a space or operator after it")
        if is_float:
            f = float(text)
            if f == float("inf"):       # 1e400: Python would silently make it infinity (SPEC §5: finite only)
                raise self.err(f"float literal out of range: {raw!r}", line, col,
                               hint="the largest Float is about 1.8e308")
            self.add("float", f, line, col)
        else:
            # a decimal of more than 4300 digits makes Python's int() raise; the bit limit is the runtime's
            v = int(text) if len(text) <= 4300 else None
            if v is None or v.bit_length() > MAX_INT_LITERAL_BITS:
                raise self.err(f"integer literal too large ({len(text)} digits)", line, col,
                               hint="an Int has at most 14,000 bits (about 4200 digits); use a Float or a Str")
            self.add("int", v, line, col)

    def string(self, line: int, col: int) -> None:
        triple = self.src.startswith('"""', self.i)
        q = '"""' if triple else '"'
        self.adv(len(q))
        start = self.i
        # find the closing quote while skipping escapes and balanced interpolations
        depth = 0
        while True:
            if self.i >= len(self.src):
                raise self.err("unterminated string", line, col, hint=f"close it with {q}")
            ch = self.peek()
            if ch == "\\":
                self.adv(2)
                continue
            if ch == "\n" and not triple and depth == 0:
                raise self.err("unterminated string (newline inside \"...\")", line, col,
                               hint='use """...""" for multi-line text')
            if depth == 0 and self.src.startswith(q, self.i):
                break
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth = max(0, depth - 1)
            elif ch == '"' and depth > 0:
                # nested simple string inside an interpolation
                self.adv()
                while self.i < len(self.src) and self.peek() != '"':
                    if self.peek() == "\\":
                        self.adv()
                    self.adv()
            self.adv()
        raw = self.src[start:self.i]
        self.adv(len(q))
        body_line, body_col = line, col + len(q)
        indent = 0
        if triple:
            raw, body_line, indent, dropped = dedent_triple(raw, line)
            body_col = 1 + indent if dropped else col + len(q)
        parts = split_string(raw, self.file, body_line, body_col, indent)
        self.add("str", parts, line, col, triple=triple)


def dedent_triple(raw: str, line: int) -> tuple[str, int, int, bool]:
    """Drop one leading/trailing blank line, remove common indentation.
    Returns (text, first_line, indent, first_line_dropped)."""
    lines = raw.split("\n")
    dropped = False
    if len(lines) > 1 and lines[0].strip() == "":
        lines = lines[1:]
        line += 1
        dropped = True
    if lines and lines[-1].strip() == "":
        lines = lines[:-1]
    text = "\n".join(lines)
    ded = textwrap.dedent(text)
    first = next((ln for ln in lines if ln.strip()), "")
    first_ded = next((ln for ln in ded.split("\n") if ln.strip()), "")
    return ded, line, len(first) - len(first_ded), dropped


ESCAPES = {"n": "\n", "t": "\t", '"': '"', "\\": "\\", "{": "{", "}": "}", "r": "\r", "0": "\0"}


def split_string(raw: str, file: str, line: int, col: int, indent: int = 0) -> list[tuple]:
    """Split string body into text chunks and interpolation sources."""
    parts: list[tuple] = []
    buf: list[str] = []
    i = 0
    cur_line, cur_col = line, col
    while i < len(raw):
        ch = raw[i]
        if ch == "\\":
            nxt = raw[i + 1] if i + 1 < len(raw) else ""
            if nxt not in ESCAPES:
                raise SiparSyntaxError("E102", f"unknown escape \\{nxt}", file, cur_line, cur_col,
                                       "valid escapes: \\n \\t \\r \\0 \\\" \\\\ \\{ \\}")
            buf.append(ESCAPES[nxt])
            i += 2
            cur_col += 2
            continue
        if ch == "{":
            depth = 1
            j = i + 1
            while j < len(raw) and depth:
                if raw[j] == "{":
                    depth += 1
                elif raw[j] == "}":
                    depth -= 1
                elif raw[j] == '"':
                    j += 1
                    while j < len(raw) and raw[j] != '"':
                        j += 2 if raw[j] == "\\" else 1
                j += 1
            if depth:
                raise SiparSyntaxError("E103", "unclosed '{' in string interpolation", file, cur_line, cur_col,
                                       "write \\{ for a literal brace")
            src = raw[i + 1:j - 1]
            if not src.strip():
                raise SiparSyntaxError("E103", "empty interpolation {}", file, cur_line, cur_col,
                                       "write \\{\\} for literal braces")
            if buf:
                parts.append(("text", "".join(buf)))
                buf = []
            parts.append(("expr", src, cur_line, cur_col + 1))
            for c in raw[i:j]:
                if c == "\n":
                    cur_line += 1
                    cur_col = 1 + indent
                else:
                    cur_col += 1
            i = j
            continue
        if ch == "}":
            raise SiparSyntaxError("E103", "unmatched '}' in string", file, cur_line, cur_col,
                                   "write \\} for a literal brace")
        buf.append(ch)
        if ch == "\n":
            cur_line += 1
            cur_col = 1 + indent
        else:
            cur_col += 1
        i += 1
    if buf or not parts:
        parts.append(("text", "".join(buf)))
    return parts


def tokenize(src: str, file: str = "<input>") -> list[Token]:
    return Lexer(src, file).tokenize()
