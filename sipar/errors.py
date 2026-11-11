"""Diagnostics and error types shared by every Sipar phase."""
from __future__ import annotations

import bisect
import functools
import html.entities
import json
import re
import threading
import unicodedata
import urllib.parse
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from typing import Iterator


@dataclass
class Diagnostic:
    code: str           # E1xx syntax, E2xx names/types, E3xx effects/capabilities, E4xx match/flow
    severity: str       # "error" | "warning"
    file: str
    line: int
    col: int
    message: str
    hint: str = ""

    def __post_init__(self) -> None:        # every diagnostic says what to do next (round 4, C9)
        if not self.hint:
            self.hint = f"see {self.code} in docs/ERRORS.md; `sipar spec` prints the syntax"

    def to_dict(self) -> dict:
        return asdict(self)

    def render(self, src: str | None = None) -> str:
        """Text for a terminal: control characters in the file name, message and source line are escaped
        (M1, round 6, like runtime errors in round 5 S3); a source line longer than MAX_SNIPPET is cut around
        the column (L14, round 6). JSON output (to_dict) keeps the raw text."""
        head = f"{self.file}:{self.line}:{self.col}: {self.severity}[{self.code}]: {self.message}"
        out = [escape_controls(head)]
        if src is not None:
            lines = src.replace("\r\n", "\n").replace("\r", "\n").split("\n")   # as the lexer counts lines
            if 1 <= self.line <= len(lines):
                text = lines[self.line - 1]
                c = max(self.col, 1) - 1
                start = 0
                if len(text) > MAX_SNIPPET:
                    start = max(0, min(c - MAX_SNIPPET // 2, len(text) - MAX_SNIPPET))
                pre = "…" if start > 0 else ""
                post = "…" if start + MAX_SNIPPET < len(text) else ""
                shown = escape_controls(text[start:start + MAX_SNIPPET])
                out.append(f"  {self.line:>4} | {pre}{shown}{post}")
                out.append("       | " + " " * (len(pre) + len(escape_controls(text[start:c]))) + "^")
        if self.hint:
            out.append(escape_controls(f"  hint: {self.hint}"))
        return "\n".join(out)


MAX_SNIPPET = 200       # chars of a source line shown under a diagnostic (L14, round 6)


class SiparSyntaxError(Exception):
    def __init__(self, code: str, message: str, file: str, line: int, col: int, hint: str = ""):
        super().__init__(message)
        self.diag = Diagnostic(code, "error", file, line, col, message, hint)


# ------------------------------------------------------------------ secret redaction
# Every secret value a run reads (env.secret, provider API keys) is registered in that run's SecretRegistry;
# error messages, tool-error text fed to models and journal entries replace it (and every form secret_forms() lists)
# with «secret:NAME». Values shorter than 4 characters are not registered (they would redact ordinary text); they
# rely on label-aware rendering, which every value-embedding message uses.
# The registry is per run (round 5, C1): a secret of one run must not label or redact text in a later, unrelated
# run of the same process. use_registry() makes a registry current on this thread (deep.call_deep carries it to
# its worker); outside any run the process-wide DEFAULT registry is used. An error keeps the registry it was
# raised under, so its message stays redacted after the run has ended.
MIN_SECRET_LEN = 4


class SecretRegistry:
    __slots__ = ("secrets", "labels", "views")

    def __init__(self) -> None:
        self.secrets: dict[str, str] = {}       # every registered form -> «secret:NAME»
        self.labels: dict[str, str] = {}        # every matched form (and the «secret:NAME» marker) -> secret:NAME
        self.views: dict[str, str] = {}         # every plain form as search_view() shows it -> «secret:NAME»


DEFAULT = SecretRegistry()
_local = threading.local()


def active_registry() -> SecretRegistry | None:
    """The registry made current on this thread by use_registry(), or None."""
    return getattr(_local, "reg", None)


def current_registry() -> SecretRegistry:
    return getattr(_local, "reg", None) or DEFAULT


@contextmanager
def use_registry(reg: SecretRegistry | None) -> Iterator[SecretRegistry | None]:
    prev = getattr(_local, "reg", None)
    _local.reg = reg
    try:
        yield reg
    finally:
        _local.reg = prev


_PCT_HEX = re.compile(r"%[0-9A-F]{2}")


def _percent(v: str, plus: bool = False, safe: str = "") -> str:
    """Percent-encoding of v as UTF-8 (a lone surrogate from a non-UTF-8 environment as its original byte)."""
    for errors in ("surrogateescape", "surrogatepass"):
        try:
            return (urllib.parse.quote_plus if plus else urllib.parse.quote)(v, safe=safe, errors=errors)
        except UnicodeEncodeError:
            continue
    return v


def _escaped_forms(v: str) -> list[str]:
    """The ways a str can show up escaped in text: Python repr, bytes repr (UTF-8), JSON string bodies (with and
    without `\\/` for `/`, R8-4) and percent-encoding (`quote` with and without `/` kept, `quote_plus`, upper-
    and lower-case hex digits, R8-4)."""
    j, ju = json.dumps(v)[1:-1], json.dumps(v, ensure_ascii=False)[1:-1]
    pct = [_percent(v), _percent(v, safe="/"), _percent(v, plus=True)]
    out = [repr(v)[1:-1], repr(v.encode("utf-8", "surrogatepass"))[2:-1], j, ju,
           j.replace("/", "\\/"), ju.replace("/", "\\/"), *pct,
           *(_PCT_HEX.sub(lambda m: m.group().lower(), f) for f in pct)]
    return list(dict.fromkeys(f for f in out if f != v))


def secret_bases(value: str) -> list[str]:
    """The plain forms of a secret (4 characters or more each): the value and, when it has surrounding
    whitespace (a trailing space or the \\r of a Windows .env file), its trimmed form (R8-2); each as is,
    upper-case, lower-case, case-folded and lower-case of its upper-case form (R8-3: ß -> SS / ss, ı -> I / i,
    ﬀ -> FF / ff). Case mapping never shortens a str."""
    out: list[str] = []
    t = value.strip()
    for v in ((value, t) if t != value and len(t) >= MIN_SECRET_LEN else (value,)):
        up = v.upper()
        out.extend((v, up, v.lower(), v.casefold(), up.lower(), up.casefold()))
    return list(dict.fromkeys(f for f in out if len(f) >= MIN_SECRET_LEN))


def secret_forms(value: str) -> list[str]:
    """Every form of a secret that is registered (redacted and labelled): secret_bases() and their escaped
    forms. At most 2 x 6 bases x 13 escapes; for a plain ASCII token 3 to 6 forms."""
    out: list[str] = []
    for base in secret_bases(value):
        out.append(base)
        out.extend(_escaped_forms(base))
    return list(dict.fromkeys(f for f in out if len(f) >= MIN_SECRET_LEN))


# R9-1/R9-3 (round 9): a server or file may hand a secret back escaped by a stock encoder (Go JSON `\u0026`, .NET
# JSON `\u002B`, HTML `&amp;` / `&#39;`, percent-encoding) or in another Unicode form (NFD, full-width, with
# zero-width characters inside). Instead of listing every such form, text is also searched in its *search view*:
# one level of JSON / Python backslash escapes, HTML character references and percent-encoding decoded, the
# Unicode default-ignorable (invisible) characters dropped and every character in NFKD form. Each view character
# remembers where it came from, so a copy found in the view is redacted in the original text.
_INVISIBLE = ("\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f"
              "\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufff8\U0001bca0-\U0001bca3\U0001d173-\U0001d17a"
              "\U000e0000-\U000e0fff")
_INVISIBLE_RE = re.compile(f"[{_INVISIBLE}]")
_ESCAPE = re.compile(r"\\u[dD][89abAB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}"
                     r"|\\U[0-9a-fA-F]{8}|\\x[0-9a-fA-F]{2}|\\[\\/\"'bfnrt]"
                     r"|&#0*[0-9]{1,7};?|&#[xX]0*[0-9a-fA-F]{1,6};?|&[A-Za-z][A-Za-z0-9]{1,31};"   # leading zeros: round 10, S3
                     r"|%[0-9a-fA-F]{2}(?:%[0-9a-fA-F]{2})*")
_SIMPLE = {"\\": "\\", "/": "/", '"': '"', "'": "'", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


@functools.lru_cache(maxsize=1)
def _changed_re() -> re.Pattern:
    """Characters the search view changes: invisible ones and those with a decomposition (built on first use,
    about 40 ms; no character above U+2FFFF has one). Hangul syllables are kept composed on both sides."""
    ranges: list[list[int]] = []
    for c in range(0x30000):
        if unicodedata.decomposition(chr(c)):
            if ranges and ranges[-1][1] == c - 1:
                ranges[-1][1] = c
            else:
                ranges.append([c, c])
    cls = "".join(re.escape(chr(x)) if x == y else f"{re.escape(chr(x))}-{re.escape(chr(y))}" for x, y in ranges)
    return re.compile(f"[{_INVISIBLE}{cls}]")


def _norm_char(ch: str) -> str:
    """One character as the search view shows it: nothing for an invisible one, else its NFKD form."""
    if _INVISIBLE_RE.match(ch):
        return ""
    return unicodedata.normalize("NFKD", ch) if _changed_re().match(ch) else ch


def view_form(value: str) -> str:
    """A plain secret form as the search view shows it (no decoding: only the Unicode steps)."""
    return value if value.isascii() else "".join(map(_norm_char, value))


def _unescape(tok: str) -> str | None:
    """The text one escape token stands for, or None when it stands for nothing (an unknown entity)."""
    c = tok[0]
    try:
        if c == "\\":
            k = tok[1]
            if k == "u" and len(tok) == 12:
                return chr(0x10000 + ((int(tok[2:6], 16) - 0xD800) << 10) + int(tok[8:12], 16) - 0xDC00)
            if k in "uUx":
                return chr(int(tok[2:], 16))
            return _SIMPLE[k]
        if c == "&":
            body = tok[1:].rstrip(";")
            if body[:1] == "#":
                return chr(int(body[2:], 16) if body[1:2] in "xX" else int(body[1:]))
            return html.entities.html5.get(body + ";")
    except (ValueError, OverflowError, KeyError):
        return None
    return None


@functools.lru_cache(maxsize=16)
def search_view(text: str) -> tuple[str, tuple | None]:
    """(view, map) of text: map is None when the view is text itself, else (view starts, pieces): piece k
    begins at view index starts[k] and is (orig_start, orig_end, same) where same=True means a run copied
    char for char."""
    if not _ESCAPE.search(text) and (text.isascii() or not _changed_re().search(text)):
        return text, None
    out: list[str] = []
    starts: list[int] = []
    pieces: list[tuple[int, int, bool]] = []
    n = 0

    def emit(v: str, a: int, b: int, same: bool) -> None:
        nonlocal n
        if v:
            starts.append(n)
            pieces.append((a, b, same))
            out.append(v)
            n += len(v)

    def literal(a: int, b: int) -> None:
        if not text.isascii():
            for m in _changed_re().finditer(text, a, b):
                emit(text[a:m.start()], a, m.start(), True)
                a = m.end()
                emit(_norm_char(m.group()), m.start(), a, False)
        emit(text[a:b], a, b, True)

    pos = 0
    for m in _ESCAPE.finditer(text):
        a, b = m.span()
        literal(pos, a)
        pos = b
        tok = m.group()
        if tok[0] == "%":                            # a run of percent-encoded UTF-8 bytes, one char at a time
            for ch in bytes.fromhex(tok.replace("%", "")).decode("utf-8", "surrogateescape"):
                w = 3 * len(ch.encode("utf-8", "surrogateescape"))
                emit("".join(map(_norm_char, ch)), a, a + w, False)
                a += w
            continue
        v = _unescape(tok)
        if v is None:
            literal(a, b)
        else:
            emit("".join(map(_norm_char, v)), a, b, False)
    literal(pos, len(text))
    return "".join(out), (starts, pieces)


def _orig_span(vmap: tuple | None, vs: int, ve: int) -> tuple[int, int]:
    """The span of the original text a view span [vs, ve) comes from (whole escape tokens)."""
    if vmap is None:
        return vs, ve
    starts, pieces = vmap
    p = bisect.bisect_right(starts, vs) - 1
    a, b, same = pieces[p]
    s = a + (vs - starts[p]) if same else a
    q = bisect.bisect_right(starts, ve - 1) - 1
    a, b, same = pieces[q]
    e = a + (ve - 1 - starts[q]) + 1 if same else b
    return s, e


def fold_case(text: str) -> str:
    """Caseless form for comparing secrets with other text (R8-3): upper-case, then case-folded, so ß / SS / ss,
    ı / I / i and ﬀ / FF / ff all compare equal. Maps character by character, so a caseless substring stays a
    substring."""
    return text.upper().casefold()


def secret_key(text: str) -> str:
    """Caseless search view of text (R9-3): one level of escapes decoded, invisible characters dropped, NFKD,
    fold_case. A secret's key inside a text's key means the text holds a copy of the secret in some case."""
    return view_form(fold_case(search_view(str.__str__(text))[0]))


def register_secret(value: str, label: str) -> None:
    if not isinstance(value, str) or len(value) < MIN_SECRET_LEN:
        return
    reg = current_registry()
    mark = f"«{label}»"
    value = str.__str__(value)
    for form in secret_forms(value):
        reg.secrets.setdefault(form, mark)
        reg.labels.setdefault(form, label)
    for base in secret_bases(value):
        v = view_form(base)
        if len(v) >= MIN_SECRET_LEN:
            reg.views.setdefault(v, mark)
    reg.labels.setdefault(mark, label)


def secret_labels_in(text: str) -> frozenset:
    """Labels of the registered secrets whose value (any registered form, or a plain form in the search view)
    or «secret:NAME» marker occurs in text. Sources use it to label echoed secrets (SPEC §6)."""
    reg = current_registry()
    if not reg.labels or not isinstance(text, str) or not text:
        return frozenset()
    text = str.__str__(text)
    found = {lab for form, lab in reg.labels.items() if form in text}
    if reg.views:
        view = search_view(text)[0]
        found.update(mark[1:-1] for v, mark in reg.views.items() if v in view)
    return frozenset(found)


def secret_in_text(text: str, value: str) -> bool:
    """text holds a copy of the secret value that registering it would label (and redact)."""
    with use_registry(SecretRegistry()):
        register_secret(value, "secret:_")
        return bool(secret_labels_in(text))


def cut_secrets(text: str, values: list[tuple[str, str]]) -> str:
    """text with every copy redact_text() would redact, once the (value, label) pairs are registered too,
    replaced by NUL, so the pieces left cannot join up (env.get checks what is left, R8C-1)."""
    cur, reg = current_registry(), SecretRegistry()
    reg.secrets.update(cur.secrets)
    reg.labels.update(cur.labels)
    reg.views.update(cur.views)
    with use_registry(reg):
        for value, label in values:
            register_secret(value, label)
    return redact_text(text, reg, replace="\0")


def has_secrets() -> bool:
    return bool(current_registry().labels)


def redact_spans(text: str, reg: SecretRegistry | None = None, extra: dict | None = None) -> list:
    """The spans redact_text() replaces: sorted, disjoint [start, end, [marker, ...]] in text (R9-4: overlapping
    matches are merged and keep every marker; a match inside another one keeps the outer marker)."""
    reg = reg or current_registry()
    if not (reg.secrets or extra) or not isinstance(text, str):
        return []
    out = str.__str__(text)
    spans: list[tuple[int, int, str]] = []
    for table in (extra or {}, reg.secrets):
        for form, mark in table.items():
            i = out.find(form)
            while i >= 0:
                spans.append((i, i + len(form), mark))
                i = out.find(form, i + 1)
    if reg.views:
        view, vmap = search_view(out)
        for v, mark in reg.views.items():
            i = view.find(v)
            while i >= 0:
                spans.append((*_orig_span(vmap, i, i + len(v)), mark))
                i = view.find(v, i + 1)
    spans.sort(key=lambda x: (x[0], -x[1]))           # at one start, the longest match first
    merged: list = []
    for s, e, mark in spans:
        cur = merged[-1] if merged else None
        if cur is not None and s < cur[1]:
            if e > cur[1]:                             # overlaps past the end: both markers stand for the span
                cur[1] = e
                if mark not in cur[2]:
                    cur[2].append(mark)
            continue                                   # a match inside another one: the outer marker only
        merged.append([s, e, [mark]])
    return merged


def redact_text(text: str, reg: SecretRegistry | None = None, extra: dict | None = None,
                replace: str | None = None) -> str:
    """text with every copy of a registered secret (any registered form, or a plain form found in the search
    view) replaced by its «secret:NAME» marker (or by `replace`). R9-4 (round 9): the union of all matches is
    replaced, so two overlapping secrets leave no part of either in clear. extra: more value -> marker pairs."""
    reg = reg or current_registry()
    if not (reg.secrets or extra) or not isinstance(text, str):
        return text
    out = str.__str__(text)
    spans = redact_spans(out, reg, extra)
    if not spans:
        return out
    parts, pos = [], 0
    for s, e, marks in spans:
        parts.append(out[pos:s] + (replace if replace is not None else "".join(marks)))
        pos = e
    parts.append(out[pos:])
    return "".join(parts)


def escape_text(text: str) -> str:
    """One printable line: line breaks, tabs, ESC and other control chars, bidi overrides and every other
    non-printable char are shown as escapes (\\n, \\x1b, \\u202e), so text from a program, model or journal
    cannot draw fake lines or recolour a terminal. A backslash is doubled only when escapes are added."""
    text = str.__str__(text) if isinstance(text, str) else str(text)
    if text.isprintable():
        return text
    out = []
    for ch in text:
        if ch.isprintable():
            out.append("\\\\" if ch == "\\" else ch)
        elif ch in "\n\r\t":
            out.append({"\n": "\\n", "\r": "\\r", "\t": "\\t"}[ch])
        else:
            o = ord(ch)
            out.append(f"\\x{o:02x}" if o < 0x100 else f"\\u{o:04x}" if o < 0x10000 else f"\\U{o:08x}")
    return "".join(out)


_CONTROLS = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b\u200e\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
TERM_RESET = "\x1b[0m\x1b[?25h"       # SGR reset + show cursor: undo whatever earlier output switched on


def escape_controls(text: str) -> str:
    """Text for a terminal (S3, round 5): C0 controls except line feed and tab, DEL, C1 controls, bidi
    controls and (R9-3) the invisible U+200B, U+2060..U+2064 and U+FEFF are shown as \\x1b / \\u202e, so
    text from a model, server or file cannot recolour, hide, retitle or rewrite the screen. Everything else (backslashes too) is unchanged."""
    text = str.__str__(text) if isinstance(text, str) else str(text)
    return _CONTROLS.sub(lambda m: f"\\x{ord(m.group()):02x}" if ord(m.group()) < 0x100
                         else f"\\u{ord(m.group()):04x}", text)


def is_tty(stream) -> bool:
    tty = getattr(stream, "isatty", None)
    if tty is None:
        return False
    try:
        return bool(tty())
    except (OSError, ValueError):       # closed or detached stream
        return False


def flush(stream) -> None:
    """Flush an output stream if it can be flushed: an API `out=` writer needs only write() (SPEC §10; M2,
    round 6)."""
    fl = getattr(stream, "flush", None)
    if callable(fl):
        fl()


def clip(text: str, n: int, partial: bool = False) -> str:
    """Redact, then cut to n chars: cutting first could leave a secret's prefix that no longer matches.
    partial=True: text was already cut at its end by the caller (a read limit), so a tail that could be the
    start of a secret is dropped too."""
    text = str(text)
    secrets = current_registry().secrets
    if partial and secrets:
        text = text.rstrip("\ufffd")          # a multi-byte char cut by the read limit
        for form in secrets:
            for k in range(min(len(form) - 1, len(text)), 0, -1):
                if text.endswith(form[:k]):
                    text = text[:-k]
                    break
    return redact_text(text)[:n]


_NUMBER = re.compile(r"(?<![A-Za-z_\d.])-?(?:\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?|nan|inf)(?![A-Za-z_\d])")


def mask_numbers(text: str, mark: str) -> str:
    """Every number in text (also `nan`, `inf`) replaced by mark."""
    return _NUMBER.sub(mark, text)


class SiparRuntimeError(Exception):
    """A Sipar-level error value: catchable with try/catch as Error { kind, message }.
    `.message` is always redacted (no registered secret value can be read from it)."""

    KINDS = {"type", "decode", "taint", "capability", "budget", "denied", "replay", "ai", "io",
             "assert", "user", "index", "key", "zero", "value", "mcp"}

    def __init__(self, kind: str, message: str, line: int = 0, col: int = 0, file: str = ""):
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.line = line
        self.col = col
        self.file = file
        self.labels: frozenset = frozenset()   # labels of the operands the message was built from (SPEC §6)
        self._reg = current_registry()         # the run's secrets: redaction still works after the run ends

    def secret_labels(self) -> list:
        return sorted(l for l in self.labels if l.startswith("secret:"))

    @property
    def kind(self) -> str:                    # fail(kind, ...) takes the kind from program text: redact it too
        return redact_text(self._kind, getattr(self, "_reg", None))

    @kind.setter
    def kind(self, value: str) -> None:
        self._kind = str(value)

    @property
    def message(self) -> str:
        """The text that leaves the runtime (stderr, journal, Python API, tool errors fed to a model). When the
        error was built from secret-labelled operands, every number in it is replaced by «secret:NAME»: a size,
        index or bound computed from a secret must not be readable (SPEC §6)."""
        text = redact_text(self._message, getattr(self, "_reg", None))
        sec = self.secret_labels()
        return mask_numbers(text, "«" + ",".join(sec) + "»") if sec else text

    @message.setter
    def message(self, value: str) -> None:
        self._message = str(value)

    @property
    def args(self) -> tuple:                  # repr(e), tracebacks and pickling see the redacted text too
        return (self.message,)

    @args.setter
    def args(self, value) -> None:
        pass

    def __str__(self) -> str:
        return self.message

    def __repr__(self) -> str:
        return f"SiparRuntimeError({self.kind!r}, {self.message!r})"

    def render(self) -> str:
        where = f"{self.file}:{self.line}:{self.col}: " if self.line and self.file else ""   # no ":1:1:" without a file
        # error output is diagnostics, never program data: control characters are always escaped (S3, round 5)
        return escape_controls(f"{where}runtime error[{self.kind}]: {self.message}")
