"""Parser and checker support for MCP servers (SPEC.md §7 MCP). Kept out of parser.py and checker.py so those
files only carry one-line hooks.

    allow mcp "fs" ["npx", "-y", "@modelcontextprotocol/server-filesystem", "./data"]
        tools ["read_text_file", "write_file"] readonly ["read_text_file"] pin "sha256:<64 hex>"

    mcp.fs.read_text_file(path: "notes.txt")             # Str (or a typed value: let s: Stats = mcp.fs.stats(...))
    mcp.call("fs", "read_text_file", {"path": "x"})      # Str; the tool by its MCP name
    agent fn helper(q: Str) -> Str uses ai, mcp { tools [mcp.fs.read_text_file] }
"""
from __future__ import annotations

import re
from typing import Any, Optional

from . import ast as A
from .types import ANY, NEVER, NONE, STR, UNKNOWN, OptT, has_tvar, has_unknown, ty_to_te

SERVER_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
PIN_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RESERVED = {"call"}
EXAMPLE = 'allow mcp "fs" ["npx", "-y", "@modelcontextprotocol/server-filesystem", "."] tools ["read_text_file"]'


def ident(tool: str) -> str:
    """The Sipar name of an MCP tool (same rule as sipar.runtime.mcp.ident)."""
    s = re.sub(r"[^A-Za-z0-9_]", "_", tool)
    return "_" + s if not s or s[0].isdigit() else s


# ------------------------------------------------------------------ parser

def _str_list(p, what: str) -> list[str]:
    p.expect("[", hint=EXAMPLE)
    out: list[str] = []
    while not p.at("]"):
        out.append(_str(p, what))
        if not p.at("]"):
            p.expect(",")
    p.expect("]")
    return out


def _str(p, what: str) -> str:
    if not p.at("str"):
        raise p.err(f"{what} must be a string literal", hint=EXAMPLE)
    lit = p.string_lit(p.adv())
    if any(not isinstance(x, str) for x in lit.parts):
        raise p.err(f"{what} cannot use interpolation", hint=EXAMPLE)
    return "".join(lit.parts)


def _clause(p) -> Optional[str]:
    """The next clause keyword (tools / readonly / pin), also when it starts the next line."""
    j = 0
    while p.peek(j).kind == "newline":
        j += 1
    t = p.peek(j)
    if t.kind == "tools" and p.peek(j + 1).kind == "[":
        name = "tools"
    elif t.kind == "ident" and (t.value, p.peek(j + 1).kind) in (("readonly", "["), ("pin", "str")):
        name = t.value
    else:
        return None
    for _ in range(j):
        p.adv()
    return name


def parse_allow(p, s) -> A.Allow:
    """After `allow mcp`: "name" [command...] tools [...] [readonly [...]] [pin "sha256:..."]."""
    name = _str(p, "the MCP server name")
    if not p.at("["):
        raise p.err("`allow mcp` needs the command that starts the server, as a list of strings", hint=EXAMPLE)
    command = _str_list(p, "an MCP server command part")
    got: dict[str, Any] = {}
    while True:
        c = _clause(p)
        if c is None:
            break
        if c in got:
            raise p.err(f"`{c}` appears twice in this `allow mcp` line", hint=EXAMPLE)
        p.adv()
        got[c] = _str(p, "the pin") if c == "pin" else _str_list(p, f"a {c} entry")
    if "tools" not in got:
        raise p.err(f"`allow mcp {name!r}` must list the tools it allows: tools [\"...\"]", hint=EXAMPLE)
    p.end_stmt()
    return A.Allow(s.line, s.col, "mcp", command, server=name, tools=got["tools"], readonly=got.get("readonly"),
                   pin=got.get("pin"))


def parse_tool(p, first: str) -> str:
    """`tools [mcp.fs.read_text_file]`: after the first name, any `.name` parts."""
    parts = [first]
    while p.at("."):
        p.adv()
        parts.append(p.expect_ident("MCP tool name").value)
    return ".".join(parts)


# ------------------------------------------------------------------ checker

def servers(ck) -> dict[str, A.Allow]:
    s = getattr(ck, "_mcp_servers", None)
    if s is None:
        s = ck._mcp_servers = {}
        for it in ck.p.items:
            if isinstance(it, A.Allow) and it.cap == "mcp" and it.server is not None:
                s.setdefault(it.server, it)
    return s


def check_allow(ck, it: A.Allow) -> None:
    ck.allowed.setdefault("mcp", it)
    name = it.server
    if name is None:
        return ck.err("E310", it, "`allow mcp` needs a server name, a command and a tools list", EXAMPLE)
    if not SERVER_NAME.match(name) or name in RESERVED:
        ck.err("E310", it, f"MCP server name {name!r} must be an identifier (letters, digits, _), not `call`",
               'allow mcp "fs" [...] tools [...]   then call mcp.fs.<tool>(...)')
    if servers(ck).get(name) is not it:
        ck.err("E310", it, f"MCP server {name!r} is allowed twice", "merge the two `allow mcp` lines into one")
    if not it.scopes or not it.scopes[0].strip():
        ck.err("E310", it, f"`allow mcp {name!r}` has an empty command", EXAMPLE)
    tools = it.tools or []
    if not tools:
        ck.err("E310", it, f"`allow mcp {name!r}` allows no tools", "list the tools the program may call")
    seen: dict[str, str] = {}
    for t in tools:
        if not t:
            ck.err("E310", it, f"`allow mcp {name!r}` lists an empty tool name")
            continue
        i = ident(t)
        if i in seen and seen[i] == t:
            ck.err("E310", it, f"`allow mcp {name!r}` lists tool {t!r} twice", "list each tool once")
        elif i in seen:
            ck.err("E310", it, f"MCP tools {seen[i]!r} and {t!r} of server {name!r} both become mcp.{name}.{i}",
                   "list only one of them (or call the other with mcp.call)")
        seen[i] = t
    for r in it.readonly or []:
        if r not in tools:
            ck.err("E310", it, f"readonly tool {r!r} is not in the tools list of `allow mcp {name!r}`",
                   "readonly lists a subset of tools")
    if it.pin is not None and not PIN_RE.match(it.pin):
        ck.err("E310", it, f"bad pin {it.pin!r}", 'pin "sha256:<64 lowercase hex digits>"; `sipar run` prints '
               'the right value when it does not match')


def _server(ck, name: str, node, code: str = "E205") -> Optional[A.Allow]:
    from .checker import similar
    a = servers(ck).get(name)
    if a is None:
        ck.err(code, node, f"no MCP server {name!r}: there is no `allow mcp {name!r} [...]` line",
               similar(name, servers(ck)) or EXAMPLE)
    return a


def _tool(ck, a: A.Allow, tool: str, node, by_ident: bool, code: str = "E205") -> Optional[str]:
    from .checker import similar
    names = {ident(t): t for t in a.tools or []} if by_ident else {t: t for t in a.tools or []}
    real = names.get(tool)
    if real is None:
        ck.err(code, node, f"MCP tool {tool!r} is not in the tools list of `allow mcp {a.server!r}`",
               similar(tool, names) or f"add it to the line: tools [\"{tool}\"]")
    return real


def is_dotted(ck, c) -> bool:
    return isinstance(c, A.Field) and isinstance(c.obj, A.Field) and isinstance(c.obj.obj, A.Name) \
        and c.obj.obj.name == "mcp" and ck.lookup_var("mcp") is None


def is_call(ck, c) -> bool:
    return isinstance(c, A.Field) and c.name == "call" and isinstance(c.obj, A.Name) and c.obj.name == "mcp" \
        and ck.lookup_var("mcp") is None


def check_call(ck, e: A.Call, exp):
    """Checker hook for mcp.<server>.<tool>(...) and mcp.call(...). None: not an MCP call."""
    c = e.callee
    if is_call(ck, c):
        res = ck.call_builtin("mcp.call", e, exp)
        pos = [a.value for a in e.args if a.name is None]
        named = {a.name: a.value for a in e.args if a.name is not None}
        srv, tool = named.get("server", pos[0] if pos else None), named.get("tool", pos[1] if len(pos) > 1 else None)
        lit = lambda x: "".join(x.parts) if isinstance(x, A.StrLit) and all(isinstance(q, str) for q in x.parts) \
            else None
        if lit(srv) is not None:
            a = _server(ck, lit(srv), srv)
            if a is not None and lit(tool) is not None:
                _tool(ck, a, lit(tool), tool, by_ident=False)
        return res
    if not is_dotted(ck, c):
        return None
    what = f"mcp.{c.obj.name}.{c.name}"
    ck.use_effect("mcp", c.obj.obj, what)
    a = _server(ck, c.obj.name, c.obj)
    if a is not None:
        _tool(ck, a, c.name, c, by_ident=True)
    for arg in e.args:
        t = ck.expr(arg.value)
        if arg.name is None:
            ck.err("E212", arg.value, f"{what} takes named arguments only", f'{what}(path: "notes.txt")')
        elif t not in (UNKNOWN, NEVER) and not has_unknown(t) and not ck.jsonable(t):
            ck.err("E212", arg.value, f"argument `{arg.name}` of {what} is {t}, which cannot be sent as JSON",
                   "MCP arguments must be JSON-able: Int Float Str Bool none, lists, maps, records, enums")
    t = exp.inner if isinstance(exp, OptT) else exp
    if t is None or t in (STR, ANY, NONE, NEVER) or has_unknown(t) or has_tvar(t) or not ck.jsonable(t):
        return STR
    e.mcp_type = ty_to_te(t)
    return t


def check_tool(ck, info, name: str) -> None:
    """`tools [mcp.fs.read_text_file]` in an agent fn."""
    d = info.decl
    parts = name.split(".")
    if len(parts) != 3:
        return ck.err("E203", d, f"bad MCP tool `{name}` in {info.title}", "write tools [mcp.<server>.<tool>]")
    a = _server(ck, parts[1], d, "E203")
    if a is None:
        return
    real = _tool(ck, a, parts[2], d, by_ident=True, code="E203")
    if real is None:
        return
    if real not in (a.readonly or []):
        ck.err("E232", d, f"MCP tool `{name}` is not listed as readonly, so an agent cannot use it: the model "
               "chooses its arguments, and they are untrusted",
               f"add it to `readonly [...]` if it only reads, or wrap it in a fn that uses approve()")
    if "mcp" not in info.effects:
        ck.err("E301", d, f"{info.title} uses `mcp` through its tool `{name}` but does not declare it",
               f"add `uses mcp` to {info.title}")
