"""`ai fn` and `agent fn`: schema, prompts, robust JSON extraction, validation, retries, tool loop."""
from __future__ import annotations

import json
import re
from typing import Any

from .. import ast as A
from ..errors import SiparRuntimeError
from . import mcp as MCP
from .decode import DECODER, PY_DECODER, from_json, json_loads, schema, type_str
from .values import deep_label, dumps, mark_secrets, render, secrets_in, to_json, with_labels

FENCE = re.compile(r"```[A-Za-z0-9_+-]*[ \t]*\n?(.*?)```", re.S)
# a number standing alone: not glued to letters, digits, "." or "-" ("payload2", "v2.0", "x-1", "1.2.3" are not numbers)
NUMBER = re.compile(r"(?<![\w.\-])-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?(?![\w\-]|\.\d)")


def attr_values(decl: A.FnDecl) -> dict:
    out = {}
    for a in decl.attrs:
        v = a.value
        if isinstance(v, A.StrLit):
            out[a.name] = "".join(p for p in v.parts if isinstance(p, str))
        else:
            out[a.name] = getattr(v, "value", None)
    return out


def signature(decl: A.FnDecl) -> str:
    ps = ", ".join(f"{p.name}: {type_str(p.type)}" for p in decl.params)
    return f"{decl.name}({ps}) -> {type_str(decl.ret)}"


def is_raw_str(t: A.TypeExpr | None) -> bool:
    return isinstance(t, A.TName) and t.name == "Str"


# ------------------------------------------------------------------ JSON extraction

def json_candidates(text: str, limit: int = 40) -> list[Any]:
    """Parsed JSON values found in a model reply, best first: whole text, fenced blocks, embedded {...}/[...]."""
    t = text.strip()
    out: list[Any] = []
    try:
        out.append(json_loads(t))
    except (ValueError, RecursionError):
        pass
    for m in FENCE.finditer(t):
        try:
            out.append(json_loads(m.group(1).strip()))
        except (ValueError, RecursionError):
            pass
    dec = DECODER
    limit = min(limit, max(1, 2_000_000 // max(len(t), 1)))     # bound the work on huge replies
    tries = 0
    for i, ch in enumerate(t):
        if ch in "{[":
            tries += 1
            if tries > limit:
                break
            try:
                try:
                    obj, _ = dec.raw_decode(t, i)
                except RecursionError:      # Python 3.12's C scanner: retry in Python (round 5, D3)
                    obj, _ = PY_DECODER.raw_decode(t, i)
                out.append(obj)
            except ValueError:
                continue
            except RecursionError:      # nested too deeply: later starts are inside the same nest, stop scanning
                break
    return out


def _prose_numbers(text: str, t: A.TypeExpr) -> set:
    """The distinct numbers in a prose reply for an Int or Float return type (else none)."""
    inner = t.inner if isinstance(t, A.TOptional) else t
    s = text.strip().strip("`").strip()
    if isinstance(inner, A.TName) and inner.name in ("Int", "Float") and s[:1] not in "{[":
        return {json_loads(m) for m in NUMBER.findall(s)}       # a huge one is a HugeInt: `value` for Int
    return set()


def _scalar_fallbacks(text: str, t: A.TypeExpr) -> list[Any]:
    inner = t.inner if isinstance(t, A.TOptional) else t
    s = text.strip().strip("`").strip()
    out: list[Any] = []
    if isinstance(t, A.TOptional) and s.lower() in ("none", "null"):
        out.append(None)
    if isinstance(inner, A.TName):
        if inner.name in ("Int", "Float"):
            nums = _prose_numbers(text, t)
            if len(nums) == 1:         # "The answer is 42." -> 42; ambiguous prose ("3 or 4") -> retry
                out.append(nums.pop())
        elif inner.name == "Bool":
            w = s.lower().strip(".! ")
            if w in ("true", "yes"):
                out.append(True)
            elif w in ("false", "no"):
                out.append(False)
        else:
            word = s.strip('"\'. ')
            if "." in word:
                word = word.rsplit(".", 1)[1]
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", word):
                out.append(word)      # bare enum variant
    return out


def decode_reply(text: str, ret: A.TypeExpr | None, tenv, labels: frozenset) -> Any:
    """Model text -> value of type ret carrying `labels`; an echoed secret gets its `secret:` label (SPEC §6)."""
    return mark_secrets(_decode_reply(text, ret, tenv, labels))


def _decode_reply(text: str, ret: A.TypeExpr | None, tenv, labels: frozenset) -> Any:
    if is_raw_str(ret):
        t = text.strip()
        fm = FENCE.fullmatch(t)
        if fm:
            t = fm.group(1).strip()
        if len(t) >= 2 and t[0] == '"' and t[-1] == '"':
            try:
                v = json.loads(t)
                if isinstance(v, str):
                    t = v
            except ValueError:
                pass
        return with_labels(t, labels)
    try:
        return _decode_candidates(text, ret, tenv, labels)
    except (ValueError, OverflowError, RecursionError, TypeError, KeyError, IndexError) as e:
        # model text must never cause an internal error: whatever Python raised, it is a decode failure
        raise SiparRuntimeError("decode", f"the reply could not be decoded ({type(e).__name__})")


def _decode_candidates(text: str, ret: A.TypeExpr | None, tenv, labels: frozenset) -> Any:
    first_err: SiparRuntimeError | None = None
    cands = json_candidates(text) + _scalar_fallbacks(text, ret)
    for c in cands:
        try:
            return from_json(c, ret, tenv, labels)
        except SiparRuntimeError as e:
            if e.kind != "decode":
                raise
            first_err = first_err or e
    if first_err is not None:
        raise first_err
    if len(_prose_numbers(text, ret)) > 1:         # "12 and 13" (round 9, F3: it said "no JSON value found")
        raise SiparRuntimeError("decode", "more than one number in the reply; expected exactly one")
    raise SiparRuntimeError("decode", "no JSON value found in the reply")


# ------------------------------------------------------------------ ai fn

def system_prompt(decl: A.FnDecl, tenv) -> str:
    lines = [f"You are the body of the function `{signature(decl)}` in a Sipar program."]
    if decl.doc:
        lines.append(f"Purpose: {decl.doc.strip()}")
    if is_raw_str(decl.ret):
        lines.append("Reply with only the answer text, no preamble.")
    else:
        lines.append("Reply with ONLY a JSON value matching this JSON schema (no prose, no code fences):")
        lines.append(json.dumps(schema(decl.ret, tenv), ensure_ascii=False))
    extra = attr_values(decl).get("system")
    if extra:
        lines.append(str(extra))
    return "\n".join(lines)


def _check_prompt(fn: str, prompt: Any) -> None:
    sec = secrets_in(prompt)
    if sec:
        raise SiparRuntimeError("taint", f"{', '.join(sec)} cannot flow into the prompt of {fn}()")


def run_ai(rt, decl: A.FnDecl, prompt: Any) -> Any:
    _check_prompt(decl.name, prompt)
    attrs = attr_values(decl)
    retries = attrs.get("retries", 2)
    if isinstance(retries, bool) or not isinstance(retries, int) or retries < 0:      # checker: E231
        raise SiparRuntimeError("type", f"@retries on {decl.name}() must be an Int >= 0, got {retries!r}")
    temp = attrs.get("temperature")
    labels = frozenset({f"untrusted:ai:{decl.name}"})
    sch = None if is_raw_str(decl.ret) else schema(decl.ret, rt.tenv)
    messages = [{"role": "system", "content": system_prompt(decl, rt.tenv)},
                {"role": "user", "content": str(prompt)}]
    hint = {"fn": decl.name, "schema": sch, "raw_text": sch is None, "agent": False}
    last = ""
    for attempt in range(retries + 1):
        text = rt.ai_call("ai", decl, list(messages), temp, hint)
        try:
            return decode_reply(text, decl.ret, rt.tenv, labels)
        except SiparRuntimeError as e:
            if e.kind != "decode":
                raise
            last = e.message
            messages.append({"role": "assistant", "content": text})
            messages.append({"role": "user", "content": f"Your reply was invalid: {e.message}\n"
                                                        "Reply again with ONLY the JSON value matching the schema."})
    raise SiparRuntimeError("ai", f"{decl.name}: the model reply did not match {type_str(decl.ret)} after "
                                  f"{retries + 1} attempt(s): {last}")


# ------------------------------------------------------------------ agent fn

def tool_spec(t: A.FnDecl, tenv) -> dict:
    props = {p.name: schema(p.type, tenv) for p in t.params}
    return {"name": t.name, "description": (t.doc or "").strip(),
            "parameters": {"type": "object", "properties": props, "required": [p.name for p in t.params]},
            "returns": type_str(t.ret)}


def agent_system_prompt(decl: A.FnDecl, tools: list[A.FnDecl], tenv) -> str:
    final_schema = {"type": "string"} if is_raw_str(decl.ret) else schema(decl.ret, tenv)
    lines = [f"You are the agent `{signature(decl)}` in a Sipar program.",
             "You can call these tools (JSON):",
             json.dumps([t.spec() if getattr(t, "is_mcp", False) else tool_spec(t, tenv) for t in tools],
                        ensure_ascii=False),
             "Each turn reply with exactly ONE JSON object and nothing else:",
             '  {"tool": "<tool name>", "args": {...}}   to call a tool (you will get its result), or',
             '  {"final": <answer>}   when done; <answer> must match this JSON schema:',
             json.dumps(final_schema, ensure_ascii=False)]
    if decl.doc:
        lines.insert(1, f"Purpose: {decl.doc.strip()}")
    extra = attr_values(decl).get("system")
    if extra:
        lines.append(str(extra))
    return "\n".join(lines)


def _protocol_obj(text: str) -> dict | None:
    for c in json_candidates(text):
        if isinstance(c, dict) and ("tool" in c or "final" in c):
            return c
    return None


FATAL_TOOL_ERRORS = {"taint", "capability", "budget", "replay", "denied"}


def run_agent(rt, decl: A.FnDecl, prompt: Any) -> Any:
    _check_prompt(decl.name, prompt)
    attrs = attr_values(decl)
    max_steps = attrs.get("max_steps", 10)
    if isinstance(max_steps, bool) or not isinstance(max_steps, int) or max_steps <= 0:   # checker: E231
        raise SiparRuntimeError("type", f"@max_steps on {decl.name}() must be an Int > 0, got {max_steps!r}")
    temp = attrs.get("temperature")
    tools = []
    for name in decl.tools:
        t = MCP.AgentTool(rt, name) if name.startswith("mcp.") else rt.fns.get(name)
        if t is None:
            raise SiparRuntimeError("type", f"agent {decl.name}: unknown tool {name!r}")
        tools.append(t)
    by_name = {t.name: t for t in tools}
    labels = frozenset({f"untrusted:ai:{decl.name}"})
    final_schema = {"type": "string"} if is_raw_str(decl.ret) else schema(decl.ret, rt.tenv)
    messages = [{"role": "system", "content": agent_system_prompt(decl, tools, rt.tenv)},
                {"role": "user", "content": str(prompt)}]
    hint = {"fn": decl.name, "schema": final_schema, "agent": True}

    def feedback(msg: str) -> None:
        messages.append({"role": "user", "content": msg})

    for step in range(1, max_steps + 1):
        text = rt.ai_call("agent", decl, list(messages), temp, dict(hint, step=step))
        messages.append({"role": "assistant", "content": text})
        obj = _protocol_obj(text)
        if obj is None:
            feedback('Invalid reply. Reply with exactly one JSON object: {"tool": name, "args": {...}} '
                     'or {"final": answer}.')
            continue
        if "final" in obj:
            fv = obj["final"]
            try:
                if is_raw_str(decl.ret):
                    return mark_secrets(with_labels(fv if isinstance(fv, str) else dumps(fv), labels))
                return mark_secrets(from_json(fv, decl.ret, rt.tenv, labels))
            except SiparRuntimeError as e:
                if e.kind != "decode":
                    raise
                feedback(f"Your final answer is invalid: {e.message}. It must match {type_str(decl.ret)}.")
                continue
        name = obj.get("tool")
        tool = by_name.get(name) if isinstance(name, str) else None
        if tool is None:
            feedback(f"Unknown tool {str(name)[:60]!r}. Available tools: {', '.join(by_name) or 'none'}.")
            continue
        raw_args = obj.get("args", {})
        if raw_args is None:
            raw_args = {}
        if not isinstance(raw_args, dict):
            feedback(f"'args' for {name} must be a JSON object.")
            continue
        try:
            extra = [k for k in raw_args if k not in {p.name for p in tool.params}]
            if extra:
                raise SiparRuntimeError("decode", f"unknown argument(s) {extra} for {name}")
            args = {}
            for p in tool.params:
                if p.name not in raw_args and not isinstance(p.type, A.TOptional):
                    raise SiparRuntimeError("decode", f"missing argument '{p.name}' for {name}")
                args[p.name] = mark_secrets(from_json(raw_args.get(p.name), p.type, rt.tenv, labels,
                                                      f"args.{p.name}"))
        except SiparRuntimeError as e:
            if e.kind != "decode":
                raise
            feedback(f"Bad arguments for {name}: {e.message}")
            continue
        try:
            result = tool.call(rt, args) if getattr(tool, "is_mcp", False) else rt.call_fn(tool, [], args)
        except SiparRuntimeError as e:
            if e.kind in FATAL_TOOL_ERRORS or getattr(e, "fatal", False):
                raise
            feedback(f"Tool {name} failed with error [{e.kind}]: {e.message}")
            continue
        sec = secrets_in(result)
        if sec:
            raise SiparRuntimeError("taint", f"{', '.join(sec)} returned by tool {name} cannot flow into the "
                                             f"prompt of agent {decl.name}")
        feedback(f"Result of {name}: {dumps(to_json(result))}")
    raise SiparRuntimeError("ai", f"agent {decl.name}: no final answer after {max_steps} steps (max_steps)")
