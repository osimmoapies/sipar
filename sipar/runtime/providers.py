"""Model providers. `complete(messages, model, temperature, timeout, hint) -> (text, usage)`.

usage = {"input": prompt_tokens, "output": completion_tokens}.
Providers: mock (deterministic, scriptable), and OpenAI-compatible chat completions over urllib for
openrouter, openai, gemini and local (LM Studio / llama.cpp / Ollama OpenAI endpoints).
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from ..errors import SiparRuntimeError, clip, register_secret
from ..fileread import MAX_FILE_BYTES, read_text, why_unreadable
from . import jsondeep, netio
from .decode import TOO_DEEP, too_deep
from .values import scrub_text

BASES = {
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY"),
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai", "GEMINI_API_KEY"),
    "local": (None, None),
}
# R9-5 (round 9): the variables that hold provider API keys. The runtime reads them for ai calls; a program may
# read one only with `allow secret` + env.secret (labelled), never with env.get, and no other variable or command
# environment may carry a copy of one (effects.Caps.guarded_names).
KEY_ENVS = tuple(k for _, k in BASES.values() if k) + ("SIPAR_LOCAL_KEY",)


def parse_model(spec: str) -> tuple[str, str]:
    """'openrouter/qwen/qwen3-coder' -> ('openrouter', 'qwen/qwen3-coder'); 'mock' -> ('mock', '')."""
    spec = (spec or "").strip()
    if not spec:
        raise SiparRuntimeError("ai", "empty model name")
    prov, _, model = spec.partition("/")
    if prov == "mock":
        return "mock", model
    if prov not in BASES:
        raise SiparRuntimeError("ai", f"unknown model provider {prov!r} in {spec!r}; use openrouter/, openai/, "
                                      "gemini/, local/ or mock")
    if not model:
        raise SiparRuntimeError("ai", f"model {spec!r} needs a model name after '{prov}/'")
    return prov, model


def parse_chain(spec: str) -> list[str]:
    """'openrouter/a | gemini/b | mock' -> ['openrouter/a', 'gemini/b', 'mock'] (each one validated)."""
    parts = [p.strip() for p in (spec or "").split("|")]
    if parts == [""]:
        raise SiparRuntimeError("ai", "empty model name")
    if "" in parts:                     # also " | | " (round 9, F4: it said "empty model name")
        raise SiparRuntimeError("ai", f"model chain {spec.strip()!r} has an empty entry; write "
                                      "\"provider/model | provider/model\"")
    for p in parts:
        parse_model(p)
    return parts


def estimate_tokens(text: str) -> int:
    return len(text) // 4 + 1


MAX_USAGE = 10_000_000      # tokens per call; a larger (or negative, non-Int) count from a provider is not believed


def valid_count(v: Any) -> bool:
    return type(v) is int and 0 <= v <= MAX_USAGE


def clean_usage(usage: Any, prompt_text: str, text: str) -> dict:
    """{"input", "output"} token counts: the provider's numbers when they are sane Ints, else chars/4 estimates,
    so a hostile or broken provider cannot switch off a token budget."""
    u = usage if isinstance(usage, dict) else {}
    return {k: (u.get(k) if valid_count(u.get(k)) else estimate_tokens(src))
            for k, src in (("input", prompt_text), ("output", text))}


def prompt_text(messages: list[dict]) -> str:
    return "".join(str(m.get("content", "")) for m in messages if isinstance(m, dict))


# ------------------------------------------------------------------ mock

def default_for_schema(s: dict) -> Any:
    if "anyOf" in s:
        alts = s["anyOf"]
        for a in alts:
            if a.get("type") == "null":
                return None
        return default_for_schema(alts[0])
    if "const" in s:
        return s["const"]
    if "enum" in s:
        return s["enum"][0]
    t = s.get("type")
    if t == "integer":
        return 0
    if t == "number":
        return 0.0
    if t == "string":
        return "mock"
    if t == "boolean":
        return False
    if t == "null":
        return None
    if t == "array":
        return []
    if t == "object":
        props = s.get("properties")
        if props is None:
            return {}
        return {k: default_for_schema(v) for k, v in props.items()}
    return None


SCRIPT_SHAPE = "must be a JSON list of replies or an object {fn name: [replies]}"


def json_type(x: Any) -> str:
    """The JSON name of a value's type (an error message talks JSON, not Python: "number", not "int")."""
    if x is None:
        return "null"
    if isinstance(x, bool):
        return "a boolean"
    if isinstance(x, (int, float)):
        return "a number"
    if isinstance(x, str):
        return "a string"
    return "a list" if isinstance(x, list) else "an object" if isinstance(x, dict) else type(x).__name__


class _NotJson(ValueError):
    pass


def _no_constant(name: str) -> Any:
    raise _NotJson(name)


def load_script(path: str) -> Any:
    """The SIPAR_MOCK_SCRIPT file: a JSON list or object, or error kind `ai` "cannot load SIPAR_MOCK_SCRIPT
    <path>: <why>" for every other file (missing, unreadable, not UTF-8, empty, not JSON, null or a scalar).
    A UTF-8 byte-order mark (Windows editors write one) is skipped, as in Sipar source (SPEC §2)."""
    why = None
    try:            # round 8: a FIFO hung here; a device or a file over 256 MB is refused, never read
        text = read_text(path, MAX_FILE_BYTES, encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as e:
        why = why_unreadable(e)
    if why is None:
        try:
            # empty: said below, not "expecting value"; NaN / Infinity are not JSON (as for mock_script=)
            script = jsondeep.loads(text, parse_constant=_no_constant) if text.strip() else None
        except jsondeep.NumberTooLarge as e:
            why = f"it holds {e}"
        except _NotJson as e:
            why = f"not valid JSON ({e} is not a JSON value)"
        except ValueError as e:
            pos = f" (line {e.lineno} column {e.colno}: {e.msg[:1].lower() + e.msg[1:]})" \
                if isinstance(e, json.JSONDecodeError) else ""
            why = f"not valid JSON{pos}"
        except RecursionError:
            why = TOO_DEEP
        else:
            if not text.strip():
                why = "the file is empty; it " + SCRIPT_SHAPE
            elif not isinstance(script, (list, dict)):
                why = f"it {SCRIPT_SHAPE}, not {json_type(script)}"
            elif too_deep(script):      # R8C-7 (round 8): parsed on a deep stack, it failed later as "recursion too deep"
                why = TOO_DEEP
            else:
                return script
    raise SiparRuntimeError("ai", clip(f"cannot load SIPAR_MOCK_SCRIPT {path}: {why}", 2000))


class MockProvider:
    """Deterministic provider. Script: a list of replies (global queue) or {fn_name: [replies]}.
    Non-string replies are JSON-encoded. Set SIPAR_MOCK_SCRIPT=path.json to script it from the CLI.
    Without a script every call gets a schema-valid default (for agents: {"final": default}). With a script the
    mock is strict (M5, round 6): a call with no scripted reply left fails with error[ai] (naming the invalid
    reply that used up the retries, if any), so a wrong script never passes silently as the default answer."""

    name = "mock"

    def __init__(self, script: Any = None):
        if script is None:
            path = os.environ.get("SIPAR_MOCK_SCRIPT")
            if path:            # round 7: every bad file is this one error, never a silent unscripted mock
                script = load_script(path)
        script = scrub_text(script)                 # replies never hold a lone surrogate (round 5, C2)
        self.scripted = script is not None
        if isinstance(script, list):
            self.queue: list | None = list(script)
            self.by_fn: dict = {}
        elif isinstance(script, dict):
            self.queue = None
            self.by_fn = {k: list(v) if isinstance(v, list) else [v] for k, v in script.items()}
        elif script is None:
            self.queue, self.by_fn = None, {}
        else:                                       # M5 (round 6): not silently "no reply left" on every call
            raise SiparRuntimeError("ai", f"the mock script (mock_script / SIPAR_MOCK_SCRIPT) {SCRIPT_SHAPE}, "
                                          f"not {json_type(script)}")
        self.calls: list[dict] = []

    def complete(self, messages: list[dict], model: str, temperature: float | None, timeout: float,
                 hint: dict) -> tuple[str, dict]:
        self.calls.append({"messages": messages, "hint": hint})
        fn = hint.get("fn", "")
        q = self.queue if self.queue is not None else self.by_fn.get(fn)
        if q:
            reply = q.pop(0)
        elif self.scripted:         # {} is the per-function form too: "has no reply for f()" (round 7)
            raise _script_used_up(fn, messages, None if self.queue is not None else self.by_fn)
        else:
            d = default_for_schema(hint.get("schema") or {"type": "string"})
            if hint.get("agent"):
                reply = {"final": d}
            elif hint.get("raw_text"):
                reply = "mock answer"
            else:
                reply = d
        text = reply if isinstance(reply, str) else jsondeep.dumps(reply, ensure_ascii=False)
        prompt = "".join(m.get("content", "") for m in messages)
        return text, {"input": estimate_tokens(prompt), "output": estimate_tokens(text)}


# the feedback ai.py sends after a reply it rejected (an invalid typed reply, final answer, tool call or args)
INVALID_FEEDBACK = ("Your reply was invalid:", "Your final answer is invalid:", "Invalid reply.", "Unknown tool ",
                    "'args' for ", "Bad arguments for ")


def _script_used_up(fn: str, messages: list[dict], by_fn: dict | None) -> SiparRuntimeError:
    where = f"the mock script has no reply for {fn}()" if by_fn is not None and fn not in by_fn else \
        f"the mock script has no reply left for {fn}()"
    last = messages[-1].get("content", "") if messages else ""
    why = ""
    if isinstance(last, str) and last.startswith(INVALID_FEEDBACK):     # a scripted reply did not fit (ai.py)
        why = "; the last scripted reply was rejected: " + last.split("\n", 1)[0].removeprefix("Your reply was invalid: ")
    e = SiparRuntimeError("ai", clip(where + why, 2000) + " (with a script the mock never invents an answer: "
                                "add a valid reply to mock_script / SIPAR_MOCK_SCRIPT)")
    e.no_request = True
    return e


def check_script_names(script: Any, names: set) -> None:
    """A {fn name: replies} script may name only ai / agent fns of the program (M5, round 6)."""
    if isinstance(script, dict):
        bad = sorted(k for k in script if k not in names)
        if bad:
            known = ", ".join(sorted(names)) or "none"
            raise SiparRuntimeError("ai", clip(f"the mock script names no ai/agent fn: {', '.join(map(repr, bad))} "
                                               f"(the program's ai/agent fns: {known})", 2000))


# ------------------------------------------------------------------ OpenAI-compatible

def _origin_text(url: str) -> str:
    u = urllib.parse.urlsplit(url)
    try:
        port = u.port
    except ValueError:
        port = None
    host = (u.hostname or "?") + (f":{port}" if port else "")
    return clip(f"{u.scheme}://{host}", 200).encode("ascii", "backslashreplace").decode("ascii")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Provider requests carry the API key: a redirect is never followed (SPEC §7), so the key can never be
    sent to another origin and https is never downgraded to http."""

    def __init__(self, name: str):
        self.name = name

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        fp.close()
        raise SiparRuntimeError("ai", f"{self.name}: provider redirected to {_origin_text(newurl)} (HTTP {code}); "
                                      f"redirects are not followed")


class OpenAICompatProvider:
    def __init__(self, name: str, base_url: str | None = None, key_env: str | None = None):
        if name not in BASES:
            raise SiparRuntimeError("ai", f"unknown provider {name}")
        dflt, kenv = BASES[name]
        if name == "local":
            dflt = os.environ.get("SIPAR_LOCAL_URL", "http://127.0.0.1:1234/v1")
            kenv = "SIPAR_LOCAL_KEY"
        self.name = name
        self.base = (base_url or os.environ.get(f"SIPAR_{name.upper()}_URL") or dflt).rstrip("/")
        self.key_env = key_env or kenv

    def complete(self, messages: list[dict], model: str, temperature: float | None, timeout: float,
                 hint: dict) -> tuple[str, dict]:
        key = os.environ.get(self.key_env or "", "")
        if not key and self.name != "local":
            e = SiparRuntimeError("ai", f"{self.name}: environment variable {self.key_env} is not set")
            e.no_request = True             # nothing was sent: the attempt costs nothing (SPEC §7 budgets)
            raise e
        body: dict = {"model": model, "messages": messages}
        if temperature is not None:
            body["temperature"] = temperature
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "User-Agent": "sipar/0.1"}
        if key:
            register_secret(key, f"secret:{self.key_env}")
            headers["Authorization"] = "Bearer " + key
        if self.name == "openrouter":
            headers["X-Title"] = "Sipar"
        req = urllib.request.Request(self.base + "/chat/completions", data=json.dumps(body).encode(),
                                     headers=headers, method="POST")
        try:
            raw = netio.fetch(req, max(timeout, 0.1), 20_000_000, (_NoRedirect(self.name),))
        except netio.DeadlineExceeded:
            raise SiparRuntimeError("ai", f"{self.name}: request timed out after {timeout:.3g}s")
        except urllib.error.HTTPError as e:
            body = getattr(e, "sipar_body", b"")
            txt = _body_text(body, 300, len(body) >= netio.ERROR_BODY)
            err = SiparRuntimeError("ai", f"{self.name}: HTTP {e.code} {e.reason}: {txt}")
            err.usage = _error_body_usage(body)      # SPEC §7: the usage the provider reported in the error reply
            raise err
        except (TimeoutError, socket.timeout):
            raise SiparRuntimeError("ai", f"{self.name}: request timed out after {timeout:.3g}s")
        except urllib.error.URLError as e:
            if isinstance(e.reason, (TimeoutError, socket.timeout)):
                raise SiparRuntimeError("ai", f"{self.name}: request timed out after {timeout:.3g}s")
            raise SiparRuntimeError("ai", f"{self.name}: cannot reach {self.base}: {e.reason}")
        except (OSError, http.client.HTTPException) as e:
            raise SiparRuntimeError("ai", f"{self.name}: connection error: {clip(str(e), 300)}")
        try:
            data = scrub_text(jsondeep.loads(raw.decode("utf-8", "replace")))   # no lone surrogate (C2)
        except jsondeep.NumberTooLarge as e:      # valid JSON: say what is wrong (round 6)
            raise SiparRuntimeError("ai", f"{self.name}: the response holds {e}")
        except (ValueError, RecursionError):
            raise SiparRuntimeError("ai", f"{self.name}: response is not JSON: {_body_text(raw, 200)}")
        try:
            return self.parse_reply(data, messages)
        except SiparRuntimeError as e:
            e.usage = _reported_usage(data)   # a bad reply the provider still billed for: count what it reports
            raise
        except (AttributeError, TypeError, ValueError, KeyError, IndexError, OverflowError, RecursionError):
            e = SiparRuntimeError("ai", f"{self.name}: malformed response: {_short(data)}")
            e.usage = _reported_usage(data)
            raise e

    def parse_reply(self, data: Any, messages: list[dict]) -> tuple[str, dict]:
        """OpenAI-shaped reply -> (text, usage). Anything unexpected is an `ai` error (catchable, falls back)."""
        if not isinstance(data, dict):
            raise SiparRuntimeError("ai", f"{self.name}: response is not a JSON object: {_short(data)}")
        if data.get("error"):
            err = data["error"]
            msg = err.get("message") if isinstance(err, dict) else err
            raise SiparRuntimeError("ai", f"{self.name}: {clip(str(msg), 300)}")
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict) \
                or not isinstance(choices[0].get("message"), dict):
            raise SiparRuntimeError("ai", f"{self.name}: unexpected response shape: {_short(data)}")
        content = choices[0]["message"].get("content")
        if isinstance(content, list):
            parts = [p.get("text", "") if isinstance(p, dict) else None for p in content]
            if not all(isinstance(p, str) for p in parts):
                raise SiparRuntimeError("ai", f"{self.name}: unexpected content parts: {_short(content)}")
            content = "".join(parts)
        if content is None:
            content = ""
        if not isinstance(content, str):
            raise SiparRuntimeError("ai", f"{self.name}: message content is not text: {_short(content)}")
        usage = data.get("usage")
        usage = usage if isinstance(usage, dict) else {}
        return content, clean_usage({"input": usage.get("prompt_tokens"), "output": usage.get("completion_tokens")},
                                    prompt_text(messages), content)


def _error_body_usage(body: Any) -> dict | None:
    """Usage reported in the JSON body of an HTTP error reply (round 5, C3); None when there is none."""
    if not isinstance(body, (bytes, bytearray)) or not body:
        return None
    try:
        return _reported_usage(jsondeep.loads(bytes(body).decode("utf-8", "replace")))
    except (ValueError, RecursionError):
        return None


def _reported_usage(data: Any) -> dict | None:
    """Sane token counts reported in a reply that failed otherwise; None when there are none."""
    u = data.get("usage") if isinstance(data, dict) else None
    if not isinstance(u, dict):
        return None
    out = {"input": u.get("prompt_tokens"), "output": u.get("completion_tokens")}
    return out if all(valid_count(v) for v in out.values()) else None


def _short(x: Any) -> str:
    try:
        return clip(json.dumps(x), 200)
    except (TypeError, ValueError, RecursionError):
        return type(x).__name__


_body_text = netio.body_text


def make_provider(name: str, mock_script: Any = None):
    if name == "mock":
        return MockProvider(mock_script)
    return OpenAICompatProvider(name)
