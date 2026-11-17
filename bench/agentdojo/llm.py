"""Tiny OpenAI-compatible chat client with retry on rate limits (stdlib only)."""
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

PROVIDERS = {
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai", "~/.gemini_key"),
    "groq": ("https://api.groq.com/openai/v1", "~/.groq_key"),
    "openrouter": ("https://openrouter.ai/api/v1", "~/.openrouter_key"),
}


class Unavailable(RuntimeError):
    """The provider could not answer (quota, 5xx, no network) after every retry: try again later."""


def quota_left(model, reserve=None):
    """False when the provider's free daily requests left are at or below BENCH_OR_RESERVE (OpenRouter only: the
    same key and the same 1000 free requests a day serve the owner's other tools, so the benchmark leaves them
    a reserve). Unknown (no network, other provider, no reserve set) counts as left."""
    reserve = int(os.environ.get("BENCH_OR_RESERVE", "0") if reserve is None else reserve)
    if not reserve or not model.startswith("openrouter/"):
        return True
    try:
        req = urllib.request.Request("https://openrouter.ai/api/v1/key", headers={
            "Authorization": "Bearer " + key_of("openrouter"), "User-Agent": "sipar-bench/0.2"})
        with urllib.request.urlopen(req, timeout=30) as r:
            left = json.load(r)["data"]["free_model_daily_requests"]["remaining"]
    except Exception:
        return True
    return left is None or int(left) > reserve


def key_of(provider):
    return Path(os.path.expanduser(PROVIDERS[provider][1])).read_text().strip()


def chat(model, messages, tools=None, max_tokens=8000, temperature=0.0, tries=8):
    """model = 'provider/name'. Returns the assistant message dict."""
    provider, name = model.split("/", 1)
    base, _ = PROVIDERS[provider]
    body = {"model": name, "messages": messages, "max_tokens": max_tokens, "temperature": temperature}
    if tools:
        body["tools"] = tools
    data = json.dumps(body).encode()
    delay = 10
    for attempt in range(tries):
        req = urllib.request.Request(base + "/chat/completions", data=data, headers={
            "Authorization": "Bearer " + key_of(provider), "Content-Type": "application/json",
            "User-Agent": "sipar-bench/0.2"})
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                d = json.load(r)
            return d["choices"][0]["message"]
        except urllib.error.HTTPError as e:
            txt = e.read().decode(errors="replace")[:300]
            if e.code in (429, 500, 502, 503, 504) and attempt < tries - 1:
                time.sleep(delay)
                delay = min(delay * 2, 120)
                continue
            cls = Unavailable if e.code in (429, 500, 502, 503, 504) else RuntimeError
            raise cls(f"{model}: HTTP {e.code}: {txt}") from None
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt < tries - 1:
                time.sleep(delay)
                continue
            raise Unavailable(f"{model}: {e}") from None
