"""Capabilities, taint sinks and the effectful standard library (http, fs, shell, env, time, random, input,
approve, trust). Every effect checks sinks and capabilities *before* it happens and goes through the journal."""
from __future__ import annotations

import hashlib
import hmac
import http.client
import os
import random as _random
import shlex
import signal
import subprocess
import time as _time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .. import ast as A
from .. import deep, netscope
import re

from ..errors import (MIN_SECRET_LEN, TERM_RESET, SiparRuntimeError, clip, cut_secrets, fold_case, secret_forms,
                      secret_in_text, secret_key, secret_labels_in, escape_controls, escape_text, is_tty)
from ..errors import flush as _flush
from ..fileread import why_unreadable
from ..stdlib import FUNCTIONS
from . import children, netio
from .providers import KEY_ENVS
from .values import (EMPTY, LStr, deep_strip, is_num, labels_of, mark_secrets, own_labels, render, scrub_text, secrets_in, set_labels, to_json,
                     untrusted_in, with_labels)

MAX_BODY = 10_000_000
_BAD_URL_CHARS = set(" \t\r\n\\\x00") | {chr(i) for i in range(32)} | {"\x7f"}


def cap_error(msg: str) -> SiparRuntimeError:
    return SiparRuntimeError("capability", msg)


# ------------------------------------------------------------------ capabilities

class Caps:
    def __init__(self, allows: list[A.Allow], base_dir: str):
        self.base_dir = os.path.realpath(base_dir)
        self.grants: dict[str, list[str] | None] = {}
        for a in allows:
            if a.cap in self.grants and self.grants[a.cap] is None:
                continue
            if a.scopes is None:
                self.grants[a.cap] = None
            else:
                self.grants.setdefault(a.cap, [])
                self.grants[a.cap] = list(self.grants[a.cap] or []) + list(a.scopes)

    def require(self, cap: str) -> None:
        if cap not in self.grants:
            raise cap_error(f"this program has no 'allow {cap}' line")

    # -- net
    @staticmethod
    def host_matches(host: str, port: int | None, scope: str) -> bool:
        return netscope.matches(host, port, scope)       # same parser as the checker (E310): SPEC §8

    def check_url(self, url: str) -> str:
        """Validate URL against `allow net`; return the host."""
        self.require("net")
        u = str(url)
        if any(c in _BAD_URL_CHARS for c in u):
            raise cap_error(f"URL contains whitespace, backslash or control characters: {u[:80]!r}")
        try:
            parts = urllib.parse.urlsplit(u)
            port = parts.port
        except ValueError:
            raise cap_error(f"malformed URL {u[:80]!r}")
        if parts.scheme.lower() not in ("http", "https"):
            raise cap_error(f"only http/https URLs are allowed, got {parts.scheme or 'no scheme'!r}")
        host = (parts.hostname or "").rstrip(".")
        if not host:
            raise cap_error(f"URL has no host: {u[:80]!r}")
        if port is None:
            port = 443 if parts.scheme.lower() == "https" else 80
        scopes = self.grants["net"]
        if scopes is not None and not any(self.host_matches(host, port, s) for s in scopes):
            raise cap_error(f"host {host!r} is not in 'allow net' ({', '.join(scopes) or 'empty'})")
        if "@" in parts.netloc:           # urllib would look up "user@host" as one name (round 11)
            raise cap_error("URL has a user name or password before the host (user@host); "
                            "send credentials in a header instead")
        if not u.isascii():               # http.client can only send ASCII in the request line (round 11)
            raise cap_error("URL has a character outside ASCII; percent-encode it (é is %C3%A9) and write an "
                            "international host name in its xn-- form")
        return host

    # -- fs
    def resolve_path(self, path: str, cap: str) -> str:
        self.require(cap)
        p = str(path)
        if "\x00" in p or p == "":
            raise cap_error(f"invalid path {p!r}")
        full = os.path.realpath(os.path.join(self.base_dir, p))
        scopes = self.grants[cap]
        if scopes is None:
            return full
        for s in scopes:
            pref = os.path.realpath(os.path.join(self.base_dir, s))
            if full == pref or full.startswith(pref.rstrip(os.sep) + os.sep):
                return full
        raise cap_error(f"path {p!r} is outside 'allow {cap}' ({', '.join(scopes) or 'empty'})")

    # -- shell
    def check_command(self, cmd: str) -> list[str]:
        self.require("shell")
        try:
            toks = shlex.split(str(cmd), posix=True)
        except ValueError as e:
            raise cap_error(f"cannot parse command: {e}")
        if not toks:
            raise cap_error("empty command")
        scopes = self.grants["shell"]
        if scopes is None:
            return toks
        for s in scopes:
            try:
                pt = shlex.split(s, posix=True)
            except ValueError:
                continue
            if pt and toks[:len(pt)] == pt:
                return toks
        raise cap_error(f"command {toks[0]!r} (as {toks[:4]}) does not start with an allowed prefix "
                        f"({', '.join(scopes) or 'empty'})")

    # -- env / secret
    def secret_names(self) -> list[str]:
        return list(self.grants.get("secret") or [])

    def check_env(self, name: str) -> None:
        self.require("env")
        scopes = self.grants["env"]
        if str(name) in self.secret_names():
            raise cap_error(f"environment variable {str(name)!r} is listed in 'allow secret'; read it with "
                            "env.secret, not env.get")
        if str(name) in KEY_ENVS:
            raise cap_error(f"environment variable {str(name)!r} holds an AI provider API key; read it with "
                            f"`allow secret [\"{str(name)}\"]` and env.secret, not env.get")
        if scopes is not None and str(name) not in scopes:
            raise cap_error(f"environment variable {str(name)!r} is not in 'allow env'")

    def check_secret(self, name: str) -> None:
        self.require("secret")
        if self.grants["secret"] is None:
            raise cap_error("'allow secret' needs a list of names, e.g. allow secret [\"API_KEY\"]")
        if str(name) not in self.grants["secret"]:
            raise cap_error(f"secret {str(name)!r} is not in 'allow secret'")


# ------------------------------------------------------------------ sinks

def check_sinks(fname: str, args: dict[str, Any]) -> None:
    sig = FUNCTIONS.get(fname)
    if sig is None:
        return
    for p in sig.no_secret:
        if p in args:
            sec = secrets_in(args[p])
            if sec:
                raise SiparRuntimeError("taint", f"{', '.join(sec)} cannot flow into {fname}({p}); secrets may only "
                                                 "be used as http header values")
    for p in sig.sink:
        if p in args:
            un = untrusted_in(args[p])
            if un:
                raise SiparRuntimeError("taint", f"untrusted data ({', '.join(un[:3])}) cannot flow into "
                                                 f"{fname}({p}); check it, then use trust(x, \"reason\") or "
                                                 "approve(x, \"question\")")


def _detail(v: Any) -> str:
    if secrets_in(v):
        return "«secret»"
    s = render(v)
    return s if len(s) <= 80 else s[:80] + "…"


# ------------------------------------------------------------------ effects

CREDENTIAL_HEADERS = {"authorization", "cookie", "proxy-authorization"}


def _origin(url: str) -> tuple:
    u = urllib.parse.urlsplit(url)
    return u.scheme.lower(), (u.hostname or "").lower(), u.port or {"http": 80, "https": 443}.get(u.scheme.lower())


class _CapRedirect(urllib.request.HTTPRedirectHandler):
    """Redirects must stay inside `allow net`; a redirect to another origin (scheme, host, port) drops
    Authorization, Cookie, Proxy-Authorization and every header whose value carries a secret."""

    def __init__(self, caps: Caps, secret_headers: set[str] | frozenset = frozenset()):
        self.caps = caps
        self.secret_headers = {h.lower() for h in secret_headers}

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            self.caps.check_url(newurl)
        except BaseException:
            fp.close()                         # urllib closes the 3xx response only when we return a request
            raise
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and _origin(newurl) != _origin(req.full_url):
            drop = CREDENTIAL_HEADERS | self.secret_headers
            for store in (new.headers, new.unredirected_hdrs):
                for k in [k for k in store if k.lower() in drop]:
                    del store[k]
        return new


def _deadline(rt, default_env: str, default: float) -> tuple[float, bool]:
    """(seconds this effect may take in total, True when the time budget is what limits it)."""
    t = netio.env_seconds(default_env, default)
    rem = rt.budget_remaining_seconds()
    if rem is not None and rem <= t:
        return max(0.05, rem), True
    return t, False


def _timeout(rt, default_env: str, default: float) -> float:
    return _deadline(rt, default_env, default)[0]


def _too_slow(what: str, seconds: float, by_budget: bool, rt=None) -> SiparRuntimeError:
    if by_budget:
        e = SiparRuntimeError("budget", f"time budget exceeded: {what} did not finish within the remaining "
                                        f"{seconds:.2f}s")
        if rt is not None:        # the time left comes from the limits: it carries their labels (S1, round 5)
            e.labels = e.labels | rt.budget_labels()
        return e
    return SiparRuntimeError("io", f"{what} timed out after {seconds:g}s")


_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_BAD_VALUE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f]")      # C0 but TAB, DEL, C1


def check_headers(hdrs: Any) -> None:
    """Refuse a header that could split the request or that http.client would choke on, before anything is
    sent (SPEC §7). The message names the header but never quotes the value: it may hold a secret."""
    for k, v in hdrs.items():
        name, value = str.__str__(k) if isinstance(k, str) else str(k), str.__str__(v) if isinstance(v, str) else str(v)
        if not _TOKEN.fullmatch(name):
            raise SiparRuntimeError("value", f"http header name '{escape_text(clip(name, 100))}' is not a valid "
                                             f"header name (letters, digits and !#$%&'*+-.^_`|~ only)")
        if name.lower() in ("host", "content-length", "transfer-encoding"):
            # written by the runtime from the URL and the body: a second `Host` could reach a site that
            # `allow net` does not list, a wrong length makes the server wait (round 11)
            raise SiparRuntimeError("value", f"http header {name!r} is set by the runtime from the URL and the "
                                             f"body; a program may not set it")
        if _BAD_VALUE.search(value):
            raise SiparRuntimeError("value", f"http header {name!r}: the value contains a line break or a control "
                                             f"character; nothing was sent")
        try:
            value.encode("latin-1")
        except UnicodeEncodeError:
            raise SiparRuntimeError("value", f"http header {name!r}: the value has a character outside Latin-1; "
                                             f"nothing was sent") from None


def http_request(rt, method: str, url: Any, body: Any, headers: Any) -> Any:
    fname = "http.get" if method == "GET" else "http.post"
    hdrs = headers or {}
    # headers leave the machine like the URL and the body: untrusted data may not ride in them, in a name or
    # in a value (round 11; `headers` is in the sink list of both functions in stdlib.py)
    args = {"url": url, "headers": hdrs}
    if method == "POST":
        args["body"] = body
    check_sinks(fname, args)
    for k in hdrs:
        if secrets_in(k):
            raise SiparRuntimeError("taint", "secrets may be header values, not header names")
    check_headers(hdrs)
    host = rt.caps.check_url(url)
    # a header map picked with a secret index/key (SPEC §6) carries the secret on the map itself: then every
    # header (names too) is secret: hidden in the journal and dropped on a cross-origin redirect
    whole_secret = any(l.startswith("secret:") for l in own_labels(hdrs))
    request = {"method": method, "url": str(url), "headers": to_json(hdrs, redact=True)}
    if method == "POST":
        request["body"] = str(body)
    label = f"untrusted:net:{host}"

    def perform():
        data = str(body).encode("utf-8") if method == "POST" else None
        req = urllib.request.Request(str(url), data=data, method=method,
                                     headers={str(k): str(v) for k, v in hdrs.items()})
        seconds, by_budget = _deadline(rt, "SIPAR_HTTP_TIMEOUT", 30)
        try:
            secret_headers = {str(k) for k, v in hdrs.items() if whole_secret or secrets_in(v)}
            raw = netio.fetch(req, seconds, MAX_BODY + 1, (_CapRedirect(rt.caps, secret_headers),))
        except netio.DeadlineExceeded:
            raise _too_slow(f"{method} {host}", seconds, by_budget, rt)
        except urllib.error.HTTPError as e:
            eb = getattr(e, "sipar_body", b"")
            # redact everything read first, then window (500 chars) and cut: a secret across the cut can't leak
            txt = " ".join(clip(eb.decode("utf-8", "replace"), 500, len(eb) >= netio.ERROR_BODY).split())[:200]
            raise SiparRuntimeError("io", f"{method} {host}: HTTP {e.code} {e.reason}" + (f": {txt}" if txt else ""))
        except urllib.error.URLError as e:
            raise SiparRuntimeError("io", f"{method} {host}: {e.reason}")
        except (TimeoutError, OSError, ValueError, http.client.HTTPException) as e:
            raise SiparRuntimeError("io", f"{method} {host}: {type(e).__name__}: {clip(e, 300)}")
        if len(raw) > MAX_BODY:
            raise SiparRuntimeError("io", f"{method} {host}: response larger than {MAX_BODY} bytes")
        return raw.decode("utf-8", "replace")

    resp = rt.journal.effect("http", request, perform, [label])
    return mark_secrets(with_labels(str(resp), {label}))


def fs_read(rt, path: Any) -> Any:
    full = rt.caps.resolve_path(path, "fs.read")
    label = f"untrusted:file:{_detail(path)}"

    def perform():
        try:
            with open(full, encoding="utf-8", errors="replace") as fh:
                data = fh.read(MAX_BODY + 1)
        except OSError as e:
            raise SiparRuntimeError("io", f"cannot read {str(path)!r}: {why_unreadable(e)}")
        if len(data) > MAX_BODY:
            raise SiparRuntimeError("io", f"{str(path)!r} is larger than {MAX_BODY} characters")
        return data

    resp = rt.journal.effect("fs.read", {"path": str(path)}, perform, [label])
    return mark_secrets(with_labels(str(resp), {label}))


def fs_exists(rt, path: Any) -> bool:
    full = rt.caps.resolve_path(path, "fs.read")
    return bool(rt.journal.effect("fs.exists", {"path": str(path)}, lambda: os.path.exists(full)))


def fs_write(rt, path: Any, text: Any) -> None:
    check_sinks("fs.write", {"path": path, "text": text})
    full = rt.caps.resolve_path(path, "fs.write")

    def perform():
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(full, flags, 0o644)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(str(text))
        except OSError as e:
            raise SiparRuntimeError("io", f"cannot write {str(path)!r}: {why_unreadable(e)}")
        return None

    rt.journal.effect("fs.write", {"path": str(path), "text": str(text)}, perform)
    return None


SHELL_BASE_ENV = ("PATH", "HOME", "LANG", "TMPDIR")


def guarded_names(caps: "Caps") -> list[str]:
    """The variables whose values are secrets: the `allow secret` names and, in a program with `allow ai`, the
    provider API key variables (R9-5), which the runtime reads for ai calls."""
    return list(dict.fromkeys((*caps.secret_names(), *(KEY_ENVS if "ai" in caps.grants else ()))))


def shell_env(caps: "Caps") -> dict[str, str]:
    """The environment a command sees: a minimal base plus the names listed in `allow env [...]`, never a name
    listed in `allow secret` (SPEC §7). A bare `allow env` adds nothing: only listed names are passed."""
    listed = caps.grants.get("env") or []
    secret = set(guarded_names(caps))
    names = [n for n in (*SHELL_BASE_ENV, *listed) if n not in secret]
    out = {}
    for n in names:
        v = os.environ.get(n)
        # R4 (round 6): a variable whose value holds a secret value (one read with env.secret, or the value of
        # any `allow secret` name) is not passed: the filter is by value, not only by name
        if v is None or secret_labels_in(v) or holds_secret(v, caps):
            continue
        out[n] = v
    return out


def holds_secret(v: str, caps: "Caps") -> list[str]:
    """R7-6 (round 7): names of the `allow secret` variables whose value is in v in any upper/lower-case mix
    (4 characters or more), or is v itself in any case (a shorter secret: a substring test would match
    ordinary text). R8-2/R8-3 (round 8): the trimmed value of a secret with surrounding whitespace counts the
    same way, the case comparison is caseless (fold_case: ß / SS / ss), and an escaped form that would be
    redacted (secret_forms: JSON, percent-encoded, ...) counts too. R9-1/R9-3 (round 9): so does a copy in the
    caseless search view (secret_key: one level of JSON / HTML / percent escapes decoded, invisible characters
    dropped, NFKD), on both sides."""
    fv, fvs = fold_case(v), fold_case(v.strip())
    kv, kvs = secret_key(v), secret_key(v.strip())
    found = []
    for n in guarded_names(caps):                  # R9-5: provider API keys too
        h = os.environ.get(str(n))
        if not h:
            continue
        for x in dict.fromkeys((h, h.strip())):
            if not x:
                continue
            fx = fold_case(x)
            kx = secret_key(x)
            if len(x) < MIN_SECRET_LEN or len(kx) < MIN_SECRET_LEN:
                hit = fx == fvs or (bool(kx) and kx == kvs)
            else:
                hit = fx in fv or kx in kv or any(f in v for f in secret_forms(x))
            if hit:
                found.append(str(n))
                break
    return found


def _kill_group(p: subprocess.Popen) -> None:
    """Kill the command and everything it started (it runs in its own session), then reap it."""
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except (OSError, AttributeError):
        p.kill()
    try:
        p.communicate(timeout=2)
    except (subprocess.TimeoutExpired, OSError, ValueError):
        for f in (p.stdout, p.stderr):     # a grandchild that left the group holds the pipe: stop reading
            try:
                f.close()
            except OSError:
                pass
        try:
            p.wait(timeout=2)                  # the command itself is dead: reap it (no zombie)
        except (subprocess.TimeoutExpired, OSError):
            pass


def shell_run(rt, cmd: Any) -> Any:
    check_sinks("shell.run", {"cmd": cmd})
    toks = rt.caps.check_command(cmd)
    label = f"untrusted:shell:{toks[0]}"

    def perform():
        seconds, by_budget = _deadline(rt, "SIPAR_SHELL_TIMEOUT", 120)
        try:
            p = subprocess.Popen(toks, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, cwd=rt.caps.base_dir, env=shell_env(rt.caps),
                                 start_new_session=True)
        except FileNotFoundError:
            raise SiparRuntimeError("io", f"command not found: {toks[0]!r}")
        except OSError as e:
            raise SiparRuntimeError("io", f"cannot run {toks[0]!r}: {why_unreadable(e)}")
        children.track(p)
        try:
            stdout, stderr = p.communicate(timeout=seconds)
        except subprocess.TimeoutExpired:
            _kill_group(p)
            raise _too_slow(f"command {toks[0]!r}", seconds, by_budget, rt)
        except BaseException:
            _kill_group(p)
            raise
        finally:
            children.untrack(p)
        out = stdout[:MAX_BODY].decode("utf-8", "replace")
        if p.returncode != 0:
            err = netio.body_text(stderr, 300)
            raise SiparRuntimeError("io", f"command {toks[0]!r} exited with status {p.returncode}"
                                    + (f": {err}" if err else ""))
        return out

    resp = rt.journal.effect("shell", {"cmd": toks}, perform, [label])
    return mark_secrets(with_labels(str(resp), {label}))


def allowed_secret_values(caps: "Caps") -> list[tuple[str, str]]:
    """(name, value) of every `allow secret` name and provider API key variable (R9-5) set in the environment
    (values of 4 characters or more)."""
    out = []
    for n in guarded_names(caps):
        v = os.environ.get(str(n))
        if v and len(v) >= MIN_SECRET_LEN:
            out.append((str(n), v))
    return out


def env_get(rt, name: Any) -> Any:
    rt.caps.check_env(name)
    raw = os.environ.get(str(name))
    if raw:
        # R4 (round 6): an allowed variable whose value holds the value of an `allow secret` name is labelled
        # secret (and kept out of the journal) even when the program never read that secret
        seen = {}
        for n, h in allowed_secret_values(rt.caps):
            if secret_in_text(raw, h):                      # a copy add_secret would label (R8-2..4, R9-1/3)
                rt.journal.add_secret(h, f"secret:{n}")
                seen[n] = h
        # R7-6: a copy the labelling above cannot see (a secret under 4 characters, or a mixed-case form) is
        # refused before it is read or journaled. R8C-1 (round 8): also when the variable holds a registered
        # form too ("a hunter2xyz b HuNtEr2XyZ"): what is left once the journal redaction has cut out every
        # labelled copy (each replaced by NUL, so the pieces left cannot join up) is checked
        other = holds_secret(raw, rt.caps)
        if seen and other:
            cut = cut_secrets(raw, [(h, f"secret:{n}") for n, h in seen.items()])
            other = [n for n in other if n not in seen or n in holds_secret(cut, rt.caps)]
        if other:
            raise SiparRuntimeError("taint", f"env.get({str(name)!r}): the variable holds the value of secret "
                                             f"{', '.join(other)}; read it with env.secret")
    v = rt.journal.effect("env.get", {"name": str(name)}, lambda: scrub_text(os.environ.get(str(name))))
    return mark_secrets(v)


SECRET_HASH_ROUNDS = 100_000


def pbkdf2_sha256(password: bytes, salt: bytes, rounds: int) -> bytes:
    """PBKDF2-HMAC-SHA256, 32 bytes (RFC 8018), in plain Python: the same bytes as hashlib.pbkdf2_hmac.
    For a Python built without OpenSSL (Pyodide in a browser is one), where hashlib has no pbkdf2_hmac."""
    key = hashlib.sha256(password).digest() if len(password) > 64 else password
    key = key.ljust(64, b"\0")
    inner, outer = hashlib.sha256(bytes(b ^ 0x36 for b in key)), hashlib.sha256(bytes(b ^ 0x5C for b in key))

    def prf(msg: bytes) -> bytes:
        i, o = inner.copy(), outer.copy()
        i.update(msg)
        o.update(i.digest())
        return o.digest()

    u = prf(salt + b"\x00\x00\x00\x01")
    acc = int.from_bytes(u, "big")
    for _ in range(rounds - 1):
        u = prf(u)
        acc ^= int.from_bytes(u, "big")
    return acc.to_bytes(32, "big")


def secret_hash(value: str, salt: str) -> str:
    """Slow salted hash of a secret, journaled instead of the value so replay can check it got the same one."""
    slow = getattr(hashlib, "pbkdf2_hmac", None)
    raw, salt_bytes = value.encode("utf-8"), bytes.fromhex(salt)
    if slow is None:
        return pbkdf2_sha256(raw, salt_bytes, SECRET_HASH_ROUNDS).hex()
    return slow("sha256", raw, salt_bytes, SECRET_HASH_ROUNDS).hex()


def env_secret(rt, name: Any) -> Any:
    rt.caps.check_secret(name)
    n = str(name)
    label = f"secret:{n}"

    def perform():
        v = scrub_text(os.environ.get(n))
        if v is None:
            raise SiparRuntimeError("io", f"secret {n!r} is not set in the environment")
        salt = os.urandom(16).hex()
        return {"salt": salt, "hash": secret_hash(v, salt), "len": len(v)}

    rec = rt.journal.effect("env.secret", {"name": n}, perform, [label], raw=True)
    v = scrub_text(os.environ.get(n))
    if rt.journal.replaying:
        # replay re-reads the real secret and checks it is the one the recorded run used
        if v is None:
            raise SiparRuntimeError("replay", f"secret {n!r} is not set in the environment; replay needs the "
                                              f"same value as the recorded run")
        try:
            same = len(v) == rec["len"] and hmac.compare_digest(secret_hash(v, rec["salt"]), rec["hash"])
        except ValueError:                     # salt is not hex
            same = False
        if not same:
            raise SiparRuntimeError("replay", f"secret {n!r} differs from the one used in the recorded run")
    elif v is None:                            # removed from the environment while the effect ran
        raise SiparRuntimeError("io", f"secret {n!r} is not set in the environment")
    rt.journal.add_secret(v, label)
    return set_labels(v, frozenset({label}))


def time_now(rt) -> Any:
    rt.caps.require("time")
    return float(rt.journal.effect("time", {}, _time.time))


def random_int(rt, lo: Any, hi: Any) -> Any:
    rt.caps.require("random")
    if int(lo) > int(hi):
        raise SiparRuntimeError("value", f"random.int: lo ({render(lo, redact=True)}) > hi ({render(hi, redact=True)})")
    v = rt.journal.effect("random", {"lo": int(lo), "hi": int(hi)}, lambda: _random.randint(int(lo), int(hi)))
    return with_labels(int(v), labels_of(lo) | labels_of(hi))


MAX_SLEEP = 86_400.0


def sleep(rt, seconds: Any) -> None:
    """S2 (round 5): the duration is checked before anything else, the same way when running and replaying: a
    negative, NaN, infinite or too large duration is a catchable `value` error (NaN on the replay clock would
    otherwise switch budget(seconds) off, and Python's sleep raises on NaN)."""
    rt.caps.require("time")
    if not is_num(seconds) or not (0 <= seconds <= MAX_SLEEP):      # NaN fails every comparison
        raise SiparRuntimeError("value", f"sleep: the duration must be a finite number of seconds from 0 to "
                                         f"{MAX_SLEEP:g}, got {render(seconds, redact=True)}")
    s = float(seconds)
    if rt.journal.replaying:
        rt.replay_time_over({"sleep": s})
        rt.journal.vclock += s
        return None
    rem = rt.budget_remaining_seconds()
    if rem is not None and s > rem:
        rt.time_over(f"sleep({s:g}) exceeds the remaining time budget ({rem:.2f}s)", {"sleep": s})
    _pause(s)
    return None


def _pause(s: float) -> None:
    """R6 (round 6): on the deep worker thread a sleep waits on the run's stop event, so the first Ctrl-C ends
    it at once (an asynchronous exception cannot interrupt time.sleep)."""
    stop = deep.stop_event()
    if stop is None:
        _time.sleep(s)
    elif stop.wait(s):
        raise KeyboardInterrupt


def read_line(stream: Any) -> str:
    """One line from stdin. Bytes that are not UTF-8 become U+FFFD (SPEC §5), never a UnicodeDecodeError
    (round 10, F1: `printf 'x\\xc0z' | sipar run` ended with an internal error no `try` could catch): a
    strict text stream (Python's sys.stdin) is switched to errors="replace" before its first read."""
    if getattr(stream, "errors", None) == "strict" and hasattr(stream, "reconfigure"):
        try:
            stream.reconfigure(errors="replace")
        except (OSError, ValueError, AttributeError):     # already read from (by the host): decoded as it is
            pass
    try:
        return stream.readline()
    except UnicodeDecodeError:
        raise SiparRuntimeError("io", "input: stdin holds bytes that are not text in its encoding") from None


def input_line(rt, prompt: Any) -> Any:
    rt.caps.require("io")
    if secrets_in(prompt):
        raise SiparRuntimeError("taint", f"{', '.join(secrets_in(prompt))} cannot flow into input(prompt)")
    rt.out.write(escape_controls(str(prompt)) if is_tty(rt.out) else str(prompt))
    _flush(rt.out)

    def perform():
        line = scrub_text(read_line(rt.stdin))
        if line == "":
            raise SiparRuntimeError("io", "input: end of input")
        return line.rstrip("\r\n")

    v = rt.journal.effect("input", {"prompt": str(prompt)}, perform, ["untrusted:input:stdin"])
    return mark_secrets(with_labels(str(v), {"untrusted:input:stdin"}))


def _printable(s: str) -> str:
    """The value block of approve(): its own lines are kept (indented by the caller), every other control or
    bidi char is escaped."""
    return "\n".join(escape_text(line) for line in s.split("\n"))


def trust(rt, value: Any, reason: Any) -> Any:
    removed = untrusted_in(value)
    rt.journal.effect("trust", {"reason": render(reason, redact=True), "removed": removed, "value": to_json(value, redact=True)},
                      lambda: None)
    return deep_strip(value, lambda l: not l.startswith("untrusted:"))


_is_tty = is_tty


def approve(rt, value: Any, question: Any) -> Any:
    rt.caps.require("io")
    shown = render(value, redact=True)
    question = render(question, redact=True)
    request = {"question": question, "value": to_json(value, redact=True)}

    def perform():
        if not _is_tty(rt.stdin):
            return False
        # the question is one line (newlines and control chars escaped): it cannot draw a fake value block
        # reset first: earlier output may have hidden the text (ESC[8m) or recoloured it (S3, round 5)
        rt.err.write(f"{TERM_RESET}\n[sipar] approval needed\n  question: {escape_text(question)}\n")
        # the whole value, never a cut: a hidden tail could carry the real payload
        rt.err.write(f"  value ({len(shown)} chars):\n         "
                     + _printable(shown).replace("\n", "\n         ") + "\n")
        rt.err.write("  approve? [y/N] ")
        _flush(rt.err)
        ans = read_line(rt.stdin)
        return ans.strip().lower() in ("y", "yes")

    ok = rt.journal.effect("approve", request, perform)
    if not ok:
        raise SiparRuntimeError("denied", f"not approved: {escape_text(question)[:100]}"
                                + ("" if rt.journal.replaying or _is_tty(rt.stdin)
                                   else " (stdin is not a terminal)"))
    return deep_strip(value, lambda l: not l.startswith("untrusted:"))
