"""`allow net` entries (SPEC §8): one parser for the checker (E310/E311) and the runtime (host matching),
so an entry means the same thing in both."""
from __future__ import annotations

import ipaddress
import re

_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?"          # no "-" at either end of a label (RFC 1123)
HOST = re.compile(rf"^(\*\.)?{_LABEL}(\.{_LABEL})*\.?$")     # ASCII only; IDNs use the xn-- form

# Wildcards under these grant hosts anyone can register (a short built-in list; no download).
# Public suffixes the SECOND_LEVEL rule below does not already catch (co.uk, com.au, ne.jp ... are caught by it)
PUBLIC_SUFFIXES = frozenset("""
me.uk github.io gitlab.io herokuapp.com vercel.app netlify.app pages.dev workers.dev web.app firebaseapp.com
appspot.com azurewebsites.net cloudfront.net amazonaws.com s3.amazonaws.com blogspot.com wordpress.com
glitch.me repl.co onrender.com fly.dev ngrok.io ngrok-free.app
""".split())
SECOND_LEVEL = frozenset("co com net org gov edu ac or ne go mil ltd plc nic".split())


class ScopeError(ValueError):
    def __init__(self, why: str, hint: str):
        super().__init__(why)
        self.why, self.hint = why, hint


def parse(entry: str) -> tuple[str, int | None]:
    """(host, port) for one entry: host lower-cased, no trailing dot, IPv6 without brackets in its short
    form; port None = any port. Raises ScopeError for an entry that can never mean what it says."""
    s = entry
    if not s.strip():
        raise ScopeError("is empty", 'remove it or write what it grants, e.g. ["example.com"]')
    if s != s.strip():
        raise ScopeError("has spaces around it", f'allow net ["{s.strip()}"]')
    if "://" in s:
        raise ScopeError("has a scheme; list host names only", f'allow net ["{s.split("://", 1)[1].split("/")[0]}"]')
    if "/" in s:
        raise ScopeError("has a path; hosts are matched, not URLs", f'allow net ["{s.split("/", 1)[0]}"]')
    port = None
    if s.startswith("["):
        end = s.find("]")
        if end < 0:
            raise ScopeError("has an unclosed '['", 'IPv6 addresses are written in brackets: ["[::1]:8080"]')
        try:
            host = ipaddress.IPv6Address(s[1:end]).compressed
        except ValueError:
            raise ScopeError("is not a valid IPv6 address", 'allow net ["[::1]"] or ["[::1]:8080"]') from None
        rest = s[end + 1:]
        if rest:
            if not rest.startswith(":"):
                raise ScopeError("has text after ']'", 'allow net ["[::1]:8080"]')
            port = rest[1:]
    else:
        n = s.count(":")
        if n >= 2:
            raise ScopeError("has more than one ':'", 'write host:port, and put IPv6 addresses in brackets: '
                                                      '["example.com:8080", "[::1]:8080"]')
        host, _, p = s.partition(":")
        if n == 1:
            port = p
        if host != "*" and not HOST.match(host):
            raise ScopeError("is not a host name", 'allow net ["example.com"] or ["*.example.com"]')
        host = host.lower().rstrip(".")
    if port is not None:
        if not (port.isascii() and port.isdigit() and 0 < int(port) <= 65535):
            raise ScopeError("has an invalid port (use 1..65535)", 'allow net ["example.com:8080"]')
        port = int(port)
    return host, port


def broad_wildcard(host: str) -> str | None:
    """Why a "*.x" host grants too much (E311), or None."""
    if not host.startswith("*."):
        return None
    rest = host[2:]
    labels = rest.split(".")
    if len(labels) == 1:
        return "allows every host under a top-level domain"
    if rest in PUBLIC_SUFFIXES or (len(labels) == 2 and labels[0] in SECOND_LEVEL and len(labels[1]) <= 3):
        return f"allows every host under the public suffix {rest!r}, where anyone can register a name"
    return None


def norm_host(host: str) -> str:
    """A URL's host in the form parse() gives scopes."""
    h = host.lower().rstrip(".")
    if ":" in h:
        try:
            return ipaddress.IPv6Address(h).compressed
        except ValueError:
            return h
    return h


def matches(host: str, port: int | None, entry: str) -> bool:
    try:
        sh, sp = parse(entry)
    except ScopeError:
        return False            # the checker reports it (E310); at run time it grants nothing
    if sp is not None and sp != port:
        return False
    h = norm_host(host)
    if sh.startswith("*."):
        suffix = sh[1:]          # ".example.com"
        return h.endswith(suffix) and len(h) > len(suffix)
    return h == sh
