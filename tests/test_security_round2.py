"""Security round 2: regression tests for the critic's findings A-L.

Every test not marked "guard" failed on the code before the fix.
All servers are local (127.0.0.1) and stopped by the tests."""
from __future__ import annotations

import io
import json
import math
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from rt_helpers import ROOT, FakeTTY, Prog, Server, main_src

from sipar.errors import TERM_RESET, SiparRuntimeError, redact_text, register_secret
from sipar.runtime import netio
from sipar.runtime.journal import Journal

OUT = {"out/.keep": ""}
SEC = 'allow secret ["R2K"]\nallow fs.write ["./out"]'
W = 'fs.write("out/w.txt", trust({}, "checked"))'    # trust drops untrusted labels, never secret ones


def forms(s: str) -> list[str]:
    """The raw, upper, lower, repr-escaped and bytes-escaped forms of s (what must never leak)."""
    out = {s, s.upper(), s.lower(), repr(s)[1:-1], repr(s.encode())[2:-1], json.dumps(s)[1:-1]}
    return sorted(out)


class Base(unittest.TestCase):
    def P(self, body: str, head: str, files=None, uses: str | None = None) -> Prog:
        """uses=...: a checked program (`fn main() uses ...`), needed where the checker annotates (memory.load)."""
        src = main_src(body, head) if uses is None else f"{head}\nfn main() uses {uses} {{\n{body}\n}}\n"
        p = Prog(src, dict(OUT, **(files or {})))
        self.addCleanup(p.cleanup)
        if uses is not None:
            from sipar.checker import check
            errs = [d for d in check(p.program, src) if d.severity == "error"]
            self.assertEqual(errs, [], "checker errors")
        return p

    def secret_taint(self, e, name: str = "R2K"):
        """The error is a taint error caused by the secret label (not by an untrusted one)."""
        self.assertIsInstance(e, SiparRuntimeError)
        self.assertEqual(e.kind, "taint", e.message)
        self.assertIn("secret:" + name, e.message)

    def server(self) -> Server:
        s = Server()
        self.addCleanup(s.close)
        return s

    def no_leak(self, secret: str, text: str):
        for f in forms(secret):
            self.assertNotIn(f, text)
        self.assertNotIn(secret[:8], text)

    def written(self, p: Prog) -> bool:
        return os.path.exists(os.path.join(p.dir, "out/w.txt"))


# ================================================================== A. an echoed secret keeps its label

class A_SourceLabels(Base):
    K = "Zq9-r2-SECRET-alpha"

    def test_A1_http_echo_of_secret_header_is_secret(self):
        srv = self.server()
        p = self.P(f'let k = env.secret("R2K")\nlet r = http.get("{srv.url}/echo", headers: ["Authorization": k])\n'
                   f'print(http.post("{srv.url}/ok", trust(r, "ok")))', 'allow net ["127.0.0.1"]\n' + SEC)
        e = p.error(env={"R2K": self.K})
        self.secret_taint(e)
        self.assertEqual([h["path"] for h in srv.hits], ["/echo"])     # the post never left

    def test_A2_upper_and_lower_case_echo(self):
        for reply in (self.K.upper(), self.K.lower(), "x " + self.K + " y"):
            with self.subTest(reply=reply):
                p = self.P('let k = env.secret("R2K")\nlet r = ask("q")\n' + W.format("r"),
                           SEC + '\nallow ai\nai fn ask(q: Str) -> Str { "{q}" }')
                self.secret_taint(p.error(env={"R2K": self.K}, script={"ask": [json.dumps(reply)]}))
                self.assertFalse(self.written(p))

    def test_A3_shell_output_with_secret(self):
        p = self.P('let k = env.secret("R2K")\nlet r = shell.run("cat s.txt")\n' + W.format("r"),
                   SEC + '\nallow shell ["cat"]', {"s.txt": "token=" + self.K})
        self.secret_taint(p.error(env={"R2K": self.K}))
        self.assertFalse(self.written(p))

    def test_A4_fs_read_of_secret_file(self):
        p = self.P('let k = env.secret("R2K")\nlet r = fs.read("data/s.txt")\n' + W.format("r"),
                   SEC + '\nallow fs.read ["./data"]', {"data/s.txt": self.K + "\n"})
        self.secret_taint(p.error(env={"R2K": self.K}))

    def test_A5_ai_reply_and_agent_final_answer(self):
        p = self.P('let k = env.secret("R2K")\nlet r = helper("go")\n' + W.format("r"),
                   SEC + '\nallow ai\nfn probe(x: Str) -> Str { "p" }\n'
                         'agent fn helper(goal: Str) -> Str { tools [probe]\n "Goal: {goal}" }')
        e = p.error(env={"R2K": self.K}, script={"helper": [{"final": "the key is " + self.K}]})
        self.secret_taint(e)
        self.assertFalse(self.written(p))

    def test_A6_memory_load_of_old_entry_and_input_line(self):
        store = {"version": 1, "entries": {"old": {"value": "saved " + self.K, "labels": [], "enc": 2}}}
        p = self.P('let k = env.secret("R2K")\nlet v: Str = memory.load("old") ?? ""\nmemory.save("again", trust(v, "ok"))',
                   SEC + '\nallow memory', {".sipar/memory/prog.json": json.dumps(store)}, uses="memory, secret")
        self.secret_taint(p.error(env={"R2K": self.K}))
        p = self.P('let k = env.secret("R2K")\nlet r = input("> ")\n' + W.format("r"), SEC + '\nallow io')
        self.secret_taint(p.error(env={"R2K": self.K}, stdin=io.StringIO(self.K + "\n")))

    def test_A7_guard_short_secret_and_clean_text(self):
        p = self.P('let k = env.secret("R2K")\nlet r = ask("q")\n' + W.format("r") + '\nprint("ok")',
                   SEC + '\nallow ai\nai fn ask(q: Str) -> Str { "{q}" }')
        self.assertEqual(p.run(env={"R2K": "xyz"}, script={"ask": ['"xyz and more"']}), "ok\n")   # < 4 chars
        self.assertEqual(p.run(env={"R2K": self.K}, script={"ask": ['"nothing secret"']}), "ok\n")

    def test_A8_replay_takes_the_same_path(self):
        srv = self.server()
        p = self.P(f'let k = env.secret("R2K")\nlet r = http.get("{srv.url}/echo", headers: ["Authorization": k])\n'
                   + W.format("r"), 'allow net ["127.0.0.1"]\n' + SEC)
        j = Journal()
        self.secret_taint(p.error(env={"R2K": self.K}, journal=j))
        entries = json.loads(json.dumps(j.entries))
        self.assertNotIn(self.K, json.dumps(entries))
        e = p.error(env={"R2K": self.K}, journal=Journal(replay=entries))
        self.secret_taint(e)
        self.assertFalse(self.written(p))

    def test_A9_map_keys_from_a_model_are_labelled(self):
        p = self.P('let k = env.secret("R2K")\nlet m = ask("q")\nlet ks = m.keys()\n' + W.format("ks[0]"),
                   SEC + '\nallow ai\nai fn ask(q: Str) -> Map[Int] { "{q}" }')
        self.secret_taint(p.error(env={"R2K": self.K}, script={"ask": [json.dumps({self.K: 1})]}))

    def test_A10_error_text_redacted_before_the_cut(self):
        srv = self.server()
        srv.status_body = "x" * 190 + self.K                  # the secret straddles the 200-char cut
        p = self.P(f'let k = env.secret("R2K")\nlet t = try {{ http.get("{srv.url}/status/500") }} catch e {{ e.message }}\n'
                   'print(t)', 'allow net ["127.0.0.1"]\n' + SEC)
        out = p.run(env={"R2K": self.K})
        self.assertIn("HTTP 500", out)
        self.no_leak(self.K, out)
        p = self.P('let k = env.secret("R2K")\nlet t = try { shell.run("sh -c \'cat s.txt >&2; exit 1\'") } '
                   'catch e { e.message }\nprint(t)', SEC + '\nallow shell ["sh"]', {"s.txt": "y" * 280 + self.K})
        out = p.run(env={"R2K": self.K})
        self.assertIn("status 1", out)
        self.no_leak(self.K, out)

    def test_A10b_provider_error_text_redacted_before_the_cut(self):
        key = "sk-r2-ProviderKey-0123456789"
        srv = ProviderServer(lambda h: h.reply(500, json.dumps({"error": {"message": "y" * 267 + key}})))
        self.addCleanup(srv.close)
        p = self.P('let t = try { ask("q") } catch e { e.message }\nprint(t)',
                   'allow ai\n@model("openrouter/m")\nai fn ask(q: Str) -> Str { "{q}" }')
        out = p.run(env={"OPENROUTER_API_KEY": key, "SIPAR_OPENROUTER_URL": srv.url})
        self.assertIn("HTTP 500", out)
        self.no_leak(key, out)

    def test_A11_env_get_value_holding_the_secret(self):
        p = self.P('let k = env.secret("R2K")\nlet o = env.get("R2O") ?? ""\n' + W.format("o"),
                   SEC + '\nallow env ["R2O"]')
        self.secret_taint(p.error(env={"R2K": self.K, "R2O": "pre-" + self.K}))


# ================================================================== B. providers never follow redirects

class ProviderServer:
    """127.0.0.1 OpenAI-shaped endpoint; `handler(h)` answers each request. Records every request."""

    def __init__(self, handler):
        self.hits: list[dict] = []
        srv = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, code, text, headers=None):
                data = text.encode()
                self.send_response(code)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def handle_any(self):
                n = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(n)
                srv.hits.append({"path": self.path, "headers": dict(self.headers)})
                handler(self)

            do_GET = do_POST = handle_any

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


OK_REPLY = json.dumps({"choices": [{"message": {"content": '"fine"'}}], "usage": {"prompt_tokens": 1,
                                                                                    "completion_tokens": 1}})


class B_ProviderRedirect(Base):
    KEY = "sk-r2-redirect-KEY-42"
    SRC = 'allow ai\n@model("openrouter/m")\nai fn ask(q: Str) -> Str { "{q}" }'

    def run_redirect(self, same_origin: bool):
        other = ProviderServer(lambda h: h.reply(200, OK_REPLY))
        self.addCleanup(other.close)
        target = "/v2/chat/completions" if same_origin else other.url + "/chat/completions"
        first = ProviderServer(lambda h: h.reply(200, OK_REPLY) if h.path.startswith("/v2") else
                               h.reply(302, "", {"Location": (first.url if same_origin else "") + target}))
        self.addCleanup(first.close)
        p = self.P('print(ask("q"))', self.SRC)
        e = p.error(env={"OPENROUTER_API_KEY": self.KEY, "SIPAR_OPENROUTER_URL": first.url})
        return e, first, other

    def test_B1_cross_origin_redirect_refused_key_not_forwarded(self):
        e, first, other = self.run_redirect(False)
        self.assertEqual(e.kind, "ai")
        self.assertIn("provider redirected to", e.message)
        self.assertEqual(other.hits, [])
        self.assertEqual(len(first.hits), 1)

    def test_B2_same_origin_redirect_refused_too(self):
        e, first, other = self.run_redirect(True)
        self.assertEqual(e.kind, "ai")
        self.assertIn("redirects are not followed", e.message)
        self.assertEqual([h["path"] for h in first.hits], ["/chat/completions"])


# ================================================================== C / E / F / J. Python API

class ApiBase(Base):
    def load(self, src: str):
        import sipar
        d = os.path.realpath(tempfile.mkdtemp(prefix="sipar_api2_"))
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        path = os.path.join(d, "p.sipar")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(src)
        return sipar.load(path)

    def call_err(self, prog, name, *args, env=None):
        with unittest.mock.patch.dict(os.environ, env or {}):
            try:
                prog.call(name, *args)
            except SiparRuntimeError as e:
                return e
        raise AssertionError("expected SiparError")


class C_ApiKeys(ApiBase):
    K = "Zq9-r2-SECRET-keyleak"

    def test_C1_secret_map_key_not_returned(self):
        prog = self.load('allow secret ["R2K"]\nfn keyleak() -> Map[Int] uses secret { ["{env.secret("R2K")}": 1] }')
        e = self.call_err(prog, "keyleak", env={"R2K": self.K})
        self.assertEqual(e.kind, "taint")
        self.no_leak(self.K, str(e) + repr(e))

    def test_C2_guard_untrusted_key_is_returned(self):
        prog = self.load('allow ai\nai fn m(q: Str) -> Map[Int] { "{q}" }\nfn f() -> Map[Int] uses ai { m("x") }')
        self.assertEqual(prog.call("f", mock_script={"m": ['{"a": 1}']}), {"a": 1})


ENUM_TAG = 'enum E { x(tag: Str), y(tag: Str) }\nfn g(e: E) -> E { e }\nfn mk() -> E { E.x(tag: "y") }\n'


class E_EnumTag(ApiBase):
    def test_E5_api_wrapped_form_keeps_the_variant(self):
        prog = self.load(ENUM_TAG)
        self.assertEqual(prog.call("g", {"x": {"tag": "y"}}), {"x": {"tag": "y"}})
        self.assertEqual(prog.call("mk"), {"x": {"tag": "y"}})

    def test_E6_tagged_input_only_without_a_tag_field(self):
        prog = self.load(ENUM_TAG)
        e = self.call_err(prog, "g", {"tag": "x"})
        self.assertEqual(e.kind, "decode")
        self.assertIn('{"variant": {fields}}', e.message)
        self.assertIn("named 'tag', so the {\"tag\": ...} form is not accepted", e.message)
        prog = self.load('enum S { c(r: Int), n }\nfn g(s: S) -> S { s }')            # guard: no `tag` field
        self.assertEqual(prog.call("g", {"tag": "c", "r": 2}), {"c": {"r": 2}})
        self.assertEqual(prog.call("g", {"c": {"r": 2}}), {"c": {"r": 2}})
        self.assertEqual(prog.call("g", "n"), "n")
        prog = self.load('enum T { c(r: List[Int]) }\nfn g(s: T) -> T { s }')     # fields are converted too
        self.assertEqual(prog.call("g", {"tag": "c", "r": (1, 2)}), {"c": {"r": [1, 2]}})
        self.assertEqual(prog.call("g", {"c": {"r": (1, 2)}}), {"c": {"r": [1, 2]}})

    def test_E7_ai_decode_and_schema_use_the_wrapped_form(self):
        from sipar.runtime.decode import schema
        prog = self.load(ENUM_TAG + 'allow ai\nai fn pick(q: Str) -> E { "{q}" }\nfn f() -> E uses ai { pick("q") }')
        self.assertEqual(prog.call("f", mock_script={"pick": ['{"y": {"tag": "x"}}']}), {"y": {"tag": "x"}})
        with self.assertRaises(SiparRuntimeError) as cm:     # the old tagged form is not read for this enum
            prog.call("f", mock_script={"pick": ['{"tag": "x"}'] * 5})
        self.assertIn(cm.exception.kind, ("decode", "ai"))
        p = self.P('print(pick("q"))', ENUM_TAG + 'allow ai\nai fn pick(q: Str) -> E { "{q}" }')
        p.run(script={"pick": ['{"x": {"tag": "y"}}']})
        decl = next(i for i in p.program.items if getattr(i, "name", "") == "pick")
        sch = json.dumps(schema(decl.ret, p.last.tenv))
        self.assertIn('"required": ["x"]', sch)
        self.assertNotIn('"const": "x"', sch)

    def test_E8_bad_wrapped_shapes_are_decode_errors(self):
        prog = self.load(ENUM_TAG)
        for bad in ({"z": {"tag": "q"}}, {"x": {"tag": 3}}, {"x": "y"}, {"x": {}, "y": {}}):
            with self.subTest(bad=bad):
                self.assertEqual(self.call_err(prog, "g", bad).kind, "decode")


    def test_E9_wrapped_form_fields(self):
        prog = self.load('enum F { a(tag: Str, n: Int?), b }\nfn g(e: F) -> F { e }\n')
        self.assertEqual(prog.call("g", {"a": {"tag": "t"}}), {"a": {"tag": "t", "n": None}})   # optional absent
        self.assertEqual(prog.call("g", "b"), "b")
        cases = [({"a": {"n": 1}}, "missing field 'tag' of F.a"), ("a", "variant F.a needs fields"),
                 ("zz", "'zz' is not a variant of F (a, b)"), (5, "expected F variant, got")]
        for bad, msg in cases:
            with self.subTest(bad=bad):
                e = self.call_err(prog, "g", bad)
                self.assertEqual(e.kind, "decode")
                self.assertIn(msg, e.message)
        self.assertIn("'" + "z" * 40 + "' is not", self.call_err(prog, "g", "z" * 50).message)   # cut at 40


class F_ApiWalk(ApiBase):
    def test_F1_large_flat_list_is_linear(self):
        prog = self.load('fn big() -> List[Int] { range(0, 200000) }\n'
                         'fn big2() -> List[List[Int]] { var a: List[List[Int]] = []\n var i = 0\n'
                         ' while i < 20000 { a.push([i]); i = i + 1 }\n a }')
        t = time.time()
        self.assertEqual(len(prog.call("big")), 200000)
        self.assertEqual(len(prog.call("big2")), 20000)
        self.assertLess(time.time() - t, 3.0)

    def test_F1b_deep_but_legal_nest_is_linear(self):
        prog = self.load('type N = { kids: List[N] }\nfn deep(n: Int) -> N {\n var x = N { kids: [] }\n var i = 0\n'
                         ' while i < n { x = N { kids: [x] }; i = i + 1 }\n x\n}')
        prog.call("deep", 10)
        t = time.time()
        prog.call("deep", 5000)                           # d5: old path strings grew with depth (quadratic)
        self.assertLess(time.time() - t, 2.0)

    def test_F2_deep_nest_is_a_clean_value_error(self):
        prog = self.load('type N = { kids: List[N] }\nfn deep(n: Int) -> N {\n var x = N { kids: [] }\n var i = 0\n'
                         ' while i < n { x = N { kids: [x] }; i = i + 1 }\n x\n}')
        r = prog.call("deep", 3000)                       # guard: moderately deep values still convert
        self.assertEqual(len(json.dumps(r)), len('{"kids": []}') + 3000 * len('{"kids": []}'))
        t = time.time()
        e = self.call_err(prog, "deep", 80000)
        self.assertEqual(e.kind, "value")
        self.assertIn("nested too deeply", e.message)
        self.assertLess(time.time() - t, 20)

    def test_F3_shared_value_ok_cycle_is_value_error(self):
        prog = self.load('fn shared() -> List[List[Int]] { let a = [1]\n [a, a] }\n'
                         'fn cyc() -> List[Int] { [1] }')
        self.assertEqual(prog.call("shared"), [[1], [1]])
        from sipar.api import _py_out
        x: list = [1]
        x.append(x)
        with self.assertRaises(SiparRuntimeError) as cm:
            _py_out(x, "f()")
        self.assertEqual(cm.exception.kind, "value")
        self.assertIn("f()[1]", cm.exception.message)

    def test_F4_error_path_names_the_place(self):
        prog = self.load('allow secret ["R2K"]\nfn f() -> Map[List[Str]] uses secret { ["a": ["ok", env.secret("R2K")]] }')
        e = self.call_err(prog, "f", env={"R2K": "Zq9-r2-SECRET-path"})
        self.assertEqual(e.kind, "taint")
        self.assertIn("f().a[1]", e.message)


class J_ApiErrors(ApiBase):
    K = "Zq9-r2-SECRET-fail"

    def test_J1_J2_every_attribute_redacted(self):
        prog = self.load('allow secret ["R2K"]\nfn boom() -> Int uses secret { fail("user", "key is " + env.secret("R2K")) }\n'
                         'fn boom2() -> Int uses secret { fail(env.secret("R2K"), "m") }')
        for fn in ("boom", "boom2"):
            with self.subTest(fn=fn):
                e = self.call_err(prog, fn, env={"R2K": self.K})
                text = " ".join([str(e), repr(e), repr(e.args), str(e.value), str(e.kind_value), e.kind,
                                 e.message, repr(vars(e)), str(e.file)])
                for v in vars(e).values():
                    text += " " + (str.__str__(v) if isinstance(v, str) else repr(v))
                self.no_leak(self.K, text)
                self.assertIsNone(e.__context__)
                self.assertIsNone(e.__cause__)
                self.assertIsInstance(e.kind, str)

    def test_J3_kind_stays_a_valid_word(self):
        prog = self.load('fn boom() -> Int { fail("user", "plain") }')
        e = self.call_err(prog, "boom")
        self.assertEqual((e.kind, e.message, e.value, e.kind_value), ("user", "plain", "plain", "user"))


# ================================================================== D. header values

class D_Headers(Base):
    K = 'k"ey\\x-SECRET-ü1'                     # quote, backslash and non-ASCII: escaped forms differ

    def call(self, hdr_src: str, env=None):
        srv = self.server()
        p = self.P(f'let k = env.secret("R2K")\nprint(http.get("{srv.url}/ok", headers: [{hdr_src}]))',
                   'allow net ["127.0.0.1"]\n' + SEC)
        try:
            return p.run(env=dict({"R2K": self.K}, **(env or {}))), srv
        except SiparRuntimeError as e:
            return e, srv

    def test_D1_D2_D5_crlf_in_secret_value(self):
        e, srv = self.call('"X-Key": k + "\\r\\nX-Evil: 1"')
        self.assertIsInstance(e, SiparRuntimeError)
        self.assertEqual(e.kind, "value")
        self.assertIn("X-Key", e.message)
        self.no_leak(self.K, e.message + repr(e) + str(e.args))
        self.assertEqual(srv.hits, [])

    def test_D3_bad_header_names(self):
        for name in ("X Key", "X:Key", "X\\rKey", ""):
            with self.subTest(name=name):
                e, srv = self.call(f'"{name}": "v"')
                self.assertIsInstance(e, SiparRuntimeError)
                self.assertEqual(e.kind, "value")
                self.assertEqual(srv.hits, [])

    def test_D4_control_chars_and_latin1(self):
        for val in ('k + "\\0"', '"a\x7f"', '"a\x1b[31m"', 'k + "\x85"', '"Ж"'):
            with self.subTest(val=val):
                e, srv = self.call(f'"X-V": {val}')
                self.assertIsInstance(e, SiparRuntimeError, e)
                self.assertEqual(e.kind, "value")
                self.no_leak(self.K, e.message)
                self.assertEqual(srv.hits, [])
        out, srv = self.call('"X-V": "a\\tb", "X-L": "café"')          # guard: TAB and Latin-1 are fine
        self.assertEqual(out, "hello from server\n")
        self.assertEqual(srv.hits[0]["headers"]["X-V"], "a\tb")

    def test_D7_messages_and_digit_names(self):
        out, srv = self.call('"X-0": "v"')                                  # guard: digits are token chars
        self.assertEqual(out, "hello from server\n")
        self.assertEqual(srv.hits[0]["headers"]["X-0"], "v")
        e, srv = self.call(f'"X {"n" * 300}": "v"')                          # long bad name is cut in the message
        self.assertIn("is not a valid header name", e.message)
        self.assertIn("'X " + "n" * 98 + "' is not", e.message)            # exactly 100 chars of the name
        e, srv = self.call('"X-V": "a\\nb"')
        self.assertIn("contains a line break or a control character; nothing was sent", e.message)

    def test_D8_redaction_helpers_exact(self):
        from sipar import errors as E
        s = 'q"u\\o-ü-Secret-r2d8'
        E.register_secret(s, "secret:R2D8")
        for f in forms(s) + [json.dumps(s, ensure_ascii=False)[1:-1]]:   # the whole form, not a part of it
            with self.subTest(form=f):
                self.assertEqual(E.redact_text("x " + f + " y"), "x «secret:R2D8» y")
        E.register_secret("wq4Z", "secret:R2D8S")                          # exactly MIN_SECRET_LEN chars
        self.assertEqual(E.secret_labels_in("a wq4Z b"), frozenset({"secret:R2D8S"}))
        self.assertEqual(E.escape_text(12), "12")                          # non-str input
        self.assertEqual(E.clip(12, 5), "12")
        E.register_secret("WXYZ1234", "secret:R2D8P")
        self.assertEqual(E.clip("hello WXYZ12", 100, partial=True), "hello ")        # cut secret start dropped
        self.assertEqual(E.clip("hello WXYZ12�", 100, partial=True), "hello ")  # also after a cut char
        self.assertEqual(E.clip("hello WXYZ1234", 100, partial=True), "hello «secret:R2D8P»")
        self.assertEqual(E.clip("hello WXYZWXYZ12", 100, partial=True), "hello WXYZ")  # one cut, not more
        self.assertEqual(E.clip("hello WXYZ12", 100), "hello WXYZ12")                # not partial: kept

    def test_D6_redaction_covers_escaped_forms(self):
        s = 'q"u\\o-ü-Secret-r2d6'
        register_secret(s, "secret:R2D6")
        for f in forms(s):
            self.assertNotIn(f, redact_text("x " + f + " y").replace("«secret:R2D6»", ""))
        self.assertIn("«secret:R2D6»", redact_text(repr(s.encode())))


# ================================================================== G. sipar trace on hostile journals

class G_Trace(Base):
    def trace(self, lines: list[str], *flags):
        from sipar.cli import main
        d = tempfile.mkdtemp(prefix="sipar_tr2_")
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        path = os.path.join(d, "j\x1b[2J.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        out, err = io.StringIO(), io.StringIO()
        code = main(["trace", *flags, path], out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    def test_G1_G2_huge_numbers(self):
        big = "1" + "0" * 400
        for line in (f'{{"kind":"ai","t":{big},"ms":1}}', '{"kind":"ai","t":1e400,"ms":1}',
                     f'{{"kind":"ai","t":1,"ms":{big}}}', '{"kind":"ai","t":1,"ms":1e400}',
                     f'{{"kind":"ai","t":1,"ms":1}}\n{{"kind":"x","t":{big},"ms":{big}}}'):
            with self.subTest(line=line[:40]):
                code, out, err = self.trace(line.split("\n"))
                self.assertEqual(code, 0, err)
                self.assertNotIn("internal", out + err)
                self.assertIn("(total)", out)

    def test_G3_nan_and_infinity_are_bad_lines(self):
        for lit in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(lit=lit):
                code, out, err = self.trace(['{"kind":"ai","t":1}', f'{{"kind":"ai","t":{lit},"ms":1}}'])
                self.assertEqual(code, 1)
                self.assertIn("line 2", err)
                self.assertNotIn("\x1b", err)

    def test_G4_G6_names_escaped(self):
        line = json.dumps({"kind": "ai", "fn": "x\x1b[2J‮evil", "meta": {"model": "m\x1b]0;pwn\x07\u0085"}})
        for flags in ((), ("--json",)):
            with self.subTest(flags=flags):
                code, out, err = self.trace([line], *flags)
                self.assertEqual(code, 0)
                for bad in ("\x1b", "‮", "\x07", "\u0085"):
                    self.assertNotIn(bad, out)
                if not flags:
                    self.assertIn("x\\x1b[2J\\u202eevil", out)

    def test_G5_tokens_and_usd_beyond_the_maximum_count_as_zero(self):
        from sipar.trace import summarize
        s = summarize([{"kind": "ai", "fn": "f", "response": {"usage": {"input": 10**12, "output": 5}},
                        "meta": {"usd": 1e308}}, {"kind": "ai", "fn": "f", "meta": {"usd": 1e308}}])
        r = s["functions"]["f"]
        self.assertEqual((r["tokens_in"], r["tokens_out"], r["usd"]), (0, 5, 0))

    def test_G7_deeply_nested_line(self):
        code, out, err = self.trace(['{"kind":"ai","x":' + "[" * 200000 + "]" * 200000 + "}"])
        self.assertIn(code, (0, 1))
        self.assertNotIn("internal", err)

    def test_G8_bounds_are_inclusive(self):
        from sipar import trace as T
        self.assertEqual(T._num(T.MAX_MS), T.MAX_MS)
        self.assertEqual(T._num(T.MAX_MS * 2), 0)
        self.assertEqual(T._num(0), 0)
        self.assertEqual(T._num(0.5), 0.5)
        from sipar.errors import escape_text
        self.assertEqual(escape_text("a\x1b\u202e\U000e0001"), "a\\x1b\\u202e\\U000e0001")
        self.assertEqual(T._num(-1), 0)


# ================================================================== H. timeout variables

class H_Timeouts(Base):
    def test_H1_bad_http_timeouts_use_the_default(self):
        for v in ("inf", "nan", "-1", "0", "1e300", "abc", "86400.5"):
            with self.subTest(v=v), unittest.mock.patch.dict(os.environ, {"SIPAR_HTTP_TIMEOUT": v}):
                self.assertEqual(netio.env_seconds("SIPAR_HTTP_TIMEOUT", 30.0), 30.0)
        srv = self.server()
        p = self.P(f'print(http.get("{srv.url}/ok"))', 'allow net ["127.0.0.1"]')
        for v in ("inf", "1e300", "nan"):
            with self.subTest(run=v):
                self.assertEqual(p.run(env={"SIPAR_HTTP_TIMEOUT": v}), "hello from server\n")

    def test_H2_ai_timeout_inf(self):
        srv = ProviderServer(lambda h: h.reply(200, OK_REPLY))
        self.addCleanup(srv.close)
        p = self.P('print(ask("q"))', 'allow ai\n@model("openrouter/m")\nai fn ask(q: Str) -> Str { "{q}" }')
        for v in ("inf", "1e308", "nan"):
            with self.subTest(v=v):
                out = p.run(env={"OPENROUTER_API_KEY": "sk-test", "SIPAR_OPENROUTER_URL": srv.url,
                                 "SIPAR_AI_TIMEOUT": v})
                self.assertEqual(out, "fine\n")

    def test_H3_shell_timeout_huge(self):
        p = self.P('print(shell.run("echo hi"))', 'allow shell ["echo"]')
        for v in ("1e300", "inf"):
            with self.subTest(v=v):
                self.assertEqual(p.run(env={"SIPAR_SHELL_TIMEOUT": v}), "hi\n\n")

    def test_H4_boundary(self):
        for v, want in (("86400", 86400.0), (" 2.5 ", 2.5), ("86400.5", 7.0), ("1e-9", 1e-9)):
            with self.subTest(v=v), unittest.mock.patch.dict(os.environ, {"X_T": v}):
                self.assertEqual(netio.env_seconds("X_T", 7.0), want)

    def test_H5_max_depth_variable_never_breaks_import(self):
        for v, want in (("abc", "800"), ("-5", "800"), ("0", "800"), ("99999999", "800"), ("300", "300")):
            with self.subTest(v=v):
                r = subprocess.run([sys.executable, "-c", "import sipar.runtime.interp as i; print(i.MAX_DEPTH)"],
                                   cwd=ROOT, capture_output=True, text=True, timeout=60,
                                   env=dict(os.environ, SIPAR_MAX_DEPTH=v))
                self.assertEqual(r.stdout.strip(), want, r.stderr[-300:])


# ================================================================== I. approve question

class I_Approve(Base):
    HEAD = 'allow io'

    def test_I1_I3_question_is_one_marked_line(self):
        p = self.P('let a = approve("rm -rf ~", "Approve?\\n  value (3 chars):\\n         ok\x1b[2J\u202e")\n'
                   'print(a)', self.HEAD)
        self.assertEqual(p.run(stdin=FakeTTY("y\n")), "rm -rf ~\n")
        err = p.stderr.getvalue()
        self.assertTrue(err.startswith(TERM_RESET))      # round 5 S3d: approve resets the terminal first
        err = err[len(TERM_RESET):]
        lines = err.split("\n")
        q = [ln for ln in lines if ln.startswith("  question: ")]
        self.assertEqual(len(q), 1)
        self.assertIn("\\n  value (3 chars):\\n", q[0])
        self.assertEqual(sum(1 for ln in lines if "value (" in ln and not ln.startswith("  question: ")), 1)
        self.assertNotIn("\x1b", err)
        self.assertNotIn("‮", err)
        self.assertIn("  value (8 chars):", err)

    def test_I4_denied_message_escaped(self):
        p = self.P('print(approve("x", "ok?\\n\x1b[31mfake"))', self.HEAD)
        e = p.error(stdin=FakeTTY("n\n"))
        self.assertEqual(e.kind, "denied")
        self.assertNotIn("\n", e.message)
        self.assertNotIn("\x1b", e.message)


# ================================================================== K. deep memory store

class K_MemoryDeep(Base):
    def test_K1_store_file_nested_too_deeply(self):
        p = self.P('let v: Int? = memory.load("a")\nprint(v)', 'allow memory',
                   {".sipar/memory/prog.json": '{"version": 1, "entries": {"a": ' + "[" * 100000 + "]" * 100000
                    + '}}'}, uses="memory")
        self.assertEqual(p.error().kind, "io")

    def test_K2_stored_value_too_deep_to_rebuild(self):
        deep = '{"kids": [' * 40000 + '{"kids": []}' + ']}' * 40000
        store = '{"version": 1, "entries": {"a": {"value": ' + deep + ', "labels": [], "enc": 2}}}'
        p = self.P('let v: N? = memory.load("a")\nprint(v == none)', 'allow memory\ntype N = { kids: List[N] }',
                   {".sipar/memory/prog.json": store}, uses="memory")
        self.assertEqual(p.error().kind, "io")


# ================================================================== E. memory store format

class E_MemoryEnum(Base):
    HEAD = 'allow memory\nallow ai\nenum E { x(tag: Str), y(tag: Str) }\nai fn ask(q: Str) -> Str { "{q}" }'

    def store(self, p: Prog) -> dict:
        with open(os.path.join(p.dir, ".sipar/memory/prog.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def test_E1_E2_round_trip_keeps_variant_and_label(self):
        p = self.P('let t = ask("q")\nmemory.save("e", E.x(tag: t))\nlet v: E? = memory.load("e")\n'
                   'match v { E.x(tag) => print("x {tag}"), E.y(tag) => print("y {tag}"), none => print("none") }\n'
                   'match v { E.x(tag) => fs.write("out/w.txt", tag), _ => print("?") }',
                   self.HEAD + '\nallow fs.write ["./out"]', uses="memory, ai, fs.write")
        e = p.error(script={"ask": ['"y"']})
        self.assertEqual(p.out, "x y\n")
        self.assertEqual(e.kind, "taint")                      # the untrusted label survived the store
        self.assertIn("untrusted:ai:ask", e.message)
        entry = self.store(p)["entries"]["e"]
        self.assertEqual(entry["value"], {"x": {"tag": "y"}})
        self.assertEqual(entry["enc"], 2)
        self.assertTrue(entry["labels"])

    def test_E3_old_format_without_tag_field_loads(self):
        store = {"version": 1, "entries": {"s": {"value": {"tag": "c", "r": 2}, "labels": []}}}
        p = self.P('let v: S? = memory.load("s")\nmatch v { S.c(r) => print("c {r}"), _ => print("other") }',
                   'allow memory\nenum S { c(r: Int), n }', {".sipar/memory/prog.json": json.dumps(store)}, uses="memory")
        self.assertEqual(p.run(), "c 2\n")

    def test_E4_old_ambiguous_format_fails_closed(self):
        store = {"version": 1, "entries": {"e": {"value": {"tag": "y"}, "labels": []}}}
        p = self.P('let v: E? = memory.load("e")\nprint("loaded")', self.HEAD,
                   {".sipar/memory/prog.json": json.dumps(store)}, uses="memory")
        e = p.error()
        self.assertEqual(e.kind, "io")
        self.assertIn("older format", e.message)
        self.assertIn("delete the entry and save it again", e.message)


# ================================================================== L. failed fallback attempts are charged

class L_FailedAttempts(Base):
    SRC = ('allow ai\n@model("local/bad | local/good")\nai fn ask(q: Str) -> Str {{ "{prompt}" }}\n'
           'fn main() {{\n budget({limit}) {{ print(ask("x")) }}\n}}\n')
    PROMPT = "p" * 400                      # ~100 tokens of estimate for the failed attempt

    def setUp(self):
        self.mode = "status"

        def handle(h):
            if h.server_model == "bad":
                if self.mode == "status":
                    return h.reply(500, '{"error": {"message": "boom"}}')
                return h.reply(200, json.dumps({"error": {"message": "overloaded"},       # billed, then failed
                                                "usage": {"prompt_tokens": 500, "completion_tokens": 7}}))
            return h.reply(200, json.dumps({"choices": [{"message": {"content": '"ok"'}}],
                                            "usage": {"prompt_tokens": 10, "completion_tokens": 2}}))

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, code, text):
                data = text.encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                self.server_model = json.loads(self.rfile.read(n) or b"{}").get("model")
                handle(self)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.env = {"SIPAR_LOCAL_URL": f"http://127.0.0.1:{self.httpd.server_address[1]}"}
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def prog(self, limit: str) -> Prog:
        p = Prog(self.SRC.format(prompt=self.PROMPT, limit=limit))
        self.addCleanup(p.cleanup)
        return p

    def test_L1_http_500_attempt_counts_the_estimate(self):
        e = self.prog("tokens: 60").error(env=self.env)     # 12 for the good call alone; + ~100 estimate
        j = Journal()
        self.prog("tokens: 1000").run(env=self.env, journal=j)
        bad = [x for x in j.entries if x.get("kind") == "ai"][0]["meta"]["usage"]
        self.assertEqual(bad["output"], 0)
        self.assertGreaterEqual(bad["input"], 100)
        self.assertEqual(e.kind, "budget")
        self.assertEqual(self.prog("tokens: 1000").run(env=self.env), "ok\n")    # guard

    def test_L2_reported_usage_of_a_bad_reply_counts(self):
        self.mode = "error"
        j = Journal()
        self.assertEqual(self.prog("tokens: 1000").run(env=self.env, journal=j), "ok\n")
        bad = [x for x in j.entries if x.get("kind") == "ai"][0]
        self.assertEqual(bad["meta"]["usage"], {"input": 500, "output": 7})
        self.assertEqual(self.prog("tokens: 400").error(env=self.env).kind, "budget")

    def test_L3_usd_budget_counts_the_failed_attempt(self):
        env = dict(self.env, SIPAR_PRICE_IN="1000", SIPAR_PRICE_OUT="0")    # $0.001 per token in
        self.assertEqual(self.prog("usd: 0.05").error(env=env).kind, "budget")   # ok call alone: $0.01
        self.assertEqual(self.prog("usd: 1.0").run(env=env), "ok\n")

    def test_L3b_usd_of_a_reported_failed_attempt_is_exact(self):
        self.mode = "error"
        j = Journal()
        env = dict(self.env, SIPAR_PRICE_IN="0.123456789", SIPAR_PRICE_OUT="3000")
        self.assertEqual(self.prog("tokens: 1000").run(env=env, journal=j), "ok\n")
        bad = [x for x in j.entries if x.get("kind") == "ai"][0]
        self.assertEqual(bad["meta"]["usd"], 0.021061728)           # 500 * 0.123456789e-6 + 7 * 3e-3, 9 digits

    def test_L4_replay_counts_the_same(self):
        j = Journal()
        p = self.prog("tokens: 1000")
        p.run(env=self.env, journal=j)
        entries = json.loads(json.dumps(j.entries))
        p2 = self.prog("tokens: 60")
        self.assertEqual(p2.error(journal=Journal(replay=entries)).kind, "budget")

    def test_L5_guard_missing_key_is_not_charged(self):
        src = ('allow ai\n@model("openrouter/m | mock")\nai fn ask(q: Str) -> Str {{ "{p}" }}\n'
               'fn main() {{\n budget(tokens: 200) {{ print(ask("x")) }}\n}}\n').format(p="p" * 400)   # one estimate fits, two don't
        p = Prog(src)
        self.addCleanup(p.cleanup)
        j = Journal()
        out = p.run(env={"OPENROUTER_API_KEY": ""}, journal=j, script={"ask": ['"m"']})
        self.assertEqual(out, "m\n")
        self.assertNotIn("usage", [x for x in j.entries if x.get("kind") == "ai"][0]["meta"])


if __name__ == "__main__":
    unittest.main()
