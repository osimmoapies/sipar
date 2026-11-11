"""Phase 2 — model fallback chain `@model("a | b | mock")` (cases F1-F18).
Offline: every provider is a 127.0.0.1 http.server or the mock."""
from __future__ import annotations

import json
import os
import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from rt_helpers import Prog, ROOT  # noqa: F401
from sipar.checker import check_source
from sipar.runtime.journal import Journal


class ChatServer:
    """OpenAI-shaped /chat/completions; behaviour per model name:
    ("status", code) | ("sleep", seconds) | ("ok", text) | ("garbage",)."""

    def __init__(self, plan: dict):
        self.plan = plan
        self.hits: list[str] = []
        srv = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n).decode() or "{}")
                model = body.get("model", "")
                srv.hits.append(model)
                how = srv.plan.get(model, ("ok", '"default"'))
                if how[0] == "status":
                    return self._send(how[1], json.dumps({"error": {"message": f"fail {how[1]}"}}))
                if how[0] == "sleep":
                    time.sleep(how[1])
                    return self._send(200, json.dumps({"choices": [{"message": {"content": '"late"'}}]}))
                if how[0] == "garbage":
                    return self._send(200, json.dumps({"choices": [{"message": {"content": "not json at all"}}],
                                                       "usage": {"prompt_tokens": 5, "completion_tokens": 3}}))
                return self._send(200, json.dumps({"choices": [{"message": {"content": how[1]}}],
                                                   "usage": {"prompt_tokens": 10, "completion_tokens": 2}}))

            def _send(self, code, text):
                data = text.encode()
                try:
                    self.send_response(code)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except OSError:
                    pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


SRC = """allow ai
@model("{chain}")
ai fn ask(q: Str) -> Str {{ "answer {{q}}" }}
fn main() {{
    print(ask("x"))
}}
"""


class Base(unittest.TestCase):
    def setUp(self):
        self.srv = None
        self.progs: list[Prog] = []

    def tearDown(self):
        if self.srv:
            self.srv.close()
        for p in self.progs:
            p.cleanup()

    def prog(self, chain: str, src: str = SRC) -> Prog:
        p = Prog(src.format(chain=chain))
        self.progs.append(p)
        return p

    def server(self, plan: dict) -> dict:
        self.srv = ChatServer(plan)
        return {"SIPAR_LOCAL_URL": self.srv.url, "SIPAR_OPENROUTER_URL": self.srv.url,
                "OPENROUTER_API_KEY": "test-key-not-real", "SIPAR_AI_TIMEOUT": "5"}

    @staticmethod
    def ai_entries(j: Journal) -> list[dict]:
        return [e for e in j.entries if e.get("kind") == "ai"]


class TestFallback(Base):
    def run_chain(self, plan, chain="local/bad | local/good", env_extra=None):
        env = self.server(plan)
        env.update(env_extra or {})
        p = self.prog(chain)
        j = Journal()
        out = p.run(journal=j, env=env)
        return out, j

    def test_F1_http_500_falls_to_next(self):
        out, j = self.run_chain({"bad": ("status", 500), "good": ("ok", '"from good"')})
        self.assertEqual(out.strip(), "from good")
        ai = self.ai_entries(j)
        self.assertEqual(len(ai), 2)
        self.assertEqual(ai[0]["error"]["kind"], "ai")
        self.assertIn("HTTP 500", ai[0]["error"]["message"])
        # round 2 (L): a failed attempt after the request records what it counts against the budget
        self.assertEqual(ai[0]["meta"], {"model": "local/bad", "attempt": 1, "of": 2,
                                         "usage": {"input": ai[0]["meta"]["usage"]["input"], "output": 0}})
        self.assertGreater(ai[0]["meta"]["usage"]["input"], 0)
        self.assertEqual(ai[1]["meta"], {"model": "local/good", "attempt": 2, "of": 2})
        self.assertNotIn("error", ai[1])
        self.assertEqual(self.srv.hits, ["bad", "good"])

    def test_F2_http_429_falls_through(self):
        out, j = self.run_chain({"bad": ("status", 429), "good": ("ok", '"ok429"')})
        self.assertEqual(out.strip(), "ok429")
        self.assertIn("HTTP 429", self.ai_entries(j)[0]["error"]["message"])

    def test_F3_timeout_falls_through(self):
        out, j = self.run_chain({"slow": ("sleep", 2), "good": ("ok", '"fast"')}, chain="local/slow | local/good",
                                env_extra={"SIPAR_AI_TIMEOUT": "0.3"})
        self.assertEqual(out.strip(), "fast")
        self.assertIn("timed out", self.ai_entries(j)[0]["error"]["message"])

    def test_F4_connection_refused_falls_through(self):
        env = self.server({"good": ("ok", '"alive"')})
        env["SIPAR_OPENROUTER_URL"] = f"http://127.0.0.1:{closed_port()}"
        p = self.prog("openrouter/dead | local/good")
        j = Journal()
        self.assertEqual(p.run(journal=j, env=env).strip(), "alive")
        self.assertIn("cannot reach", self.ai_entries(j)[0]["error"]["message"])

    def test_F5_missing_key_falls_to_mock(self):
        p = self.prog("openrouter/x | mock")
        j = Journal()
        out = p.run(journal=j, env={"OPENROUTER_API_KEY": ""}, script=["from mock"])
        self.assertEqual(out.strip(), "from mock")
        ai = self.ai_entries(j)
        self.assertIn("OPENROUTER_API_KEY is not set", ai[0]["error"]["message"])
        self.assertEqual(ai[1]["meta"]["model"], "mock")

    def test_F6_all_fail_lists_every_model(self):
        env = self.server({"a": ("status", 503), "b": ("status", 502)})
        p = self.prog("local/a | local/b")
        e = p.error(env=env)
        self.assertEqual(e.kind, "ai")
        self.assertIn("every model in the chain failed", e.message)
        self.assertIn("local/a: local: HTTP 503", e.message)
        self.assertIn("local/b: local: HTTP 502", e.message)

    def test_F7_decode_failure_is_not_a_fallback(self):
        env = self.server({"garb": ("garbage",), "good": ("ok", '"never"')})
        src = SRC.replace('@model("{chain}")', '@model("{chain}")\n@retries(1)').replace(
            "-> Str", "-> Int")
        p = self.prog("local/garb | local/good", src)
        e = p.error(env=env)
        self.assertEqual(e.kind, "ai")
        self.assertIn("did not match", e.message)
        self.assertEqual(self.srv.hits, ["garb", "garb"])      # retried on the same model, never the next

    def test_F8_budget_counts_every_attempt(self):
        env = self.server({"bad": ("status", 500), "good": ("ok", '"x"')})
        src = """allow ai
@model("{chain}")
ai fn ask(q: Str) -> Str {{ "answer {{q}}" }}
fn main() {{
    budget(ai_calls: 1) {{
        print(ask("x"))
    }}
}}
"""
        p = self.prog("local/bad | local/good", src)
        e = p.error(env=env)
        self.assertEqual(e.kind, "budget")
        self.assertEqual(self.srv.hits, ["bad"])

    def test_F8b_budget_two_calls_is_enough(self):
        env = self.server({"bad": ("status", 500), "good": ("ok", '"x"')})
        src = """allow ai
@model("{chain}")
ai fn ask(q: Str) -> Str {{ "answer {{q}}" }}
fn main() {{
    budget(ai_calls: 2) {{
        print(ask("x"))
    }}
}}
"""
        p = self.prog("local/bad | local/good", src)
        self.assertEqual(p.run(env=env).strip(), "x")

    def test_F9_replay_of_fallback_run(self):
        out, j = self.run_chain({"bad": ("status", 500), "good": ("ok", '"from good"')})
        recorded = json.loads(json.dumps(j.entries))
        self.srv.close()
        self.srv = None
        p = self.progs[0]
        r = Journal(replay=recorded)
        out2 = p.run(journal=r, env={"SIPAR_LOCAL_URL": f"http://127.0.0.1:{closed_port()}"})
        self.assertEqual(out2, out)
        self.assertEqual(r.unused(), 0)

    def test_F10_replay_follows_journal_not_program_chain(self):
        p1 = self.prog("mock")
        j = Journal()
        out = p1.run(journal=j, script=["once"])
        p2 = self.prog("local/never | mock")          # program now has a chain; journal has one attempt
        r = Journal(replay=json.loads(json.dumps(j.entries)))
        self.assertEqual(p2.run(journal=r), out)
        self.assertEqual(r.unused(), 0)

    def test_F10b_replay_error_without_next_raises(self):
        p = self.prog("local/a | local/b")
        env = self.server({"a": ("status", 500), "b": ("status", 500)})
        j = Journal()
        p.error(journal=j, env=env)
        rec = json.loads(json.dumps(j.entries))
        self.assertEqual(len(rec), 2)
        e = p.error(journal=Journal(replay=rec))
        self.assertEqual(e.kind, "ai")
        self.assertIn("every model in the chain failed", e.message)

    def test_F11_env_chain(self):
        src = """allow ai
ai fn ask(q: Str) -> Str { "answer {q}" }
fn main() {
    print(ask("x"))
}
"""
        p = Prog(src)
        self.progs.append(p)
        j = Journal()
        out = p.run(journal=j, env={"SIPAR_MODEL": "openrouter/x | mock", "OPENROUTER_API_KEY": ""},
                    script=["env chain"])
        self.assertEqual(out.strip(), "env chain")
        self.assertEqual([e["meta"]["model"] for e in self.ai_entries(j)], ["openrouter/x", "mock"])

    def test_F12_env_empty_entry_is_ai_error(self):
        src = SRC.replace('@model("{chain}")\n', "")
        for bad in ("mock || mock", " | mock", "mock |", "|"):
            p = Prog(src.format(chain=""))
            self.progs.append(p)
            e = p.error(env={"SIPAR_MODEL": bad})
            self.assertEqual(e.kind, "ai", bad)
            self.assertTrue("empty" in e.message, e.message)

    def test_F13_env_unknown_provider_before_any_call(self):
        env = self.server({})
        src = SRC.replace('@model("{chain}")\n', "")
        p = Prog(src.format(chain=""))
        self.progs.append(p)
        j = Journal()
        e = p.error(journal=j, env=dict(env, SIPAR_MODEL="local/a | foo/x"))
        self.assertEqual(e.kind, "ai")
        self.assertIn("unknown model provider 'foo'", e.message)
        self.assertEqual(self.srv.hits, [])
        # round 8, M1: the setup failure is journaled (so replay agrees), but no request was sent
        self.assertEqual([(x["kind"], x["meta"].get("setup"), x["error"]["kind"]) for x in j.entries],
                         [("ai", True, "ai")])

    def test_F14_single_model_meta_unchanged(self):
        p = self.prog("mock")
        j = Journal()
        p.run(journal=j)
        self.assertEqual(self.ai_entries(j)[0]["meta"], {"model": "mock"})

    def test_F15_agent_walks_chain_each_step(self):
        src = """allow ai
/// Add one.
fn inc(n: Int) -> Int {{ n + 1 }}
@model("{chain}")
agent fn solve(goal: Str) -> Int {{
    tools [inc]
    "{{goal}}"
}}
fn main() {{
    print(solve("go"))
}}
"""
        p = self.prog("openrouter/x | mock", src)
        j = Journal()
        out = p.run(journal=j, env={"OPENROUTER_API_KEY": ""},
                    script=[{"tool": "inc", "args": {"n": 1}}, {"final": 7}])
        self.assertEqual(out.strip(), "7")
        models = [e["meta"]["model"] for e in j.entries if e["kind"] == "agent"]
        self.assertEqual(models, ["openrouter/x", "mock", "openrouter/x", "mock"])

    def test_F17_http_4xx_falls_through(self):
        for code in (401, 404):
            out, _ = self.run_chain({"bad": ("status", code), "good": ("ok", f'"ok{code}"')})
            self.assertEqual(out.strip(), f"ok{code}")
            self.srv.close()
            self.srv = None

    def test_F18_duplicate_model_allowed(self):
        p = self.prog("mock | mock")
        self.assertEqual(p.run(script=["dup"]).strip(), "dup")

    def test_price_goes_to_meta(self):
        p = self.prog("mock")
        j = Journal()
        p.run(journal=j, env={"SIPAR_PRICE_IN": "1000000", "SIPAR_PRICE_OUT": "0"})
        ai = self.ai_entries(j)[0]
        self.assertEqual(ai["meta"]["usd"], ai["response"]["usage"]["input"] * 1.0)

    def test_journal_fn_and_timing_fields(self):
        p = self.prog("mock")
        j = Journal()
        p.run(journal=j)
        ai = self.ai_entries(j)[0]
        self.assertEqual(ai["fn"], "ask")
        self.assertIsInstance(ai["ms"], float)
        self.assertGreater(ai["t"], 1.7e9)


class TestModelAttrChecker(unittest.TestCase):
    def codes(self, chain: str) -> list[str]:
        src = f'allow ai\n@model("{chain}")\nai fn ask(q: Str) -> Str {{ "{{q}}" }}\n'
        return [d.code for d in check_source(src, "t.sipar")[1]]

    def test_F12_checker_empty_entries(self):
        for bad in ("mock || mock", " | mock", "mock |", "", "openrouter/"):
            self.assertIn("E231", self.codes(bad), bad)

    def test_F13_checker_unknown_provider(self):
        self.assertIn("E231", self.codes("foo/x | mock"))

    def test_good_chains_pass(self):
        for good in ("mock", "openrouter/qwen/qwen3-coder | gemini/gemini-2.5-flash | mock", "local/x|mock"):
            self.assertEqual(self.codes(good), [], good)


if __name__ == "__main__":
    unittest.main()
