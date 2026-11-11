"""Round-9 security fixes. Each test failed before the fix unless marked *guard*.
Fake secrets only (tok&<9+zz, hunter2X, ...).

R9-1  a secret echoed back in a stock escaped form (Go / .NET JSON \\uXXXX, HTML entities) was not labelled and
      was printed and journaled in clear
R9-2  replay always diverged when a short secret occurred inside public text of a request (?order=12345, KEY=2345),
      and the message showed two identical strings
R9-3  env.get of an NFD copy or a copy with zero-width characters inside was read, printed and journaled; print
      did not escape U+200B on a terminal
R9-4  two overlapping secrets ("hunter2X" + "Xyzzy-pass") left most of the first one in clear
R9-5  provider API keys (OPENROUTER_API_KEY, ...) could be read unlabelled with env.get
"""

import json
import os
import shutil
import sys
import tempfile
import textwrap
import threading
import time
import unicodedata
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from rt_helpers import Prog  # noqa: E402
from sipar.checker import check_source  # noqa: E402
from sipar.errors import (SecretRegistry, SiparRuntimeError, escape_controls, redact_text,  # noqa: E402
                          register_secret, secret_labels_in, use_registry)
from sipar import errors as ER  # noqa: E402
from sipar.runtime import effects as E  # noqa: E402
from sipar.runtime.journal import Journal, first_diff  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOK = "tok&<9+zz"
MARK = "«secret:KEY»"


def main(body, head, uses):
    return head + f"fn main() uses {uses} {{\n" + textwrap.dedent(body) + "\n}\n"


def prog(test, src):
    p = Prog(src)
    test.addCleanup(p.cleanup)
    program, d = check_source(src, p.path)
    test.assertEqual([(x.code, x.message) for x in d if x.severity == "error"], [])
    p.program = program
    return p


def run_journal(test, p, env, replay=None):
    """(output, journal text) of one run of p recorded to a file."""
    path = os.path.join(p.dir, "j.jsonl")
    j = Journal(path)
    try:
        out = p.run(env=env, journal=j)
    finally:
        j.close()
    with open(path, encoding="utf-8") as f:
        return out, f.read()


class Reg(unittest.TestCase):
    """Registry checks under a fresh per-test registry (as one run has)."""

    def setUp(self):
        self.reg = SecretRegistry()
        cm = use_registry(self.reg)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)

    def both(self, secret, text, label="secret:KEY"):
        register_secret(secret, label)
        return secret_labels_in(text), redact_text(text)


# ====================================================================== R9-1. stock escaped forms

class T_R9_1_EscapedForms(Reg):
    def assertCaught(self, secret, text, redacted):
        labels, red = self.both(secret, text)
        self.assertEqual(labels, {"secret:KEY"}, text)
        self.assertEqual(red, redacted)

    def test_go_json_lowercase_u(self):                       # the critic's repro
        self.assertCaught(TOK, '{"auth":"tok\\u0026\\u003c9+zz"}', '{"auth":"' + MARK + '"}')

    def test_dotnet_json_uppercase_u(self):
        self.assertCaught(TOK, '{"auth":"tok&<9\\u002Bzz"}', '{"auth":"' + MARK + '"}')

    def test_every_char_escaped_mixed_hex_case(self):
        esc = "".join(f"\\u{ord(c):04X}" if i % 2 else f"\\u{ord(c):04x}" for i, c in enumerate(TOK))
        self.assertCaught(TOK, f"a {esc} b", f"a {MARK} b")

    def test_html_named_entities(self):
        self.assertCaught(TOK, "<p>tok&amp;&lt;9+zz</p>", f"<p>{MARK}</p>")

    def test_html_quote_entities(self):
        self.assertCaught("it's\"q1", "x it&#39;s&quot;q1 y", f"x {MARK} y")
        self.reg = None

    def test_html_hex_entity_x27(self):
        self.assertCaught("it's-key", "it&#x27;s-key", MARK)

    def test_numeric_entities_decimal_and_hex(self):
        self.assertCaught(TOK, "tok&#38;&#x3C;9&#43;zz", MARK)

    def test_percent_lowercase_and_partial(self):
        self.assertCaught(TOK, "q=tok%26<9%2bzz&x=1", f"q={MARK}&x=1")

    def test_backslash_x_and_simple_escapes(self):
        self.assertCaught('a"b/c\\9', 'v="a\\"b\\/c\\\\9"', f'v="{MARK}"')

    def test_surrogate_pair_escape(self):
        self.assertCaught("k\U0001F600y9", "k\\ud83d\\ude00y9", MARK)

    def test_unknown_entity_and_bad_escape_stay(self):        # guard: no false decoding
        register_secret(TOK, "secret:KEY")
        for t in ("&foo; \\u0041 &#1114112; \\uZZZZ %G1", "tok&<9+z"):
            self.assertEqual(secret_labels_in(t), frozenset())
            self.assertEqual(redact_text(t), t)

    def test_literal_entity_in_secret_still_found(self):      # guard: the plain text is searched too
        self.assertCaught("a&amp;b12", "x a&amp;b12 y", f"x {MARK} y")

    def test_only_the_escaped_copy_is_redacted(self):         # guard: neighbours stay readable
        self.assertCaught(TOK, "\\u0041 tok\\u0026<9+zz \\u0042", f"\\u0041 {MARK} \\u0042")

    def test_one_mb_response_is_fast(self):
        register_secret(TOK, "secret:KEY")
        row = '{"id":12345,"name":"some \\u0026 text \\"q\\"","url":"https:\\/\\/x.y\\/z"},'
        big = row * (1_000_000 // len(row)) + '{"auth":"tok\\u0026\\u003c9\\u002Bzz"}'
        if hasattr(ER, "search_view"):
            ER.search_view.cache_clear()          # time a cold run
        t = time.perf_counter()
        labels, red = secret_labels_in(big), redact_text(big)
        self.assertLess(time.perf_counter() - t, 5.0)
        self.assertEqual(labels, {"secret:KEY"})
        self.assertTrue(red.endswith('{"auth":"' + MARK + '"}'))
        self.assertNotIn("9\\u002Bzz", red)


class _Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        a = self.headers.get("Authorization", "")
        mode = self.path.strip("/").split("?")[0]
        body = {"go": '{"auth":"' + a.replace("&", "\\u0026").replace("<", "\\u003c") + '"}',
                "net": '{"auth":"' + a.replace("+", "\\u002B") + '"}',
                "html": "<p>" + a.replace("&", "&amp;").replace("<", "&lt;") + "</p>",
                "plain": "ok"}[mode]
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class T_R9_Http(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
        cls.port = cls.srv.server_address[1]
        cls.th = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.th.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def head(self):
        return f'allow secret ["KEY"]\nallow net ["127.0.0.1:{self.port}"]\nallow io\n'

    def test_echo_modes_are_secret_and_redacted(self):          # R9-1 end to end, as the critic ran it
        body = (f'let k = env.secret("KEY")\nfor m in ["go", "net", "html"] {{\n'
                f'  let r = http.get("http://127.0.0.1:{self.port}/{{m}}", headers: ["Authorization": k])\n'
                f'  try {{ print(r) }} catch e {{ print(e.kind) }}\n}}')
        p = prog(self, main(body, self.head(), "secret, net, io"))
        out, journal = run_journal(self, p, {"KEY": TOK})
        self.assertEqual(out, "taint\ntaint\ntaint\n")
        self.assertEqual(journal.count(MARK), 6)                  # 3 requests + 3 responses
        for piece in ("9+zz", "9\\\\u002Bzz", "tok\\\\u0026", "tok&amp;"):
            self.assertNotIn(piece, journal)

    def replay(self, p, path, env):
        j = Journal(replay=Journal.load(path))
        try:
            return p.run(env=env, journal=j)
        finally:
            j.close()

    def test_replay_short_secret_in_public_url(self):            # R9-2, the critic's repro
        body = (f'let k = env.secret("KEY")\n'
                f'let r = http.get("http://127.0.0.1:{self.port}/plain?order=12345", headers: ["X-Key": k])\n'
                f'print(r.len())')
        p = prog(self, main(body, self.head(), "secret, net, io"))
        out, journal = run_journal(self, p, {"KEY": "2345"})
        self.assertIn("order=1«secret:KEY»", journal)
        self.assertNotIn("2345", journal)
        self.assertEqual(self.replay(p, os.path.join(p.dir, "j.jsonl"), {"KEY": "2345"}), out)

    def test_replay_real_divergence_still_found(self):           # R9-2 guard: a changed URL still diverges
        src = main(f'let k = env.secret("KEY")\nlet r = http.get("http://127.0.0.1:{self.port}/plain?order=12345", '
                   f'headers: ["X-Key": k])\nprint(r.len())', self.head(), "secret, net, io")
        p = prog(self, src)
        run_journal(self, p, {"KEY": "2345"})
        p2 = prog(self, src.replace("order=12345", "order=12346"))
        with self.assertRaises(SiparRuntimeError) as cm:
            self.replay(p2, os.path.join(p.dir, "j.jsonl"), {"KEY": "2345"})
        e = cm.exception
        self.assertEqual(e.kind, "replay")
        self.assertIn(".url differs", e.message)
        self.assertIn("order=1«secret:KEY»", e.message)               # journal side
        self.assertIn("order=12346", e.message)                       # program side, secret not in it
        self.assertNotIn("2345", redact_text(e.message, e.registry if hasattr(e, "registry") else None))


class T_R9_2_FirstDiff(Reg):
    def test_identical_looking_strings_say_why(self):
        register_secret("2345", "secret:KEY")
        d = first_diff({"url": "u?order=12345"}, {"url": "u?order=1«secret:KEY»"})
        self.assertIn("differ inside text that matches a secret value", d)

    def test_visible_difference_has_no_note(self):              # guard
        register_secret("2345", "secret:KEY")
        d = first_diff({"url": "u?order=1"}, {"url": "u?order=2"})
        self.assertNotIn("secret value", d)

    def test_journal_scrub_compare_unit(self):
        j = Journal(replay=[{"seq": 1, "kind": "http", "request": {"url": "u?o=1«secret:KEY»"}, "response": "x"}])
        j.add_secret("2345", "secret:KEY")
        self.assertEqual(j.effect("http", {"url": "u?o=12345"}, lambda: None), "x")


# ====================================================================== R9-3. Unicode forms

CAFE = "Café+tok/9"


class T_R9_3_Unicode(Reg):
    def test_nfd_copy_labelled_and_redacted(self):
        nfd = unicodedata.normalize("NFD", CAFE)
        self.assertNotEqual(nfd, CAFE)
        self.assertEqual(self.both(CAFE, f"a {nfd} b"), ({"secret:KEY"}, f"a {MARK} b"))

    def test_nfc_copy_of_nfd_secret(self):
        self.assertEqual(self.both(unicodedata.normalize("NFD", CAFE), f"a {CAFE} b"), ({"secret:KEY"}, f"a {MARK} b"))

    def test_zero_width_inside(self):
        for zw in ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"):
            reg = SecretRegistry()
            with use_registry(reg):
                register_secret(CAFE, "secret:KEY")
                t = "x " + CAFE[:3] + zw + CAFE[3:] + " y"
                self.assertEqual((secret_labels_in(t), redact_text(t)), ({"secret:KEY"}, f"x {MARK} y"), repr(zw))

    def test_fullwidth_copy(self):                               # NFKC: ｔｏｋ -> tok
        wide = "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in TOK)
        self.assertEqual(self.both(TOK, wide), ({"secret:KEY"}, MARK))

    def test_cyrillic_text_untouched(self):                      # guard: decomposed chars map back exactly
        register_secret(TOK, "secret:KEY")
        t = "йод ё " + TOK + " Привет"
        self.assertEqual(redact_text(t), f"йод ё {MARK} Привет")

    def holds(self, secret, value):
        caps = mock.Mock()
        caps.secret_names.return_value = ["KEY"]
        caps.grants = {}
        with mock.patch.dict(os.environ, {"KEY": secret}):
            return E.holds_secret(value, caps)

    def test_holds_secret_nfd_zw_entity_mixed_case(self):
        for v in (unicodedata.normalize("NFD", CAFE), CAFE[:2] + "\u200b" + CAFE[2:], "Caf&eacute;+tok/9",
                  unicodedata.normalize("NFD", CAFE.swapcase())):
            self.assertEqual(self.holds(CAFE, v), ["KEY"], repr(v))
        self.assertEqual(self.holds(CAFE, "Cafe+tok/9"), [])      # guard: no accent is another value

    def test_holds_secret_short_secret_with_zw(self):
        self.assertEqual(self.holds("ab1", " a\u200bb1 "), ["KEY"])

    def env_get(self, foo):
        src = main('try { let v = env.get("FOO") ?? "none"\n print(v) } catch e { print(e.kind) }',
                   'allow secret ["KEY"]\nallow env ["FOO"]\nallow io\n', "env, io")
        p = prog(self, src)
        return run_journal(self, p, {"KEY": CAFE, "FOO": foo})

    def test_env_get_nfd_and_zw_copies_not_printed_or_journaled(self):   # the critic's repro
        for foo in (unicodedata.normalize("NFD", CAFE), "a " + CAFE[:4] + "\u200b" + CAFE[4:]):
            out, journal = self.env_get(foo)
            self.assertEqual(out, "taint\n", repr(foo))
            self.assertNotIn("tok/9", journal)
            self.assertNotIn("tok\\/9", journal)

    def test_shell_env_drops_nfd_copy(self):
        caps = mock.Mock()
        caps.secret_names.return_value = ["KEY"]
        caps.grants = {"env": ["FOO"]}
        with use_registry(SecretRegistry()), mock.patch.dict(
                os.environ, {"KEY": CAFE, "FOO": unicodedata.normalize("NFD", CAFE)}):
            self.assertNotIn("FOO", E.shell_env(caps))

    def test_print_escapes_invisible_on_terminal(self):
        self.assertEqual(escape_controls("a\u200bb\u2060c\ufeffd\u2064"), "a\\u200bb\\u2060c\\ufeffd\\u2064")

    def test_zwj_emoji_kept(self):                               # guard: ZWJ sequences still draw
        self.assertEqual(escape_controls("\U0001F468\u200d\U0001F469"), "\U0001F468\u200d\U0001F469")


# ====================================================================== R9-4. overlapping secrets

class T_R9_4_Overlap(Reg):
    def test_overlap_union_redacted(self):                       # the critic's repro
        register_secret("hunter2X", "secret:A")
        register_secret("Xyzzy-pass", "secret:B")
        self.assertEqual(redact_text("token=hunter2Xyzzy-pass end"), "token=«secret:A»«secret:B» end")

    def test_three_way_chain(self):
        for s, n in (("aaa1b", "A"), ("1bbb2", "B"), ("b2ccc", "C")):
            register_secret(s, f"secret:{n}")
        self.assertEqual(redact_text("<aaa1bbb2ccc>"), "<«secret:A»«secret:B»«secret:C»>")

    def test_nested_keeps_outer_marker(self):                    # guard (round 1 behaviour)
        register_secret("kp9r", "secret:S")
        register_secret("kp9r-tail-555", "secret:L")
        self.assertEqual(redact_text("x kp9r-tail-555 y kp9r"), "x «secret:L» y «secret:S»")

    def test_adjacent_not_merged(self):                          # guard
        register_secret("hunter2X", "secret:A")
        self.assertEqual(redact_text("hunter2Xhunter2X"), "«secret:A»«secret:A»")

    def test_self_overlapping_secret(self):
        register_secret("abab", "secret:A")
        self.assertEqual(redact_text("xababab"), "x«secret:A»")

    def test_journal_scrub_overlap(self):
        j = Journal()
        j.add_secret("hunter2X", "secret:A")
        j.add_secret("Xyzzy-pass", "secret:B")
        self.assertEqual(j.scrub({"t": "token=hunter2Xyzzy-pass"}), {"t": "token=«secret:A»«secret:B»"})

    def test_marker_text_not_matched_by_a_secret(self):          # guard: no re-redaction inside a marker
        register_secret("secret:A", "secret:A")
        register_secret("cret", "secret:C")
        self.assertEqual(redact_text("x secret:A"), "x «secret:A»")


# ====================================================================== R9-5. provider API keys

class T_R9_5_ProviderKeys(unittest.TestCase):
    KEY = "sk-or-fake-r9-1234"

    def run_src(self, head, body, env, uses="env, io"):
        p = prog(self, main(body, head, uses))
        return run_journal(self, p, env)

    def test_env_get_of_provider_key_refused(self):
        for name in ("OPENROUTER_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "SIPAR_LOCAL_KEY"):
            for ai in ("allow ai\n", ""):
                out, journal = self.run_src(f'{ai}allow env ["{name}"]\nallow io\n',
                                            f'try {{ print(env.get("{name}") ?? "none") }} catch e {{ print(e.kind) }}',
                                            {name: self.KEY})
                self.assertEqual(out, "capability\n", (name, ai))
                self.assertNotIn(self.KEY, journal)

    def test_copy_in_other_variable_labelled_with_allow_ai(self):
        out, journal = self.run_src('allow ai\nallow env ["FOO"]\nallow io\n',
                                    'try { print(env.get("FOO") ?? "none") } catch e { print(e.kind) }',
                                    {"OPENROUTER_API_KEY": self.KEY, "FOO": f"x {self.KEY}"})
        self.assertEqual(out, "taint\n")
        self.assertNotIn(self.KEY, journal)
        self.assertIn("«secret:OPENROUTER_API_KEY»", journal)

    def test_mixed_case_copy_refused_with_allow_ai(self):
        out, journal = self.run_src('allow ai\nallow env ["FOO"]\nallow io\n',
                                    'try { print(env.get("FOO") ?? "none") } catch e { print(e.kind) }',
                                    {"OPENAI_API_KEY": self.KEY, "FOO": self.KEY.swapcase()})
        self.assertEqual(out, "taint\n")
        self.assertNotIn(self.KEY.swapcase(), journal)

    def test_without_allow_ai_other_variable_is_plain(self):      # guard: documented scope
        out, _ = self.run_src('allow env ["FOO"]\nallow io\n', 'print(env.get("FOO") ?? "none")',
                              {"OPENROUTER_API_KEY": self.KEY, "FOO": "plain"})
        self.assertEqual(out, "plain\n")

    def test_env_secret_still_reads_it(self):                    # guard: the allowed way
        out, journal = self.run_src('allow secret ["OPENAI_API_KEY"]\nallow io\n',
                                    'let k = env.secret("OPENAI_API_KEY")\nprint(k == "")',
                                    {"OPENAI_API_KEY": self.KEY}, "secret, io")
        self.assertEqual(out, "false\n")
        self.assertNotIn(self.KEY, journal)

    def test_shell_env_drops_provider_key_with_allow_ai(self):
        caps = mock.Mock()
        caps.secret_names.return_value = []
        caps.grants = {"ai": None, "env": ["OPENAI_API_KEY", "FOO"]}
        with use_registry(SecretRegistry()), mock.patch.dict(
                os.environ, {"OPENAI_API_KEY": self.KEY, "FOO": f"a{self.KEY}"}):
            env = E.shell_env(caps)
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotIn("FOO", env)


if __name__ == "__main__":
    unittest.main()
