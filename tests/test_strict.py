"""Strict mode (SPEC §6.2): implicit flows. A value decided by a labelled condition (if, match, while, for,
and/or/??, return, break, continue, try/catch, callbacks, calls) carries the condition's labels; a write the
pre-upgrade cannot reach is a fatal `taint` error (no-sensitive-upgrade); an error whose occurrence depends on a
secret cannot be caught. Without `strict` (and without SIPAR_STRICT=1) nothing changes."""
import unittest

from rt_helpers import Prog

HEAD = ('allow secret ["K"]\nallow net ["example.com"]\nallow ai\nallow io\nallow memory\nallow shell ["echo"]\n'
        'enum Mood { happy, sad }\ntype Box = { v: Int }\n'
        'ai fn ok(q: Str) -> Bool { "{q}" }\nai fn txt(q: Str) -> Str { "{q}" }\n'
        'fn add(xs: List[Int], x: Int) { xs.push(x) }\n'
        'fn f(k: Str) -> Int { if k == "abc" { return 1 }\n return 2 }\n'
        'fn g(k: Str) -> Int { var c = 0\n if k == "abc" { return 1 }\n c = c + 1\n return 0 }\n')
SCRIPT = {"ok": [True], "txt": ["true"]}
SEC = "secret:K cannot flow into"
UNT = "untrusted data (untrusted:ai:{}) cannot flow into"
K = 'let k = env.secret("K")\n'


class Base(unittest.TestCase):
    def prog(self, body, strict=True, extra=""):
        src = ("strict\n" if strict else "") + HEAD + extra + \
            f'fn main() uses secret, net, ai, io, memory, shell {{\n{body}\n}}\n'
        p = Prog(src)
        self.addCleanup(p.cleanup)
        return p

    def run_ok(self, body, strict=True, env=None, **kw):
        return self.prog(body, strict, kw.pop("extra", "")).run(env={"K": "abc", "SIPAR_STRICT": "0", **(env or {})}, script=SCRIPT)

    def err(self, body, strict=True, env=None, extra=""):
        return self.prog(body, strict, extra).error(env={"K": "abc", "SIPAR_STRICT": "0", **(env or {})}, script=SCRIPT)

    def leak(self, body, sink="print(value)", **kw):
        e = self.err(K + body, **kw)
        self.assertEqual(e.kind, "taint", str(e))
        self.assertIn(f"{SEC} {sink}", str(e))
        return e


class T_Control(Base):
    """Every control construct carries its condition's labels."""

    def test_if_assign(self):
        self.leak('var a = false\nif k.starts_with("a") { a = true }\nprint(a)')

    def test_print_under_secret_pc(self):
        self.leak('if k.len() > 1 { print("x") }')

    def test_comparison_is_labelled(self):
        self.leak('print(k == "abc")')

    def test_while_count(self):
        self.leak('var i = 0\nwhile i < k.len() { i = i + 1 }\nprint(i)')

    def test_and(self):
        self.leak('let b = k == "abc" and true\nprint(b)')

    def test_or_short_circuit_assign(self):
        self.leak('var n = 0\nlet b = k == "abc" or ok("x")\nprint(b)')

    def test_match(self):
        self.leak('let m = if k == "abc" { Mood.happy } else { Mood.sad }\n'
                  'match m { Mood.happy => print("h"), Mood.sad => print("s") }')

    def test_coalesce(self):
        self.leak('let x: Int? = if k == "abc" { 1 } else { none }\nprint(x ?? 0)')

    def test_none_is_labelled(self):
        self.leak('let x: Int? = if k == "abc" { 1 } else { none }\nprint(x == none)')

    def test_return(self):
        self.leak('print(f(k))')

    def test_break(self):
        self.leak('var n = 0\nfor i in [1,2,3] { if k.len() == i { break }\n n = n + 1 }\nprint(n)')

    def test_continue(self):
        self.leak('var n = 0\nfor i in [1,2,3] { if k.len() == i { continue }\n n = n + 1 }\nprint(n)')

    def test_function_value_chosen_by_secret(self):
        self.leak('let h = if k == "abc" { fn(i: Int) -> Int => i } else { fn(i: Int) -> Int => 0 }\nprint(h(2))')

    def test_secret_url_after_branch(self):
        self.leak('var a = false\nif k.starts_with("a") { a = true }\nhttp.get("https://example.com/?x={a}")',
                  "http.get(url)")

    def test_memory_save_under_secret_pc(self):
        self.leak('if k == "abc" { memory.save("m", 1) }', "memory.save(key)")


class T_Callbacks(Base):
    def test_filter(self):
        self.leak('let xs = [1,2,3].filter(fn(i: Int) -> Bool => k.len() > i)\nprint(xs.len())')

    def test_any(self):
        self.leak('print([1,2].any(fn(i: Int) -> Bool => k.len() > i))')

    def test_map(self):
        self.leak('let ys = [1,2].map(fn(i: Int) -> Int => if k == "abc" { 1 } else { 2 })\nprint(ys)')

    def test_reduce(self):
        self.leak('let y = [1,2].reduce(0, fn(a: Int, i: Int) -> Int => if k == "abc" { a } else { a + i })\n'
                  'print(y)')

    def test_sort_by(self):
        self.leak('let ys = [1,2].sort_by(fn(i: Int) -> Int => if k == "abc" { i } else { 0 - i })\nprint(ys)')


class T_Heap(Base):
    """Containers changed under a secret condition carry it, through aliases and calls too."""

    def test_interprocedural_push(self):
        self.leak('var xs = [0]\nif k == "abc" { add(xs, 1) }\nprint(xs.len())')

    def test_alias_push(self):
        self.leak('let a = [0]\nlet b = a\nif k == "abc" { b.push(1) }\nprint(a.len())')

    def test_record_view_field(self):
        self.leak('let b = Box { v: 0 }\nlet bs = [b]\nif k == "abc" { bs[0].v = 1 }\nprint(b.v)')

    def test_assigned_from_call_is_upgraded(self):
        self.leak('var n = 0\nlet h = fn(i: Int) -> Int => i\nif k == "abc" { n = h(1) }\nprint(n)')


class T_Try(Base):
    def test_secret_decided_error_cannot_be_caught(self):
        e = self.err(K + 'var c = 0\ntry { if k == "abc" { fail("x", "y") }\n c = 1 } catch e { c = 2 }\nprint(c)')
        self.assertEqual(e.kind, "x")
        self.assertIn("depends on «secret:K», so it cannot be caught", str(e))
        self.assertTrue(getattr(e, "fatal", False))

    def test_secret_decode_cannot_be_caught(self):
        e = self.err(K + 'var c = 0\ntry { let n = k as Int\n c = 1 } catch e { c = 2 }\nprint("done")')
        self.assertEqual(e.kind, "decode")
        self.assertIn("so it cannot be caught", str(e))
        self.assertNotIn("§«", str(e))         # the note has no number for the secret mask to eat

    def test_secret_index_error_cannot_be_caught(self):
        e = self.err(K + 'let xs = [1]\nvar c = 0\ntry { let y = xs[k.len()]\n c = 1 } catch e { c = 2 }\nprint("x")')
        self.assertEqual(e.kind, "index")
        self.assertIn("so it cannot be caught", str(e))

    def test_untrusted_decided_error_labels_the_result(self):
        e = self.err('let s = txt("q")\nvar c = 0\ntry { if s == "boom" { fail("x","y") }\n c = 1 } '
                     'catch e { c = 2 }\nhttp.get("https://example.com/?c={c}")')
        self.assertEqual(e.kind, "taint")
        self.assertIn(UNT.format("txt") + " http.get(url)", str(e))

    def test_untrusted_decided_error_may_be_printed(self):
        out = self.run_ok('let s = txt("q")\nvar c = 0\ntry { if s == "boom" { fail("x","y") }\n c = 1 } '
                          'catch e { c = 2 }\nprint(c)')
        self.assertEqual(out, "1\n")

    def test_public_error_is_caught(self):
        out = self.run_ok('var c = 0\ntry { fail("x", "y") } catch e { c = 2 }\nprint(c)')
        self.assertEqual(out, "2\n")


class T_Untrusted(Base):
    def test_ai_bool_decides_url(self):
        e = self.err('let b = ok("q")\nvar n = 0\nif b { n = 1 }\nhttp.get("https://example.com/?n={n}")')
        self.assertIn(UNT.format("ok") + " http.get(url)", str(e))

    def test_decoded_bool_decides_url(self):
        e = self.err('let s = txt("q")\nlet b = s as Bool\nvar n = 0\nif b { n = 1 }\n'
                     'http.get("https://example.com/?n={n}")')
        self.assertIn(UNT.format("txt") + " http.get(url)", str(e))

    def test_ai_bool_decides_command(self):
        e = self.err('let b = ok("q")\nvar n = 0\nif b { n = 1 }\nprint(shell.run("echo {n}"))')
        self.assertIn(UNT.format("ok") + " shell.run(cmd)", str(e))

    def test_trusted_bool_decides_command(self):
        out = self.run_ok('let b = ok("q")\nlet t = trust(b, "checked")\nvar n = 0\nif t { n = 1 }\n'
                          'print(shell.run("echo {n}"))')
        self.assertEqual(out.strip(), "1")

    def test_effect_under_model_decided_test(self):
        e = self.err('let b = ok("q")\nif b { http.get("https://example.com/") }')
        self.assertIn(UNT.format("ok") + " http.get(url)", str(e))

    def test_approved_bool_decides_command(self):
        from rt_helpers import FakeTTY
        p = self.prog('let b = ok("q")\nlet t = approve(b, "go?")\nvar n = 0\nif t { n = 1 }\n'
                      'print(shell.run("echo {n}"))')
        out = p.run(env={"K": "abc", "SIPAR_STRICT": "0"}, script=SCRIPT, stdin=FakeTTY("y\n"))
        self.assertEqual(out.strip(), "1")

    def test_ai_bool_may_be_printed(self):
        self.assertEqual(self.run_ok('let b = ok("q")\nif b { print("yes") }'), "yes\n")


class T_NoFalseAlarm(Base):
    def test_public_loop(self):
        self.assertEqual(self.run_ok('var n = 0\nfor x in [1,2,3] { if x > 1 { n = n + x } }\nprint(n)'), "5\n")

    def test_var_before_secret_return(self):
        # c is written after a secret-decided return: pre-upgraded, so no fatal no-sensitive-upgrade error
        self.assertEqual(self.run_ok(K + 'let r = g(k)\nprint("done")'), "done\n")

    def test_secret_decided_value_not_used(self):
        out = self.run_ok(K + 'let n = if k == "abc" { 1 } else { 2 }\nprint("ok")')
        self.assertEqual(out, "ok\n")


class T_Switch(Base):
    """Without strict the old rules apply; SIPAR_STRICT=1 turns strict on for every program."""

    def test_non_strict_if_unchanged(self):
        out = self.run_ok(K + 'var a = false\nif k.starts_with("a") { a = true }\nprint(a)', strict=False)
        self.assertEqual(out, "true\n")

    def test_non_strict_catch_unchanged(self):
        out = self.run_ok(K + 'var c = 0\ntry { if k == "abc" { fail("x","y") }\n c = 1 } catch e { c = 2 }\n'
                          'print(c)', strict=False)
        self.assertEqual(out, "2\n")

    def test_env_switch(self):
        e = self.err(K + 'var a = false\nif k.starts_with("a") { a = true }\nprint(a)', strict=False,
                     env={"SIPAR_STRICT": "1"})
        self.assertIn(SEC, str(e))


AGENT = ('/// Probe.\nfn probe(x: Int) -> Int uses secret { let k = env.secret("K")\n'
         ' if k.len() > x { fail("user", "small") }\n x }\n'
         'agent fn ag(goal: Str) -> Int { tools [probe]\n "Goal: {goal}" }\n')


class T_Agent(Base):
    def test_secret_decided_tool_error_is_not_fed_back(self):
        p = self.prog('print(ag("go"))', extra=AGENT)
        e = p.error(env={"K": "abc"}, script={"ag": [{"tool": "probe", "args": {"x": 1}}, {"final": 2}]})
        self.assertIn("whether tool probe failed depends on «secret:K»", str(e))
        calls = p.last.providers["mock"].calls
        self.assertEqual(len(calls), 1)              # the model never saw whether the probe failed

    def test_non_strict_tool_error_fed_back(self):
        p = self.prog('print(ag("go"))', strict=False, extra=AGENT)
        out = p.run(env={"K": "abc", "SIPAR_STRICT": "0"}, script={"ag": [{"tool": "probe", "args": {"x": 1}}, {"final": 2}]})
        self.assertEqual(out, "2\n")




AGENT2 = ('/// Probe.\nfn probe(a: Str, b: Str) -> Int { ("{a}{b}") as Int }\n'
          'agent fn ag2(goal: Str) -> Int { tools [probe]\n "Goal: {goal}" }\n'
          'agent fn ag3(goal: Str) -> Mood { tools [probe]\n "Goal: {goal}" }\n'
          'ai fn mood(q: Str) -> Mood { "{q}" }\n')
K4 = {"K": "abcd", "SIPAR_STRICT": "0"}        # 4+ chars: registered for redaction
K4_OTHER = {"K": "wxyz", "SIPAR_STRICT": "0"}
CAUGHT = "cannot be caught"


class T_Leaks(Base):
    """Errors whose kind, text or existence a secret decides cannot be caught or fed back to a model in strict
    mode (critic round 1: echo-labelled taint errors, redacted messages, agent tool errors, ai fn retries)."""

    def run2(self, body, env, script=None, strict=True):
        p = self.prog(K + body, strict, AGENT2)
        return p, p.run(env=env, script=script or SCRIPT)

    def err2(self, body, env, script=None):
        p = self.prog(K + body, True, AGENT2)
        return p, p.error(env=env, script=script or SCRIPT)

    def test_taint_error_not_catchable(self):
        _, e = self.err2('try { print(k) } catch e { print("caught") }', K4)
        self.assertEqual(e.kind, "taint")
        self.assertIn("secret-flow (taint) error cannot be caught", str(e))

    def test_taint_error_catchable_without_strict(self):
        _, out = self.run2('try { print(k) } catch e { print("caught") }', K4, strict=False)
        self.assertEqual(out, "caught\n")

    def test_echo_labelled_reply_taint_not_catchable(self):
        # the model's reply equals the secret: echo-labelling makes print fail; catching it would tell
        p, e = self.err2('let r = txt("q")\ntry { print(r) } catch e { print("caught") }', K4,
                         {"txt": ["abcd"]})
        self.assertEqual(e.kind, "taint")
        self.assertNotIn("caught", p.out)

    def test_memory_key_bruteforce_stops(self):
        body = ('for c in ["wxyz", "abcd"] {\n memory.save(c, 1)\n'
                ' try { memory.save("t", memory.keys().join(",")) } catch e { print("PIN=" + c) }\n'
                ' memory.delete(c)\n}')
        for env in (K4, K4_OTHER):
            p, e = self.err2(body, env)
            self.assertEqual(e.kind, "taint")
            self.assertNotIn("PIN=", p.out)

    def test_redacted_message_not_catchable(self):
        body = 'try { let n = ("ab" + "cd") as Int\n print(n) } catch e { print(e.message) }'
        _, e = self.err2(body, K4)
        self.assertIn(f"depends on «secret:K», so it {CAUGHT}", str(e))
        _, out = self.run2(body, K4_OTHER)                 # nothing redacted: an ordinary catch
        self.assertEqual(out, 'cannot parse "abcd" as Int\n')

    def test_redacted_kind_not_catchable(self):
        body = 'try { fail("ab" + "cd", "m") } catch e { print("caught") }'
        _, e = self.err2(body, K4)
        self.assertIn(CAUGHT, str(e))
        _, out = self.run2(body, K4_OTHER)
        self.assertEqual(out, "caught\n")

    def test_redacted_message_catchable_without_strict(self):
        _, out = self.run2('try { let n = ("ab" + "cd") as Int\n print(n) } catch e { print(e.message) }',
                           K4, strict=False)
        self.assertEqual(out, 'cannot parse "«secret:K»" as Int\n')

    def test_agent_tool_error_with_redaction_not_fed_back(self):
        script = {"ag2": [{"tool": "probe", "args": {"a": "ab", "b": "cd"}}, {"final": 2}]}
        p, e = self.err2('print(ag2("go"))', K4, script)
        self.assertIn("whether tool probe failed depends on «secret:K»", str(e))
        self.assertEqual(len(p.last.providers["mock"].calls), 1)
        p, out = self.run2('print(ag2("go"))', K4_OTHER, script)
        self.assertEqual(out, "2\n")
        self.assertIn('cannot parse "abcd"', p.last.providers["mock"].calls[1]["messages"][-1]["content"])

    def test_agent_final_answer_error_with_redaction_not_fed_back(self):
        script = {"ag3": [{"final": "abcd"}, {"final": "sad"}]}
        p, e = self.err2('print(ag3("go"))', K4, script)
        self.assertIn("cannot be sent to the model of ag3", str(e))
        self.assertEqual(len(p.last.providers["mock"].calls), 1)
        p, out = self.run2('print(ag3("go"))', K4_OTHER, script)
        self.assertEqual(out, "sad\n")
        self.assertIn("'abcd' is not a variant", p.last.providers["mock"].calls[1]["messages"][-1]["content"])

    def test_agent_bad_args_with_redaction_not_fed_back(self):
        script = {"ag2": [{"tool": "probe", "args": {"a": "x", "b": "y", "abcd": 1}}, {"final": 2}]}
        p, e = self.err2('print(ag2("go"))', K4, script)
        self.assertIn("cannot be sent to the model of ag2", str(e))
        self.assertEqual(len(p.last.providers["mock"].calls), 1)
        _, out = self.run2('print(ag2("go"))', K4_OTHER, script)
        self.assertEqual(out, "2\n")

    def test_ai_fn_retry_with_redaction_not_fed_back(self):
        script = {"mood": ['"abcd"', '"sad"']}
        p, e = self.err2('print(mood("q"))', K4, script)
        self.assertIn("cannot be sent to the model of mood", str(e))
        self.assertEqual(len(p.last.providers["mock"].calls), 1)
        _, out = self.run2('print(mood("q"))', K4_OTHER, script)
        self.assertEqual(out, "sad\n")

    def test_ai_fn_retry_fed_back_without_strict(self):
        p, out = self.run2('print(mood("q"))', K4, {"mood": ['"abcd"', '"sad"']}, strict=False)
        self.assertEqual(out, "sad\n")
        self.assertIn("«secret:K»", p.last.providers["mock"].calls[1]["messages"][-1]["content"])


class T_Api(unittest.TestCase):
    """The Python API returns plain bool / None for strict-mode labelled values and refuses a secret one."""

    def test_api_results(self):
        import os
        import shutil
        import tempfile
        from unittest import mock

        import sipar
        d = tempfile.mkdtemp(prefix="sipar_strict_")
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "a.sipar")
        with open(path, "w") as fh:
            fh.write('strict\nallow secret ["K"]\nfn chk() -> Bool uses secret { let k = env.secret("K")\n'
                     ' k == "abc" }\nfn pub(x: Int) -> Bool { x > 1 }\n'
                     'fn opt(x: Int) -> Int? { if x > 1 { x } else { none } }\n')
        p = sipar.load(path)
        with mock.patch.dict(os.environ, {"K": "abc"}):
            self.assertIs(p.call("pub", 2), True)
            self.assertIsNone(p.call("opt", 0))
            self.assertEqual(p.call("opt", 5), 5)
            with self.assertRaises(sipar.SiparError) as cm:
                p.call("chk")
        self.assertEqual(cm.exception.kind, "taint")


if __name__ == "__main__":
    unittest.main()
