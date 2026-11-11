"""Round-7 security fixes. Each test failed before the fix unless marked *guard*.

R7-1  a secret in the kind of fail(kind, msg) was printed / returned raw (only registered values were redacted)
R7-2  the same kind went into the tool-error text fed to an agent's model and into the journal
R7-3  an MCP timeout did not hold when the server left a setsid grandchild holding its pipes
R7-4  an index error showed the length of a list built from a secret, and was unlabelled in `catch`
R7-6  a secret under 4 characters, or a mixed-case copy, reached a child's environment / env.get
"""

import json
import os
import signal
import sys
import tempfile
import textwrap
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from rt_helpers import Prog  # noqa: E402
from sipar.checker import check_source  # noqa: E402
from sipar.errors import SiparRuntimeError  # noqa: E402
from sipar.runtime.journal import Journal  # noqa: E402

SECRET = "abc-123-zzz"                       # fake secret values
SHORT = "Q9z"
MARK = "«secret:R7_TOKEN»"
HEAD = 'allow secret ["R7_TOKEN"]\nallow io\n'


def forms(v):
    """Forms of a fake secret that must never show up."""
    return {v, v.upper(), v.lower(), v.replace("-", " "), v.replace("-", "")} - {""}


def prog(test, src):
    p = Prog(src)
    test.addCleanup(p.cleanup)
    program, d = check_source(src, p.path)
    test.assertEqual([(x.code, x.message) for x in d if x.severity == "error"], [])
    p.program = program
    return p


def main(body, head=HEAD, uses="secret, io"):
    return head + f"fn main() uses {uses} {{\n" + textwrap.dedent(body) + "\n}\n"


class T_R7_1_FailKind(unittest.TestCase):
    """R7-1: the kind of fail() is masked by its labels."""

    def err(self, body, secret=SECRET, **kw):
        p = prog(self, main(body, **kw))
        j = Journal(os.path.join(p.dir, "j.jsonl"))
        try:
            e = p.error(env={"R7_TOKEN": secret}, journal=j)
        finally:
            j.close()
        with open(os.path.join(p.dir, "j.jsonl"), encoding="utf-8") as f:
            self.journal = f.read()
        return e

    def assert_clean(self, e, secret=SECRET):
        for text in (e.kind, e.message, e.render(), repr(e), str(e), self.journal):
            for f in forms(secret):
                self.assertNotIn(f, text)

    def test_transformed_secret_kind_masked(self):
        e = self.err('let s = env.secret("R7_TOKEN")\nfail(s.split("-").join(" "), "boom")')
        self.assertEqual(e.kind, MARK)
        self.assertIn(f"runtime error[{MARK}]: boom", e.render())
        self.assert_clean(e)

    def test_short_secret_kind_masked(self):
        e = self.err('let s = env.secret("R7_TOKEN")\nfail(s, "boom")', secret=SHORT)
        self.assertEqual(e.kind, MARK)
        self.assertNotIn(SHORT, e.render())

    def test_secret_nested_in_kind_masked(self):
        e = self.err('let s = env.secret("R7_TOKEN")\nfail("pre-{s.lower()}-post", "boom")', secret=SHORT)
        self.assertEqual(e.kind, MARK)
        self.assertNotIn(SHORT.lower(), e.render())

    def test_secret_length_in_kind_masked(self):
        e = self.err('let s = env.secret("R7_TOKEN")\nfail("len{s.len()}", "boom")')
        self.assertEqual(e.kind, MARK)
        self.assertNotIn("11", e.render())

    def test_two_secrets_in_kind_both_named(self):
        head = 'allow secret ["R7_TOKEN", "R7_B"]\nallow io\n'
        p = prog(self, main('let a = env.secret("R7_TOKEN")\nlet b = env.secret("R7_B")\nfail(a + b, "x")', head))
        e = p.error(env={"R7_TOKEN": SHORT, "R7_B": "k2"})
        self.assertEqual(e.kind, "«secret:R7_B,secret:R7_TOKEN»")

    def test_catch_then_refail_kind_masked(self):
        e = self.err('let s = env.secret("R7_TOKEN")\ntry { fail("x{s}", "a") } catch e { fail(e.kind, "again") }',
                     secret=SHORT)
        self.assertEqual(e.kind, MARK)
        self.assertEqual(e.message, "again")

    def test_caught_secret_kind_keeps_its_label(self):           # guard: `catch` still sees a secret
        e = self.err('let s = env.secret("R7_TOKEN")\ntry { fail(s, "a") } catch e { print(e.kind) }', secret=SHORT)
        self.assertEqual(e.kind, "taint")
        self.assertIn("secret:R7_TOKEN", e.message)

    def test_plain_kind_unchanged(self):                         # guard
        e = self.err('fail("my_kind", "plain")')
        self.assertEqual((e.kind, e.message), ("my_kind", "plain"))

    def test_untrusted_kind_shown_with_controls_escaped(self):   # guard: documented choice
        src = 'allow ai\nallow io\nai fn word() -> Str { "w" }\nfn main() uses ai, io {\n    fail(word(), "m")\n}\n'
        p = prog(self, src)
        e = p.error(script={"word": ["bad\x1b[31mkind\nline"]})
        self.assertEqual(e.kind, "bad\x1b[31mkind\nline")
        self.assertNotIn("\x1b", e.render())
        self.assertIn("runtime error[bad\\x1b[31mkind", e.render())

    def test_api_kind_masked(self):
        import sipar
        d = tempfile.mkdtemp(prefix="sipar_r7_")
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        path = os.path.join(d, "k.sipar")
        with open(path, "w", encoding="utf-8") as f:
            f.write('allow secret ["R7_TOKEN"]\nfn main() uses secret {\n    let s = env.secret("R7_TOKEN")\n'
                    '    fail(s.split("-").join(" "), "boom")\n}\n')
        old = os.environ.get("R7_TOKEN")
        os.environ["R7_TOKEN"] = SECRET
        try:
            with self.assertRaises(sipar.SiparError) as c:
                sipar.load(path).call("main")
        finally:
            if old is None:
                del os.environ["R7_TOKEN"]
            else:
                os.environ["R7_TOKEN"] = old
        e = c.exception
        self.assertEqual((e.kind, e.kind_value), (MARK, MARK))
        for text in (e.kind, e.message, str(e), repr(e)):
            for f in forms(SECRET):
                self.assertNotIn(f, text)


AGENT = '''allow ai
allow secret ["R7_TOKEN"]
allow io
/// Leaks.
fn leak() -> Str uses secret {
    let s = env.secret("R7_TOKEN")
    fail(s.split("-").join(" "), "nope")
}
@max_steps(3)
agent fn helper(goal: Str) -> Str uses secret {
    tools [leak]
    "Do: {goal}"
}
fn main() uses ai, secret, io {
    print(helper("x"))
}
'''


class T_R7_2_AgentFeedback(unittest.TestCase):
    """R7-2: the tool-error text sent to the model and written to the journal never carries a secret kind."""

    def run_agent(self, secret):
        p = prog(self, AGENT)
        path = os.path.join(p.dir, "j.jsonl")
        j = Journal(path)
        try:
            out = p.run(env={"R7_TOKEN": secret}, journal=j,
                        script={"helper": [{"tool": "leak", "args": {}}, {"final": "done"}]})
        finally:
            j.close()
        with open(path, encoding="utf-8") as f:
            journal = f.read()
        prompts = json.dumps(p.last.providers["mock"].calls, ensure_ascii=False)
        return out, prompts, journal

    def test_tool_error_kind_masked_in_prompt_and_journal(self):
        out, prompts, journal = self.run_agent(SECRET)
        self.assertEqual(out, "done\n")
        self.assertIn(f"Tool leak failed with error [{MARK}]: nope", prompts)
        for f in forms(SECRET):
            self.assertNotIn(f, prompts)
            self.assertNotIn(f, journal)

    def test_short_secret_tool_error_kind_masked(self):
        out, prompts, journal = self.run_agent("Q9")
        self.assertIn(f"failed with error [{MARK}]", prompts)
        self.assertNotIn("failed with error [Q9]", prompts)
        self.assertNotIn("[Q9]", journal)


FORK_SERVER = r'''
import json, os, sys, time
pidfile = sys.argv[1]
def out(o):
    sys.stdout.write(json.dumps(o) + "\n"); sys.stdout.flush()
for line in sys.stdin:
    m = json.loads(line); i = m.get("id"); meth = m.get("method")
    if i is None:
        continue
    if meth == "initialize":
        out({"jsonrpc": "2.0", "id": i, "result": {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                                                   "serverInfo": {"name": "x", "version": "1"}}}); continue
    if meth == "tools/list":
        out({"jsonrpc": "2.0", "id": i, "result": {"tools": [{"name": "read", "inputSchema": {"type": "object"}}]}})
        continue
    if meth != "tools/call":
        out({"jsonrpc": "2.0", "id": i, "error": {"code": -32601, "message": "no"}}); continue
    if os.fork() == 0:                        # a grandchild in its own session keeps stdout/stderr open
        os.setsid()
        if os.fork() == 0:
            with open(pidfile, "w") as f:
                f.write(str(os.getpid()))
            time.sleep(25); os._exit(0)
        os._exit(0)
    time.sleep(3600)
'''


class T_R7_3_McpForkTimeout(unittest.TestCase):
    """R7-3: the MCP timeout holds although a setsid grandchild keeps the server's pipes open."""

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="sipar_r7f_")
        self.pidfile = os.path.join(self.d, "orphan.pid")
        self.srv = os.path.join(self.d, "fork_srv.py")
        with open(self.srv, "w", encoding="utf-8") as f:
            f.write(FORK_SERVER)
        self.addCleanup(self.kill_orphan)

    def kill_orphan(self):
        import shutil
        try:
            with open(self.pidfile) as f:
                pid = int(f.read())
            os.kill(pid, signal.SIGKILL)           # only the grandchild this test's server started
        except (OSError, ValueError):
            pass
        shutil.rmtree(self.d, ignore_errors=True)

    def test_timeout_holds_with_setsid_grandchild(self):
        cmd = [sys.executable, self.srv, self.pidfile]
        src = (f'allow mcp "e" {json.dumps(cmd)} tools ["read"] readonly ["read"]\nallow io\n'
               'fn main() uses mcp, io {\n    print(mcp.call("e", "read", ["path": "x"]))\n}\n')
        p = prog(self, src)
        t0 = time.monotonic()
        e = p.error(env={"SIPAR_MCP_TIMEOUT": "2"})
        took = time.monotonic() - t0
        self.assertIn("timed out after 2s", e.message)
        self.assertLess(took, 8, f"close() waited for the grandchild ({took:.1f}s)")
        self.assertTrue(os.path.exists(self.pidfile))       # the grandchild really held the pipes


class T_R7_4_IndexError(unittest.TestCase):
    """R7-4: an out-of-range index error carries the labels `len()` would have."""

    def err(self, body, secret=SECRET):
        return prog(self, main(body)).error(env={"R7_TOKEN": secret})

    def test_secret_list_length_masked(self):
        e = self.err('let s = env.secret("R7_TOKEN")\nlet xs = s.split("")\nlet r = xs[99]')
        self.assertEqual(e.kind, "index")
        self.assertNotIn("11", e.message)
        self.assertNotIn("99", e.message)
        self.assertIn(f"length {MARK}", e.message)

    def test_caught_index_error_is_secret_labelled(self):
        e = self.err('let s = env.secret("R7_TOKEN")\nlet xs = s.split("")\nvar m = ""\n'
                     'try { let r = xs[99] } catch e { m = e.message }\nprint(m)')
        self.assertEqual(e.kind, "taint")
        self.assertIn("secret:R7_TOKEN", e.message)

    def test_index_assignment_length_masked(self):
        e = self.err('let s = env.secret("R7_TOKEN")\nvar xs = s.split("")\nxs[99] = "q"')
        self.assertEqual(e.kind, "index")
        self.assertNotIn("11", e.message)

    def test_secret_item_in_public_list_masks_length(self):
        e = self.err('let s = env.secret("R7_TOKEN")\nlet xs = ["a", "b", s]\nlet r = xs[7]')
        self.assertNotIn("3", e.message)

    def test_secret_str_index_masked(self):                     # guard: already masked before
        e = self.err('let s = env.secret("R7_TOKEN")\nlet c = s[99]')
        self.assertNotIn("11", e.message)

    def test_public_index_error_unchanged(self):                # guard
        e = self.err('let xs = [1]\nlet r = xs[5]')
        self.assertEqual(e.message, "index 5 out of range (length 1)")


ENV_HEAD = 'allow env ["MYV"]\nallow secret ["R7_TOKEN"]\nallow shell ["env"]\nallow io\n'


class T_R7_6_ChildEnv(unittest.TestCase):
    """R7-6: a short or mixed-case copy of a secret never reaches a child's environment or env.get."""

    def child_env(self, token, myv):
        p = prog(self, main('let o = shell.run("env")\nprint(o.contains("MYV="))', ENV_HEAD, "shell, io"))
        return p.run(env={"R7_TOKEN": token, "MYV": myv})

    def env_get(self, token, myv):
        p = prog(self, main('try { print(env.get("MYV") ?? "none") } catch e { print(e.kind) }', ENV_HEAD,
                            "env, io"))
        path = os.path.join(p.dir, "j.jsonl")
        j = Journal(path)
        try:
            out = p.run(env={"R7_TOKEN": token, "MYV": myv}, journal=j)
        finally:
            j.close()
        with open(path, encoding="utf-8") as f:
            return out, f.read()

    def test_short_secret_value_not_in_child_env(self):
        self.assertEqual(self.child_env(SHORT, SHORT), "false\n")

    def test_short_secret_other_case_not_in_child_env(self):
        self.assertEqual(self.child_env(SHORT, SHORT.swapcase()), "false\n")

    def test_mixed_case_secret_not_in_child_env(self):
        self.assertEqual(self.child_env(SECRET, "x-AbC-123-zZz"), "false\n")

    def test_short_secret_inside_longer_value_passes(self):     # guard: documented 4-character limit
        self.assertEqual(self.child_env(SHORT, "x" + SHORT + "x"), "true\n")

    def test_public_value_passes(self):                          # guard
        self.assertEqual(self.child_env(SECRET, "plain-value"), "true\n")

    def test_env_get_short_secret_copy_is_taint(self):
        out, journal = self.env_get(SHORT, SHORT)
        self.assertEqual(out, "taint\n")
        self.assertNotIn(SHORT, journal)

    def test_env_get_mixed_case_copy_is_taint(self):
        out, journal = self.env_get(SECRET, "AbC-123-ZzZ")
        self.assertEqual(out, "taint\n")
        self.assertNotIn("AbC-123-ZzZ", journal)

    def test_env_get_upper_case_copy_is_secret(self):
        out, journal = self.env_get(SECRET, "x" + SECRET.upper())
        self.assertEqual(out, "taint\n")
        self.assertNotIn(SECRET.upper(), journal)

    def test_env_get_exact_copy_still_labelled(self):           # guard: round-6 behaviour
        out, journal = self.env_get(SECRET, "pre-" + SECRET)
        self.assertEqual(out, "taint\n")
        self.assertNotIn(SECRET, journal)


if __name__ == "__main__":
    unittest.main()
