"""Capabilities and information flow (cases C1-C11, T1-T12) including attack cases."""
import glob
import json
import os
import unittest
from pathlib import Path

from rt_helpers import FakeTTY, Prog, Server, error, main_src, run

from sipar.runtime.journal import Journal


def caps_for(head):
    p = Prog(main_src("", head))
    from sipar.runtime.interp import Interp
    return Interp(p.program, p.path).caps, p


class Net(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = Server()

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def test_C1_exact_host(self):
        out = run(f'print(http.get("{self.srv.url}/ok"))', 'allow net ["127.0.0.1"]')
        self.assertEqual(out, "hello from server\n")
        e = error('print(http.get("http://example.com/"))', 'allow net ["127.0.0.1"]')
        self.assertEqual(e.kind, "capability")

    def test_C1_port_scope(self):
        out = run(f'print(http.get("{self.srv.url}/ok"))', f'allow net ["127.0.0.1:{self.srv.port}"]')
        self.assertEqual(out, "hello from server\n")
        e = error(f'print(http.get("{self.srv.url}/ok"))', 'allow net ["127.0.0.1:1"]')
        self.assertEqual(e.kind, "capability")

    def test_C2_wildcard(self):
        caps, p = caps_for('allow net ["*.example.com"]')
        self.addCleanup(p.cleanup)
        self.assertEqual(caps.check_url("https://a.example.com/x"), "a.example.com")
        self.assertEqual(caps.check_url("https://b.a.example.com/x"), "b.a.example.com")
        for bad in ("https://example.com/", "https://evilexample.com/", "https://example.com.evil.org/",
                    "https://a.example.com.evil.org/"):
            with self.subTest(url=bad):
                with self.assertRaises(Exception) as cm:
                    caps.check_url(bad)
                self.assertEqual(cm.exception.kind, "capability")

    def test_C3_url_tricks(self):
        caps, p = caps_for('allow net ["good.com"]')
        self.addCleanup(p.cleanup)
        self.assertEqual(caps.check_url("HTTPS://GOOD.COM/a"), "good.com")
        self.assertEqual(caps.check_url("https://good.com./a"), "good.com")
        for bad in ("http://good.com@evil.com/", "http://evil.com\\@good.com/", "http://evil.com#@good.com",
                    "file:///etc/passwd", "ftp://good.com/x", "http://good.com /x", "http://evil.com/?good.com",
                    "javascript:alert(1)", "http://good.com:99999/", "//good.com/x", "http://gооd.com/",
                    "http://good.com\n.evil.com/"):
            with self.subTest(url=bad):
                with self.assertRaises(Exception) as cm:
                    caps.check_url(bad)
                self.assertEqual(cm.exception.kind, "capability")

    def test_C4_redirect_to_disallowed_host(self):
        target = f"http://localhost:{self.srv.port}/ok"
        n = len(self.srv.hits)
        e = error(f'print(http.get("{self.srv.url}/redirect?to={target}"))', 'allow net ["127.0.0.1"]')
        self.assertEqual(e.kind, "capability")
        self.assertEqual(len(self.srv.hits), n + 1)          # the redirect target was never fetched

    def test_redirect_to_allowed_host_followed(self):
        target = f"{self.srv.url}/ok"
        out = run(f'print(http.get("{self.srv.url}/redirect?to={target}"))', 'allow net ["127.0.0.1"]')
        self.assertEqual(out, "hello from server\n")

    def test_http_error_is_io(self):
        e = error(f'print(http.get("{self.srv.url}/status/500"))', 'allow net ["127.0.0.1"]')
        self.assertEqual(e.kind, "io")
        self.assertIn("500", e.message)

    def test_http_post_body(self):
        out = run(f'print(http.post("{self.srv.url}/echo", "payload"))', 'allow net ["127.0.0.1"]')
        self.assertEqual(json.loads(out)["body"], "payload")

    def test_T7_secret_header_allowed_and_redacted_in_journal(self):
        # round 2 (finding A): the echoed secret comes back labelled secret:TOK, so it is not printed here
        p = Prog(main_src(f'let k = env.secret("TOK")\nlet r = http.get("{self.srv.url}/echo", '
                          'headers: ["Authorization": "Bearer {k}"])\nprint("sent")',
                          'allow net ["127.0.0.1"]\nallow secret ["TOK"]'))
        self.addCleanup(p.cleanup)
        jpath = os.path.join(p.dir, "j.jsonl")
        j = Journal(path=jpath)
        out = p.run(journal=j, env={"TOK": "s3cr3t-VALUE-123"})
        j.close()
        self.assertEqual(out, "sent\n")
        self.assertEqual(self.srv.hits[-1]["headers"].get("Authorization"), "Bearer s3cr3t-VALUE-123")
        text = Path(jpath).read_text(encoding="utf-8")
        self.assertNotIn("s3cr3t-VALUE-123", text)
        self.assertIn("«secret:TOK»", text)

    def test_T1_untrusted_url(self):
        e = error(f'let u = http.get("{self.srv.url}/ok")\nprint(http.get("{self.srv.url}/x?q={{u}}"))',
                  'allow net ["127.0.0.1"]')
        self.assertEqual(e.kind, "taint")

    def test_T1_untrusted_post_body_blocked_before_request(self):
        n = len(self.srv.hits)
        e = error(f'let u = http.get("{self.srv.url}/ok")\nprint(http.post("{self.srv.url}/echo", u))',
                  'allow net ["127.0.0.1"]')
        self.assertEqual(e.kind, "taint")
        self.assertEqual(len(self.srv.hits), n + 1)

    def test_secret_header_name_rejected(self):
        e = error(f'let k = env.secret("TOK")\nprint(http.get("{self.srv.url}/ok", headers: [k: "x"]))',
                  'allow net ["127.0.0.1"]\nallow secret ["TOK"]', env={"TOK": "abc"})
        self.assertEqual(e.kind, "taint")


class Files(unittest.TestCase):
    def prog(self, body, head, files=None):
        p = Prog(main_src(body, head), files)
        self.addCleanup(p.cleanup)
        return p

    def test_C5_read_inside_and_escapes(self):
        p = self.prog('print(fs.read("data/a.txt"))', 'allow fs.read ["./data"]', {"data/a.txt": "A", "secret.txt": "S"})
        self.assertEqual(p.run(), "A\n")
        for path in ("secret.txt", "data/../secret.txt", "../../../../etc/hosts", "/etc/hosts", "data/..", "",
                     "./datax/a.txt"):
            with self.subTest(path=path):
                q = self.prog(f'print(fs.read("{path}"))', 'allow fs.read ["./data"]',
                              {"data/a.txt": "A", "secret.txt": "S", "datax/a.txt": "X"})
                self.assertEqual(q.error().kind, "capability")

    def test_C5_symlink_escape(self):
        p = self.prog('print(fs.read("data/link/hosts"))', 'allow fs.read ["./data"]', {"data/a.txt": "A"})
        os.symlink("/etc", os.path.join(p.dir, "data", "link"))
        self.assertEqual(p.error().kind, "capability")

    def test_C6_write_prefix_trick_and_ok(self):
        p = self.prog('fs.write("outside/x.txt", "a")', 'allow fs.write ["./out"]')
        os.makedirs(os.path.join(p.dir, "outside"))
        self.assertEqual(p.error().kind, "capability")
        self.assertFalse(os.path.exists(os.path.join(p.dir, "outside", "x.txt")))
        q = self.prog('fs.write("out/x.txt", "hello")', 'allow fs.write ["./out"]')
        os.makedirs(os.path.join(q.dir, "out"))
        q.run()
        self.assertEqual(Path(q.dir, "out", "x.txt").read_text(), "hello")

    def test_C6_write_through_symlink_refused(self):
        q = self.prog('fs.write("out/l.txt", "pwned")', 'allow fs.write ["./out"]')
        os.makedirs(os.path.join(q.dir, "out"))
        victim = os.path.join(q.dir, "victim.txt")
        Path(victim).write_text("orig")
        os.symlink(victim, os.path.join(q.dir, "out", "l.txt"))
        e = q.error()
        self.assertIn(e.kind, ("capability", "io"))
        self.assertEqual(Path(victim).read_text(), "orig")

    def test_C7_exists_outside(self):
        p = self.prog('print(fs.exists("../../etc"))', 'allow fs.read ["./data"]')
        self.assertEqual(p.error().kind, "capability")
        q = self.prog('print(fs.exists("data/a.txt"))\nprint(fs.exists("data/b.txt"))', 'allow fs.read ["./data"]',
                      {"data/a.txt": ""})
        self.assertEqual(q.run(), "true\nfalse\n")

    def test_T1_file_content_into_write_and_shell(self):
        p = self.prog('let t = fs.read("data/a.txt")\nfs.write("out/b.txt", t)',
                      'allow fs.read ["./data"]\nallow fs.write ["./out"]', {"data/a.txt": "x", "out/.keep": ""})
        self.assertEqual(p.error().kind, "taint")
        self.assertFalse(os.path.exists(os.path.join(p.dir, "out", "b.txt")))
        q = self.prog('let t = fs.read("data/a.txt")\nfs.write("out/{t}.txt", "x")',
                      'allow fs.read ["./data"]\nallow fs.write ["./out"]', {"data/a.txt": "x", "out/.keep": ""})
        self.assertEqual(q.error().kind, "taint")


class Shell(unittest.TestCase):
    def test_C8_prefix_tricks(self):
        caps, p = caps_for('allow shell ["ls", "git status"]')
        self.addCleanup(p.cleanup)
        self.assertEqual(caps.check_command("ls -la"), ["ls", "-la"])
        self.assertEqual(caps.check_command("git status -s"), ["git", "status", "-s"])
        for bad in ("ls; rm x", "lsx", "$(rm x)", "`rm x`", "git", "git push", "git statusx", "rm -rf /", "",
                    "'ls", "/bin/ls", "gitstatus"):
            with self.subTest(cmd=bad):
                with self.assertRaises(Exception) as cm:
                    caps.check_command(bad)
                self.assertEqual(cm.exception.kind, "capability")

    def test_C8_metachar_after_allowed_prefix_is_not_executed(self):
        p = Prog(main_src('print(shell.run("ls && rm victim.txt"))', 'allow shell ["ls"]'), {"victim.txt": "v"})
        self.addCleanup(p.cleanup)
        e = p.error()
        self.assertEqual(e.kind, "io")          # ls fails on '&&', nothing else runs
        self.assertTrue(os.path.exists(os.path.join(p.dir, "victim.txt")))

    def test_C9_no_shell_expansion(self):
        out = run('print(shell.run("echo $HOME * `id` $(id)"))', 'allow shell ["echo"]')
        self.assertEqual(out, "$HOME * `id` $(id)\n\n")

    def test_shell_output_untrusted(self):
        e = error('let o = shell.run("echo ls")\nprint(shell.run(o))', 'allow shell ["echo", "ls"]')
        self.assertEqual(e.kind, "taint")


class Env(unittest.TestCase):
    def test_C10_env(self):
        self.assertEqual(run('print(env.get("FOO"))\nprint(env.get("NOPE_X"))', 'allow env ["FOO", "NOPE_X"]',
                             env={"FOO": "bar"}), "bar\nnone\n")
        self.assertEqual(error('print(env.get("PATH"))', 'allow env ["FOO"]').kind, "capability")
        self.assertEqual(error('let s = env.secret("PATH")', 'allow secret ["FOO"]').kind, "capability")
        self.assertEqual(error('let s = env.secret("FOO")', 'allow secret ["FOO"]').kind, "io")

    def test_C11_no_allow_line(self):
        for body in ('print(time.now())', 'print(random.int(1, 2))', 'print(input("x"))', 'print(env.get("A"))',
                     'print(http.get("http://127.0.0.1/"))', 'print(fs.read("a"))', 'fs.write("a", "b")',
                     'print(shell.run("ls"))', 'sleep(0)', 'print(approve(1, "q"))'):
            with self.subTest(body=body):
                self.assertEqual(error(body).kind, "capability")

    def test_C11_ai_without_allow(self):
        src = 'ai fn f(x: Str) -> Str { "{x}" }\nfn main() { print(f("a")) }'
        p = Prog(src)
        self.addCleanup(p.cleanup)
        self.assertEqual(p.error().kind, "capability")

    def test_time_random(self):
        out = run('let t = time.now()\nprint(t > 1000000000.0)\nlet r = random.int(3, 3)\nprint(r)',
                  'allow time\nallow random')
        self.assertEqual(out, "true\n3\n")


SEC_HEAD = 'allow secret ["TOK"]\nallow fs.write ["./out"]\nallow shell ["echo"]\nallow net ["127.0.0.1"]\nallow io\nallow ai'


class Secrets(unittest.TestCase):
    def test_T6_secret_sinks(self):
        bodies = ['print(k)', 'print("token={k}")', 'print([k])', 'fs.write("out/a.txt", k)', 'shell.run("echo {k}")',
                  'http.post("http://127.0.0.1:9/x", k)', 'http.get("http://127.0.0.1:9/{k}")', 'print(json.encode(k))',
                  'print(input(k))', 'print(f(k))', 'print(g(k))', 'print(k.upper())', 'print(k.len())',
                  'print(k[0..2])', 'let m = ["a": k]\nprint(m)']
        tail = '\nai fn f(x: Str) -> Str { "say {x}" }\nagent fn g(x: Str) -> Str { tools []\n "do {x}" }'
        for b in bodies:
            with self.subTest(body=b):
                p = Prog(main_src('let k = env.secret("TOK")\n' + b, SEC_HEAD + tail), {"out/.keep": ""})
                self.addCleanup(p.cleanup)
                e = p.error(env={"TOK": "hunter2-secret"})
                self.assertEqual(e.kind, "taint", e.message)
                self.assertNotIn("hunter2", e.message)
                self.assertNotIn("hunter2", p.out)

    def test_T8_secret_in_fail_and_decode(self):
        e = error('let k = env.secret("TOK")\nfail("user", "bad {k}")', SEC_HEAD, env={"TOK": "hunter2-secret"})
        self.assertNotIn("hunter2", e.message)
        e = error('let k = env.secret("TOK")\nlet n = k as Int', SEC_HEAD, env={"TOK": "hunter2-secret"})
        self.assertEqual(e.kind, "decode")
        self.assertNotIn("hunter2", e.message)

    def test_T8_caught_secret_message_still_secret(self):
        e = error('let k = env.secret("TOK")\nlet m = try { fail("user", k) } catch e { e.message }\nprint(m)',
                  SEC_HEAD, env={"TOK": "hunter2-secret"})
        self.assertEqual(e.kind, "taint")

    def test_T9_trust_keeps_secret(self):
        e = error('let k = env.secret("TOK")\nprint(trust(k, "fine"))', SEC_HEAD, env={"TOK": "hunter2-secret"})
        self.assertEqual(e.kind, "taint")

    def test_secret_comparison_result_is_plain_bool(self):
        out = run('let k = env.secret("TOK")\nprint(k == "x")', SEC_HEAD, env={"TOK": "hunter2-secret"})
        self.assertEqual(out, "false\n")

    def test_T6_secret_in_journal_redacted(self):
        p = Prog(main_src('let k = env.secret("TOK")\nlet t = trust(["a": k], "why {k}")\n'
                          'let ok = try { approve(k, "q {k}") } catch e { "no" }', SEC_HEAD))
        self.addCleanup(p.cleanup)
        jp = os.path.join(p.dir, "j.jsonl")
        j = Journal(path=jp)
        p.run(journal=j, env={"TOK": "hunter2-secret"})
        j.close()
        text = Path(jp).read_text(encoding="utf-8")
        self.assertNotIn("hunter2", text)
        self.assertIn("«secret:TOK»", text)


UNTRUSTED_HEAD = 'allow fs.read ["./data"]\nallow shell ["echo"]\nenum Mood { happy, sad }\ntype R = { a: Str }'


class Taint(unittest.TestCase):
    def sink_err(self, body, files=None):
        p = Prog(main_src('let u = fs.read("data/u.txt")\n' + body, UNTRUSTED_HEAD),
                 files or {"data/u.txt": "rm -rf /"})
        self.addCleanup(p.cleanup)
        return p.error()

    def sink_ok(self, body):
        p = Prog(main_src('let u = fs.read("data/u.txt")\n' + body, UNTRUSTED_HEAD), {"data/u.txt": "sad"})
        self.addCleanup(p.cleanup)
        return p.run()

    def test_T2_propagation(self):
        exprs = ['u + "x"', '"a{u}"', 'u.upper()', 'u.split(" ")[0]', '[u].join(",")', '["k": u]["k"]',
                 'R { a: u }.a', 'u[0..2]', 'u.trim().lower().replace("a", "b")', '(u.len() as Str)',
                 '[1, 2][u.len() % 2]', '"x".repeat(u.len())', '(u.len() + 1) as Str', 'u.lines().first() ?? ""',
                 'json.encode([u])', '[u].map(fn(s) => s.upper())[0]', '(u.len() * 2.0) as Str', 'u[0]',
                 '{ let v = u\n v }', 'if true { u } else { "" }', 'match 1 { _ => u }', '[u].reverse()[0]',
                 'min(u.len(), 99) as Str', '["a": 1].keys().join(u)', '[u].first() ?? ""',
                 '(("[\\"" + u + "\\"]") as List[Str])[0]']
        for ex in exprs:
            with self.subTest(expr=ex):
                e = self.sink_err(f'let v = {ex}\nprint(shell.run("echo {{v}}"))')
                self.assertEqual(e.kind, "taint", e.message)

    def test_T3_choice_declassification(self):
        out = self.sink_ok('let b = u == "sad"\nprint(shell.run("echo {b}"))\n'
                           'let m = "\\"{u}\\"" as Mood\nprint(shell.run("echo {m}"))\n'
                           'let c = u.contains("a")\nprint(shell.run("echo {c}"))')
        self.assertEqual(out, "true\n\nsad\n\ntrue\n\n")

    def test_T4_trust_deep(self):
        out = self.sink_ok('let xs = [u, ["k": u]]\nlet t = trust(xs, "checked by regex")\n'
                           'print(shell.run("echo {t}"))')
        self.assertIn("sad", out)

    def test_T4_trust_journaled(self):
        p = Prog(main_src('let u = fs.read("data/u.txt")\nlet t = trust(u, "looked at it")', UNTRUSTED_HEAD),
                 {"data/u.txt": "x"})
        self.addCleanup(p.cleanup)
        j = Journal()
        p.run(journal=j)
        kinds = [(e["kind"], e["request"].get("reason")) for e in j.entries]
        self.assertIn(("trust", "looked at it"), kinds)
        tr = [e for e in j.entries if e["kind"] == "trust"][0]
        self.assertEqual(tr["request"]["removed"], ["untrusted:file:data/u.txt"])

    def test_T5_approve(self):
        head = UNTRUSTED_HEAD + '\nallow io'
        body = 'let u = fs.read("data/u.txt")\nlet a = approve(u, "run it?")\nprint(shell.run("echo {a}"))'
        p = Prog(main_src(body, head), {"data/u.txt": "hi"})
        self.addCleanup(p.cleanup)
        self.assertEqual(p.run(stdin=FakeTTY("y\n")), "hi\n\n")
        self.assertIn("approval needed", p.stderr.getvalue())
        e = p.error(stdin=FakeTTY("n\n"))
        self.assertEqual(e.kind, "denied")
        e = p.error(stdin=FakeTTY(""))
        self.assertEqual(e.kind, "denied")
        import io
        e = p.error(stdin=io.StringIO("y\n"))          # not a TTY: never approve, even if 'y' is piped in
        self.assertEqual(e.kind, "denied")
        self.assertIn("not a terminal", e.message)

    def test_T5_approve_replayed(self):
        head = UNTRUSTED_HEAD + '\nallow io'
        body = 'let u = fs.read("data/u.txt")\nlet a = approve(u, "ok?")\nprint(a)'
        p = Prog(main_src(body, head), {"data/u.txt": "hi"})
        self.addCleanup(p.cleanup)
        j = Journal()
        p.run(stdin=FakeTTY("y\n"), journal=j)
        r = Journal(replay=json.loads(json.dumps(j.entries)))
        import io
        self.assertEqual(p.run(stdin=io.StringIO(""), journal=r), "hi\n")

    def test_T11_untrusted_numbers(self):
        e = self.sink_err('let n = u.len() + 1\nprint(shell.run("echo {n}"))')
        self.assertEqual(e.kind, "taint")
        e = self.sink_err('let xs = ["a", "b"]\nlet i = u.len() % 2\nprint(shell.run("echo {xs[i]}"))')
        self.assertEqual(e.kind, "taint")

    def test_T12_implicit_flow_not_tracked(self):
        # documented limitation (SPEC section 6): control flow does not carry labels
        out = self.sink_ok('if u == "sad" { print(shell.run("echo yes")) }')
        self.assertEqual(out, "yes\n\n")

    def test_input_untrusted(self):
        head = 'allow io\nallow shell ["echo"]'
        import io
        e = error('let x = input("> ")\nprint(shell.run("echo {x}"))', head, stdin=io.StringIO("hi\n"))
        self.assertEqual(e.kind, "taint")
        self.assertEqual(run('print(input("> "))', head, stdin=io.StringIO("hi\n")), "> hi\n")


AGENT_HEAD = '''allow ai
allow shell ["echo", "ls"]
allow fs.write ["./out"]
allow net ["127.0.0.1"]
/// Run a command.
fn run_cmd(cmd: Str) -> Str uses shell { shell.run(cmd) }
/// Save a note.
fn save(path: Str, text: Str) uses fs.write { fs.write(path, text) }
/// Fetch a page.
fn fetch(url: Str) -> Str uses net { http.get(url) }
/// Count letters (safe tool).
fn count(s: Str) -> Int { s.len() }
agent fn helper(goal: Str) -> Str { tools [run_cmd, save, fetch, count]
 "Goal: {goal}" }
'''


class PromptInjection(unittest.TestCase):
    def test_T10_injected_tool_calls_blocked(self):
        attacks = [{"tool": "run_cmd", "args": {"cmd": "ls"}},
                   {"tool": "save", "args": {"path": "out/x.txt", "text": "pwned"}},
                   {"tool": "fetch", "args": {"url": "http://127.0.0.1:9/exfil"}}]
        for a in attacks:
            with self.subTest(tool=a["tool"]):
                p = Prog(main_src('print(helper("summarise the page"))', AGENT_HEAD), {"out/.keep": ""})
                self.addCleanup(p.cleanup)
                e = p.error(script={"helper": [a, {"final": "done"}]})
                self.assertEqual(e.kind, "taint", e.message)
                self.assertFalse(os.path.exists(os.path.join(p.dir, "out", "x.txt")))

    def test_T10_safe_tool_still_works(self):
        p = Prog(main_src('print(helper("count"))', AGENT_HEAD))
        self.addCleanup(p.cleanup)
        out = p.run(script={"helper": [{"tool": "count", "args": {"s": "abcd"}}, {"final": "it has 4"}]})
        self.assertEqual(out, "it has 4\n")
        prov = p.last.providers["mock"]
        self.assertIn("Result of count: 4", prov.calls[1]["messages"][-1]["content"])

    def test_T10_agent_result_untrusted(self):
        p = Prog(main_src('let r = helper("x")\nprint(shell.run("echo {r}"))', AGENT_HEAD))
        self.addCleanup(p.cleanup)
        self.assertEqual(p.error(script={"helper": [{"final": "ls"}]}).kind, "taint")


if __name__ == "__main__":
    unittest.main()
