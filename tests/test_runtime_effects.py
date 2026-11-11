"""Direct unit tests of sipar/runtime/effects.py (written to kill mutation-test survivors, cases E1-E12)."""
import io
import os
import socket
import stat
import time
import unittest
from unittest import mock

from rt_helpers import FakeTTY, Prog, Server, error, main_src, run

from sipar.errors import SiparRuntimeError
from sipar.runtime import effects as E
from sipar.runtime.interp import Interp
from sipar.runtime.journal import Journal
from sipar.runtime.values import labels_of, set_labels


def caps_for(head):
    p = Prog(main_src("", head))
    caps = Interp(p.program, p.path).caps
    p.cleanup()
    return caps


class Out(io.StringIO):
    def __init__(self):
        super().__init__()
        self.flushes = 0

    def flush(self):
        self.flushes += 1
        super().flush()


class TTYOut(FakeTTY):
    pass


class Rt:
    """Minimal runtime object: what effects.* functions use."""

    def __init__(self, head="", rem=None, journal=None, stdin=None):
        self.caps = caps_for(head)
        self.journal = journal or Journal()
        self.out = Out()
        self.err = Out()
        self.stdin = stdin if stdin is not None else io.StringIO("")
        self.rem = rem

    def budget_remaining_seconds(self):
        return self.rem

    def time_over(self, message, extra=None):          # Interp journals the moment; enough to raise here
        raise SiparRuntimeError("budget", message)

    def replay_time_over(self, extra=None):
        pass


def kind(fn, *a):
    try:
        fn(*a)
    except SiparRuntimeError as e:
        return e.kind, str(e)
    return None, ""


ALL = 'allow net\nallow fs.read\nallow fs.write\nallow shell\nallow env\nallow time\nallow random\nallow io'


class CapsUnit(unittest.TestCase):
    def test_E1_no_grant_is_capability_error(self):
        c = caps_for("")
        for fn, args in ((c.check_url, ("http://a.com/",)), (c.resolve_path, ("x.txt", "fs.read")),
                         (c.check_command, ("ls",)), (c.check_env, ("HOME",))):
            self.assertEqual(kind(fn, *args)[0], "capability", fn.__name__)
        rt = Rt("")
        for fn, args in ((E.time_now, (rt,)), (E.random_int, (rt, 1, 2)), (E.sleep, (rt, 0)),
                         (E.input_line, (rt, "p")), (E.approve, (rt, 1, "q"))):
            self.assertEqual(kind(fn, *args)[0], "capability", fn.__name__)

    def test_E2_control_chars_in_url(self):
        c = caps_for("allow net")
        for ch in "\x01\x1f\x7f \t\\":
            self.assertEqual(kind(c.check_url, f"http://a.com/x{ch}y")[0], "capability", repr(ch))
        self.assertEqual(c.check_url("http://a.com/x!y~"), "a.com")
        self.assertIn("control characters: 'http://a.com/x\\x01y'", kind(c.check_url, "http://a.com/x\x01y")[1])
        self.assertIn("malformed URL 'http://[::1'", kind(c.check_url, "http://[::1")[1])
        self.assertIn("URL has no host: 'http:///x'", kind(c.check_url, "http:///x")[1])
        c = caps_for('allow env ["A"]')
        self.assertIn("'B' is not in 'allow env'", kind(c.check_env, "B")[1])

    def test_E3_scope_normalised(self):
        self.assertTrue(E.Caps.host_matches("good.com", 80, "GOOD.com."))
        self.assertFalse(E.Caps.host_matches("good.com", 80, " good.com"))   # round 4 C15: no strip, as E310
        self.assertFalse(E.Caps.host_matches("good.com", 80, "good.com:abc"))
        self.assertFalse(E.Caps.host_matches(".example.com", 80, "*.example.com"))
        self.assertTrue(E.Caps.host_matches("a.example.com", 80, "*.example.com"))
        self.assertFalse(E.Caps.host_matches("example.com", 80, "*.example.com"))

    def test_E3_default_ports(self):
        c = caps_for('allow net ["good.com:443", "plain.com:80"]')
        self.assertEqual(c.check_url("https://good.com/"), "good.com")
        self.assertEqual(c.check_url("HTTPS://good.com/"), "good.com")
        self.assertEqual(kind(c.check_url, "http://good.com/"),
                         ("capability", "host 'good.com' is not in 'allow net' (good.com:443, plain.com:80)"))
        self.assertEqual(c.check_url("http://plain.com/"), "plain.com")
        self.assertEqual(kind(c.check_url, "https://plain.com/")[0], "capability")
        self.assertEqual(c.check_url("http://good.com:443/"), "good.com")

    def test_E4_shell_prefix_uses_posix_quoting(self):
        c = caps_for('allow shell ["git status"]')
        self.assertEqual(c.check_command('git "status" -s'), ["git", "status", "-s"])
        c = caps_for('allow shell ["git \\"status\\""]')
        self.assertEqual(c.check_command("git status"), ["git", "status"])
        self.assertIn("command 'git' (as ['git', 'push', 'origin', 'main']) does not start with",
                      kind(c.check_command, "git push origin main --force")[1])
        self.assertEqual(run("print(shell.run(\"echo 'a b'\"))", "allow shell"), "a b\n\n")

    def test_E5_check_sinks_missing_param_and_message(self):
        E.check_sinks("http.post", {"url": "http://a.com/"})        # body absent: no KeyError
        E.check_sinks("fs.write", {"path": "x"})
        E.check_sinks("no.such.fn", {"x": 1})
        u = set_labels("evil", frozenset({"untrusted:net:x"}))
        k, msg = kind(E.check_sinks, "shell.run", {"cmd": u})
        self.assertEqual(k, "taint")
        self.assertIn("untrusted data (untrusted:net:x) cannot flow into shell.run(cmd)", msg)
        self.assertIn('check it, then use trust(x, "reason") or approve(x, "question")', msg)

    def test_E6_detail_truncation(self):
        self.assertEqual(E._detail("a" * 80), "a" * 80)
        self.assertEqual(E._detail("a" * 81), "a" * 80 + "…")
        self.assertEqual(E._detail(set_labels("pw", frozenset({"secret:P"}))), "«secret»")

    def test_E7_timeout_capped_by_budget(self):
        rt = Rt()
        with mock.patch.dict(os.environ, {"SIPAR_X": "7"}):
            self.assertEqual(E._timeout(rt, "SIPAR_X", 30), 7.0)
            rt.rem = 2.0
            self.assertEqual(E._timeout(rt, "SIPAR_X", 30), 2.0)
            rt.rem = 0.001
            self.assertEqual(E._timeout(rt, "SIPAR_X", 30), 0.05)
        with mock.patch.dict(os.environ, {"SIPAR_X": "zz"}):
            rt.rem = None
            self.assertEqual(E._timeout(rt, "SIPAR_X", 30), 30)


class Http(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = Server()

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()

    def test_E8_short_secret_redacted_in_journal_and_post_body_recorded(self):
        p = Prog(main_src(f'let k = env.secret("TOK")\n'
                          f'print(http.get("{self.srv.url}/ok", headers: ["Authorization": k]))\n'
                          f'print(http.post("{self.srv.url}/ok", "payload"))',
                          'allow net ["127.0.0.1"]\nallow secret ["TOK"]'))
        j = Journal()
        try:
            p.run(journal=j, env={"TOK": "ab9"})
        finally:
            p.cleanup()
        http = [e for e in j.entries if e["kind"] == "http"]
        self.assertEqual(http[0]["request"]["headers"], {"Authorization": "«secret:TOK»"})
        self.assertNotIn("body", http[0]["request"])
        self.assertEqual(http[1]["request"]["body"], "payload")
        self.assertEqual(self.srv.hits[-2]["headers"]["Authorization"], "ab9")   # the real value was sent
        sec = [e for e in j.entries if e["kind"] == "env.secret"]
        self.assertEqual(sec[0]["response"]["len"], 3)        # hash + length only (SPEC §7)
        self.assertEqual(set(sec[0]["response"]), {"salt", "hash", "len"})
        self.assertEqual(sec[0]["request"], {"name": "TOK"})

    def test_E8_secret_header_name_rejected(self):
        e = error('let k = env.secret("TOK")\nprint(http.get("http://127.0.0.1/", headers: [k: "v"]))',
                  'allow net ["127.0.0.1"]\nallow secret ["TOK"]', env={"TOK": "abcdef"})
        self.assertEqual(e.kind, "taint")
        self.assertIn("not header names", str(e))

    def test_E9_body_size_limit(self):
        url = f"{self.srv.url}/ok"                       # body is "hello from server" (17 bytes)
        with mock.patch.object(E, "MAX_BODY", 16):
            e = error(f'print(http.get("{url}"))', 'allow net ["127.0.0.1"]')
            self.assertEqual(e.kind, "io")
            self.assertIn("larger than 16 bytes", str(e))
        with mock.patch.object(E, "MAX_BODY", 17):
            self.assertEqual(run(f'print(http.get("{url}"))', 'allow net ["127.0.0.1"]'), "hello from server\n")

    def test_E10_http_error_body_and_refused(self):
        e = error(f'print(http.get("{self.srv.url}/status/500"))', 'allow net ["127.0.0.1"]')
        self.assertEqual(e.kind, "io")
        self.assertIn("HTTP 500", str(e))
        self.assertIn("error body xxxx", str(e))
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()                                        # nothing listens there now
        e = error(f'print(http.get("http://127.0.0.1:{port}/"))', 'allow net ["127.0.0.1"]')
        self.assertEqual(e.kind, "io")
        self.assertNotIn("URLError", str(e))
        self.assertIn("refused", str(e).lower())

    def test_E10_http_read_timeout(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(5)                                      # accepts at kernel level, never answers
        try:
            t0 = time.monotonic()
            e = error(f'print(http.get("http://127.0.0.1:{s.getsockname()[1]}/"))', 'allow net ["127.0.0.1"]',
                      env={"SIPAR_HTTP_TIMEOUT": "0.3"})
            self.assertEqual(e.kind, "io")
            self.assertLess(time.monotonic() - t0, 5)
        finally:
            s.close()


class Files(unittest.TestCase):
    def test_E9_file_size_limit(self):
        p = Prog(main_src('print(fs.read("d/a.txt"))', 'allow fs.read ["d"]'), {"d/a.txt": "0123456789"})
        try:
            with mock.patch.object(E, "MAX_BODY", 9):
                e = p.error()
                self.assertEqual(e.kind, "io")
                self.assertIn("larger than 9", str(e))
            with mock.patch.object(E, "MAX_BODY", 10):
                self.assertEqual(p.run(), "0123456789\n")
        finally:
            p.cleanup()

    def test_E6_long_path_label_truncated(self):
        name = "d/" + "p" * 100 + ".txt"
        p = Prog(main_src(f'print(fs.read("{name}"))', 'allow fs.read ["d"]'), {name: "x"})
        j = Journal()
        try:
            p.run(journal=j)
        finally:
            p.cleanup()
        lab = j.entries[0]["labels"][0]
        self.assertEqual(lab, "untrusted:file:" + name[:80] + "…")


class Shell(unittest.TestCase):
    def test_E11_label_is_command_name(self):
        p = Prog(main_src('print(shell.run("echo hi"))', 'allow shell ["echo"]'))
        j = Journal()
        try:
            self.assertEqual(p.run(journal=j), "hi\n\n")
        finally:
            p.cleanup()
        self.assertEqual(j.entries[0]["labels"], ["untrusted:shell:echo"])

    def test_E11_timeout(self):
        t0 = time.monotonic()
        e = error('print(shell.run("sleep 5"))', 'allow shell ["sleep"]', env={"SIPAR_SHELL_TIMEOUT": "0.2"})
        self.assertEqual(e.kind, "io")
        self.assertIn("command 'sleep' timed out after 0.2s", str(e))
        self.assertLess(time.monotonic() - t0, 4)

    def test_E11_not_executable_and_not_found(self):
        p = Prog(main_src('print(shell.run("./x.sh"))', 'allow shell'), {"x.sh": "echo hi\n"})
        os.chmod(os.path.join(p.dir, "x.sh"), stat.S_IRUSR | stat.S_IWUSR)
        try:
            e = p.error()
        finally:
            p.cleanup()
        self.assertEqual(e.kind, "io")
        self.assertIn("cannot run './x.sh'", str(e))
        e = error('print(shell.run("no-such-cmd-sipar-xyz"))', 'allow shell')
        self.assertEqual((e.kind, "command not found" in str(e)), ("io", True))

    def test_E11_failure_includes_stderr(self):
        e = error('print(shell.run("ls /no/such/dir/sipar"))', 'allow shell ["ls"]')
        self.assertEqual(e.kind, "io")
        self.assertIn("command 'ls' exited with status", str(e))
        self.assertIn("/no/such/dir/sipar", str(e))


class SleepInput(unittest.TestCase):
    def test_E12_sleep(self):
        rt = Rt("allow time")
        t0 = time.monotonic()
        self.assertIsNone(E.sleep(rt, 0.05))
        self.assertGreaterEqual(time.monotonic() - t0, 0.045)
        self.assertIsNone(E.sleep(rt, 0))
        self.assertEqual(kind(E.sleep, rt, -1)[0], "value")
        rt.rem = 0.1
        self.assertEqual(kind(E.sleep, rt, 5)[0], "budget")
        rt.rem = 0.02
        self.assertIsNone(E.sleep(rt, 0.02))           # exactly the remaining budget is allowed

    def test_E12_sleep_in_replay_does_not_wait(self):
        rt = Rt("allow time", journal=Journal(replay=[]))
        t0 = time.monotonic()
        E.sleep(rt, 3)
        self.assertLess(time.monotonic() - t0, 1)

    def test_E12_sleep_budget_in_program(self):
        e = error('budget(seconds: 0.1) { sleep(5) }', 'allow time')
        self.assertEqual(e.kind, "budget")

    def test_E12_messages(self):
        rt = Rt("allow random\nallow env\nallow secret [\"NOPE_SIPAR\"]")
        self.assertEqual(kind(E.random_int, rt, 5, 1), ("value", "random.int: lo (5) > hi (1)"))
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(kind(E.env_secret, rt, "NOPE_SIPAR"),
                             ("io", "secret 'NOPE_SIPAR' is not set in the environment"))

    def test_E12_input_flushes_prompt(self):
        rt = Rt("allow io", stdin=io.StringIO("bob\n"))
        v = E.input_line(rt, "name? ")
        self.assertEqual((str(v), rt.out.getvalue(), rt.out.flushes), ("bob", "name? ", 1))
        self.assertEqual(labels_of(v), {"untrusted:input:stdin"})


class NoTTY:
    """stdin with readline but no isatty."""

    def readline(self):
        return "y\n"


class Approve(unittest.TestCase):
    def test_E13_no_isatty_or_closed_stdin_is_denied(self):
        rt = Rt("allow io", stdin=NoTTY())
        k, msg = kind(E.approve, rt, 1, "ok?")
        self.assertEqual(k, "denied")
        self.assertEqual(msg, "not approved: ok? (stdin is not a terminal)")
        closed = io.StringIO("y\n")
        closed.close()
        rt = Rt("allow io", stdin=closed)
        self.assertEqual(kind(E.approve, rt, 1, "ok?")[0], "denied")

    def test_E13_tty_prompt_and_redaction(self):
        sec = set_labels("ab9", frozenset({"secret:TOK"}))
        rt = Rt("allow io", stdin=FakeTTY("y\n"))
        val = {"cmd": "rm -rf x", "key": sec}
        self.assertEqual(E.approve(rt, val, set_labels("send ab9?", frozenset({"secret:TOK"}))), val)
        err = rt.err.getvalue()
        self.assertIn("approval needed", err)
        self.assertIn("  value (42 chars):", err)
        self.assertIn("rm -rf x", err)
        self.assertIn("approve? [y/N] ", err)
        self.assertNotIn("ab9", err)
        self.assertGreaterEqual(rt.err.flushes, 1)
        ent = rt.journal.entries[-1]
        self.assertEqual(ent["kind"], "approve")
        self.assertNotIn("ab9", repr(ent))

    def test_E13_trust_journal_redacted(self):
        rt = Rt("")
        sec = set_labels("ab9", frozenset({"secret:TOK"}))
        E.trust(rt, {"k": sec}, set_labels("because ab9", frozenset({"secret:TOK"})))
        ent = rt.journal.entries[-1]
        self.assertEqual(ent["kind"], "trust")
        self.assertNotIn("ab9", repr(ent))


if __name__ == "__main__":
    unittest.main()
