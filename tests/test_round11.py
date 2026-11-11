"""Round 11: HTTP headers are a sink for untrusted data, like the URL and the body; a URL with user@host is
refused with a clear message before anything is sent."""
import unittest

from rt_helpers import Prog, Server


class Base(unittest.TestCase):
    def setUp(self):
        self.srv = Server()
        self.addCleanup(self.srv.close)
        self.url = self.srv.url + "/ok"

    def prog(self, body):
        p = Prog(f'allow ai\nallow net ["127.0.0.1:{self.srv.port}"]\nai fn gen() -> Str {{ "say" }}\n'
                 f'fn main() uses ai, net {{\n{body}\n}}\n')
        self.addCleanup(p.cleanup)
        return p

    def sent_headers(self):
        return {k.lower(): v for k, v in self.srv.hits[-1]["headers"].items()}


class T_UntrustedHeaders(Base):
    def blocked(self, call, fname, reply="hello"):
        e = self.prog(f"let u = gen()\n{call}").error(script={"gen": [reply]})
        self.assertEqual(e.kind, "taint")
        self.assertIn(f"untrusted data (untrusted:ai:gen) cannot flow into {fname}(headers)", str(e))
        self.assertEqual(len(self.srv.hits), 0)

    def test_value_in_get(self):
        self.blocked(f'print(http.get("{self.url}", headers: ["X-Note": u]))', "http.get")

    def test_value_in_post(self):
        self.blocked(f'print(http.post("{self.url}", "b", headers: ["X-Note": u]))', "http.post")

    def test_part_of_a_value(self):
        self.blocked(f'print(http.get("{self.url}", headers: ["X-Note": "id-" + u.upper()]))', "http.get")

    def test_name(self):
        self.blocked(f'print(http.get("{self.url}", headers: [u: "x"]))', "http.get", reply="X-Note")

    def test_name_that_is_not_a_valid_header_name_is_still_a_taint_error(self):
        self.blocked(f'print(http.get("{self.url}", headers: [u: "x"]))', "http.get", reply="not a name")

    def test_map_built_earlier(self):
        self.blocked(f'var hs = ["Accept": "text/plain"]\nhs["X-Note"] = u\nprint(http.post("{self.url}", "b", headers: hs))',
                     "http.post")

    def test_trusted_value_is_sent(self):
        p = self.prog(f'let u = trust(gen(), "checked in a test")\n'
                      f'print(http.get("{self.url}", headers: ["X-Note": u]))')
        self.assertEqual(p.run(script={"gen": ["hello"]}), "hello from server\n")
        self.assertEqual(self.sent_headers()["x-note"], "hello")

    def test_plain_header_is_sent(self):
        p = self.prog(f'print(http.post("{self.url}", "b", headers: ["X-Note": "plain"]))')
        self.assertEqual(p.run(), "hello from server\n")
        self.assertEqual(self.sent_headers()["x-note"], "plain")


class T_UntrustedHeaderCarriers(Base):
    CARRIERS = ['"{u}"', '"id-" + u', 'u.upper()', 'u[0..1]', '[u][0]', 'json.encode([u])', '["k": u]["k"]']

    def test_every_carrier_is_blocked_in_a_value_and_in_a_name(self):
        for carrier in self.CARRIERS:
            for call, fname in (('http.get("{url}", headers: {h})', "http.get"),
                                ('http.post("{url}", "b", headers: {h})', "http.post")):
                for h in (f'["X-Note": {carrier}]', f'[{carrier}: "x"]'):
                    with self.subTest(carrier=carrier, fname=fname, headers=h):
                        p = self.prog(f"let u = gen()\nprint({call.format(url=self.url, h=h)})")
                        e = p.error(script={"gen": ["hello"]})
                        self.assertEqual(e.kind, "taint")
                        self.assertIn(f"cannot flow into {fname}(headers)", str(e))
        self.assertEqual(len(self.srv.hits), 0)

    def test_map_decoded_from_untrusted_text(self):
        p = self.prog(f'let hs = gen() as Map[Str]\nprint(http.get("{self.url}", headers: hs))')
        e = p.error(script={"gen": ['{"X-Note": "v"}']})
        self.assertEqual(e.kind, "taint")
        self.assertEqual(len(self.srv.hits), 0)

    def test_secret_value_is_still_allowed_and_hidden(self):
        p = Prog(f'allow net ["127.0.0.1:{self.srv.port}"]\nallow secret ["K"]\n'
                 f'fn main() uses net, secret {{\n'
                 f'  print(http.get("{self.url}", headers: ["Authorization": "Bearer " + env.secret("K")]))\n}}\n')
        self.addCleanup(p.cleanup)
        self.assertEqual(p.run(env={"K": "s3cr3t-Zeta-9917"}), "hello from server\n")
        self.assertEqual(self.sent_headers()["authorization"], "Bearer s3cr3t-Zeta-9917")


class T_RuntimeHeaders(Base):
    def test_a_program_may_not_set_host_content_length_or_transfer_encoding(self):
        for name in ("Host", "host", "Content-Length", "TRANSFER-ENCODING"):
            with self.subTest(name=name):
                e = self.prog(f'print(http.post("{self.url}", "b", headers: ["{name}": "1"]))').error()
                self.assertEqual(e.kind, "value")
                self.assertIn("is set by the runtime", str(e))
        self.assertEqual(len(self.srv.hits), 0)

    def test_other_headers_are_sent(self):
        p = self.prog(f'print(http.post("{self.url}", "b", headers: ["Content-Type": "text/plain", "X-Host": "h"]))')
        self.assertEqual(p.run(), "hello from server\n")
        self.assertEqual(self.sent_headers()["content-type"], "text/plain")
        self.assertEqual(self.sent_headers()["x-host"], "h")
        self.assertEqual(self.sent_headers()["content-length"], "1")


class T_NonAsciiUrl(Base):
    def test_refused_with_a_clear_message(self):
        e = self.prog(f'print(http.get("{self.url}?q=é"))').error()
        self.assertEqual(e.kind, "capability")
        self.assertIn("outside ASCII", str(e))
        self.assertNotIn("codec", str(e))
        self.assertEqual(len(self.srv.hits), 0)

    def test_host_that_is_not_allowed_is_still_named(self):
        e = self.prog('print(http.get("http://exämple.test/"))').error()
        self.assertEqual(e.kind, "capability")
        self.assertIn("is not in 'allow net'", str(e))

    def test_percent_encoded_url_is_sent(self):
        p = self.prog(f'print(http.get("{self.url}?q=%C3%A9"))')
        self.assertEqual(p.run(), "hello from server\n")
        self.assertEqual(self.srv.hits[-1]["path"], "/ok?q=%C3%A9")


class T_EmptyFailKind(unittest.TestCase):
    def prog(self, body):
        p = Prog(f"fn main() {{\n{body}\n}}\n")
        self.addCleanup(p.cleanup)
        return p

    def test_empty_or_blank_kind_is_reported_as_fail(self):
        for kind in ('""', '"  "'):
            with self.subTest(kind=kind):
                e = self.prog(f'fail({kind}, "stop here")').error()
                self.assertEqual(e.kind, "fail")
                self.assertIn("stop here", str(e))

    def test_catch_sees_the_same_kind(self):
        p = self.prog('try {\n  fail("", "m")\n} catch e {\n  print(e.kind + "|" + e.message)\n}')
        self.assertEqual(p.run(), "fail|m\n")

    def test_a_named_kind_is_kept(self):
        self.assertEqual(self.prog('fail("bad_input", "m")').error().kind, "bad_input")


class T_UserInfoUrl(Base):
    def test_user_at_allowed_host_is_refused_before_any_request(self):
        e = self.prog(f'print(http.get("http://user:hunter2@127.0.0.1:{self.srv.port}/ok"))').error()
        self.assertEqual(e.kind, "capability")
        self.assertIn("user name or password before the host", str(e))
        self.assertNotIn("hunter2", str(e))
        self.assertEqual(len(self.srv.hits), 0)

    def test_user_at_another_host_names_the_real_host(self):
        e = self.prog(f'print(http.get("http://127.0.0.1:{self.srv.port}@evil.example/"))').error()
        self.assertEqual(e.kind, "capability")
        self.assertIn("host 'evil.example' is not in 'allow net'", str(e))
        self.assertEqual(len(self.srv.hits), 0)


if __name__ == "__main__":
    unittest.main()
