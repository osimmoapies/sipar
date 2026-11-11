"""Round-7 CLI fixes: the SIPAR_MOCK_SCRIPT file, one wording for a file that cannot
be read, journal exit codes, the api.py RecursionError branch. Each test failed before the fix unless marked
*guard*."""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from rt_helpers import Prog  # noqa: E402
from sipar.errors import SiparRuntimeError  # noqa: E402
from sipar.fileread import why_unreadable  # noqa: E402
from sipar.runtime.journal import Journal  # noqa: E402
from sipar.runtime.providers import MockProvider, json_type  # noqa: E402

ROOT_USER = hasattr(os, "geteuid") and os.geteuid() == 0

MOCK_SRC = 'allow ai\nai fn f(t: Str) -> Str { "say {t}" }\nfn main() uses ai { print(f("x")) }\n'
SHAPE = "must be a JSON list of replies or an object {fn name: [replies]}"


def cli(*argv, env=None):
    from sipar.cli import main as cli_main
    out, err = io.StringIO(), io.StringIO()
    clean = {k: v for k, v in os.environ.items() if not k.startswith("SIPAR_")}
    clean.update(env or {})
    with mock.patch.dict(os.environ, clean, clear=True):
        rc = cli_main(list(argv), out, err)
    return rc, out.getvalue(), err.getvalue()


class Tmp(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp(prefix="sipar_r7c_"))

    def tearDown(self):
        for root, dirs, files in os.walk(self.d):
            for n in dirs + files:
                try:
                    os.chmod(os.path.join(root, n), 0o700)
                except OSError:
                    pass
        shutil.rmtree(self.d, ignore_errors=True)

    def put(self, name, data, mode=0o600):
        p = os.path.join(self.d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb" if isinstance(data, bytes) else "w", encoding=None if isinstance(data, bytes) else "utf-8") as f:
            f.write(data)
        os.chmod(p, mode)
        return p


# ------------------------------------------------------------------ 1-2: the SIPAR_MOCK_SCRIPT file

class T_MockScriptFile(Tmp):
    def setUp(self):
        super().setUp()
        self.prog = Prog(MOCK_SRC)

    def tearDown(self):
        self.prog.cleanup()
        super().tearDown()

    def err(self, path):
        e = self.prog.error(env={"SIPAR_MOCK_SCRIPT": path})
        self.assertNotIn("mock answer", self.prog.out)
        return e

    def test_missing_file(self):                                         # prov12 / prov13
        p = os.path.join(self.d, "none.json")
        e = self.err(p)
        self.assertEqual(e.kind, "ai")
        self.assertEqual(e.message, f"cannot load SIPAR_MOCK_SCRIPT {p}: no such file")

    def test_null_is_an_error(self):                                     # was: strict mode silently off
        p = self.put("null.json", "null")
        e = self.err(p)
        self.assertEqual((e.kind, e.message), ("ai", f"cannot load SIPAR_MOCK_SCRIPT {p}: it {SHAPE}, not null"))

    def test_scalars_use_json_type_names(self):                          # was: "not str" / "not int"
        for text, name in (('"spam"', "a string"), ("1", "a number"), ("-2.5", "a number"), ("true", "a boolean"),
                           ("false", "a boolean")):
            with self.subTest(text=text):
                p = self.put("s.json", text)
                e = self.err(p)
                self.assertEqual((e.kind, e.message), ("ai", f"cannot load SIPAR_MOCK_SCRIPT {p}: it {SHAPE}, not {name}"))

    def test_unreadable_files(self):
        cases = [("bad8.json", b"[\"\xff\"]", "not UTF-8 text"),
                 ("empty.json", b"", f"the file is empty; it {SHAPE}"),
                 ("blank.json", b" \n\t\n", f"the file is empty; it {SHAPE}"),
                 ("trunc.json", b"[1,", "not valid JSON (line 1 column 4: expecting value)"),
                 ("two.json", b"[1]\n[2]", "not valid JSON (line 2 column 1: extra data)"),
                 ("nan.json", b"[NaN]", "not valid JSON (NaN is not a JSON value)"),
                 ("inf.json", b'{"f": [-Infinity]}', "not valid JSON (-Infinity is not a JSON value)"),
                 ("big.json", b"[" + b"9" * 5000 + b"]", "it holds a number too large to read (5,000 digits; "
                                                          "the limit is 4,300)")]
        for name, raw, why in cases:
            with self.subTest(name=name):
                p = self.put(name, raw)
                e = self.err(p)
                self.assertEqual((e.kind, e.message), ("ai", f"cannot load SIPAR_MOCK_SCRIPT {p}: {why}"))

    def test_directory(self):
        p = os.path.join(self.d, "dir.json")
        os.mkdir(p)
        self.assertEqual(self.err(p).message, f"cannot load SIPAR_MOCK_SCRIPT {p}: is a directory")

    @unittest.skipIf(ROOT_USER, "root reads every file")
    def test_permission_denied_names_the_file_once(self):
        p = self.put("np.json", '["a"]', mode=0)
        m = self.err(p).message
        self.assertEqual(m, f"cannot load SIPAR_MOCK_SCRIPT {p}: permission denied")
        self.assertNotIn("Errno", m)

    def test_bom_is_skipped(self):                                       # like Sipar source (SPEC §2)
        p = self.put("bom.json", b'\xef\xbb\xbf["hi"]')
        self.assertEqual(self.prog.run(env={"SIPAR_MOCK_SCRIPT": p}), "hi\n")

    def test_valid_shapes_guard(self):                                   # guard
        for text, out in (('["a"]', "a\n"), ('{"f": ["b"]}', "b\n"), ('{"f": "c"}', "c\n"), ('[5]', "5\n")):
            with self.subTest(text=text):
                p = self.put("ok.json", text)
                self.assertEqual(self.prog.run(env={"SIPAR_MOCK_SCRIPT": p}), out)

    def test_empty_env_var_is_no_script_guard(self):                     # guard: "" means unset
        self.assertEqual(self.prog.run(env={"SIPAR_MOCK_SCRIPT": ""}), "mock answer\n")

    def test_empty_list_wording_guard(self):                             # guard: the global-queue form
        p = self.put("el.json", "[]")
        self.assertIn("the mock script has no reply left for f()", self.err(p).message)

    def test_empty_object_uses_per_fn_wording(self):                     # was: "no reply left"
        p = self.put("eo.json", "{}")
        e = self.err(p)
        self.assertEqual(e.kind, "ai")
        self.assertIn("the mock script has no reply for f()", e.message)
        self.assertNotIn("no reply left", e.message)

    def test_empty_object_api(self):
        import sipar
        path = os.path.join(self.d, "p.sipar")
        with open(path, "w") as fh:
            fh.write(MOCK_SRC)
        with self.assertRaises(sipar.SiparError) as cm:
            sipar.load(path).call("f", "x", mock_script={})
        self.assertIn("the mock script has no reply for f()", cm.exception.message)

    def test_cli_end_to_end(self):
        prog = self.put("m.sipar", MOCK_SRC)
        for text in ("null", '"s"'):
            with self.subTest(text=text):
                s = self.put("s.json", text)
                rc, o, e = cli("run", prog, env={"SIPAR_MODEL": "mock", "SIPAR_MOCK_SCRIPT": s})
                self.assertEqual(rc, 1)
                self.assertEqual(o, "")
                self.assertIn(f"runtime error[ai]: cannot load SIPAR_MOCK_SCRIPT {s}: it {SHAPE}", e)
        rc, o, e = cli("run", prog, env={"SIPAR_MODEL": "mock", "SIPAR_MOCK_SCRIPT": os.path.join(self.d, "no.json")})
        self.assertEqual((rc, o), (1, ""))
        self.assertIn("no.json: no such file", e)
        self.assertNotIn("Errno", e)

    def test_direct_script_json_names(self):
        for v, name in ((5, "a number"), (True, "a boolean"), ("s", "a string"), (2.5, "a number")):
            with self.subTest(v=v):
                with self.assertRaises(SiparRuntimeError) as cm:
                    MockProvider(v)
                self.assertEqual(cm.exception.kind, "ai")
                self.assertTrue(cm.exception.message.endswith(f"{SHAPE}, not {name}"), cm.exception.message)

    def test_json_type(self):
        self.assertEqual([json_type(x) for x in (None, False, 0, 1.5, "", [], {})],
                         ["null", "a boolean", "a number", "a number", "a string", "a list", "an object"])


# ------------------------------------------------------------------ 3: one wording for an unreadable file

class T_ReadWording(Tmp):
    def test_why_unreadable(self):
        self.assertEqual(why_unreadable(UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")),
                         "not UTF-8 text")
        self.assertEqual(why_unreadable(FileNotFoundError(2, "No such file or directory", "x")), "no such file")
        self.assertEqual(why_unreadable(IsADirectoryError(21, "Is a directory", "x")), "is a directory")
        self.assertEqual(why_unreadable(PermissionError(13, "Permission denied", "x")), "permission denied")
        self.assertEqual(why_unreadable(NotADirectoryError(20, "Not a directory", "x")), "not a directory")
        self.assertEqual(why_unreadable(OSError("Plain")), "plain")
        self.assertEqual(why_unreadable(OSError()), "oSError")

    def test_not_utf8_source(self):                                      # was: 'utf-8' codec can't decode ...
        p = self.put("b.sipar", b"fn main() { print(\"\xff\") }\n")
        for cmd in ("check", "run", "test"):
            with self.subTest(cmd=cmd):
                self.assertEqual(cli(cmd, p), (2, "", f"sipar: cannot read {p}: not UTF-8 text\n"))
        prog_ok = self.put("ok.sipar", "fn main() { print(1) }\n")
        self.assertEqual(cli("replay", p, prog_ok)[2], f"sipar: cannot read {p}: not UTF-8 text\n")

    @unittest.skipIf(ROOT_USER, "root reads every file")
    def test_permission_denied_source(self):                             # was: [Errno 13] ...: 'x.sipar'
        p = self.put("np.sipar", "fn main() { print(1) }\n", mode=0)
        for cmd in ("check", "run", "test"):
            with self.subTest(cmd=cmd):
                rc, o, e = cli(cmd, p)
                self.assertEqual((rc, o, e), (2, "", f"sipar: cannot read {p}: permission denied\n"))
                self.assertEqual(e.count(p), 1)

    def test_check_json(self):
        p = self.put("b.sipar", b"\xff")
        rc, o, e = cli("check", p, "--json")
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(o)[0]["message"], f"cannot read {p}: not UTF-8 text")
        if not ROOT_USER:
            q = self.put("np.sipar", "x", mode=0)
            rc, o, e = cli("check", q, "--json")
            self.assertEqual(json.loads(o)[0]["message"], f"cannot read {q}: permission denied")

    def test_not_a_directory(self):
        f = self.put("file", "x")
        p = os.path.join(f, "a.sipar")
        self.assertEqual(cli("check", p), (2, "", f"sipar: cannot read {p}: not a directory\n"))

    def test_missing_and_directory_guard(self):           # guard: the round-4 missing wording stays (dir: round 9 F4)
        p = os.path.join(self.d, "none.sipar")
        self.assertEqual(cli("check", p), (2, "", f"sipar: no such file: {p}\n"))
        self.assertEqual(cli("check", self.d), (2, "", f"sipar: cannot read {self.d}: is a directory\n"))

    def test_spec_unreadable(self):                                      # was: internal error (...)
        from sipar import cli as C
        with mock.patch.object(C, "open", create=True, side_effect=PermissionError(13, "Permission denied")):
            rc, o, e = cli("spec")
        self.assertEqual(rc, 2)
        self.assertRegex(e, r"^sipar: cannot read .*SPEC\.md: permission denied\n$")
        self.assertNotIn("internal error", e)

    def test_memory_store_not_utf8(self):                                # was: a raw UnicodeDecodeError
        from sipar.runtime import memory as MEM
        p = self.put("m.json", b'{"version": 1, "entries": {"\xff": 1}}')
        with self.assertRaises(SiparRuntimeError) as cm:
            MEM.FileStore(p).keys()
        self.assertEqual((cm.exception.kind, cm.exception.message),
                         ("io", f"cannot read memory store {p}: not UTF-8 text; fix or delete it (it was not changed)"))
        with open(p, "rb") as fh:
            self.assertEqual(fh.read(), b'{"version": 1, "entries": {"\xff": 1}}')     # not changed

    def test_memory_store_not_utf8_in_a_program(self):
        src = 'allow memory\nfn main() uses memory { print(memory.keys()) }\n'
        prog = self.put("p.sipar", src)
        self.put(".sipar/memory/p.json", b"\xff\xfe")
        rc, o, e = cli("run", prog)
        self.assertEqual(rc, 1)
        self.assertIn("runtime error[io]: cannot read memory store", e)
        self.assertIn("p.json: not UTF-8 text", e)
        self.assertNotIn("internal error", e)

    @unittest.skipIf(ROOT_USER, "root reads every file")
    def test_memory_store_log_permission(self):
        from sipar.runtime import memory as MEM
        p = self.put("m.json", '{"version": 1, "entries": {}}')
        log = self.put("m.json.log", "", mode=0)
        with self.assertRaises(SiparRuntimeError) as cm:
            MEM.FileStore(p).keys()
        self.assertEqual(cm.exception.message, f"cannot read memory store log {log}: permission denied")

    def test_pin_file_wording(self):                                     # was: Python's JSON / codec text
        from sipar.runtime import mcp as MCP
        for raw, why in ((b"{broken", "not valid JSON"), (b'{"servers": {"\xff": {}}}', "not UTF-8 text")):
            with self.subTest(why=why):
                p = self.put("pins.json", raw)
                with self.assertRaises(SiparRuntimeError) as cm:
                    MCP.PinStore(p)
                self.assertEqual((cm.exception.kind, cm.exception.message),
                                 ("mcp", f"cannot read the MCP pin file {p}: {why}; delete it to trust the servers "
                                         f"again"))


# ------------------------------------------------------------------ 4: journals: exit 2 and one prefix

class T_Journal(Tmp):
    def setUp(self):
        super().setUp()
        self.prog = self.put("p.sipar", "fn main() { print(1) }\n")

    def both(self, j):
        rt = cli("trace", j)
        rr = cli("replay", self.prog, j)
        return rt, rr

    def test_not_utf8_exit_2_same_message(self):                         # was: exit 1, two prefixes
        j = self.put("j.jsonl", b'{"kind": "x", "request": {}}\n\xff\n')
        rt, rr = self.both(j)
        self.assertEqual(rt, (2, "", f"sipar: cannot read {j}: not UTF-8 text\n"))
        self.assertEqual(rr, rt)
        rc, o, e = cli("trace", j, "--json")
        self.assertEqual((rc, o), (2, ""))

    def test_char_across_chunk_boundary_is_text(self):                   # the check reads 1 MiB chunks
        line = b'{"kind": "x", "request": "' + b"a" * ((1 << 20) - 27) + "é".encode() + b'"}\n'
        self.assertEqual(line.index("é".encode()), (1 << 20) - 1)        # é starts on the last byte of chunk 1
        j = self.put("j.jsonl", line)
        rc, o, e = cli("trace", j)
        self.assertNotIn("UTF-8", e)
        self.assertEqual(rc, 0, e)

    def test_cut_char_at_end_is_not_text(self):                          # a character cut at the end of file
        j = self.put("j.jsonl", b'{"kind": "x", "request": {}}\n' + "é".encode()[:1])
        rt, rr = self.both(j)
        self.assertEqual(rt, (2, "", f"sipar: cannot read {j}: not UTF-8 text\n"))
        self.assertEqual(rr, rt)

    def test_bad_line_guard(self):                                       # guard: SPEC §9, a bad line is exit 1
        j = self.put("j.jsonl", '{"kind": "x", "request": {}}\nnope\n')
        (rc_t, _, e_t), (rc_r, _, e_r) = self.both(j)
        self.assertEqual((rc_t, rc_r), (1, 1))
        self.assertIn("line 2 is not valid JSON", e_t)
        self.assertIn("line 2 is not valid JSON", e_r)

    def test_journal_load_wording(self):
        j = self.put("j.jsonl", b"\xff")
        with self.assertRaises(SiparRuntimeError) as cm:
            Journal.load(j)
        self.assertEqual((cm.exception.kind, cm.exception.message), ("replay", f"cannot read journal {j}: not UTF-8 text"))

    def test_fixture_not_utf8_in_sipar_test(self):
        from sipar.runtime.interp import _fixture_name
        prog = self.put("t.sipar", 'test "one" { assert(1 == 1) }\n')
        self.put(os.path.join(".sipar", "fixtures", _fixture_name("one") + ".jsonl"), b"\xff\n")
        rc, o, e = cli("test", prog)
        self.assertEqual(rc, 1)
        self.assertIn("FAIL one", o)
        self.assertIn("runtime error[replay]: cannot read journal ", o)
        self.assertIn(".jsonl: not UTF-8 text", o)


# ------------------------------------------------------------------ 5: api.py RecursionError branch

class T_ApiRecursion(Tmp):
    def test_recursion_error_is_a_sipar_error(self):                     # api56 / api57: was raise None
        import sipar
        path = self.put("p.sipar", "fn add(a: Int, b: Int) -> Int { a + b }\n")
        prog = sipar.load(path)
        with mock.patch("sipar.api.call_deep", side_effect=RecursionError("deep")):
            with self.assertRaises(sipar.SiparError) as cm:
                prog.call("add", 1, 2)
        self.assertEqual((cm.exception.kind, cm.exception.message),
                         ("value", "add: an argument or value is nested too deeply"))
        self.assertIsNone(cm.exception.__context__)
        self.assertEqual(prog.call("add", 1, 2), 3)                      # guard: the next call works


if __name__ == "__main__":
    unittest.main()
