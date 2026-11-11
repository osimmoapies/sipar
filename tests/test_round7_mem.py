"""Round-7 fixes: memory store + log generations, log line checks, LSP framing and positions
Each test failed before the fix unless marked *guard*."""

import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sipar import lsp  # noqa: E402
from sipar.errors import SiparRuntimeError  # noqa: E402
from sipar.runtime import memory as MEM  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def cli(*argv):
    from sipar.cli import main as cli_main
    out, err = io.StringIO(), io.StringIO()
    rc = cli_main(list(argv), out, err)
    return rc, out.getvalue(), err.getvalue()


class _Store(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="sipar_r7m_")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.p = os.path.join(self.d, "m.json")
        self.log = self.p + ".log"

    def big(self, n=0):             # every write goes to the log (the store file is "big" at once)
        return mock.patch.object(MEM, "SMALL_STORE", n)

    def entry(self, i):
        return {"value": i, "labels": [], "enc": 2}

    def seed(self):                 # a stamped 5 KB store file
        with self.big(10 ** 9):
            MEM.FileStore(self.p).put("seed", {"value": "x" * 5000, "labels": [], "enc": 2})

    def gen(self):
        with open(self.p, encoding="utf-8") as fh:
            return json.load(fh).get("gen")

    def read(self, path):
        with open(path, "rb") as fh:
            return fh.read()

    def write(self, path, data: bytes):
        with open(path, "wb") as fh:
            fh.write(data)

    def header(self, gen=None):
        return json.dumps({"g": gen if gen is not None else self.gen()}).encode() + b"\n"

    def io_error(self, f):
        with self.assertRaises(SiparRuntimeError) as cm:
            f()
        self.assertEqual(cm.exception.kind, "io")
        return cm.exception.message


class T7_M1_Generations(_Store):
    """M1 (MEDIUM): deleting <stem>.json while <stem>.json.log stayed brought old keys back from the log."""

    def test_deleted_store_does_not_bring_back_log_keys(self):
        self.seed()
        with self.big(0):
            s = MEM.FileStore(self.p)
            s.put("a", self.entry(1))
            s.put("b", self.entry(2))
            self.assertTrue(os.path.exists(self.log))
            os.remove(self.p)
            self.assertEqual(MEM.FileStore(self.p).keys(), [])         # a fresh reader: empty
            self.assertEqual(s.keys(), [])                              # the cached one too
            self.assertIsNone(MEM.FileStore(self.p).get("a"))
            s2 = MEM.FileStore(self.p)
            s2.put("c", self.entry(3))                                  # the next write removes the stale log
            self.assertFalse(os.path.exists(self.log))
            self.assertEqual(MEM.FileStore(self.p).keys(), ["c"])
            self.assertEqual(s.keys(), ["c"])

    def test_deleted_store_end_to_end(self):          # the critic's repro: two real runs of one program file
        path = os.path.join(self.d, "big.sipar")

        def run(body):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("allow memory\nfn main() uses memory {\n" + body + "}\n")
            return cli("run", path)
        self.assertEqual(run('    for i in 0..400 { memory.save("k{i}", "v{i}") }\n    print("ok")\n'),
                         (0, "ok\n", ""))
        store = MEM.store_path(path)
        self.assertTrue(os.path.exists(store + ".log"))
        os.remove(store)
        self.assertEqual(run('    let v: Str? = memory.load("k399")\n    print(v ?? "none")\n'
                             '    print(memory.keys().len())\n'), (0, "none\n0\n", ""))
        self.assertEqual(run('    memory.save("n", "1")\n    print(memory.keys())\n'), (0, '["n"]\n', ""))
        self.assertFalse(os.path.exists(store + ".log"))

    def test_log_deleted_store_kept(self):             # *guard*: the log's saves go, the store's stay
        self.seed()
        with self.big(0):
            s = MEM.FileStore(self.p)
            s.put("a", self.entry(1))
            os.remove(self.log)
            self.assertEqual(MEM.FileStore(self.p).keys(), ["seed"])
            self.assertEqual(s.keys(), ["seed"])
            s.put("b", self.entry(2))
            self.assertEqual(MEM.FileStore(self.p).keys(), ["b", "seed"])

    def test_both_deleted(self):                       # *guard*
        self.seed()
        with self.big(0):
            s = MEM.FileStore(self.p)
            s.put("a", self.entry(1))
            os.remove(self.log)
            os.remove(self.p)
            self.assertEqual((s.keys(), MEM.FileStore(self.p).keys()), ([], []))
            s.put("b", self.entry(2))
            self.assertEqual(MEM.FileStore(self.p).keys(), ["b"])

    def test_log_of_another_store_is_ignored_then_replaced(self):
        self.seed()
        with self.big(0):
            MEM.FileStore(self.p).put("a", self.entry(1))
            stale = self.read(self.log)
            with self.big(10 ** 9):
                MEM.FileStore(self.p).put("z", self.entry(26))          # a full rewrite: a new gen, no log
                MEM.FileStore(self.p).delete("a")                       # and another one
            self.assertFalse(os.path.exists(self.log))
            self.write(self.log, stale)                                 # the old log is back (say, a crash)
            self.assertEqual(MEM.FileStore(self.p).keys(), ["seed", "z"])   # "a" stays deleted
            MEM.FileStore(self.p).put("b", self.entry(2))               # appended: the stale log is cut first
            lines = self.read(self.log).split(b"\n")
            self.assertEqual(lines[0] + b"\n", self.header())
            self.assertEqual([json.loads(x)["k"] for x in lines[1:] if x], ["b"])
            self.assertEqual(MEM.FileStore(self.p).keys(), ["b", "seed", "z"])

    def test_crash_between_rename_and_log_removal(self):
        self.seed()
        with self.big(0):
            s = MEM.FileStore(self.p)
            for i in range(5):
                s.put(f"k{i}", self.entry(i))
            pending = self.read(self.log)
        real = os.unlink
        with mock.patch("os.unlink", side_effect=lambda p, *a, **k: None if p == self.log else real(p, *a, **k)):
            with self.big(10 ** 9):
                MEM.FileStore(self.p).delete("k1")                      # folded in; the old log stays
        self.assertEqual(self.read(self.log), pending)
        self.assertEqual(MEM.FileStore(self.p).keys(), ["k0", "k2", "k3", "k4", "seed"])   # k1 not back

    def test_reader_sees_a_log_rewritten_in_place(self):    # a stale log cut and restarted on the same inode
        self.seed()
        self.write(self.log, self.header("0" * 16) + b'{"k": "old", "e": {"value": 1}}\n')
        with self.big(0):
            reader = MEM.FileStore(self.p)
            self.assertEqual(reader.keys(), ["seed"])
            ino = os.stat(self.log).st_ino
            MEM.FileStore(self.p).put("n", self.entry(1))
            self.assertEqual(os.stat(self.log).st_ino, ino)
            self.assertEqual(reader.keys(), ["n", "seed"])
            self.assertEqual(reader.get("n"), self.entry(1))

    def test_round6_store_and_log_still_load(self):   # backwards compatibility: no gen, no header
        fill = {"value": "x" * 5000, "labels": [], "enc": 2}           # bigger than the log: no compaction
        self.write(self.p, MEM.dump_store({"a": self.entry(1), "b": self.entry(2), "f": fill}).encode())
        self.write(self.log, b'{"k": "c", "e": {"value": 3, "labels": [], "enc": 2}}\n{"k": "a", "d": 1}\n')
        self.assertEqual(MEM.FileStore(self.p).keys(), ["b", "c", "f"])
        with self.big(0):
            s = MEM.FileStore(self.p)
            s.put("d", self.entry(4))                                   # the first write stamps the store
            self.assertFalse(os.path.exists(self.log))
            self.assertRegex(self.gen(), "^[0-9a-f]{16}$")
            s.put("e", self.entry(5))                                   # then the log has its header
            self.assertEqual(self.read(self.log).split(b"\n")[0] + b"\n", self.header())
        self.assertEqual(MEM.FileStore(self.p).keys(), ["b", "c", "d", "e", "f"])
        self.assertEqual(MEM.FileStore(self.p).get("c"), self.entry(3))

    def test_round6_store_alone_still_loads(self):     # *guard*
        self.write(self.p, MEM.dump_store({"a": self.entry(1)}).encode())
        self.assertEqual(MEM.FileStore(self.p).get("a"), self.entry(1))

    def test_round6_log_without_its_store_is_ignored(self):
        self.write(self.log, b'{"k": "c", "e": {"value": 3}}\n')
        self.assertEqual(MEM.FileStore(self.p).keys(), [])

    def test_headerless_log_next_to_a_stamped_store_is_an_error(self):
        self.seed()
        bad = b'{"k": "c", "e": {"value": 3}}\n'
        self.write(self.log, bad)
        want = f"memory store log {self.log} has an unknown format; fix or delete it (it was not changed)"
        with self.big(0):
            self.assertEqual(self.io_error(lambda: MEM.FileStore(self.p).keys()), want)
            self.assertEqual(self.io_error(lambda: MEM.FileStore(self.p).put("z", self.entry(0))), want)
        self.assertEqual(self.read(self.log), bad)

    def test_bad_gen_in_store_is_unknown_format(self):
        for g in ("1", "null", "[]"):
            self.write(self.p, ('{"version": 1, "gen": ' + g + ', "entries": {}}').encode())
            self.assertIn("has an unknown format", self.io_error(lambda: MEM.FileStore(self.p).keys()))

    def test_store_text_has_the_gen(self):            # *guard*: the format stays the round-6 one plus "gen"
        self.assertEqual(MEM.dump_store({}, "ab"), '{"version": 1, "gen": "ab", "entries": {}}\n')
        self.assertEqual(MEM.dump_store({}), '{"version": 1, "entries": {}}\n')

    def test_every_rewrite_gets_a_new_gen(self):
        s = MEM.FileStore(self.p)
        gens = set()
        for i in range(5):
            s.put("a", self.entry(i))
            gens.add(self.gen())
        self.assertEqual(len(gens), 5)


_WRITER = r"""
import sys
sys.path.insert(0, sys.argv[1])
from sipar.runtime import memory as M
M.SMALL_STORE = int(sys.argv[4])
s = M.FileStore(sys.argv[2])
w = sys.argv[3]
for i in range(int(sys.argv[5])):
    s.put(f"{w}{i}", {"value": i, "labels": [], "enc": 2})
    if i % 7 == 3:
        s.delete(f"{w}{i - 1}")
    print(f"{w}{i}", flush=True)
"""


class T7_M1_CrashAndWriters(_Store):
    """*guard*: the generation stamp keeps the round-6 crash and multi-writer guarantees."""

    def script(self):
        path = os.path.join(self.d, "writer.py")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_WRITER)
        return path

    def expected(self, w, n):
        keys = {f"{w}{i}": i for i in range(n)}
        for i in range(n):
            if i % 7 == 3:
                keys.pop(f"{w}{i - 1}", None)
        return keys

    def test_concurrent_writers(self):
        self.seed()
        code = self.script()
        procs = [subprocess.Popen([sys.executable, code, ROOT, self.p, w, "0", "120"], stdout=subprocess.DEVNULL)
                 for w in ("a", "b", "c", "d")]
        for p in procs:
            self.assertEqual(p.wait(timeout=120), 0)
        want = {"seed": "x" * 5000}
        for w in ("a", "b", "c", "d"):
            want.update(self.expected(w, 120))
        s = MEM.FileStore(self.p)
        self.assertEqual(s.keys(), sorted(want))
        self.assertEqual({k: s.get(k)["value"] for k in want}, want)

    def test_kill_9_mid_write(self):
        code = self.script()
        for run in range(4):
            w = f"r{run}x"
            p = subprocess.Popen([sys.executable, code, ROOT, self.p, w, "2000", "100000"], stdout=subprocess.PIPE)
            try:
                done = []
                t0 = time.monotonic()
                while len(done) < 200 + 150 * run and time.monotonic() - t0 < 60:
                    line = p.stdout.readline()
                    if not line:
                        break
                    done.append(line.decode().strip())
            finally:
                os.kill(p.pid, signal.SIGKILL)          # only the child this test started
                p.wait(timeout=30)
                p.stdout.close()
            self.assertGreater(len(done), 100)
            s = MEM.FileStore(self.p)
            keys = set(s.keys())
            exp = self.expected(w, len(done))            # every acknowledged write is there, right
            for k, v in exp.items():
                if k != done[-1]:                        # the next, unacknowledged step may delete the last
                    self.assertIn(k, keys)
                    self.assertEqual(s.get(k)["value"], v)
            gone = [k for k in done if k not in exp]
            self.assertFalse(set(gone) & keys)
        s.put("final", self.entry(0))                    # a write after the crashes is fine too
        self.assertIn("final", MEM.FileStore(self.p).keys())


class T7_M2_BlankLines(_Store):
    """M2 (LOW): one blank or "\\r\\n" line in the log made the whole store unreadable."""

    def test_blank_and_crlf_lines_are_skipped(self):
        self.seed()
        rec = b'{"k": "a", "e": {"value": 1, "labels": [], "enc": 2}}'
        self.write(self.log, self.header() + b"\n\r\n   \n" + rec + b"\r\n\n" + b'{"k": "b", "d": 1}\n\r\n')
        with self.big(0):
            self.assertEqual(MEM.FileStore(self.p).keys(), ["a", "seed"])
            s = MEM.FileStore(self.p)
            s.put("c", self.entry(3))
            self.assertEqual(MEM.FileStore(self.p).keys(), ["a", "c", "seed"])

    def test_blank_line_before_the_header(self):
        self.seed()
        self.write(self.log, b"\r\n" + self.header() + b'{"k": "a", "e": {"value": 1}}\n')
        self.assertEqual(MEM.FileStore(self.p).keys(), ["a", "seed"])

    def test_blank_line_in_a_round6_log(self):
        self.write(self.p, MEM.dump_store({"a": self.entry(1)}).encode())
        self.write(self.log, b'\n{"k": "c", "e": {"value": 3}}\n\r\n')
        self.assertEqual(MEM.FileStore(self.p).keys(), ["a", "c"])

    def test_torn_last_line_still_ignored_then_cut(self):      # *guard*
        self.seed()
        with self.big(0):
            s = MEM.FileStore(self.p)
            s.put("a", self.entry(1))
            with open(self.log, "ab") as fh:
                fh.write(b"\n" + b'{"k": "b", "e": {"val')
            self.assertEqual(MEM.FileStore(self.p).keys(), ["a", "seed"])
            MEM.FileStore(self.p).put("c", self.entry(3))
            self.assertEqual(MEM.FileStore(self.p).keys(), ["a", "c", "seed"])
            self.assertNotIn(b'"b"', self.read(self.log))

    def test_torn_header_is_cut(self):                          # a crash in the very first log write
        self.seed()
        self.write(self.log, b'{"g": "0')
        with self.big(0):
            self.assertEqual(MEM.FileStore(self.p).keys(), ["seed"])
            MEM.FileStore(self.p).put("a", self.entry(1))
        self.assertEqual(self.read(self.log).split(b"\n")[0] + b"\n", self.header())
        self.assertEqual(MEM.FileStore(self.p).keys(), ["a", "seed"])


class T7_M3_StrictLines(_Store):
    """M3 (LOW): "d": true / "d": 1.0 counted as a delete and a line with both "e" and "d" was accepted;
    the "unknown format" message did not say what to fix or delete."""

    def test_only_exact_shapes(self):
        self.seed()
        want = f"memory store log {self.log} has an unknown format; fix or delete it (it was not changed)"
        g = self.gen()
        for bad in [b'{"k": "a", "d": true}', b'{"k": "a", "d": 1.0}', b'{"k": "a", "e": {}, "d": 1}',
                    b'{"k": "a", "e": {}, "x": 0}', b'{"k": "a", "d": 1, "x": 0}', b'{"k": "a", "d": 2}',
                    b'{"k": "a", "e": []}', b'{"k": 1, "e": {}}', b'{"k": "a"}', b'[1]', b'"s"',
                    b'{"g": "' + g.encode() + b'"}']:          # a second header mid-log
            data = self.header() + bad + b"\n"
            self.write(self.log, data)
            with self.big(0):
                self.assertEqual(self.io_error(lambda: MEM.FileStore(self.p).keys()), want, bad)
                self.assertEqual(self.io_error(lambda: MEM.FileStore(self.p).put("z", self.entry(0))), want, bad)
            self.assertEqual(self.read(self.log), data)

    def test_bad_headers(self):
        self.seed()
        want = f"memory store log {self.log} has an unknown format; fix or delete it (it was not changed)"
        for bad in [b'{"g": 1}', b'{"g": null}', b'{"g": "' + self.gen().encode() + b'", "x": 1}']:
            self.write(self.log, bad + b"\n")
            self.assertEqual(self.io_error(lambda: MEM.FileStore(self.p).keys()), want, bad)

    def test_good_lines_still_work(self):                       # *guard*
        self.seed()
        self.write(self.log, self.header() + b'{"k": "a", "e": {"value": 1}}\n{"k": "b", "e": {"value": 2}}\n'
                   b'{"d": 1, "k": "a"}\n')
        self.assertEqual(MEM.FileStore(self.p).keys(), ["b", "seed"])


# ====================================================================== LSP

def _frame(obj):
    body = json.dumps(obj).encode()
    return b"Content-Length: %d\r\n\r\n" % len(body) + body


def _serve(data: bytes):
    out, err = io.BytesIO(), io.StringIO()
    code = lsp.serve(io.BytesIO(data), out, err)
    replies = [json.loads(m) for m in re.split(rb"Content-Length: \d+\r\n\r\n", out.getvalue()) if m]
    return code, replies, err.getvalue()


INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
SYM = {"jsonrpc": "2.0", "id": 2, "method": "textDocument/documentSymbol", "params": {"textDocument": {"uri": "file:///x.sipar"}}}
DOWN = {"jsonrpc": "2.0", "id": 99, "method": "shutdown"}
EXIT = {"jsonrpc": "2.0", "method": "exit"}


class T7_L4_ContentLength(unittest.TestCase):
    """L4 (LOW): a Content-Length of 13+ digits counted as over the 64 MiB cap even when its value was small."""

    def test_leading_zeros_count_the_value(self):
        body = json.dumps(SYM).encode()
        for cl in [b"0" * 11 + str(len(body)).encode(), b"0" * 5000 + str(len(body)).encode()]:
            code, replies, err = _serve(_frame(INIT) + b"Content-Length: " + cl + b"\r\n\r\n" + body
                                        + _frame(DOWN) + _frame(EXIT))
            self.assertEqual(([r.get("id") for r in replies], code, err), ([1, 2, 99], 0, ""), len(cl))

    def test_read_message_values(self):
        rm = lambda cl, rest=b"{}": lsp.read_message(io.BytesIO(b"Content-Length: " + cl + b"\r\n\r\n" + rest))  # noqa
        self.assertEqual(rm(b"0000000000002"), b"{}")
        self.assertEqual(rm(b" 000000000000000000002 "), b"{}")                 # spaces around are fine
        self.assertEqual(rm(b"0" * 20), b"")                                     # zero (L5: a parse error)
        self.assertNotIsInstance(rm(b"0" * 20), lsp.Skipped)
        for bad in [b"+2", b"+0000000000002", b"0 2", b"-0", b"2e0"]:                # *guard*: not lengths
            got = rm(bad)
            self.assertIsInstance(got, lsp.Skipped, bad)
            self.assertEqual(got.reason, "skipped a message without a valid Content-Length header")
        self.assertIsNone(rm(b"1000000000000"))       # *guard*: a real 10^12: over the cap, read past to EOF
        self.assertIsNone(rm(b"9" * 5000))            # *guard*

    def test_cap_edges(self):                         # *guard*: the cap compares values
        n = lsp.MAX_BODY
        got = lsp.read_message(io.BytesIO(b"Content-Length: 000000%d\r\n\r\n" % (n + 1) + b"a" * (n + 1)))
        self.assertIsInstance(got, lsp.Skipped)
        self.assertIn("larger than", got.reason)


class T7_L5_EmptyBody(unittest.TestCase):
    """L5 (LOW): Content-Length: 0 logged "without a valid Content-Length header" and sent no -32700 reply."""

    def test_zero_length_is_a_parse_error(self):
        code, replies, err = _serve(_frame(INIT) + b"Content-Length: 0\r\n\r\n" + _frame(SYM) + _frame(DOWN)
                                    + _frame(EXIT))
        self.assertEqual([r.get("id") for r in replies], [1, None, 2, 99])
        self.assertEqual(replies[1]["error"], {"code": lsp.PARSE_ERROR, "message": "parse error: JSONDecodeError"})
        self.assertNotIn("Content-Length", err)
        self.assertIn("malformed message: JSONDecodeError", err)
        self.assertEqual(code, 0)

    def test_same_as_a_non_utf8_body(self):
        out, err = io.BytesIO(), io.StringIO()
        srv = lsp.Server(out, err)
        srv.handle_bytes(b"")
        srv.handle_bytes(b"\xff")
        replies = [json.loads(m) for m in re.split(rb"Content-Length: \d+\r\n\r\n", out.getvalue()) if m]
        self.assertEqual([(r["id"], r["error"]["code"]) for r in replies], [(None, lsp.PARSE_ERROR)] * 2)

    def test_skipped_frames_still_only_log(self):     # *guard*
        code, replies, err = _serve(_frame(INIT) + b"X: 1\r\n\r\n" + _frame(DOWN) + _frame(EXIT))
        self.assertEqual([r.get("id") for r in replies], [1, 99])
        self.assertIn("skipped a message without a valid Content-Length header", err)


class T7_L6_Positions(unittest.TestCase):
    """L6 (LOW): a didChange range {start: {}, end: {}} silently inserted at offset 0 (a missing line or
    character was read as 0)."""

    URI = "file:///tmp/r7.sipar"
    TEXT = "fn main() {\n    let xs = [1]\n    print(xs.len())\n}\n"

    def setUp(self):
        self.srv = lsp.Server(io.BytesIO(), io.StringIO())
        self.srv.handle({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}})
        self.srv.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen",
                         "params": {"textDocument": {"uri": self.URI, "text": self.TEXT, "version": 1}}})

    def call(self, method, params, notify=False):
        self.srv.out, self.srv.err = io.BytesIO(), io.StringIO()
        msg = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notify:
            msg["id"] = 7
        self.srv.handle(msg)
        replies = [json.loads(m) for m in re.split(rb"Content-Length: \d+\r\n\r\n", self.srv.out.getvalue()) if m]
        return [r for r in replies if r.get("id") == 7], self.srv.err.getvalue()

    def test_did_change_with_missing_parts(self):
        p0 = {"line": 0, "character": 0}
        for r in [{"start": {}, "end": {}}, {"start": {"line": 0}, "end": p0}, {"start": p0, "end": {"character": 0}}]:
            _, err = self.call("textDocument/didChange", {"textDocument": {"uri": self.URI, "version": 2},
                                                          "contentChanges": [{"range": r, "text": "zz"}]}, notify=True)
            self.assertIn("invalid params", err, r)
            self.assertIn("is missing", err, r)
            self.assertEqual(self.srv.docs[self.URI].text, self.TEXT, r)

    def test_hover_with_missing_parts(self):
        for pos in [{}, {"line": 2}, {"character": 5}]:
            replies, _ = self.call("textDocument/hover", {"textDocument": {"uri": self.URI}, "position": pos})
            self.assertEqual(replies[0]["error"]["code"], lsp.INVALID_PARAMS, pos)
            key = "line" if "line" not in pos else "character"
            self.assertEqual(replies[0]["error"]["message"], f"position.{key} is missing", pos)

    def test_full_positions_still_work(self):        # *guard*
        p = {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 0}}
        self.call("textDocument/didChange", {"textDocument": {"uri": self.URI, "version": 2},
                                             "contentChanges": [{"range": p, "text": "\n"}]}, notify=True)
        self.assertEqual(self.srv.docs[self.URI].text, "\n" + self.TEXT)
        replies, _ = self.call("textDocument/hover", {"textDocument": {"uri": self.URI},
                                                       "position": {"line": 3, "character": 13}})
        self.assertIn("len", json.dumps(replies[0]["result"]))


if __name__ == "__main__":
    unittest.main()
