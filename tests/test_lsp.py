"""`sipar lsp`: the language server (sipar/lsp.py) and the VS Code extension files (editors/vscode).

Most tests talk to the server with real Content-Length frames, either in-process
(`serve()` on byte streams) or through a `python -m sipar lsp` subprocess.
"""
import bisect
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from sipar import lsp  # noqa: E402

URI = "file:///tmp/t%20dir/a.sipar"

SRC = '''allow net ["wttr.in"]

/// A point.
type P = { name: Str, age: Int }
enum Shape { dot, circle(r: Float) }
let LIMIT = 10

/// Adds two numbers.
fn add(a: Int, b: Int) -> Int { a + b }

fn main() uses net {
    let xs = [1, 2]
    var n = 0
    for x in xs { n = n + x }
    let s = Shape.circle(r: 1.5)
    let k = match s {
        Shape.circle(r) => r,
        Shape.dot => 0.0
    }
    let p = P { name: "a", age: add(1, 2) }
    try { print(http.get("https://wttr.in")) } catch e { print(e.message) }
    let f = fn(y: Int) -> Int => y + LIMIT
    print("{p.name} {k} {f(n)} add")   // add xs
}
'''


def u16(s):
    return len(s.encode("utf-16-le")) // 2


def at(src, needle, nth=0, offset=0):
    """LSP position (0-based line, UTF-16 character) of the nth occurrence of needle (+offset chars)."""
    i = -1
    for _ in range(nth + 1):
        i = src.index(needle, i + 1)
    i += offset
    line = src.count("\n", 0, i)
    start = src.rfind("\n", 0, i) + 1
    return {"line": line, "character": u16(src[start:i])}


def frame(obj):
    body = json.dumps(obj).encode("utf-8")
    return b"Content-Length: %d\r\n\r\n" % len(body) + body


def parse_frames(data):
    out = []
    while data:
        head, _, rest = data.partition(b"\r\n\r\n")
        m = re.search(rb"Content-Length: (\d+)", head)
        n = int(m.group(1))
        out.append(json.loads(rest[:n].decode("utf-8")))
        data = rest[n:]
    return out


def run_frames(*msgs, raw=b""):
    """Feed frames to serve(); return (messages out, exit code, stderr text)."""
    inp = io.BytesIO(b"".join(frame(m) if isinstance(m, dict) else m for m in msgs) + raw)
    out, err = io.BytesIO(), io.StringIO()
    code = lsp.serve(inp, out, err)
    return parse_frames(out.getvalue()), code, err.getvalue()


INIT = {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"processId": None, "capabilities": {}}}


class Session:
    """An in-process server driven with framed bytes, one message at a time."""

    def __init__(self, text=SRC, uri=URI, init=True):
        self.out, self.err = io.BytesIO(), io.StringIO()
        self.server = lsp.Server(self.out, self.err)
        self.uri = uri
        self.next_id = 100
        if init:
            self.request("initialize", {"capabilities": {}})
            self.notify("initialized", {})
            if text is not None:
                self.open(text)

    def send(self, obj):
        body = frame(obj)
        msg = lsp.read_message(io.BytesIO(body))
        self.server.handle_bytes(msg)
        data = self.out.getvalue()
        self.out.seek(0)
        self.out.truncate()
        return parse_frames(data)

    def request(self, method, params):
        self.next_id += 1
        msgs = self.send({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params})
        resp = [m for m in msgs if m.get("id") == self.next_id]
        assert len(resp) == 1, msgs
        return resp[0]

    def notify(self, method, params):
        return self.send({"jsonrpc": "2.0", "method": method, "params": params})

    def open(self, text, version=1):
        msgs = self.notify("textDocument/didOpen",
                           {"textDocument": {"uri": self.uri, "languageId": "sipar", "version": version, "text": text}})
        self.text = text
        return msgs[-1]["params"]["diagnostics"] if msgs else None

    def change(self, text, version=2):
        msgs = self.notify("textDocument/didChange", {"textDocument": {"uri": self.uri, "version": version},
                                                       "contentChanges": [{"text": text}]})
        self.text = text
        return msgs[-1]["params"]

    def pos_req(self, method, pos):
        r = self.request(method, {"textDocument": {"uri": self.uri}, "position": pos})
        assert "error" not in r, r
        return r["result"]

    def hover(self, needle, nth=0, offset=0, text=None):
        r = self.pos_req("textDocument/hover", at(text or self.text, needle, nth, offset))
        return r["contents"]["value"] if r else None

    def definition(self, needle, nth=0, offset=0):
        r = self.pos_req("textDocument/definition", at(self.text, needle, nth, offset))
        return r[0]["range"]["start"] if r else None

    def complete(self, pos):
        return self.pos_req("textDocument/completion", pos)


def read_text(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def labels(items):
    return [i["label"] for i in items]


# ====================================================================== transport

class Transport(unittest.TestCase):
    def test_read_message_headers(self):
        body = b'{"a": 1}'
        data = b"content-length: 8\r\nContent-Type: application/vscode-jsonrpc; charset=utf-8\r\n\r\n" + body
        self.assertEqual(lsp.read_message(io.BytesIO(data)), body)
        self.assertEqual(lsp.read_message(io.BytesIO(b"CONTENT-LENGTH:8\r\n\r\n" + body)), body)
        self.assertIsNone(lsp.read_message(io.BytesIO(b"")))

    def test_frame_roundtrip_unicode(self):
        obj = {"jsonrpc": "2.0", "id": 1, "result": "имя 🙂"}
        data = lsp.frame(obj)
        head, _, body = data.partition(b"\r\n\r\n")
        self.assertEqual(int(head.split(b":")[1]), len(body))
        self.assertEqual(len(body), len(json.dumps(obj, ensure_ascii=False).encode("utf-8")))
        self.assertEqual(json.loads(lsp.read_message(io.BytesIO(data))), obj)

    def test_bad_header_skipped(self):
        msgs, code, err = run_frames(raw=b"X-Foo: 1\r\n\r\n" + b"Content-Length: abc\r\n\r\n" + frame(INIT))
        self.assertEqual([m.get("id") for m in msgs], [0])
        self.assertIn("capabilities", msgs[0]["result"])
        self.assertIn("without a valid Content-Length", err)

    def test_truncated_body_eof(self):
        msgs, code, err = run_frames(INIT, raw=b"Content-Length: 50\r\n\r\n{\"jsonrpc\"")
        self.assertEqual(len(msgs), 1)
        self.assertEqual(code, 1)

    def test_malformed_json_then_ok(self):
        bad = b"{not json"
        msgs, code, err = run_frames(INIT, b"Content-Length: %d\r\n\r\n" % len(bad) + bad,
                                     {"jsonrpc": "2.0", "id": 2, "method": "shutdown"})
        self.assertEqual(msgs[1], {"jsonrpc": "2.0", "id": None,
                                   "error": {"code": -32700, "message": msgs[1]["error"]["message"]}})
        self.assertEqual(msgs[2], {"jsonrpc": "2.0", "id": 2, "result": None})
        self.assertIn("malformed", err)
        bad_utf8 = b'{"x": "\xff"}'
        msgs, _, _ = run_frames(b"Content-Length: %d\r\n\r\n" % len(bad_utf8) + bad_utf8)
        self.assertEqual(msgs[0]["error"]["code"], -32700)

    def test_non_object_message(self):
        for body in (b"[1, 2]", b"7", b'"x"', b"null"):
            msgs, _, _ = run_frames(b"Content-Length: %d\r\n\r\n" % len(body) + body)
            self.assertEqual(msgs[0]["error"]["code"], -32600, body)
            self.assertIsNone(msgs[0]["id"])

    def test_unknown_method(self):
        s = Session()
        r = s.request("textDocument/frobnicate", {})
        self.assertEqual(r["error"]["code"], -32601)
        self.assertIn("frobnicate", r["error"]["message"])
        self.assertIsNotNone(s.hover("main"))          # still alive

    def test_unknown_notification_silent(self):
        s = Session()
        self.assertEqual(s.notify("custom/thing", {}), [])
        self.assertEqual(s.notify("$/cancelRequest", {"id": 3}), [])
        self.assertEqual(s.notify("$/setTrace", {"value": "off"}), [])

    def test_bad_id(self):
        s = Session()
        for mid in (True, 1.5, {"a": 1}, [1]):
            msgs = s.send({"jsonrpc": "2.0", "id": mid, "method": "shutdown"})
            self.assertEqual(msgs[0]["error"]["code"], -32600, mid)
            self.assertIsNone(msgs[0]["id"])
        self.assertEqual(s.server.state, "running")

    def test_response_ignored(self):
        s = Session()
        self.assertEqual(s.send({"jsonrpc": "2.0", "id": 5, "result": None}), [])
        self.assertEqual(s.send({"jsonrpc": "2.0", "id": 6, "error": {"code": 1, "message": "x"}}), [])
        msgs = s.send({"jsonrpc": "2.0", "id": 7})
        self.assertEqual(msgs[0]["error"]["code"], -32600)
        self.assertEqual(msgs[0]["id"], 7)

    def test_string_id(self):
        s = Session()
        msgs = s.send({"jsonrpc": "2.0", "id": "abc", "method": "textDocument/hover",
                       "params": {"textDocument": {"uri": URI}, "position": at(SRC, "main")}})
        self.assertEqual(msgs[0]["id"], "abc")
        self.assertIn("fn main()", msgs[0]["result"]["contents"]["value"])

    def test_invalid_params(self):
        s = Session()
        for params in ({}, {"textDocument": {}}, {"textDocument": {"uri": URI}},
                       {"textDocument": {"uri": 5}, "position": {"line": 0, "character": 0}},
                       {"textDocument": {"uri": URI}, "position": "x"}):
            r = s.request("textDocument/hover", params)
            self.assertEqual(r["error"]["code"], -32602, params)
        r = s.request("textDocument/documentSymbol", {})
        self.assertEqual(r["error"]["code"], -32602)
        self.assertEqual(s.notify("textDocument/didOpen", {"textDocument": {"uri": URI}}), [])
        self.assertEqual(s.notify("textDocument/didChange", {"textDocument": {"uri": "file:///nope.sipar"},
                                                             "contentChanges": [{"text": ""}]}), [])
        self.assertIn("invalid params", s.err.getvalue())
        self.assertIsNotNone(s.hover("main"))

    def test_handler_crash_isolated(self):
        s = Session()
        with mock.patch.object(lsp, "classify", side_effect=ZeroDivisionError("boom")):
            r = s.request("textDocument/hover", {"textDocument": {"uri": URI}, "position": at(SRC, "main")})
        self.assertEqual(r["error"]["code"], -32603)
        self.assertIn("ZeroDivisionError", r["error"]["message"])
        self.assertIn("Traceback", s.err.getvalue())
        self.assertIn("fn main()", s.hover("main"))
        with mock.patch.object(lsp, "diagnostics_for", side_effect=RuntimeError("x")):
            self.assertEqual(s.notify("textDocument/didChange", {"textDocument": {"uri": URI, "version": 9},
                                                                 "contentChanges": [{"text": SRC}]}), [])
        self.assertIn("didChange failed", s.err.getvalue())

    def test_unencodable_result(self):
        s = Session()
        with mock.patch.object(lsp, "describe", return_value=float("nan")), \
                mock.patch.object(lsp, "code_md", side_effect=lambda *a: a[0]):
            r = s.request("textDocument/hover", {"textDocument": {"uri": URI}, "position": at(SRC, "main")})
        self.assertEqual(r["error"]["code"], -32603)
        self.assertIn("encode", r["error"]["message"])

    def test_serve_survives_unexpected_error(self):
        with mock.patch.object(lsp.Server, "handle", side_effect=[KeyError("k"), None, None]) as h:
            msgs, code, err = run_frames(INIT, INIT)
        self.assertIn("unexpected error", err)
        self.assertEqual(h.call_count, 2)          # the frame after the crash was still read and handled


# ====================================================================== lifecycle

class Lifecycle(unittest.TestCase):
    def test_initialize_capabilities(self):
        msgs, code, _ = run_frames(INIT)
        caps = msgs[0]["result"]["capabilities"]
        self.assertEqual(caps["textDocumentSync"], {"openClose": True, "change": 1, "save": False})
        self.assertEqual(caps["positionEncoding"], "utf-16")
        self.assertTrue(caps["hoverProvider"])
        self.assertTrue(caps["definitionProvider"])
        self.assertTrue(caps["documentSymbolProvider"])
        self.assertIn(".", caps["completionProvider"]["triggerCharacters"])
        self.assertNotIn("documentFormattingProvider", caps)
        self.assertEqual(msgs[0]["result"]["serverInfo"]["name"], "sipar")
        self.assertEqual(code, 1)          # EOF without shutdown

    def test_request_before_initialize(self):
        s = Session(init=False)
        r = s.request("textDocument/hover", {"textDocument": {"uri": URI}, "position": {"line": 0, "character": 0}})
        self.assertEqual(r["error"]["code"], -32002)
        r = s.request("shutdown", None)
        self.assertEqual(r["error"]["code"], -32002)
        self.assertEqual(s.notify("textDocument/didOpen",
                                  {"textDocument": {"uri": URI, "version": 1, "text": "fn main() { x }"}}), [])
        self.assertEqual(s.server.docs, {})
        self.assertIn("result", s.request("initialize", {}))

    def test_double_initialize(self):
        s = Session()
        r = s.request("initialize", {})
        self.assertEqual(r["error"]["code"], -32600)
        self.assertEqual(s.server.state, "running")

    def test_initialize_bad_params(self):
        s = Session(init=False)
        r = s.request("initialize", [1])
        self.assertEqual(r["error"]["code"], -32602)
        self.assertEqual(s.server.state, "new")
        r = s.request("initialize", {})
        self.assertIn("capabilities", r["result"])
        self.assertEqual(s.server.state, "running")

    def test_shutdown_then_request(self):
        s = Session()
        self.assertEqual(s.request("shutdown", None), {"jsonrpc": "2.0", "id": s.next_id, "result": None})
        r = s.request("textDocument/hover", {"textDocument": {"uri": URI}, "position": at(SRC, "main")})
        self.assertEqual(r["error"]["code"], -32600)
        self.assertEqual(s.notify("textDocument/didChange", {"textDocument": {"uri": URI, "version": 3},
                                                             "contentChanges": [{"text": "x"}]}), [])

    def test_shutdown_exit_code(self):
        msgs, code, err = run_frames(INIT, {"jsonrpc": "2.0", "id": 1, "method": "shutdown"},
                                     {"jsonrpc": "2.0", "method": "exit"},
                                     {"jsonrpc": "2.0", "id": 2, "method": "shutdown"})
        self.assertEqual(code, 0)
        self.assertEqual([m["id"] for m in msgs], [0, 1])      # nothing read after exit

    def test_exit_without_shutdown(self):
        msgs, code, _ = run_frames(INIT, {"jsonrpc": "2.0", "method": "exit"})
        self.assertEqual(code, 1)
        msgs, code, _ = run_frames({"jsonrpc": "2.0", "method": "exit"})
        self.assertEqual(code, 1)

    def test_eof_codes(self):
        self.assertEqual(run_frames(INIT)[1], 1)
        self.assertEqual(run_frames(INIT, {"jsonrpc": "2.0", "id": 1, "method": "shutdown"})[1], 0)
        self.assertEqual(run_frames()[1], 1)

    def test_feature_registry_capability(self):
        calls = []

        @lsp.feature("textDocument/formatting", "documentFormattingProvider")
        def fmt(server, params):
            calls.append(params)
            return []
        try:
            msgs, _, _ = run_frames(INIT, {"jsonrpc": "2.0", "id": 1, "method": "textDocument/formatting",
                                           "params": {"textDocument": {"uri": URI}}})
            self.assertTrue(msgs[0]["result"]["capabilities"]["documentFormattingProvider"])
            self.assertEqual(msgs[1]["result"], [])
            self.assertEqual(len(calls), 1)
        finally:
            del lsp.FEATURES["textDocument/formatting"]


# ====================================================================== positions

class Positions(unittest.TestCase):
    def test_utf16_helpers(self):
        self.assertEqual(lsp.utf16_len("abc"), 3)
        self.assertEqual(lsp.utf16_len("🙂"), 2)
        self.assertEqual(lsp.utf16_len("имя"), 3)
        t = "a🙂b"
        self.assertEqual([lsp.cp_to_utf16(t, i) for i in range(5)], [0, 1, 3, 4, 4])
        self.assertEqual([lsp.utf16_to_cp(t, u) for u in range(6)], [0, 1, 1, 2, 3, 3])
        self.assertEqual(lsp.utf16_to_cp(t, -3), 0)
        self.assertEqual(lsp.cp_to_utf16(t, -1), 0)
        self.assertEqual(lsp.utf16_to_cp("", 4), 0)
        self.assertEqual(lsp.utf16_to_cp("🙂🙂x", 4), 2)

    def test_hover_after_emoji(self):
        text = 'fn main() {\n    let 🙂s = "🙂🙂"; let tail = 1\n}\n'.replace('🙂s', 's')
        text = 'fn main() {\n    let s = "🙂🙂"\n    print("🙂{s}🙂" + s)\n}\n'
        s = Session(text)
        h = s.hover("+ s", offset=2)
        self.assertIn("let s: Str", h)
        p = at(text, "+ s", offset=2)
        self.assertEqual(p["character"], 22)              # 4 emoji = 8 units, not 4
        r = s.pos_req("textDocument/hover", p)
        self.assertEqual(r["range"]["start"], p)
        self.assertEqual(r["range"]["end"], {"line": 2, "character": 23})
        self.assertIn("let s: Str", s.hover("{s}", offset=1))
        self.assertEqual(s.definition("{s}", offset=1), at(text, "s =")),
        # one unit to the right of the word is still on it; inside an emoji is not
        self.assertIsNone(s.pos_req("textDocument/hover", {"line": 2, "character": 12}))

    def test_diagnostic_range_after_emoji(self):
        text = 'fn main() {\n    print("🙂🙂" + nope)\n}\n'
        diags = Session(text).open(text)
        self.assertEqual(len(diags), 1)
        self.assertEqual(diags[0]["range"], {"start": at(text, "nope"), "end": at(text, "nope", offset=4)})
        self.assertEqual(diags[0]["range"]["start"]["character"], 19)      # 17 code points + 2 for the emoji pairs

    def test_cyrillic_identifier(self):
        # names are ASCII (E101 since round 4); the error points at the first non-ASCII letter
        bad = 'fn main() {\n    let имя = "мир"\n}\n'
        d = Session(bad).open(bad)
        self.assertEqual([(x["code"], x["range"]["start"]) for x in d], [("E101", {"line": 1, "character": 8})])
        # Cyrillic text inside strings shifts columns on the same line
        text = 'fn main() {\n    let name = "мир"\n    print("мир" + name.upper())\n}\n'
        s = Session(text)
        self.assertEqual(s.open(text), [])
        self.assertIn("let name: Str", s.hover("name", nth=1))
        self.assertEqual(s.definition("name", nth=1), at(text, "name"))
        self.assertEqual(at(text, "name", nth=1)["character"], 18)
        self.assertIn("Str.upper() -> Str", s.hover("upper"))
        text2 = 'fn main() {\n    let name = "мир"\n    print("мир" + name.)\n}\n'
        s.change(text2)
        items = s.complete(at(text2, "name.)", offset=5))
        self.assertIn("upper", labels(items))
        self.assertNotIn("push", labels(items))

    def test_positions_out_of_range(self):
        s = Session()
        self.assertIsNone(s.pos_req("textDocument/hover", {"line": 999, "character": 0}))
        self.assertIsNone(s.pos_req("textDocument/definition", {"line": 0, "character": 999}))
        s.pos_req("textDocument/completion", {"line": 999, "character": 999})
        self.assertIsNone(s.pos_req("textDocument/hover", {"line": -1, "character": -5}))
        a = lsp.Analysis("fn main() {}\n", "x.sipar")
        self.assertEqual(a.lsp_pos((99, 7)), {"line": 1, "character": 0})
        fake = type("D", (), {"line": 50, "col": 3, "message": "m", "hint": "", "severity": "error", "code": "E1"})
        a.diags = [fake]
        d = lsp.diagnostics_for(a)[0]
        self.assertEqual(d["range"]["start"], {"line": 1, "character": 0})

    def test_crlf_document(self):
        text = SRC.replace("\n", "\r\n")
        s = Session(text)
        self.assertEqual(s.open(text), [])
        self.assertIn("(parameter) a: Int", s.hover("a + b"))
        self.assertEqual(s.definition("a + b"), at(SRC, "a: Int"))

    def test_incremental_change_crlf(self):
        text = "fn main() {\r\n    let a = 1\r\n    print(a)\r\n}\r\n"
        new = lsp.apply_change(text, {"range": {"start": {"line": 2, "character": 10}, "end": {"line": 2, "character": 11}},
                                      "text": "a + 1"})
        self.assertEqual(new, "fn main() {\r\n    let a = 1\r\n    print(a + 1)\r\n}\r\n")
        new = lsp.apply_change(text, {"range": {"start": {"line": 1, "character": 99}, "end": {"line": 2, "character": 0}},
                                      "text": ""})
        self.assertEqual(new, "fn main() {\r\n    let a = 1    print(a)\r\n}\r\n")
        self.assertEqual(lsp.apply_change("a\rb", {"range": {"start": {"line": 1, "character": 0},
                                                             "end": {"line": 1, "character": 1}}, "text": "X"}), "a\rX")

    def test_incremental_change_emoji(self):
        text = 'let s = "🙂x🙂"\n'
        rng = {"start": {"line": 0, "character": 11}, "end": {"line": 0, "character": 12}}
        self.assertEqual(lsp.apply_change(text, {"range": rng, "text": "Y"}), 'let s = "🙂Y🙂"\n')
        rev = {"start": rng["end"], "end": rng["start"]}
        self.assertEqual(lsp.apply_change(text, {"range": rev, "text": "Y"}), 'let s = "🙂Y🙂"\n')
        self.assertEqual(lsp.apply_change(text, {"range": {"start": {"line": 9, "character": 0},
                                                            "end": {"line": 9, "character": 0}}, "text": "z"}), text + "z")
        self.assertEqual(lsp.apply_change(text, {"text": "whole"}), "whole")
        s = Session('fn main() {\n    let s = "🙂x"\n    print(s)\n}\n')
        msgs = s.notify("textDocument/didChange", {
            "textDocument": {"uri": URI, "version": 5},
            "contentChanges": [{"range": {"start": {"line": 2, "character": 10}, "end": {"line": 2, "character": 11}},
                                "text": "nope"}]})
        p = msgs[0]["params"]
        self.assertEqual(p["version"], 5)
        self.assertEqual([d["code"] for d in p["diagnostics"]], ["E203"])
        self.assertEqual(s.server.docs[URI].text, 'fn main() {\n    let s = "🙂x"\n    print(nope)\n}\n')


# ====================================================================== diagnostics

class Diagnostics(unittest.TestCase):
    def test_diagnostics_error_with_hint(self):
        text = 'fn main() {\n    http.get("x")\n}\n'
        d = Session(text).open(text)
        self.assertEqual(len(d), 1)
        self.assertEqual(d[0]["severity"], 1)
        self.assertEqual(d[0]["code"], "E301")
        self.assertEqual(d[0]["source"], "sipar")
        self.assertTrue(d[0]["message"].endswith("\nhint: add `uses net` to fn main"), d[0]["message"])
        self.assertEqual(d[0]["range"], {"start": at(text, "http"), "end": at(text, "http", offset=4)})
        text = 'fn main() {\n    let x: Int = "a"\n}\n'
        d = Session(text).open(text)
        self.assertTrue(d[0]["message"].endswith("\nhint: see E210 in docs/ERRORS.md; `sipar spec` prints the syntax"),
                        d[0]["message"])
        self.assertEqual(d[0]["range"], {"start": at(text, '"a"'), "end": at(text, '"a"', offset=1)})

    def test_diagnostics_warning(self):
        text = 'allow net ["*"]\nfn main() {}\n'
        d = Session(text).open(text)
        self.assertEqual([(x["code"], x["severity"]) for x in d], [("E311", 2)])
        self.assertEqual(d[0]["range"]["end"], {"line": 0, "character": 5})

    def test_diagnostics_syntax_error(self):
        text = "fn main() {\n    let x = (\n}\n"
        d = Session(text).open(text)
        self.assertEqual([x["code"] for x in d], ["E110"])
        self.assertEqual(d[0]["range"]["start"], {"line": 2, "character": 0})

    def test_did_change_clears(self):
        s = Session("fn main() { print(nope) }\n")
        p = s.change("fn main() { print(1) }\n", version=7)
        self.assertEqual(p, {"uri": URI, "version": 7, "diagnostics": []})

    def test_did_close_clears(self):
        s = Session("fn main() { print(nope) }\n")
        msgs = s.notify("textDocument/didClose", {"textDocument": {"uri": URI}})
        self.assertEqual(msgs, [{"jsonrpc": "2.0", "method": "textDocument/publishDiagnostics",
                                 "params": {"uri": URI, "diagnostics": []}}])
        self.assertNotIn(URI, s.server.docs)
        self.assertIsNone(s.pos_req("textDocument/hover", at(s.text, "main")))
        self.assertEqual(s.notify("textDocument/didClose", {"textDocument": {"uri": URI}}), [])

    def test_checker_crash_reported(self):
        import sipar.checker as checker
        with mock.patch.object(checker, "check_source", side_effect=RuntimeError("kaput")):
            s = Session(None)
            d = s.open(SRC)
        self.assertEqual(len(d), 1)
        self.assertEqual(d[0]["severity"], 2)
        self.assertNotIn("code", d[0])
        self.assertIn("kaput", d[0]["message"])
        self.assertIn("checker crashed", s.err.getvalue())
        self.assertIn("fn main()", s.hover("main"))         # parse-only fallback still gives outline / hover
        r = s.request("textDocument/documentSymbol", {"textDocument": {"uri": URI}})
        self.assertIn("main", [x["name"] for x in r["result"]])

    def test_examples_clean(self):
        for rel in ("examples/tour.sipar", "examples/triage.sipar", "examples/injection/assistant.sipar"):
            text = read_text(rel)
            s = Session(None)
            self.assertEqual(s.open(text), [], rel)
            self.assertEqual(s.err.getvalue(), "", rel)

    def test_uri_to_path(self):
        self.assertEqual(lsp.uri_to_path("file:///tmp/t%20dir/a.sipar"), "/tmp/t dir/a.sipar")
        self.assertEqual(lsp.uri_to_path("file:///tmp/%D0%BC%D0%B8%D1%80.sipar"), "/tmp/мир.sipar")
        self.assertEqual(lsp.uri_to_path("file:///C:/x/a.sipar"), "C:/x/a.sipar")
        self.assertEqual(lsp.uri_to_path("untitled:Untitled-1"), "untitled:Untitled-1")
        s = Session("fn main() { print(nope) }\n", uri="untitled:Untitled-1")
        self.assertEqual(len(s.server.docs["untitled:Untitled-1"].analysis.diags), 1)
        self.assertEqual(s.server.docs["untitled:Untitled-1"].analysis.diags[0].file, "untitled:Untitled-1")
        s = Session("fn main() { print(nope) }\n")
        self.assertEqual(s.server.docs[URI].analysis.diags[0].file, "/tmp/t dir/a.sipar")


# ====================================================================== hover

class Hover(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = Session()
        assert cls.s.server.docs[URI].analysis.diags == [], cls.s.server.docs[URI].analysis.diags

    def test_hover_locals(self):
        h = self.s.hover
        self.assertEqual(h("in xs", offset=3), "```sipar\nlet xs: List[Int]\n```")
        self.assertEqual(h("n = n", offset=0), "```sipar\nvar n: Int\n```")
        self.assertEqual(h("x }"), "```sipar\n(loop variable) x: Int\n```")
        self.assertEqual(h("r) =>"), "```sipar\n(match binding) r: Float\n```")
        self.assertEqual(h("=> r,", offset=3), "```sipar\n(match binding) r: Float\n```")
        self.assertEqual(h("e.message"), "```sipar\n(caught error) e: Error\n```")
        self.assertEqual(h("catch e", offset=6), "```sipar\n(caught error) e: Error\n```")
        self.assertEqual(h("y + LIMIT"), "```sipar\n(parameter) y: Int\n```")
        self.assertEqual(h("a + b"), "```sipar\n(parameter) a: Int\n```")
        self.assertEqual(h("let k", offset=4), "```sipar\nlet k: Float\n```")
        self.assertEqual(h("let f", offset=4), "```sipar\nlet f: fn(Int) -> Int\n```")
        self.assertEqual(h("LIMIT\n"), "```sipar\nlet LIMIT: Int\n```\n\ntop-level constant")

    def test_hover_fn_signature_doc(self):
        self.assertEqual(self.s.hover("add(1"), "```sipar\nfn add(a: Int, b: Int) -> Int\n```\n\nAdds two numbers.")
        self.assertEqual(self.s.hover("main"), "```sipar\nfn main() uses net\n```")
        tour = read_text("examples/tour.sipar")
        s = Session(tour)
        h = s.hover("helper(goal")
        self.assertEqual(h, "```sipar\n@max_steps(5)\nagent fn helper(goal: Str) -> Str uses net\n"
                            "    tools [weather, add]\n```\n\nEffects: ai, net")
        h = s.hover("review(code")
        self.assertTrue(h.startswith("```sipar\n@retries(3) @temperature(0.2)\nai fn review(code: Str) -> Review\n```"), h)

    def test_hover_types(self):
        h = self.s.hover
        self.assertEqual(h("P {"), "```sipar\ntype P = { name: Str, age: Int }\n```\n\nA point.")
        self.assertEqual(h("P = {", offset=0), h("P {"))
        self.assertEqual(h("Shape {"), "```sipar\nenum Shape { dot, circle(r: Float) }\n```")
        self.assertEqual(h("circle(r: 1", offset=0),
                         "```sipar\nShape.circle(r: Float)\n```\n\nvariant of enum `Shape`")
        self.assertEqual(h("dot =>"), "```sipar\nShape.dot\n```\n\nvariant of enum `Shape`")
        self.assertEqual(h("name: Str"), "```sipar\n(field) P.name: Str\n```")
        self.assertEqual(h('name: "a"'), "```sipar\n(field) P.name: Str\n```")
        self.assertEqual(h("age: add"), "```sipar\n(field) P.age: Int\n```")
        self.assertEqual(h("p.name", offset=2), "```sipar\n(field) P.name: Str\n```")
        self.assertEqual(h("r: 1.5"), "```sipar\n(field) Shape.circle.r: Float\n```")
        self.assertEqual(h("r: Float"), "```sipar\n(field) Shape.circle.r: Float\n```")
        self.assertEqual(h("message"), "```sipar\n(field) Error.message: Str\n```")
        self.assertIn("Whole number", h("Int }"))

    def test_hover_stdlib(self):
        h = self.s.hover("get(")
        self.assertTrue(h.startswith("```sipar\nfn http.get(url: Str, headers: Map[Str]) -> Str uses net\n```"), h)
        self.assertIn("Untrusted data is rejected in: `url`", h)
        self.assertIn("Optional named argument(s): `headers`", h)
        self.assertIn("Result is untrusted", h)
        self.assertTrue(self.s.hover("print(http").startswith("```sipar\nfn print(value: Any) -> None\n```"))
        self.assertIn("module http", self.s.hover("http"))
        self.assertIn("`http.post`", self.s.hover("http"))

    def test_hover_methods(self):
        text = 'fn main() {\n    let xs = [1]\n    let m = ["a": "b"]\n    print(xs.map(fn(x) => x).len())\n' \
               '    print(m.keys())\n    print("s".split(","))\n}\n'
        s = Session(text)
        self.assertEqual(s.open(text), [])
        self.assertTrue(s.hover("map").startswith("```sipar\nList[Int].map(f: fn(Int) -> U) -> List[U]\n```"))
        self.assertTrue(s.hover("len").startswith("```sipar\nList[Int].len() -> Int\n```"))
        self.assertTrue(s.hover("keys").startswith("```sipar\nMap[Str].keys() -> List[Str]\n```"))
        self.assertTrue(s.hover("split").startswith("```sipar\nStr.split("))

    def test_hover_expression_type(self):
        text = 'fn main() {\n    let z = (1 + 2.5) * 2\n    print([z])\n}\n'
        s = Session(text)
        r = s.pos_req("textDocument/hover", at(text, "+ 2"))
        self.assertIn("Float", r["contents"]["value"])
        self.assertIn("expression type", r["contents"]["value"])
        r = s.pos_req("textDocument/hover", at(text, "[z]"))
        self.assertIn("List[Float]", r["contents"]["value"])
        self.assertIsNone(s.pos_req("textDocument/hover", at(text, "let")))
        self.assertIsNone(s.pos_req("textDocument/hover", at(text, "2.5", offset=1)))

    def test_hover_not_in_strings(self):
        self.assertIsNone(self.s.hover("add\")"))
        self.assertIsNone(self.s.hover("add xs"))
        self.assertIsNone(self.s.hover("xs\n"))
        self.assertIsNone(self.s.hover("Adds"))
        self.assertIsNone(self.s.hover("point"))
        text = 'fn main() {\n    let t = 1\n    print("""\n    t {t} t \\{t\\}\n    """)\n}\n'
        s = Session(text)
        self.assertIsNone(s.hover("t {"))
        self.assertIn("let t: Int", s.hover("{t}", offset=1))
        self.assertEqual(s.open(text), [])
        self.assertIsNone(s.hover("t \\{"))
        self.assertIsNone(s.hover("\\{t", offset=2))

    def test_hover_in_interpolation(self):
        self.assertEqual(self.s.hover("p.name"), "```sipar\nlet p: P\n```")
        self.assertEqual(self.s.hover("f(n)"), "```sipar\nlet f: fn(Int) -> Int\n```")
        self.assertEqual(self.s.hover("n)}"), "```sipar\nvar n: Int\n```")
        text = 'fn main() {\n    let m = ["a": 1]\n    print("{m["a"]} {m}")\n}\n'
        s = Session(text)
        self.assertIn("let m: Map[Int]", s.hover("m}"))
        self.assertIsNone(s.hover('a"]'))

    def test_hover_attribute_capability(self):
        tour = read_text("examples/tour.sipar")
        s = Session(tour)
        self.assertEqual(s.hover("retries"), "```sipar\n@retries(Int)\n```\n\nAttribute of ai fn and agent fn.")
        self.assertEqual(s.hover("max_steps"), "```sipar\n@max_steps(Int)\n```\n\nAttribute of agent fn.")
        self.assertEqual(self.s.hover("net"), "```sipar\ncapability net\n```\n\nNeeded by: `http.get`, `http.post`.")
        self.assertEqual(self.s.hover("uses net", offset=5), self.s.hover("net"))
        text = 'allow fs.read ["./x"]\nfn main() uses fs.read, ai {}\n'
        s = Session(text)
        self.assertIn("capability fs.read", s.hover("read"))
        self.assertIn("capability fs.read", s.hover("fs.read,"))
        self.assertIn("`fs.exists`", s.hover("read,"))
        self.assertIn("ai fn", s.hover("ai {"))

    def test_unknown_document(self):
        s = Session()
        for m in ("textDocument/hover", "textDocument/definition"):
            r = s.request(m, {"textDocument": {"uri": "file:///other.sipar"}, "position": {"line": 0, "character": 0}})
            self.assertIsNone(r["result"])
        r = s.request("textDocument/completion", {"textDocument": {"uri": "file:///o.sipar"},
                                                  "position": {"line": 0, "character": 0}})
        self.assertEqual(r["result"], [])
        r = s.request("textDocument/documentSymbol", {"textDocument": {"uri": "file:///o.sipar"}})
        self.assertEqual(r["result"], [])

    def test_hover_after_word_end(self):
        self.assertEqual(self.s.hover("add(1", offset=3), self.s.hover("add(1"))
        r = self.s.pos_req("textDocument/hover", at(SRC, "add(1", offset=3))
        self.assertEqual(r["range"], {"start": at(SRC, "add(1"), "end": at(SRC, "add(1", offset=3)})


# ====================================================================== definition

class Definition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = Session()

    def test_definition_kinds(self):
        d = self.s.definition
        self.assertEqual(d("add(1"), at(SRC, "add(a"))
        self.assertEqual(d("P {"), at(SRC, "P = {"))
        self.assertEqual(d("Shape.circle(r: 1"), at(SRC, "Shape {"))
        self.assertEqual(d("circle(r: 1"), at(SRC, "circle(r: F"))
        self.assertEqual(d("circle(r)"), at(SRC, "circle(r: F"))
        self.assertEqual(d("dot =>"), at(SRC, "dot,"))
        self.assertEqual(d("in xs", offset=3), at(SRC, "xs ="))
        self.assertEqual(d("n = n", offset=4), at(SRC, "n = 0"))
        self.assertEqual(d("LIMIT\n"), at(SRC, "LIMIT ="))
        self.assertEqual(d("b }"), at(SRC, "b: Int"))
        self.assertEqual(d("p.name"), at(SRC, "p = P"))
        self.assertEqual(d("p.name", offset=2), at(SRC, "name: Str"))
        self.assertEqual(d('name: "a"'), at(SRC, "name: Str"))
        self.assertEqual(d("r: 1.5"), at(SRC, "r: Float"))
        self.assertEqual(d("add(a"), at(SRC, "add(a"))
        self.assertEqual(d("main"), at(SRC, "main"))
        r = self.s.pos_req("textDocument/definition", at(SRC, "add(1"))
        self.assertEqual(r, [{"uri": URI, "range": {"start": at(SRC, "add(a"), "end": at(SRC, "add(a", offset=3)}}])

    def test_definition_locals(self):
        d = self.s.definition
        self.assertEqual(d("y + LIMIT"), at(SRC, "y: Int"))
        self.assertEqual(d("x }"), at(SRC, "x in"))
        self.assertEqual(d("=> r,", offset=3), at(SRC, "r) =>"))
        self.assertEqual(d("e.message"), at(SRC, "e { print"))
        self.assertEqual(d("k}"), at(SRC, "k = match"))

    def test_definition_none(self):
        for needle in ("print(http", "get(", "http", "let xs", '"https', "Int }", "net ["):
            self.assertIsNone(self.s.definition(needle), needle)
        self.assertIsNone(self.s.definition("message"))      # Error.message is built in

    def test_definition_shadowing(self):
        text = ('fn main() {\n    let v = 1\n    if true {\n        let v = "s"\n        print(v)\n    }\n'
                '    print(v)\n    let w = fn(v: Int) => v\n    print(w(v))\n}\n'
                'fn other(v: Str) { print(v) }\n')
        s = Session(text)
        self.assertEqual(s.open(text), [])
        self.assertEqual(s.definition("print(v)", offset=6), at(text, 'v = "s"'))
        self.assertEqual(s.definition("print(v)", nth=1, offset=6), at(text, "v = 1"))
        self.assertEqual(s.definition("=> v", offset=3), at(text, "v: Int"))
        self.assertEqual(s.definition("w(v)", offset=2), at(text, "v = 1"))
        self.assertEqual(s.definition("print(v) }", offset=6), at(text, "v: Str"))
        self.assertIn("let v: Str", s.hover("print(v)", offset=6))
        self.assertIn("let v: Int", s.hover("print(v)", nth=1, offset=6))

    def test_lambda_scope_ends(self):
        """An expression-bodied lambda's parameter is not visible after the lambda (comma, bracket, next line)."""
        text = ('fn app(g: fn(Int) -> Int, n: Int) -> Int { g(n) }\n'
                'let K = fn(v: Int) => v\nlet V = 3\n'
                'fn main() {\n    let v = 1\n    print(app(fn(v: Int) => v * 2, v))\n'
                '    print([fn(v: Int) => (v), fn(u: Int) => u + v])\n    print(V)\n}\n')
        s = Session(text)
        self.assertEqual(s.open(text), [])
        self.assertEqual(s.definition("=> v *", offset=3), at(text, "v: Int) => v *"))
        self.assertEqual(s.definition("2, v", offset=3), at(text, "v = 1"))
        self.assertEqual(s.definition("=> (v)", offset=4), at(text, "v: Int) => (v)"))
        self.assertEqual(s.definition("u + v", offset=4), at(text, "v = 1"))
        self.assertEqual(s.definition("=> v\n", offset=3), at(text, "v: Int) => v\n"))
        self.assertEqual(s.definition("print(V)", offset=6), at(text, "V = 3"))


# ====================================================================== completion

class Completion(unittest.TestCase):
    BASE = ('allow net\ntype P = { name: Str, age: Int }\nenum Color { red, green(v: Int) }\n\n'
            'fn helper() -> Int { 1 }\n\nfn main() uses net {\n    let xs = [1, 2]\n    let p = P { name: "a", age: 3 }\n'
            '    @@\n    let later = 1\n}\n\nfn other(q: Int) { print(q) }\n')

    def at_marker(self, fill, extra=""):
        text = self.BASE.replace("@@", fill)
        s = Session(text)
        return s, s.complete(at(text, "\n    " + fill, offset=5 + len(fill)))

    def test_completion_general(self):
        s, items = self.at_marker("x")
        by = {i["label"]: i for i in items}
        for k in ("let", "fn", "match", "true"):
            self.assertEqual(by[k]["kind"], 14, k)
        self.assertEqual(by["xs"]["kind"], 6)
        self.assertEqual(by["xs"]["detail"], "List[Int]")
        self.assertEqual(by["p"]["detail"], "P")
        self.assertNotIn("later", by)
        self.assertNotIn("q", by)
        self.assertEqual(by["helper"]["kind"], 3)
        self.assertEqual(by["helper"]["detail"], "fn helper() -> Int")
        self.assertEqual(by["P"]["kind"], 22)
        self.assertEqual(by["Color"]["kind"], 13)
        self.assertEqual(by["print"]["kind"], 3)
        self.assertEqual(by["http"]["kind"], 9)
        self.assertEqual(by["Int"]["kind"], 7)
        self.assertLess(by["xs"]["sortText"], by["helper"]["sortText"])
        self.assertLess(by["helper"]["sortText"], by["let"]["sortText"])
        self.assertEqual(len(labels(items)), len(set(labels(items))))

    def test_completion_module(self):
        _, items = self.at_marker("http.")
        self.assertEqual(labels(items), ["get", "post"])
        self.assertEqual(items[0]["kind"], 3)
        self.assertIn("uses net", items[0]["detail"])

    def test_completion_enum(self):
        _, items = self.at_marker("Color.")
        self.assertEqual(labels(items), ["red", "green"])
        self.assertEqual(items[1]["detail"], "Color.green(v: Int)")
        self.assertEqual(items[0]["kind"], 20)

    def test_completion_methods_incomplete(self):
        s, items = self.at_marker("xs.")
        self.assertEqual(s.server.docs[URI].analysis.ok, False)       # `xs.` alone does not parse
        names = labels(items)
        self.assertIn("map", names)
        self.assertIn("push", names)
        self.assertNotIn("upper", names)
        by = {i["label"]: i for i in items}
        self.assertEqual(by["first"]["detail"], "List[Int].first() -> Int?")
        self.assertEqual(by["first"]["kind"], 2)
        _, items = self.at_marker('"s".')
        self.assertIn("upper", labels(items))

    def test_completion_record_fields(self):
        _, items = self.at_marker("p.")
        self.assertEqual([(i["label"], i["detail"], i["kind"]) for i in items], [("name", "Str", 5), ("age", "Int", 5)])

    def test_completion_partial_member(self):
        text = self.BASE.replace("@@", "print(xs)")
        s = Session(text)
        bad = self.BASE.replace("@@", "xs.le")
        s.change(bad)
        items = s.complete(at(bad, "xs.le", offset=5))
        self.assertIn("len", labels(items))
        s2 = Session(bad)                 # never parsed: the receiver is found by the placeholder parse
        self.assertIn("len", labels(s2.complete(at(bad, "xs.le", offset=5))))

    def test_completion_unknown_receiver(self):
        _, items = self.at_marker("nope.")
        self.assertEqual(items, [])
        _, items = self.at_marker("0..")                   # a range: the end is an expression
        self.assertIn("abs", labels(items))
        self.assertNotIn("push", labels(items))

    def test_completion_capabilities(self):
        text = "allow fs.r\nfn main() uses net, fs.w {}\n"
        s = Session(text)
        items = s.complete(at(text, "fs.r", offset=4))
        self.assertIn("fs.read", labels(items))
        self.assertIn("net", labels(items))
        fr = [i for i in items if i["label"] == "fs.read"][0]
        self.assertEqual(fr["textEdit"]["range"], {"start": at(text, "fs.r"), "end": at(text, "fs.r", offset=4)})
        items = s.complete(at(text, "fs.w", offset=4))
        self.assertIn("fs.write", labels(items))
        self.assertEqual([i for i in items if i["label"] == "fs.write"][0]["textEdit"]["range"]["start"],
                         at(text, "fs.w"))

    def test_completion_attributes(self):
        text = "@\nai fn f(x: Str) -> Str { \"{x}\" }\n"
        s = Session(text)
        items = s.complete({"line": 0, "character": 1})
        self.assertEqual(labels(items), ["max_steps", "model", "retries", "system", "temperature"])
        self.assertEqual(items[1]["detail"], "@model(Str)")

    def test_completion_not_in_text(self):
        for fill in ('print("ab', "// xs", 'print("a" + "b c', 'print("x") // y'):
            _, items = self.at_marker(fill)
            self.assertEqual(items, [], fill)

    def test_completion_in_interpolation(self):
        text = self.BASE.replace("@@", 'print("{}")')       # what auto-closing pairs leave in the editor
        s = Session(text)
        self.assertFalse(s.server.docs[URI].analysis.ok)       # `{}` alone is a syntax error
        items = s.complete(at(text, '"{}', offset=2))
        self.assertIn("xs", labels(items))
        self.assertNotIn("later", labels(items))
        self.assertNotIn(lsp.PLACEHOLDER, labels(items))
        s = Session(self.BASE.replace("@@", "print(1)"))     # a good version first, then the unclosed string
        bad = self.BASE.replace("@@", 'print("{')
        s.change(bad)
        self.assertIn("xs", labels(s.complete(at(bad, '"{', offset=2))))
        text = self.BASE.replace("@@", 'print("{p.}")')
        items = Session(text).complete(at(text, "{p.", offset=3))
        self.assertEqual(labels(items), ["name", "age"])
        _, items = self.at_marker('print("{x}')
        self.assertEqual(items, [])


# ====================================================================== symbols

class Symbols(unittest.TestCase):
    def test_document_symbols(self):
        tour = read_text("examples/tour.sipar")
        s = Session(tour)
        r = s.request("textDocument/documentSymbol", {"textDocument": {"uri": URI}})["result"]
        got = [(x["name"], x["kind"], x.get("detail")) for x in r]
        self.assertEqual(got, [
            ("Review", 23, None), ("Mood", 10, None), ("Action", 10, None), ("LIMIT", 14, "Int"),
            ("add", 12, "fn add(a: Int, b: Int) -> Int"), ("review", 12, "ai fn review(code: Str) -> Review"),
            ("weather", 12, "fn weather(city: Str) -> Str uses net"),
            ("helper", 12, "agent fn helper(goal: Str) -> Str uses net"), ("main", 12, "fn main() uses ai, net"),
            ('test "review mock"', 6, None)])
        review = r[0]
        self.assertEqual([(c["name"], c["kind"], c["detail"]) for c in review["children"]],
                         [("score", 8, "Int"), ("verdict", 8, "Str"), ("issues", 8, "List[Str]")])
        action = r[2]
        self.assertEqual([(c["name"], c["kind"], c.get("detail")) for c in action["children"]],
                         [("search", 22, "search(query: Str)"), ("answer", 22, "answer(text: Str)")])
        self.assertEqual(action["range"]["start"], at(tour, "enum Action"))
        self.assertEqual(action["range"]["end"], {"line": at(tour, "enum Action")["line"] + 3, "character": 1})
        main = r[8]
        self.assertEqual(main["selectionRange"], {"start": at(tour, "main"), "end": at(tour, "main", offset=4)})
        self.assertEqual(main["range"]["start"], at(tour, "fn main"))
        self.assertEqual(main["range"]["end"], {"line": at(tour, 'test "review')["line"] - 2, "character": 1})
        review_fn = r[5]
        self.assertEqual(review_fn["range"]["start"], at(tour, "@retries"))
        for sym in r:
            self.assertLessEqual((sym["range"]["start"]["line"], sym["range"]["start"]["character"]),
                                 (sym["selectionRange"]["start"]["line"], sym["selectionRange"]["start"]["character"]))

    def test_symbols_last_good(self):
        s = Session()
        good = s.request("textDocument/documentSymbol", {"textDocument": {"uri": URI}})["result"]
        s.change(SRC.replace("let xs = [1, 2]", "let xs = [1, 2"))
        again = s.request("textDocument/documentSymbol", {"textDocument": {"uri": URI}})["result"]
        self.assertEqual(again, good)
        s2 = Session("fn main( {\n")
        self.assertEqual(s2.request("textDocument/documentSymbol", {"textDocument": {"uri": URI}})["result"], [])
        self.assertIsNone(s2.pos_req("textDocument/hover", {"line": 0, "character": 4}))

    def test_big_document_time(self):
        text = "".join(f"fn f{i}(a: Int) -> Int {{ a + {i} }}\n" for i in range(2000)) + \
            "fn main() { print(f1999(1)) }\n"
        t0 = time.monotonic()
        s = Session(text)
        h = s.hover("f1999(1")
        elapsed = time.monotonic() - t0
        self.assertIn("fn f1999(a: Int) -> Int", h)
        self.assertLess(elapsed, 10.0)


# ====================================================================== subprocess and CLI

class Subprocess(unittest.TestCase):
    def run_server(self, msgs, args=("-m", "sipar", "lsp")):
        data = b"".join(frame(m) for m in msgs)
        env = dict(os.environ, PYTHONPATH=ROOT)
        p = subprocess.run([sys.executable, *args], input=data, capture_output=True, cwd=ROOT, env=env, timeout=60)
        return parse_frames(p.stdout), p.returncode, p.stderr.decode()

    def test_subprocess_session(self):
        text = 'fn main() {\n    let v = "🙂"\n    print("🙂" + v + nope)\n}\n'
        msgs, code, err = self.run_server([
            INIT, {"jsonrpc": "2.0", "method": "initialized", "params": {}},
            {"jsonrpc": "2.0", "method": "textDocument/didOpen",
             "params": {"textDocument": {"uri": URI, "languageId": "sipar", "version": 1, "text": text}}},
            {"jsonrpc": "2.0", "id": 1, "method": "textDocument/hover",
             "params": {"textDocument": {"uri": URI}, "position": at(text, "v +")}},
            {"jsonrpc": "2.0", "id": 2, "method": "textDocument/definition",
             "params": {"textDocument": {"uri": URI}, "position": at(text, "v +")}},
            {"jsonrpc": "2.0", "id": 3, "method": "textDocument/completion",
             "params": {"textDocument": {"uri": URI}, "position": at(text, "v +", offset=1)}},
            {"jsonrpc": "2.0", "id": 4, "method": "textDocument/documentSymbol", "params": {"textDocument": {"uri": URI}}},
            {"jsonrpc": "2.0", "id": 5, "method": "nope/nope", "params": {}},
            {"jsonrpc": "2.0", "id": 6, "method": "shutdown"},
            {"jsonrpc": "2.0", "method": "exit"}])
        self.assertEqual(code, 0, err)
        self.assertEqual(err, "")
        by = {m.get("id", m.get("method")): m for m in msgs}
        diags = by["textDocument/publishDiagnostics"]["params"]["diagnostics"]
        self.assertEqual([(d["code"], d["range"]["start"]) for d in diags], [("E203", at(text, "nope"))])
        self.assertIn("let v: Str", by[1]["result"]["contents"]["value"])
        self.assertEqual(by[2]["result"][0]["range"]["start"], at(text, "v ="))
        self.assertIn("v", labels(by[3]["result"]))
        self.assertEqual(by[4]["result"][0]["name"], "main")
        self.assertEqual(by[5]["error"]["code"], -32601)
        self.assertIsNone(by[6]["result"])

    def test_subprocess_stdout_clean(self):
        script = ("import sys; sys.argv = ['sipar', 'lsp']\n"
                  "from sipar import lsp\n"
                  "orig = lsp.FEATURES['textDocument/hover'][0]\n"
                  "def noisy(server, params):\n    print('stray output'); return orig(server, params)\n"
                  "lsp.FEATURES['textDocument/hover'] = (noisy, 'hoverProvider', True)\n"
                  "from sipar.cli import main\nsys.exit(main())\n")
        msgs, code, err = self.run_server([
            INIT, {"jsonrpc": "2.0", "method": "textDocument/didOpen",
                   "params": {"textDocument": {"uri": URI, "version": 1, "text": SRC}}},
            {"jsonrpc": "2.0", "id": 1, "method": "textDocument/hover",
             "params": {"textDocument": {"uri": URI}, "position": at(SRC, "main")}},
            {"jsonrpc": "2.0", "id": 2, "method": "shutdown"}, {"jsonrpc": "2.0", "method": "exit"}],
            args=("-c", script))
        self.assertEqual(code, 0, err)
        self.assertIn("stray output", err)
        self.assertIn("fn main()", [m for m in msgs if m.get("id") == 1][0]["result"]["contents"]["value"])

    def test_subprocess_eof_without_exit(self):
        msgs, code, err = self.run_server([INIT])
        self.assertEqual(code, 1)
        self.assertEqual(len(msgs), 1)

    def test_cli_lists_lsp(self):
        p = subprocess.run([sys.executable, "-m", "sipar", "--help"], capture_output=True, text=True, cwd=ROOT,
                           env=dict(os.environ, PYTHONPATH=ROOT), timeout=60)
        self.assertEqual(p.returncode, 0)
        self.assertIn("lsp", p.stdout)
        for cmd in ("run", "check", "test", "replay", "trace", "spec"):
            self.assertIn(cmd, p.stdout)


# ====================================================================== VS Code extension files

VSC = os.path.join(ROOT, "editors", "vscode")


def onig_to_python(rx):
    """Map the few Oniguruma-only constructs the grammar uses to Python `re` syntax."""
    upper = "A-ZÀ-ÖØ-ÞА-ЯЁ"            # Python `re` has no \p{..}; these classes are close enough for a smoke test
    for onig, py in (("[\\p{L}\\p{N}_]", "\\w"), ("[\\p{L}_]", "[^\\W\\d]"), ("[\\p{Lu}\\p{N}_]", f"[{upper}0-9_]"),
                     ("\\p{Lu}", f"[{upper}]")):
        rx = rx.replace(onig, py)
    if "\\p{" in rx:
        raise AssertionError(f"unmapped Unicode property in {rx!r}")
    return rx


def grammar_rules(node, out):
    if isinstance(node, dict):
        for k in ("match", "begin", "end", "while"):
            if isinstance(node.get(k), str):
                out.append((k, node[k], node))
        for v in node.values():
            grammar_rules(v, out)
    elif isinstance(node, list):
        for v in node:
            grammar_rules(v, out)
    return out


class VSCode(unittest.TestCase):
    def load(self, *parts):
        with open(os.path.join(VSC, *parts), encoding="utf-8") as f:
            return json.load(f)

    def test_vscode_files_valid(self):
        pkg = self.load("package.json")
        lang = pkg["contributes"]["languages"][0]
        self.assertEqual(lang["id"], "sipar")
        self.assertEqual(lang["extensions"], [".sipar"])
        self.assertEqual(pkg["contributes"]["grammars"][0]["scopeName"], "source.sipar")
        self.assertEqual(pkg["contributes"]["configuration"]["properties"]["sipar.path"]["default"], "python3 -m sipar")
        self.assertEqual(pkg["main"], "./extension.js")
        self.assertIn("vscode-languageclient", pkg["dependencies"])
        conf = self.load("language-configuration.json")
        self.assertEqual(conf["comments"]["lineComment"], "//")
        self.assertIn(["{", "}"], conf["brackets"])
        self.assertIn({"open": "\"", "close": "\"", "notIn": ["string"]}, conf["autoClosingPairs"])
        self.assertIn({"open": "{", "close": "}"}, conf["autoClosingPairs"])
        g = self.load("syntaxes", "sipar.tmLanguage.json")
        self.assertEqual(g["scopeName"], "source.sipar")
        for inc in re.findall(r'"include":\s*"#([\w-]+)"', json.dumps(g)):
            self.assertIn(inc, g["repository"], inc)
        self.assertTrue(os.path.isfile(os.path.join(VSC, "extension.js")))
        self.assertTrue(os.path.isfile(os.path.join(VSC, "README.md")))

    def test_vscode_grammar_regexes(self):
        g = self.load("syntaxes", "sipar.tmLanguage.json")
        rules = grammar_rules(g, [])
        self.assertGreater(len(rules), 15)
        for kind, rx, _ in rules:
            if kind == "end" and re.search(r"\\\d", rx):
                continue                      # back-references to `begin` are resolved by the editor
            re.compile(onig_to_python(rx))

    def scopes(self, line):
        """Very small TextMate runner: top-level `match` rules and begin/end with their inner patterns."""
        g = self.load("syntaxes", "sipar.tmLanguage.json")
        repo = g["repository"]

        def expand(pats):
            out = []
            for p in pats:
                if "include" in p:
                    r = repo[p["include"][1:]]
                    out.extend([r] if ("match" in r or "begin" in r) else expand(r["patterns"]))
                else:
                    out.append(p)
            return out

        found = []

        def run(pats, text, pos, end_rx=None):
            pats = expand(pats)
            while pos < len(text):
                best = None
                if end_rx is not None:
                    m = re.compile(onig_to_python(end_rx)).search(text, pos)
                    if m:
                        best = (m.start(), -1, m, None)
                for i, p in enumerate(pats):
                    rx = p.get("match") or p.get("begin")
                    m = re.compile(onig_to_python(rx)).search(text, pos)
                    if m and (best is None or m.start() < best[0]):
                        best = (m.start(), i, m, p)
                if best is None:
                    return len(text)
                _, i, m, p = best
                if p is None:
                    return m.end()
                name = p.get("name")
                if name:
                    found.append((m.group(0), name))
                for gi, cap in (p.get("captures") or p.get("beginCaptures") or {}).items():
                    if m.group(int(gi)) is not None and "name" in cap:
                        found.append((m.group(int(gi)), cap["name"]))
                if "begin" in p:
                    pos = run(p.get("patterns", []), text, m.end(), p["end"])
                else:
                    pos = max(m.end(), pos + 1)
            return pos

        run(g["patterns"], line, 0)
        return found

    def test_vscode_grammar_smoke(self):
        def has(line, text, scope_part):
            got = self.scopes(line)
            self.assertTrue(any(t == text and scope_part in s for t, s in got), (line, text, scope_part, got))

        has("fn main() uses net {", "fn", "keyword")
        has("fn main() uses net {", "net", "capability")
        has('allow fs.write ["./out"]', "fs.write", "capability")
        has('allow fs.write ["./out"]', "allow", "keyword")
        has("let n = 1_000_000", "1_000_000", "constant.numeric")
        has("let f = 3.5e-2", "3.5e-2", "constant.numeric")
        has("// note", "// note", "comment.line")
        has("/// Adds two numbers.", "/// Adds two numbers.", "comment.line.documentation")
        has('print("hi {name} x")', "name", "variable")
        has('print("hi {name} x")', "{", "punctuation.section.interpolation")
        has('print("a\\n")', "\\n", "constant.character.escape")
        has('@model("gpt")', "model", "entity.name")
        has('@model("gpt")', "@", "punctuation")
        has("type Review = {", "Review", "entity.name.type")
        has("let x: List[Str] = []", "Str", "support.type")
        has("let ok = true", "true", "constant.language")
        has("agent fn helper(goal: Str) -> Str", "helper", "entity.name.function")
        has('    """', '"""', "string.quoted.triple")
        for rel in ("examples/tour.sipar", "examples/triage.sipar", "examples/injection/assistant.sipar"):
            with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
                for line in f:
                    self.scopes(line.rstrip("\n"))        # every line tokenizes without a regex error

    @unittest.skipUnless(shutil.which("node") and os.path.isdir(os.path.join(VSC, "node_modules", "vscode-textmate")),
                         "node or editors/vscode/node_modules missing (run npm install there)")
    def test_vscode_node_suites(self):
        """The real VS Code tokenizer (vscode-textmate) on the grammar, and extension.js under a stubbed vscode."""
        for script in ("test/grammar.test.js", "test/extension.test.js"):
            r = subprocess.run(["node", script], cwd=VSC, capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, script + "\n" + r.stdout + r.stderr)
            self.assertIn("all passed", r.stdout)


# ====================================================================== unit tests of the helpers

def mask_str(lines):
    return ["".join("CTMOXI"[v] for v in row) for row in lsp.text_mask(lines)]


class Units(unittest.TestCase):
    """Exact behaviour of the small helpers (written to kill mutation survivors)."""

    def test_lsp_enum_values_match_the_spec(self):
        self.assertEqual(lsp.SEV, {"error": 1, "warning": 2, "info": 3, "hint": 4})
        self.assertEqual(lsp.CK, {"method": 2, "function": 3, "field": 5, "variable": 6, "class": 7, "module": 9,
                                  "keyword": 14, "enum_member": 20, "constant": 21, "struct": 22, "enum": 13,
                                  "type_param": 25})
        self.assertEqual(lsp.SK, {"method": 6, "field": 8, "enum": 10, "function": 12, "constant": 14,
                                  "enum_member": 22, "struct": 23})
        self.assertEqual(len({lsp.CODE, lsp.TEXT, lsp.COMMENT, lsp.OPEN, lsp.CLOSE, lsp.INTERP}), 6)

    def test_text_mask_exact(self):
        cases = [
            (['"a{b}c" x // "q" {'], ["OTICTTXCCCMMMMMMMM"]),
            (['"x{ {y} }z"'], ["OTICCCCCTTX"]),
            (['"ab\\'], ["OTTT"]),
            (['"\\{x\\}" "\\"" k'], ["OTTTTTXCOTTXCC"]),
            (['p = """a', 'b"c{d}"e', 'f"""g'], ["CCCCOOOT", "TTTICTTT", "TXXXC"]),
            (['"abc', 'd "e"'], ["OTTT", "CCOTX"]),
            (['""""', 'h'], ["OOOT", "T"]),
            (['"{"{1}"}" w'], ["OIOICTXTXCC"]),
            (['x}"y"'], ["CCOTX"]),
            (['a // b', 'c'], ["CCMMMM", "C"]),
            (['"""a\\', '"""'], ["OOOTT", "XXX"]),
        ]
        for lines, want in cases:
            with self.subTest(lines=lines):
                self.assertEqual(mask_str(lines), want)

    def test_text_mask_open_interpolation_ends_at_the_line(self):
        # bug: an unclosed `{` in a "..." string kept the rest of the file "inside the interpolation", so a later
        # `}` was marked as string text and hover / completion went silent there
        self.assertEqual(mask_str(['x = "a{b', 'c "d"', '} z']), ["CCCCOTIC", "CCOTX", "CCC"])
        # a triple-quoted string may hold a multi-line interpolation: that one stays open
        self.assertEqual(mask_str(['"""a{', 'b}c"""']), ["OOOTI", "CTTXXX"])

    def test_utf16_to_cp_edges(self):
        self.assertEqual(lsp.utf16_to_cp("ab", 0), 0)
        self.assertEqual(lsp.utf16_to_cp("ab", 1), 1)
        self.assertEqual(lsp.utf16_to_cp("ab", 2), 2)
        self.assertEqual(lsp.utf16_to_cp("ab", 9), 2)
        self.assertEqual(lsp.utf16_to_cp("\U0001F600b", 1), 0)     # inside the pair -> start of the emoji
        self.assertEqual(lsp.utf16_to_cp("\U0001F600b", 2), 1)
        self.assertEqual(lsp.utf16_to_cp("\uffffb", 1), 1)         # U+FFFF is one unit
        self.assertEqual(lsp.cp_to_utf16("a\U0001F600b", 2), 3)
        self.assertEqual(lsp.cp_to_utf16("ab", -3), 0)
        self.assertEqual(lsp.cp_to_utf16("ab", 7), 2)

    def test_line_starts(self):
        self.assertEqual(lsp.line_starts(""), [0])
        self.assertEqual(lsp.line_starts("a\nb"), [0, 2])
        self.assertEqual(lsp.line_starts("a\r\nb"), [0, 3])
        self.assertEqual(lsp.line_starts("a\rb"), [0, 2])
        self.assertEqual(lsp.line_starts("a\r"), [0, 2])
        self.assertEqual(lsp.line_starts("\r\n\n\r"), [0, 2, 3, 4])

    def test_offset_at(self):
        t = "ab\r\ncd\nef"
        st = lsp.line_starts(t)
        self.assertEqual(lsp.offset_at(t, st, {"line": 0, "character": 9}), 2)      # clamps before the \r\n
        self.assertEqual(lsp.offset_at(t, st, {"line": 1, "character": 1}), 5)
        self.assertEqual(lsp.offset_at(t, st, {"line": 2, "character": 2}), 9)
        self.assertEqual(lsp.offset_at(t, st, {"line": 2, "character": 5}), 9)
        self.assertEqual(lsp.offset_at(t, st, {"line": 3, "character": 0}), 9)      # past the last line
        self.assertEqual(lsp.offset_at(t, st, {"line": -1, "character": 4}), 0)
        for pos in ({}, {"line": 1}, {"character": 0}):       # round 7: missing parts are errors, not 0
            with self.assertRaises(lsp.ParamsError):
                lsp.offset_at(t, st, pos)

    def test_apply_change(self):
        t = "ab\ncd"
        rng = lambda a, b, c, d: {"start": {"line": a, "character": b}, "end": {"line": c, "character": d}}
        self.assertEqual(lsp.apply_change(t, {"text": "X"}), "X")
        self.assertEqual(lsp.apply_change(t, {"range": None, "text": "X"}), "X")
        self.assertEqual(lsp.apply_change(t, {"range": rng(0, 1, 1, 1), "text": "X"}), "aXd")
        self.assertEqual(lsp.apply_change(t, {"range": rng(1, 1, 0, 1), "text": "X"}), "aXd")   # reversed
        self.assertEqual(lsp.apply_change(t, {"range": rng(1, 2, 1, 2), "text": "!"}), "ab\ncd!")

    def test_word_at_and_dot_before(self):
        self.assertEqual(lsp.word_at("ab cd", 0), (0, 2))
        self.assertEqual(lsp.word_at("ab cd", 2), (0, 2))       # just after a word
        self.assertEqual(lsp.word_at("ab cd", 3), (3, 5))
        self.assertEqual(lsp.word_at("ab cd", 5), (3, 5))
        self.assertIsNone(lsp.word_at("a  b", 2))
        self.assertIsNone(lsp.word_at("", 0))
        self.assertIsNone(lsp.word_at(" a", 0))
        self.assertIsNone(lsp.word_at("a", 7))
        self.assertEqual(lsp.word_at("x_1.y", 1), (0, 3))
        self.assertEqual(lsp.dot_before("a.b", 2), 1)
        self.assertEqual(lsp.dot_before("a . b", 4), 2)
        self.assertEqual(lsp.dot_before("a.\tb", 3), 1)
        self.assertIsNone(lsp.dot_before("a..b", 3))
        self.assertEqual(lsp.dot_before(".b", 1), 0)
        self.assertIsNone(lsp.dot_before("b", 0))
        self.assertIsNone(lsp.dot_before("a b", 2))

    def test_need(self):
        self.assertEqual(lsp.need({"a": {"b": 3}}, "a", "b"), 3)
        with self.assertRaises(lsp.ParamsError) as cm:
            lsp.need({"a": 1}, "a", "b")
        self.assertEqual(str(cm.exception), "missing params.a.b")
        with self.assertRaises(lsp.ParamsError):
            lsp.need(None, "a")

    def test_log_flushes_and_survives_a_broken_stream(self):
        class S(io.StringIO):
            flushed = 0

            def flush(self):
                S.flushed += 1
        s = S()
        lsp.log(s, "m")
        self.assertEqual((s.getvalue(), S.flushed), ("sipar lsp: m\n", 1))

        class Broken:
            def write(self, _):
                raise OSError("closed")
        lsp.log(Broken(), "m")          # no exception


def analyse(text, err=None):
    return lsp.Analysis(text, "/t/a.sipar", err if err is not None else io.StringIO())


SCOPES = '''allow ai
type Pair = { a: Int, b: Int }
enum Res { ok(a: Int, b: Str), bad }
let K = 2

ai fn judge(code: Str, mode: Str) -> Int {
    """
    Score {code} in {mode} mode.
    """
}

fn twice(h: fn(Int) -> Int, n: Int) -> Int { h(h(n)) }

fn main() {
    let q = 5
    let lam = "{twice(fn(q: Int) -> Int => q + K, q)}"
    let r = Res.ok(a: 1, b: "x")
    let pr = Pair { b: 2, a: q }
    print(lam)
}

test "judge mock" {
    mock judge(code, mode) => code.len() + mode.len()
    assert judge("ab", "c") == 3, "mocked"
}
'''


class AnalysisUnits(unittest.TestCase):
    def test_examples_analyse_without_logging(self):
        # every analysis step runs inside try/except; a silent exception would only show in this log
        files = []
        for base, _, names in os.walk(os.path.join(ROOT, "examples")):
            files += [os.path.join(base, n) for n in names if n.endswith(".sipar")]
        self.assertGreaterEqual(len(files), 3)
        for path in files + ["<SRC>", "<SCOPES>"]:
            if path.startswith("<"):
                text = SRC if path == "<SRC>" else SCOPES
            else:
                with open(path, encoding="utf-8") as fh:
                    text = fh.read()
            err = io.StringIO()
            a = analyse(text, err)
            with self.subTest(path=path):
                self.assertEqual(err.getvalue(), "")
                self.assertTrue(a.ok)
                self.assertTrue(a.toks and a.bindings and a.types)

    def test_scopes_matrix(self):
        s = Session(SCOPES)
        self.assertEqual(s.open(SCOPES), [])
        d = s.definition
        self.assertEqual(d("{code} in", offset=1), at(SCOPES, "code: Str"))     # ai fn prompt -> its param
        self.assertEqual(d("{mode} mode", offset=1), at(SCOPES, "mode: Str"))
        self.assertEqual(d("=> q + K", offset=3), at(SCOPES, "q: Int"))          # lambda inside interpolation
        self.assertEqual(d("+ K", offset=2), at(SCOPES, "K = 2"))
        self.assertEqual(d("K, q)", offset=3), at(SCOPES, "q = 5"))              # after the lambda's comma
        self.assertEqual(d("a: 1"), at(SCOPES, "a: Int, b: Str"))                # enum variant fields, in order
        self.assertEqual(d('b: "x"'), at(SCOPES, "b: Str"))
        self.assertEqual(d("b: 2"), at(SCOPES, "b: Int }"))                      # record fields, in order
        self.assertEqual(d("a: q"), at(SCOPES, "a: Int, b: Int"))
        self.assertEqual(d("a: q", offset=3), at(SCOPES, "q = 5"))
        self.assertEqual(d("code.len"), at(SCOPES, "code, mode"))                # mock params
        self.assertEqual(d("mode.len"), at(SCOPES, "mode) =>"))
        self.assertEqual(d('judge("ab'), at(SCOPES, "judge(code"))
        self.assertEqual(d("h(n)", offset=2), at(SCOPES, "n: Int)"))
        self.assertEqual(d("print(lam", offset=6), at(SCOPES, "lam ="))

    def test_steps_fail_independently(self):
        for step in ("_scan_tokens", "_record", "_walk"):
            err = io.StringIO()
            def boom(self):
                raise RuntimeError("x")
            boom.__name__ = step
            with mock.patch.object(lsp.Analysis, step, boom):
                a = analyse(SRC, err)
            with self.subTest(step=step):
                self.assertIn(f"analysis step {step} failed", err.getvalue())
                self.assertTrue(a.ok)
                if step != "_scan_tokens":
                    self.assertTrue(a.toks)
                if step != "_record":
                    self.assertTrue(a.types)
                if step != "_walk":
                    self.assertTrue(a.bindings)

    def test_checker_and_parser_both_crash(self):
        err = io.StringIO()
        with mock.patch("sipar.checker.check_source", side_effect=RuntimeError("c")), \
                mock.patch("sipar.parser.parse", side_effect=RuntimeError("p")):
            a = analyse(SRC, err)
        self.assertFalse(a.ok)
        self.assertEqual(a.crash, "RuntimeError: c")
        self.assertIn("checker crashed on /t/a.sipar", err.getvalue())
        self.assertEqual(a.bindings, [])
        self.assertEqual(lsp.diagnostics_for(a)[-1]["severity"], 2)

    def test_positions(self):
        a = analyse("ab\n\U0001F600c")
        self.assertEqual(a.lsp_pos((1, 1)), {"line": 0, "character": 0})
        self.assertEqual(a.lsp_pos((2, 2)), {"line": 1, "character": 2})
        self.assertEqual(a.lsp_pos((9, 1)), {"line": 1, "character": 3})          # past the end: clamps
        self.assertEqual(a.lsp_pos((0, 1)), {"line": 0, "character": 0})
        self.assertEqual(a.lsp_pos((1, 0)), {"line": 0, "character": 0})
        with self.assertRaises(lsp.ParamsError):          # round 7: a missing line/character is an error
            a.sipar_pos({})
        self.assertEqual(a.sipar_pos({"line": 1, "character": 2}), (2, 2))
        self.assertEqual(a.sipar_pos({"line": 1, "character": 1}), (2, 1))
        self.assertEqual(a.sipar_pos({"line": 7, "character": 3}), (8, 1))
        self.assertEqual((a.line_text(0), a.line_text(1), a.line_text(2), a.line_text(3)), ("", "ab", "\U0001F600c", ""))
        self.assertEqual(a.name_range((2, 2), "c"), {"start": {"line": 1, "character": 2},
                                                     "end": {"line": 1, "character": 3}})

    def test_token_helpers(self):
        text = 'fn main() {\n    let p = f([1, (2)], g(3))\n    let r = P { a: 1, b: a }\n}\n'
        a = analyse(text)
        self.assertTrue(a.toks)
        self.assertEqual(a.tok_pos, sorted(a.tok_pos))
        self.assertEqual(a.record_keys((3, 1)), {"a": (3, 17), "b": (3, 23)})     # `b: a`: a is a value
        b = analyse("let Z = 1\nlet W = Z")
        self.assertEqual(b.toks[-1].value, "Z")
        t = a.tok_after((2, 13), "ident", "f")
        self.assertEqual((t.line, t.col), (2, 13))
        self.assertIsNone(a.tok_after((2, 13), "ident", "f", strict=True))
        self.assertEqual(a.name_after((2, 13), "f"), (2, 13))   # strictly after: not found -> the given pos
        self.assertEqual(a.name_after((2, 12), "f"), (2, 13))
        # brackets on line 2: f( 14..29, [ 15..22, ( 19..21, g( 26..28; main's { is 1:11..4:1
        self.assertEqual(a.enclosing_close((2, 16)), (2, 22))      # innermost: the [ ] list
        self.assertEqual(a.enclosing_close((2, 20)), (2, 21))
        self.assertEqual(a.enclosing_close((2, 15)), (2, 29))      # on the `[` itself: the f( ... ) around it
        self.assertEqual(a.enclosing_close((2, 22)), (2, 29))      # on the `]` itself
        self.assertEqual(a.enclosing_close((2, 14)), (4, 1))
        self.assertEqual(a.enclosing_close((5, 1)), lsp.EOF_POS)

    def test_lambda_end(self):
        text = ('fn g(h: fn(Int) -> Int, n: Int) -> Int { h(n) }\n'
                'fn main() {\n'
                '    let a = g(fn(x: Int) -> Int => [x, (x)][0], 2)\n'
                '    let b = g(fn(x: Int) -> Int => x)\n'
                '    print(a + b)\n'
                '}\n')
        a = analyse(text)
        line3 = text.split("\n")[2]
        line4 = text.split("\n")[3]
        start3 = (3, line3.index("fn(") + 1)
        self.assertEqual(a.lambda_end(start3), (3, line3.index(", 2)") + 1))
        start4 = (4, line4.index("fn(") + 1)
        self.assertEqual(a.lambda_end(start4), (4, line4.rindex(")") + 1))
        a.limit = (3, line3.index("[x") + 1)
        self.assertEqual(a.lambda_end(start3), a.limit)
        a.limit = (5, 1)
        self.assertEqual(a.lambda_end((5, 5)), (5, 1))                 # no `=>` after: the limit
        a.limit = lsp.EOF_POS
        self.assertEqual(a.lambda_end((5, 5)), a.enclosing_close((5, 5)))
        self.assertEqual(a.lambda_end((6, 2)), lsp.EOF_POS)

    def test_resolve_and_visible(self):
        text = 'fn main() {\n    let v = 1\n    let v = v + 1\n    print(v)\n}\n'
        a = analyse(text)
        lets = [b for b in a.bindings if b.name == "v"]
        self.assertEqual(len(lets), 2)
        self.assertIs(a.resolve("v", (3, 13)), lets[0])           # the right side sees the old v
        self.assertIs(a.resolve("v", (4, 11)), lets[1])
        self.assertIs(a.resolve("v", lets[1].scope[0]), lets[1])  # scope edges are inclusive
        self.assertIs(a.resolve("v", lets[1].scope[1]), lets[1])
        self.assertIsNone(a.resolve("v", (5, 2)))
        self.assertIsNone(a.resolve("v", (2, 5)))
        self.assertIs(a.resolve("main", (2, 5)), a.global_binding("main"))
        self.assertEqual([b.name for b in a.visible((4, 11))], ["v"])
        self.assertIs(a.visible((4, 11))[0], lets[1])
        self.assertEqual(a.visible((5, 2)), [])
        self.assertTrue(a.is_local("v", (4, 11)))
        self.assertFalse(a.is_local("main", (4, 11)))
        self.assertFalse(a.is_local("nope", (4, 11)))
        self.assertIsNone(a.global_binding("main", ("const",)))


RENDER = '''allow ai
allow net ["a.com"]
allow fs.read ["./data"]
type Empty = {}
type Opt = { f: fn(Int, Str) -> Int, g: (fn(Int) -> Int)?, h: Int?, m: Map[List[Str]] }

@model("mock") @temperature(0.5)
ai fn pick(x: Str) -> Bool {
    """
    {x}
    """
}

fn main() uses net, fs.read {
    let yes = true
    let nothing: Str? = none
    print(fs.read("./data/x"))
    print(http.get("https://a.com"))
    print("{yes} {nothing}")
}
'''


class Rendering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = Session(RENDER)
        cls.a = analyse(RENDER)

    def test_render_document_is_clean(self):
        self.assertEqual(Session(RENDER).open(RENDER), [])

    def test_type_texts(self):
        opt = self.a.global_binding("Opt").node
        self.assertEqual(lsp.type_decl_text(opt),
                         "type Opt = { f: fn(Int, Str) -> Int, g: (fn(Int) -> Int)?, h: Int?, m: Map[List[Str]] }")
        self.assertEqual(lsp.type_decl_text(self.a.global_binding("Empty").node), "type Empty = {}")
        self.assertEqual(lsp.texpr(None), "None")
        self.assertIn("(field) Opt.g: (fn(Int) -> Int)?", self.s.hover("g: (fn"))

    def test_enum_text_wraps_after_80_characters(self):
        for n, multi in ((69, False), (70, True)):
            text = "enum E { %s }\nfn main() { print(1) }\n" % ("a" * n)
            e = analyse(text).global_binding("E").node
            one = "enum E { %s }" % ("a" * n)
            self.assertEqual(len(one), 11 + n)
            self.assertEqual(lsp.type_decl_text(e), "enum E {\n    %s,\n}" % ("a" * n) if multi else one)

    def test_literals(self):
        self.assertEqual(lsp.lit(lsp.A.BoolLit(1, 1, True)), "true")
        self.assertEqual(lsp.lit(lsp.A.BoolLit(1, 1, False)), "false")
        self.assertEqual(lsp.lit(lsp.A.StrLit(1, 1, ["é", lsp.A.BoolLit(1, 1, True), "\""])), '"é\\""')
        self.assertEqual(lsp.lit(lsp.A.FloatLit(1, 1, 0.5)), "0.5")
        md = self.s.hover("pick(x")
        self.assertIn('@model("mock") @temperature(0.5)\nai fn pick(x: Str) -> Bool', md)

    def test_stdlib_docs(self):
        get = lsp.stdlib_doc("http.get").split("\n\n")
        self.assertEqual(get[-3:], ["Optional named argument(s): `headers`.", "Result is untrusted (`untrusted:net`).",
                                    "Untrusted data is rejected in: `url`, `headers`."])
        self.assertEqual(lsp.stdlib_doc("env.secret").split("\n\n")[-1], "Result is a secret (`secret:NAME`).")
        rd = lsp.stdlib_doc("fs.read")
        self.assertTrue(rd.endswith("Result is untrusted (`untrusted:file`)."), rd)
        self.assertNotIn("rejected", rd)
        self.assertNotIn("secret", rd)
        self.assertNotIn("untrusted", lsp.stdlib_doc("print"))

    def test_keyword_and_builtin_hovers(self):
        self.assertEqual(self.s.hover("true"), "```sipar\nBool\n```")
        self.assertEqual(self.s.hover("none"), "```sipar\nNone\n```")
        self.assertIsNone(self.s.hover("let yes"))
        for t, doc in lsp.BUILTIN_TYPE_DOCS.items():
            self.assertEqual(lsp.describe(self.a, lsp.Target("builtin_type", name=t)), f"```sipar\ntype {t}\n```\n\n{doc}")
        self.assertIn("true or false", lsp.BUILTIN_TYPE_DOCS["Bool"])
        self.assertTrue(lsp.BUILTIN_TYPE_DOCS["List"].startswith("List[T]"))
        self.assertTrue(lsp.BUILTIN_TYPE_DOCS["Map"].startswith("Map[T]"))
        self.assertIn("catch e", lsp.BUILTIN_TYPE_DOCS["Error"])

    def test_capability_spans(self):
        line = RENDER.split("\n").index("allow fs.read [\"./data\"]")
        for ch in (6, 8, 9, 12, 13):
            t, span = lsp.classify(self.a, line + 1, ch)
            self.assertEqual((t.kind, t.name, span), ("capability", "fs.read", (6, 13)), ch)
        uses = RENDER.split("\n").index("fn main() uses net, fs.read {") + 1
        text = self.a.line_text(uses)
        t, span = lsp.classify(self.a, uses, text.index("read"))
        self.assertEqual((t.kind, t.name, span), ("capability", "fs.read", (20, 27)))
        t, span = lsp.classify(self.a, uses, text.index("net"))
        self.assertEqual((t.kind, t.name, span), ("capability", "net", (15, 18)))
        call = RENDER.split("\n").index('    print(fs.read("./data/x"))') + 1
        t, _ = lsp.classify(self.a, call, 14)
        self.assertEqual((t.kind, t.name), ("stdlib", "fs.read"))           # a call, not a capability
        self.assertEqual(lsp._capability_at("net", 0, 3), None)            # no `allow` / `uses` before it
        self.assertEqual(lsp._capability_at("allow net.", 6, 9), ("net", (6, 9)))   # trailing dot not taken
        self.assertEqual(lsp._capability_at("allow fs.read", 9, 13), ("fs.read", (6, 13)))
        self.assertEqual(lsp._capability_at("allow fs.read", 6, 8), ("fs.read", (6, 13)))

    def test_attribute_hover(self):
        md = self.s.hover("temperature")
        self.assertIn("Attribute of ai fn and agent fn.", md)
        md = lsp.describe(self.a, lsp.Target("attribute", name="max_steps"))
        self.assertIn("Attribute of agent fn.", md)
        md = lsp.describe(self.a, lsp.Target("capability", name="ai"))
        self.assertIn("Needed by every `ai fn` and `agent fn` call.", md)
        md = lsp.describe(self.a, lsp.Target("capability", name="net"))
        self.assertIn("Needed by: `http.get`, `http.post`.", md)

    def test_diagnostics_ranges(self):
        D = lsp.dataclasses.make_dataclass("D", ["line", "col", "message", "hint", "severity", "code"])
        a = analyse("ab cd\nx+")
        cases = [
            (D(0, 0, "m", "", "info", "E1"), (0, 0, 0, 2), 3),          # line/col 0 clamp to 1:1, word span
            (D(1, 4, "m", "h", "hint", "E2"), (0, 3, 0, 5), 4),         # word at the end of the line
            (D(1, 3, "m", None, "warning", "E3"), (0, 2, 0, 3), 2),     # a space: one character
            (D(2, 2, "m", None, "error", "E4"), (1, 1, 1, 2), 1),       # punctuation: one character
            (D(2, 3, "m", None, "odd", "E5"), (1, 2, 1, 2), 1),         # past the line end: empty
            (D(9, 9, "m", None, "error", "E6"), (1, 2, 1, 2), 1),       # past the last line
            (D(2, 1, "m", None, "error", "E7"), (1, 0, 1, 1), 1),       # x is a word of one
        ]
        for d, (l1, c1, l2, c2), sev in cases:
            a.diags = [d]
            a.crash = None
            out = lsp.diagnostics_for(a)
            self.assertEqual(out, [{"range": {"start": {"line": l1, "character": c1}, "end": {"line": l2, "character": c2}},
                                    "severity": sev, "code": d.code, "source": "sipar",
                                    "message": "m" + ("\nhint: h" if d.hint else "")}], d)
        a.diags = []
        a.crash = "KeyError: 'k'"
        self.assertEqual(lsp.diagnostics_for(a), [{
            "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 0}}, "severity": 2,
            "source": "sipar", "message": "the sipar checker crashed (KeyError: 'k'); diagnostics may be incomplete"}])


NESTED_REC = '''type In = { b: Int }
type Out = { inner: In, b: Int }
fn main() {
    let o = Out { inner: In { b: 1 }, b: 2 }
    let f = Out { inner: In { b: [In { b: 3 }].len() }, b: (4) }
    print(o.b + f.b)
}
'''


class RecordKeys(unittest.TestCase):
    def test_nested_record_with_the_same_key(self):
        # bug: the outer `b: 2` was matched to the inner `In { b: 1 }` key, so it had no hover/definition
        s = Session(NESTED_REC)
        self.assertEqual(s.open(NESTED_REC), [])
        self.assertEqual(s.definition("b: 1"), at(NESTED_REC, "b: Int }"))
        self.assertEqual(s.definition("b: 2"), at(NESTED_REC, "b: Int }", 1))
        self.assertEqual(s.definition("b: 3"), at(NESTED_REC, "b: Int }"))
        self.assertEqual(s.definition("b: (4)"), at(NESTED_REC, "b: Int }", 1))
        self.assertEqual(s.definition("inner: In {"), at(NESTED_REC, "inner: In,"))
        self.assertIn("b: Int", s.hover("b: 2"))

    def test_record_keys_helper(self):
        a = analyse(NESTED_REC)
        self.assertEqual(a.record_keys((4, 13)), {"inner": (4, 19), "b": (4, 39)})
        self.assertEqual(a.record_keys((4, 26)), {"b": (4, 31)})
        self.assertEqual(a.record_keys((7, 1)), {})                    # `}` then nothing: no `{` after
        self.assertEqual(analyse("let W = Z").record_keys((1, 1)), {})
        u = analyse("fn main() {\n    let r = P { a: 1, b: a }\n}\n")
        self.assertEqual(u.record_keys((2, 13)), {"a": (2, 17), "b": (2, 23)})
        del u.brackets[(2, 15)]                                         # no matching `}`: scan to the end
        self.assertEqual(u.record_keys((2, 13)), {"a": (2, 17), "b": (2, 23)})
        self.assertEqual(analyse("let r = P { a").record_keys((1, 9)), {})   # a parse error: no tokens


def stub_doc(analysis, last_good=None, text=""):
    return types.SimpleNamespace(analysis=analysis, last_good=last_good, text=text, path="/t/a.sipar",
                                 err=io.StringIO())


MEM_LIST = "fn main() {\n    let xs = [1]\n    xs.len()\n}\n"
MEM_PRINT = "fn main() {\n    let xs = [1]\n    print(1)\n}\n"
MEM_STR = 'fn main() {\n    let xs = "a"\n    print(1)\n}\n'
MEM_NONE = "fn main() {\n    print(1)\n}\n"


class Members(unittest.TestCase):
    def labels_of(self, doc, before="    xs.", partial="l", line=3):
        return labels(lsp._members(doc, line, len(before), before, partial))

    def test_last_good_is_tried_when_the_current_analysis_knows_nothing(self):
        got = self.labels_of(stub_doc(analyse(MEM_NONE), analyse(MEM_LIST)))
        self.assertIn("push", got)

    def test_nothing_known_gives_no_items(self):
        self.assertEqual(self.labels_of(stub_doc(analyse("fn ("))), [])
        self.assertEqual(self.labels_of(stub_doc(analyse(MEM_NONE))), [])
        self.assertEqual(self.labels_of(stub_doc(analyse("fn ("), analyse(MEM_NONE))), [])

    def test_the_first_analysis_that_knows_the_type_wins(self):
        got = self.labels_of(stub_doc(analyse(MEM_PRINT), analyse(MEM_STR)))      # local decl type path
        self.assertIn("push", got)
        self.assertNotIn("upper", got)
        got = self.labels_of(stub_doc(analyse(MEM_STR), analyse(MEM_LIST)))
        self.assertIn("upper", got)
        self.assertNotIn("push", got)
        got = self.labels_of(stub_doc(analyse(MEM_LIST), analyse(MEM_STR)))       # field type path
        self.assertIn("push", got)
        self.assertNotIn("upper", got)

    def test_space_before_the_dot(self):
        text = "fn main() {\n    let xs = [1]\n    xs .len()\n}\n"
        self.assertIn("push", self.labels_of(stub_doc(analyse(text)), before="    xs ."))

    def test_module_members_keep_the_full_name_after_the_dot(self):
        got = lsp._members(stub_doc(analyse(MEM_NONE)), 2, 7, "    fs.", "r")
        self.assertIn("read", labels(got))
        self.assertTrue(all("." not in i["label"] for i in got))
        self.assertIn("fn fs.read(path: Str) -> Str uses fs.read", [i["detail"] for i in got])


GEN = '''type P = { a: Int }
let K = 1
@model("mock")
ai fn helper(x: Str) -> Int {
    """
    {x}
    """
}
fn main() {
    let xs = [1]
    print(xs)
}
'''


class General(unittest.TestCase):
    def test_sort_order_and_kinds(self):
        a = analyse(GEN)
        items = {i["label"]: i for i in lsp._general(a, (11, 5))}
        sorts = {k: items[k]["sortText"] for k in ("xs", "helper", "K", "P", "print", "http", "Int", "let")}
        self.assertEqual(sorts, {"xs": "1xs", "helper": "2helper", "K": "2K", "P": "3P", "print": "4print",
                                 "http": "4http", "Int": "6Int", "let": "9let"})
        self.assertEqual(items["helper"]["detail"], "ai fn helper(x: Str) -> Int")
        self.assertNotIn("documentation", items["helper"])
        self.assertNotIn("documentation", items["K"])
        self.assertEqual(items["K"]["detail"], "Int")
        self.assertEqual(items["xs"]["detail"], "List[Int]")
        self.assertEqual(items["http"]["detail"], "module http")
        self.assertEqual(items["P"]["kind"], lsp.CK["struct"])

    def test_a_local_hides_a_global_of_the_same_name(self):
        text = "type P = { a: Int }\nfn main() {\n    let P = 1\n    let http = 2\n    let Int = 3\n    print(P)\n}\n"
        a = analyse(text)
        got = labels(lsp._general(a, (6, 5)))
        for name in ("P", "http", "Int"):
            self.assertEqual(got.count(name), 1, name)
        items = {i["label"]: i for i in lsp._general(a, (6, 5))}
        self.assertEqual(items["P"]["sortText"], "1P")
        self.assertEqual(items["http"]["sortText"], "1http")

    def test_a_broken_document_gives_keywords_and_stdlib(self):
        got = lsp._general(analyse("fn ("), (1, 1))
        self.assertIn("print", labels(got))
        self.assertIn("let", labels(got))

    def test_item_fields(self):
        self.assertEqual(lsp._item("len", "method"), {"label": "len", "kind": lsp.CK["method"], "sortText": "5len"})
        d = lsp._item("x", "field", "Int", "doc", "1", {"r": 1})
        self.assertEqual(d["documentation"], {"kind": "markdown", "value": "doc"})
        self.assertEqual(d["textEdit"], {"range": {"r": 1}, "newText": "x"})


SYMS = '''type P = { a: Int, bb: Str }
enum E { one(x: Int), two }
let K = 1
fn f(a: Int) -> Int {
    a
}
test "t" {
    assert f(1) == 1, "x"
}
'''


def rng(l1, c1, l2, c2):
    return {"start": {"line": l1, "character": c1}, "end": {"line": l2, "character": c2}}


class SymbolRanges(unittest.TestCase):
    def test_exact_ranges(self):
        out = lsp.symbols(analyse(SYMS))
        by = {s["name"]: s for s in out}
        self.assertEqual(by["P"]["range"], rng(0, 0, 0, 28))
        self.assertEqual(by["P"]["selectionRange"], rng(0, 5, 0, 6))
        self.assertEqual([(k["name"], k["range"], k["detail"]) for k in by["P"]["children"]],
                         [("a", rng(0, 11, 0, 12), "Int"), ("bb", rng(0, 19, 0, 21), "Str")])
        self.assertEqual(by["E"]["range"], rng(1, 0, 1, 27))
        self.assertEqual([(k["name"], k["range"], k.get("detail")) for k in by["E"]["children"]],
                         [("one", rng(1, 9, 1, 12), "one(x: Int)"), ("two", rng(1, 22, 1, 25), None)])
        self.assertEqual(by["K"]["range"], rng(2, 0, 2, 9))
        self.assertEqual(by["K"]["detail"], "Int")
        self.assertEqual(by["f"]["range"], rng(3, 0, 5, 1))
        self.assertEqual(by["f"]["detail"], "fn f(a: Int) -> Int")
        self.assertEqual(by['test "t"']["range"], rng(6, 0, 8, 1))
        self.assertEqual(by['test "t"']["selectionRange"], rng(6, 0, 6, 4))
        self.assertNotIn("children", by["K"])
        self.assertNotIn("detail", by['test "t"'])

    def test_without_tokens_ends_fall_back_to_the_line_end(self):
        def boom(self):
            raise RuntimeError("boom")
        with mock.patch.object(lsp.Analysis, "_scan_tokens", boom):
            a = analyse(SYMS)
        by = {s["name"]: s for s in lsp.symbols(a)}
        self.assertEqual(by["f"]["range"], rng(3, 0, 3, 21))
        self.assertEqual(by["P"]["range"], rng(0, 0, 0, 28))
        self.assertEqual(by['test "t"']["range"], rng(6, 0, 6, 10))


NAMED = '''fn add(a: Int, b: Int) -> Int { a + b }
fn other(b: Int) -> Int { b }
fn main() {
    print(add(b: 1, a: 2))
    let g = fn(b: Int) -> Int => b
    print(g(b: 3))
}
'''

LOOPS = '''fn main() {
    for c in "ab".lines() {
        let d = c
        print(d)
    }
    let late = 1
    print(late)
}
'''

ARMS = '''enum E { a, b }
fn main() {
    let e = E.a
    match e {
        E.a => print(1),
        E.b => print(false),
    }
}
'''


class WalkUnits(unittest.TestCase):
    def test_named_args_go_to_the_called_fn(self):
        s = Session(NAMED)
        self.assertEqual(s.definition("b: 1"), at(NAMED, "b: Int)"))      # add's b, not other's b
        self.assertEqual(s.definition("a: 2"), at(NAMED, "a: Int"))
        self.assertIsNone(s.definition("b: 3"))                             # a lambda callee: no declaration
        a = analyse(NAMED)
        self.assertEqual(sorted((k, v[0], v[2]) for k, v in a.refs.items()),
                         [((4, 15), "arg", "b"), ((4, 21), "arg", "a"), ((6, 13), "arg", "b")])

    def test_a_top_level_lambda_does_not_hide_later_globals(self):
        text = "let F = fn(x: Int) -> Int => x + 1\nlet x = 3\nfn main() { print(x) }\n"
        s = Session(text)
        self.assertEqual(s.definition("x)"), at(text, "x = 3"))
        self.assertEqual(s.definition("x + 1"), at(text, "x: Int"))
        a = analyse(text)
        self.assertEqual(a.resolve("x", (3, 19)).kind, "const")
        self.assertEqual(a.resolve("x", (1, 30)).kind, "param")
        self.assertEqual(a.limit, lsp.EOF_POS)                              # restored after the walk

    def test_variant_fields_are_bound_at_their_own_position(self):
        a = analyse("enum R { val(val: Int) }\n")
        self.assertEqual([(b.name, b.kind, b.pos, b.owner) for b in a.bindings],
                         [("R", "enum", (1, 6), ""), ("val", "variant", (1, 10), "R"),
                          ("val", "field", (1, 14), "R.val")])
        a = analyse("enum E { a(b: Int), b(b: Str) }\n")
        self.assertEqual([(b.name, b.kind, b.pos, b.owner) for b in a.bindings],
                         [("E", "enum", (1, 6), ""), ("a", "variant", (1, 10), "E"), ("b", "field", (1, 12), "E.a"),
                          ("b", "variant", (1, 21), "E"), ("b", "field", (1, 23), "E.b")])

    def test_loops_and_statement_scopes(self):
        s = Session(LOOPS)
        self.assertIn("lines", s.hover("lines"))
        self.assertEqual(s.definition("d)"), at(LOOPS, "d = c"))
        self.assertEqual(s.definition("c\n"), at(LOOPS, "c in"))
        self.assertEqual(s.definition("late)"), at(LOOPS, "late = 1"))
        a = analyse(LOOPS)
        self.assertIsNone(a.resolve("late", (6, 9)))         # a let is visible from the next statement on
        self.assertIsNone(a.resolve("late", (4, 15)))
        self.assertEqual(a.resolve("late", (7, 11)).kind, "let")
        self.assertIsNone(a.resolve("d", (3, 13)))

    def test_mock_body_and_prompt_interpolation(self):
        s = Session(SCOPES)
        self.assertIn("len", s.hover("len() + mode"))
        self.assertIn("code: Str", s.hover("{code} in", offset=1))

    def test_match_arm_patterns_and_literals(self):
        s = Session(ARMS)
        self.assertEqual(s.definition("a =>"), at(ARMS, "a, b"))
        self.assertEqual(s.definition("b =>"), at(ARMS, "b }"))
        self.assertIn("Bool", s.hover("false"))

    def test_definition_with_the_cursor_just_after_a_word(self):
        s = Session(SCOPES)
        self.assertEqual(s.definition("lam)", offset=3), at(SCOPES, "lam = "))


class AnalysisEdges(unittest.TestCase):
    def test_lambda_end_without_tokens(self):
        self.assertEqual(analyse("fn (").lambda_end((1, 1)), lsp.EOF_POS)

    def test_without_the_record_step_every_lookup_still_answers(self):
        def boom(self):
            raise RuntimeError("boom")
        err = io.StringIO()
        with mock.patch.object(lsp.Analysis, "_record", boom):
            a = analyse(SRC, err)
        self.assertIn("analysis step boom failed", err.getvalue())
        for b in a.bindings:
            if b.scope is None:
                self.assertIsInstance(lsp.describe(a, lsp.Target("binding", b, b.name)), str)
        for t in a.toks:
            lsp.classify(a, t.line, t.col - 1)

    def test_text_mask_escape_at_the_end_and_triple_interpolation(self):
        self.assertEqual(mask_str(['"a\\']), ["OTT"])
        self.assertEqual(mask_str(['"a\\b"']), ["OTTTX"])
        self.assertEqual(mask_str(['"""a{"b"}', '"""']), ["OOOTIOTXT", "XXX"])
        self.assertEqual(mask_str(['"a{', "x"]), ["OTI", "C"])
        self.assertEqual(mask_str(['"""a{', "x}", '"""']), ["OOOTI", "CT", "XXX"])

    def test_line_starts(self):
        self.assertEqual(lsp.line_starts("\n"), [0, 1])
        self.assertEqual(lsp.line_starts("\nx"), [0, 1])
        self.assertEqual(lsp.line_starts("a\r\n"), [0, 3])
        self.assertEqual(lsp.line_starts("a\rb"), [0, 2])
        self.assertEqual(lsp.line_starts("\r"), [0, 1])
        self.assertEqual(lsp.line_starts(""), [0])

    def test_classify_edges(self):
        a = analyse("model @")
        t, _ = lsp.classify(a, 1, 0)
        self.assertNotEqual(t.kind, "attribute")
        t, _ = lsp.classify(a, 1, 1)
        self.assertNotEqual(t.kind, "attribute")
        a = analyse("    x .print")
        self.assertFalse(a.ok)
        t, _ = lsp.classify(a, 1, 9)
        self.assertEqual(t.kind, "none")
        t, _ = lsp.classify(analyse(ARMS), 5, 10)
        self.assertEqual((t.kind, t.binding.kind, t.binding.pos), ("binding", "variant", (1, 10)))


class BadIn:
    def readline(self, limit=-1):         # round 6 F5: read_message passes a limit
        raise OSError("read failed")


class PipeOut(io.BytesIO):
    def write(self, data):
        raise BrokenPipeError("closed")


class FlushOut(io.BytesIO):
    flushes = 0

    def flush(self):
        self.flushes += 1


INIT1 = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}}


class ServerUnits(unittest.TestCase):
    def test_serve_read_and_write_failures(self):
        err = io.StringIO()
        self.assertEqual(lsp.serve(BadIn(), io.BytesIO(), err), 1)
        self.assertIn("cannot read input: read failed", err.getvalue())
        err = io.StringIO()
        self.assertEqual(lsp.serve(io.BytesIO(frame(INIT1) + frame(INIT1)), PipeOut(), err), 1)
        self.assertEqual(err.getvalue().count("cannot write output: closed"), 1)    # stops at the first
        fake = io.StringIO()
        with mock.patch.object(sys, "stderr", fake):
            self.assertEqual(lsp.serve(BadIn(), io.BytesIO()), 1)
        self.assertIn("cannot read input", fake.getvalue())

    def test_quiet_notifications(self):
        s = Session()
        for m in ("workspace/didChangeConfiguration", "workspace/didChangeWatchedFiles", "textDocument/didSave",
                  "$/cancelRequest", "$/setTrace", "$/anything", "initialized"):
            self.assertEqual(s.notify(m, {}), [], m)
        self.assertEqual(s.err.getvalue(), "")
        self.assertEqual(s.notify("custom/thing", {}), [])
        self.assertIn("ignored unknown notification custom/thing", s.err.getvalue())

    def test_bad_messages_get_exactly_one_error_and_no_log(self):
        s = Session()
        cases = [(5, None, lsp.INVALID_REQUEST, "a message must be a JSON object"),
                 ({"jsonrpc": "2.0", "id": 3, "method": 5}, 3, lsp.INVALID_REQUEST, "missing method"),
                 ({"jsonrpc": "2.0", "id": [1], "method": 5}, None, lsp.INVALID_REQUEST, "missing method"),
                 ({"jsonrpc": "2.0", "id": 1.5, "method": "shutdown"}, None, lsp.INVALID_REQUEST,
                  "id must be an integer or a string"),
                 ({"jsonrpc": "2.0", "id": True, "method": "shutdown"}, None, lsp.INVALID_REQUEST,
                  "id must be an integer or a string")]
        for msg, mid, code, text in cases:
            out = s.send(msg)
            self.assertEqual(out, [{"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": text}}], msg)
        self.assertEqual(s.send({"jsonrpc": "2.0", "id": 9, "result": 1}), [])
        self.assertEqual(s.err.getvalue(), "")

    def test_not_initialized_message(self):
        s = Session(init=False)
        r = s.request("textDocument/hover", {})
        self.assertEqual(r["error"], {"code": lsp.SERVER_NOT_INITIALIZED, "message": "the server is not initialized"})
        self.assertEqual(s.notify("textDocument/didOpen", {}), [])      # dropped before initialize, no log
        self.assertEqual(s.err.getvalue(), "")

    def test_did_change_errors(self):
        s = Session()
        r = s.request("textDocument/didChange", {"textDocument": {"uri": "file:///nope.sipar"}, "contentChanges": []})
        self.assertEqual(r["error"]["code"], lsp.INVALID_PARAMS)
        self.assertEqual(r["error"]["message"], "didChange for a document that is not open: file:///nope.sipar")
        r = s.request("textDocument/didChange", {"textDocument": {"uri": URI}, "contentChanges": {"text": "x"}})
        self.assertEqual(r["error"]["message"], "contentChanges must be a list")
        r = s.request("textDocument/didChange", {"textDocument": {"uri": URI}, "contentChanges": [{"text": 1}]})
        self.assertEqual(r["error"]["message"], "each content change needs a text")
        self.assertEqual(s.server.docs[URI].text, SRC)                  # nothing applied

    def test_read_message_blank_lines_and_headers(self):
        body = frame({"a": 1})
        self.assertEqual(lsp.read_message(io.BytesIO(b"\r\n\r\n" + body)), body.split(b"\r\n\r\n", 1)[1])
        self.assertEqual(lsp.read_message(io.BytesIO(b"X-Other: 1\r\n\r\n{}")), b"")
        self.assertEqual(lsp.read_message(io.BytesIO(b"Content-Length: x\r\n\r\n{}")), b"")
        self.assertEqual(lsp.read_message(io.BytesIO(b"Content-Length: 0\r\n\r\n")), b"")
        self.assertEqual(lsp.read_message(io.BytesIO(b"content-length : 2\r\n\r\n{}")), b"{}")
        self.assertIsNone(lsp.read_message(io.BytesIO(b"Content-Length: 5\r\n\r\n{}")))
        self.assertIsNone(lsp.read_message(io.BytesIO(b"\r\n")))
        out, err = io.BytesIO(), io.StringIO()
        lsp.serve(io.BytesIO(b"\r\n" + frame(INIT1)), out, err)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(parse_frames(out.getvalue())[0]["id"], 1)

    def test_respond_encode_failure_and_flush(self):
        out, err = FlushOut(), io.StringIO()
        srv = lsp.Server(out, err)
        srv.respond(4, {1, 2})
        self.assertIn("cannot encode the result", err.getvalue())
        self.assertEqual(parse_frames(out.getvalue()),
                         [{"jsonrpc": "2.0", "id": 4, "error": {"code": lsp.INTERNAL_ERROR,
                                                               "message": "cannot encode the result: TypeError"}}])
        self.assertEqual(out.flushes, 1)
        srv.respond(5, None)
        self.assertEqual(out.flushes, 2)
        srv.notify("x", {})
        self.assertEqual(out.flushes, 3)

    def test_capabilities_exact(self):
        self.assertEqual(lsp.Server(io.BytesIO()).capabilities(), {
            "positionEncoding": "utf-16",
            "textDocumentSync": {"openClose": True, "change": 1, "save": False},
            "hoverProvider": True, "definitionProvider": True, "documentSymbolProvider": True,
            "completionProvider": {"triggerCharacters": [".", "@"], "resolveProvider": False}})
        r = Session(init=False).request("initialize", {"capabilities": {}})["result"]
        self.assertEqual(r["serverInfo"], {"name": "sipar", "version": lsp.__version__})

    def test_shutdown_and_exit_states(self):
        s = Session()
        self.assertEqual(s.request("shutdown", None), {"jsonrpc": "2.0", "id": s.next_id, "result": None})
        self.assertEqual(s.server.state, "shutdown")
        self.assertEqual(s.notify("textDocument/didOpen", {}), [])     # dropped after shutdown
        s.notify("exit", None)
        self.assertEqual(s.server.exit_code, 0)


NEST = '''enum Sh { circle(r: Int), sq(r: Int), dot }
fn main() {
    let g = fn(y: Int) -> Int => {
        let z = y
        z
    }
    if true {
        if true {
            let k = 1
            print(k)
        }
    }
    try {
        let t = "a".upper()
        print(t)
    } catch err {
        print(err)
    }
    let h = Sh.sq(r: 2)
    match h {
        Sh.circle(r) => print(r),
        Sh.sq(r) => {
            let q = "{r}"
            print(q.upper())
        },
        Sh.dot => print(g(1)),
    }
}
'''


class VisitOnce(unittest.TestCase):
    def test_every_scope_binds_each_name_once(self):
        a = analyse(NEST)
        self.assertEqual(a.diags, [])
        self.assertEqual([(b.name, b.kind, b.pos) for b in a.bindings if b.scope is not None],
                         [("y", "param", (3, 16)), ("z", "let", (4, 13)), ("g", "let", (3, 9)),
                          ("k", "let", (9, 17)), ("t", "let", (14, 13)), ("err", "catch", (16, 13)),
                          ("h", "let", (19, 9)), ("r", "bind", (21, 19)), ("r", "bind", (22, 15)),
                          ("q", "let", (23, 17))])

    def test_bodies_of_lambda_try_and_arms_are_walked(self):
        s = Session(NEST)
        self.assertEqual(s.definition("y\n"), at(NEST, "y: Int"))            # lambda body
        self.assertEqual(s.definition("z\n"), at(NEST, "z = y"))
        self.assertEqual(s.definition("(t)", offset=1), at(NEST, "t = "))     # try body
        self.assertIn("Str.upper()", s.hover("upper()\n"))
        self.assertEqual(s.definition("(err)", offset=1), at(NEST, "err {"))
        self.assertEqual(s.definition("(r),", offset=1), at(NEST, "r) =>"))    # first arm
        self.assertEqual(s.definition("{r}", offset=1), at(NEST, "r) => {"))  # second arm, inside a string
        self.assertEqual(s.definition("(q.", offset=1), at(NEST, "q = "))
        self.assertIn("Str.upper()", s.hover("upper())"))
        self.assertEqual(s.definition("g(1)"), at(NEST, "g = "))
        self.assertEqual(s.err.getvalue(), "")

    def test_match_subject_and_arm_bodies(self):
        text = 'fn main() {\n    let s = "ab"\n    match s.len() {\n        0 => print(0),\n        _ => print(s.upper()),\n    }\n}\n'
        s = Session(text)
        self.assertIn("Str.len()", s.hover("len()"))
        self.assertIn("Str.upper()", s.hover("upper()"))


class EdgeUnits(unittest.TestCase):
    def test_members_receiver_with_a_space_before_the_dot(self):
        got = lsp._members(stub_doc(analyse(MEM_NONE)), 2, 8, "    fs .", "r")
        self.assertIn("read", labels(got))

    def test_members_use_the_patched_text_when_nothing_is_typed(self):
        text = "fn main() {\n    let xs = [1]\n    xs.\n}\n"
        s = Session(text)
        r = s.pos_req("textDocument/completion", at(text, ".\n", 0, 1))
        self.assertIn("push", labels(r))
        doc = s.server.docs[URI]
        self.assertFalse(doc.analysis.ok)
        self.assertIn("push", labels(lsp._members(doc, 3, 7, "    xs.", "")))
        self.assertEqual(lsp._members(doc, 3, 7, "    xs.", "p"), [])      # a typed name: no patching

    def test_mask_escape_inside(self):
        self.assertEqual(mask_str(['"a\\b']), ["OTTT"])

    def test_record_keys_stop_at_the_last_token(self):
        u = analyse("fn main() {\n    let r = P { a: 1, b: a }\n}\n")
        del u.brackets[(2, 15)]
        k = bisect.bisect_right(u.tok_pos, (2, 26))
        u.toks, u.tok_pos = u.toks[:k], u.tok_pos[:k]                     # ends at the value `a`
        self.assertEqual(u.record_keys((2, 13)), {"a": (2, 17), "b": (2, 23)})
        k = bisect.bisect_right(u.tok_pos, (2, 24))
        u.toks, u.tok_pos = u.toks[:k], u.tok_pos[:k]                     # ends at the `:` after b
        self.assertEqual(u.record_keys((2, 13)), {"a": (2, 17), "b": (2, 23)})

    def test_capability_at_a_trailing_dot(self):
        self.assertIsNone(lsp._capability_at("allow fs.", 6, 8))
        self.assertIsNone(lsp._capability_at("allow fs.r", 6, 8))
        self.assertEqual(lsp._capability_at("allow fs.read", 6, 8), ("fs.read", (6, 13)))


HOV = '''fn main() {
    let f = fn(x: Int) -> Int => x + 1
    if true {
        print(1)
    }
    let v = if true { 1 } else { 2 }
    print(false)
}
'''


class SurvivorUnits(unittest.TestCase):
    def test_word_at_edges(self):
        self.assertIsNone(lsp.word_at(" ab", 0))
        self.assertEqual(lsp.word_at("ab", 0), (0, 2))
        self.assertEqual(lsp.word_at("ab", 2), (0, 2))
        self.assertIsNone(lsp.word_at("ab", 3))
        self.assertIsNone(lsp.word_at("ab", -1))
        self.assertEqual(lsp.word_at("a b", 1), (0, 1))
        self.assertEqual(lsp.word_at("a .", 1), (0, 1))
        self.assertEqual(lsp.word_at("a ", 1), (0, 1))
        self.assertIsNone(lsp.word_at("", 0))

    def test_dot_before_edges(self):
        self.assertEqual(lsp.dot_before(".a.", 1), 0)
        self.assertIsNone(lsp.dot_before("..a", 2))
        self.assertEqual(lsp.dot_before("x . \ty", 5), 2)
        self.assertIsNone(lsp.dot_before("  y", 2))
        self.assertIsNone(lsp.dot_before("ab", 5))

    def test_capability_at_needs_a_word_after_the_dot(self):
        self.assertEqual(lsp._capability_at("allow net. x", 6, 9), ("net", (6, 9)))
        self.assertIsNone(lsp._capability_at("allow net.x", 6, 9))

    def test_in_text_bounds(self):
        a = analyse("// a\n// b")
        self.assertTrue(lsp._in_text(a, 1, 1))
        self.assertTrue(lsp._in_text(a, 2, 4))          # the last line
        self.assertFalse(lsp._in_text(a, 0, 1))         # before the first line
        self.assertFalse(lsp._in_text(a, 3, 1))         # after the last line
        self.assertFalse(lsp._in_text(a, 1, 0))         # before the first character

    def test_hover_on_keywords_and_expressions(self):
        s = Session(HOV)
        r = s.pos_req("textDocument/hover", at(HOV, "fn(x"))
        self.assertEqual(r, {"contents": {"kind": "markdown", "value": "```sipar\nfn(Int) -> Int\n```\n\nexpression type"},
                             "range": rng(1, 12, 1, 14)})
        self.assertIsNone(s.pos_req("textDocument/hover", at(HOV, "if true {\n")))       # a statement: None type
        r = s.pos_req("textDocument/hover", at(HOV, "if true { 1"))
        self.assertEqual(r["contents"]["value"], "```sipar\nInt\n```\n\nexpression type")
        self.assertEqual(s.hover("false"), "```sipar\nBool\n```")
        self.assertEqual(s.err.getvalue(), "")

    def test_general_lists_a_redefined_builtin_once(self):
        for src, name in (("fn http() -> Int { 1 }\n", "http"), ("let http = 1\n", "http"),
                          ("enum Str { a }\n", "Str"), ("fn max(a: Int) -> Int { a }\n", "max")):
            a = analyse(src + "fn main() { print(1) }\n")
            self.assertEqual(labels(lsp._general(a, (2, 5))).count(name), 1, src)

    def test_local_scope_bounds_in_completion(self):
        text = "type P = { a: Int }\nfn main() {\n    let P = 1\n    let http = 2\n    let Int = 3\n    print(P)\n}\n"
        a = analyse(text)
        items = {i["label"]: i for i in lsp._general(a, (6, 5))}
        self.assertEqual(items["Int"]["sortText"], "1Int")              # its scope starts exactly here
        items = {i["label"]: i for i in lsp._general(a, (7, 1))}
        self.assertEqual(items["P"]["sortText"], "1P")                  # and ends at the closing brace
        text = "fn main() {\n    let x = 1\n    x\n}\n"
        s = Session(text)
        self.assertIn("x", labels(s.complete({"line": 2, "character": 4})))
        self.assertIn("x", labels(s.complete({"line": 3, "character": 0})))
        self.assertNotIn("x", labels(s.complete({"line": 1, "character": 8})))

    def test_capability_completion_range(self):
        text = "fn main() {\n    allow fs.r\n}\n"
        r = Session(text).complete({"line": 1, "character": 14})
        self.assertEqual(r[0]["textEdit"]["range"], rng(1, 10, 1, 14))

    def test_symbols_with_text_after_the_braces(self):
        text = ("type P = { a: Int } // c\nenum E { one } // c\nfn f() -> Int {\n    1\n} // end\n"
                'test "t" {\n    assert true, "x"\n} // e\n')
        by = {x["name"]: x["range"] for x in lsp.symbols(analyse(text))}
        self.assertEqual(by, {"P": rng(0, 0, 0, 19), "E": rng(1, 0, 1, 14), "f": rng(2, 0, 4, 1),
                              'test "t"': rng(5, 0, 7, 1)})

    def test_innermost_binding_wins_in_any_order(self):
        text = 'fn main() {\n    let x = 1\n    if true {\n        let x = "a"\n        print(x)\n    }\n}\n'
        a = analyse(text)
        inner = a.resolve("x", (5, 15))
        self.assertEqual(inner.pos, (4, 13))
        a.bindings.reverse()
        self.assertIs(a.resolve("x", (5, 15)), inner)
        self.assertIs({b.name: b for b in a.visible((5, 15))}["x"], inner)
        a.bindings.reverse()
        twin = lsp.dataclasses.replace(inner, pos=(9, 9))
        a.bindings.append(twin)                                          # same scope start: the later one wins
        self.assertIs(a.resolve("x", (5, 15)), twin)
        self.assertIs({b.name: b for b in a.visible((5, 15))}["x"], twin)

    def test_enclosing_close_in_any_order(self):
        a = analyse('fn main() {\n    let p = f([1, (2)], g(3))\n}\n')
        a.brackets = dict(sorted(a.brackets.items()))                   # outer brackets first
        self.assertEqual(a.enclosing_close((2, 20)), (2, 21))
        self.assertEqual(a.enclosing_close((2, 16)), (2, 22))

    def test_a_lambda_ends_at_the_next_statement(self):
        a = analyse("fn main() {\n    let f = fn(x: Int) -> Int => x + 1\n    print(1)\n}\n")
        self.assertEqual(a.resolve("x", (2, 34)).kind, "param")
        self.assertIsNone(a.resolve("x", (3, 11)))

    def test_offset_at_clamps_to_the_line(self):
        self.assertEqual(lsp.offset_at("ab\ncd", [0, 3], {"line": 0, "character": 10}), 2)
        self.assertEqual(lsp.offset_at("ab\r\ncd", [0, 4], {"line": 0, "character": 10}), 2)
        self.assertEqual(lsp.offset_at("ab\ncd", [0, 3], {"line": 1, "character": 10}), 5)

    def test_handle_bytes_empty_and_malformed(self):
        out, err = io.BytesIO(), io.StringIO()
        srv = lsp.Server(out, err)
        srv.handle_bytes(lsp.Skipped())                    # round 7: a skipped frame, not any empty body
        self.assertEqual(out.getvalue(), b"")
        self.assertEqual(err.getvalue(), "sipar lsp: skipped a message without a valid Content-Length header\n")
        err.truncate(0), err.seek(0)
        srv.handle_bytes(b"{bad")
        self.assertEqual(parse_frames(out.getvalue()),
                         [{"jsonrpc": "2.0", "id": None, "error": {"code": lsp.PARSE_ERROR,
                                                                  "message": "parse error: JSONDecodeError"}}])
        self.assertEqual(err.getvalue().count("\n"), 1)
        self.assertTrue(err.getvalue().startswith("sipar lsp: malformed message: JSONDecodeError"))

    def test_feature_functions_stay_callable(self):
        for name in ("hover", "definition", "completion"):
            self.assertTrue(callable(getattr(lsp, name)), name)
        self.assertEqual({v[1] for v in lsp.FEATURES.values()},
                         {"hoverProvider", "definitionProvider", "documentSymbolProvider", "completionProvider"})

    def test_unknown_members_are_none(self):
        a = analyse(MEM_LIST)
        self.assertEqual(lsp._static_member(a, "Nope", "x").kind, "none")
        (dpos, f), = a.fields.items()
        self.assertEqual(lsp._member(a, f.obj, "len", f, dpos).kind, "method")
        self.assertEqual(lsp._member(a, f.obj, "zz", f, dpos).kind, "none")

    def test_params_keep_their_type_without_the_checker(self):
        def boom(self):
            raise RuntimeError("boom")
        with mock.patch.object(lsp.Analysis, "_record", boom):
            a = analyse("fn f(a: Int) -> Int { a }\n")
        self.assertEqual(a.decl_types, {})
        got = {b.name: a.binding_type(b) for b in a.bindings if b.kind == "param"}
        self.assertEqual(got["a"], "Int")
        self.assertIsNone(analyse("fn (").program)

    def test_patched_bounds(self):
        doc = stub_doc(None, text="ab")
        self.assertEqual(lsp._patched(doc, 1, 1).text, "a" + lsp.PLACEHOLDER + "b")
        self.assertEqual(lsp._patched(doc, 0, 1).text, "ab")
        self.assertEqual(lsp._patched(doc, 2, 1).text, "ab")

    def test_diagnostic_at_column_zero_before_punctuation(self):
        D = lsp.dataclasses.make_dataclass("D", ["line", "col", "message", "hint", "severity", "code"])
        a = analyse("ab .")
        a.diags, a.crash = [D(1, 0, "m", None, "error", "E1")], None
        self.assertEqual(lsp.diagnostics_for(a)[0]["range"], rng(0, 0, 0, 2))

    def test_prompt_names_resolve(self):
        s = Session(GEN)
        self.assertEqual(s.definition("{x}", offset=1), at(GEN, "x: Str"))
        self.assertIn("x: Str", s.hover("{x}", offset=1))
        self.assertEqual(s.err.getvalue(), "")


PROMPT_ARGS = '''fn add(a: Int, b: Int) -> Int { a + b }
@model("mock")
ai fn helper(x: Str) -> Int {
    """
    {add(b: 1, a: 2)} {x}
    """
}
'''


class SurvivorUnits2(unittest.TestCase):
    def test_named_args_inside_a_prompt(self):
        s = Session(PROMPT_ARGS)
        self.assertEqual(s.definition("b: 1"), at(PROMPT_ARGS, "b: Int"))
        self.assertEqual(s.definition("a: 2"), at(PROMPT_ARGS, "a: Int"))
        self.assertEqual(s.err.getvalue(), "")

    def test_an_interpolation_the_sub_lexer_rejects(self):
        # the parser rejects this text, so it is scanned on its own (the scanner must not trust the lexer)
        a = analyse(MEM_NONE)
        a.text, a.toks, a.brackets = 'print("{$}")\n', [], {}
        a._scan_tokens()
        self.assertEqual([t.value for t in a.toks][:2], ["print", "("])
        self.assertEqual(a.brackets, {(1, 6): (1, 12)})

    def test_symbol_end_without_tokens_uses_the_name_line(self):
        def boom(self):
            raise RuntimeError("boom")
        with mock.patch.object(lsp.Analysis, "_scan_tokens", boom):
            a = analyse(SYMS)
        self.assertEqual(a.toks, [])
        by = {s["name"]: s for s in lsp.symbols(a)}
        self.assertEqual(by["E"]["range"], rng(1, 0, 1, 27))

    def test_capability_completion_range_mid_line(self):
        text = "fn main() {\n    allow fs.r x\n}\n"
        r = Session(text).complete({"line": 1, "character": 14})
        self.assertEqual(r[0]["textEdit"]["range"], rng(1, 10, 1, 14))


if __name__ == "__main__":
    unittest.main()
