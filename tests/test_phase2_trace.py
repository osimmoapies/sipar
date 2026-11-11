"""Phase 2 — `sipar trace JOURNAL.jsonl` (cases T1-T8)."""
from __future__ import annotations

import io
import json
import os
import shutil
import tempfile
import unittest

import rt_helpers  # noqa: F401  (puts the repo on sys.path)
from sipar import cli
from sipar.trace import read_entries, render, summarize


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(list(argv), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


E = [
    {"seq": 1, "kind": "ai", "request": {"fn": "summarize"}, "fn": "summarize", "t": 100.0, "ms": 250.0,
     "meta": {"model": "openrouter/a", "attempt": 1, "of": 2}, "response": None, "labels": [],
     "error": {"kind": "ai", "message": "HTTP 503"}},
    {"seq": 2, "kind": "ai", "request": {"fn": "summarize"}, "fn": "summarize", "t": 100.3, "ms": 10.0,
     "meta": {"model": "mock", "attempt": 2, "of": 2},
     "response": {"text": "x", "usage": {"input": 120, "output": 30}}, "labels": []},
    {"seq": 3, "kind": "ai", "request": {"fn": "classify"}, "fn": "classify", "t": 100.5, "ms": 5.0,
     "meta": {"model": "mock"}, "response": {"text": "y", "usage": {"input": 40, "output": 2}}, "labels": []},
    {"seq": 4, "kind": "http.get", "request": {"url": "http://127.0.0.1/"}, "fn": "main", "t": 100.6, "ms": 400.0,
     "response": {"status": 200}, "labels": []},
    {"seq": 5, "kind": "fs.read", "request": {"path": "/x"}, "fn": "main", "t": 101.0, "ms": 1.0,
     "response": None, "labels": [], "error": {"kind": "io", "message": "no such file"}},
]


class TestSummary(unittest.TestCase):
    def test_T1_per_function_rows_and_totals(self):
        s = summarize(E)
        f = s["functions"]
        self.assertEqual(sorted(f), ["classify", "main", "summarize"])
        self.assertEqual(f["summarize"], {"effects": 2, "ai_calls": 2, "tokens_in": 120, "tokens_out": 30,
                                          "usd": None, "ms": 260.0, "errors": 1})
        self.assertEqual(f["main"]["ai_calls"], 0)
        self.assertEqual(f["main"]["errors"], 1)
        self.assertEqual(f["main"]["ms"], 401.0)
        t = s["totals"]
        self.assertEqual((t["effects"], t["ai_calls"], t["tokens_in"], t["tokens_out"], t["errors"]),
                         (5, 3, 160, 32, 2))
        self.assertEqual(t["ms"], 666.0)
        self.assertEqual(t["span_ms"], 1001.0)
        self.assertEqual(s["kinds"], {"ai": 3, "fs.read": 1, "http.get": 1})
        text = render(s)
        self.assertIn("summarize", text)
        self.assertRegex(text, r"\(total\)\s+5\s+3\s+160\s+32\s+-\s+666\.0\s+2")
        self.assertIn("SIPAR_PRICE_IN", text)

    def test_T3_priced(self):
        es = [dict(E[1], meta={"model": "m", "usd": 0.0015}), dict(E[2], meta={"model": "m", "usd": 0.00025}), E[3]]
        s = summarize(es)
        self.assertEqual(s["functions"]["summarize"]["usd"], 0.0015)
        self.assertEqual(s["functions"]["main"]["usd"], None)
        self.assertEqual(s["totals"]["usd"], 0.00175)
        text = render(s)
        self.assertIn("0.00175", text)
        self.assertNotIn("SIPAR_PRICE_IN", text)
        self.assertRegex(text, r"main\s+1\s+0\s+0\s+0\s+-")

    def test_T4_old_journal_without_new_fields(self):
        old = [{"seq": 1, "kind": "ai", "request": {"fn": "f", "messages": []}, "response": {"text": "x"},
                "labels": []},
               {"seq": 2, "kind": "env.get", "request": {"name": "X"}, "response": "1", "labels": []}]
        s = summarize(old)
        self.assertEqual(sorted(s["functions"]), ["(top)", "f"])
        self.assertEqual(s["functions"]["f"]["ai_calls"], 1)
        self.assertEqual(s["totals"]["ms"], 0)
        self.assertIsNone(s["totals"]["span_ms"])
        self.assertEqual(s["models"], {})
        self.assertNotIn("run span", render(s))

    def test_T4b_hostile_numbers_ignored(self):
        bad = [{"kind": "ai", "fn": "f", "ms": -5, "t": "x", "meta": {"model": 3, "usd": float("nan")},
                "response": {"usage": {"input": True, "output": -3}}},
               {"kind": "ai", "fn": "f", "ms": float("inf"), "response": "text"}]
        s = summarize(bad)
        self.assertEqual(s["functions"]["f"], {"effects": 2, "ai_calls": 2, "tokens_in": 0, "tokens_out": 0,
                                               "usd": 0, "ms": 0, "errors": 0})

    def test_T7_fallback_models_table(self):
        s = summarize(E)
        self.assertEqual(s["models"]["openrouter/a"]["errors"], 1)
        self.assertEqual(s["models"]["openrouter/a"]["ai_calls"], 1)
        self.assertEqual(s["models"]["mock"]["ai_calls"], 2)
        self.assertEqual(s["models"]["mock"]["tokens_in"], 160)
        text = render(s)
        self.assertIn("openrouter/a", text)
        self.assertIn("model", text.split("\n\n")[1].split("\n")[0])

    def test_render_layout(self):
        from sipar.trace import _cell
        self.assertEqual((_cell(None), _cell(5), _cell(0.5), _cell(1.0), _cell(1.5), _cell(0.00175)),
                         ("-", "5", "0.5", "1.00", "1.50", "0.00175"))
        lines = render(summarize(E)).split("\n")
        self.assertTrue(lines[0].startswith("function "))
        self.assertTrue(set(lines[1]) <= {"-", " "})
        self.assertTrue(lines[2].startswith("classify "))           # names left-aligned
        self.assertRegex(lines[2], r"\s5\.0\s+0$")                 # numbers right-aligned
        total = next(i for i, l in enumerate(lines) if l.startswith("(total)"))
        self.assertEqual(lines[total - 1], lines[1])                # rule above the totals row
        self.assertEqual(total, 6)
        self.assertIn("effects by kind: ai 3, fs.read 1, http.get 1, run span 1.001 s", lines)
        self.assertEqual(render(summarize([])), "no entries\ntotal: 0 effects, 0 ai calls, 0 tokens, 0 errors\n")

    def test_ms_rounding(self):
        s = summarize([{"kind": "x", "ms": 0.0004}, {"kind": "x", "ms": 0.0004}])
        self.assertEqual(s["totals"]["ms"], 0.001)

    def test_read_entries_rejects(self):
        from sipar.trace import TraceError
        for text in ('{"kind": "ai"}\nnot json', '[1]', '{"seq": 1}', '{"kind": 3}'):
            with self.assertRaises(TraceError):
                read_entries(text)
        self.assertEqual(read_entries("\n\n"), [])
        with self.assertRaisesRegex(TraceError, r"^j line 1 is not a journal entry"):
            read_entries('{"seq": 1}', "j")


class TestCli(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="sipar_trace_")
        self.path = os.path.join(self.dir, "run.jsonl")
        with open(self.path, "w") as fh:
            fh.write("\n".join(json.dumps(e) for e in E) + "\n")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_T1_cli_table(self):
        code, out, err = run_cli("trace", self.path)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("function", out)
        self.assertIn("classify", out)

    def test_T2_json(self):
        code, out, err = run_cli("trace", self.path, "--json")
        self.assertEqual(code, 0)
        d = json.loads(out)
        self.assertEqual(set(d), {"functions", "models", "kinds", "totals"})
        self.assertEqual(d["totals"]["ai_calls"], 3)

    def test_T5_empty(self):
        p = os.path.join(self.dir, "empty.jsonl")
        open(p, "w").close()
        code, out, _ = run_cli("trace", p)
        self.assertEqual(code, 0)
        self.assertIn("no entries", out)
        code, out, _ = run_cli("trace", p, "--json")
        self.assertEqual(json.loads(out)["totals"]["effects"], 0)

    def test_T6_missing_and_invalid(self):
        code, _, err = run_cli("trace", os.path.join(self.dir, "nope.jsonl"))
        self.assertEqual(code, 2)
        self.assertIn("no such journal", err)     # L12 (round 6): the wording of `replay`
        p = os.path.join(self.dir, "bad.jsonl")
        with open(p, "w") as fh:
            fh.write('{"kind": "ai"}\n{oops\n')
        code, out, err = run_cli("trace", p)
        self.assertEqual((code, out), (1, ""))
        self.assertIn("line 2", err)

    def test_T8_real_run_then_trace_and_replay(self):
        src = os.path.join(self.dir, "p.sipar")
        with open(src, "w") as fh:
            fh.write('allow ai\nai fn greet(n: Str) -> Str { "hi {n}" }\nfn main() uses ai {\n'
                     '    print(greet("a"))\n    print(greet("b"))\n}\n')
        old = os.environ.get("SIPAR_MODEL")
        os.environ["SIPAR_MODEL"] = "mock"
        try:
            code, out, err = run_cli("run", src)
        finally:
            if old is None:
                os.environ.pop("SIPAR_MODEL")
            else:
                os.environ["SIPAR_MODEL"] = old
        self.assertEqual(code, 0, err)
        jdir = os.path.join(self.dir, ".sipar", "runs")
        journal = os.path.join(jdir, sorted(os.listdir(jdir))[-1])
        code, tout, _ = run_cli("trace", journal, "--json")
        d = json.loads(tout)
        self.assertEqual(d["functions"]["greet"]["ai_calls"], 2)
        self.assertEqual(list(d["models"]), ["mock"])
        code, rout, rerr = run_cli("replay", src, journal)
        self.assertEqual((code, rout), (0, out), rerr)


if __name__ == "__main__":
    unittest.main()
