"""Phase 2 — labelled persistent memory (cases M1-M30)."""
from __future__ import annotations

import io
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from rt_helpers import ROOT, Prog
from sipar import ast as A
from sipar.checker import check, check_source
from sipar.errors import SiparRuntimeError
from sipar.parser import parse
from sipar.runtime import memory as M
from sipar.runtime.decode import TypeEnv
from sipar.runtime.interp import Interp, run_tests
from sipar.runtime.journal import Journal
from sipar.runtime.values import EnumVal, Record, labels_of, set_labels, with_labels


def T(text: str):
    from sipar.lexer import Lexer
    from sipar.parser import Parser
    return Parser(Lexer(text, "<t>").tokenize(), "<t>").type_expr()


class Dir:
    """Programs that share one directory (so they share the memory store when they share a name)."""

    def __init__(self, dirname: str | None = None):
        base = os.path.realpath(tempfile.mkdtemp(prefix="sipar_mem_"))
        self.root = base
        self.dir = os.path.join(base, dirname) if dirname else base
        os.makedirs(self.dir, exist_ok=True)

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def program(self, src: str, name: str = "prog.sipar"):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(src)
        prog = parse(src, path)
        errs = [d for d in check(prog, src) if d.severity == "error"]
        if errs:
            raise AssertionError("checker errors: " + "; ".join(f"{d.code} {d.message}" for d in errs))
        return prog, path

    def run(self, src: str, name: str = "prog.sipar", journal=None, script=None, env=None) -> str:
        prog, path = self.program(src, name)
        out = io.StringIO()
        p = Prog.__new__(Prog)          # reuse only the env() helper (SIPAR_MODEL=mock, clean env)
        with p.env(env):
            it = Interp(prog, path, journal=journal or Journal(), out=out, err_out=io.StringIO(),
                        stdin=io.StringIO(""), mock_script=script)
            self.last = it
            try:
                it.run_main(None)
            finally:
                if journal is not None:
                    journal.close()
        return out.getvalue()

    def error(self, src: str, **kw) -> SiparRuntimeError:
        try:
            out = self.run(src, **kw)
        except SiparRuntimeError as e:
            return e
        raise AssertionError("expected a runtime error, got output:\n" + out)

    def store(self, name: str = "prog") -> str:
        return os.path.join(self.dir, ".sipar", "memory", name + ".json")


def _text(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def prog(body: str, head: str = "", uses: str = "memory") -> str:
    return f"allow memory\n{head}\nfn main() uses {uses} {{\n{body}\n}}\n"


AI_HEAD = 'allow ai\nai fn fetch(q: Str) -> Str { "say {q}" }\n'


class Base(unittest.TestCase):
    def setUp(self):
        self.d = Dir()

    def tearDown(self):
        self.d.cleanup()


class TestPersistence(Base):
    def test_M1_save_then_load_in_second_run(self):
        src = prog('let n: Int = memory.load("count") ?? 0\nmemory.save("count", n + 1)\nprint(n)')
        self.assertEqual(self.d.run(src).strip(), "0")
        self.assertEqual(self.d.run(src).strip(), "1")
        self.assertEqual(self.d.run(src).strip(), "2")
        data = json.loads(_text(self.d.store()))
        self.assertRegex(data.pop("gen"), "^[0-9a-f]{16}$")            # round 7: the store's generation stamp
        self.assertEqual(data, {"version": 1, "entries": {"count": {"value": 3, "labels": [], "enc": 2}}})

    def test_M2_untrusted_stays_untrusted_across_runs(self):
        save = prog('memory.save("note", fetch("x"))', AI_HEAD, "ai, memory")
        self.d.run(save, script=["rm -rf ~"])
        use = prog('let n: Str = memory.load("note") ?? "echo hi"\nprint(shell.run(n))',
                   'allow shell ["echo", "rm"]', "memory, shell")
        e = self.d.error(use)
        self.assertEqual(e.kind, "taint")
        self.assertIn("untrusted:ai:fetch", e.message)

    def test_M3_trusted_value_stays_usable(self):
        self.d.run(prog('memory.save("cmd", "echo trusted")'))
        out = self.d.run(prog('let c: Str = memory.load("cmd") ?? "echo none"\nprint(shell.run(c))',
                              'allow shell ["echo"]', "memory, shell"))
        self.assertEqual(out.strip(), "trusted")

    def test_M3b_trust_after_load_declassifies(self):
        self.d.run(prog('memory.save("note", fetch("x"))', AI_HEAD, "ai, memory"), script=["echo ok"])
        out = self.d.run(prog('let n: Str = memory.load("note") ?? ""\nprint(shell.run(trust(n, "checked")))',
                              'allow shell ["echo"]', "memory, shell"))
        self.assertEqual(out.strip(), "ok")

    def test_M4_labels_exact_per_leaf(self):
        head = AI_HEAD + 'type Note = { title: Str, body: Str }\nallow shell ["echo"]'
        self.d.run(prog('memory.save("n", Note { title: "echo title", body: fetch("q") })', head, "ai, memory"),
                   script=["echo body"])
        ok = prog('let n: Note? = memory.load("n")\nlet x = n ?? Note { title: "", body: "" }\n'
                  'print(shell.run(x.title))', head, "memory, shell")
        self.assertEqual(self.d.run(ok).strip(), "title")
        bad = ok.replace("x.title", "x.body")
        self.assertEqual(self.d.error(bad).kind, "taint")
        entry = json.loads(_text(self.d.store()))["entries"]["n"]
        self.assertEqual(entry["labels"], [[["body"], ["untrusted:ai:fetch"]]])

    def test_M9_missing_key_is_none(self):
        self.assertEqual(self.d.run(prog('let x: Int? = memory.load("nope")\nprint(x)')).strip(), "none")
        self.assertFalse(os.path.exists(self.d.store()))

    def test_M10_type_changed_is_decode_error(self):
        self.d.run(prog('memory.save("k", 5)'))
        e = self.d.error(prog('let s: Str? = memory.load("k")\nprint(s)'))
        self.assertEqual(e.kind, "decode")
        self.assertIn("'k'", e.message)

    def test_M16_keys_and_delete(self):
        out = self.d.run(prog('memory.save("b", 1)\nmemory.save("a", 2)\nprint(memory.keys())\n'
                              'print(memory.delete("a"))\nprint(memory.delete("a"))\nprint(memory.keys())'))
        self.assertEqual(out.split("\n")[:4], ['["a", "b"]', "true", "false", '["b"]'])

    def test_M19_corrupt_store_is_io_and_untouched(self):
        os.makedirs(os.path.dirname(self.d.store()))
        with open(self.d.store(), "w") as fh:
            fh.write("{not json")
        for body in ('let x: Int? = memory.load("k")\nprint(x)', 'memory.save("k", 1)', 'print(memory.keys())'):
            e = self.d.error(prog(body))
            self.assertEqual(e.kind, "io", body)
            self.assertIn(self.d.store(), e.message)
        self.assertEqual(_text(self.d.store()), "{not json")

    def test_M20_unknown_version_is_io(self):
        os.makedirs(os.path.dirname(self.d.store()))
        for text in ('{"entries": {}}', '{"version": 2, "entries": {}}', '[]', '{"version": 1, "entries": []}'):
            with open(self.d.store(), "w") as fh:
                fh.write(text)
            e = self.d.error(prog('memory.save("k", 1)'))
            self.assertEqual(e.kind, "io", text)
            self.assertEqual(_text(self.d.store()), text)

    def test_M20b_malformed_entry_is_io(self):
        os.makedirs(os.path.dirname(self.d.store()))
        for entry in ('{"labels": []}', '{"value": 1, "labels": [["x", []]]}', '{"value": 1, "labels": [[[true], ["a"]]]}',
                      '5'):
            with open(self.d.store(), "w") as fh:
                fh.write('{"version": 1, "entries": {"k": %s}}' % entry)
            e = self.d.error(prog('let x: Int? = memory.load("k")\nprint(x)'))
            self.assertEqual(e.kind, "io", entry)

    def test_M21_unicode_keys_and_values(self):
        key = r'заметки \"q\" x'          # Sipar source text: a key with Cyrillic, quotes and spaces
        src = prog(f'memory.save("{key}", "привет «мир»")\nlet v: Str? = memory.load("{key}")\nprint(v)\n'
                   'print(memory.keys())')
        out = self.d.run(src)
        self.assertIn("привет «мир»", out)
        with open(self.d.store(), encoding="utf-8") as fh:
            self.assertEqual(list(json.load(fh)["entries"]), ['заметки "q" x'])

    def test_M21b_empty_key_is_value_error(self):
        for body in ('memory.save("", 1)', 'let x: Int? = memory.load("")\nprint(x)', 'print(memory.delete(""))'):
            self.assertEqual(self.d.error(prog(body)).kind, "value", body)

    def test_M22_cycle_is_value_error_and_nothing_written(self):
        head = "type R = { items: List[R] }"
        e = self.d.error(prog('let r = R { items: [] }\nr.items.push(r)\nmemory.save("c", r)', head))
        self.assertEqual(e.kind, "value")
        self.assertIn("cycle", e.message)
        self.assertFalse(os.path.exists(self.d.store()))

    def test_M24_enums_floats_optionals_round_trip(self):
        head = ("enum Act { stop, go(speed: Float, note: Str?) }\n"
                "type Box = { a: Act, b: Act, f: Float, o: Int?, nested: List[Map[Int?]] }")
        save = prog('memory.save("x", Box { a: Act.stop, b: Act.go(speed: 2.5, note: none), f: 1.25, o: none, '
                    'nested: [["k": 1, "n": none]] })\nmemory.save("i", 3)', head)
        self.d.run(save)
        out = self.d.run(prog('let b: Box? = memory.load("x")\nprint(b)\nlet f: Float = memory.load("i") ?? 0.0\n'
                              'print(f + 0.5)', head))
        lines = out.strip().split("\n")
        self.assertEqual(json.loads(lines[0]), {"a": "stop", "b": {"tag": "go", "speed": 2.5, "note": None},
                                                "f": 1.25, "o": None, "nested": [{"k": 1, "n": None}]})
        self.assertEqual(lines[1], "3.5")

    def test_M28_key_too_long(self):
        k = "k" * 257
        self.assertEqual(self.d.error(prog(f'memory.save("{k}", 1)')).kind, "value")
        self.d.run(prog(f'memory.save("{"k" * 256}", 1)'))

    def test_M30_cyrillic_dir_with_spaces(self):
        d = Dir("папка с пробелами")
        try:
            src = prog('let n: Int = memory.load("c") ?? 0\nmemory.save("c", n + 1)\nprint(n)')
            d.run(src)
            self.assertEqual(d.run(src).strip(), "1")
            self.assertTrue(os.path.exists(d.store()))
        finally:
            d.cleanup()

    def test_store_per_program_name(self):
        src = prog('let n: Int = memory.load("c") ?? 0\nmemory.save("c", n + 1)\nprint(n)')
        self.d.run(src, name="a.sipar")
        self.assertEqual(self.d.run(src, name="b.sipar").strip(), "0")
        self.assertTrue(os.path.exists(self.d.store("a")) and os.path.exists(self.d.store("b")))

    def test_M26_no_tmp_leftovers(self):
        self.d.run(prog('memory.save("a", 1)\nmemory.save("b", 2)\nprint(memory.delete("a"))'))
        left = sorted(os.listdir(os.path.dirname(self.d.store())))
        self.assertEqual(left, ["prog.json", "prog.json.lock"])

    def test_M26b_failed_write_keeps_old_file(self):
        self.d.run(prog('memory.save("a", 1)'))
        before = _text(self.d.store())
        st = M.FileStore(self.d.store())

        # round 6 F6: _update no longer takes a change function; the disk fills up during the write instead
        with mock.patch("os.fsync", side_effect=OSError(28, "No space left on device")):
            with self.assertRaises(SiparRuntimeError) as cm:
                st.put("b", {"value": 2, "labels": []})
        self.assertEqual(cm.exception.kind, "io")
        self.assertEqual(_text(self.d.store()), before)
        self.assertEqual(st.keys(), ["a"])


class TestTaint(Base):
    def test_M5_secret_value_rejected_nothing_written(self):
        head = 'allow secret ["TOKEN"]'
        for body in ('memory.save("t", env.secret("TOKEN"))',
                     'memory.save("t", ["a", env.secret("TOKEN")])',
                     'memory.save("t", ["x": "a" + env.secret("TOKEN")])'):
            e = self.d.error(prog(body, head, "memory, secret"), env={"TOKEN": "s3cr3t-value"})
            self.assertEqual(e.kind, "taint", body)
            self.assertNotIn("s3cr3t-value", e.message)
        self.assertFalse(os.path.exists(self.d.store()))

    def test_M6_secret_key_rejected(self):
        head = 'allow secret ["TOKEN"]'
        for body in ('memory.save(env.secret("TOKEN"), 1)', 'let x: Int? = memory.load(env.secret("TOKEN"))',
                     'print(memory.delete(env.secret("TOKEN")))'):
            e = self.d.error(prog(body, head, "memory, secret"), env={"TOKEN": "s3cr3t-value"})
            self.assertEqual(e.kind, "taint", body)

    def test_M7_untrusted_key_in_save_delete(self):
        for body in ('memory.save(fetch("k"), 1)', 'print(memory.delete(fetch("k")))'):
            e = self.d.error(prog(body, AI_HEAD, "ai, memory"), script=["slot"])
            self.assertEqual(e.kind, "taint", body)
        self.assertFalse(os.path.exists(self.d.store()))

    def test_M8_untrusted_key_in_load_labels_result(self):
        self.d.run(prog('memory.save("slot", "echo hi")'))
        e = self.d.error(prog('let v: Str = memory.load(fetch("k")) ?? "echo no"\nprint(shell.run(v))',
                              AI_HEAD + 'allow shell ["echo"]', "ai, memory, shell"), script=["slot"])
        self.assertEqual(e.kind, "taint")
        self.assertIn("untrusted:ai:fetch", e.message)

    def test_M23_map_key_labels_survive(self):
        v = {with_labels("evil", ["untrusted:net:x"]): 1, "ok": with_labels(2, ["untrusted:file:f"])}
        data, paths = M.encode(v)
        self.assertEqual(paths, [[[{"key": "evil"}], ["untrusted:net:x"]], [["ok"], ["untrusted:file:f"]]])
        back = M.decode(json.loads(json.dumps({"value": data, "labels": paths})), T("Map[Int]"), TypeEnv({}, {}), "k")
        ks = {str(k): labels_of(k) for k in back}
        self.assertEqual(ks, {"evil": frozenset({"untrusted:net:x"}), "ok": frozenset()})
        self.assertEqual(labels_of(back["ok"]), frozenset({"untrusted:file:f"}))
        self.assertEqual(list(back), ["evil", "ok"])                     # order kept

    def test_labels_that_no_longer_fit_fail_closed(self):
        entry = {"value": ["go"], "labels": [[[0], ["untrusted:ai:x"]]]}
        tenv = TypeEnv({}, {"Act": [A.Variant(line=0, col=0, name="go", fields=[])]})
        with self.assertRaises(SiparRuntimeError) as cm:
            M.decode(entry, T("List[Act]"), tenv, "k")
        self.assertEqual(cm.exception.kind, "decode")
        with self.assertRaises(SiparRuntimeError) as cm:
            M.decode({"value": [1], "labels": [[[3], ["untrusted:ai:x"]]]}, T("List[Int]"), tenv, "k")
        self.assertEqual(cm.exception.kind, "decode")

    def test_M29_property_labels_round_trip(self):
        rng = random.Random(20261107)
        LABELS = ["untrusted:ai:f", "untrusted:net:h", "untrusted:file:p"]
        tenv = TypeEnv({"R": [("s", T("Str")), ("xs", T("List[Float]")), ("o", T("Int?"))]}, {})

        def leaf(kind):
            v = {"Int": rng.randint(-5, 5), "Float": rng.random(), "Str": rng.choice(["", "a", "я", '"q"'])}[kind]
            if rng.random() < 0.5:
                v = set_labels(v, frozenset(rng.sample(LABELS, rng.randint(1, 2))))
            return v

        def gen(depth):
            r = rng.random()
            if depth > 3 or r < 0.3:
                k = rng.choice(["Int", "Float", "Str"])
                return k, (lambda: leaf(k))
            if r < 0.55:
                ek, eg = gen(depth + 1)
                return f"List[{ek}]", (lambda: [eg() for _ in range(rng.randint(0, 3))])
            if r < 0.8:
                ek, eg = gen(depth + 1)
                return f"Map[{ek}]", (lambda: {leaf("Str"): eg() for _ in range(rng.randint(0, 3))})
            return "R", (lambda: Record("R", {"s": leaf("Str"), "xs": [leaf("Float") for _ in range(2)],
                                               "o": rng.choice([None, leaf("Int")])}))

        def flat(v, path=()):
            if isinstance(v, list):
                return [x for i, y in enumerate(v) for x in flat(y, path + (i,))]
            if isinstance(v, dict):
                out = []
                for k, y in v.items():
                    out.append((path + (("key", str(k)),), labels_of(k), str(k)))
                    out += flat(y, path + (str(k),))
                return out
            if isinstance(v, Record):
                return [x for f, y in v.fields.items() for x in flat(y, path + (f,))]
            return [(path, labels_of(v), v)]

        for _ in range(300):
            ty, g = gen(0)
            v = g()
            data, paths = M.encode(v)
            entry = json.loads(json.dumps({"value": data, "labels": paths}))
            back = M.decode(entry, T(ty), tenv, "k")
            self.assertEqual(flat(back), flat(v), ty)


class TestJournalAndTests(Base):
    def test_M17_replay_serves_without_store(self):
        src = prog('let n: Int = memory.load("c") ?? 0\nmemory.save("c", n + 1)\nprint(memory.keys())\nprint(n)')
        self.d.run(src)
        jp = os.path.join(self.d.dir, "run.jsonl")
        out = self.d.run(src, journal=Journal(path=jp))
        kinds = [json.loads(l)["kind"] for l in _text(jp).splitlines()]
        self.assertEqual(kinds, ["memory.load", "memory.save", "memory.keys"])
        os.remove(self.d.store())
        r = Journal(replay=Journal.load(jp))
        self.assertEqual(self.d.run(src, journal=r), out)
        self.assertEqual(r.unused(), 0)
        self.assertFalse(os.path.exists(self.d.store()))

    def test_M17b_labels_survive_replay(self):
        self.d.run(prog('memory.save("note", fetch("x"))', AI_HEAD, "ai, memory"), script=["echo x"])
        use = prog('let n: Str = memory.load("note") ?? "echo hi"\nprint(shell.run(n))',
                   'allow shell ["echo"]', "memory, shell")
        jp = os.path.join(self.d.dir, "run.jsonl")
        self.assertEqual(self.d.error(use, journal=Journal(path=jp)).kind, "taint")
        os.remove(self.d.store())
        self.assertEqual(self.d.error(use, journal=Journal(replay=Journal.load(jp))).kind, "taint")

    def test_M18_replay_diverges_on_different_save(self):
        jp = os.path.join(self.d.dir, "run.jsonl")
        self.d.run(prog('memory.save("k", 1)'), journal=Journal(path=jp))
        e = self.d.error(prog('memory.save("k", 2)'), journal=Journal(replay=Journal.load(jp)))
        self.assertEqual(e.kind, "replay")

    def test_M27_sipar_test_uses_isolated_memory(self):
        src = ('allow memory\n'
               'fn bump() -> Int uses memory {\n    let n: Int = memory.load("c") ?? 0\n'
               '    memory.save("c", n + 1)\n    return n + 1\n}\n'
               'test "first" {\n    assert bump() == 1\n    assert bump() == 2\n}\n'
               'test "second is fresh" {\n    assert bump() == 1\n}\n')
        prog_, path = self.d.program(src)
        with Prog.__new__(Prog).env():
            p, f = run_tests(prog_, path, out=io.StringIO(), err_out=io.StringIO())
        self.assertEqual((p, f), (2, 0))
        self.assertFalse(os.path.exists(os.path.join(self.d.dir, ".sipar", "memory")))

    def test_M25_concurrent_writers_keep_all_keys(self):
        store = self.d.store()
        code = ("import sys; sys.path.insert(0, sys.argv[1]); from sipar.runtime.memory import FileStore\n"
                "s = FileStore(sys.argv[2])\n"
                "for i in range(40): s.put(sys.argv[3] + str(i), {'value': i, 'labels': []})\n")
        procs = [subprocess.Popen([sys.executable, "-c", code, ROOT, store, w]) for w in ("a", "b", "c")]
        for p in procs:
            self.assertEqual(p.wait(timeout=60), 0)
        keys = M.FileStore(store).keys()
        self.assertEqual(len(keys), 120)


class TestChecker(unittest.TestCase):
    def codes(self, body: str, head: str = "", uses: str = "memory") -> list[str]:
        src = prog(body, head, uses)
        return [d.code for d in check_source(src, "t.sipar")[1] if d.severity == "error"]

    def test_M11_no_expected_type(self):
        for body in ('let x = memory.load("k")', 'print(memory.load("k"))', 'let x = memory.load("k") ?? []',
                     'let x = memory.load("k") ?? none', 'let x = memory.load("k") ?? fail("io", "x")'):
            self.assertEqual(self.codes(body), ["E222"], body)

    def test_M12_expected_type_from_context(self):
        head = ("type Note = { t: Str }\nfn want(n: Note?) -> Int { 1 }\n"
                "fn get() -> List[Str]? uses memory { return memory.load(\"g\") }\n"
                "fn get2() -> Int uses memory { memory.load(\"g\") ?? 3 }")
        for body in ('let x: List[Str]? = memory.load("k")', 'let n = memory.load("k") ?? 0\nlet m: Int = n + 1',
                     'let n: Note = memory.load("k") ?? Note { t: "" }', 'print(want(memory.load("k")))',
                     'let s: Str = memory.load("k") ?? "x"', 'print(memory.load("k") ?? "d")',
                     'let f: Float = memory.load("k") ?? 0'):
            self.assertEqual(self.codes(body, head), [], body)

    def test_M12b_result_is_optional(self):
        self.assertEqual(self.codes('let x: Int = memory.load("k")'), ["E210"])

    def test_M13_missing_allow_and_uses(self):
        src = 'fn main() uses memory {\n    memory.save("k", 1)\n}\n'
        self.assertIn("E302", [d.code for d in check_source(src, "t.sipar")[1]])
        src = 'allow memory\nfn main() {\n    memory.save("k", 1)\n}\n'
        self.assertIn("E301", [d.code for d in check_source(src, "t.sipar")[1]])

    def test_M14_save_fn_value(self):
        self.assertEqual(self.codes('memory.save("k", fn(x: Int) -> Int => x)'), ["E222"])
        self.assertEqual(self.codes('let x: Int? = memory.load("k")\nmemory.save("k", [fn(x: Int) -> Int => x])'),
                         ["E222"])
        self.assertEqual(self.codes('let f: fn(Int) -> Int = fn(x: Int) -> Int => x\n'
                                    'let g: fn(Int) -> Int = memory.load("k") ?? f'), ["E222"])

    def test_save_empty_list_ok(self):
        self.assertEqual(self.codes('memory.save("k", [])\nmemory.save("m", [:])\nmemory.save(key: "a", value: 1)'), [])

    def test_save_wrong_key_type(self):
        self.assertEqual(self.codes('memory.save(1, 1)'), ["E210"])

    def test_M15_allow_memory_takes_no_list(self):
        src = 'allow memory ["x"]\nfn main() uses memory {\n    memory.save("k", 1)\n}\n'
        self.assertIn("E306", [d.code for d in check_source(src, "t.sipar")[1]])

    def test_memory_is_a_reserved_module_name(self):
        self.assertEqual(self.codes('let memory = [1]\nprint(memory.len())', uses="memory"), ["E202"])


class TestMutationSurvivors(unittest.TestCase):
    def test_label_paths_shape(self):
        self.assertFalse(M._valid_paths([[[], "ab"]]))             # labels part must be a list, not a str
        self.assertFalse(M._valid_paths([[[], 3]]))
        self.assertTrue(M._valid_paths([[["a", 0, {"key": "k"}], ["untrusted:x"]]]))

    def test_memstore_delete_result(self):
        st = M.MemStore()
        self.assertFalse(st.delete("nope"))
        st.put("k", {"value": 1})
        self.assertTrue(st.delete("k"))
        self.assertFalse(st.delete("k"))

    def test_corrupt_store_message(self):
        d = tempfile.mkdtemp(prefix="sipar_memmut_")
        try:
            p = os.path.join(d, "m.json")
            with open(p, "w") as fh:
                fh.write("{oops")
            with self.assertRaises(SiparRuntimeError) as cm:
                M.FileStore(p).get("x")
            self.assertTrue(cm.exception.message.endswith("(it was not changed)"), cm.exception.message)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
