"""Round 13. (1) The value under a labelled key in a map literal is a write at a labelled position (SPEC §6), like
`m[k] = v`: `["safe": "ls", k: "id"]` let a model-chosen key replace the value under a fixed key with an unlabelled
one, which then reached shell.run. (2) A sweep: every built-in function, method and operator that returns data
computed from a model-chosen Str or Int keeps the label up to the shell; the passes SPEC §6 documents (Bool,
`filter` with a labelled test, loop counts, another field of a record) are pinned too."""
import io
import unittest

from rt_helpers import Prog

HEAD = ('allow ai\nallow io\nallow random\nallow env ["b"]\nallow shell ["echo"]\nallow fs.read ["data"]\n'
        'allow memory\n'
        'type P = { name: Str, k: Int }\nenum R { bad, ok(v: Str) }\n'
        'ai fn gs(q: Str) -> Str { "{q}" }\nai fn gi(q: Str) -> Int { "{q}" }\n'
        'fn idf(x: Str) -> Str { x }\n'
        'fn main() uses ai, io, random, env, shell, fs.read, memory {\n let u = gs("s")\n let n = gi("n")\n'
        ' let xs = ["a", "b", "c"]\n let m = ["a": "x", "b": "y"]\n var r = ""\n')
SINK = '\n print(shell.run("echo {r}"))\n}\n'

# `let q = <expr>` with u = "b" and n = 2 chosen by a model: "echo {q}" must not reach the shell
EXPRS = '''min(n, 5) | min(5, n) | max(n, 1) | max(1, n) | abs(n) | round(n * 1.0) | floor(n * 1.0)
range(0, n) | range(n, 5) | range(0, n).len() | range(n, 5).len() | range(0, n).last() ?? 0
json.encode(u) | json.encode([n]) | json.encode(["k": u]) | random.int(n, n) | random.int(1, n) | env.get(u) ?? "none"
u.len() | u.upper() | u.lower() | u.trim() | u.split(",") | "a,b,c".split(u) | "a,b,c".split(u).len() | u.lines()
u.replace("b", "z") | "abc".replace(u, "z") | "abc".replace("a", u) | u.find("b") ?? 9 | "abc".find(u) ?? 9
u.repeat(2) | "x".repeat(n) | "x".repeat(n).len() | "abc"[n] | xs[n] | m[u] | m.get(u) ?? "none" | m.remove(u) ?? "none"
[u].pop() ?? "" | xs.map(fn(s) => s + u) | xs.reduce(u, fn(a, s) => a + s) | [n].reduce(0, fn(a, x) => a + x)
xs.join(u) | [u, "k"].join(",") | [u, "a"].sort() | [n, 1].sort() | [u, "a"].sort_by(fn(s) => s) | [u, "a"].reverse()
xs.index_of(u) ?? 9 | [u].index_of("b") ?? 9 | [u].first() ?? "" | [u].last() ?? "" | [n, 1].sum()
xs.take(n) | xs.skip(n) | xs.take(n).len() | xs.skip(n).len() | xs.take(n).last() ?? "" | [u, "a"].take(1)
["k": u].values() | ["k": u].get("k") ?? "" | [u: "v"].keys() | [u: "v"].keys().join("") | [u: "v"].values()
u + "x" | "{u}" | n + 1 | n * 2 | n % 5 | 0 - n | n as Str | n as Float | ("4" + (n as Str)) as Int | u[0]
xs.sort_by(fn(s) => s + u) | [u].len() | [u: "v"].len() | xs.map(fn(s) => s + u).len() | u.split("").len()
[u, u].join("").len() | xs.take(n).join("") | xs.skip(n).first() ?? "" | "abc".replace(u, "").len() | xs.index_of(u)
"abc".find(u) | m.keys().take(n) | m.values().skip(n) | range(0, n).map(fn(i) => i * 0).len() | range(0, n).sum()
range(0, n).reverse() | range(n, 5).first() ?? 0 | "a".repeat(n).split("").len() | json.encode(n).len()'''

# statements that end with the result in `r`
BODIES = {
    "catch: fail message": 'try { fail(u) } catch e { r = e.message }',
    "catch: fail kind": 'try { fail(u, "m") } catch e { r = e.kind }',
    "catch: decode message": 'try { let z = (u + "x") as Int\n print(z) } catch e { r = e.message }',
    "catch: assert message": 'try { assert n > 99, u } catch e { r = e.message }',
    "catch: index message": 'try { r = xs[n + 50] } catch e { r = e.message }',
    "catch: message length": 'try { fail(u) } catch e { r = e.message.len() as Str }',
    "closure": 'let f = fn(x) => x + u\n r = f("a")',
    "user function": 'r = idf(u)',
    "record field": 'let p = P { name: u, k: 1 }\n r = p.name',
    "enum payload": 'let e = R.ok(u)\n r = match e { R.ok(v) => v, R.bad => "bad" }',
    "list slice": 'r = xs[0..n].join("")',
    "list slice length": 'r = xs[0..n].len() as Str',
    "string slice": 'r = "abcdef"[0..n]',
    "for over a range: last item": 'var last = 0\n for i in 0..n { last = i }\n r = last as Str',
    "for over a range: items": 'for i in 0..n { r = r + (i as Str) }',
    "for over a list": 'for s in [u, "k"] { r = r + s }',
    "for over take(n)": 'for s in xs.take(n) { r = r + s }',
    "for over a map with a labelled key": 'let m2 = ["safe": "ls", u: "id"]\n for k in m2 { r = r + m2[k] }',
    "file picked by name": 'r = fs.read("data/" + u)',
    "typed input": 'r = input("? ")',
    "if expression": 'r = if n > 1 { u } else { "x" }',
    "match arm": 'r = match u { "b" => u + "!", _ => "x" }',
    "write at a labelled index": 'var ys = ["a", "b", "c"]\n ys[n] = "id"\n r = ys[2]',
    "push after": 'var ys = [u]\n ys.push("k")\n r = ys.first() ?? ""',
    "push of": 'var ys = ["k"]\n ys.push(u)\n r = ys.last() ?? ""',
    "list concat length": 'r = ([u] + xs).len() as Str',
    "sorted first": 'r = [u, "a"].sort().first() ?? ""',
    "nested list length": 'r = [[u]].len() as Str',
    "coalesce": 'let o = xs.index_of(u)\n r = (o ?? 7) as Str',
    "times zero": 'r = (n * 0) as Str',
    "divide": 'r = (n / 1) as Str',
    "negate": 'r = (-n) as Str',
    "float text": 'r = (n as Float) as Str',
    "char by index": 'r = "abc"[n] + ""',
    "json of a map": 'r = json.encode(["a": n])',
    "map literal values": 'let m2 = ["safe": "ls", u: "id"]\n r = m2.values().join(",")',
}

# SPEC §6, by design: Bool is never labelled, `filter` with a labelled test and loop counts are implicit flows,
# and a label on one field of a record does not spread to the others
PASSES = {
    "filter with a labelled test": ('r = xs.filter(fn(s) => s == u).join("")', "b"),
    "contains": ('r = xs.contains(u) as Str', "true"),
    "has": ('r = m.has(u) as Str', "true"),
    "another field of the record": ('let p = P { name: "lit", k: n }\n r = p.name', "lit"),
    "loop count over a range": ('var c = 0\n for i in 0..n { c = c + 1 }\n r = c as Str', "2"),
    "loop count over take(n)": ('var c = 0\n for s in xs.take(n) { c = c + 1 }\n r = c as Str', "2"),
}


class Base(unittest.TestCase):
    def prog(self, body):
        p = Prog(HEAD + " " + body + SINK, files={"data/b": "plain"})
        self.addCleanup(p.cleanup)
        return p

    def args(self, s="b", n=2):
        return {"script": {"gs": [s], "gi": [n]}, "env": {"b": "val"}, "stdin": io.StringIO("typed\n")}

    def blocked(self, body, **kw):
        e = self.prog(body).error(**self.args(**kw))
        self.assertEqual(e.kind, "taint", str(e))
        self.assertIn("cannot flow into shell.run(cmd)", str(e))

    def passes(self, body, want, **kw):
        self.assertEqual(self.prog(body).run(**self.args(**kw)).strip(), want)


class T_MapLiteral(Base):
    LIT = 'let m2 = ["safe": "ls", u: "id"]\n '

    def test_model_key_replaces_the_fixed_value(self):
        for name, read in (("index", 'r = m2["safe"]'), ("get", 'r = m2.get("safe") ?? "none"'),
                           ("values", 'r = m2.values().join(",")'), ("for", 'for k in m2 { r = r + m2[k] }')):
            with self.subTest(name):
                self.blocked(self.LIT + read, s="safe")

    def test_same_as_assignment(self):
        self.blocked('var m3 = ["safe": "ls"]\n m3[u] = "id"\n r = m3["safe"]', s="safe")

    def test_list_value_under_a_labelled_key(self):
        self.blocked('let m2 = ["safe": ["ls"], u: ["id"]]\n r = m2["safe"][0]', s="safe")

    def test_another_key_leaves_the_fixed_value_plain(self):
        self.passes(self.LIT + 'r = m2["safe"]', "ls", s="other")

    def test_literal_keys_stay_plain(self):
        self.passes('let m2 = ["safe": "ls", "k": "id"]\n r = m2["k"]', "id")

    def test_bool_under_a_labelled_key_stays_plain(self):
        self.passes('let fl = [u: true]\n if fl.get("safe") ?? false { r = "yes" }', "yes", s="safe")


class T_Sweep(Base):
    def test_expressions_keep_the_label(self):
        exprs = [e.strip() for line in EXPRS.splitlines() for e in line.split(" | ")]
        self.assertEqual(len(exprs), 94)
        for expr in exprs:
            with self.subTest(expr):
                self.blocked(f'let q = {expr}\n r = "{{q}}"')

    def test_statements_keep_the_label(self):
        for name, body in BODIES.items():
            with self.subTest(name):
                self.blocked(body)

    def test_documented_passes(self):
        for name, (body, want) in PASSES.items():
            with self.subTest(name):
                self.passes(body, want)


if __name__ == "__main__":
    unittest.main()
