# Sipar 0.1 — language specification

Sipar (Tajik/Persian «сипар» = *shield*) is a statically typed language for writing AI-agent programs
that are **safe by construction, typed end to end, budgeted, and exactly replayable**.

Design pillars
1. **Typed AI.** `ai fn` turns a prompt into a function with a real return type. The runtime derives a JSON
   schema from the type, validates the model's answer and retries with the validation error.
2. **Capabilities.** A program can only touch what its `allow` lines grant (hosts, paths, commands).
   Every function declares its effects with `uses`; the checker proves callers declare what callees use.
3. **Information-flow control (anti prompt-injection).** Data from AI, network, files and shell is
   *untrusted*. Untrusted data can be computed with, but can never reach a dangerous sink
   (`shell.run`, `fs.write`, `http.get/post` URL and body) unless explicitly declassified by
   `trust(x, "reason")` or a human `approve(x, "question")`. Secrets (`env.secret`) can never flow into
   prompts, prints, files or journals.
4. **Budgets.** `budget(ai_calls:, tokens:, usd:, seconds:) { ... }` is a hard limit enforced by the runtime.
5. **Journal + exact replay.** Every nondeterministic effect is recorded. `sipar replay` re-runs a program
   offline with byte-identical effect results and reports the first divergence.
6. **Agents are a construct.** `agent fn` runs a tool-calling loop; tools are ordinary typed functions,
   and every tool call passes the same capability, taint and budget checks.
7. **Built for LLM authors.** Small regular grammar, one way to do things, JSON diagnostics with codes
   and fix hints (`sipar check --json`), and `sipar spec` prints the full reference (this file plus generated tables) to paste into prompts.

## 1. Lexical
- Source is UTF-8; a leading byte-order mark is ignored. Outside strings and comments the source is ASCII:
  any other character (also Unicode letters and digits such as `١٢`) is E101.
- Comments: `// line`. Doc comments `/// text` attach to the next item (used as tool descriptions).
- Identifiers `[A-Za-z_][A-Za-z0-9_]*`. Keywords:
  `fn ai agent type enum let var if else while for in match return break continue try catch budget
   allow uses test mock assert and or not true false none as tools`.
- Numbers: `42`, `3.14`, `1_000` (`_` only between two digits). An Int literal has at most 14,000 bits
  (about 4200 digits, the runtime Int limit; more is E101 "integer literal too large"). Strings: `"..."` with escapes `\n \t \r \0 \" \\ \{ \}` (`\r` is a carriage return, `\0` the NUL character) and interpolation
  `{expr}`. Triple-quoted `"""..."""` strings may span lines; common leading indentation is removed and
  one leading/trailing blank line is dropped.
- Statements end at a newline or `;`. A newline is ignored inside `( )` and `[ ]`, after a binary operator,
  `,`, `=`, `=>`, `->`, `{`, and before a line that starts with `.` (method chains), `)` `]` `}`.
- Nesting limits (E115 "nested too deeply"): at most 256 levels of brackets, blocks, calls, types and
  patterns inside each other (the function body counts as one; a `{ }` block or `if` used as a value counts
  as two, the block and the expression it sits in, so about 127 such blocks), at most 16 strings nested
  through interpolations, and no chain of operators, fields, indexes or calls deeper than 10,000 levels.
  Long flat chains are fine (`1 + 2 + ... + 500`). The checker accepts every program the parser accepts;
  `sipar check --json` stays JSON for such files.

## 2. Types
`Int Float Str Bool None`, `List[T]`, `Map[T]` (keys are `Str`), `T?` (optional), `fn(A, B) -> R`,
records `type Name = { field: T, ... }`, enums `enum Name { a, b(field: T, ...) }`.
`Int` widens to `Float` implicitly wherever the checker expects a `Float`: `let`/`var` with a type,
assignment, arguments (also `push`), `return` and a fn or lambda body, list/map/record literals (an element
type joins `Int` and `Float` to `Float`), `if`/`match`/`try` arms, both sides of `??`, a function value used
as `fn(...) -> Float` or `fn(Float) -> ...`, and so the value `json.encode` and the Python API see. The value
really becomes a `Float` at run time (`let x: Float = 2; x / 4` is `0.5`; `print` shows `2.0`). Containers are
invariant: an existing `List[Int]` is not a `List[Float]`, and only the items of a literal itself widen:
`[1, 2.5]` is a `List[Float]`, but `[[1], [2.5]]` is E218 and `[0.5] + [3]` is E214 (the hint says to write
`3.0`). Function parameters are contravariant: a `fn(Float) -> T` is accepted where a `fn(Int) -> T` is
expected, so `[1, 2].map(half)` with `fn half(x: Float) -> Float` is a `List[Float]`. An Int too large for a
Float is error kind `value`.

## 3. Items
```sipar
allow ai
allow net ["wttr.in", "api.github.com"]     // host allow-list (exact host or *.suffix)
allow fs.read ["./data"]                    // path prefixes, relative to the program file
allow fs.write ["./out"]
allow shell ["ls", "git status"]            // command prefixes
allow env ["HOME"]                          // env.get names; also passed to shell.run
allow secret ["OPENROUTER_API_KEY"]         // env.secret names (a list is required)
allow memory                                // labelled persistent memory (no list)
allow mcp "fs" ["npx", "-y", "@modelcontextprotocol/server-filesystem", "./data"]
    tools ["read_text_file", "write_file"] readonly ["read_text_file"]   // an MCP server (§7a)
// The checker validates every entry: E310 (error) for an empty entry, a net entry with a scheme, path or
// port outside 1..65535, spaces around it, more than one ':' (IPv6 goes in brackets: "[::1]:8080"), a shell
// entry that does not parse, an env/secret entry that is not a variable name; E311 (warning) for net "*"
// (matches no host), net "*.com" (a whole top-level domain), "*.co.uk"-style public suffixes, and an fs
// entry that resolves (realpath against the program folder) to "/", the home folder or a folder above the
// program, or starts with "~". The runtime reads entries with the same parser: an entry the checker rejects
// grants nothing, and it is never trimmed.

type Review = { score: Int, verdict: Str, issues: List[Str] }
enum Mood { happy, sad, neutral }
enum Action { search(query: Str), answer(text: Str) }

/// Adds two numbers.
fn add(a: Int, b: Int) -> Int { a + b }

@retries(3) @temperature(0.2) @model("openrouter/qwen/qwen3-coder")
ai fn review(code: Str) -> Review {
    """
    Review this code and score it 1-10:
    {code}
    """
}

enum City { dushanbe, london, tokyo }

/// Weather in one city (a tool for the agent below). An enum argument is a choice, never model text, so it
/// may go into a URL; a Str argument from the model would be untrusted there (§6).
fn weather(city: City) -> Str uses net { http.get("https://wttr.in/{city}?format=3") }
/// The latest issues of one fixed repository.
fn cpython_issues() -> Str uses net { http.get("https://api.github.com/repos/python/cpython/issues?per_page=5") }

@max_steps(8)
agent fn researcher(goal: Str) -> Str uses net {
    tools [weather, cpython_issues]
    "You are a careful researcher. Goal: {goal}"
}

fn main() uses ai, net { print(review("x = 1").score) }

test "review is parsed" {
    mock review(code) => Review { score: 9, verdict: "ok", issues: [] }
    assert review("x").score == 9
}
```
- Effects: `ai net fs.read fs.write shell env secret time random io memory mcp`. `ai fn` and `agent fn` implicitly use `ai`;
  an `agent fn` also uses every effect of its tools. `print` needs no effect; `input` uses `io`.
- `fn main()` (optionally `main(args: List[Str])`) is the entry point. It may use only allowed effects.
- Top-level `let NAME = expr` defines a constant (pure expression).
- Attributes `@name(literal)` before `ai fn`/`agent fn`: `model`, `retries` (default 2), `temperature`,
  `max_steps` (agent, default 10), `system` (extra system text).
- `@model("a | b | c")` is a **fallback chain**: models are tried left to right; the next one is tried only
  when a model fails with a provider error (error kind `ai`: HTTP error of any status, timeout, connection
  refused, missing API key, unusable reply). A reply that does not decode into the return type is retried on
  the *same* model (`@retries`), not passed down the chain. `budget` and `taint` errors are never swallowed.
  Every attempt is a separate journal entry and counts as an ai call in `budget`. If all fail: error kind
  `ai` "every model in the chain failed: m1: ...; m2: ...". `SIPAR_MODEL` accepts the same syntax.
  An empty element or unknown provider is checker error E231 (for `@model`) or error kind `ai` (env).

## 4. Statements and expressions
```sipar fragment
let x = 1            let y: Float = 2      var n = 0      n = n + 1    p.score = 3   xs[0] = 4
if c { } else if d { } else { }            while c { }            for x in xs { }   for i in 0..10 { }
for k in map_value { }                      return e   break   continue          assert c, "msg"
try { } catch e { e.kind; e.message }       budget(ai_calls: 5, seconds: 30) { }
```
- Blocks are expressions: the value of a block is its last expression statement (else `none`).
  `if`/`match`/`try`/`budget` can be used as expressions: `let m = if a > b { a } else { b }`.
- Operators (low → high): `??` · `or` · `and` · `not` · `== != < <= > >= in` · `..` · `+ -` · `* / %` ·
  unary `-` · `as` · postfix `() [] .field`.  `/` on two `Int` is integer division (floor); `%` is floor mod.
  `+` on `Str` concatenates; on `List` appends lists.
  `==` compares values (lists item by item, maps whatever the key order, records and enum payloads field by
  field; `1 == 1.0`). A NaN equals nothing, itself included, wherever it stands: `nan == nan`,
  `[nan] == [nan]` (even the same NaN in both), `[nan].contains(nan)`, `index_of(nan)` and `nan in [nan]`
  are all false (IEEE; `!=` is the opposite of `==`).
- Calls take positional then named arguments: `f(1, b: 2)`. Named arguments match parameter names.
- Literals: `[1, 2]`, `[:]` (empty map), `["a": 1]`, `Review { score: 1, verdict: "", issues: [] }`,
  `Mood.happy`, `Action.search(query: "x")` or `Action.search("x")`, lambdas `fn(x: Int) -> Int => x * 2`
  (parameter/return types may be omitted when the expected type is known).
- `match v { pattern => expr_or_block, ... }` with patterns `_`, literals, `none`, a binding name,
  `Enum.variant`, `Enum.variant(p1, p2)`. The checker requires exhaustive enum matches (or `_`). The proof
  takes at most 200,000 steps; a match too complex to prove gets warning E408 instead (add a `_` arm).
- `x as T`: Str→Int/Float/Bool parse, Int↔Float, anything→Str (render), and **Str→record/enum/List/Map
  decodes JSON and validates against T** (error kind `decode`). Str→Float takes an optional sign and a
  number written as in a literal (`_` only between digits, never in the exponent), plus `.5` and `5.`:
  `"1_0.5"` is 10.5, `"1_0e1_0"` is `decode`. A well-formed Int above about 4200 digits — from `as Int`, a
  JSON value or a model reply — is error kind `value` ("number too large for Int"). Decoded JSON nested more
  than 20,000 levels deep (each list, map or record is a level) is error kind `decode`.
- Optional chaining is not provided; use `??` or `match`.

## 5. Standard library (v0.1)
Methods — Str: `len upper lower trim split(sep) lines contains(s) starts_with(s) ends_with(s)
replace(old, new) find(s)->Int? repeat(n)` and slicing `s[a..b]`, indexing `s[i]`.
List: `len push(item) pop()->T? map(f) filter(f) reduce(init, f) any(f) all(f) join(sep) sort() sort_by(key)
reverse() contains(item) first()->T? last()->T? sum() take(n) skip(n) index_of(item)->Int?` and slicing `xs[a..b]`.
A list holds at most 10,000,000 items (`+`, `push`, literals, ranges, `split`, `lines`); more is error kind
`value`. A Str holds at most 100,000,000 characters: `+`, interpolation (`"{s}{s}"`), `join`, `upper`/`lower`
and the text of a value (`print`, `"{x}"`, `x as Str`) that would be longer are error kind `value` "string too
large", raised before the text is built (`repeat` and `replace` stop at 10,000,000 characters). A list, map,
record or enum value whose JSON text would pass 100,000,000 characters — counting a shared part each time it
is written out — is error kind `value` "value too large" wherever it is turned into text or data (`print`,
`json.encode`, a prompt, the journal, the Python API), found before anything is copied. `xs.sum()` has the
Int limit of `+` (about 4200 digits, error kind `value`). `s.lines()` breaks only at `\n`, `\r\n` and a lone `\r` (never at form feed, U+0085, U+2028 and
the like), and a final line break does not start another line: `"a\r\nb\n".lines()` is `["a", "b"]`.
`sort()` and `sort_by(key)` put NaN after every number (NaNs keep their order), wherever it stood.
Floats are finite: a literal that overflows (`1e400`) is a syntax error (E101, "float literal out of range");
`"nan" as Float`, `"inf" as Float`, `"1e400" as Float` are error kind `decode` (the same rule as JSON
decoding); `json.encode` of a NaN or infinite number (which arithmetic can produce, e.g. `1e308 * 10.0`) is
error kind `value`, never the non-JSON `NaN`/`Infinity`.
Text is always valid Unicode: a lone surrogate (an unpaired `\ud800`..`\udfff` escape) never becomes a Str.
In JSON decoded with `as` and in a Python API argument it is error kind `decode`
("text holds a lone surrogate ..."); in text from outside (program arguments, environment variables,
stdin, model and mock replies) each one is replaced by U+FFFD, like a byte that is not UTF-8 (`input()` and
`approve` read stdin as UTF-8 with every invalid byte as U+FFFD, and the journal holds that text); a journal line
holding one is error kind `replay`, a memory store holding one is error kind `io` (the file is not changed).
The exact method table lives in `sipar/stdlib.py` and is printed by `sipar spec`.
Map: `len keys values has(key) get(key)->T? remove(key)`.
Functions: `print(value)`, `min(a, b) max(a, b) abs(x) round(x) floor(x)` (Int/Float; `round` is exact
half away from zero: `round(2.5)` = 3, `round(-2.5)` = -3, `round(0.49999999999999994)` = 0;
`min`/`max` with a NaN argument give NaN in either order, and `min(0.0, -0.0)` is `-0.0`),
`range(start, end)`, `sleep(seconds)` (time; `seconds` must be a finite number from 0 to 86400, else error
kind `value` — checked the same way on replay, before the time budget),
`xs.sum()` of an empty list is `0`, or `0.0` for a `List[Float]`.
`print` writes text byte-exact to a pipe or file; on a terminal, control and bidi characters are shown
escaped (`\x1b`, `\u202e`, and the invisible `\u200b`, `\u2060`-`\u2069`, `\ufeff`; newline and tab stay;
the joiners `\u200c`/`\u200d` stay so emoji and scripts still draw), so printed data cannot drive the terminal or
hide characters. `input`
prompts are escaped the same way, error messages always are, and `approve` resets the terminal first.
`http.get(url, headers: Map[Str]) -> Str` (net), `http.post(url, body, headers: Map[Str]) -> Str` (net),
`fs.read(path) -> Str` (fs.read), `fs.write(path, text)` (fs.write), `fs.exists(path) -> Bool` (fs.read),
`shell.run(cmd) -> Str` (shell), `env.get(name) -> Str?` (env), `env.secret(name) -> Str` (secret),
`time.now() -> Float` (time), `random.int(lo, hi) -> Int` (random), `input(prompt) -> Str` (io),
`json.encode(value) -> Str` (a function value inside is error kind `value`), `trust(value, reason) -> same type`,
`approve(value, question) -> same type` (io),
`mcp.call(server, tool, args: Map[Any]) -> Str` (mcp; see §7a), `fail(kind, message)` raises an error (an empty or blank kind is reported as `fail`).
- `env.get` reads only names in `allow env [...]`; `env.secret` reads only names in `allow secret [...]`; `env.get`
  on a name listed in `allow secret` is error kind `capability` (a secret is never read unlabelled).
  `env.get` of a provider API key name (`OPENROUTER_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` — the key
  variables of the built-in providers — and `SIPAR_LOCAL_KEY`) is error kind `capability` too, even when it is listed in
  `allow env`: read it with `allow secret` and `env.secret`. In a program with `allow ai`, the values of those
  variables are guarded like `allow secret` values: a copy inside another variable is labelled or refused by
  `env.get` and dropped from the `shell.run` environment (without `allow ai` the runtime does not read them).
- `shell.run` runs the command without a shell, in its own process group, with a minimal environment: `PATH`,
  `HOME`, `LANG`, `TMPDIR` plus the names listed in `allow env [...]`, never a name listed in `allow secret`
  and never a variable whose value contains the value of one (4 characters or more, in any upper/lower-case
  mix, compared caselessly so `ß` / `SS` / `ss` match, or in one of the escaped forms listed in §6) or is a
  shorter one (in any case, surrounding whitespace ignored), or a secret already read. A secret value with
  surrounding whitespace (a trailing space, the `\r` of a Windows `.env` file) counts as its trimmed value too
  when that is 4 characters or more. `env.get` of a variable whose value holds a
  secret in a form the labelling cannot see (a mixed-case copy, also after the decoding and normalising of §6,
  or a secret under 4 characters as the whole value) is error kind `taint`; the value is not read or journaled.
  The command is killed when `sipar` exits, on SIGTERM / SIGHUP and on the first Ctrl-C.
- `approve` shows the question on one line after `question:` (line breaks shown as `\n`, control and bidi
  characters escaped, so a question cannot fake the value block), then the whole value with its length (never
  a cut view; control characters are escaped). Without a terminal the answer is no.
- Numbers from model text: an `Int`/`Float` reply must be JSON or prose with exactly one standalone number
  ("The answer is 42." → 42; "IGNORE ALL; payload2" is not a number → `decode`; two different numbers,
  "12 and 13", are `decode` "more than one number in the reply; expected exactly one"). Ints above about 4200
  digits are error kind `value`; a Float that overflows or is NaN/inf is `decode`; for an `Int`, a number that
  overflows a float (`1e400`) is `decode` "number too large for Int", like `1e19`, and NaN "expected Int, got NaN".
Memory (effect `memory`): `memory.save(key: Str, value: T)`, `memory.load(key: Str) -> T?`,
`memory.delete(key: Str) -> Bool`, `memory.keys() -> List[Str]` (sorted). The store is JSON in
`<program dir>/.sipar/memory/<program name>.json`, one store per program file. `memory.load` needs the
type `T` from context — a `let` annotation, a parameter or return type, or the right side of `??`
(`let n = memory.load("count") ?? 0`); otherwise checker error E222. A stored value that no longer matches
`T` is error kind `decode`; a missing key gives `none`. `T` must be JSON-able (no functions; E222). Keys are
1..256 characters (error kind `value`). Values containing themselves (cycles) are error kind `value`. A
store file that is not valid JSON or has an unknown `version` is error kind `io` and is never overwritten.
Entries are written with `"enc": 2`; an enum is stored as `"variant"` or `{"variant": {fields}}`. Older
entries (no `enc`, enums as `{"tag": "variant", ...}`) still load when that is unambiguous; an old entry for
an enum that has a field named `tag` is error kind `io` (never a guessed variant). A store file or stored
value nested too deeply to read (more than 20,000 levels) is error kind `io`; `memory.save` of such a value is
error kind `value`.
Writes are atomic (temp file + rename, under an flock), so concurrent runs keep each other's keys. Once a
store file is over 8 KiB, later writes are appended to `<stem>.json.log` (one fsynced JSON line per save or
delete) and folded into the store file when the log grows past it, so N saves cost O(N), not O(N²). A log
line cut short by a crash and blank lines are ignored; a log that is not valid (any line other than
`{"k": key, "e": {entry}}`, `{"k": key, "d": 1}` and its header) is error kind `io` and is never
overwritten. Reads take a shared flock, writes an exclusive one.
The log belongs to one store file: every full write stamps the store file with a new random `"gen"`, and
the log's first line is `{"g": gen}` of that store. A log is applied only on top of the store file with the
same gen. So deleting `<stem>.json` deletes the whole memory: a log left next to no store file, or next to
a store file with another gen, is ignored and removed by the next write (it never brings old keys back).
Deleting only `<stem>.json.log` drops the saves it held. A store file without `"gen"` and a log without a
header (written before round 7) still load together; the next write stamps the store file. A log without a
header next to a stamped store file is error kind `io` — except the one log a round-6 upgrade already
folded in: the upgrade records the SHA-256 of that log as `"merged"` in the stamped store, so a crash between
"replace the store file" and "remove the log" leaves a log that is skipped (and removed by the next write);
any other header-less log there is still the `io` error (round 8).
The store file, its log and `<stem>.json.lock` must be regular files: a FIFO, a device (a symlink to
`/dev/zero`) or a store file or log over 1 GiB is error kind `io` naming the file (`not a regular file`,
`too large (...)`), never read, never a hang; no write makes either file larger than 1 GiB (the save is
error kind `io` "would be larger than 1024 MB"). Writes never follow a symlink (round 9): a log or lock that is a
symlink (also a dangling one) or a store file that is one makes a write error kind `io` naming the file (`not a
regular file (a symbolic link)`); nothing is created or written where the link points. A store file reached
through a symlink is still read. A stored entry that is not `{"value": ..., "labels": [...]}`
(also a hand-edited `null`, a labels path longer than 20,001 steps, or an `"enc"` that is not the integer 1 or 2)
is error kind `io` "memory entry 'k' is malformed" (or "has an unknown encoding") on `memory.load`, journaled,
so replay gives the same error; `memory.keys()` lists such a key and `memory.delete` removes it (true).
In `sipar test` memory lives in RAM and starts empty in every test.

## 6. Information-flow rules
- Labels: `untrusted:<source>` and `secret:<name>`. Sources: `ai fn` results, agent results, `http.*`
  results, `fs.read`, `shell.run`, `input`. Labels propagate through every operation, string
  interpolation, container construction, method results and `as` conversions.
- **An echoed secret stays a secret.** Text that enters from a source — `http.*`, `fs.read`, `shell.run`,
  `input`, `env.get`, `ai fn` and agent replies (and the arguments a model gives to tools), `memory.load` and
  `memory.keys` — gets the label `secret:NAME` when it contains a live secret value of 4 or more characters
  (in any registered form: see the redaction rule below) or its `«secret:NAME»` marker, map keys included;
  so does an `Int` / `Float` whose decimal digits contain such a value. Replay sees the marker in
  the journal, so record and replay take the same path.
- **Choice declassification:** `Bool` values and payload-free enum values are never labelled
  (a closed set chosen by the programmer cannot carry injected instructions).
- **Selection carries labels.** A value picked out of a container with a labelled index, key, count or bound
  carries those labels plus the container's own labels: `xs[i]`, `xs[a..b]`, `m[k]`, `m.get(k)`,
  `m.remove(k)`, `xs.take(n)`, `xs.skip(n)`, `xs.sort_by(f)` (labels of the keys `f` returned), `xs.sort()`
  (order depends on every item), and everything later pulled out of such a pick (`first`, `last`, `pop`,
  `[j]`, `for`, `map`, `filter`, `reduce`, `keys`, `values`, `len`, a field of a picked record, the result of a
  picked function). So `m[r.k]` and `m.get(r.k)` behave the same, and a secret cannot be copied out character by
  character through a lookup table (`abc.get(key[i])`) or a ruler (`al.take(n).last()`). A picked list or map
  is a read-only copy: changing it (`let g = m[k]; g.push(x)`) is error kind `value` (change it through its
  container, `m[k].push(x)`, which changes the original); a picked record is a view, so `xs[i].f = v` and
  `let t = xs[i]; t.f = v` change the original. A value written at a labelled position (`xs[i] = v`,
  `m[k] = v`, the value under a labelled key in a map literal `[k: v]`, a field or push through a labelled
  pick) gets the position's labels (a Str/Int/Float or record;
  a list, map or enum with a payload is stored as a copy whose items carry them, so a labelled key cannot pick
  a whole command; structure — which keys exist, list length — is not labelled).
  The same holds for built-ins that pick a value by an argument: `random.int(lo, hi)` carries the labels of
  both bounds (`random.int(n, n)` is `n`), and `env.get(name)` / `env.secret(name)` carry the labels of
  `name`, as `memory.load(key)` carries the labels of `key`.
  **Decision: choice declassification still applies to selection.** A `Bool`, `none` or payload-free enum
  value picked with a labelled key stays unlabelled. Justification: labelling them would also have to label
  every `if`, `match` and comparison on labelled data (Sipar does not track implicit flows), so it would close
  no channel that `if key[i] == "a" { ... }` leaves open, while it would make every closed-set lookup
  (`allowed[action]`, `flags.get(name)`) unusable as a guard. The cost is bounded and visible in the code: one
  such lookup reveals at most which of the programmer's own closed values was chosen (1 bit for a Bool), the
  same as one comparison; a leak needs a loop of lookups, the known implicit-flow limitation below. Likewise
  `filter` with a labelled test and loop counts are implicit flows (not labelled).
- Sinks requiring *no untrusted label*: `shell.run(cmd)`, `fs.write(path, text)`, `http.get(url)`,
  `http.post(url, body)` and the `headers:` of both (the map itself, every name, every value).  Violation =
  runtime error kind `taint` (before the effect happens).
- Sinks forbidding *secret*: prompts of `ai fn`/`agent fn`, `print`, `fs.write`, `json.encode`, and **every
  parameter of every effectful stdlib function** (paths, URLs, bodies, commands, names, prompts, memory keys
  and values, `approve`, `sleep`, `random`, ...) except the `headers:` values of `http.get/post` — the only
  place a secret may go. Header names may not be secret.
- **Secrets are redacted everywhere text leaves the runtime:** every error message (whoever produced it),
  tool-error text fed back to an agent's model, `print` of an error, CLI error output and every journal entry.
  Each active secret value — and its trimmed value when it has surrounding whitespace (4 characters or more),
  the upper-case, lower-case and case-folded forms of both (`ß` → `SS`, `ss`), and the repr-, bytes-repr-,
  JSON- (with and without `\/` for `/`) and percent-encoded (`%2F` and `%2f`; `/` kept or encoded; space as
  `%20` or `+`) forms of those — is replaced by `«secret:NAME»` (forms under 4 characters are not).
  The same search (and the labelling of effect results, e.g. an HTTP body that echoes a secret) also runs on a
  decoded view of the text, mapped back to the original characters: one level of JSON / Python backslash
  escapes (`\u0026` or `\u002B` in any hex case, surrogate pairs, `\xNN`, `\"`, `\/`, `\\`), HTML entities
  (named ones with `;`, decimal and hex numeric ones with or without `;` and with any number of leading
  zeros), percent-encoded UTF-8 in any hex
  case; invisible characters (zero-width space / joiners, soft hyphen, BOM, other default-ignorable ones) are
  dropped, and every character is compared in its compatibility-decomposed form (NFKD), so an NFD / NFC /
  full-width copy matches. Overlapping matches of different secrets are redacted as one union (one marker per
  secret, in order; a match inside a longer one keeps only the outer marker).
  **Not seen:** a mixed-case copy other than those three forms (only `env.get` and `shell.run` compare
  caselessly), double or nested encoding (`%2526`, `\\u0026`), base64 / hex dumps / any other encoding, named
  entities without `;`, a numeric entity without `;` followed by a (hex) digit, combining marks in a non-canonical order,
  look-alike letters from other scripts, and a secret split across two effects or two values.
  Messages that embed a value render secret-labelled values the same way. Text is redacted before it is cut, so a cut never leaves part of a secret.
- **Caught errors carry labels.** In `catch e`, `e.message` is labelled `untrusted:error` (it may quote model
  text, an HTTP body, stderr or file content), except for the program's own `fail(kind, msg)` / `assert ...`
  with an unlabelled message, which stays unlabelled; a labelled message keeps its labels. `e.kind` is
  unlabelled for built-in kinds; `fail(kind, ...)` keeps the labels of `kind`. Outside `catch` (stderr, the
  Python API's `e.kind`, the tool-error text fed back to an agent's model, the journal) a secret-labelled kind
  is shown as `«secret:NAME»` — by its labels, so also a short, changed or partial copy of a secret
  (`fail(k.split("-").join(" "), ...)`). An untrusted kind (e.g. model text) is shown as it is; on a terminal
  its control characters are escaped like every error text.
- **Errors carry the labels of their operands.** A runtime error built from labelled values (an index, a
  size, a count, a bound, a duration, a converted value) carries their labels, so `e.message` in `catch`
  has them too. When those labels include `secret:NAME`, every number in the message is shown as
  `«secret:NAME»` — on stderr, in the journal, in the Python API and in `catch` — so a length or index
  computed from a secret cannot be read from an error (`xs[k.len()]` → "index «secret:K» out of range
  (length «secret:K»)": public numbers in the same message are masked too). Such an `e.message` is
  secret-labelled, so it cannot be printed either.
- `trust(x, "reason")` removes `untrusted` labels (logged in the journal). `approve(x, "question")`
  asks a human on the terminal, showing the whole value; yes → removes `untrusted`, no → error kind `denied`.
- **Memory keeps labels.** `memory.save` stores, next to the JSON value, the labels of every leaf (string,
  number, map key) and of every picked container (SPEC §6 selection); `memory.load` puts them back exactly where they were, so data saved while untrusted is
  untrusted in a later run (no laundering through storage). If a stored label cannot be put back (the type
  changed so the leaf is now a Bool, none or enum) the load fails with error kind `decode` (fail closed).
  Secrets cannot be stored (`taint`, nothing written). The key of `memory.save`/`memory.delete` must not be
  untrusted (`taint`: an injected text must not choose which slot is overwritten); an untrusted key in
  `memory.load` is allowed and the loaded value gets the key's labels. The store file itself is trusted as
  much as the program: whoever can edit it can change stored values and labels.
- Known limitation (documented): implicit flows through control flow are not tracked.

## 7. Runtime: providers, budgets, journal
- Model string `provider/model`: `openrouter/...`, `openai/...`, `gemini/...`, `local/...`, `mock`.
  Selected by `@model`, else env `SIPAR_MODEL`; if neither is set, the call fails with error kind `ai`
  (no silent fake answers). `mock` must be chosen explicitly. Keys: env `OPENROUTER_API_KEY`,
  `OPENAI_API_KEY`, `GEMINI_API_KEY`; `local` uses `SIPAR_LOCAL_URL` (default `http://127.0.0.1:1234/v1`).
- `mock` without a script answers every call with a schema-valid default (an agent: `{"final": default}`).
  A script (`SIPAR_MOCK_SCRIPT=file.json`, or `mock_script=` in the Python API) is a JSON list of replies
  used in call order, or an object `{fn name: [replies]}` (a value that is not a list is one reply); a
  non-string reply is sent as JSON. With a script the mock is strict: a key that names no `ai`/`agent` fn of
  the program, and a call with no scripted reply left (also after an invalid reply used up the `@retries`),
  fail with error kind `ai`. A `SIPAR_MOCK_SCRIPT` file that cannot be used — missing, unreadable, not UTF-8,
  empty, not JSON (also `NaN` / `Infinity`), nested more than 20,000 levels deep, or `null` / a number / a
  string / a boolean — is error kind `ai`
  `cannot load SIPAR_MOCK_SCRIPT <path>: <why>` at the first AI call, never an unscripted mock answer.
  A FIFO, a device or a file over 256 MB is refused the same way (`not a regular file`, `too large (...)`).
- **A model that cannot be set up is a journaled failure** (round 8): no model, a bad model name or chain, a
  mock script that cannot be loaded or names no `ai`/`agent` fn. No request is sent and no budget is used,
  but the error is journaled as the outcome of that ai/agent effect (`meta: {"setup": true, "model": ...}`),
  so a caught error replays the same, and replay needs no model environment. `sipar trace` does not count
  such an entry as an ai call. (Journals written before round 8 have no such entry and still diverge.)
- `budget(...)` limits nest; the innermost exceeded limit raises error kind `budget`. Every limit must be a
  finite number >= 0 (`tokens` and `ai_calls` Ints); NaN, infinity or a negative value is error kind `type`
  and the body does not run (a NaN limit would otherwise compare false and switch the budget off).
- `@retries(n)` needs an Int >= 0 and `@max_steps(n)` an Int > 0: the checker reports E231, and a program
  run without the checker fails with error kind `type` instead of falling back to the default.
  Token/usd accounting uses provider `usage` when it holds sane Ints (0..10,000,000 per call); a missing,
  negative, non-Int or huge count is replaced by an estimate (characters / 4), so a provider cannot switch a
  token budget off. A malformed provider reply (no choices, non-string content, bad JSON, ...) is error kind
  `ai`, catchable. usd uses `SIPAR_PRICE_IN`/`SIPAR_PRICE_OUT` (USD per 1M input/output tokens; `0` is
  allowed). **A `usd` limit fails closed:** an ai call inside `budget(usd: ...)` without both prices set to
  finite non-negative numbers is error kind `budget` naming the two variables.
- `seconds` is a deadline for the whole block, and for each effect inside it the whole request: an HTTP call
  (connect, headers and body together), a model call or a shell command is cut when the remaining time runs
  out (error kind `budget`), not after each slow socket read. The deadline is also checked after every
  built-in function and method call and when the block ends, so a slow pure loop (`"x".repeat(n)`, a long
  `sort`) cannot overrun it; the check goes through the journaled clock, so replay stops at the same step.
  Outside a budget the same whole-request limits
  come from `SIPAR_HTTP_TIMEOUT` (default 30 s, error kind `io`), `SIPAR_AI_TIMEOUT` (120 s, `ai`) and
  `SIPAR_SHELL_TIMEOUT` (120 s, `io`); a timed-out command is killed with its whole process group. These
  variables share one rule: a finite number of seconds above 0 and at most 86400; anything else (`inf`, `nan`,
  `0`, negative, text) means the default. `SIPAR_MAX_DEPTH` (call depth, default 800) accepts 1..20000, else
  800; the whole range works (the parser, checker and interpreter run on a thread with a 1 GiB stack). `SIPAR_PRICE_IN/OUT` above 1e9 count as not set.
- **Failed fallback attempts are charged.** An attempt that fails after its request was sent (HTTP error,
  timeout, malformed reply) counts against `tokens` and `usd` budgets: the usage the provider reported in the
  error reply, else an estimate (prompt characters / 4 input tokens, 0 output). It is recorded as `meta.usage`
  (and `meta.usd`) on the failed journal entry, so replay charges the same. An attempt that never sent a
  request (missing API key) costs nothing.
- **Model providers never follow redirects:** a 3xx reply is error kind `ai` ("provider redirected to …") and
  nothing is sent to the new location, so the API key stays with the configured endpoint.
- `http.get/post` headers: a name must be an RFC 7230 token; a value with CR, LF, NUL or another control
  character (C0 except TAB, DEL, C1) or a character outside Latin-1 is error kind `value` before anything is
  sent. The message names the header and never quotes the value. `Host`, `Content-Length` and
  `Transfer-Encoding` are written by the runtime from the URL and the body: a program that sets one gets error
  kind `value`.
- A URL with a user name or password before the host (`user@host`) or with a character outside ASCII is error
  kind `capability` before anything is sent: credentials go in a header, other characters are percent-encoded.
- HTTP redirects are followed only to hosts allowed by `allow net`; on a redirect to another origin
  (scheme, host or port) the `Authorization`, `Cookie`, `Proxy-Authorization` headers and every header whose
  value carries a secret are dropped. A headers map that is itself secret-labelled (built from or picked with
  a secret, §6) makes every header in it secret: all are redacted in the journal and all are dropped on such
  a redirect.
- Journal: `sipar run` writes `.sipar/runs/<UTC stamp>Z-<pid>-<ns>.jsonl` next to the program (§9: for a
  program read from a pipe, in the current folder), one line per effect:
  `{seq, kind, request, response, labels}`. `sipar replay prog.sipar run.jsonl` serves effects from the
  journal; if the program issues a different request the run stops with error kind `replay` and a diff.
  Entries also carry `t` (start, Unix seconds), `ms` (duration), `fn` (the Sipar function running) and, for
  ai/agent calls, `meta: {model}` (plus `attempt`, `of` in a fallback chain and `usd` when prices are set).
  `meta`, `t`, `ms`, `fn` are not compared on replay; replay follows the journal's recorded chain attempts.
  Memory operations are effects too (`memory.save/load/delete/keys`), so replay never touches the store.
- **Replay is exact and fails closed.** A time-budget overrun is journaled as a `budget` entry at the step
  where it happened; replay raises the same error at the same step, and remaining-time arithmetic uses a
  virtual clock built from the journaled effect durations (`sleep` does not sleep on replay). `env.secret`
  journals only `{salt, hash, len}` (PBKDF2-SHA256, 100,000 rounds); replay re-reads the variable from the
  real environment and checks length and hash — missing or different is error kind `replay`. (A short secret
  could still be guessed from its hash: treat journals as sensitive.) A journaled request is stored redacted, so replay
  compares it with the live request redacted the same way; when the only difference is inside text that
  matches a secret value, the `replay` error says so instead of showing two identical-looking strings.
  A response that held a secret is journaled with `«secret:NAME»` in its place
  plus a `restore` field: for each such marker, its position and the index of the registered form of the
  secret it replaced — never the text. Replay, which has re-read and checked the secret, puts the same form
  back, so it sees what the run saw (a model reply `482913` equal to a secret PIN decodes to the same Int,
  `len` gives the same number). A marker that was literally in the response, two overlapping secrets, a copy
  found only in the decoded view (§6: an HTML-entity, backslash-escaped or full-width copy is no registered
  form), or a secret replay does not have stays the marker. (An error message needs no restore: the program sees it
  redacted in the run too.) A malformed entry — a response of the
  wrong shape for its effect, a recorded error that is not `{kind, message}` with a known kind, non-finite
  numbers, a journal that is not UTF-8 text or is nested too deeply to read — is error kind `replay` (the
  message names the journal file), never an internal error. On replay the usd price comes from the
  journal's `meta.usd`.

## 7a. MCP servers (Model Context Protocol client)
A program can call the tools of MCP servers that its `allow mcp` lines name. Only stdio servers.
```sipar
allow ai
allow io
allow mcp "fs" ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/abs/data"]
    tools ["read_text_file", "list_directory", "write_file", "get_stats"]  // the only tools it may call
    readonly ["read_text_file", "list_directory"]                // optional subset, see the readonly rule
    // pin "sha256:<64 hex>"                                     // optional, see pins
type Stats = { size: Int, lines: Int }
fn main() uses mcp, io {
    let t = mcp.fs.read_text_file(path: "/abs/data/notes.txt")   // Str
    let s: Stats = mcp.fs.get_stats(path: "x")                   // typed: decoded from the result
    print(mcp.call("fs", "read_text_file", ["path": "x"]))       // by MCP name; dynamic names allowed
}
agent fn helper(q: Str) -> Str uses mcp { tools [mcp.fs.read_text_file] "{q}" }
```
- **Syntax.** `allow mcp "<name>" [command...]` then `tools [...]`, optional `readonly [...]` and `pin "..."`,
  on the same line or the following lines, each once. All parts are string literals without interpolation.
  The server name is an identifier and not `call`. A tool is called as `mcp.<server>.<tool>(name: value, ...)`
  (named arguments only, each JSON-able); in that form a tool name is mapped to an identifier: every
  character outside `[A-Za-z0-9_]` becomes `_` (`read-notes` -> `mcp.fs.read_notes`), and a leading digit
  gets a `_` prefix. `mcp.call(server, tool, args: Map[Any]) -> Str` uses the MCP name (`[:]` for no args).
  The checker reports E310 for a bad `allow mcp` line (bad or duplicate server name, empty command, no tools,
  an empty or repeated tool, two tools with the same identifier, a readonly tool not in `tools`, a bad pin),
  E205 for an unknown server or tool (also in `mcp.call` with literal names), E212 for positional or
  non-JSON-able arguments, E301 when `uses mcp` is missing and E302 when no `allow mcp` line exists. The
  result is `Str`; when the expected type (a `let` annotation, parameter or return type) is a JSON-able type
  other than `Str`, the result is decoded into it: `structuredContent` if the server sent it, else the text as
  JSON; a mismatch is error kind `decode`. Typed results need the checker (as `sipar run` does).
- **Protocol.** The command is started without a shell, in the program's folder, with the same minimal
  environment as `shell.run` (`PATH`, `HOME`, `LANG`, `TMPDIR` and `allow env` names; never a secret, also not
  inside another variable), in its own process group; stderr is kept (last 64 KB) and shown when the server fails. Messages are
  newline-delimited JSON-RPC 2.0. Sipar first sends `server/discover` with
  `_meta: {"io.modelcontextprotocol/protocolVersion": "2026-07-28", clientInfo, clientCapabilities: {}}`
  (that `_meta` goes on every request of a 2026-07-28 session). If the server answers with
  `supportedVersions` containing 2026-07-28 it is used; if it answers -32601 (or any non-MCP error), or does
  not answer within `SIPAR_MCP_PROBE_TIMEOUT` (default 10 s), Sipar falls back to `initialize` with
  protocolVersion 2025-11-25 then `notifications/initialized` (accepted replies: 2025-11-25, 2025-06-18,
  2025-03-26, 2024-11-05). Error -32022 with `data.supported` selects from that list. A server that supports
  neither era is error kind `mcp`. `tools/list` is read page by page (`nextCursor`, at most 100 pages; a
  repeated cursor is an error). Server pings are answered, other server requests get -32601, notifications
  are ignored. While Sipar waits for one answer, at most 10,000 other messages (64 MB) may arrive, and at most
  10,000 unread messages or 16 MB (each message counted with 128 bytes extra) are held between calls (the
  reader then pauses and the server waits); more is error kind `mcp`, and the server is stopped. Blank lines are
  not messages and are dropped. Requests are written
  by a separate thread, so a server that stops reading its input runs into the timeout; more than 16 MB
  waiting to be written is error kind `mcp`. The server starts on the first call and is stopped (process group
  killed) when the run ends, when `sipar` exits, on SIGTERM / SIGHUP and on the first Ctrl-C. A timeout holds
  even when something the server started keeps its pipes open: Sipar stops reading them and does not wait for
  them to close. **Known limit:** a process the server (or a `shell.run` command) starts in a new session or
  process group of its own (`setsid`, a daemon) is outside the group Sipar kills, so it can outlive the call and
  `sipar` itself; macOS has no standard-library way to find or reap such a process (no subreaper, no cgroups),
  so Sipar does not claim to. Run untrusted servers in a container or sandbox if that matters.
- **Results.** Text parts become the `Str` (joined with newlines); `structuredContent` is used for typed
  results; image, audio, resource_link, binary resources and unknown parts become opaque markers such as
  `«mcp image: image/png, 1024 bytes»` (embedded text resources become their text; in a marker, server text
  is cut short and control, line-break, bidi and `«»` characters are escaped as `\uXXXX`; a missing MIME
  type or URI shows as `unknown`). A missing or `null` `content` means no parts. `isError: true` is error
  kind `mcp` (`mcp.fs.read_text_file reported an error: ...`), catchable. A JSON-RPC error reply, invalid JSON,
  a message over 10 MB or with more than 1,000,000 JSON values (counted as the `[`, `{` and `,` outside
  strings; parsed, each costs about 600 bytes), a crashed server, a missing command or a malformed result is error kind `mcp`.
  `resultType: "input_required"` (server asks for user input) is not supported (kind `mcp`). A message or
  `structuredContent` nested deeper than 20,000 levels, or a message holding an integer of more than 4,300
  digits, is error kind `mcp` (catchable). A lone surrogate
  (`\ud800`) in any text from the server (results, errors, tool definitions) becomes U+FFFD.
- **Timeouts.** Every request has the whole-request limit `SIPAR_MCP_TIMEOUT` (default 60 s, error kind `io`);
  inside `budget(seconds: ...)` the remaining budget is the limit when it is tighter (error kind `budget`).
  The limit covers starting the server and writing the request too. A server that times out is killed and restarted on the next call.
- **Labels.** Every result (Str or typed value) is labelled `untrusted:mcp:<server>/<tool>` (with the MCP
  tool name), so it cannot reach `shell.run`, `fs.write`, `http.*` or a non-readonly MCP tool.
- **Arguments are sinks.** A secret may never be an MCP argument (error kind `taint`; also for readonly
  tools), and the server and tool names of `mcp.call` must be trusted. Untrusted data may be an argument only
  of a tool listed in `readonly [...]`. **The readonly rule:** list a tool as readonly only when calling it
  with attacker-chosen arguments is harmless: it reads, writes nothing, sends nothing outside, and its
  results are themselves untrusted. A server's own `readOnlyHint` annotation is untrusted and ignored. Tools
  that fetch URLs, send messages, run code or change files are never readonly; call them with trusted data,
  or after `trust`/`approve`. A secret value (from `env.secret`) in the launch command is error kind `taint`.
- **Agents.** `tools [mcp.<server>.<tool>]` offers an MCP tool to an agent fn. It must be a readonly tool
  (E232: the model picks its arguments, so they are untrusted) and the agent must declare `uses mcp` (E301).
  The model sees the tool's input schema and its description, prefixed with
  `[untrusted: written by MCP server '<name>', not by the program]` (at most 2000 characters; a schema over
  20,000 characters is error kind `mcp`). The model's arguments are checked against the schema's property
  names and `required` list (wrong ones are fed back to the model); a tool error is fed back too, but a rug
  pull, a protocol failure or a timeout stops the agent.
- **Tool pins (rug-pull defence).** For each allowed tool Sipar hashes its definition: SHA-256 of the
  canonical JSON (sorted keys, no spaces) of `{name, description, inputSchema, title?, outputSchema?}`
  (annotations are not hashed). A tool in `tools [...]` that the server does not list is error kind `mcp`.
  Without `pin`, the hashes are stored on first use (trust on first use) in
  `.sipar/mcp/<program>.pins.json` next to the program; a later run whose server changed an allowed tool's
  definition stops with error kind `mcp` ("changed the definition of tool ... (possible rug pull)") until the
  user deletes the entry. With `pin "sha256:..."` (the hash of all allowed tools, printed in the mismatch
  message) the pin file is not used. `sipar test` keeps pins in memory. A pin file that is not a regular
  file (a FIFO), over 16 MB or nested more than 8 levels is error kind `mcp` (round 8), never a hang. Before every call the tool list is
  read again; a change during the run is error kind `mcp` too. Pins defend against a *remote* server that
  changes its tools (a rug pull), not against local code: a stdio server runs as the same user, in the
  program's folder, and can edit `.sipar/mcp/*.pins.json` itself. Use `pin "sha256:..."` in the program
  (the pin file is then not read), and treat an `allow mcp` command like any program you run.
- **Journal and replay.** `mcp.connect` entries record `{server, command, tools, pin}` -> `{version, tools,
  hash}` and `mcp` entries record `{server, tool, args}` -> `{text, structured?}` with the result label.
  `sipar replay` serves both from the journal and never starts a server; different arguments are error kind
  `replay`.

## 8. Errors and diagnostics
Runtime errors are values of `Error { kind: Str, message: Str }` inside `catch`. Kinds: `type decode
taint capability budget denied replay ai io assert user index key zero value mcp`.
Static diagnostics: `{code, severity, file, line, col, message, hint}`; codes `E1xx` syntax,
`E2xx` names/types, `E3xx` effects/capabilities, `E4xx` match/flow. `sipar check --json` prints them.

## 9. CLI
`sipar run prog.sipar [args]` · `sipar check prog.sipar [--json]` · `sipar test prog.sipar [--live]
[--record]` · `sipar replay prog.sipar journal.jsonl` · `sipar trace journal.jsonl [--json]` · `sipar spec` · `sipar lsp` ·
`sipar --version`.
- Exit codes: 0 ok; 1 an error in the program, its check, its tests or its replay; 2 a usage problem or an
  input file that cannot be read; 141 a closed output pipe.
- Sipar needs Python 3.12 or newer. On an older Python, `sipar` (and `python3 -m sipar`, `-m sipar.cli`) prints one
  line, `sipar: needs Python 3.12 or newer (this is 3.9.6)`, to stderr and exits 2 (also when stderr is closed);
  `import sipar` raises `ImportError` with the same text. The `bin/sipar` launcher runs `python3`, or the Python
  named in `SIPAR_PYTHON` (`SIPAR_PYTHON=python3.12 sipar run a.sipar` when `python3` is older).
- Usage problems exit 2 with the usage of the command (`sipar check a b`); an unknown option before the
  command (`sipar --foo check a.sipar`) shows the usage of `sipar` itself. `check --json` prints a JSON
  diagnostic (`code` "usage") even for a file it cannot read. A file that cannot be read says why in the same
  words everywhere: `sipar: cannot read x.sipar: permission denied` (or `not UTF-8 text`; a missing file is
  `no such file: x.sipar`). `sipar replay prog.sipar dir/` says the journal is a directory; a journal that cannot
  be read (missing, a directory, no permission, not UTF-8) is exit 2 with the same message in `replay` and
  `trace`; only a path that does not exist is `no such journal`, a FIFO, a device or a symlink loop is
  `cannot read X: not a regular file` (or `too many levels of symbolic links`).
- A program file may be a regular file or a pipe: `sipar check <(gen.sh)` reads the pipe to its end (a named
  FIFO with no writer reads as an empty file, never hangs). A device (`/dev/null`) or a source over 256 MB is
  exit 2 `cannot read X: not a regular file` / `too large (...)`; a directory is `cannot read X: is a directory`.
- "The program's folder" (where `.sipar/` keeps runs, memory, fixtures and MCP pins, where MCP servers start,
  and where relative `allow fs` paths begin) is the folder of the program file — or the current folder when the
  program is not a regular file: `sipar run <(gen.sh)`, `cat x.sipar | sipar run /dev/stdin` write their journal
  to `./.sipar/runs/`. `sipar replay copy.sipar journal.jsonl` with a regular-file copy of the program replays it.
  The memory store and pin file of such a program are named after the pipe (`stdin.json`; `63.json` for `/dev/fd/63`).
- `sipar run` refuses, before it writes a journal, a program without `fn main()` (an empty file too) and
  arguments given to a `fn main()` without parameters (error at `file:line`). A replay that leaves journal
  entries unused is error kind `replay` at `file:1:1`. On Ctrl-C `run` prints the journal path.
- `sipar test` checks for unused fixture entries also when a test ends with `return`. Any exception during
  `--record` (also Ctrl-C) deletes the partial fixture; an exception that is not a Sipar error is reported,
  never silently ends the test run.
- `sipar test` keeps each test's fixture in `.sipar/fixtures/<name>-<hash>.jsonl`: `<name>` is the test name
  with every run of other characters than `A-Za-z0-9_.-` replaced by `_` (at most 60 characters) and `<hash>`
  is the first 12 hex digits of SHA-256 of the exact test name, so "a b" and "a_b" never share a file. A
  fixture recorded by an older version under `<name>.jsonl` is still replayed when there is no new file and no
  other test in the file maps to the same old name (otherwise it is ignored; re-record with `--record`).
- `sipar trace` prints, per Sipar function and per model: effects, ai calls, tokens in/out (provider
  `usage`), usd (`-` when no price was recorded), effect time in ms and errors, then totals, effects by kind
  and the run span. `--json` prints `{functions, models, kinds, totals}`. Old journals without `fn`/`ms`
  work (function from the ai request or `(top)`, time 0). Missing file: exit 2; a bad line (not JSON, `NaN` /
  `Infinity` literals, nested too deeply): exit 1. A number outside a sane range counts as 0 (`t` 0..1e11,
  `ms` 0..1e10, tokens 0..10,000,000 per call, usd 0..1e9). Function, model and kind names and the file name
  are printed with control and bidi characters escaped (`\x1b`, `\u202e`), in `--json` too.
  A failed attempt's tokens come from its `meta.usage` (§7) when the reply has none; usd below 1 is shown
  with up to 9 decimal places (`0.00000015`), so a cheap call never shows as 0.
- A closed output pipe (`sipar run x | head -1`) ends the command quietly with exit 141 (128 + SIGPIPE); so
  does a standard output that is closed from the start (`sipar run x >&-`, also `--help` and `--version`). A
  closed or broken stderr (`2>&-`) only loses the messages: the exit code is the same as with stderr open. A
  closed stdin reads as empty. Closed descriptors 0-2 are held by `/dev/null`, so no file Sipar opens takes them.
- Signals: SIGTERM and SIGHUP stop `sipar` with exit 128 + the signal number and kill its MCP servers; Ctrl-C
  (SIGINT) stops a run with exit 1 (`interrupted`). A signal that is ignored when `sipar` starts (`nohup`,
  a background job of a script, `trap '' INT`) stays ignored, as for any Unix program: it does not stop the run.
  A character the terminal's encoding cannot show (`LC_ALL=C`, `PYTHONIOENCODING=ascii`) is printed as an
  escape such as `\xe9` (stdout and stderr), never a crash.

- `sipar lsp` runs a language server, LSP 3.17 over stdio (`Content-Length` framed JSON-RPC 2.0), until
  `exit` or end of input. The exit code is 0 after `shutdown` then `exit`, and 1 otherwise. Positions are
  UTF-16 (`positionEncoding: "utf-16"`); Sipar's 1-based code-point columns are converted both ways.
  Documents are synced in full (`change: 1`). `didOpen` and `didChange` publish the diagnostics of
  `sipar check` (severity, code, and the message followed by a `hint: ...` line); `didClose` clears them.
  The published `version` is the document's version when the client sent an integer, else `null` (a version
  such as `1e400`, `NaN` or `1.5` never stops diagnostics).
  - Requests: `hover` (expression type; signature with `uses` and `///` doc for functions, types and
    enums; stdlib signatures), `definition`, `completion` (keywords, names in scope, stdlib modules and
    functions, fields and methods after `.`, attributes after `@`) and `documentSymbol`.
  - When the current text does not parse, hover, definition and completion use the last text that did.
  - Error codes:
    - an unknown request gets -32601;
    - bad params get -32602;
    - a request before `initialize` gets -32002;
    - a frame that is not JSON gets -32700;
    - a crash inside a handler gets -32603, with a traceback on stderr, and the server keeps running.

## 10. Python embedding
```python
import sipar
prog = sipar.load("triage.sipar")              # parse + check; raises sipar.CheckError(.diagnostics)
prog.call("route", "tech")                   # "tech"
prog.call("classify", "hi", model="mock",
          mock_script=[{"team": "spam", "urgent": False, "summary": "an ad"}])   # a Verdict
sipar.check_source("fn main() { x }")        # [{code, severity, file, line, col, message, hint}]
```
- `call(name, *args, model="mock", mock_script=None, out=None, journal=None, **named)`. `model="mock"` is
  the default (no network); a model or chain string overrides `@model`; `model=None` uses the program's
  `@model` / `SIPAR_MODEL`. `out` receives `print` output; `journal` (a str or `os.PathLike`) writes a run journal file (a bare
  name is in the current folder; a missing folder on the path is created, like `.sipar/runs/` for `sipar run`;
  an existing file is replaced, not appended to). If `out.write()` / `out.flush()` raises an `Exception`, that is error
  kind `io` like any failed write (`the host's out.write() raised ValueError: ...`; a `catch` in the program
  sees it), and the call raises `SiparError`.
- Host mistakes in the options raise before the run: `TypeError` for a `model` that is not a str or None,
  a `mock_script` that is not a list/tuple/dict of JSON data (dict keys are function names), an `out`
  without `write()`, a `journal` that is not a str or `os.PathLike` path; `ValueError` for an empty `model` or
  `journal`, or a `journal` with a NUL or a character the file system cannot encode (such as a lone `\ud800`). A journal path whose folder part is a file
  is error kind `io` `cannot write journal X: afile is not a folder`.
  Arity and parameter-name mistakes are `SiparError` kind `type`. `check_source` of a non-str (also bytes)
  raises `TypeError`. `load` takes a str or an `os.PathLike` path (a `pathlib.Path` is turned into its str, so
  `Program.path` and `CheckError.diagnostics` hold a str, the same dicts as `sipar check --json`); a bytes path
  (or an `os.PathLike` that gives bytes) or a non-path raises `TypeError` (decode bytes first), and a path with a NUL
  or a character the file system cannot encode (such as a lone `\ud800`) raises `ValueError`; the `\udc80`..`\udcff`
  stand-ins for raw bytes that `os.listdir` gives are a usable name. A relative path is taken from the current folder
  at `load` time: the program's folder (`.sipar/`, relative `allow fs` paths) does not move with a later
  `os.chdir()`, and errors name the file as given. `sipar.Program(program, path, warnings)` checks `path` the
  same way. It reads the file like `sipar check` (a pipe to its end, a FIFO with no writer as
  empty) and raises `SiparError` kind `io` for a file that is not UTF-8, a device (`/dev/zero`) or a file over
  256 MB (`cannot read X: not a regular file` / `too large (...)`).
- Conversion: Int/Float/Str/Bool/none ↔ int/float/str/bool/None (bool is not accepted for Int; int is
  widened to Float; a whole-number float such as `2.0` is accepted for Int, while `2.5` is error kind `decode`
  `expected Int, got number`, and so is a float above 1e18 in size, `number too large for Int`; a Python int may
  have up to about 4200 digits, a larger one is kind `value`), List ↔ list (tuples accepted), Map ↔ dict with str keys, record ↔ dict of fields, enum ↔
  `"variant"` or `{"variant": {fields}}`; going in, the form `{"tag": "variant", ...}` is also accepted, but
  only for an enum with no field named `tag` (for such an enum it is error kind `decode`). Arguments are
  validated like decoded JSON (error kind `decode`). Function values cannot cross (kind `type`).
- **Labels are dropped at the boundary.** Python gets plain values (the host decides what to trust);
  arguments from Python are trusted. A result containing a secret — in a value, a map key, or the own labels
  of a list/map/record/function picked with a secret index or key (§6) — raises `taint` instead. Untrusted
  labels are dropped like the others: the host decides what to trust. A result or argument nested more than 20,000 levels deep is error kind `value`; the walk is linear.
- Capabilities and effects are enforced exactly as in `sipar run`. Runtime errors raise `sipar.SiparError`
  (`.kind`, `.message`); every attribute of it (`message`, `value`, `kind`, `args`, `file`) is redacted and it
  carries no chained exception. A missing file raises the usual `OSError`.
