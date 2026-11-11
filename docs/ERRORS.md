# Sipar diagnostics

`sipar check prog.sipar --json` prints every diagnostic as
`{code, severity, file, line, col, message, hint}`. Codes: `E1xx` syntax, `E2xx` names and types,
`E3xx` effects and capabilities, `E4xx` match and control flow. Severity is `error` unless marked
**warning** below; warnings do not stop `sipar run`.

Every example below is checked by `tests/test_checker.py` (test `C93`): it must produce its code.
The checker reports all independent errors in one run, sorted by position. One mistake gives one
diagnostic: an expression that already failed has type *Unknown*, which is accepted everywhere, so
there is no cascade. A syntax error stops at the first one (the parser does not recover).

## Rules the spec does not spell out

The checker uses these rules where SPEC.md is silent. Each is the simplest sound choice.

- **Scopes.** A name may not be declared twice in the same block (E202). An inner block, a loop
  variable, a `catch` variable or a local may shadow an outer name or a parameter.
- **Parameters are immutable.** Assigning to a parameter is E207, like `let`. Copy it into a `var`.
  `let` only blocks rebinding: `p.score = 3` and `xs[0] = 1` work on a `let` binding (values are shared
  by reference).
- **Optional stdlib arguments are named-only.** `http.get(url, headers: h)` — `headers` cannot be given
  positionally. User functions have no default arguments.
- **Built-in functions are not values.** `let f = print` is E206; wrap it: `fn(x: Str) => print(x)`.
  User `fn`, `ai fn` and `agent fn` can be passed as values; their effects travel with them (a fn that
  mentions `fetch` as a value must declare `fetch`'s effects).
- **Containers are invariant.** `List[Int]` is not a `List[Float]` (the list is shared, so a later
  `push(1.5)` would break the `Int` view). An empty literal `[]` / `[:]` fits any element type when the
  expected type is known. `Int` widens to `Float` everywhere else (let, assignment, arguments, return, list/map/record items,
  `if`/`match`/`try` arms, `??`, function values) and the runtime value really becomes a `Float` (SPEC §2).
- **Function types**: parameters contravariant, result covariant; a function returning anything fits
  `fn(...) -> None`.
- **Blocks as values.** A block's value is its last expression statement, otherwise `none`. A bare
  `return` in a fn returning `T` is E210. An `if` without `else` used as a value is E218.
- **`main`** is a plain `fn` with no parameters or exactly `args: List[Str]` (E243). Its effects must be
  allowed, like any fn.
- **Effects.** `uses` must cover the effects of everything a fn calls or references: built-ins, user fns,
  fn values, lambdas written inside it (E301). Every used effect must have an `allow` line (E302).
  `ai fn` and `agent fn` use `ai`; an `agent fn` must also declare the effects of its tools.
  `test` blocks need no `uses`; they may use any allowed effect.
- **Pure places.** Top-level constants and `ai fn` / `agent fn` prompts must be pure: no effects (E304).
  A constant calling a user function or using a later constant is E305. Prompts may read only their
  parameters and constants: calling a user function there is E230.
- **Match.** An enum match must name every variant or have `_` / a binding arm; `Bool` needs `true` and
  `false`; an optional needs `none`; `Int`, `Float` and `Str` need `_` or a binding (E401). Sub-patterns
  count, recursively: `E.b(true)` + `E.b(false)` cover `E.b(flag: Bool)`, `Out.a(In.p)` + `Out.a(In.q)` cover
  `Out.a(i: In)`; the message names a missing value, e.g. `missing T.node(T.node(_, _), _)`. A literal
  payload (`E.s("x")`) never covers `E.s`.
  A match arm binding a name that equals a constant is a warning (E407): it binds, it does not compare.
- **Agent tools** are `fn` or `ai fn` (not `agent fn`, not built-ins) whose parameters and result are
  JSON-able (E232). A tool without a `///` doc comment is a warning (E308).
- **Escapes.** Besides `\n \t \" \\ \{ \}` the lexer also accepts `\r` and `\0`. In numbers `_` may only
  stand between two digits (`1_000`).

## Syntax (E1xx)

### E101 — bad token
Bad number (`12abc`, `1__0`), an Int literal over 14,000 bits (about 4200 digits), a non-ASCII character outside strings and
comments (`let x = ١٢`), an unknown character, an unterminated string.
```sipar
let X = 12abc
```

### E102 — unknown escape
Valid escapes are `\n \t \r \0 \" \\ \{ \}`.
```sipar
let X = "a\qb"
```

### E103 — bad interpolation
Empty `{}`, unmatched `}`, extra tokens inside `{...}`. Write `\{` `\}` for literal braces.
```sipar
let X = "price: {}"
```

### E104 — unclosed block
```sipar
fn f() {
    print(1)
```

### E110 — unexpected token
The general syntax error: a missing token, a keyword used as a name, a statement at the top level,
chained comparisons (`a < b < c`), a top-level `var`.
```sipar
fn f() -> Bool { 1 < 2 < 3 }
```

### E111 — bad attribute
An attribute on something other than `ai fn` / `agent fn`, or a value that is not a plain literal.
```sipar
@retries(3)
fn f() { }
```

### E112 — unknown capability
```sipar
allow internet
```

### E113 — cannot assign to this expression
```sipar
fn f() { g() = 1 }
fn g() -> Int { 1 }
```

### E114 — bad argument list
A positional argument after a named one, or the same named argument twice.
```sipar
fn f() { print(a: 1, 2) }
```

### E115 — nested too deeply
More than 256 levels of brackets, blocks, calls, types or patterns inside each other (a block or `if`
used as a value counts as two levels), more than 16
strings nested through `{...}` interpolations, or a chain of operators, fields, indexes or calls deeper
than 10,000 levels. Long flat chains such as `1 + 2 + ... + 500` are fine. Move inner parts into `let`
names or small functions.
```sipar
let X = "{"{"{"{"{"{"{"{"{"{"{"{"{"{"{"{"{1}"}"}"}"}"}"}"}"}"}"}"}"}"}"}"}"}"
```

## Names and types (E2xx)

### E201 — duplicate in a declaration
Duplicate field, variant or parameter; an enum without variants.
```sipar
type T = { a: Int, a: Str }
```

### E202 — name already defined
Twice in one block, a fn / type / const / test defined twice, or a name that clashes with a built-in.
```sipar
fn f() {
    let x = 1
    let x = 2
}
```

### E203 — unknown name
Hints suggest the closest name.
```sipar
fn f() -> Int {
    let count = 1
    cuont + 1
}
```

### E204 — unknown or malformed type
```sipar
fn f(m: Map[Str, Int]) { }
```

### E205 — unknown field, variant, method or module function
Also an MCP server or tool that no `allow mcp` line lists (`mcp.fz.read(...)`, `mcp.call("fs", "nope", [:])`).
```sipar
type P = { name: Str }
fn f(p: P) -> Str { p.nmae }
```

### E206 — not a value
A module, type, enum or built-in function used as a value; a method named without a call.
```sipar
fn f() { let g = print }
```

### E207 — cannot assign
To a `let`, a parameter, a constant, a loop variable or a function.
```sipar
fn f() {
    let n = 0
    n = 1
}
```

### E210 — type mismatch
```sipar
fn f() -> Int { "five" }
```

### E211 — cannot infer a type
`let x = none`, an empty `[]` / `[:]` without an annotation, a lambda parameter without a type and
without an expected type.
```sipar
fn f() { let xs = [] }
```

### E212 — wrong arguments
Too many / too few, unknown named argument, a payload variant without its data, a lambda with the
wrong number of parameters.
```sipar
fn add(a: Int, b: Int) -> Int { a + b }
fn f() -> Int { add(1) }
```

### E213 — not callable
```sipar
fn f() {
    let n = 1
    n()
}
```

### E214 — bad operand
```sipar
fn f(n: Int) -> Str { "n = " + n }
```

### E215 — condition is not Bool
```sipar
fn f(n: Int) { if n { print(n) } }
```

### E216 — impossible `as` conversion
Allowed: Str to Int/Float/Bool, Int to/from Float, anything to Str, Str to a record/enum/List/Map
(JSON decode).
```sipar
fn f(n: Int) -> Bool { n as Bool }
```

### E217 — record literal is missing fields
```sipar
type P = { name: Str, age: Int }
fn f() -> P { P { name: "a" } }
```

### E218 — branches or items of different types
List items, map values, `if` / `match` branches used as a value, or an `if` without `else` used as a
value.
```sipar
fn f() { let xs = [1, "two"] }
```

### E219 — value may be none
`none` where a non-optional type is expected, a field read or call on an optional value.
```sipar
type P = { name: Str }
fn f(p: P?) -> Str { p.name }
```

### E220 — cannot index, slice or loop
```sipar
fn f(n: Int) { for x in n { print(x) } }
```

### E221 — return value in a fn without a result type
```sipar
fn f() { return 1 }
```

### E222 — memory type unknown or not storable
`memory.load(key)` returns `T?`, where `T` is the type expected at the use site (a `let` annotation, a
parameter, a return type, or the default after `??`). Without one, or when `T` / the saved value is not
JSON-able (a function), this error is reported.
```sipar
allow memory
fn main() uses memory {
    print(memory.load("count"))
}
```

### E230 — cannot cross the model boundary
An `ai fn` / `agent fn` parameter or result that is not JSON-able (fn types), or a prompt that uses
something other than its parameters and constants (for example, it calls a user function).
```sipar
allow ai
ai fn ask(f: fn(Int) -> Int) -> Str { "go" }
```
```sipar
allow ai
ai fn ask(q: Str) -> Str { "{helper()} {q}" }
fn helper() -> Str { "x" }
```

### E231 — bad attribute
Unknown attribute, given twice, wrong literal type, out of range, `@max_steps` on an `ai fn`.
```sipar
allow ai
@retries(-1)
ai fn ask(q: Str) -> Str { "{q}" }
```

### E232 — bad agent tool
A built-in, an `agent fn`, or a tool whose parameters or result are not JSON-able; or an MCP tool
(`tools [mcp.fs.write_file]`) that its `allow mcp` line does not list as `readonly`.
```sipar
allow ai
agent fn a(goal: Str) -> Str {
    tools [print]
    "{goal}"
}
```

### E240 — `mock` outside a test
```sipar
allow ai
ai fn ask(q: Str) -> Str { "{q}" }
fn f() { mock ask(q) => "x" }
```

### E241 — bad mock
A built-in target, or the wrong number of parameters.
```sipar
allow ai
ai fn ask(q: Str) -> Str { "{q}" }
test "t" { mock ask(a, b) => "x" }
```

### E242 — bad budget limit
Limits: `ai_calls` and `tokens` (Int), `usd` and `seconds` (number).
```sipar
fn f() { budget(calls: 5) { print(1) } }
```

### E243 — bad `main`
```sipar
fn main(n: Int) { }
```

### E250 — `??` on a value that is never none (warning)
```sipar
fn f(n: Int) -> Int { n ?? 0 }
```

## Effects and capabilities (E3xx)

### E301 — effect not declared with `uses`
```sipar
allow net ["example.com"]
fn f() -> Str { http.get("https://example.com") }
```

### E302 — effect not allowed by the program
```sipar
fn f() -> Str uses net { http.get("https://example.com") }
```

### E303 — duplicate `allow` (warning)
```sipar
allow ai
allow ai
```

### E304 — effect in a pure place
A constant or a prompt that uses an effect.
```sipar
allow time
let START = time.now()
```

### E305 — bad reference in a pure place
A constant used before its definition, or a constant calling a user function.
```sipar
let A = B + 1
let B = 2
```

### E306 — `allow` list missing or not allowed
`net fs.read fs.write shell env secret` need a list; `ai time random io memory` take none.
```sipar
allow net
```

### E307 — empty `allow` list (warning)
```sipar
allow net []
```

### E308 — agent tool without a doc comment (warning)
```sipar
allow ai
fn add(a: Int, b: Int) -> Int { a + b }
agent fn a(goal: Str) -> Str {
    tools [add]
    "{goal}"
}
```

### E309 — secret-looking name in `allow env` (warning)
```sipar
allow env ["OPENAI_API_KEY"]
```

### E310 — malformed `allow` entry
An entry that can never mean what it says: an empty string; a net entry with a scheme (`"https://x.com"`), a
path (`"x.com/api"`), a port outside 1..65535, spaces around it (`" x.com"`; the runtime never trims), or more
than one `:` without brackets (`"a:b:c"`, `"x.com:8080:1"`; write IPv6 as `"[::1]"` or `"[::1]:8080"`); a shell entry that is not a valid command (unterminated quote);
an env or secret entry that is not a variable name (`"*"`, `"MY KEY"`); an `allow mcp` line with a bad or
repeated server name, an empty command, no tools, a repeated tool, a `readonly` tool not in `tools` or a bad pin.
```sipar
allow net ["https://api.example.com"]
```

### E311 — `allow` entry grants too much (warning)
`net ["*"]` (matches no host: it is not a wildcard; a bare `allow net` without a list is E306),
`net ["*.com"]` (every host under a top-level domain), `net ["*.co.uk"]`, `["*.github.io"]` and other public
suffixes (a built-in list, plus `co`/`com`/`org`/`net`/`gov`/`edu`/`ac`/... under a code of up to 3 letters, e.g. `*.com.br`), `fs.read`/`fs.write` entries that
resolve, after symlinks, to `/`, your home folder or a folder above the program (`".."`, `"../.."`), and
`["~"]` (not expanded: a folder named `~`).
```sipar
allow fs.write ["/"]
```

## Match and control flow (E4xx)

### E401 — match not exhaustive (or empty)
```sipar
enum Mood { happy, sad }
fn f(m: Mood) -> Int {
    match m {
        Mood.happy => 1
    }
}
```

### E402 — missing return
```sipar
fn f(n: Int) -> Int {
    if n > 0 { return 1 }
}
```

### E403 — `break` / `continue` outside a loop
```sipar
fn f() { break }
```

### E404 — unreachable code (warning)
```sipar
fn f() -> Int {
    return 1
    print(2)
}
```

### E405 — arm never reached (warning)
```sipar
fn f(n: Int) -> Int {
    match n {
        _ => 0
        1 => 1
    }
}
```

### E406 — pattern does not fit the value
```sipar
fn f(n: Int) -> Int {
    match n {
        "one" => 1
        _ => 0
    }
}
```

### E407 — binding arm named like a constant (warning)
```sipar
let LIMIT = 3
fn f(n: Int) -> Int {
    match n {
        LIMIT => 1
    }
}
```

### E408 — match too complex to prove exhaustive (warning)
Proving that a match covers every case took more than 200,000 steps, so the checker stopped and does not
know whether a case is missing. Many columns that each list several variants cause this. Add a final
`_ => ...` arm, or match in two steps.
```sipar
enum C { a, b, c, d }
enum R { r(f0: C, f1: C, f2: C, f3: C, f4: C, f5: C, f6: C, f7: C, f8: C) }
fn f(x: R) -> Int {
    match x {
        R.r(C.a, C.a, _, _, _, _, _, _, _) => 0,
        R.r(C.b, C.b, _, _, _, _, _, _, _) => 1,
        R.r(C.c, C.c, _, _, _, _, _, _, _) => 2,
        R.r(C.d, C.d, _, _, _, _, _, _, _) => 3,
        R.r(_, C.a, C.a, _, _, _, _, _, _) => 4,
        R.r(_, C.b, C.b, _, _, _, _, _, _) => 5,
        R.r(_, C.c, C.c, _, _, _, _, _, _) => 6,
        R.r(_, C.d, C.d, _, _, _, _, _, _) => 7,
        R.r(_, _, C.a, C.a, _, _, _, _, _) => 8,
        R.r(_, _, C.b, C.b, _, _, _, _, _) => 9,
        R.r(_, _, C.c, C.c, _, _, _, _, _) => 10,
        R.r(_, _, C.d, C.d, _, _, _, _, _) => 11,
        R.r(_, _, _, C.a, C.a, _, _, _, _) => 12,
        R.r(_, _, _, C.b, C.b, _, _, _, _) => 13,
        R.r(_, _, _, C.c, C.c, _, _, _, _) => 14,
        R.r(_, _, _, C.d, C.d, _, _, _, _) => 15,
        R.r(_, _, _, _, C.a, C.a, _, _, _) => 16,
        R.r(_, _, _, _, C.b, C.b, _, _, _) => 17,
        R.r(_, _, _, _, C.c, C.c, _, _, _) => 18,
        R.r(_, _, _, _, C.d, C.d, _, _, _) => 19,
        R.r(_, _, _, _, _, C.a, C.a, _, _) => 20,
        R.r(_, _, _, _, _, C.b, C.b, _, _) => 21,
        R.r(_, _, _, _, _, C.c, C.c, _, _) => 22,
        R.r(_, _, _, _, _, C.d, C.d, _, _) => 23,
        R.r(_, _, _, _, _, _, C.a, C.a, _) => 24,
        R.r(_, _, _, _, _, _, C.b, C.b, _) => 25,
        R.r(_, _, _, _, _, _, C.c, C.c, _) => 26,
        R.r(_, _, _, _, _, _, C.d, C.d, _) => 27,
        R.r(_, _, _, _, _, _, _, C.a, C.a) => 28,
        R.r(_, _, _, _, _, _, _, C.b, C.b) => 29,
        R.r(_, _, _, _, _, _, _, C.c, C.c) => 30,
        R.r(_, _, _, _, _, _, _, C.d, C.d) => 31,
        R.r(_, _, _, _, _, _, _, _, C.a) => 32,
        R.r(_, _, _, _, _, _, _, _, C.b) => 33,
        R.r(_, _, _, _, _, _, _, _, C.c) => 34,
        R.r(_, _, _, _, _, _, _, _, C.d) => 35
    }
}
```

