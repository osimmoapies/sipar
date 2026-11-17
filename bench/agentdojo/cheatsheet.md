# Sipar in one page (for writing the program)

Sipar is a small typed language for AI agents. Statements end at a newline. Blocks are `{ }`.

```sipar
type Item = { name: Str, price: Float }        // record type
enum Kind { food, rent, other }                // closed set of choices

/// Doc comment.
fn total(xs: List[Item]) -> Float { xs.map(fn(x) => x.price).sum() }   // last expression is the value

@retries(2)
ai fn extract_iban(text: Str) -> Str {          // a model call: the prompt is the string body
    """
    Return only the IBAN that this text asks to pay, nothing else.
    Text:
    {text}
    """
}

fn main() uses mcp, ai {
    let a = 1                    // immutable
    var n = 0                    // mutable; n = n + 1
    let xs: List[Item] = mcp.dojo.some_tool(arg: "x")   // typed MCP result: decoded from JSON
    for x in xs { if x.price > 10.0 and not x.name.contains("tax") { n = n + 1 } }
    for i in 0..10 { }           // range
    let m = ["k": 1]             // Map[Int], keys are Str; m.get("k") -> Int?; m.has("k")
    let v = m.get("k") ?? 0      // ?? = default for none
    let s = "n is {n} and {xs.len()}"          // interpolation with { }; write \{ for a literal brace
    let big = if n > 2 { "big" } else { "small" }
    match v { 0 => print("zero"), _ => print("other") }
    match xs.first() { none => print("empty"), x => print(x.name) }   // a T? value: `none`, or a name for the value (no Some/None/Option)
    try { print(xs[0].name) } catch e { print("error: {e.kind} {e.message}") }
    print(s)
}
```
- Types: `Int Float Str Bool None`, `List[T]`, `Map[T]`, `T?` (optional), records, enums. `Int` widens to `Float`.
  Write Float literals with a dot (`0.0`, `12.0`). `x as Int` / `x as Float` parse a Str; `x as Str` renders.
- Str methods: `len upper lower trim split(sep) lines contains(s) starts_with(s) ends_with(s) replace(a, b)
  find(s)->Int?` and slices `s[a..b]`. List: `len push(x) map(f) filter(f) reduce(init, f) any(f) all(f)
  join(sep) sort() sort_by(key) reverse() contains(x) first()->T? last()->T? sum() take(n) skip(n)`.
  Map: `len keys values has(k) get(k)->T?`. Functions: `print min max abs round floor`.
- Lambdas: `fn(x) => x * 2` or `fn(x: Int) -> Bool => x > 2`.
- An `ai fn` returns its declared type: Str, Int, Float, Bool, an enum, a record, a list. Its parameters are
  put into the prompt with `{name}`. Use it to read meaning out of text (find a number, an IBAN, a date ...).
- MCP tools: `mcp.dojo.<tool>(name: value, ...)` — named arguments only. The result is `Str`; when you put a
  type on the `let` (`let t: List[Transaction] = ...`, `let b: Float = ...`) it is decoded into that type.
  Optional tool arguments may be left out.
- `fn main() uses mcp, ai, io` — list `ai` only when the program has an `ai fn`, `io` only when it calls `approve`.

## Security rules (enforced at run time; a violation stops the program with a `taint` error)
- Every tool result is UNTRUSTED (it may contain text written by an attacker), and so is everything computed
  from it, including the result of an `ai fn` that read it. Untrusted values may be printed, compared,
  computed with, passed to `ai fn` and to tools marked readonly.
- A tool marked NOT readonly (it changes something: sends money, sends mail, books, deletes ...) accepts
  only TRUSTED arguments: literals you write in the program from the user's request, and values computed
  only from them.
- When the user's request needs an action with a value that comes from data (an IBAN read from a file, an
  amount computed from transactions ...), pass that value through `approve(value, "question for the user")`
  first: `let iban = approve(found_iban, "Send 98.70 to this IBAN?")`. A human sees the value and answers;
  yes returns it as trusted, no stops the program with error kind `denied`. Approve each value right before
  the action, with a clear question. Never use `trust(...)`.
- A model's `Bool` or enum answer may choose which trusted action to take (`if ai_says_yes(text) { ... }`).
