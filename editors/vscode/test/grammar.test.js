// Tokenizes Sipar code with the engine VS Code itself uses (vscode-textmate +
// vscode-oniguruma) and checks the scopes. Run: npm run test:grammar
'use strict';

const fs = require('fs');
const path = require('path');
const assert = require('assert');
const vsctm = require('vscode-textmate');
const oniguruma = require('vscode-oniguruma');

const HERE = path.join(__dirname, '..');
const REPO = path.join(HERE, '..', '..');
const GRAMMAR = path.join(HERE, 'syntaxes', 'sipar.tmLanguage.json');

async function loadGrammar() {
  const wasm = fs.readFileSync(require.resolve('vscode-oniguruma/release/onig.wasm'));
  await oniguruma.loadWASM(wasm.buffer.slice(wasm.byteOffset, wasm.byteOffset + wasm.byteLength));
  const registry = new vsctm.Registry({
    onigLib: Promise.resolve({
      createOnigScanner: (p) => new oniguruma.OnigScanner(p),
      createOnigString: (s) => new oniguruma.OnigString(s),
    }),
    loadGrammar: async (scope) => scope === 'source.sipar'
      ? vsctm.parseRawGrammar(fs.readFileSync(GRAMMAR, 'utf8'), GRAMMAR)
      : null,
  });
  return registry.loadGrammar('source.sipar');
}

// [[text, scopes], ...] for every token of every line.
function tokenize(grammar, text) {
  const out = [];
  let stack = vsctm.INITIAL;
  for (const line of text.split(/\r?\n/)) {
    const r = grammar.tokenizeLine(line, stack);
    for (const t of r.tokens) out.push([line.slice(t.startIndex, t.endIndex), t.scopes]);
    stack = r.ruleStack;
  }
  return out;
}

// The scopes of the first token whose text is `text` (the nth one when nth > 0).
function scopesOf(tokens, text, nth = 0) {
  const hits = tokens.filter(([t]) => t === text);
  assert.ok(hits.length > nth, 'no token ' + JSON.stringify(text) + ' #' + nth);
  return hits[nth][1];
}

function has(tokens, text, scope, nth = 0) {
  const sc = scopesOf(tokens, text, nth);
  assert.ok(sc.some((s) => s.startsWith(scope)),
    JSON.stringify(text) + ' #' + nth + ' should have ' + scope + ', got ' + sc.join(' '));
}

function lacks(tokens, text, scope, nth = 0) {
  const sc = scopesOf(tokens, text, nth);
  assert.ok(!sc.some((s) => s.startsWith(scope)),
    JSON.stringify(text) + ' #' + nth + ' should not have ' + scope + ', got ' + sc.join(' '));
}

const CASES = {
  'keywords, declarations, types': (g) => {
    const t = tokenize(g, 'type P = { a: Int }\nenum E { x }\nai fn ask(q: Str) -> P uses ai, net { "q" }\nlet v = 1\nvar w = none');
    has(t, 'type', 'keyword.declaration.type');
    has(t, 'P', 'entity.name.type', 0);
    has(t, 'Int', 'support.type.builtin');
    has(t, 'ai', 'storage.modifier', 0);
    has(t, 'fn', 'keyword.declaration.function');
    has(t, 'ask', 'entity.name.function.sipar');
    has(t, 'uses', 'keyword.other.uses');
    has(t, 'ai', 'support.constant.capability', 1);
    has(t, 'net', 'support.constant.capability');
    has(t, 'let', 'keyword.declaration');
    has(t, 'none', 'constant.language');
  },
  'strings and interpolation': (g) => {
    const t = tokenize(g, 'let s = "hi {name.upper()} \\{x\\} \\q {m["a"]}"');
    has(t, 'hi ', 'string.quoted.double');
    has(t, '{', 'punctuation.section.interpolation.begin', 0);
    has(t, 'name', 'variable.other');
    has(t, 'upper', 'entity.name.function.call');
    has(t, '\\{', 'constant.character.escape');
    has(t, '\\q', 'invalid.illegal.escape');
    has(t, 'a', 'string.quoted.double', 0);
    lacks(t, 'x', 'meta.interpolation');
  },
  'triple strings keep state across lines': (g) => {
    const t = tokenize(g, 'let p = """\nline fn {code}\n"""\nlet after = 1');
    has(t, 'line fn ', 'string.quoted.triple');
    lacks(t, 'line fn ', 'keyword');
    has(t, 'code', 'meta.interpolation');
    lacks(t, 'after', 'string');
  },
  'numbers with underscores': (g) => {
    const t = tokenize(g, 'let n = 1_000_000 + 3.14 + 2e10 + 1.5E-3');
    for (const n of ['1_000_000', '3.14', '2e10', '1.5E-3']) has(t, n, 'constant.numeric');
  },
  'comments and docs': (g) => {
    const t = tokenize(g, '/// Adds.\n// plain\nlet x = 1 // tail');
    has(t, '/// Adds.', 'comment.line.documentation');
    has(t, '// plain', 'comment.line.double-slash');
    has(t, '// tail', 'comment.line.double-slash');
  },
  'attributes and allow': (g) => {
    const t = tokenize(g, '@model("gpt") @retries(3)\nallow fs.read ["."]\nallow net ["x.com"]');
    has(t, 'model', 'entity.name.function.decorator');
    has(t, 'retries', 'entity.name.function.decorator');
    has(t, 'fs.read', 'support.constant.capability');
    has(t, 'net', 'support.constant.capability');
    has(t, 'allow', 'keyword.other.allow');
  },
  'unterminated string stops at end of line': (g) => {
    const t = tokenize(g, 'let s = "oops\nlet y = 2');
    lacks(t, 'y', 'string');
  },
  // L8 (round 6): names are ASCII only (SPEC §1), as in the lexer; other letters are marked invalid
  'non-ASCII names are invalid, text is not': (g) => {
    const t = tokenize(g, 'fn привет(имя: Str) { print("{имя} и {x}") }\nlet Тип = 1\nlet s = "текст" // коммент');
    has(t, 'привет', 'invalid.illegal.character');
    lacks(t, 'привет', 'entity.name.function');
    has(t, 'имя', 'invalid.illegal.character', 0);
    has(t, 'имя', 'invalid.illegal.character', 1);
    has(t, 'Тип', 'invalid.illegal.character');
    lacks(t, 'Тип', 'entity.name.type');
    has(t, ' и ', 'string.quoted.double');
    lacks(t, ' и ', 'invalid');
    has(t, 'текст', 'string.quoted.double');
    lacks(t, 'текст', 'invalid');
    has(t, '// коммент', 'comment.line');
    const u = tokenize(g, 'fn ok_1() { let Ab = A_B }\ntype Été = { x: Int }');
    has(u, 'ok_1', 'entity.name.function.sipar');
    has(u, 'Ab', 'entity.name.type');
    has(u, 'A_B', 'variable.other.constant');
    lacks(u, 'type', 'invalid');
    has(u, 'É', 'invalid.illegal.character');
  },
  // L7 (round 6): MCP servers: `allow mcp`, `uses mcp`, `mcp.server.tool(...)`, `readonly [...]`, `pin "..."`
  'MCP lines': (g) => {
    const t = tokenize(g, 'allow mcp "fs" ["python3", "fs_server.py"]\n    tools ["read_text_file"] readonly ["read_text_file"] pin "sha256:ab"\n' +
      'fn f() -> Str uses mcp, shell { mcp.fs.read_text_file(path: "a") }\nlet readonly = 1\nlet pin = readonly');
    has(t, 'allow', 'keyword.other.allow');
    has(t, 'mcp', 'support.constant.capability', 0);
    has(t, 'tools', 'keyword.other');
    has(t, 'readonly', 'keyword.other', 0);
    has(t, 'pin', 'keyword.other', 0);
    has(t, 'mcp', 'support.constant.capability', 1);
    has(t, 'mcp', 'support.module', 2);
    has(t, 'read_text_file', 'entity.name.function.call', 2);
    has(t, 'readonly', 'variable.other', 1);
    has(t, 'pin', 'variable.other', 1);
    has(t, 'readonly', 'variable.other', 2);
  },
};

async function main() {
  const g = await loadGrammar();
  let failed = 0;
  for (const [name, fn] of Object.entries(CASES)) {
    try { fn(g); console.log('ok   ' + name); } catch (e) { failed++; console.log('FAIL ' + name + ': ' + e.message); }
  }
  // Smoke: every example tokenizes, no line ends inside a string, nothing is invalid.
  const files = [];
  (function walk(d) {
    for (const f of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, f.name);
      if (f.isDirectory()) walk(p); else if (f.name.endsWith('.sipar')) files.push(p);
    }
  })(path.join(REPO, 'examples'));
  for (const f of files) {
    const name = 'smoke ' + path.relative(REPO, f);
    try {
      const t = tokenize(g, fs.readFileSync(f, 'utf8'));
      const bad = t.filter(([, sc]) => sc.some((s) => s.startsWith('invalid')));
      assert.deepStrictEqual(bad, [], 'invalid tokens');
      const fns = t.filter(([, sc]) => sc.includes('entity.name.function.sipar')).length;
      assert.ok(t.length > 50 && fns > 0, 'too few tokens');
      console.log('ok   ' + name + ' (' + t.length + ' tokens)');
    } catch (e) { failed++; console.log('FAIL ' + name + ': ' + e.message); }
  }
  assert.ok(files.length >= 3, 'examples not found');
  console.log(failed ? failed + ' failed' : 'all passed');
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });
