// Loads extension.js outside VS Code: `vscode` is a stub; the real
// vscode-languageclient is loaded once, then a fake LanguageClient records
// what activate() would spawn. Run: npm run test:extension
'use strict';

const assert = require('assert');
const Module = require('module');
const path = require('path');

const calls = { errors: [], started: 0, stopped: 0, commands: {}, configListeners: [] };
let setting = undefined;

function disposable() { return { dispose() {} }; }
// A permissive stub: any unknown property is a no-op function/class, so the
// real languageclient can load against it.
function permissive(name) {
  const fn = function () { return permissive(name + '()'); };
  return new Proxy(fn, {
    get(_t, k) {
      if (k === Symbol.toPrimitive) return () => name;
      if (k === 'then') return undefined;
      return permissive(name + '.' + String(k));
    },
    construct() { return permissive('new ' + name); },
  });
}
const vscodeStub = new Proxy({
  window: {
    createOutputChannel: (n) => ({ name: n, lines: [], appendLine(l) { this.lines.push(l); }, dispose() {} }),
    showErrorMessage: (m) => { calls.errors.push(m); },
  },
  commands: { registerCommand: (id, fn) => { calls.commands[id] = fn; return disposable(); } },
  workspace: {
    getConfiguration: (sec) => ({ get: (k, d) => (sec === 'sipar' && k === 'path' && setting !== undefined ? setting : d) }),
    onDidChangeConfiguration: (fn) => { calls.configListeners.push(fn); return disposable(); },
  },
}, { get: (t, k) => (k in t ? t[k] : permissive('vscode.' + String(k))) });

let fakeClients = null;   // null = use the real LanguageClient module
const realLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === 'vscode') return vscodeStub;
  if (request === 'vscode-languageclient/node' && fakeClients) {
    const real = realLoad.apply(this, arguments);
    return {
      TransportKind: real.TransportKind,
      LanguageClient: class {
        constructor(id, name, server, client) {
          Object.assign(this, { id, name, server, client });
          fakeClients.push(this);
        }
        async start() {
          calls.started++;
          if (this.server.run.command === 'boom') throw new Error('spawn boom ENOENT');
        }
        async stop() { calls.stopped++; }
      },
    };
  }
  return realLoad.apply(this, arguments);
};

const EXT = path.join(__dirname, '..', 'extension.js');
const tests = [];
const test = (name, fn) => tests.push([name, fn]);

test('loads with the real vscode-languageclient', () => {
  const ext = require(EXT);
  assert.strictEqual(typeof ext.activate, 'function');
  assert.strictEqual(typeof ext.deactivate, 'function');
  const lc = require('vscode-languageclient/node');
  assert.strictEqual(typeof lc.LanguageClient, 'function');
  assert.strictEqual(lc.TransportKind.stdio, 0);
});

test('splitCommand', () => {
  const { splitCommand } = require(EXT);
  const eq = (s, w) => assert.deepStrictEqual(splitCommand(s), w, JSON.stringify(s));
  eq('python3 -m sipar', ['python3', '-m', 'sipar']);
  eq('  python3   -m\tsipar  ', ['python3', '-m', 'sipar']);
  eq('"/Applications/My Py/python3" -m sipar', ['/Applications/My Py/python3', '-m', 'sipar']);
  eq("'/a b/c' x", ['/a b/c', 'x']);
  eq('/a\\ b/c', ['/a b/c']);
  eq('"a\\"b"', ['a"b']);
  eq("'a\\b'", ['a\\b']);
  eq('C:\\\\Py\\\\python.exe', ['C:\\Py\\python.exe']);
  // M3 (round 6): a single backslash before a letter is literal, so Windows paths work as typed
  eq('C:\\Python314\\python.exe -m sipar', ['C:\\Python314\\python.exe', '-m', 'sipar']);
  eq('"C:\\Program Files\\Py\\python.exe" -m sipar', ['C:\\Program Files\\Py\\python.exe', '-m', 'sipar']);
  eq('a\\$b', ['a\\$b']);
  eq('"a\\$b"', ['a\\$b']);
  eq("a\\'b c", ["a'b", 'c']);
  // on Windows a backslash is always literal (UNC paths, a trailing backslash)
  const win = (s, w) => assert.deepStrictEqual(splitCommand(s, true), w, 'win ' + JSON.stringify(s));
  win('\\\\srv\\share\\python.exe -m sipar', ['\\\\srv\\share\\python.exe', '-m', 'sipar']);
  win('"C:\\dir\\" x', ['C:\\dir\\', 'x']);
  win('C:\\a\\ b', ['C:\\a\\', 'b']);
  assert.deepStrictEqual(splitCommand('C:\\\\x', false), ['C:\\x']);
  eq('"" x', ['', 'x']);
  eq('ab"c d"e', ['abc de']);
  eq('', []);
  eq('sipar', ['sipar']);
  assert.throws(() => splitCommand('"unclosed'), /unclosed/);
  assert.throws(() => splitCommand("'unclosed"), /unclosed/);
});

test('serverCommand appends lsp and defaults', () => {
  const { serverCommand } = require(EXT);
  assert.deepStrictEqual(serverCommand('python3 -m sipar'), { command: 'python3', args: ['-m', 'sipar', 'lsp'] });
  assert.deepStrictEqual(serverCommand('/usr/local/bin/sipar'), { command: '/usr/local/bin/sipar', args: ['lsp'] });
  assert.deepStrictEqual(serverCommand(''), { command: 'python3', args: ['-m', 'sipar', 'lsp'] });
  assert.deepStrictEqual(serverCommand('   '), { command: 'python3', args: ['-m', 'sipar', 'lsp'] });
  assert.deepStrictEqual(serverCommand(undefined), { command: 'python3', args: ['-m', 'sipar', 'lsp'] });
  assert.deepStrictEqual(serverCommand(42), { command: 'python3', args: ['-m', 'sipar', 'lsp'] });
  assert.throws(() => serverCommand('""'), /empty/);
  // M3 (round 6): the example in the sipar.path description must spawn the right program
  const desc = require(path.join(__dirname, '..', 'package.json')).contributes.configuration
    .properties['sipar.path'].markdownDescription;
  const winEx = desc.match(/`(C:[^`]*)`/)[1];
  assert.deepStrictEqual(serverCommand(winEx),
    { command: 'C:\\Python314\\python.exe', args: ['-m', 'sipar', 'lsp'] });
  assert.throws(() => serverCommand("'' -m sipar"), /empty/);
});

test('activate spawns `<sipar.path> lsp` over stdio for sipar files', async () => {
  fakeClients = [];
  delete require.cache[EXT];
  const ext = require(EXT);
  const ctx = { subscriptions: [] };
  await ext.activate(ctx);
  assert.strictEqual(fakeClients.length, 1);
  const c = fakeClients[0];
  assert.strictEqual(c.id, 'sipar');
  assert.deepStrictEqual(c.server.run.command, 'python3');
  assert.deepStrictEqual(c.server.run.args, ['-m', 'sipar', 'lsp']);
  assert.strictEqual(c.server.run.transport, 0);
  assert.deepStrictEqual(c.client.documentSelector,
    [{ scheme: 'file', language: 'sipar' }, { scheme: 'untitled', language: 'sipar' }]);
  assert.ok(c.client.outputChannel && c.client.outputChannel.name === 'Sipar');
  assert.strictEqual(calls.started, 1);
  assert.ok(typeof calls.commands['sipar.restartServer'] === 'function');
  assert.ok(ctx.subscriptions.length >= 3);

  // Restart command: stops the old client, starts a new one.
  await calls.commands['sipar.restartServer']();
  assert.strictEqual(calls.stopped, 1);
  assert.strictEqual(fakeClients.length, 2);

  // Unrelated setting change: nothing happens; sipar.path change: restart with the new command.
  setting = '"/opt/my py/sipar"';
  for (const l of calls.configListeners) l({ affectsConfiguration: (s) => s === 'editor.fontSize' });
  await new Promise((r) => setTimeout(r, 10));
  assert.strictEqual(fakeClients.length, 2);
  for (const l of calls.configListeners) l({ affectsConfiguration: (s) => s === 'sipar.path' });
  await new Promise((r) => setTimeout(r, 10));
  assert.strictEqual(fakeClients.length, 3);
  assert.strictEqual(fakeClients[2].server.run.command, '/opt/my py/sipar');
  assert.deepStrictEqual(fakeClients[2].server.run.args, ['lsp']);

  // A command that fails to start: an error message, no crash, deactivate still fine.
  setting = 'boom';
  await calls.commands['sipar.restartServer']();
  assert.strictEqual(calls.errors.length, 1);
  assert.match(calls.errors[0], /sipar\.path/);
  assert.match(calls.errors[0], /spawn boom ENOENT/);
  // A bad setting (unclosed quote) also reports instead of throwing.
  setting = '"python3';
  await calls.commands['sipar.restartServer']();
  assert.strictEqual(calls.errors.length, 2);
  assert.match(calls.errors[1], /unclosed/);
  const before = calls.stopped;
  await ext.deactivate();
  assert.strictEqual(calls.stopped, before);   // no client running: nothing to stop

  setting = undefined;
  await calls.commands['sipar.restartServer']();
  const stoppedBefore = calls.stopped;
  await ext.deactivate();
  assert.strictEqual(calls.stopped, stoppedBefore + 1);
});

(async () => {
  let failed = 0;
  for (const [name, fn] of tests) {
    try { await fn(); console.log('ok   ' + name); } catch (e) { failed++; console.log('FAIL ' + name + ': ' + (e && e.stack || e)); }
  }
  console.log(failed ? failed + ' failed' : 'all passed');
  process.exit(failed ? 1 : 0);
})();
