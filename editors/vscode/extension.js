// Sipar for VS Code: starts `<sipar.path> lsp` and talks LSP over stdio.
'use strict';

const vscode = require('vscode');
const { LanguageClient, TransportKind } = require('vscode-languageclient/node');

const DEFAULT_PATH = 'python3 -m sipar';

let client = null;
let output = null;

// Split a command line like a shell does, without running a shell:
// spaces separate words; '...' keeps everything literal; "..." groups words.
// A backslash escapes only a space, a quote or a backslash (outside quotes;
// inside "..." only " and \), so a Windows path such as
// C:\Python314\python.exe -m sipar keeps its backslashes. On Windows
// (windows = true) a backslash is always literal: \\server\share works.
// Throws on an unclosed quote.
function splitCommand(line, windows = process.platform === 'win32') {
  const words = [];
  let cur = '';
  let inWord = false;
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote === "'") {
      if (c === "'") quote = null; else cur += c;
    } else if (quote === '"') {
      if (c === '"') quote = null;
      else if (!windows && c === '\\' && i + 1 < line.length && '"\\'.includes(line[i + 1])) cur += line[++i];
      else cur += c;
    } else if (c === "'" || c === '"') {
      quote = c; inWord = true;
    } else if (!windows && c === '\\' && i + 1 < line.length && /[\s'"\\]/.test(line[i + 1])) {
      cur += line[++i]; inWord = true;
    } else if (/\s/.test(c)) {
      if (inWord) { words.push(cur); cur = ''; inWord = false; }
    } else {
      cur += c; inWord = true;
    }
  }
  if (quote) throw new Error('unclosed ' + quote + ' in sipar.path');
  if (inWord) words.push(cur);
  return words;
}

// The executable and arguments for the language server.
function serverCommand(setting) {
  const text = (typeof setting === 'string' && setting.trim()) ? setting : DEFAULT_PATH;
  const words = splitCommand(text);
  if (words.length === 0 || words[0] === '') throw new Error('sipar.path is empty');
  return { command: words[0], args: words.slice(1).concat(['lsp']) };
}

function makeClient() {
  const setting = vscode.workspace.getConfiguration('sipar').get('path', DEFAULT_PATH);
  const { command, args } = serverCommand(setting);
  const run = { command, args, transport: TransportKind.stdio };
  const serverOptions = { run, debug: run };
  const clientOptions = {
    documentSelector: [
      { scheme: 'file', language: 'sipar' },
      { scheme: 'untitled', language: 'sipar' },
    ],
    outputChannel: output,
    traceOutputChannel: output,
  };
  return new LanguageClient('sipar', 'Sipar', serverOptions, clientOptions);
}

async function start() {
  try {
    client = makeClient();
    await client.start();
  } catch (err) {
    client = null;
    const msg = 'Sipar: could not start the language server (' + (err && err.message ? err.message : err) +
      '). Check the "sipar.path" setting.';
    output.appendLine(msg);
    vscode.window.showErrorMessage(msg);
  }
}

async function stop() {
  const c = client;
  client = null;
  if (c) {
    try { await c.stop(); } catch (err) { output.appendLine('Sipar: stop failed: ' + err); }
  }
}

async function restart() {
  await stop();
  await start();
}

async function activate(context) {
  output = vscode.window.createOutputChannel('Sipar');
  context.subscriptions.push(output);
  context.subscriptions.push(vscode.commands.registerCommand('sipar.restartServer', restart));
  context.subscriptions.push(vscode.workspace.onDidChangeConfiguration((e) => {
    if (e.affectsConfiguration('sipar.path')) restart();
  }));
  await start();
}

function deactivate() {
  return stop();
}

module.exports = { activate, deactivate, splitCommand, serverCommand };
