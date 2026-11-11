# Sipar for VS Code

Language support for [Sipar](https://github.com/osimmoapies/sipar#readme) `.sipar` files.

- **Highlighting**: keywords, types, `"strings with {interpolation}"`, `"""triple strings"""`,
  numbers like `1_000_000`, `//` comments and `///` doc comments, `@model(...)` attributes,
  and the capabilities after `allow` and `uses`.
- **Language server** (`sipar lsp`, started for you):
  - errors and warnings as you type, with their code (`E103`, ...) and the hint;
  - hover: types, function signatures with `uses`, `///` docs, and stdlib signatures;
  - go to definition;
  - completion: keywords, names in scope, stdlib modules and functions, and methods after `.`;
  - outline (document symbols).
- **Editing**: bracket and quote pairs, `{}` auto-close inside strings, and `///` continued on Enter.

## Setup

The extension runs `<sipar.path> lsp`. The default `sipar.path` is `python3 -m sipar`, which
works only when `python3` can import the `sipar` package (for example, VS Code started with
`PYTHONPATH` set to this repository). The simplest fix is to point the setting at the launcher
in this repository's `bin/` folder. It sets `PYTHONPATH` itself:

```jsonc
// settings.json
"sipar.path": "/path/to/sipar/bin/sipar"
// or, with spaces in a path:
"sipar.path": "\"/path with spaces/python3\" -m sipar"
```

Sipar needs Python 3.12 or newer. With an older `python3` (macOS's own is 3.9) the server stops at once with
`sipar: needs Python 3.12 or newer (this is 3.9.6)`; name a newer Python for the launcher (macOS / Linux):

```jsonc
"sipar.path": "env SIPAR_PYTHON=/opt/homebrew/bin/python3.12 /path/to/sipar/bin/sipar"
```

Quote any part that contains spaces. A backslash is kept as typed unless it comes before a space,
a quote or another backslash, so a Windows path works as typed (`C:\Python314\python.exe -m sipar`);
on Windows a backslash is always kept. When you change `sipar.path`, the server restarts by
itself. You can also run **Sipar: Restart Language Server** at any time. Server logs go to
the **Output** panel, channel "Sipar"; set `sipar.trace.server` to `messages` to log the
LSP traffic too.

## Install from this folder

```sh
cd editors/vscode
npm install
# either link the folder into VS Code (macOS/Linux):
ln -s "$PWD" ~/.vscode/extensions/sipar
# or build a .vsix and install it:
npx @vscode/vsce package && code --install-extension sipar-0.1.0.vsix
```

## Tests

```sh
npm test    # the grammar on examples/*.sipar with VS Code's own tokenizer, plus extension.js under a stub
```

`python3 -m unittest discover -s tests -p 'test_lsp.py'` (from the repo root) runs the server
tests, and runs these node tests too when `node_modules` is present.
