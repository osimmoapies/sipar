# Contributing

Thanks for helping. Sipar has no runtime dependencies (Python 3.12+ standard library only), and the
goal is to keep it that way.

## Run the tests

```sh
python3 tools/ptest.py          # all tests, in parallel (about 20 s)
python3 -m unittest discover -s tests -p 'test_round9_sec.py'   # one file
```

## Build the playground

The site at https://osimmoapies.github.io/sipar/ is `playground/` plus the `sipar` package plus a pinned
Pyodide release. Nothing built is kept in the repository.

```sh
python3 tools/build_site.py --out _site --fetch-pyodide    # downloads the Pyodide archive (6.5 MB), checks its hash
node tools/site_smoke.mjs _site                            # every scenario on the site's own Python runtime
python3 -m http.server -d _site --bind 127.0.0.1           # then open http://127.0.0.1:8000
```

## Rules for changes

- Every bug fix comes with a test that fails before the fix.
- Security behaviour is defined by SPEC.md. If you change behaviour, change SPEC.md in the same pull request.
- Error messages must never contain a secret value; use the existing redaction helpers in `sipar/errors.py`.
- No new runtime dependencies.

## Reporting bugs

Open an issue with a small `.sipar` program, the command you ran, what you got and what you expected.
Security problems: see SECURITY.md.
