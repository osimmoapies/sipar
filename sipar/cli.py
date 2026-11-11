"""Command line: sipar run|check|test|replay|trace|spec|lsp|--version.
Exit codes: 0 ok, 1 an error in the program, its checks, tests or replay, 2 usage or an input file that cannot be
read (missing, a directory, no permission, not UTF-8), 141 a closed output pipe (SPEC.md §9)."""
from __future__ import annotations

import argparse
import codecs
import errno
import json
import os
import sys
import traceback

from . import __version__
from .errors import SiparRuntimeError, SiparSyntaxError, escape_controls
from .fileread import MAX_FILE_BYTES, open_regular, read_text, why_unreadable

USAGE_EXIT = 2


class UsageError(Exception):
    pass


USAGE_HINT = "check the file path and the command line; `sipar --help` shows the usage"


def _read(path: str) -> str:
    """A program source: a regular file, or a pipe such as `sipar check <(gen.sh)` (read to its end; a named
    FIFO with no writer reads as empty, never hangs). A device or more than 256 MB is refused (round 8, L1)."""
    try:
        return read_text(path, MAX_FILE_BYTES, allow_pipe=True)
    except FileNotFoundError:
        raise UsageError(f"no such file: {path}")
    except (OSError, UnicodeDecodeError) as e:          # round 7: not Python's `[Errno 13] ...: 'x.sipar'`
        # round 9 (F4): a directory too says "cannot read X: is a directory", like every other reader
        raise UsageError(f"cannot read {path}: {why_unreadable(e)}")


def _checker():
    try:
        from . import checker  # noqa: F401
    except ImportError:
        return None
    return getattr(checker, "check_source", None)


def load_program(path: str, err, *, gate: bool = True):
    """Parse (and, when the checker is available, check) a program. Returns (program, src) or None on errors."""
    src = _read(path)
    check_source = _checker() if gate else None
    if check_source is not None:
        program, diags = check_source(src, path)
        errors = [d for d in diags if d.severity == "error"]
        for d in diags:
            err.write(d.render(src) + "\n")
        if program is None or errors:
            n = len(errors) or 1
            err.write(f"sipar: {n} error(s); not running\n")
            return None
        return program, src
    from .parser import parse
    try:
        return parse(src, path), src
    except SiparSyntaxError as e:
        err.write(e.diag.render(src) + "\n")
        return None


def _main_error(program, path: str, args) -> SiparRuntimeError | None:
    """`sipar run` refuses, before it writes a journal, a program without `fn main()` or arguments that a
    0-parameter main cannot take (SPEC §9)."""
    from . import ast as A
    main = next((it for it in program.items if isinstance(it, A.FnDecl) and it.name == "main"), None)
    if main is None or main.kind != "fn":
        return SiparRuntimeError("type", "the program has no 'fn main()'", 1, 1, path)
    if not main.params and args:
        given = f"{len(args)} {'was' if len(args) == 1 else 'were'} given"
        return SiparRuntimeError("value", f"fn main() takes no arguments, but {given}; declare "
                                          "`fn main(args: List[Str])` to read them", main.line, main.col, path)
    return None


def _render_runtime_error(e: SiparRuntimeError, file: str) -> str:
    from .runtime.interp import safe_render_error
    if not e.file:
        e.file = file
    return safe_render_error(e)


# ------------------------------------------------------------------ commands

def cmd_check(a, out, err) -> int:
    try:
        src = _read(a.file)
    except UsageError as e:
        if not a.json:
            raise
        out.write(json.dumps([{"code": "usage", "severity": "error", "file": a.file, "line": 0, "col": 0,
                               "message": str(e), "hint": USAGE_HINT}], ensure_ascii=False, indent=2) + "\n")
        return USAGE_EXIT
    check_source = _checker()
    if check_source is None:
        from .parser import parse
        try:
            parse(src, a.file)
            diags = []
        except SiparSyntaxError as e:
            diags = [e.diag]
    else:
        _, diags = check_source(src, a.file)
    errors = [d for d in diags if d.severity == "error"]
    if a.json:
        out.write(json.dumps([d.to_dict() for d in diags], ensure_ascii=False, indent=2) + "\n")
    else:
        for d in diags:
            out.write(d.render(src) + "\n")
        if not diags:
            name = escape_controls(a.file)
            out.write(f"{name}: ok\n" if check_source else f"{name}: syntax ok (checker not installed)\n")
        else:
            out.write(f"{len(errors)} error(s), {len(diags) - len(errors)} warning(s)\n")
    return 1 if errors else 0


def cmd_run(a, out, err) -> int:
    from .runtime.interp import Interp
    from .runtime.journal import Journal, new_run_path
    loaded = load_program(a.file, err)
    if loaded is None:
        return 1
    program, _ = loaded
    bad = _main_error(program, a.file, list(a.args))
    if bad is not None:
        err.write(_render_runtime_error(bad, a.file) + "\n")
        return 1
    path = new_run_path(a.file)
    journal = Journal(path=path)
    try:
        it = Interp(program, a.file, journal=journal, out=out, err_out=err)
        it.run_main(list(a.args))
        return 0
    except SiparRuntimeError as e:
        err.write(_render_runtime_error(e, a.file) + "\n")
        err.write(f"journal: {escape_controls(path)}\n")
        return 1
    except KeyboardInterrupt:
        err.write(f"\nsipar: interrupted\njournal: {escape_controls(path)}\n")
        return 1
    finally:
        journal.close()


def _check_journal(path: str) -> None:
    """The usage errors of a journal argument, the same words and exit code 2 for `replay` and `trace` (L12,
    round 6); a journal that is not UTF-8 text is one of them (round 7), checked in chunks."""
    if os.path.isdir(path):
        raise UsageError(f"{path} is a directory, not a journal file")
    if not os.path.lexists(path):       # L3 (round 8): only a path that is not there is "no such journal"
        raise UsageError(f"no such journal: {path}")
    dec = codecs.getincrementaldecoder("utf-8")()
    try:                                # a FIFO, a device or a symlink loop: "cannot read X: <why>"
        with open(open_regular(path, None), "rb") as fh:
            while chunk := fh.read(1 << 20):
                dec.decode(chunk)
            dec.decode(b"", final=True)
    except (OSError, UnicodeDecodeError) as e:
        raise UsageError(f"cannot read {path}: {why_unreadable(e)}")


def cmd_replay(a, out, err) -> int:
    from .runtime.interp import Interp
    from .runtime.journal import Journal
    loaded = load_program(a.file, err)
    if loaded is None:
        return 1
    program, _ = loaded
    _check_journal(a.journal)
    try:
        journal = Journal(replay=Journal.load(a.journal))
        it = Interp(program, a.file, journal=journal, out=out, err_out=err)
        it.run_main(None)
        left = journal.unused()
        if left:
            raise SiparRuntimeError("replay", f"the program finished but {left} entr(ies) of journal {a.journal} "
                                              "were not used; the program or its inputs changed", 1, 1, a.file)
        return 0
    except SiparRuntimeError as e:
        err.write(_render_runtime_error(e, a.file) + "\n")
        return 1


def cmd_test(a, out, err) -> int:
    from .runtime.interp import run_tests
    loaded = load_program(a.file, err)
    if loaded is None:
        return 1
    program, _ = loaded
    passed, failed = run_tests(program, a.file, live=a.live, record=a.record, out=out, err_out=err)
    return 1 if failed else 0


def spec_text() -> str:
    from .stdlib import ATTRIBUTES, BUDGET_LIMITS, FUNCTIONS, METHODS

    def sig(name, s):
        ps = []
        for p, t in s.params:
            ps.append(f"{p}: {t}" + (" = default" if p in s.defaults else ""))
        line = f"  {name}({', '.join(ps)}) -> {s.ret}"
        tags = []
        if s.effects:
            tags.append("needs allow " + "/".join(sorted(s.effects)))
        if s.source:
            tags.append(f"result untrusted:{s.source}")
        if s.secret:
            tags.append("result secret")
        if s.sink:
            tags.append("untrusted not allowed in " + ",".join(sorted(s.sink)))
        if s.no_secret:
            tags.append("secret not allowed in " + ",".join(sorted(s.no_secret)))
        if tags:
            line += "   [" + "; ".join(tags) + "]"
        if s.doc:
            line += "  — " + s.doc
        return line

    parts = []
    spec_path = spec_file()
    if spec_path is not None:
        try:
            with open(spec_path, encoding="utf-8") as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError) as e:      # round 7: not "internal error (UnicodeDecodeError)"
            raise UsageError(f"cannot read {spec_path}: {why_unreadable(e)}")
        # all of SPEC.md (§5 holds rules the tables below cannot show); the generated tables are exact
        # blank lines between sections are dropped (compact for prompts); inside a ``` fence they are code (L15)
        out_lines, fence = [], False
        for line in text.splitlines():
            if line.lstrip().startswith("```"):
                fence = not fence
            if line.strip() or fence:
                out_lines.append(line.rstrip())
        parts.append("\n".join(out_lines))
    parts.append("## Standard library (generated from sipar/stdlib.py)")
    parts.append("Functions:")
    parts.extend(sig(n, s) for n, s in FUNCTIONS.items())
    for ty, ms in METHODS.items():
        parts.append(f"{ty} methods:")
        parts.extend(sig("." + n, s) for n, s in ms.items())
    parts.append("Attributes on ai/agent fn: " + ", ".join(f"@{k}({v})" for k, v in ATTRIBUTES.items()))
    parts.append("Budget limits: " + ", ".join(f"{k}: {v}" for k, v in BUDGET_LIMITS.items()))
    return "\n".join(parts) + "\n"


def spec_file(package_dir: str | None = None) -> str | None:
    """Where SPEC.md is: inside the package (an installed wheel carries a copy there, see pyproject.toml), else
    one folder up (a source checkout). None when neither is a file."""
    here = os.path.dirname(os.path.abspath(__file__)) if package_dir is None else package_dir
    for path in (os.path.join(here, "SPEC.md"), os.path.join(os.path.dirname(here), "SPEC.md")):
        if os.path.isfile(path):
            return path
    return None


def cmd_trace(a, out, err) -> int:
    from .trace import TraceError, read_entries, render, summarize
    _check_journal(a.journal)
    try:
        with open(a.journal, "rb") as fh:
            text = fh.read().decode("utf-8")
    except (OSError, UnicodeDecodeError) as e:      # changed since _check_journal: the same words (round 7)
        raise UsageError(f"cannot read {a.journal}: {why_unreadable(e)}")
    try:
        s = summarize(read_entries(text, os.path.basename(a.journal)))
    except TraceError as e:
        err.write(escape_controls(f"sipar trace: {e}") + "\n")
        return 1
    if a.json:
        out.write(json.dumps(s, ensure_ascii=False, indent=2) + "\n")
    else:
        out.write(render(s))
    return 0


def cmd_spec(a, out, err) -> int:
    out.write(spec_text())
    return 0


def cmd_lsp(a, out, err) -> int:
    from . import lsp
    if isinstance(sys.stdout, _ClosedOut):      # no stream to answer on (round 9, M2)
        return PIPE_EXIT
    return lsp.main()


# ------------------------------------------------------------------ main

class _Parser(argparse.ArgumentParser):
    def _print_message(self, message, file=None):
        """argparse drops a failed write; here `sipar --help >&-` / `| head` is a closed pipe, exit 141 (round 9)."""
        if message:
            (file or sys.stderr).write(message)

    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write(f"sipar: {escape_controls(message)}\n")
        sys.exit(USAGE_EXIT)


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="sipar", description="Sipar — a safe, typed, replayable language for AI agents.")
    p.add_argument("--version", action="version", version=f"sipar {__version__}")
    sub = p.add_subparsers(dest="cmd", metavar="command")
    p.subs = {}
    r = sub.add_parser("run", help="run fn main()")
    r.add_argument("file", help="the .sipar program")
    r.add_argument("args", nargs=argparse.REMAINDER, help="arguments for `fn main(args: List[Str])`")
    c = sub.add_parser("check", help="type/effect check without running")
    c.add_argument("file", help="the .sipar program")
    c.add_argument("--json", action="store_true", help="print the diagnostics as a JSON list (for editors and CI)")
    t = sub.add_parser("test", help="run test blocks")
    t.add_argument("file", help="the .sipar program with test blocks")
    t.add_argument("--live", action="store_true", help="allow real AI calls for unmocked ai/agent fns")
    t.add_argument("--record", action="store_true", help="record fixtures to .sipar/fixtures/<name>-<hash>.jsonl")
    rp = sub.add_parser("replay", help="re-run a program from a journal without real effects")
    rp.add_argument("file", help="the .sipar program that wrote the journal")
    rp.add_argument("journal", help="the run journal (.sipar/runs/*.jsonl)")
    tr = sub.add_parser("trace", help="cost, tokens, time and errors per function from a run journal")
    tr.add_argument("journal", help="the run journal (.sipar/runs/*.jsonl)")
    tr.add_argument("--json", action="store_true", help="print the summary as JSON")
    sub.add_parser("spec", help="print the full language reference: SPEC.md and the stdlib tables (for humans and LLM prompts)")
    sub.add_parser("lsp", help="language server over stdio (for editors)")
    p.subs.update(sub.choices)
    return p


COMMANDS = {"run": cmd_run, "check": cmd_check, "test": cmd_test, "replay": cmd_replay, "spec": cmd_spec,
            "trace": cmd_trace, "lsp": cmd_lsp}


PIPE_EXIT = 141      # 128 + SIGPIPE: what a Unix tool killed by a closed pipe (`sipar run x | head`) reports


def _tolerant_streams() -> None:
    """A terminal or pipe whose encoding cannot show a character (PYTHONIOENCODING=ascii, LC_ALL=C) gets an
    escape such as \\xe9 instead of a crash (round 5, C9)."""
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass


class _ClosedOut:
    """sys.stdout when fd 1 was closed at start (`sipar run x >&-`; Python leaves sys.stdout None): every
    write is a closed pipe, so the command ends quietly with exit 141 like `| head` (round 9, M2)."""

    def write(self, text: str) -> int:
        raise BrokenPipeError(errno.EPIPE, "standard output is closed")

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False


class _QuietErr:
    """sys.stderr for the real process: a message that cannot be written (fd 2 closed at start, `2>&-`, or a
    reader that went away) is dropped, so the exit code never depends on stderr (round 9, M3)."""

    def __init__(self, stream) -> None:
        self._stream = stream

    def write(self, text: str) -> int:
        try:
            return self._stream.write(text)
        except (AttributeError, OSError, ValueError):
            return len(text)

    def flush(self) -> None:
        try:
            self._stream.flush()
        except (AttributeError, OSError, ValueError):
            pass

    def isatty(self) -> bool:
        try:
            return bool(self._stream.isatty())
        except (AttributeError, OSError, ValueError):
            return False

    def __getattr__(self, name):
        return getattr(self._stream, name)


def _closed_streams() -> None:
    """A standard stream that was closed when sipar started (`>&-`, `2>&-`, `<&-`; Python sets it to None).
    Its fd is held by /dev/null, so no file Sipar opens (a journal) becomes fd 0-2; stdin then reads as
    empty, stdout is a closed pipe and stderr drops its messages (round 9, M2/M3)."""
    for fd in (0, 1, 2):
        try:
            os.fstat(fd)
        except OSError:
            try:
                new = os.open(os.devnull, os.O_RDWR)
                if new != fd:
                    os.dup2(new, fd)
                    os.close(new)
            except OSError:
                pass
    if sys.stdin is None:
        sys.stdin = open(os.devnull, encoding="utf-8")
    if sys.stdout is None:
        sys.stdout = _ClosedOut()
    if not isinstance(sys.stderr, _QuietErr):
        sys.stderr = _QuietErr(sys.stderr)


def _before_command(argv: list[str] | None, cmd: str | None, extra: list[str]) -> bool:
    """True when the first unknown argument comes before the command (`sipar --foo check a.sipar`): that is a
    mistake in `sipar`'s own options, so `sipar`'s usage is shown, not the command's (round 10)."""
    args = sys.argv[1:] if argv is None else list(argv)
    if cmd not in args or extra[0] not in args:
        return cmd is None
    return args.index(extra[0]) < args.index(cmd)


def main(argv: list[str] | None = None, out=None, err=None) -> int:
    if out is None and err is None:     # the real `sipar` process, not a test calling main()
        _tolerant_streams()
        _closed_streams()
        from .runtime import children
        children.install_signal_handlers()      # R5 (round 6): SIGTERM / SIGHUP kill MCP servers too
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    p = build_parser()
    try:
        a, extra = p.parse_known_args(argv)
    except BrokenPipeError:             # `sipar --help >&-`, `sipar --version | true`
        return PIPE_EXIT
    if extra:                       # `sipar check a b`: show the usage of `check`, not of `sipar`
        (p if _before_command(argv, a.cmd, extra) else p.subs.get(a.cmd, p)).error(
            f"unrecognized arguments: {' '.join(extra)}")
    if not a.cmd:
        p.print_help(err)
        return USAGE_EXIT
    try:
        return COMMANDS[a.cmd](a, out, err)
    except UsageError as e:
        err.write(f"sipar: {escape_controls(str(e))}\n")
        return USAGE_EXIT
    except KeyboardInterrupt:
        err.write("\nsipar: interrupted\n")
        return 1
    except BrokenPipeError:             # the reader went away: stop quietly, like a tool killed by SIGPIPE
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return PIPE_EXIT
    except SiparRuntimeError as e:          # e.g. a journal that cannot be written
        err.write(_render_runtime_error(e, getattr(a, "file", "")) + "\n")
        return 1
    except Exception as e:  # noqa: BLE001 — never show a Python traceback unless asked
        if os.environ.get("SIPAR_DEBUG") == "1":
            traceback.print_exc(file=err)
        err.write(f"sipar: internal error ({type(e).__name__}); set SIPAR_DEBUG=1 for details\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
