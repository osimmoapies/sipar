"""Playground harness: runs one Sipar program with the real interpreter and reports what left the sandbox.

The same file runs in the browser (Pyodide, see worker.js) and under CPython (tests/test_playground.py).
The interpreter is not changed. Two functions it calls at the very end of an effect are replaced for one run:

    subprocess.Popen             the command is recorded, nothing is started
    sipar.runtime.netio.fetch    the request is recorded, a canned page is returned

Everything before that point is the real code: labels, sinks, capabilities, secrets, the journal.
Files are real too: the program runs in a fresh folder, and what it wrote is read back from disk.

    python3 playground/glue.py < payload.json      # {"scenario": {...}, "edits": {"model.json": "..."}}
"""
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

MAX_TEXT = 60_000           # stdout / stderr / journal shown in the page
MAX_EDIT = 200_000          # one edited file
FAKE_PID = 2_000_000_000    # above any real pid: a kill aimed at it finds nobody
REPORT = "https://github.com/osimmoapies/sipar/security/advisories/new"


class _Recorder:
    def __init__(self, scenario: dict, files: dict):
        self.scenario = scenario
        self.files = files
        self.events: list[dict] = []
        self.pid = FAKE_PID

    # -- shell: sipar.runtime.effects.shell_run ends in subprocess.Popen(toks, shell=False, stdin=DEVNULL, ...)
    def popen(self, cmd, *args, **kw):
        if kw.get("stdin") != subprocess.DEVNULL:           # an MCP server talks over pipes: not simulated
            raise OSError("no processes in the playground")
        self.pid += 1
        self.events.append({"kind": "shell", "cmd": [str(t) for t in cmd]})
        return _Finished(self.pid, list(cmd))

    # -- http: sipar.runtime.effects.http_request ends in netio.fetch(req, seconds, limit, handlers)
    def fetch(self, req, seconds, limit, handlers=()):
        body = req.data.decode("utf-8", "replace") if req.data else ""
        ev = {"kind": "http", "method": req.get_method(), "url": req.full_url, "body": body,
              "headers": dict(req.header_items())}
        self.events.append(ev)
        return self._respond(ev).encode("utf-8")[:limit]

    def _respond(self, ev: dict) -> str:
        for rule in self.scenario.get("web") or []:
            if rule.get("method", "GET") != ev["method"]:
                continue
            url = rule["url"]
            if ev["url"] != url and not (rule.get("prefix") and ev["url"].startswith(url)):
                continue
            if rule.get("echo"):                            # a server that sends the request back
                return json.dumps({"url": ev["url"], "headers": ev["headers"]})
            if "file" in rule:
                return self.files.get(rule["file"], "")
            return rule.get("body", "")
        return "ok"


class _Finished:
    """What shell_run needs from a Popen object: a process that already ended well."""

    def __init__(self, pid: int, args: list):
        self.pid, self.args, self.returncode = pid, args, 0

    def communicate(self, input=None, timeout=None):
        return b"(playground: the command was recorded, not run)\n", b""

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass

    terminate = kill


def scenario_files(scenario: dict, edits: dict | None) -> dict:
    """name -> text for one run: the scenario's files, with the visitor's edits on the files that are not locked."""
    out = {}
    for f in scenario["files"]:
        text = f["text"]
        edit = (edits or {}).get(f["name"])
        if isinstance(edit, str) and not f.get("locked"):
            text = edit[:MAX_EDIT]
        out[f["name"]] = text
    return out


def _snapshot(root: str) -> dict:
    out = {}
    for d, _dirs, names in os.walk(root):
        for n in names:
            p = os.path.join(d, n)
            try:
                with open(p, "rb") as fh:
                    out[os.path.relpath(p, root).replace(os.sep, "/")] = fh.read()
            except OSError:
                pass
    return out


def _clip(s: str, n: int = MAX_TEXT) -> str:
    return s if len(s) <= n else s[:n] + f"\n… ({len(s) - n} more characters)"


def _hide(s: str, secrets: dict) -> str:
    for name, value in secrets.items():
        s = s.replace(value, f"‹{name}›")
    return s


def _public(ev: dict, secrets: dict) -> dict:
    """An event as the page shows it: secret values replaced by ‹NAME›."""
    if ev["kind"] == "shell":
        return {"kind": "shell", "cmd": [_hide(t, secrets) for t in ev["cmd"]]}
    if ev["kind"] == "http":
        return {"kind": "http", "method": ev["method"], "url": _hide(ev["url"], secrets),
                "body": _clip(_hide(ev["body"], secrets), 2000),
                "headers": {_hide(k, secrets): _hide(v, secrets) for k, v in ev["headers"].items()}}
    return {"kind": "file", "path": _hide(ev["path"], secrets), "bytes": ev["bytes"],
            "text": _clip(_hide(ev["text"], secrets), 2000)}


def _leaks(secrets: dict, stdout: str, stderr: str, events: list, written: dict) -> list[str]:
    """Every place a secret value shows up in full. An HTTP header value is the one place it may be.
    `written`: the files the run made or changed (the journal too), not the ones the visitor typed."""
    found = []
    for name, value in secrets.items():
        if value in stdout:
            found.append(f"{name} is in the output")
        if value in stderr:
            found.append(f"{name} is in the error output")
        raw = value.encode("utf-8")
        for path, data in sorted(written.items()):
            if raw in data:
                where = "the journal" if path.startswith(".sipar/") else f"the file {path}"
                found.append(f"{name} is in {where}")
        for ev in events:
            if ev["kind"] == "http":
                if value in ev["url"]:
                    found.append(f"{name} is in a request URL")
                if value in ev["body"]:
                    found.append(f"{name} is in a request body")
                if any(value in k for k in ev["headers"]):
                    found.append(f"{name} is in a header name")
            elif ev["kind"] == "shell" and any(value in t for t in ev["cmd"]):
                found.append(f"{name} is in a command")
    return found


def _count(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _declared_secret(program: str, name: str) -> bool:
    """Does the program still say `allow secret [... "NAME" ...]` (outside a // comment)?"""
    for line in program.split("\n"):
        m = re.match(r"\s*allow\s+secret\s*\[([^\]]*)\]", line)
        if m and f'"{name}"' in m.group(1):
            return True
    return False


LIMIT = "https://github.com/osimmoapies/sipar/blob/main/SECURITY.md"


def _model_silent(journal: str) -> bool:
    """True when the model was asked and never answered: its script did not load, or had no reply to give.
    Then nothing was attempted, and "held" would claim a defence that was never tested."""
    asked = False
    for line in journal.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict) and e.get("kind") in ("agent", "ai"):
            if e.get("response") is not None:
                return False
            asked = True
    return asked


def verdict(scenario: dict, run1: dict, secrets: dict, program: str = "", canary=None) -> dict:
    """What the run means for the scenario's goal: held, broken, limit (a secret got out: the documented
    limit or a real hole, the harness cannot tell which), off (the visitor changed the game) or none.

    `run1` is the result of _execute. `canary` is called only when a secret seems to have leaked: it runs the
    same program with another key and says where THAT key showed up. A key the visitor typed into the program
    (in one piece or in parts) shows up in the first run and not in the second, so it is not called a leak.
    """
    rule = scenario.get("rule") or {"type": "none"}
    events = run1["events"]
    if rule["type"] != "none" and not run1["ran"]:
        return {"state": "none", "title": "Did not run", "text": "Nothing ran: see the error in the output."}
    shell = [e for e in events if e["kind"] == "shell"]
    http = [e for e in events if e["kind"] == "http"]
    files = [e for e in events if e["kind"] == "file"]
    bug = f"The program was not changed, so this is a real hole in Sipar. Please report it: {REPORT}"
    silent = {"state": "none", "title": "The model said nothing",
              "text": f"{scenario.get('model') or 'The model script'} could not be used, so the model asked for "
                      "nothing and there was nothing to stop. The reason is in the output."}
    if rule["type"] == "no_actions":
        if shell or files:
            what = [_count(len(shell), "command ran", "commands ran")] if shell else []
            what += [_count(len(files), "file was written", "files were written")] if files else []
            return {"state": "broken", "title": "You got through", "text": f"{' and '.join(what)}. {bug}"}
        if _model_silent(run1.get("journal", "")):
            return silent
        return {"state": "held", "title": "Held",
                "text": "No command ran and no file was written. "
                        "Whatever the model asked for, it did not reach the shell or the disk."}
    if rule["type"] == "only_requests":
        allowed = set(rule.get("allowed") or [])
        extra = [e for e in http if f"{e['method']} {e['url']}" not in allowed or e["body"]]
        if extra or shell or files:
            what = [_count(len(extra), "request left that should not have", "requests left that should not have")
                    ] if extra else []
            what += [_count(len(shell), "command ran", "commands ran")] if shell else []
            what += [_count(len(files), "file was written", "files were written")] if files else []
            return {"state": "broken", "title": "You got through", "text": f"{'; '.join(what)}. {bug}"}
        if _model_silent(run1.get("journal", "")):
            return silent
        left = ("No request left at all." if not http else
                "One request left: the fixed one." if len(http) == 1 else
                f"{len(http)} requests left, all of them the fixed one.")
        return {"state": "held", "title": "Held",
                "text": f"{left} Nothing the model wrote became part of a URL or a body."}
    if rule["type"] == "secret_stays":
        found = _leaks(secrets, run1["stdout"], run1["stderr"], events, run1["written"])
        gone = [n for n in secrets if not _declared_secret(program, n)]
        if found and gone:
            return {"state": "off", "title": "Not a secret any more",
                    "text": f'The program no longer says allow secret ["{gone[0]}"], so the key is ordinary data. '
                            "Put the line back: the game is to leak a value that was declared secret."}
        if found and canary is not None:
            again = canary()
            if not again:
                return {"state": "off", "title": "That is your own copy",
                        "text": "The key in the result was typed into the program, it did not come from "
                                "env.secret(): the same program run with a different key does not show that key. "
                                "The game is to get the value out of the variable."}
            found = again
        if found:
            return {"state": "limit", "title": "The key got out",
                    "text": f"{'; '.join(dict.fromkeys(found))} (checked again with a second, random key). "
                            "If you rebuilt it piece by piece with `if` on the key, that is the documented limit: "
                            f"choices made from a secret are not tracked ({LIMIT}). "
                            f"Any other way is a real hole in Sipar. Please report it: {REPORT}"}
        sent = sum(1 for e in http for v in e["headers"].values() if any(s in v for s in secrets.values()))
        text = "The key's value is not in the output, in a file, in the journal or in a URL."
        if sent:
            text += f" It was sent as a header value {_count(sent, 'time', 'times')}: the one place it may go."
        return {"state": "held", "title": "Held", "text": text}
    return {"state": "none", "title": "", "text": ""}


def _execute(scenario: dict, files: dict, env: dict) -> dict:
    """One real run in a fresh folder. Returns rc, ms, stdout, stderr, events, written, journal, ran."""
    rec = _Recorder(scenario, files)

    import sipar.cli as cli
    from sipar.runtime import netio

    work = os.path.realpath(tempfile.mkdtemp(prefix="sipar-play-"))
    saved = (os.getcwd(), dict(os.environ), sys.stdin, subprocess.Popen, netio.fetch)
    out, err = io.StringIO(), io.StringIO()
    t0 = time.monotonic()
    try:
        for name, text in files.items():
            with open(os.path.join(work, name), "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
        for d in scenario.get("dirs") or []:
            os.makedirs(os.path.join(work, d), exist_ok=True)
        before = _snapshot(work)
        os.chdir(work)
        for k in [k for k in os.environ if k.startswith("SIPAR_")]:
            del os.environ[k]
        os.environ.update(env)
        os.environ["SIPAR_MODEL"] = "mock"
        if scenario.get("model"):
            os.environ["SIPAR_MOCK_SCRIPT"] = scenario["model"]
        sys.stdin = io.StringIO("")
        subprocess.Popen = rec.popen
        netio.fetch = rec.fetch
        try:
            rc = cli.main(["run", scenario["main"]], out, err)
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 0 if e.code is None else 1
        except BaseException as e:      # noqa: BLE001 - the page must get an answer, whatever the program did
            rc = 70
            err.write(f"playground: {type(e).__name__}: {e}\n")
        after = _snapshot(work)
    finally:
        os.chdir(saved[0])
        os.environ.clear()
        os.environ.update(saved[1])
        sys.stdin, subprocess.Popen, netio.fetch = saved[2:]
        shutil.rmtree(work, ignore_errors=True)
    ms = round((time.monotonic() - t0) * 1000)

    written = {p: d for p, d in after.items() if before.get(p) != d}       # made or changed by the run
    for path in sorted(written):
        if not path.startswith(".sipar/"):
            rec.events.append({"kind": "file", "path": path, "bytes": len(written[path]),
                               "text": written[path].decode("utf-8", "replace")})
    journal = "".join(after[p].decode("utf-8", "replace") for p in sorted(after)
                      if p.startswith(".sipar/runs/") and p.endswith(".jsonl"))
    return {"rc": rc, "ms": ms, "stdout": out.getvalue(),
            "stderr": err.getvalue().replace(work + os.sep, "").replace(work, "."),
            "events": rec.events, "written": written, "journal": journal, "ran": bool(journal) or rc == 0}


def other_key(value: str) -> str:
    """A different key of the same shape: the same length, the same start up to the last separator, the rest
    drawn from the characters the real key has there. A program that gets the real key out of the variable
    (also one that knows its prefix or its alphabet) gets this one out too; a key typed into the program stays
    the typed one."""
    cut = max((i for i, c in enumerate(value) if not c.isalnum()), default=-1) + 1
    for head, tail in ((value[:cut], value[cut:]), ("", value)):
        chars = sorted(set(tail))
        if len(tail) >= 8 and len(chars) >= 4:
            while True:
                other = head + "".join(chars[b % len(chars)] for b in os.urandom(len(tail)))
                if other != value:
                    return other
    return "canary-" + os.urandom(8).hex()


def run(payload: dict) -> dict:
    scenario = payload["scenario"]
    files = scenario_files(scenario, payload.get("edits"))
    env = {str(k): str(v) for k, v in (scenario.get("env") or {}).items()}
    secrets = {n: env[n] for n in scenario.get("secrets") or [] if n in env}
    r = _execute(scenario, files, env)

    def canary() -> list[str]:
        other = {n: other_key(v) for n, v in secrets.items()}
        r2 = _execute(scenario, files, {**env, **other})
        return _leaks(other, r2["stdout"], r2["stderr"], r2["events"], r2["written"])

    v = verdict(scenario, r, secrets, program=files.get(scenario["main"], ""), canary=canary)
    return {"rc": r["rc"], "ms": r["ms"], "stdout": _clip(r["stdout"]), "stderr": _clip(r["stderr"]),
            "events": [_public(e, secrets) for e in r["events"]], "verdict": v,
            "journal": _clip(_hide(r["journal"], secrets))}


def run_json(payload: str) -> str:
    return json.dumps(run(json.loads(payload)), ensure_ascii=False)


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.stdout.write(run_json(sys.stdin.read()) + "\n")
