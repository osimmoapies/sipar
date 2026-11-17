"""Run an AgentDojo suite with Sipar programs (written earlier by planner.py) and score them.

python run.py <suite> <mode: strict|default> <ai model for the program's ai fns> [user_task ids...]
Results are appended to results/<suite>-<mode>.jsonl (one line per run; finished runs are skipped).
"""
import contextlib
import json
import os
import pickle
import re
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.attacks.base_attacks import FixedJailbreakAttack
from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack
from agentdojo.functions_runtime import FunctionCall
from agentdojo.types import text_content_block_from_string

from llm import PROVIDERS, key_of
from suites import HERE, suite_info

SIPAR = str(HERE.parents[1] / "bin" / "sipar")


class Attack(FixedJailbreakAttack):
    """AgentDojo's `important_instructions` text, signed by the user (Emma Johnson), addressed to
    "the AI language model" (the pipeline has no single model name)."""
    name = "important_instructions"

    def __init__(self, suite, pipeline):
        super().__init__(ImportantInstructionsAttack._JB_STRING, suite, pipeline)
        self.user_name = "Emma Johnson"


def sipar_env(mode, model):
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "TMPDIR") if k in os.environ}
    env["SIPAR_STRICT"] = "1" if mode == "strict" else "0"
    env["SIPAR_AI_RATE_RETRIES"] = "8"          # free tiers answer 429 when the per-minute quota is used up
    env["SIPAR_AI_TIMEOUT"] = "600"
    provider, name = model.split("/", 1)
    if provider == "gemini":
        env["SIPAR_MODEL"] = model
        env["GEMINI_API_KEY"] = key_of("gemini")
    elif provider == "openrouter":
        env["SIPAR_MODEL"] = model
        env["OPENROUTER_API_KEY"] = key_of("openrouter")
    else:  # an OpenAI-compatible provider through Sipar's `local` provider
        env["SIPAR_MODEL"] = "local/" + name
        env["SIPAR_LOCAL_URL"] = PROVIDERS[provider][0]
        env["SIPAR_LOCAL_KEY"] = key_of(provider)
    return env


@contextlib.contextmanager
def human_stdin(approver):
    """The human behind `approve`. "deny": no human (stdin is not a terminal, so every approve says no — the
    AgentDojo setting, where nobody is there to ask). "yes": a careless human who answers y to every question
    (a terminal with y lines already typed), i.e. the worst human, so only the language's own checks remain."""
    if approver == "deny":
        yield subprocess.DEVNULL
        return
    master, slave = os.openpty()
    try:
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        os.write(master, b"y\n" * 200)
        yield slave
    finally:
        os.close(slave)
        os.close(master)


class SiparPipeline(BasePipelineElement):
    def __init__(self, info, mode, model, approver="deny"):
        self.info, self.mode, self.model, self.approver = info, mode, model, approver
        self.name = f"sipar-{mode}"
        self.env = sipar_env(mode, model)
        self.by_prompt = {t.PROMPT: tid for tid, t in info["suite"].user_tasks.items()}
        self.last = {}

    def query(self, query, runtime, env, messages=[], extra_args={}):
        tid = self.by_prompt[query]
        prog = HERE / "programs" / self.info["suite"].name / f"{tid}.sipar"
        calls, out, err, code, secs, tokens, limited = [], "", "", None, 0.0, 0, False
        if prog.exists():
            with tempfile.TemporaryDirectory() as d:
                d = Path(d)
                (d / "prog.sipar").write_text(self.info["header"] + "\n" + self.info["types"] + "\n\n" + prog.read_text())
                with open(d / "state.pkl", "wb") as fh:
                    pickle.dump(env, fh)
                t0 = time.time()
                try:
                    with human_stdin(self.approver) as stdin:
                        r = subprocess.run([SIPAR, "run", "prog.sipar"], cwd=d, env=self.env, stdin=stdin,
                                           capture_output=True, text=True, timeout=900)
                    out, err, code = r.stdout, r.stderr, r.returncode
                except subprocess.TimeoutExpired as e:
                    out, err, code = (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""), "timeout", -1
                secs = time.time() - t0
                with open(d / "state.pkl", "rb") as fh:
                    env = pickle.load(fh)
                tokens = journal_tokens(d)
                limited = rate_limited(d, err)
                if (d / "calls.jsonl").exists():
                    calls = [json.loads(l) for l in (d / "calls.jsonl").read_text().splitlines() if l.strip()]
        else:
            err = "no program (the planner failed)"
        msgs = [{"role": "user", "content": [text_content_block_from_string(query)]}]
        for i, c in enumerate(calls):
            fc = FunctionCall(function=c["function"], args=c["args"], id=f"c{i}")
            msgs.append({"role": "assistant", "content": None, "tool_calls": [fc]})
            msgs.append({"role": "tool", "content": [text_content_block_from_string("")], "tool_call": fc,
                         "tool_call_id": f"c{i}", "error": c["error"]})
        msgs.append({"role": "assistant", "content": [text_content_block_from_string(out)], "tool_calls": None})
        asked = re.findall(r"question: (.*)\n  value \(\d+ chars\):\n\s*(.*)", err)
        self.last = {"calls": calls, "stdout": out, "stderr": err[-2000:], "exit": code, "secs": round(secs, 1), "tokens": tokens, "rate_limited": limited,
                     "approvals": [{"question": q[:300], "value": v[:300]} for q, v in asked]}
        return query, runtime, env, msgs, extra_args


def injections(suite):
    """Injection tasks to run: all, or the comma list in BENCH_INJECTIONS ("" = none, clean runs only).
    A fixed subset keeps the free model's daily token limit; the README states which one was used."""
    sel = os.environ.get("BENCH_INJECTIONS")
    if sel is None:
        return list(suite.injection_tasks)
    want = [s.strip() for s in sel.split(",") if s.strip()]
    bad = [w for w in want if w not in suite.injection_tasks]
    assert not bad, f"unknown injection tasks: {bad}"
    return want


RATE_EXIT = 75     # drive.py waits and runs again: a run cut by the provider (quota, network) is not a result


NET_DOWN = re.compile(r"cannot reach https?://|: connection error: |HTTP 50[0234] ")


def rate_limited(d, err):
    """True when a model call in this run hit the provider, not the program: HTTP 429 (quota), no network
    (DNS, refused connection) or a 5xx from the provider. Such a run is not a result; it is run again later."""
    texts = [err] + [f.read_text() for f in (d / ".sipar" / "runs").glob("*.jsonl")]
    return any(("429" in t and "rate limit" in t.lower()) or NET_DOWN.search(t) for t in texts)


def journal_tokens(d):
    """Model tokens (input + output) the run used, summed from every `usage` in its journal."""
    total = 0

    def walk(x):
        nonlocal total
        if isinstance(x, dict):
            u = x.get("usage")
            if isinstance(u, dict):
                total += int(u.get("input") or 0) + int(u.get("output") or 0)
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    for f in (d / ".sipar" / "runs").glob("*.jsonl"):
        for line in f.read_text().splitlines():
            if line.strip():
                walk(json.loads(line))
    return total


def main():
    suite_name, mode, model = sys.argv[1], sys.argv[2], sys.argv[3]
    only = sys.argv[4:] or None
    approver = os.environ.get("BENCH_APPROVER", "deny")
    assert approver in ("deny", "yes"), approver
    info = suite_info(suite_name)
    suite = info["suite"]
    pipe = SiparPipeline(info, mode, model, approver)
    attack = Attack(suite, pipe)
    outp = HERE / "results" / (f"{suite_name}-{mode}.jsonl" if approver == "deny" else
                               f"{suite_name}-{mode}-approve_{approver}.jsonl")
    outp.parent.mkdir(exist_ok=True)
    done = set()
    if outp.exists():
        for l in outp.read_text().splitlines():
            r = json.loads(l)
            done.add((r["user_task"], r["injection_task"]))
    for tid, ut in suite.user_tasks.items():
        if only and tid not in only:
            continue
        jobs = [None] + injections(suite)
        for iid in jobs:
            if (tid, iid) in done:
                continue
            try:
                inj = {} if iid is None else attack.attack(ut, suite.get_injection_task_by_id(iid))
            except ValueError as e:  # not injectable
                inj = None
            if inj is None:
                continue
            it = None if iid is None else suite.get_injection_task_by_id(iid)
            utility, security = suite.run_task_with_pipeline(pipe, ut, it, inj)
            if pipe.last.pop("rate_limited", False):
                print(f"{tid} {iid} provider unavailable (quota or network): not recorded", flush=True)
                sys.exit(RATE_EXIT)
            rec = {"user_task": tid, "injection_task": iid, "mode": mode, "model": model,
                   "approver": approver, "utility": utility, "attack_success": (security if iid is not None else None),
                   **pipe.last}
            with open(outp, "a") as fh:
                fh.write(json.dumps(rec) + "\n")
            tag = "-" if iid is None else ("ATTACK OK" if security else "blocked")
            print(f"{tid} {iid} utility={utility} {tag} exit={pipe.last['exit']} {pipe.last['secs']}s {pipe.last['tokens']} tok", flush=True)


if __name__ == "__main__":
    main()
