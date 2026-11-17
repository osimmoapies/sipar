"""Baseline: AgentDojo's plain tool-calling agent on the same model and the same attack as run.py.

Usage: python baseline.py <suite> <provider/model> [user_task_id ...]
Writes results/<suite>-baseline.jsonl (same keys as run.py)."""
import json
import sys
import time

import openai
from agentdojo.agent_pipeline import (AgentPipeline, InitQuery, OpenAILLM, SystemMessage, ToolsExecutionLoop,
                                      ToolsExecutor)
from agentdojo.agent_pipeline.agent_pipeline import load_system_message

from llm import PROVIDERS, key_of
from run import Attack, injections
from suites import HERE, suite_info


USED = [0]


def unavailable(e):
    """The provider, not the agent, failed: quota (429), 5xx, no network or timeout. Not a result."""
    return isinstance(e, (openai.RateLimitError, openai.APIConnectionError, openai.InternalServerError)) \
        or "Error code: 429" in str(e)


def make_pipeline(model):
    provider, name = model.split("/", 1)
    client = openai.OpenAI(base_url=PROVIDERS[provider][0], api_key=key_of(provider), max_retries=8)
    create = client.chat.completions.create

    def counted(*args, **kw):          # count tokens the agent spends, like run.py does from the journal
        r = create(*args, **kw)
        if r.usage:
            USED[0] += (r.usage.prompt_tokens or 0) + (r.usage.completion_tokens or 0)
        return r
    client.chat.completions.create = counted
    llm = OpenAILLM(client, name, temperature=0.0)
    pipe = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), llm,
                          ToolsExecutionLoop([ToolsExecutor(), llm])])
    pipe.name = "baseline"
    return pipe


def main():
    suite_name, model = sys.argv[1], sys.argv[2]
    only = sys.argv[3:] or None
    suite = suite_info(suite_name)["suite"]
    pipe = make_pipeline(model)
    attack = Attack(suite, pipe)
    outp = HERE / "results" / f"{suite_name}-baseline.jsonl"
    outp.parent.mkdir(exist_ok=True)
    done = set()
    if outp.exists():
        for l in outp.read_text().splitlines():
            r = json.loads(l)
            done.add((r["user_task"], r["injection_task"]))
    for tid, ut in suite.user_tasks.items():
        if only and tid not in only:
            continue
        for iid in [None] + injections(suite):
            if (tid, iid) in done:
                continue
            it = None if iid is None else suite.get_injection_task_by_id(iid)
            inj = {} if it is None else attack.attack(ut, it)
            t0 = time.time()
            USED[0] = 0
            try:
                utility, security = suite.run_task_with_pipeline(pipe, ut, it, inj)
                errtxt = ""
            except Exception as e:          # provider failure: recorded, not counted as a result
                print(f"{tid} {iid} ERROR {str(e)[:200]}", flush=True)
                if unavailable(e):
                    sys.exit(75)            # quota used up or no network: drive.py waits and runs again
                continue
            rec = {"user_task": tid, "injection_task": iid, "mode": "baseline", "model": model,
                   "utility": utility, "attack_success": (security if iid is not None else None),
                   "secs": round(time.time() - t0, 1), "tokens": USED[0], "error": errtxt}
            with open(outp, "a") as fh:
                fh.write(json.dumps(rec) + "\n")
            tag = "-" if iid is None else ("ATTACK OK" if security else "blocked")
            print(f"{tid} {iid} utility={utility} {tag} {rec['secs']}s {rec['tokens']} tok", flush=True)


if __name__ == "__main__":
    main()
