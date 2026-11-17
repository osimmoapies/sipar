"""Run the whole AgentDojo comparison unattended on a free model with a daily token quota.

Usage: python drive.py <suite> <provider/model>
Order: planner for tasks without a program, then Sipar default/strict with the approver denying and saying yes,
then the plain tool-calling baseline. Every step is resumable (each script skips finished runs); when the provider
answers 429 (quota), a 5xx, or the network is down, the step stops without recording that run and is started again after a wait. Uses the fixed
injection subset in INJECTIONS (one per attack kind) unless BENCH_INJECTIONS is set."""
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = sys.executable
INJECTIONS = "injection_task_0,injection_task_4,injection_task_5,injection_task_7"
WAIT = 900          # seconds between tries while the daily quota refills


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def step(name, argv, env_extra):
    env = dict(os.environ, BENCH_INJECTIONS=os.environ.get("BENCH_INJECTIONS", INJECTIONS), **env_extra)
    while True:
        log(f"start {name}")
        r = subprocess.run([PY, *argv], cwd=HERE, env=env, capture_output=True, text=True)
        lines = [l for l in (r.stdout + r.stderr).splitlines() if "Warning" not in l]
        for l in lines[-40:]:
            print("   ", l, flush=True)
        # exit 75: planner / run.py / baseline.py saw the provider fail (429 quota, 5xx, no network).
        # The text forms are a second net; token counts like "1429 tok" in run lines must not match.
        quota = r.returncode == 75 or any("HTTP 429" in l or "Error code: 429" in l for l in lines)
        if r.returncode == 0 and not quota:
            log(f"done {name}")
            return
        if not quota:
            log(f"FAILED {name} (exit {r.returncode}), moving on")
            return
        log(f"quota: waiting {WAIT}s")
        time.sleep(WAIT)


def main():
    suite, model = sys.argv[1], sys.argv[2]
    progs = HERE / "programs" / suite
    from suites import suite_info
    missing = [t for t in suite_info(suite)["suite"].user_tasks if not (progs / f"{t}.sipar").exists()]
    if missing:
        step("planner", ["planner.py", suite, model, *missing], {})
    for mode in ("default", "strict"):
        for approver in ("deny", "yes"):
            step(f"sipar {mode} approver={approver}", ["run.py", suite, mode, model], {"BENCH_APPROVER": approver})
    step("baseline", ["baseline.py", suite, model], {})
    # the baseline skips a run whose provider call failed for another reason; one more pass fills those
    step("baseline (second pass)", ["baseline.py", suite, model], {})
    log("ALL DONE")


if __name__ == "__main__":
    main()
