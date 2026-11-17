"""Summarise results/*.jsonl: utility without attack, utility under attack, attack success rate.

Usage: python aggregate.py [results/banking-*.jsonl ...]   (default: every file in results/)"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def pct(a, b):
    return f"{a}/{b} = {100 * a / b:.1f}%" if b else "—"


def summary(path):
    rows = [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]
    clean = [r for r in rows if r["injection_task"] is None]
    attacked = [r for r in rows if r["injection_task"] is not None]
    denied = sum(1 for r in rows if "runtime error[denied]" in (r.get("stderr") or ""))
    asked = sum(1 for r in rows if r.get("approvals"))
    crashed = sum(1 for r in rows if r.get("exit") not in (None, 0))
    noprog = sorted({r["user_task"] for r in rows if "no program" in (r.get("stderr") or "")})
    tokens = sum(int(r.get("tokens") or 0) for r in rows)
    return {
        "file": Path(path).name,
        "model": rows[0]["model"] if rows else "",
        "utility (no attack)": pct(sum(bool(r["utility"]) for r in clean), len(clean)),
        "utility (under attack)": pct(sum(bool(r["utility"]) for r in attacked), len(attacked)),
        "attack success": pct(sum(bool(r["attack_success"]) for r in attacked), len(attacked)),
        "runs stopped by approve (no human)": denied,
        "runs that asked the human (approve=yes)": asked,
        "runs with nonzero exit": crashed,
        "user tasks with no program (planner failed)": f"{len(noprog)} {' '.join(noprog)}".strip(),
        "model tokens, all runs": tokens,
    }


def main():
    from suites import results_dir      # BENCH_TAG picks another model's results
    files = sys.argv[1:] or sorted(str(p) for p in results_dir().glob("*.jsonl"))
    for f in files:
        s = summary(f)
        print(f"== {s.pop('file')}  ({s.pop('model')})")
        for k, v in s.items():
            print(f"   {k:44} {v}")


if __name__ == "__main__":
    main()
