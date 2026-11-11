"""Run every tests/test_*.py file in its own process, in parallel.

    python3 tools/ptest.py [-j N] [pattern ...]

Same result as `python3 -m unittest discover -s tests`, several times faster.
Exit code 1 if any file fails; the failing file's full output is printed.
"""
import argparse, os, re, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.join(ROOT, "tests")


def jobs(files):
    """One job per TestCase class, so one slow file does not set the wall time."""
    out = []
    for f in files:
        classes = re.findall(r"^class (\w+)\(", open(os.path.join(TESTS, f), encoding="utf-8").read(), re.M)
        out += [(f, c) for c in classes] or [(f, None)]
    return out


def run(job):
    f, cls = job
    name = f if cls is None else f"{f}:{cls}"
    cmd = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", f]
    if cls:
        cmd += ["-k", f"*.{cls}.*"]
    t = time.monotonic()
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, errors="replace")
    out = p.stdout + p.stderr
    m = re.search(r"Ran (\d+) test", out)
    return name, p.returncode, int(m.group(1)) if m else 0, time.monotonic() - t, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-j", type=int, default=max(2, (os.cpu_count() or 4) - 1))
    ap.add_argument("-v", "--verbose", action="store_true", help="list every job with its time")
    ap.add_argument("patterns", nargs="*")
    a = ap.parse_args()
    files = sorted(f for f in os.listdir(TESTS) if f.startswith("test_") and f.endswith(".py"))
    if a.patterns:
        files = [f for f in files if any(p in f for p in a.patterns)]
    t0 = time.monotonic()
    with ThreadPoolExecutor(a.j) as ex:
        results = list(ex.map(run, jobs(files)))
    total, bad = 0, []
    for name, rc, n, dt, out in sorted(results, key=lambda r: -r[3]):
        total += n
        if rc == 5 and n == 0:      # a helper class with no tests ("NO TESTS RAN")
            continue
        if not a.verbose and rc == 0:
            continue
        print(f"{'ok ' if rc == 0 else 'FAIL'} {n:5d} {dt:6.1f}s  {name}")
        if rc != 0 and not (rc == 5 and n == 0):
            bad.append((name, out))
    for name, out in bad:
        print(f"\n===== {name} =====\n{out}")
    print(f"\n{'FAILED' if bad else 'OK'}: {total} tests in {len(files)} files ({len(results)} jobs), "
          f"{time.monotonic() - t0:.1f}s wall (python {sys.version.split()[0]})")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
