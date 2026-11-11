"""End-to-end runs of the shipped examples through the CLI (mock model, no network)."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sipar(*args, env=None, cwd=ROOT):
    e = dict(os.environ, SIPAR_MODEL="mock")
    e.pop("SIPAR_MOCK_SCRIPT", None)
    e.update(env or {})
    return subprocess.run([sys.executable, "-m", "sipar", *args], cwd=cwd, env=e,
                          capture_output=True, text=True, timeout=60)


class Examples(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        shutil.copytree(os.path.join(ROOT, "examples"), os.path.join(self.tmp, "examples"),
                        ignore=shutil.ignore_patterns(".sipar", "out"))
        os.makedirs(os.path.join(self.tmp, "examples", "out"))
        self.ex = os.path.join(self.tmp, "examples")

    def run_ex(self, *args, env=None):
        p = sipar(*args, env=env)
        self.assertNotIn("Traceback", p.stderr)
        return p

    def test_all_examples_check(self):
        for path in ["tour.sipar", "triage.sipar", "injection/assistant.sipar"]:
            with self.subTest(path=path):
                p = self.run_ex("check", os.path.join(self.ex, path))
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_example_tests_pass(self):
        for path in ["tour.sipar", "triage.sipar"]:
            with self.subTest(path=path):
                p = self.run_ex("test", os.path.join(self.ex, path))
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertIn("0 failed", p.stdout)

    def test_hijacked_agent_is_blocked(self):
        prog = os.path.join(self.ex, "injection", "assistant.sipar")
        script = os.path.join(self.ex, "injection", "hijacked_model.json")
        p = self.run_ex("run", prog, env={"SIPAR_MOCK_SCRIPT": script})
        self.assertIn("BLOCKED (taint)", p.stdout)
        self.assertIn("shell.run(cmd)", p.stdout)
        self.assertEqual(os.listdir(os.path.join(self.ex, "out")), [])

    def test_triage_writes_only_choices_and_replays(self):
        prog = os.path.join(self.ex, "triage.sipar")
        p = self.run_ex("run", prog)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(Path(self.ex, "out", "billing.txt").read_text(), "normal")
        runs = os.path.join(self.ex, ".sipar", "runs")
        journal = os.path.join(runs, sorted(os.listdir(runs))[-1])
        r = self.run_ex("replay", prog, journal)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, p.stdout)

    def test_triage_blocks_model_text_in_file(self):
        prog = os.path.join(self.ex, "triage.sipar")
        src = Path(prog).read_text().replace('if v.urgent { "URGENT" } else { "normal" }', "v.summary")
        bad = os.path.join(self.ex, "bad.sipar")
        Path(bad).write_text(src)
        p = self.run_ex("run", bad)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("runtime error[taint]", p.stderr)
        self.assertIn("fs.write(text)", p.stderr)


if __name__ == "__main__":
    unittest.main()
