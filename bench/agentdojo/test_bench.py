"""Tests for the benchmark scripts: a provider failure (quota, 5xx, no network) must never become a result.

Run: /path/to/agentdojo-venv/bin/python -m unittest test_bench   (from bench/agentdojo)"""
import io
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import httpx
import openai

import baseline
import llm
import planner
import run


def dir_with_journal(text=""):
    d = Path(tempfile.mkdtemp())
    (d / ".sipar" / "runs").mkdir(parents=True)
    (d / ".sipar" / "runs" / "r.jsonl").write_text(text)
    return d


class RunUnavailable(unittest.TestCase):
    def test_not_a_result(self):
        for err in [
            "prog.sipar:22:36: runtime error[ai]: local: cannot reach https://api.groq.com/openai/v1: "
            "[Errno 8] nodename nor servname provided, or not known",
            "runtime error[ai]: local: connection error: [Errno 54] Connection reset by peer",
            "runtime error[ai]: local: HTTP 503 Service Unavailable: busy",
            "runtime error[ai]: local: HTTP 429 Too Many Requests: Rate limit reached",
        ]:
            with self.subTest(err=err[:40]):
                self.assertTrue(run.rate_limited(dir_with_journal(), err))

    def test_found_in_journal_when_the_program_caught_it(self):
        d = dir_with_journal('{"error": "local: cannot reach https://api.groq.com/openai/v1: timed out"}\n')
        self.assertTrue(run.rate_limited(d, "exit 0"))

    def test_real_results_stay(self):
        for err in [
            "runtime error[denied]: not approved: Pay? (stdin is not a terminal)",
            "user_task_3 None utility=False 1429 tok",
            "runtime error[ai]: local: HTTP 400 Bad Request: bad tool schema",
            "runtime error[ai]: local: HTTP 501 Not Implemented: no such endpoint",
            "runtime error[ai]: local: request timed out after 30s",
            "",
        ]:
            with self.subTest(err=err[:40]):
                self.assertFalse(run.rate_limited(dir_with_journal(), err))


class BaselineUnavailable(unittest.TestCase):
    req = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")

    def resp(self, code):
        return httpx.Response(code, request=self.req)

    def test_provider_failures(self):
        for e in [openai.APIConnectionError(request=self.req), openai.APITimeoutError(request=self.req),
                  openai.RateLimitError("Error code: 429", response=self.resp(429), body=None),
                  openai.InternalServerError("Error code: 503", response=self.resp(503), body=None),
                  RuntimeError("Error code: 429 - Rate limit reached")]:
            with self.subTest(e=type(e).__name__):
                self.assertTrue(baseline.unavailable(e))

    def test_agent_failures_are_not(self):
        for e in [openai.BadRequestError("Error code: 400", response=self.resp(400), body=None),
                  ValueError("bad tool args"), KeyError("x")]:
            with self.subTest(e=type(e).__name__):
                self.assertFalse(baseline.unavailable(e))


class LlmAndPlanner(unittest.TestCase):
    def test_network_down_is_unavailable(self):
        with mock.patch("llm.urllib.request.urlopen", side_effect=urllib.error.URLError("nodename")), \
             mock.patch("llm.time.sleep"), mock.patch("llm.key_of", return_value="k"):
            with self.assertRaises(llm.Unavailable):
                llm.chat("groq/m", [], tries=2)

    def test_http_errors(self):
        def http(code):
            return urllib.error.HTTPError("u", code, "x", {}, io.BytesIO(b"{}"))
        for code, unavailable in [(429, True), (503, True), (400, False), (401, False), (413, False)]:
            with self.subTest(code=code), mock.patch("llm.urllib.request.urlopen", side_effect=http(code)), \
                 mock.patch("llm.time.sleep"), mock.patch("llm.key_of", return_value="k"):
                with self.assertRaises(RuntimeError) as cm:
                    llm.chat("groq/m", [], tries=2)
                self.assertEqual(isinstance(cm.exception, llm.Unavailable), unavailable)

    def test_planner_stops_with_75_and_writes_nothing(self):
        out = Path(tempfile.mkdtemp())
        task = mock.Mock(PROMPT="p")
        info = {"suite": mock.Mock(user_tasks={"user_task_1": task})}
        with mock.patch.object(planner, "suite_info", return_value=info), \
             mock.patch.object(planner, "HERE", out), \
             mock.patch.object(planner, "plan", side_effect=llm.Unavailable("groq/m: HTTP 429: x")), \
             mock.patch.object(sys, "argv", ["planner.py", "banking", "groq/m"]):
            with self.assertRaises(SystemExit) as cm:
                planner.main()
        self.assertEqual(cm.exception.code, 75)
        self.assertEqual(list((out / "programs" / "banking").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
