"""Tests for the benchmark scripts: a provider failure (quota, 5xx, no network) must never become a result.

Run: /path/to/agentdojo-venv/bin/python -m unittest test_bench   (from bench/agentdojo)"""
import io
import json
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
import suites


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
            "runtime error[ai]: openrouter: HTTP 429 Too Many Requests: x:free is temporarily rate-limited upstream",
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
             mock.patch.object(planner, "programs_dir", return_value=out / "programs" / "banking"), \
             mock.patch.object(planner, "plan", side_effect=llm.Unavailable("groq/m: HTTP 429: x")), \
             mock.patch.object(sys, "argv", ["planner.py", "banking", "groq/m"]):
            with self.assertRaises(SystemExit) as cm:
                planner.main()
        self.assertEqual(cm.exception.code, 75)
        self.assertEqual(list((out / "programs" / "banking").iterdir()), [])


class OwnersReserve(unittest.TestCase):
    """The benchmark shares the owner's 1000 free OpenRouter requests a day and must leave him BENCH_OR_RESERVE."""

    def answer(self, remaining):
        body = json.dumps({"data": {"free_model_daily_requests": {"used": 1, "limit": 1000, "remaining": remaining}}})
        return mock.patch("llm.urllib.request.urlopen", return_value=io.BytesIO(body.encode()))

    def test_stops_at_the_reserve(self):
        with mock.patch("llm.key_of", return_value="k"):
            for left, ok in [(250, False), (300, False), (301, True), (1000, True)]:
                with self.subTest(left=left), self.answer(left):
                    self.assertEqual(llm.quota_left("openrouter/m:free", reserve=300), ok)

    def test_no_check_when_not_needed(self):
        with mock.patch("llm.urllib.request.urlopen") as net, mock.patch("llm.key_of", return_value="k"):
            self.assertTrue(llm.quota_left("groq/openai/gpt-oss-120b", reserve=300))
            self.assertTrue(llm.quota_left("openrouter/m:free", reserve=0))
        net.assert_not_called()

    def test_reserve_from_env(self):
        with mock.patch.dict("os.environ", {"BENCH_OR_RESERVE": "300"}), mock.patch("llm.key_of", return_value="k"), \
             self.answer(10):
            self.assertFalse(llm.quota_left("openrouter/m:free"))

    def test_unknown_counts_as_left(self):
        with mock.patch("llm.urllib.request.urlopen", side_effect=urllib.error.URLError("down")), \
             mock.patch("llm.key_of", return_value="k"):
            self.assertTrue(llm.quota_left("openrouter/m:free", reserve=300))

    def test_planner_stops_before_asking(self):
        out = Path(tempfile.mkdtemp())
        info = {"suite": mock.Mock(user_tasks={"user_task_1": mock.Mock(PROMPT="p")})}
        with mock.patch.object(planner, "suite_info", return_value=info), \
             mock.patch.object(planner, "programs_dir", return_value=out), \
             mock.patch.object(planner, "quota_left", return_value=False), \
             mock.patch.object(planner, "plan", side_effect=AssertionError("asked the model")), \
             mock.patch.object(sys, "argv", ["planner.py", "banking", "openrouter/m:free"]):
            with self.assertRaises(SystemExit) as cm:
                planner.main()
        self.assertEqual(cm.exception.code, 75)


class TagDirs(unittest.TestCase):
    def test_tag_keeps_models_apart(self):
        with mock.patch.object(suites, "TAG", ""):
            self.assertEqual(suites.programs_dir("banking"), suites.HERE / "programs" / "banking")
            self.assertEqual(suites.results_dir(), suites.HERE / "results")
        with mock.patch.object(suites, "TAG", "nemo"):
            self.assertEqual(suites.programs_dir("banking"), suites.HERE / "programs-nemo" / "banking")
            self.assertEqual(suites.results_dir(), suites.HERE / "results-nemo")


if __name__ == "__main__":
    unittest.main()
