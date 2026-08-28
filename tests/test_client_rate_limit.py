#!/usr/bin/env python3
"""
tests/test_client_rate_limit.py

Offline tests for the NSX client's rate limiting and 429/503 retry. No
network: instances are built via __new__ with only the pacing attributes.

    python -m unittest tests/test_client_rate_limit.py -v
"""

from __future__ import annotations

import logging
import sys
import threading
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "app") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "app"))

logging.disable(logging.CRITICAL)

from nsx.nsx_policy_client import NsxApiError, NsxPolicyClient  # noqa: E402


class FakeResp:
    def __init__(self, status_code, retry_after=None):
        self.status_code = status_code
        self.ok = status_code < 400
        self.headers = {"Retry-After": str(retry_after)} if retry_after is not None else {}
        self.text = f"fake body {status_code}"

    def json(self):
        return {}


def _bare_client(max_rps=0.0, retry_max=3) -> NsxPolicyClient:
    c = NsxPolicyClient.__new__(NsxPolicyClient)
    c._min_interval = (1.0 / max_rps) if max_rps else 0.0
    c._retry_max = retry_max
    c._pace_lock = threading.Lock()
    c._last_request = 0.0
    return c


class PaceTests(unittest.TestCase):
    def test_pacing_enforces_min_interval(self):
        c = _bare_client(max_rps=50)   # 20ms interval
        start = time.monotonic()
        for _ in range(4):
            c._pace()
        elapsed = time.monotonic() - start
        self.assertGreaterEqual(elapsed, 0.055)   # 3 gaps x 20ms, some slack

    def test_disabled_pacing_is_instant(self):
        c = _bare_client(max_rps=0)
        start = time.monotonic()
        for _ in range(100):
            c._pace()
        self.assertLess(time.monotonic() - start, 0.05)


class SendRetryTests(unittest.TestCase):
    def test_429_retries_then_succeeds(self):
        c = _bare_client()
        seq = [FakeResp(429, retry_after=0), FakeResp(429, retry_after=0), FakeResp(200)]
        calls = []
        resp = c._send(lambda: calls.append(1) or seq[len(calls) - 1], "GET", "/x")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(calls), 3)

    def test_503_honors_retry_after(self):
        c = _bare_client()
        seq = [FakeResp(503, retry_after=0.2), FakeResp(200)]
        calls = []
        start = time.monotonic()
        resp = c._send(lambda: calls.append(1) or seq[len(calls) - 1], "GET", "/x")
        self.assertEqual(resp.status_code, 200)
        self.assertGreaterEqual(time.monotonic() - start, 0.19)

    def test_exhausted_retries_raise(self):
        c = _bare_client(retry_max=2)
        calls = []
        with self.assertRaises(NsxApiError):
            c._send(lambda: calls.append(1) or FakeResp(429, retry_after=0), "GET", "/x")
        self.assertEqual(len(calls), 3)   # initial + 2 retries, then raise

    def test_success_passes_through_untouched(self):
        c = _bare_client()
        resp = c._send(lambda: FakeResp(200), "GET", "/x")
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
