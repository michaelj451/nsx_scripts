"""Lab traffic tool (tools/test/generate_lab_traffic.py), 2026-10-08.

Covers: the macOS nc connect timeout (-G), the plan grader (expected rules
need new hits, cold rules none), and --grade's wait loop: it keeps re-running
the report until every expected rule has moved, and stops at the deadline.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("glt", ROOT / "tools/test/generate_lab_traffic.py")
glt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(glt)

PLAN = {
    "manager": "nsx-lm2",
    "hosts": {"mac": {"local": True}, "vm": {"ssh": "u@10.7.0.101", "jump": "j"}},
    "flows": [
        {"id": "a", "from": "mac", "action": "tcp", "dst": "10.7.0.101", "port": 80, "expect": "web_rule"},
        {"id": "b", "from": "vm", "action": "ping", "dst": "8.8.8.8", "expect": "ping-out"},
    ],
    "cold": ["seed-syslog-any"],
}


def write_diff(folder: Path, deltas: dict) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "diff.json").write_text(json.dumps({
        "compared_to": "before",
        "transitions": [{"rule_id": r, "hit_count_delta": d} for r, d in deltas.items()]}), encoding="utf-8")
    return folder


class CommandTests(unittest.TestCase):
    def test_mac_nc_gets_connect_timeout(self):
        f = PLAN["flows"][0]
        if sys.platform == "darwin":
            self.assertIn("nc -G 2 -w 2 -z", glt.flow_command(f, local=True))
        self.assertIn("nc -w 2 -z", glt.flow_command(f, local=False))

    def test_jump_host_in_ssh_argv(self):
        argv = glt.host_argv(PLAN["hosts"]["vm"], "true")
        self.assertEqual(argv[argv.index("-J") + 1], "j")
        self.assertEqual(argv[-2:], ["u@10.7.0.101", "true"])


class CheckTests(unittest.TestCase):
    def test_pass_and_fail(self):
        with tempfile.TemporaryDirectory() as d:
            ok = write_diff(Path(d) / "ok", {"web_rule": 3, "ping-out": 1, "seed-syslog-any": 0})
            self.assertEqual(glt.check(PLAN, ok / "diff.json"), 0)
            cold_hit = write_diff(Path(d) / "cold", {"web_rule": 3, "ping-out": 1, "seed-syslog-any": 2})
            self.assertEqual(glt.check(PLAN, cold_hit / "diff.json"), 1)
            missing = write_diff(Path(d) / "miss", {"web_rule": 3})
            self.assertEqual(glt.check(PLAN, missing / "diff.json"), 1)


class GradeLoopTests(unittest.TestCase):
    def test_waits_until_every_expected_rule_moved(self):
        with tempfile.TemporaryDirectory() as d:
            snaps = iter([write_diff(Path(d) / "1", {"web_rule": 1}),
                          write_diff(Path(d) / "2", {"web_rule": 1, "ping-out": 1})])
            calls = []
            def fake_report(manager, out, compare_to=None):
                calls.append(compare_to)
                return next(snaps)
            with patch.object(glt, "_report", fake_report), patch.object(glt.time, "sleep") as sleep:
                rc, after = glt.grade(PLAN, Path(d), Path("before"), poll_seconds=5, wait_minutes=10)
            self.assertEqual(rc, 0)
            self.assertEqual(after, Path(d) / "2")
            self.assertEqual(calls, [Path("before"), Path("before")])
            sleep.assert_called_once_with(5)

    def test_gives_up_at_the_deadline_and_fails(self):
        with tempfile.TemporaryDirectory() as d:
            snap = write_diff(Path(d) / "1", {"web_rule": 1})
            with patch.object(glt, "_report", lambda *a, **k: snap), \
                    patch.object(glt.time, "sleep"), \
                    patch.object(glt.time, "time", side_effect=[0, 0, 10_000]):
                rc, _ = glt.grade(PLAN, Path(d), Path("before"), poll_seconds=5, wait_minutes=1)
            self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
