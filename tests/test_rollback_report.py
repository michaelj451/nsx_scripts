"""The rollback report: every rollback, dry run or apply, produces a document
that says which apply it undoes and what happens to each object, by name."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "app"))

from nsx import revert_plan  # noqa: E402

G = "/infra/domains/default/groups/"


def load_report_module():
    spec = importlib.util.spec_from_file_location(
        "report_rollback", REPO_ROOT / "tools" / "nsx" / "report_rollback.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class PlanTests(unittest.TestCase):

    def test_classifies_each_kind_of_restore_and_delete(self):
        rows, to_write = revert_plan.build(
            "policy",
            restores=[
                {"key": "same", "id": "same", "baseline": {"id": "same", "x": 1},
                 "current": {"id": "same", "x": 1, "_revision": 9}},
                {"key": "drift", "id": "drift", "baseline": {"id": "drift", "x": 1},
                 "current": {"id": "drift", "x": 2}},
                {"key": "gone", "id": "gone", "baseline": {"id": "gone"}, "current": None},
            ],
            deletes=[{"key": "new", "id": "new", "current": {"id": "new", "display_name": "New"}}],
            blocked=[{"key": "held", "id": "held", "current": {"id": "held"}}],
            already_gone=[{"key": "was", "id": "was", "current": None}])
        by = {r["id"]: r for r in rows}
        self.assertEqual(by["same"]["status"], "skipped_unchanged")
        self.assertEqual(by["drift"]["restore_kind"], "revert")
        self.assertEqual(by["drift"]["per_field_diff"], {"x": {"before": 2, "after": 1}})
        self.assertEqual(by["gone"]["restore_kind"], "recreate")
        self.assertEqual(by["new"]["display_name"], "New")
        self.assertEqual(by["held"]["status"], "blocked")
        self.assertEqual(by["was"]["status"], "already_gone")
        self.assertEqual(to_write, {"drift", "gone"})

    def test_force_writes_identical_restores(self):
        _, to_write = revert_plan.build(
            "service", restores=[{"key": "s", "id": "s", "baseline": {"id": "s"},
                                  "current": {"id": "s"}}], deletes=[], force=True)
        self.assertEqual(to_write, {"s"})

    def test_settle_marks_what_ran_and_what_never_ran(self):
        rows, _ = revert_plan.build(
            "service",
            restores=[{"key": "a", "id": "a", "baseline": {"id": "a", "x": 1},
                       "current": {"id": "a", "x": 2}},
                      {"key": "b", "id": "b", "baseline": {"id": "b", "x": 1},
                       "current": {"id": "b", "x": 2}}],
            deletes=[])
        revert_plan.settle(rows, [{"action": "restore", "id": "a", "status": "success_put"}],
                           key_of=lambda e: e.get("id"))
        by = {r["id"]: r["status"] for r in rows}
        self.assertEqual(by, {"a": "success_put", "b": "not_reached"})


class ReportTests(unittest.TestCase):

    def run_report(self, plans, apply=False):
        mod = load_report_module()
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            roots = []
            for i, (kind, rows) in enumerate(plans):
                pr = d / f"{kind}_export" / "push_report"
                (pr / "baselines").mkdir(parents=True)
                bf = pr / "baselines" / "20260924_153311_target_baseline.json"
                bf.write_text("{}")
                (pr / "baselines" / "20260923_193353_target_baseline.json").write_text("{}")
                doc = {"kind": kind, "mode": "APPLY" if apply else "DRY-RUN",
                       "ran_at": f"2026-09-24T16:00:0{i}+00:00", "baseline_file": str(bf),
                       "rows": rows}
                (pr / f"revert_plan_{i}.json").write_text(json.dumps(doc))
                roots += ["--report-root", str(pr)]
            out = d / "out"
            argv = ["report_rollback.py", "--out-dir", str(out), "--since", "2026-09-24T00:00:00",
                    "--label", "WF-A ROLLBACK TEST"] + roots
            with mock.patch.object(sys, "argv", argv):
                rc = mod.main()
            return rc, (out / "rollback_report.md").read_text()

    def test_report_names_objects_and_the_policy_and_the_baseline(self):
        rc, md = self.run_report([("rule", [
            {"action": "restore", "restore_kind": "revert", "key": "Start_Policy::r1", "id": "r1",
             "display_name": "web-rule", "policy_id": "Start_Policy",
             "policy_display_name": "test-policy-1", "status": "dry_run",
             "ref_names": {G + "vm1": "vm-group-1", G + "a8b5": "ip-address-group-10"},
             "per_field_diff": {"source_groups": {"before": [G + "vm1", G + "a8b5"],
                                                  "after": [G + "vm1"],
                                                  "added": [], "removed": [G + "a8b5"]}}}])])
        self.assertEqual(rc, 0)
        self.assertIn("`20260924_153311`", md)                   # which apply is undone
        self.assertIn("| web-rule | test-policy-1 |", " ".join(md.split()))
        self.assertIn("in policy **test-policy-1**", md)
        self.assertIn("REMOVED by the rollback (1): `ip-address-group-10`", md)
        for leaked in ("Start_Policy", "a8b5", "vm1`"):
            self.assertNotIn(leaked, md)

    def test_group_ip_removal_is_listed_first(self):
        _, md = self.run_report([("group", [
            {"action": "restore", "restore_kind": "revert", "key": "g", "id": "g",
             "display_name": "web-servers", "status": "dry_run",
             "ips_removed": ["10.7.0.5"], "ips_added": ["10.6.0.5"],
             "per_field_diff": {"expression": {"before": [1], "after": [2]}}}])])
        detail = md[md.index("**web-servers**"):]
        self.assertLess(detail.index("IPs REMOVED"), detail.index("IPs put back"))
        self.assertNotIn("`expression`", detail)                  # the IP lines already say it

    def test_unchanged_objects_are_counted_not_acted_on(self):
        _, md = self.run_report([("service", [
            {"action": "restore", "restore_kind": "unchanged", "key": "s", "id": "s",
             "display_name": "ssh-custom", "status": "skipped_unchanged"}])])
        self.assertIn("Already matching the baseline", md)
        self.assertIn("ssh-custom", md)
        self.assertNotIn("### Services", md)

    def test_blocked_delete_explains_itself(self):
        _, md = self.run_report([("group", [
            {"action": "delete", "key": "g", "id": "g", "display_name": "leftover",
             "status": "blocked"}])])
        self.assertIn("--allow-delete", md)

    def test_incomplete_apply_is_called_out_and_exits_nonzero(self):
        rc, md = self.run_report([("rule", [
            {"action": "delete", "key": "p::r", "id": "r", "display_name": "r",
             "policy_id": "p", "status": "not_reached"}])], apply=True)
        self.assertEqual(rc, 1)
        self.assertIn("ROLLBACK APPLIED", md)
        self.assertIn("never reached", md)
        self.assertIn("NOT REACHED", md)

    def test_stack_depth_counts_older_applies(self):
        _, md = self.run_report([("rule", [])])
        # two unconsumed baselines on disk; a dry run pops one, one stays stacked
        self.assertIn("| Rules | `20260924_153311` | 1 |", " ".join(md.split()))


if __name__ == "__main__":
    unittest.main()
