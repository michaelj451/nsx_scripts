"""Critical-rules copy (app/nsx/critical_rules.py and the step scripts in
tools/nsx/critical_rules/), Mike 2026-10-08: gather hit stats, pull those
objects, push them to a new, empty manager, verify, revert.

Covers: run folders (newest by name, never by modification time), exactly one
bundle per step folder, the objects a bundle would push, the target comparison,
push order (Infrastructure bundle first, services to rules), revert order
(the reverse, with --allow-delete on groups), the push summary line, the hit
list (default sections left out), and the new policy's rule order.
"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

import nsx.critical_rules as cr  # noqa: E402

DASH = chr(0x2014)   # the push tools print this between the mode and the counts


def _yaml(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


def make_bundle(root: Path, ts: str, host: str, policy: str, rules, groups, services) -> Path:
    b = root / ts / host
    for s in services:
        _yaml(b / "services/services" / f"{s}.yaml", {"id": s})
    for g in groups:
        _yaml(b / "groups/groups" / f"{g}.yaml", {"id": g})
    _yaml(b / "policies/security-policies" / policy / "policy.yaml", {"id": policy})
    for i, (rid, action, hits) in enumerate(rules, start=1):
        _yaml(b / "rules/security-policies" / policy / "rules" / f"{i:04d}_{rid}.yaml",
              {"id": rid, "action": action, "sequence_number": i,
               "parent_path": f"/infra/domains/default/security-policies/{policy}"})
    (b / "manifest.json").write_text(json.dumps({
        "kept_rules": [{"final_id": rid, "orig_id": rid, "hit_count": h} for rid, _, h in rules],
        "counts": {}}), encoding="utf-8")
    return b


class RunFolderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_new_run_writes_record_and_resolve_finds_newest_by_name(self):
        old = cr.pair_dir("nsx-lm2", "nsx-lm3", self.base) / "20261008_100000"
        old.mkdir(parents=True)
        (old / "run.json").write_text("{}", encoding="utf-8")
        run = cr.new_run("nsx-lm2", "nsx-lm3", "lm2.h", "lm3.h", base=self.base)
        rec = cr.load_record(run)
        self.assertEqual((rec["source"], rec["target"]), ("nsx-lm2", "nsx-lm3"))
        # touching the older run (a push writing into it) must not make it "newest"
        os.utime(old, (time.time() + 3600, time.time() + 3600))
        self.assertEqual(cr.resolve_run("nsx-lm2", "nsx-lm3", base=self.base), run)

    def test_resolve_run_without_any_run_exits(self):
        with self.assertRaises(SystemExit):
            cr.resolve_run("nsx-lm2", "nsx-lm3", base=self.base)

    def test_explicit_run_must_hold_run_json(self):
        with self.assertRaises(SystemExit):
            cr.resolve_run("nsx-lm2", "nsx-lm3", run=str(self.base), base=self.base)

    def test_record_step_keeps_latest_and_history(self):
        run = cr.new_run("nsx-lm2", "nsx-lm3", "a", "b", base=self.base)
        cr.record_step(run, "push_dryrun", {"ok": False})
        cr.record_step(run, "push_dryrun", {"ok": True})
        rec = cr.load_record(run)
        self.assertTrue(rec["steps"]["push_dryrun"]["ok"])
        self.assertEqual([h["ok"] for h in rec["history"]], [False, True])

    def test_check_pair_refuses_other_managers(self):
        with self.assertRaises(SystemExit):
            cr.check_pair({"source": "nsx-lm1", "target": "nsx-lm4"}, "nsx-lm2", "nsx-lm3")


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_single_bundle_requires_exactly_one(self):
        make_bundle(self.root, "20261008_141528", "h", "p", [("r1", "ALLOW", 1)], ["g1"], ["s1"])
        self.assertEqual(cr.single_bundle(self.root, "h"), self.root / "20261008_141528" / "h")
        make_bundle(self.root, "20261008_141530", "h", "p", [("r1", "ALLOW", 1)], ["g1"], ["s1"])
        with self.assertRaises(SystemExit):
            cr.single_bundle(self.root, "h")

    def test_single_bundle_ignores_non_timestamp_folders(self):
        make_bundle(self.root, "20261008_141446_collided_do_not_use", "h", "p", [], [], [])
        with self.assertRaises(SystemExit):
            cr.single_bundle(self.root, "h")

    def test_bundle_objects_and_merge(self):
        a = make_bundle(self.root / "infra", "20261008_141528", "h", "seed-policy-infra",
                        [("seed-infra-dns", "ALLOW", 0)], ["ip-address-group", "seed-tag-asl-2"], ["seed-svc-dns"])
        b = make_bundle(self.root / "hits", "20261008_141530", "h", "critical-rules",
                        [("web_rule", "ALLOW", 33), ("seed-logged-drop", "DROP", 15)],
                        ["vm1", "seed-tag-asl-2"], ["seed-svc-icmp-echo"])
        want = cr.merge_objects([cr.bundle_objects(a), cr.bundle_objects(b)])
        self.assertEqual(want["groups"], {"ip-address-group", "seed-tag-asl-2", "vm1"})
        self.assertEqual(want["policies"], {"seed-policy-infra", "critical-rules"})
        self.assertEqual(want["rules"], {"seed-policy-infra/seed-infra-dns", "critical-rules/web_rule",
                                         "critical-rules/seed-logged-drop"})

    def test_hit_rules_order_reports_actions_and_hits(self):
        b = make_bundle(self.root, "20261008_141530", "h", "critical-rules",
                        [("web_rule", "ALLOW", 33), ("seed-logged-drop", "DROP", 15)], [], [])
        order = cr.hit_rules_order(b)
        self.assertEqual([(r["sequence"], r["action"], r["id"], r["hits"]) for r in order],
                         [(1, "ALLOW", "web_rule", 33), (2, "DROP", "seed-logged-drop", 15)])


class CompareTests(unittest.TestCase):
    def test_compare_reports_missing_and_extra(self):
        want = {"services": {"s1"}, "groups": {"g1", "g2"}, "policies": {"p"}, "rules": {"p/r1"}}
        have = {"services": {"s1"}, "groups": {"g1", "old"}, "policies": set(), "rules": set()}
        res = cr.compare(want, have)
        self.assertEqual(res["groups"]["missing"], ["g2"])
        self.assertEqual(res["groups"]["extra"], ["old"])
        self.assertEqual(res["rules"]["missing"], ["p/r1"])
        self.assertEqual(res["services"], {"expected": ["s1"], "missing": [], "extra": []})

    def test_is_empty(self):
        self.assertTrue(cr.is_empty({k: set() for k in cr.CLASSES}))
        self.assertFalse(cr.is_empty({**{k: set() for k in cr.CLASSES}, "groups": {"g"}}))

    def test_target_objects_leaves_out_defaults_and_system_objects(self):
        class Client:
            def list_security_policies(self, domain_id):
                return [{"id": "default-layer3-section", "is_default": True}, {"id": "p"}]

            def list_services(self):
                return [{"id": "HTTP", "_system_owned": True}, {"id": "s1"}]

            def list_groups(self, domain_id):
                return [{"id": "sys", "_system_owned": True}, {"id": "g1"}]

            def list_security_rules(self, security_policy_id, domain_id):
                return [{"id": "r1"}] if security_policy_id == "p" else [{"id": "default-layer3-rule"}]
        objs = cr.target_objects(Client())
        self.assertEqual(objs, {"services": {"s1"}, "groups": {"g1"}, "policies": {"p"}, "rules": {"p/r1"}})


class StepCommandTests(unittest.TestCase):
    bundles = {"infra": Path("/r/infra/t1/h"), "hits": Path("/r/hits/t2/h")}

    def test_push_order_and_flags(self):
        steps = cr.push_steps(self.bundles, "nsx-lm3", apply=False)
        self.assertEqual([label for label, _ in steps], [
            "01_infra_services_dryrun", "02_infra_groups_dryrun", "03_infra_policies_dryrun",
            "04_infra_rules_dryrun", "05_hits_services_dryrun", "06_hits_groups_dryrun",
            "07_hits_policies_dryrun", "08_hits_rules_dryrun"])
        groups = dict(steps)["02_infra_groups_dryrun"]
        self.assertIn("--segments-mode", groups)
        self.assertEqual(groups[groups.index("--groups-dir") + 1], str(Path("/r/infra/t1/h/groups/groups")))
        self.assertTrue(all("--apply" not in c for _, c in steps))
        self.assertTrue(all("--apply" in c for _, c in cr.push_steps(self.bundles, "nsx-lm3", apply=True)))

    def test_revert_is_reverse_order_with_allow_delete_on_groups(self):
        steps = cr.revert_steps(self.bundles, "nsx-lm3", apply=True)
        self.assertEqual([label for label, _ in steps][:4], [
            "01_hits_rules_revert_apply", "02_hits_policies_revert_apply",
            "03_hits_groups_revert_apply", "04_hits_services_revert_apply"])
        self.assertTrue(steps[4][0].startswith("05_infra_rules"))
        for label, cmd in steps:
            self.assertEqual("--allow-delete" in cmd, "_groups_" in label, label)
            self.assertIn("--apply", cmd)
        rules = dict(steps)["01_hits_rules_revert_apply"]
        self.assertEqual(rules[rules.index("--reports-dir") + 1], str(Path("/r/hits/t2/h/rules/push_report")))

    def test_push_summary_reads_last_summary_line(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "x.log"
            f.write_text(f"noise\nPush groups DRY-RUN {DASH} ok=0 failed=0 skipped=0 (dry_run=7) total=7 [x]\n",
                         encoding="utf-8")
            self.assertEqual(cr.push_summary(f), "ok=0 failed=0 skipped=0 (dry_run=7) total=7 [x]")
            self.assertIsNone(cr.push_summary(Path(d) / "missing.log"))


class HitRowsTests(unittest.TestCase):
    def test_hit_rows_drops_zero_hits_and_default_sections(self):
        with tempfile.TemporaryDirectory() as d:
            rows = [
                {"policy_id": "Start_Policy", "rule_id": "web_rule", "hit_count": 33, "policy_category": "Application"},
                {"policy_id": "Start_Policy", "rule_id": "ping-out", "hit_count": 0, "policy_category": "Application"},
                {"policy_id": "default-layer3-section", "rule_id": "default-layer3-rule", "hit_count": 9,
                 "policy_category": "Application"},
                {"policy_id": "seed-policy-infra", "rule_id": "seed-infra-dns", "hit_count": 10,
                 "policy_category": "Infrastructure"},
            ]
            (Path(d) / "rules_usage.jsonl").write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
            got = [(r["policy_id"], r["rule_id"]) for r in cr.hit_rows(Path(d))]
            self.assertEqual(got, [("Start_Policy", "web_rule"), ("seed-policy-infra", "seed-infra-dns")])


if __name__ == "__main__":
    unittest.main()
