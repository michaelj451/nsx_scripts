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

    def test_runs_base_flag_then_env_then_repo_default(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {cr.RUNS_ENV: str(self.base / "from_env")}):
            self.assertEqual(cr.runs_base(str(self.base / "from_flag")), (self.base / "from_flag").resolve())
            self.assertEqual(cr.runs_base(None), (self.base / "from_env").resolve())
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(cr.runs_base(None), cr.RUNS_BASE)

    def test_next_command_carries_runs_dir(self):
        class A:
            source, target, runs_dir = "nsx-lm2", "nsx-lm5", "/data/runs"
        self.assertEqual(cr.next_command("step3_push.py", A(), "--apply"),
                         'python tools/nsx/critical_rules/step3_push.py --source nsx-lm2 --target nsx-lm5 '
                         '--runs-dir "/data/runs" --apply')
        A.runs_dir = None
        self.assertEqual(cr.next_command("step4_verify.py", A()),
                         "python tools/nsx/critical_rules/step4_verify.py --source nsx-lm2 --target nsx-lm5")

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



class FlatExportTests(unittest.TestCase):
    def test_emit_flat_exports_copies_trees_and_injects_parent_policy_id(self):
        with tempfile.TemporaryDirectory() as d:
            cap = Path(d) / "capture" / "nsx_export" / "h" / "domains" / "default"
            _yaml(cap / "groups" / "g1.yaml", {"id": "g1"})
            _yaml(cap / "services" / "s1.yaml", {"id": "s1"})
            _yaml(cap / "security-policies" / "Start-x" / "policy.yaml", {"id": "Start_Policy"})
            _yaml(cap / "security-policies" / "Start-x" / "rules" / "0001_r.yaml",
                  {"id": "r", "parent_path": "/infra/domains/default/security-policies/Start_Policy"})
            run = Path(d) / "run"
            counts = cr.emit_flat_exports(Path(d) / "capture", "h", run)
            self.assertEqual(counts["nsx_groups_export"], 1)
            rule = yaml.safe_load((run / "nsx_rules_export/h/security-policies/Start-x/rules/0001_r.yaml").read_text())
            self.assertEqual(rule["_parent_policy_id"], "Start_Policy")
            pol = yaml.safe_load((run / "nsx_policies_export/h/security-policies/Start-x/rules/0001_r.yaml").read_text())
            self.assertNotIn("_parent_policy_id", pol)   # only the rules tree gets the field
            with self.assertRaises(SystemExit):           # never overwrites an existing export
                cr.emit_flat_exports(Path(d) / "capture", "h", run)


class SystemDefaultTests(unittest.TestCase):
    def test_is_system_default(self):
        self.assertTrue(cr.is_system_default({"id": "default-layer3-section", "is_default": True,
                                              "_system_owned": False, "_create_user": "system"}))
        self.assertTrue(cr.is_system_default({"id": "HTTP", "_system_owned": True}))
        self.assertTrue(cr.is_system_default({"id": "x", "_create_user": "system"}))   # NSX-created, unflagged
        self.assertFalse(cr.is_system_default({"id": "seed-policy-infra", "is_default": False,
                                               "_system_owned": False, "_create_user": "admin"}))

    def test_system_defaults_in_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            b = make_bundle(Path(d), "20261008_141528", "h", "p", [("r1", "ALLOW", 0)], ["g1"], ["s1"])
            self.assertEqual(cr.system_defaults_in_bundle(b), [])
            _yaml(b / "groups/groups/sysg.yaml", {"id": "sysg", "_create_user": "system"})
            _yaml(b / "policies/security-policies/default-layer3-section/policy.yaml",
                  {"id": "default-layer3-section", "is_default": True})
            self.assertEqual(sorted(cr.system_defaults_in_bundle(b)),
                             ["group sysg", "policy default-layer3-section"])

    def _source(self, d: Path) -> Path:
        run = Path(d)
        for pid, cat, flags, rules in (
                ("seed-policy-infra", "Infrastructure", {"_create_user": "admin"}, ["a", "b"]),
                ("test-infrastructure-policy", "Infrastructure", {}, ["c"]),
                ("default-layer3-section", "Application", {"is_default": True, "_create_user": "system"}, ["d"])):
            _yaml(run / "nsx_policies_export/h/security-policies" / pid / "policy.yaml",
                  {"id": pid, "category": cat, **flags})
            for r in rules:
                _yaml(run / "nsx_rules_export/h/security-policies" / pid / "rules" / f"{r}.yaml", {"id": r})
        return run

    def test_source_policies_marks_system_defaults(self):
        with tempfile.TemporaryDirectory() as d:
            src = {p["id"]: p for p in cr.source_policies(self._source(Path(d)), "h")}
            self.assertTrue(src["default-layer3-section"]["system_default"])
            self.assertFalse(src["seed-policy-infra"]["system_default"])
            self.assertEqual(src["seed-policy-infra"]["rules"], ["a", "b"])

    def test_whole_category_gaps(self):
        with tempfile.TemporaryDirectory() as d:
            sources = cr.source_policies(self._source(Path(d) / "run"), "h")
            full = Path(d) / "full"
            make_bundle(full, "20261008_141528", "h", "seed-policy-infra",
                        [("a", "ALLOW", 0), ("b", "ALLOW", 0)], [], [])
            _yaml(full / "20261008_141528/h/policies/security-policies/test-infrastructure-policy/policy.yaml",
                  {"id": "test-infrastructure-policy"})
            _yaml(full / "20261008_141528/h/rules/security-policies/test-infrastructure-policy/rules/0001_c.yaml",
                  {"id": "c", "parent_path": "/infra/domains/default/security-policies/test-infrastructure-policy"})
            self.assertEqual(cr.whole_category_gaps(sources, {"Infrastructure"}, full / "20261008_141528/h"), [])
            part = Path(d) / "part"
            make_bundle(part, "20261008_141528", "h", "seed-policy-infra", [("a", "ALLOW", 0)], [], [])
            self.assertEqual(cr.whole_category_gaps(sources, {"Infrastructure"}, part / "20261008_141528/h"),
                             ["rule seed-policy-infra/b", "policy test-infrastructure-policy"])


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
                return [{"id": "sys", "_system_owned": True}, {"id": "nsxmade", "_create_user": "system"},
                        {"id": "g1"}]

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


def make_exports(root: Path, host: str = "h") -> Path:
    """A small flat export: two Application policies, one Infrastructure, one default section."""
    G = "/infra/domains/default/groups/"
    P = "/infra/domains/default/security-policies/"
    def pol(slug, pid, cat, seq, rules, **extra):
        _yaml(root / f"nsx_policies_export/{host}/security-policies/{slug}/policy.yaml",
              {"id": pid, "display_name": extra.pop("display", pid), "path": P + pid, "category": cat,
               "sequence_number": seq, **extra})
        _yaml(root / f"nsx_policies_export/{host}/security-policies/{slug}/rules_order.yaml",
              {"policy": pid, "rules": [r["id"] for r in rules]})
        for i, r in enumerate(rules, start=1):
            _yaml(root / f"nsx_rules_export/{host}/security-policies/{slug}/rules/{i:04d}_{r['id']}.yaml",
                  {"parent_path": P + pid, "_parent_policy_id": pid, "services": ["ANY"], **r})
    pol("Start-x", "Start_Policy", "Application", 2, [
        {"id": "web_rule", "sequence_number": 32, "action": "ALLOW", "source_groups": [G + "hw"],
         "destination_groups": [G + "vm1"], "services": ["/infra/services/web"]},
        {"id": "cold_drop", "sequence_number": 5, "action": "DROP", "source_groups": [G + "only-cold"],
         "destination_groups": ["ANY"]},
        {"id": "ssh", "sequence_number": 17, "action": "ALLOW", "source_groups": [G + "hw"],
         "destination_groups": ["ANY"]},
    ], display="test-policy-1", scope=[G + "policy-scope"])
    pol("test-x", "test-policy-2", "Application", 5, [
        {"id": "special", "sequence_number": 10, "action": "REJECT", "source_groups": ["ANY"],
         "destination_groups": ["ANY"]}])
    pol("infra-x", "seed-policy-infra", "Infrastructure", 20, [
        {"id": "dns", "sequence_number": 10, "action": "ALLOW", "source_groups": ["ANY"],
         "destination_groups": [G + "mgmt"]}])
    pol("defau-x", "default-layer3-section", "Application", 2147483647, [
        {"id": "default-layer3-rule", "sequence_number": 2147483647, "action": "DROP", "is_default": True}],
        is_default=True, _create_user="system")
    for gid, expr in (("hw", []), ("vm1", [{"resource_type": "PathExpression", "paths": [G + "nested"]}]),
                      ("nested", []), ("only-cold", []), ("mgmt", []), ("policy-scope", [])):
        _yaml(root / f"nsx_groups_export/{host}/groups/{gid}.yaml", {"id": gid, "path": G + gid, "expression": expr})
    _yaml(root / f"nsx_services_export/{host}/services/web.yaml", {"id": "web", "path": "/infra/services/web"})
    return root


class BuildBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = make_exports(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_hot_only_keeps_original_policies_and_rules_exactly(self):
        hot = {("Start_Policy", "web_rule"), ("Start_Policy", "ssh")}
        b = cr.build_bundle(self.root, "h", self.root / "hits", {"Application"}, hot=hot)
        src_pol = self.root / "nsx_policies_export/h/security-policies/Start-x/policy.yaml"
        self.assertEqual((b / "policies/security-policies/Start-x/policy.yaml").read_bytes(), src_pol.read_bytes())
        self.assertEqual((b / "rules/security-policies/Start-x/policy.yaml").read_bytes(), src_pol.read_bytes())
        copied = sorted(f.name for f in (b / "rules/security-policies/Start-x/rules").glob("*.yaml"))
        self.assertEqual(copied, ["0001_web_rule.yaml", "0003_ssh.yaml"])
        src_rule = self.root / "nsx_rules_export/h/security-policies/Start-x/rules/0001_web_rule.yaml"
        self.assertEqual((b / "rules/security-policies/Start-x/rules/0001_web_rule.yaml").read_bytes(),
                         src_rule.read_bytes())
        order = yaml.safe_load((b / "rules/security-policies/Start-x/rules_order.yaml").read_text())
        self.assertEqual(order, {"policy": "Start_Policy", "rules": ["ssh", "web_rule"]})   # by sequence
        m = json.loads((b / "manifest.json").read_text())
        self.assertEqual([p["id"] for p in m["policies"]], ["Start_Policy"])
        self.assertEqual(m["policies"][0]["display_name"], "test-policy-1")
        self.assertEqual([r["id"] for r in m["policies"][0]["not_copied"]], ["cold_drop"])
        skipped = {s["policy"]: s for s in m["skipped_policies"]}
        self.assertEqual(skipped["test-policy-2"]["reason"], "no hot rules")
        self.assertEqual(skipped["test-policy-2"]["rules"][0]["action"], "REJECT")
        self.assertEqual(skipped["default-layer3-section"]["reason"], "system default")
        groups = {g.rsplit("/", 1)[-1] for g in m["groups"]}
        self.assertEqual(groups, {"hw", "vm1", "nested", "policy-scope"})   # not only-cold
        self.assertEqual(m["services"], ["/infra/services/web"])

    def test_whole_copies_every_rule(self):
        b = cr.build_bundle(self.root, "h", self.root / "infra", {"Infrastructure"})
        m = json.loads((b / "manifest.json").read_text())
        self.assertEqual([(p["id"], [r["id"] for r in p["rules"]]) for p in m["policies"]],
                         [("seed-policy-infra", ["dns"])])
        self.assertEqual(cr.system_defaults_in_bundle(b), [])
        self.assertEqual([g.rsplit("/", 1)[-1] for g in m["groups"]], ["mgmt"])

    def test_two_bundles_never_share_a_folder(self):
        a = cr.build_bundle(self.root, "h", self.root / "out", {"Infrastructure"})
        b = cr.build_bundle(self.root, "h", self.root / "out", {"Infrastructure"})
        self.assertNotEqual(a, b)


if __name__ == "__main__":
    unittest.main()
