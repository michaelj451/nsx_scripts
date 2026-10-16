"""Tests for the vRNI flow filter (app/multisite/vrni_flows.py and
tools/multisite/filter_vrni_flows.py), Mike 2026-10-15: drop the flows whose
NSX rule sits in an Infrastructure policy."""
from __future__ import annotations

import csv
import importlib.util
import re
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from multisite import vrni_flows as vf  # noqa: E402

SAMPLE = ROOT / "data" / "samples" / "vrni_flows_sample.csv"
INFRA_SAMPLE = ROOT / "data" / "samples" / "vrni_flows_infra_sample.csv"
HOST = "lm1.test"
# lm1's rules as the sample uses them: (policy id, category, is_default, [(rule id, number, action)]).
POLICIES = [
    ("always-rules-poilicy", "Infrastructure", False, [("servers-to-rustdesk", 8177, "ALLOW"),
                                                       ("install-rustdesk", 8176, "ALLOW")]),
    ("seed-policy-infra", "Infrastructure", False, [("seed-infra-dns", 7212, "ALLOW")]),
    ("test-infrastructure-policy", "Infrastructure", False, [("test-infrastructure-rule-1", 7198, "ALLOW")]),
    ("test-policy-2", "Application", False, [("migration-rule", 8168, "ALLOW"),
                                             ("migration-rule-2", 8175, "ALLOW"),
                                             ("migration-ssh", 8178, "ALLOW")]),
    ("seed-cold-above", "Application", False, [("seed-cold-a-tcp-17239", 8170, "ALLOW")]),
    ("seed-infra-services", "Infrastructure", False, [("seed-infra-ad", 8179, "ALLOW"),
                                                     ("seed-infra-dns-lookup", 8180, "ALLOW"),
                                                     ("seed-infra-ntp", 8181, "ALLOW"),
                                                     ("seed-infra-puppet", 8182, "ALLOW"),
                                                     ("seed-infra-snmp", 8183, "ALLOW"),
                                                     ("seed-infra-splunk", 8184, "ALLOW")]),
    ("default-layer3-section", "Application", True, [("default-layer3-rule", 2, "DROP")]),
]


def pairs():
    return [({"id": pid, "display_name": pid, "category": cat, "is_default": dflt},
             {"id": rid, "display_name": rid, "rule_id": num, "action": act})
            for pid, cat, dflt, rules in POLICIES for rid, num, act in rules]


class FlowFilterTests(unittest.TestCase):
    def test_columns_by_header_name(self):
        header, _ = vf.read_flows(SAMPLE)
        cols = vf.find_columns(header)
        self.assertEqual(cols["rule_number"], 1)
        self.assertEqual(cols["packets"], 10)
        self.assertEqual(vf.window(header, cols), "14/10/2026 12:12:53 to 15/10/2026 12:12:53")
        self.assertEqual(vf.find_columns(["  Firewall RuleID ", "x"])["rule_number"], 0)
        with self.assertRaises(ValueError):
            vf.find_columns(["name", "firewall rule"])

    def test_rule_numbers_as_excel_writes_them(self):
        for raw, want in (("8168", 8168), ("8,168", 8168), ("8168.0", 8168), (" 2 ", 2), ("", None), ("n/a", None)):
            self.assertEqual(vf.parse_rule_number(raw), want, raw)

    def test_sample_splits_into_kept_removed_unmatched(self):
        header, rows = vf.read_flows(SAMPLE)
        res = vf.classify(rows, vf.find_columns(header), vf.rule_index(pairs()))
        num = lambda key: sorted(vf.parse_rule_number(r[1]) or 0 for r, _x, _y in res[key])  # noqa: E731
        self.assertEqual(num("kept"), [2, 8168, 8170, 8175, 8178, 8178])
        self.assertEqual(num("removed"), [7198, 7212, 8176, 8177])
        self.assertEqual(num("unmatched"), [0, 99999])
        self.assertEqual(len(rows), 12)
        reasons = sorted(reason for _r, _x, reason in res["unmatched"])
        self.assertEqual(reasons, ["no rule id in the row", "rule 99999 is not on the manager the rules were read from"])
        self.assertTrue(all(reason.startswith("Infrastructure rule: ") for _r, _x, reason in res["removed"]))

    def test_infra_sample_keeps_only_application_flows(self):
        header, rows = vf.read_flows(INFRA_SAMPLE)
        res = vf.classify(rows, vf.find_columns(header), vf.rule_index(pairs()))
        num = lambda key: sorted(vf.parse_rule_number(r[1]) or 0 for r, _x, _y in res[key])  # noqa: E731
        self.assertEqual(num("kept"), [2, 8168, 8175, 8178])
        self.assertEqual(num("removed"), [8177, 8179, 8179, 8179, 8180, 8180, 8181, 8181, 8182, 8183, 8183,
                                          8184, 8184])
        self.assertEqual(num("unmatched"), [0, 99999])

    def test_other_categories_can_be_left_out(self):
        header, rows = vf.read_flows(SAMPLE)
        res = vf.classify(rows, vf.find_columns(header), vf.rule_index(pairs()), ["Infrastructure", "Application"])
        self.assertEqual(len(res["kept"]), 0)
        self.assertEqual(len(res["removed"]), 10)


class CliTests(unittest.TestCase):
    def test_end_to_end_from_a_capture(self):
        tmp = Path(tempfile.mkdtemp())
        base = tmp / "capture" / "nsx_export" / HOST / "domains" / "default" / "security-policies"
        for pid, cat, dflt, rules in POLICIES:
            d = base / pid
            (d / "rules").mkdir(parents=True)
            (d / "policy.yaml").write_text(yaml.safe_dump({"id": pid, "display_name": pid, "category": cat,
                                                           "is_default": dflt}))
            for rid, num, act in rules:
                (d / "rules" / f"{rid}.yaml").write_text(yaml.safe_dump({"id": rid, "display_name": rid,
                                                                         "rule_id": num, "action": act}))
        spec = importlib.util.spec_from_file_location("filter_vrni_flows",
                                                      ROOT / "tools/multisite/filter_vrni_flows.py")
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        out = tmp / "out"
        rc = tool.main(["--flows", str(SAMPLE), "--capture", str(tmp / "capture"), "--out-dir", str(out)])
        self.assertEqual(rc, 0)

        def rows(name):
            with (out / name).open(encoding="utf-8-sig", newline="") as fh:
                return list(csv.reader(fh))
        kept, removed, unmatched = (rows(f"vrni_flows_sample_{k}.csv") for k in ("filtered", "removed", "unmatched"))
        header, _ = vf.read_flows(SAMPLE)
        self.assertEqual(kept[0], header)                     # the same columns, in order
        self.assertEqual(removed[0], header + ["filter reason"])
        self.assertEqual((len(kept) - 1, len(removed) - 1, len(unmatched) - 1), (6, 4, 2))
        rules = rows("vrni_flows_sample_rules.csv")
        # Two sections: kept rules, then the Infrastructure rules hit (Mike, 2026-10-16).
        self.assertEqual(rules[0], [f"{vf.KEPT_TITLE}: 5 rule(s)"])
        self.assertEqual(rules[1], vf.RULES_HEADER)
        self.assertEqual(rules[7], [])
        self.assertEqual(rules[8], [f"{vf.INFRA_TITLE}: 4 rule(s)"])
        self.assertEqual(rules[9], vf.RULES_HEADER)
        self.assertEqual([r[-1] for r in rules[2:7]].count("removed"), 0)
        self.assertEqual([r[-1] for r in rules[10:]], ["removed"] * 4)
        self.assertIn(["8178", "migration-ssh", "migration-ssh", "test-policy-2", "Application", "ALLOW", "2", "96",
                       "kept"], rules)
        summary = (out / "summary.md").read_text()
        self.assertIn("| 12 | 6 | 4 | 2 |", re.sub(r" +", " ", summary))
        self.assertIn("kept (NSX default section)", summary)


if __name__ == "__main__":
    unittest.main()
