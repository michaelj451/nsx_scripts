"""Multi-site planner (app/multisite/plan.py + tools/multisite/plan_multisite.py).

The safety properties that matter for three sites:
  * every manager gets every view but its own;
  * no two pushes share a report (baseline) folder;
  * suffixes never collide with each other or with the real WF-C/WF-D ones;
  * a bad map refuses before anything is built;
  * the end-to-end run builds through the existing sibling builder unchanged.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from common import ipspan  # noqa: E402
from multisite import plan as P  # noqa: E402


def load_tool():
    spec = importlib.util.spec_from_file_location("plan_multisite_t", ROOT / "tools/multisite/plan_multisite.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ViewTests(unittest.TestCase):
    def test_default_suffixes_and_matrix(self):
        views = P.build_views("nsx-lm1", ["nsx-lm2", "nsx-lm3"])
        self.assertEqual([v.suffix for v in views], ["_lm1_ips", "_lm2_ips", "_lm3_ips"])
        self.assertEqual(P.deployment(views), {"nsx-lm1": ["nsx-lm2", "nsx-lm3"],
                                               "nsx-lm2": ["nsx-lm1", "nsx-lm3"],
                                               "nsx-lm3": ["nsx-lm1", "nsx-lm2"]})

    def test_suffix_problems(self):
        views = P.build_views("nsx-lm1", ["nsx-lm2", "nsx-lm3"], {"nsx-lm3": "_lm2_ips"})
        self.assertTrue(any("share suffix" in m for m in P.suffix_problems(views, {})))
        views = P.build_views("nsx-lm1", ["nsx-lm2"], {"nsx-lm2": "_avs_ips"})
        self.assertTrue(any("OBJECT_APPENDIX_AVS" in m
                            for m in P.suffix_problems(views, {"OBJECT_APPENDIX_AVS": "_avs_ips"})))

    def test_every_push_has_its_own_report_folder(self):
        views = P.build_views("nsx-lm1", ["nsx-lm2", "nsx-lm3"])
        for v in views:
            v.bundle = Path("/r/views") / v.key / "nsx_sibling_groups" / "h"
        cmds = P.commands(Path("/r"), "nsx-lm1", views, P.deployment(views))
        dirs = [c.split("--reports-dir ")[1].split()[0] for c in cmds["window_1_siblings"]]
        dirs += [c.split("--reports-dir ")[1].split()[0] for c in cmds["window_2_rule_refs"]]
        self.assertEqual(len(dirs), 12)
        self.assertEqual(len(set(dirs)), 12)
        self.assertEqual(len(cmds["rollback"]), 12)
        self.assertTrue(all("--apply" not in c.split("#")[0] for k in cmds for c in cmds[k]))


class AnalysisTests(unittest.TestCase):
    def view(self, rows, mapped=True):
        v = P.View(key="nsx-lm3", suffix="_lm3_ips", mapped=mapped)
        v.sibling_map = {"map": rows, "no_sibling": []}
        return v

    def test_sibling_ips_for_both_build_kinds(self):
        self.assertEqual(P.sibling_ips({"ips_sibling_mapped": None, "ips_source": ["10.6.0.1"]}), ["10.6.0.1"])
        self.assertEqual(P.sibling_ips({"ips_sibling_mapped": [], "ips_source": ["10.6.0.1"]}), [])

    def test_in_use_collision_vs_covers(self):
        rows = [{"original_display_name": "g1", "ip_pairs": [["10.6.0.101", ["10.8.0.101"]],
                                                             ["10.6.0.0/24", ["10.8.0.0/24"]]],
                 "ips_sibling_mapped": ["10.8.0.101", "10.8.0.0/24"]},
                {"original_display_name": "g2", "ip_pairs": [["10.6.0.101", ["10.8.0.101"]]],
                 "ips_sibling_mapped": ["10.8.0.101"]}]
        spans, bad = P.parse_in_use("10.8.0.101   # vm\n10.8.0.1\nnot-an-ip\n")
        self.assertEqual(bad, ["not-an-ip"])
        f = P.in_use_findings(self.view(rows), spans)
        self.assertEqual([(x["kind"], x["mapped"], x["groups"]) for x in f],
                         [("collision", "10.8.0.101", ["g1", "g2"]),
                          ("covers", "10.8.0.0/24", ["g1"])])

    def test_reserved_addresses_merge(self):
        rows = [{"ips_sibling_mapped": ["10.8.0.0/25", "10.8.0.128/25", "10.8.9.9"]}]
        self.assertEqual(P.reserved_addresses(self.view(rows)), ["10.8.0.0/24", "10.8.9.9"])


TAG = {"resource_type": "Condition", "member_type": "VirtualMachine", "key": "Tag",
       "operator": "EQUALS", "value": "0|web"}
OR = {"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"}


def make_capture(root: Path, host="nsx-x.lab.local") -> Path:
    cap = root / "capture" / host
    gdir = cap / "groups_additive" / "domains" / "default" / "groups"
    gdir.mkdir(parents=True)
    groups = {
        "web": {"id": "web", "display_name": "web", "resource_type": "Group",
                "expression": [TAG, OR, {"resource_type": "IPAddressExpression",
                                         "ip_addresses": ["10.6.0.101", "10.6.1.5"]}]},
        "ipgrp": {"id": "ipgrp", "display_name": "ipgrp", "resource_type": "Group",
                  "expression": [{"resource_type": "IPAddressExpression",
                                  "ip_addresses": ["10.6.2.0/24"]}]},
    }
    for gid, g in groups.items():
        (gdir / f"{gid}.yaml").write_text(yaml.safe_dump(g), encoding="utf-8")
    (gdir / "manifest.json").write_text(json.dumps({
        "source_manager_host": host, "domain_id": "default", "ip_source": "effective",
        "groups_errors": 0, "groups_seen": 2, "effective_ip_queries": 2}), encoding="utf-8")
    (cap / "manifest.json").write_text(json.dumps({
        "ok": True, "captured_at": "2026-10-04T00:00:00+00:00",
        "captured_from": {"manager_host": host, "manager_alias": "nsx-lm1", "domain_id": "default",
                          "federation_global": False}}), encoding="utf-8")
    return cap


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.d = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def run_tool(self, map_text, *extra):
        m = self.d / "map.csv"
        m.write_text(map_text, encoding="utf-8")
        args = ["--map", str(m), "--output-base", str(self.d / "out"), *extra]
        return self.tool.main(args)

    def test_bad_map_refuses_before_building(self):
        cap = make_capture(self.d)
        rc = self.run_tool("old_subnet,nsx-lm2\n10.8.0.0/16,10.9.0.0/16\n10.8.0.0/24,10.9.1.0/24\n",
                           "--capture", str(cap))
        self.assertEqual(rc, 2)
        run = next((self.d / "out" / "nsx-x.lab.local").glob("2*"))
        self.assertFalse((run / "views").exists())
        self.assertFalse((self.d / "out" / "nsx-x.lab.local" / "latest").exists())
        self.assertIn("collision_within_site", (run / "report.md").read_text())

    def test_plan_builds_three_views(self):
        cap = make_capture(self.d)
        inuse = self.d / "lm3.txt"
        inuse.write_text("10.8.0.101\n", encoding="utf-8")
        rc = self.run_tool("old_subnet,nsx-lm2,nsx-lm3\n10.6.0.0/16,10.7.0.0/16,10.8.0.0/16\n",
                           "--capture", str(cap), "--in-use", f"nsx-lm3={inuse}")
        self.assertEqual(rc, 1)                        # the in-use collision is blocking
        run = (self.d / "out" / "nsx-x.lab.local" / "latest").resolve()
        summary = json.loads((run / "summary.json").read_text())
        self.assertEqual(summary["views"]["nsx-lm1"]["siblings"], 1)   # WF-C: tag groups only
        self.assertEqual(summary["views"]["nsx-lm2"]["siblings"], 2)   # WF-D: tag + IP-only
        self.assertEqual(summary["in_use_collisions"], 1)
        lm3 = json.loads((run / "views/nsx-lm3/nsx_sibling_groups/nsx-x.lab.local/sibling_map.json").read_text())
        web = next(r for r in lm3["map"] if r["original_id"] == "web")
        self.assertEqual(web["sibling_id"], "web_lm3_ips")
        self.assertEqual(sorted(web["ips_sibling_mapped"]), ["10.8.0.101", "10.8.1.5"])
        self.assertEqual((run / "maps/nsx-lm3.csv").read_text(),
                         "old_subnet,new_subnet\n10.6.0.0/16,10.8.0.0/16\n")
        self.assertIn("deploy/nsx-lm3/nsx-lm2/push_report", (run / "commands.txt").read_text())

    def test_source_cannot_be_a_site(self):
        cap = make_capture(self.d)
        rc = self.run_tool("old_subnet,nsx-lm1\n10.6.0.0/16,10.7.0.0/16\n", "--capture", str(cap))
        self.assertEqual(rc, 2)
        run = next((self.d / "out" / "nsx-x.lab.local").glob("2*"))
        self.assertIn("also a site column", (run / "report.md").read_text())


if __name__ == "__main__":
    unittest.main()
