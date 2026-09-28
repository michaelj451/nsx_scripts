"""WF-D as agreed on 2026-09-26:

1. Every group rules can use gets an AVS sibling holding the CSV-MAPPED IPs of
   its current members: tag groups, IP-only groups and groups that nest other
   groups alike. Hand-typed IPs are not copied; they stay on the original.
2. D3 adds each sibling next to its original in the rules, and only siblings
   the target actually holds.
3. No empty siblings: no members, or nothing mapped, means no group.
Segment-based groups are skipped.
"""
import contextlib
import copy
import importlib.util
import itertools
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
sys.path.insert(0, str(ROOT / "tools/nsx"))


def load(name):
    spec = importlib.util.spec_from_file_location(f"wfd_test_{name}", ROOT / f"tools/nsx/{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bsg = load("build_sibling_groups")
rules = load("rules")
report = load("report_avs_run")
from nsx_group_ip_remap_offline import _load_mapping_csv  # noqa: E402

TAG = {"resource_type": "Condition", "member_type": "VirtualMachine", "key": "Tag",
       "operator": "EQUALS", "value": "0|web"}
OR = {"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"}


def ips(*a):
    return {"resource_type": "IPAddressExpression", "ip_addresses": list(a)}


def paths(*a):
    return {"resource_type": "PathExpression", "paths": list(a)}


def group(gid, *expr):
    return {"id": gid, "display_name": gid, "resource_type": "Group", "expression": list(expr)}


class BuildTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        csv = Path(cls._tmp.name) / "map.csv"
        csv.write_text("old_subnet,new_subnet\n10.6.0.0/16,10.16.0.0/16\n", encoding="utf-8")
        cls.mapping, invalid = _load_mapping_csv(csv, bidirectional=False)
        assert not invalid

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def split(self, g):
        return bsg.split_group(g, appendix="_avs", csv_mapping=self.mapping,
                               skip_segment_groups=True)

    def test_tag_group_gets_mapped_ips_only(self):
        sib, info = self.split(group("web", TAG, OR, ips("10.6.0.1", "10.50.20.20")))
        self.assertEqual(sib["id"], "web_avs")
        self.assertEqual(sib["expression"][0]["ip_addresses"], ["10.16.0.1"])
        self.assertEqual(info["ips_uncovered"], ["10.50.20.20"])
        self.assertEqual(info["ip_pairs"], [["10.6.0.1", ["10.16.0.1"]], ["10.50.20.20", []]])

    def test_ip_only_group_gets_a_sibling(self):
        sib, info = self.split(group("subnet", ips("10.6.1.0/24")))
        self.assertIsNotNone(sib, info.get("skip_reason"))
        self.assertEqual(sib["expression"][0]["ip_addresses"], ["10.16.1.0/24"])

    def test_group_nesting_other_groups_by_path_is_not_segment_based(self):
        g = group("nest", paths("/infra/domains/default/groups/a",
                                "/infra/domains/default/groups/b"), OR, ips("10.6.0.9"))
        sib, info = self.split(g)
        self.assertIsNotNone(sib, info.get("skip_reason"))
        self.assertEqual(sib["expression"][0]["ip_addresses"], ["10.16.0.9"])

    def test_segment_based_group_is_skipped(self):
        g = group("seg", paths("/infra/segments/web-seg"), OR, ips("10.6.0.9"))
        sib, info = self.split(g)
        self.assertIsNone(sib)
        self.assertEqual(info["skip_reason"], "segment_group")
        self.assertEqual(info["segment_paths"], ["/infra/segments/web-seg"])

    def test_nothing_mapped_means_no_group(self):
        sib, info = self.split(group("public", ips("8.8.8.8", "1.1.1.1")))
        self.assertIsNone(sib)
        self.assertEqual(info["skip_reason"], "no_mapped_ips")

    def test_no_members_means_no_group(self):
        sib, info = self.split(group("empty", TAG))
        self.assertIsNone(sib)
        self.assertEqual(info["skip_reason"], "empty_ips")

    def test_wf_c_without_csv_still_decomposes_tag_groups_only(self):
        sib, info = bsg.split_group(group("subnet", ips("10.6.1.0/24")), appendix="_np")
        self.assertIsNone(sib)
        self.assertEqual(info["skip_reason"], "no_condition")

    def test_build_records_every_group_without_a_sibling(self):
        tmp = Path(self._tmp.name)
        cap = tmp / "cap" / "nsx-x.lab.local"
        gdir = cap / "groups_additive" / "domains" / "default" / "groups"
        gdir.mkdir(parents=True)
        for g in (group("web", TAG, OR, ips("10.6.0.1")), group("public", ips("8.8.8.8")),
                  group("empty", TAG), group("seg", paths("/infra/segments/s1"))):
            (gdir / f"{g['id']}.yaml").write_text(json.dumps(g), encoding="utf-8")
        out = tmp / "out"
        argv = ["b", "--capture", str(cap), "--output-base", str(out), "--appendix", "_avs",
                "--csv-remap", str(tmp / "map.csv"), "--skip-segment-groups"]
        with patch.object(sys, "argv", argv), \
                patch.object(bsg, "nsx_log_dir", str(tmp / "logs")):
            self.assertEqual(bsg.main(), 0)
        smap = json.loads((out / "nsx_sibling_groups" / "nsx-x.lab.local" / "sibling_map.json")
                          .read_text())
        self.assertEqual([e["sibling_id"] for e in smap["map"]], ["web_avs"])
        self.assertEqual({e["original_id"]: e["reason_code"] for e in smap["no_sibling"]},
                         {"public": "no_mapped_ips", "empty": "empty_ips", "seg": "segment_group"})
        self.assertFalse((out / "nsx_pure_ip_remap").exists())


class AmendRefsGuardTests(unittest.TestCase):
    """D3 adds a sibling to a rule only if the target holds it."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def amend(self, *, apply, present):
        smap = self.root / "sibling_map.json"
        smap.write_text(json.dumps({"domain_id": "default", "map": [
            {"original_id": "web", "sibling_id": "web_avs"},
            {"original_id": "db", "sibling_id": "db_avs"}]}))
        g = "/infra/domains/default/groups/"
        rule = {"id": "r1", "display_name": "r1", "resource_type": "Rule",
                "source_groups": [g + "web"], "destination_groups": [g + "db"]}
        current = {"p1::r1": {"policy_id": "p1", "rule_id": "r1", "payload": rule}}
        patches, reports = [], self.root / "reports"

        class Client:
            def __init__(self, **kwargs):
                pass

            def list_groups(self, domain_id="default"):
                return [{"id": i} for i in ["web", "db"] + present]

            def patch_security_rule(self, **kwargs):
                patches.append(copy.deepcopy(kwargs))

            def __getattr__(self, method):
                raise AssertionError(f"Unexpected API call: {method}")

        def setup_logging(directory, label):
            directory.mkdir(parents=True, exist_ok=True)
            return directory / "test.log", directory / "errors.log"

        argv = ["rules", "amend-refs", "--target", "nsx-lm2", "--sibling-map", str(smap),
                "--reports-dir", str(reports)] + (["--apply"] if apply else [])
        with contextlib.ExitStack() as s:
            s.enter_context(patch.object(rules, "NsxPolicyClient", Client))
            s.enter_context(patch.object(rules, "_capture_target_rules",
                                         return_value=copy.deepcopy(current)))
            s.enter_context(patch.object(rules, "target_ref_names", return_value={}))
            s.enter_context(patch.object(rules, "_setup_logging", setup_logging))
            s.enter_context(patch.object(rules, "resolve_manager", return_value="lm2.test"))
            s.enter_context(patch.object(rules, "init_cli"))
            s.enter_context(patch.object(rules.time, "sleep"))
            s.enter_context(patch("builtins.input", side_effect=itertools.repeat("")))
            s.enter_context(patch.object(sys, "argv", argv))
            rc = rules.main()
        rows = json.loads((reports / "amend_refs.json").read_text())
        summary = json.loads((reports / "amend_refs_summary.json").read_text())
        return rc, rows, summary, patches

    def test_apply_adds_only_siblings_on_the_target(self):
        rc, rows, summary, patches = self.amend(apply=True, present=["web_avs"])
        self.assertEqual(rc, 0)
        self.assertEqual(summary["siblings_not_on_target"], ["db_avs"])
        self.assertEqual(len(patches), 1)
        sent = json.dumps(patches[0])
        self.assertIn("/groups/web_avs", sent)
        self.assertNotIn("/groups/db_avs", sent)

    def test_dry_run_previews_all_and_flags_missing(self):
        rc, rows, summary, patches = self.amend(apply=False, present=["web_avs"])
        self.assertEqual(rc, 0)
        self.assertEqual(patches, [])
        self.assertEqual(rows[0]["siblings_not_on_target"], ["db_avs"])
        added = [p for d in rows[0]["per_field_diff"].values() for p in d["added"]]
        self.assertTrue(any(p.endswith("/db_avs") for p in added))

    def test_all_present_flags_nothing(self):
        rc, rows, summary, patches = self.amend(apply=True, present=["web_avs", "db_avs"])
        self.assertEqual(summary["siblings_not_on_target"], [])
        self.assertEqual(len(patches), 1)


class ReportTests(unittest.TestCase):

    def test_d2a_layout_lists_groups_mappings_and_skips(self):
        rows = [{"kind": "group", "bucket": "planned", "verdict": "created", "id": "web_avs",
                 "display_name": "web_avs", "original_display_name": "web",
                 "ips_added": ["10.16.0.1"], "ips_after": ["10.16.0.1"],
                 "ip_pairs": [["10.6.0.1", ["10.16.0.1"]], ["10.50.20.20", []]]}]
        no_sib = [{"original_id": "public", "original_display_name": "public",
                   "reason": "no IP has a CSV mapping", "ips_source": ["8.8.8.8"]}]
        md = "\n".join(report.render_wf_d("WF-D2A DRYRUN", "**DRY RUN**", rows, no_sib, False))
        self.assertIn("| web            | web_avs   | would create |", md)
        self.assertIn("### web -> web_avs", md)
        self.assertIn("| `10.50.20.20` | no AVS mapping |", md)
        self.assertIn("## Groups with no AVS group", md)
        self.assertNotIn("DROPPED", md)
        self.assertNotIn("Appendix", md)

    def test_skipped_is_up_to_date_and_resent_is_not(self):
        skipped = {"kind": "group", "bucket": "unchanged", "id": "a_avs", "display_name": "a_avs",
                   "original_display_name": "a", "ips_after": ["10.16.0.1"], "ip_pairs": []}
        resent = {"kind": "group", "bucket": "planned", "verdict": "rewritten", "id": "b_avs",
                  "display_name": "b_avs", "original_display_name": "b", "ips_added": [],
                  "ips_after": ["10.16.0.2"], "ip_pairs": []}
        md = "\n".join(report.render_wf_d("WF-D2A DRYRUN", "**DRY RUN**", [skipped, resent], [], False))
        self.assertRegex(md, r"AVS groups already up to date \(nothing sent\)\s+\|\s+1\s")
        self.assertIn("would be re-sent, no IP change", md)
        self.assertRegex(md, r"AVS groups would be re-sent with no IP change\s+\|\s+\*\*1\*\*")

    def test_d3_layout_is_one_row_per_rule(self):
        g = "/infra/domains/default/groups/"
        rows = [{"kind": "rule-amend", "bucket": "planned", "display_name": "r1",
                 "policy_id": "p1", "refs_added_total": 1,
                 "per_field_diff": {"source_groups": {"added": [g + "web_avs"]}},
                 "siblings_not_on_target": ["web_avs"]}]
        md = "\n".join(report.render_wf_d("WF-D3 DRYRUN", "**DRY RUN**", rows, [], False))
        self.assertIn("## Rules to update", md)
        self.assertIn("None of the 1 AVS groups below exist on the target yet", md)
        self.assertNotIn("(not on target yet)*", md)


if __name__ == "__main__":
    unittest.main()
