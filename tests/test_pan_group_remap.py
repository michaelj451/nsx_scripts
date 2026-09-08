#!/usr/bin/env python3
"""
tests/test_pan_group_remap.py

Offline tests for the PAN group remap analysis, including parity tests that
run the NSX remap engine and the PAN mirror against identical inputs so the
duplicated primitives cannot drift.

    python -m unittest tests/test_pan_group_remap.py -v
"""

from __future__ import annotations

import logging
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "app") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "app"))

logging.disable(logging.CRITICAL)

from palo import pan_group_remap as pan  # noqa: E402

CSV_TEXT = "old_subnet,new_subnet\n10.6.0.0/24,10.7.0.0/24\n10.1.1.0/24,10.11.1.0/24\n"


def load_maps(text: str = CSV_TEXT):
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
        f.write(text)
        path = Path(f.name)
    try:
        return pan.read_csv_mappings(path)
    finally:
        path.unlink()


def addr(name, **fields):
    return {"@name": name, **fields}


def group(name, members):
    return {"@name": name, "static": {"member": members}}


class TestCsv(unittest.TestCase):
    def test_headers_required(self):
        with self.assertRaises(pan.PanRemapError):
            load_maps("a,b\n1,2\n")

    def test_version_mismatch_rejected(self):
        with self.assertRaises(pan.PanRemapError):
            load_maps("old_subnet,new_subnet\n10.0.0.0/24,2001:db8::/64\n")

    def test_longest_prefix_sorted_first(self):
        maps = load_maps("old_subnet,new_subnet\n10.0.0.0/8,10.100.0.0/8\n10.0.1.0/24,10.200.1.0/24\n")
        self.assertEqual(str(maps[0].old), "10.0.1.0/24")


class TestRemapToken(unittest.TestCase):
    def setUp(self):
        self.maps = load_maps()

    def test_host_returns_slash32_form(self):
        # Engine parity: a bare IP parses as a /32 network, so the raw remap
        # yields the /32 form. analyze_groups() restores the source's form.
        self.assertEqual(pan.remap_token("10.6.0.50", self.maps), "10.7.0.50/32")

    def test_slash32(self):
        self.assertEqual(pan.remap_token("10.6.0.50/32", self.maps), "10.7.0.50/32")

    def test_exact_subnet(self):
        self.assertEqual(pan.remap_token("10.6.0.0/24", self.maps), "10.7.0.0/24")

    def test_sub_subnet_offset(self):
        maps = load_maps("old_subnet,new_subnet\n10.6.0.0/16,10.7.0.0/16\n")
        self.assertEqual(pan.remap_token("10.6.5.0/24", maps), "10.7.5.0/24")

    def test_unmapped_unchanged(self):
        self.assertEqual(pan.remap_token("192.168.1.1", self.maps), "192.168.1.1")

    def test_range_within_one_map(self):
        self.assertEqual(pan.remap_token("10.6.0.5-10.6.0.20", self.maps), "10.7.0.5-10.7.0.20")

    def test_range_spanning_maps_unchanged(self):
        token = "10.6.0.5-10.1.1.20"
        self.assertEqual(pan.remap_token(token, self.maps), token)


class TestParityWithNsxEngine(unittest.TestCase):
    """The PAN primitives must produce byte-identical results to the NSX
    engine for the same CSV and tokens."""

    @classmethod
    def setUpClass(cls):
        from nsx.nsx_object_functions import nsx_group_remap as nsx
        cls.nsx = nsx
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
            f.write(CSV_TEXT)
            cls.csv_path = Path(f.name)
        cls.nsx_maps = nsx.read_csv_mappings(cls.csv_path)
        cls.pan_maps = pan.read_csv_mappings(cls.csv_path)

    @classmethod
    def tearDownClass(cls):
        cls.csv_path.unlink()

    TOKENS = [
        "10.6.0.50", "10.6.0.50/32", "10.6.0.0/24", "10.6.0.128/25",
        "10.1.1.7", "192.168.9.9", "10.6.0.5-10.6.0.20", "10.6.0.5-10.1.1.9",
        "not-an-ip", "10.1.1.0/24",
        # "2001:db8::1" deliberately absent: the NSX engine raises TypeError
        # on an IPv6 token vs a v4 map (subnet_of); the PAN mirror guards it.
    ]

    def test_ipv6_guard_is_a_known_divergence(self):
        self.assertEqual(pan.remap_token("2001:db8::1", self.pan_maps), "2001:db8::1")
        with self.assertRaises(TypeError):
            self.nsx.remap_token("2001:db8::1", self.nsx_maps)

    def test_remap_token_parity(self):
        for t in self.TOKENS:
            self.assertEqual(pan.remap_token(t, self.pan_maps),
                             self.nsx.remap_token(t, self.nsx_maps), t)

    def test_classify_parity(self):
        for t in self.TOKENS:
            self.assertEqual(pan.classify_token(t), self.nsx._classify_token(t), t)

    def test_range_analysis_parity(self):
        for t in ("10.6.0.5-10.6.0.20", "10.6.0.5-10.1.1.9", "10.6.0.5-192.168.1.1"):
            self.assertEqual(pan.analyze_range_token(t, self.pan_maps),
                             self.nsx._analyze_range_token(t, self.nsx_maps), t)


class TestAnalyzeGroups(unittest.TestCase):
    def setUp(self):
        self.maps = load_maps()
        self.addresses = [
            addr("h-10.6.0.50", **{"ip-netmask": "10.6.0.50"}),
            addr("h-10.7.0.50", **{"ip-netmask": "10.7.0.50"}),
            addr("n-10.1.1.0-24", **{"ip-netmask": "10.1.1.0/24"}),
            addr("n-10.11.1.0-24", **{"ip-netmask": "10.11.1.0/24"}),
            addr("r-10.6.0.5-20", **{"ip-range": "10.6.0.5-10.6.0.20"}),
            addr("fq-example", fqdn="example.lab.local"),
            addr("v6-host", **{"ip-netmask": "2001:db8::5"}),
            addr("h-unmapped", **{"ip-netmask": "192.168.1.1"}),
        ]

    def analyze(self, groups):
        return pan.analyze_groups(groups, self.addresses, self.maps, scope="shared")

    def one(self, groups):
        return self.analyze(groups)["groups"][0]

    def test_would_add_with_existing_object_reused(self):
        g = self.one([group("g", ["n-10.1.1.0-24"])])
        self.assertEqual(len(g["would_add"]), 1)
        item = g["would_add"][0]
        self.assertEqual(item["mapped_value"], "10.11.1.0/24")
        self.assertEqual(item["existing_object"], "n-10.11.1.0-24")
        self.assertIsNone(item["suggested_name"])

    def test_would_add_with_create_suggestion(self):
        addresses = [a for a in self.addresses if a["@name"] != "h-10.7.0.50"]
        res = pan.analyze_groups([group("g", ["h-10.6.0.50"])], addresses, self.maps,
                                 scope="shared")["groups"][0]
        item = res["would_add"][0]
        self.assertIsNone(item["existing_object"])
        self.assertEqual(item["suggested_name"], "h-10.7.0.50")

    def test_already_remapped_pair_detected(self):
        g = self.one([group("g", ["h-10.6.0.50", "h-10.7.0.50"])])
        self.assertEqual(g["would_add"], [])
        self.assertEqual(len(g["already_remapped"]), 1)
        self.assertEqual(g["already_remapped"][0]["mapped_member"], "h-10.7.0.50")

    def test_range_reported_not_remapped(self):
        g = self.one([group("g", ["r-10.6.0.5-20"])])
        self.assertEqual(g["would_add"], [])
        self.assertEqual(g["ranges"][0]["status"], "mapped")
        self.assertEqual(g["ranges"][0]["proposed_change"], "10.7.0.5-10.7.0.20")

    def test_fqdn_and_ipv6_never_remapped(self):
        g = self.one([group("g", ["fq-example", "v6-host"])])
        reasons = sorted(i["reason"] for i in g["never_remapped"])
        self.assertEqual(reasons, ["fqdn", "ipv6"])

    def test_dynamic_group_never_remapped(self):
        g = self.one([{"@name": "dyn", "dynamic": {"filter": "'tag1'"}}])
        self.assertEqual(g["never_remapped"][0]["reason"], "dynamic_group")

    def test_nested_and_unresolved_members(self):
        res = self.analyze([group("outer", ["inner", "ghost"]), group("inner", [])])
        outer = res["groups"][0]
        self.assertEqual(outer["nested_groups"], ["inner"])
        self.assertEqual(outer["unresolved"], ["ghost"])

    def test_single_member_string_tolerated(self):
        g = self.one([{"@name": "g", "static": {"member": "h-10.6.0.50"}}])
        self.assertEqual(len(g["would_add"]), 1)

    def test_unmapped_member_untouched(self):
        g = self.one([group("g", ["h-unmapped"])])
        self.assertEqual(g["would_add"], [])
        self.assertEqual(g["already_remapped"], [])


def rule(name, source, destination):
    return {"@name": name, "source": {"member": source},
            "destination": {"member": destination}}


class TestAnalyzeRules(unittest.TestCase):
    def setUp(self):
        self.maps = load_maps()
        self.addresses = [
            addr("h-10.6.0.50", **{"ip-netmask": "10.6.0.50"}),
            addr("h-10.7.0.50", **{"ip-netmask": "10.7.0.50"}),
            addr("r-10.6.0.5-20", **{"ip-range": "10.6.0.5-10.6.0.20"}),
            addr("fq-example", fqdn="example.lab.local"),
        ]
        self.groups = [group("app-grp", ["h-10.6.0.50"])]

    def analyze(self, rules):
        return pan.analyze_rules(rules, self.addresses, self.groups, self.maps,
                                 scope="dg-4", rulebase="pre")

    def one(self, rules):
        return self.analyze(rules)["rules"][0]

    def test_object_member_would_add_with_reuse(self):
        r = self.one([rule("r1", ["h-10.6.0.50"], ["any"])])
        item = r["would_add"][0]
        self.assertEqual((item["side"], item["kind"]), ("source", "object"))
        self.assertEqual(item["mapped_value"], "10.7.0.50")
        self.assertEqual(item["existing_object"], "h-10.7.0.50")

    def test_literal_member_would_add(self):
        r = self.one([rule("r1", ["any"], ["10.6.0.99"])])
        item = r["would_add"][0]
        self.assertEqual((item["side"], item["kind"]), ("destination", "literal"))
        self.assertEqual(item["mapped_value"], "10.7.0.99")
        self.assertIsNone(item["suggested_name"])

    def test_literal_cidr_member(self):
        r = self.one([rule("r1", ["10.6.0.0/24"], ["any"])])
        self.assertEqual(r["would_add"][0]["mapped_value"], "10.7.0.0/24")

    def test_group_reference_recorded_not_analyzed(self):
        r = self.one([rule("r1", ["app-grp"], ["any"])])
        self.assertEqual(r["would_add"], [])
        self.assertEqual(r["group_refs"], [{"side": "source", "group": "app-grp"}])

    def test_any_skipped_and_quiet_rules_dropped(self):
        res = self.analyze([rule("r1", ["any"], ["any"]),
                            rule("r2", ["h-10.6.0.50"], ["any"])])
        self.assertEqual([r["rule"] for r in res["rules"]], ["r2"])

    def test_already_remapped_on_same_side(self):
        r = self.one([rule("r1", ["h-10.6.0.50", "h-10.7.0.50"], ["any"])])
        self.assertEqual(r["would_add"], [])
        self.assertEqual(r["already_remapped"][0]["mapped_member"], "h-10.7.0.50")

    def test_range_object_and_literal_range_reported(self):
        r = self.one([rule("r1", ["r-10.6.0.5-20"], ["10.6.0.30-10.6.0.40"])])
        self.assertEqual(len(r["ranges"]), 2)
        self.assertEqual({x["status"] for x in r["ranges"]}, {"mapped"})
        self.assertEqual(r["would_add"], [])

    def test_fqdn_never_remapped_and_unresolved(self):
        r = self.one([rule("r1", ["fq-example"], ["mystery-object"])])
        self.assertEqual(r["never_remapped"][0]["reason"], "fqdn")
        self.assertEqual(r["unresolved"], [{"side": "destination", "member": "mystery-object"}])

    def test_values_seen_include_literals_and_objects(self):
        res = self.analyze([rule("r1", ["h-10.6.0.50"], ["10.6.0.99"])])
        self.assertIn("10.6.0.50", res["values_seen"])
        self.assertIn("10.6.0.99", res["values_seen"])


class TestAggregation(unittest.TestCase):
    def setUp(self):
        self.maps = load_maps()
        self.addresses = [addr("h-10.6.0.50", **{"ip-netmask": "10.6.0.50"})]
        self.locations = {"h-10.6.0.50": "shared"}

    def test_shared_object_in_many_places_is_one_action(self):
        g_scope = pan.analyze_groups([group("g1", ["h-10.6.0.50"])],
                                     self.addresses, self.maps, scope="dg-4")
        rules = [rule("r1", ["h-10.6.0.50"], ["any"]),
                 rule("r2", ["any"], ["h-10.6.0.50"])]
        r_shared = pan.analyze_rules(rules, self.addresses, [], self.maps,
                                     scope="shared", rulebase="pre")
        r_dg = pan.analyze_rules(rules, self.addresses, [], self.maps,
                                 scope="dg-3", rulebase="post")
        agg = pan.aggregate_report_items([g_scope], [r_shared, r_dg], self.locations)
        self.assertEqual(len(agg["object_actions"]), 1)
        action = agg["object_actions"][0]
        self.assertEqual(action["location"], "shared")
        self.assertEqual(len(action["refs"]), 5)  # 1 group + 4 rule sides
        summary = pan.summarize_refs(action["refs"])
        self.assertIn("1 group (g1 [dg-4])", summary)
        self.assertIn("shared/pre 2", summary)
        self.assertIn("dg-3/post 2", summary)

    def test_literals_stay_per_rule(self):
        rules = [rule("r1", ["10.6.0.99"], ["any"]),
                 rule("r2", ["10.6.0.99"], ["any"])]
        rs = pan.analyze_rules(rules, [], [], self.maps, scope="dg-4", rulebase="pre")
        agg = pan.aggregate_report_items([], [rs], {})
        self.assertEqual(agg["object_actions"], [])
        self.assertEqual([i["rule"] for i in agg["literal_adds"]], ["r1", "r2"])

    def test_ranges_deduped_with_refs(self):
        addresses = [addr("r-6", **{"ip-range": "10.6.0.5-10.6.0.20"})]
        g1 = pan.analyze_groups([group("g1", ["r-6"]), group("g2", ["r-6"])],
                                addresses, self.maps, scope="shared")
        agg = pan.aggregate_report_items([g1], [], {"r-6": "shared"})
        self.assertEqual(len(agg["ranges"]), 1)
        self.assertEqual(len(agg["ranges"][0]["refs"]), 2)


class TestFlattenUpdates(unittest.TestCase):
    def test_per_target_rows_with_reasons(self):
        maps = load_maps()
        addresses = [addr("h-10.6.0.50", **{"ip-netmask": "10.6.0.50"}),
                     addr("h-10.7.0.50", **{"ip-netmask": "10.7.0.50"})]
        g = pan.analyze_groups([group("g1", ["h-10.6.0.50"])], addresses, maps, scope="dg-4")
        rs = pan.analyze_rules([rule("r1", ["h-10.6.0.50", "10.6.0.99"], ["any"])],
                               addresses, [], maps, scope="shared", rulebase="pre")
        agg = pan.aggregate_report_items([g], [rs], {"h-10.6.0.50": "shared"})
        updates = pan.flatten_updates(agg)
        self.assertEqual(len(updates), 2)  # the group, and r1 source
        by_name = {u["name"]: u for u in updates}
        self.assertEqual(by_name["g1"]["adds"],
                         [{"add": "h-10.7.0.50", "for": "h-10.6.0.50"}])
        r1 = by_name["r1"]
        self.assertEqual((r1["kind"], r1["side"]), ("rule", "source"))
        self.assertEqual(r1["adds"], [
            {"add": "h-10.7.0.50", "for": "h-10.6.0.50"},
            {"add": "10.7.0.99", "for": "literal 10.6.0.99"},
        ])

    def test_groups_sort_before_rules_and_shared_first(self):
        maps = load_maps()
        addresses = [addr("h-10.6.0.50", **{"ip-netmask": "10.6.0.50"})]
        g = pan.analyze_groups([group("zz-group", ["h-10.6.0.50"])], addresses, maps,
                               scope="shared")
        rs_dg = pan.analyze_rules([rule("a-rule", ["h-10.6.0.50"], ["any"])],
                                  addresses, [], maps, scope="dg-3", rulebase="pre")
        rs_sh = pan.analyze_rules([rule("b-rule", ["h-10.6.0.50"], ["any"])],
                                  addresses, [], maps, scope="shared", rulebase="post")
        agg = pan.aggregate_report_items([g], [rs_dg, rs_sh], {"h-10.6.0.50": "shared"})
        names = [u["name"] for u in pan.flatten_updates(agg)]
        self.assertEqual(names, ["zz-group", "b-rule", "a-rule"])


class TestCsvCoverage(unittest.TestCase):
    def test_matches_and_gaps(self):
        maps = load_maps()
        cov = pan.csv_coverage(maps, ["10.6.0.50", "10.6.0.5-10.6.0.20", "192.168.1.1"])
        by_old = {c["old_subnet"]: c for c in cov}
        self.assertEqual(by_old["10.6.0.0/24"]["matches"], 2)
        self.assertEqual(by_old["10.1.1.0/24"]["matches"], 0)


class TestSuggestName(unittest.TestCase):
    def test_value_derived_name(self):
        self.assertEqual(pan.suggest_object_name("n-10.1.1.0-24", "10.1.1.0/24", "10.11.1.0/24"),
                         "n-10.11.1.0-24")

    def test_fallback_appends_value(self):
        self.assertEqual(pan.suggest_object_name("web-server", "10.6.0.50", "10.7.0.50"),
                         "web-server--10.7.0.50")


if __name__ == "__main__":
    unittest.main()
