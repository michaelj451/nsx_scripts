#!/usr/bin/env python3
"""
tests/test_ip_remap_audit.py

Offline tests for tools/nsx/audit_ip_remap.py. No NSX calls.

    python -m unittest tests/test_ip_remap_audit.py -v
"""

from __future__ import annotations

import importlib.util
import logging
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
for p in (REPO_ROOT / "app", REPO_ROOT / "tools" / "nsx"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

logging.disable(logging.CRITICAL)

from nsx_group_ip_remap_offline import _load_mapping_csv  # noqa: E402


def _load_audit():
    spec = importlib.util.spec_from_file_location("audit_ip_remap", REPO_ROOT / "tools" / "nsx" / "audit_ip_remap.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


audit = _load_audit()

CSV = "old_subnet,new_subnet\n10.6.0.101/32,10.7.0.101/32\n10.6.1.0/24,10.7.1.0/24\n10.6.0.0/16,10.7.0.0/16\n"
EM_DASH = chr(0x2014)   # generated reports must never contain this character


def _tables():
    d = Path(tempfile.mkdtemp())
    csv = d / "m.csv"
    csv.write_text(CSV)
    fwd, invalid = _load_mapping_csv(csv, False)
    return fwd, audit.reverse_table(fwd), invalid, csv


def _group(gid, expression):
    return {"id": gid, "display_name": gid, "expression": expression}


def _ipx(*ips):
    return {"resource_type": "IPAddressExpression", "ip_addresses": list(ips)}


def _ip_only(gid, expression):
    """An IP-Addresses-Only group (group_type IPAddress)."""
    g = _group(gid, expression)
    g["group_type"] = ["IPAddress"]
    return g


class WalkTests(unittest.TestCase):
    def test_walks_top_level_and_nested(self):
        expr = [
            _ipx("10.0.0.1"),
            {"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"},
            {"resource_type": "NestedExpression", "expressions": [
                {"resource_type": "Condition", "key": "Tag"},
                _ipx("10.0.0.2", "10.0.0.3"),
            ]},
        ]
        got = list(audit.walk_ip_entries(expr))
        self.assertEqual(got, [
            ("10.0.0.1", "expression[0]"),
            ("10.0.0.2", "expression[2].expressions[1]"),
            ("10.0.0.3", "expression[2].expressions[1]"),
        ])


class AuditGroupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fwd, cls.rev, cls.invalid, cls.csv = _tables()
        assert cls.invalid == []

    def test_fully_mapped_group(self):
        r = audit.audit_group(_group("g", [_ipx("10.6.0.101", "10.7.0.101", "10.6.1.0/24", "10.7.1.0/24")]), self.fwd, self.rev)
        self.assertEqual(r["status"], "mapped")
        self.assertEqual([(m["original"], m["mapped"]) for m in r["mapped_pairs"]],
                         [("10.6.0.101", "10.7.0.101"), ("10.6.1.0/24", "10.7.1.0/24")])
        self.assertEqual(r["gaps_missing_mapped"], [])
        self.assertEqual(r["orphan_mapped_values"], [])

    def test_missing_mapped_in_ip_only_group_is_a_gap(self):
        r = audit.audit_group(_ip_only("g", [_ipx("10.6.0.101", "10.6.5.5")]), self.fwd, self.rev)
        self.assertEqual(r["status"], "gap")
        self.assertEqual([(g["original"], g["expected_mapped"]) for g in r["gaps_missing_mapped"]],
                         [("10.6.0.101", "10.7.0.101"), ("10.6.5.5", "10.7.5.5")])
        self.assertEqual(r["generic_remap_candidates"], [])

    def test_missing_mapped_in_generic_group_is_candidate_by_default(self):
        """Mirrors the push default: generic groups are not remapped, so a
        CSV-covered original there is informational, not a gap."""
        r = audit.audit_group(_group("g", [_ipx("10.6.0.101")]), self.fwd, self.rev)
        self.assertEqual(r["status"], "candidate")
        self.assertEqual(r["gaps_missing_mapped"], [])
        self.assertEqual([(c["original"], c["expected_mapped"]) for c in r["generic_remap_candidates"]],
                         [("10.6.0.101", "10.7.0.101")])

    def test_include_generic_promotes_candidates_to_gaps(self):
        r = audit.audit_group(_group("g", [_ipx("10.6.0.101")]), self.fwd, self.rev, include_generic=True)
        self.assertEqual(r["status"], "gap")
        self.assertEqual(r["generic_remap_candidates"], [])
        self.assertEqual(r["gaps_missing_mapped"][0]["expected_mapped"], "10.7.0.101")

    def test_format_difference_is_not_a_gap(self):
        """/32 on one side, bare IP on the other: still a pair."""
        r = audit.audit_group(_group("g", [_ipx("10.6.0.101/32", "10.7.0.101")]), self.fwd, self.rev)
        self.assertEqual(r["status"], "mapped")
        self.assertEqual(len(r["mapped_pairs"]), 1)

    def test_mapped_side_without_original_is_review_not_gap_list(self):
        r = audit.audit_group(_group("g", [_ipx("10.7.0.55")]), self.fwd, self.rev)
        self.assertEqual(r["status"], "gap")
        self.assertEqual(r["gaps_missing_mapped"], [])
        self.assertEqual(r["orphan_mapped_values"][0]["present_value"], "10.7.0.55")
        self.assertEqual(r["orphan_mapped_values"][0]["expected_original"], "10.6.0.55")

    def test_uncovered_ranges_ipv6_and_junk(self):
        r = audit.audit_group(_group("g", [_ipx("192.168.1.1", "10.6.0.52-10.6.0.53", "2001:db8::1", "bogus")]), self.fwd, self.rev)
        self.assertEqual(r["status"], "no_csv_match")
        self.assertEqual([u["value"] for u in r["uncovered_ipv4"]], ["192.168.1.1"])
        self.assertEqual({(b["value"], b["reason"]) for b in r["not_remapped_by_design"]},
                         {("10.6.0.52-10.6.0.53", "range"), ("2001:db8::1", "ipv6")})
        self.assertEqual([x["value"] for x in r["invalid_entries"]], ["bogus"])

    def test_nested_ips_are_audited_and_flagged(self):
        g = _group("g", [
            {"resource_type": "NestedExpression", "expressions": [_ipx("10.6.0.101")]},
        ])
        r = audit.audit_group(g, self.fwd, self.rev)
        self.assertTrue(r["has_nested_ips"])
        self.assertEqual(r["status"], "candidate")   # nested bodies only occur in generic groups
        self.assertEqual(r["generic_remap_candidates"][0]["location"], "expression[0].expressions[0]")
        r2 = audit.audit_group(g, self.fwd, self.rev, include_generic=True)
        self.assertEqual(r2["status"], "gap")
        self.assertEqual(r2["gaps_missing_mapped"][0]["location"], "expression[0].expressions[0]")

    def test_group_without_ips(self):
        r = audit.audit_group(_group("g", [{"resource_type": "Condition", "key": "Tag"}]), self.fwd, self.rev)
        self.assertEqual(r["status"], "no_ips")
        self.assertEqual(r["entry_count"], 0)

    def test_group_type_classification(self):
        """group_type ["IPAddress"] = IP-Addresses-Only group; anything else generic."""
        ip_only = _group("g", [_ipx("10.6.0.101")])
        ip_only["group_type"] = ["IPAddress"]
        self.assertEqual(audit.audit_group(ip_only, self.fwd, self.rev)["group_type"], "ip-only")
        self.assertEqual(audit.audit_group(_group("g", [_ipx("10.6.0.101")]), self.fwd, self.rev)["group_type"], "generic")
        empty_type = _group("g", [])
        empty_type["group_type"] = []
        self.assertEqual(audit.audit_group(empty_type, self.fwd, self.rev)["group_type"], "generic")

    def test_summary_and_has_gaps(self):
        rows = audit.audit_groups({
            "a": _group("a", [_ipx("10.6.0.101", "10.7.0.101")]),   # generic, fully mapped
            "b": _ip_only("b", [_ipx("10.6.9.9")]),                  # ip-only miss = gap
            "c": _group("c", [_ipx("10.6.8.8")]),                    # generic miss = candidate
            "d": _group("d", []),
        }, self.fwd, self.rev)
        s = audit.summarize(rows)
        self.assertEqual(s["groups_total"], 4)
        self.assertEqual(s["groups_with_ip_entries"], 3)
        self.assertEqual(s["groups_ip_only"], 1)
        self.assertEqual(s["mapped_pairs"], 1)
        self.assertEqual(s["gaps_missing_mapped"], 1)
        self.assertEqual(s["generic_remap_candidates"], 1)
        self.assertEqual(s["generic_candidate_groups"], 1)
        self.assertTrue(audit.has_gaps(s))
        # Candidates alone never trip the gap exit
        only_candidates = audit.summarize(audit.audit_groups(
            {"c": _group("c", [_ipx("10.6.8.8")])}, self.fwd, self.rev))
        self.assertFalse(audit.has_gaps(only_candidates))
        clean = audit.summarize(audit.audit_groups({"a": _group("a", [_ipx("10.6.0.101", "10.7.0.101")])}, self.fwd, self.rev))
        self.assertFalse(audit.has_gaps(clean))


class RenderAndLoadTests(unittest.TestCase):
    def test_load_groups_from_dir_skips_system_and_manifest(self):
        d = Path(tempfile.mkdtemp())
        (d / "a.yaml").write_text(yaml.safe_dump(_group("a", [_ipx("10.6.0.101")])))
        (d / "sys.yaml").write_text(yaml.safe_dump({"id": "sys", "_system_owned": True, "expression": []}))
        (d / "manifest.json").write_text("{}")
        (d / "nested").mkdir()
        (d / "nested" / "b.json").write_text('{"id": "b", "expression": []}')
        groups = audit.load_groups_from_dir(d)
        self.assertEqual(sorted(groups), ["a", "b"])

    def test_render_markdown_sections_in_order(self):
        fwd, rev, invalid, csv = _tables()
        rows = audit.audit_groups({
            "ok": _group("ok", [_ipx("10.6.0.101", "10.7.0.101")]),
            "gap": _ip_only("gap", [_ipx("10.6.1.5", "10.6.0.52-10.6.0.53", "8.8.8.8")]),
            "cand": _group("cand", [_ipx("10.6.2.9")]),
        }, fwd, rev)
        md = audit.render_markdown(rows, audit.summarize(rows), label="lab", source_desc="test",
                                   domain_id="default", csv_path=csv, csv_rows=len(fwd.rows), csv_invalid=invalid)
        order = [md.index(h) for h in ("## 1. Gaps", "### 1a.", "### 1b.", "### 1c.", "### 1d.", "## 2. Mapped",
                                       "## 3. Not remapped by design", "## 4. Per-group status")]
        self.assertEqual(order, sorted(order))
        self.assertIn("GAPS FOUND", md)
        self.assertIn("`10.6.1.5`", md)
        self.assertIn("`10.7.1.5`", md)           # expected mapped value shown in 1a
        self.assertIn("Would map to", md)         # candidate table in 1b
        self.assertIn("`10.6.2.9`", md)           # generic candidate original
        self.assertIn("`10.7.2.9`", md)           # what --remap-generic would add
        self.assertIn("`8.8.8.8`", md)            # uncovered in 1d
        self.assertIn("10.6.0.52-10.6.0.53", md)  # by design in 3
        self.assertNotIn(EM_DASH, md)

    def test_render_shows_display_name_when_it_differs(self):
        fwd, rev, invalid, csv = _tables()
        g = _group("a8b5ed22-0000", [_ipx("10.6.0.101")])
        g["display_name"] = "friendly-name"
        rows = audit.audit_groups({"a8b5ed22-0000": g}, fwd, rev)
        md = audit.render_markdown(rows, audit.summarize(rows), label="lab", source_desc="test",
                                   domain_id="default", csv_path=csv, csv_rows=len(fwd.rows), csv_invalid=invalid)
        self.assertIn("friendly-name (`a8b5ed22-0000`)", md)

    def test_render_clean(self):
        fwd, rev, invalid, csv = _tables()
        rows = audit.audit_groups({"ok": _group("ok", [_ipx("10.6.0.101", "10.7.0.101")])}, fwd, rev)
        md = audit.render_markdown(rows, audit.summarize(rows), label="lab", source_desc="test",
                                   domain_id="default", csv_path=csv, csv_rows=len(fwd.rows), csv_invalid=invalid)
        self.assertIn("CLEAN", md)


if __name__ == "__main__":
    unittest.main()
