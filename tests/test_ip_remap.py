#!/usr/bin/env python3
"""
tests/test_ip_remap.py

Offline unit tests for the NSX group IP remap path:
  - tools/nsx/nsx_group_ip_remap_offline.py  (PrefixMappingTable, _remap_group_payload)
  - tools/nsx/groups.py                        (_ip_diff, _extract_ip_entries, pushed-ids helpers)

No NSX calls. Run from the repo root:

    python -m unittest tests/test_ip_remap.py -v
"""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
for p in (REPO_ROOT / "app", REPO_ROOT / "tools" / "nsx"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

logging.disable(logging.CRITICAL)

import nsx_group_ip_remap_offline as remap  # noqa: E402


def _load_groups_module():
    spec = importlib.util.spec_from_file_location("groups", REPO_ROOT / "tools" / "nsx" / "groups.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


groups = _load_groups_module()

NONPROD_CSV = REPO_ROOT / "data" / "nonprod_map.csv"


def _csv(text: str) -> Path:
    d = Path(tempfile.mkdtemp())
    p = d / "map.csv"
    p.write_text(text, encoding="utf-8")
    return p


def _ip_group(*ips: str, gid: str = "g") -> dict:
    return {
        "id": gid,
        "display_name": gid,
        "expression": [{"resource_type": "IPAddressExpression", "ip_addresses": list(ips)}],
    }


class TokenKindTests(unittest.TestCase):
    def test_ipv4_forms_are_remappable(self):
        for tok in ("10.6.0.1", "10.6.0.1/32", "10.6.0.0/24", " 10.6.0.1 "):
            self.assertIsNone(remap._token_kind(tok), tok)

    def test_ranges_are_skipped(self):
        self.assertEqual(remap._token_kind("10.6.0.1-10.6.0.9"), remap.SKIP_RANGE)

    def test_ipv6_is_skipped(self):
        self.assertEqual(remap._token_kind("2001:db8::1"), remap.SKIP_IPV6)
        self.assertEqual(remap._token_kind("2001:db8::/64"), remap.SKIP_IPV6)

    def test_junk_is_invalid(self):
        for tok in ("", "abc", "10.6.0.256", "10.6.0.0/33"):
            self.assertEqual(remap._token_kind(tok), remap.SKIP_INVALID, tok)


class MappingTableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.table, cls.invalid = remap._load_mapping_csv(NONPROD_CSV, bidirectional=False)

    def test_lab_csv_loads_clean(self):
        """data/nonprod_map.csv is live lab data the operator edits; assert it
        parses clean, not that it has any particular number of rows."""
        self.assertEqual(self.invalid, [])
        self.assertGreater(len(self.table.rows), 0)

    def test_longest_prefix_wins(self):
        mapped, row = self.table.map_token("10.6.0.101")
        self.assertEqual(mapped, ["10.7.0.101"])
        self.assertEqual(row["source"], "10.6.0.101")   # the /32 row, not the /24 or /16

    def test_host_form_is_preserved(self):
        self.assertEqual(self.table.map_token("10.6.0.101/32")[0], ["10.7.0.101/32"])
        self.assertEqual(self.table.map_token("10.6.0.101")[0], ["10.7.0.101"])

    def test_cidr_maps_by_offset(self):
        self.assertEqual(self.table.map_token("10.6.2.64/26")[0], ["10.7.2.64/26"])
        self.assertEqual(self.table.map_token("10.6.0.0/24")[0], ["10.7.0.0/24"])

    def test_supernet_of_every_row_does_not_map(self):
        self.assertEqual(self.table.map_token("10.6.0.0/15")[0], [])

    def test_range_never_maps_and_never_raises(self):
        self.assertEqual(self.table.map_token("10.6.0.52-10.6.0.53"), ([], None))

    def test_ipv6_never_maps_and_never_raises(self):
        self.assertEqual(self.table.map_token("2001:db8::1"), ([], None))
        self.assertEqual(self.table.map_token("2001:db8::/64"), ([], None))

    def test_junk_never_raises(self):
        self.assertEqual(self.table.map_token("abc"), ([], None))
        self.assertEqual(self.table.map_token("10.6.0.256"), ([], None))

    def test_bidirectional_maps_both_ways(self):
        table, _ = remap._load_mapping_csv(NONPROD_CSV, bidirectional=True)
        self.assertEqual(table.map_token("10.6.0.101")[0], ["10.7.0.101"])
        self.assertEqual(table.map_token("10.7.0.101")[0], ["10.6.0.101"])


class MappingCsvValidationTests(unittest.TestCase):
    def test_range_rows_are_rejected_with_reason(self):
        _, invalid = remap._load_mapping_csv(_csv(
            "old_subnet,new_subnet\n192.168.1.10-192.168.1.20,192.168.2.10-192.168.2.20\n"), False)
        self.assertEqual(len(invalid), 1)
        self.assertIn("range", invalid[0]["reason"])

    def test_ipv6_rows_are_rejected_with_reason(self):
        _, invalid = remap._load_mapping_csv(_csv("old_subnet,new_subnet\n2001:db8::/32,2001:db9::/32\n"), False)
        self.assertEqual(len(invalid), 1)
        self.assertIn("IPv6", invalid[0]["reason"])

    def test_destination_smaller_than_source_is_rejected(self):
        table, invalid = remap._load_mapping_csv(_csv("old_subnet,new_subnet\n10.9.0.0/24,10.10.0.0/25\n"), False)
        self.assertEqual(table.rows, [])
        self.assertEqual(len(invalid), 1)
        self.assertIn("smaller", invalid[0]["reason"])

    def test_destination_larger_than_source_is_allowed(self):
        table, invalid = remap._load_mapping_csv(_csv("old_subnet,new_subnet\n10.20.0.0/24,10.21.0.0/23\n"), False)
        self.assertEqual(invalid, [])
        self.assertEqual(table.map_token("10.20.0.5")[0], ["10.21.0.5"])

    def test_off_boundary_cidr_is_rejected_with_hint(self):
        """10.10.3.0/23 is not a valid /23 boundary; it silently means
        10.10.2.0/23, so the loader must refuse rather than guess."""
        _, invalid = remap._load_mapping_csv(_csv("old_subnet,new_subnet\n10.10.2.0/23,10.10.3.0/23\n"), False)
        self.assertEqual(len(invalid), 1)
        self.assertIn("boundary", invalid[0]["reason"])
        self.assertIn("10.10.2.0/23", invalid[0]["reason"])
        table, invalid = remap._load_mapping_csv(_csv("old_subnet,new_subnet\n10.10.2.0/24,10.10.3.0/24\n"), False)
        self.assertEqual(invalid, [])
        self.assertEqual(table.map_token("10.10.2.0/24")[0], ["10.10.3.0/24"])

    def test_duplicate_old_subnet_is_rejected_first_row_wins(self):
        table, invalid = remap._load_mapping_csv(_csv(
            "old_subnet,new_subnet\n10.6.0.0/24,10.8.0.0/24\n10.6.0.0/24,10.9.0.0/24\n"), False)
        self.assertEqual(len(invalid), 1)
        self.assertIn("duplicate", invalid[0]["reason"])
        self.assertEqual(table.map_token("10.6.0.5")[0], ["10.8.0.5"])

    def test_bom_whitespace_and_trailing_comma_tolerated(self):
        table, invalid = remap._load_mapping_csv(_csv(
            "﻿old_subnet,new_subnet\n10.4.2.0/24,10.14.2.0/24,\n10.250.0.0/16, 10.251.0.0/16\n"), False)
        self.assertEqual(invalid, [])
        self.assertEqual(table.map_token("10.4.2.5")[0], ["10.14.2.5"])
        self.assertEqual(table.map_token("10.250.1.1")[0], ["10.251.1.1"])


class RemapGroupPayloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.table, _ = remap._load_mapping_csv(NONPROD_CSV, bidirectional=False)

    def test_additive_keeps_originals_verbatim_and_appends(self):
        g = _ip_group("10.6.0.101/32", "10.6.1.0/24", "1.1.1.1")
        p, r = remap._remap_group_payload(g, self.table)
        self.assertEqual(r["status"], "changed")
        self.assertEqual(p["expression"][0]["ip_addresses"],
                         ["10.6.0.101/32", "10.6.1.0/24", "1.1.1.1", "10.7.0.101/32", "10.7.1.0/24"])
        self.assertEqual(r["added_values"], ["10.7.0.101/32", "10.7.1.0/24"])
        self.assertEqual(r["unmapped_values"], ["1.1.1.1"])

    def test_slash32_original_is_never_rewritten(self):
        """Regression: the old code canonicalized 10.6.0.101/32 to 10.6.0.101,
        which the push-side contract diff saw as a removal."""
        g = _ip_group("10.6.0.101/32")
        p, _ = remap._remap_group_payload(g, self.table)
        self.assertIn("10.6.0.101/32", p["expression"][0]["ip_addresses"])
        added, removed = groups._ip_diff(groups._extract_ip_entries(g), groups._extract_ip_entries(p))
        self.assertEqual(removed, [])
        self.assertEqual(added, ["10.7.0.101/32"])

    def test_range_and_ipv6_left_in_place_and_reported(self):
        g = _ip_group("10.6.0.101", "10.6.0.52-10.6.0.53", "2001:db8::10")
        p, r = remap._remap_group_payload(g, self.table)
        self.assertEqual(p["expression"][0]["ip_addresses"],
                         ["10.6.0.101", "10.6.0.52-10.6.0.53", "2001:db8::10", "10.7.0.101"])
        self.assertEqual(
            {(s["value"], s["reason"]) for s in r["skipped_values"]},
            {("10.6.0.52-10.6.0.53", remap.SKIP_RANGE), ("2001:db8::10", remap.SKIP_IPV6)},
        )

    def test_group_with_only_ranges_and_ipv6_is_unchanged(self):
        g = _ip_group("10.6.0.52-10.6.0.53", "2001:db8::10")
        p, r = remap._remap_group_payload(g, self.table)
        self.assertEqual(r["status"], "unchanged")
        self.assertEqual(p, g)

    def test_mapped_value_already_present_in_other_form_is_not_duplicated(self):
        g = _ip_group("10.6.0.101", "10.7.0.101/32")
        p, r = remap._remap_group_payload(g, self.table)
        self.assertEqual(r["status"], "unchanged")
        self.assertEqual(p["expression"][0]["ip_addresses"], ["10.6.0.101", "10.7.0.101/32"])

    def test_second_pass_is_idempotent(self):
        g = _ip_group("10.6.0.101", "10.6.1.0/24")
        p1, _ = remap._remap_group_payload(g, self.table)
        p2, r2 = remap._remap_group_payload(p1, self.table)
        self.assertEqual(r2["status"], "unchanged")
        self.assertEqual(p1, p2)

    def test_non_ip_expressions_are_untouched(self):
        g = {"id": "g", "expression": [
            {"resource_type": "PathExpression", "paths": ["/infra/segments/seg-1"]},
            {"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"},
            {"resource_type": "IPAddressExpression", "ip_addresses": ["10.6.0.101"]},
        ]}
        p, _ = remap._remap_group_payload(g, self.table)
        self.assertEqual(p["expression"][0], g["expression"][0])
        self.assertEqual(p["expression"][1], g["expression"][1])

    def test_mapped_only_replaces_with_mapped_values(self):
        g = _ip_group("10.6.0.101", "1.1.1.1")
        p, _ = remap._remap_group_payload(g, self.table, mapped_only=True)
        self.assertEqual(p["expression"][0]["ip_addresses"], ["10.7.0.101"])


class GroupsPushHelpersTests(unittest.TestCase):
    def test_ip_diff_ignores_format_only_differences(self):
        added, removed = groups._ip_diff(["10.6.0.1/32", "10.6.2.0/24"], ["10.6.0.1", "10.6.2.0/24"])
        self.assertEqual((added, removed), ([], []))

    def test_ip_diff_reports_real_changes_in_as_held_form(self):
        added, removed = groups._ip_diff(["10.6.0.1/32", "10.6.9.9"], ["10.6.0.1/32", "10.7.0.1"])
        self.assertEqual(added, ["10.7.0.1"])
        self.assertEqual(removed, ["10.6.9.9"])

    def test_extract_ip_entries_top_level_only(self):
        g = {"expression": [
            {"resource_type": "IPAddressExpression", "ip_addresses": ["10.0.0.1", "10.0.0.2"]},
            {"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"},
            {"resource_type": "IPAddressExpression", "ip_addresses": ["10.0.0.2", "10.0.0.3"]},
        ]}
        self.assertEqual(groups._extract_ip_entries(g), ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_pushed_ids_companion_file_round_trip(self):
        bdir = Path(tempfile.mkdtemp())
        baseline = bdir / "20260826_120000_target_baseline.json"
        baseline.write_text("{}", encoding="utf-8")
        pushed = groups._write_pushed_ids(baseline, ["a", "b"])
        self.assertEqual(pushed.name, "20260826_120000_pushed_ids.json")
        self.assertEqual(json.loads(pushed.read_text()), ["a", "b"])
        groups._mark_baseline_reverted(baseline)
        self.assertTrue((bdir / "20260826_120000_target_baseline.json.reverted").exists())
        self.assertTrue((bdir / "20260826_120000_pushed_ids.json.reverted").exists())
        self.assertFalse(baseline.exists())
        self.assertFalse(pushed.exists())

    def test_add_mapped_segments_mode_is_gone(self):
        self.assertFalse(hasattr(groups, "_add_mapped_segment_cidrs_in_expression"))

    def test_batch_prompt_records_every_decision(self):
        """Confidence-ramp history: approve, resize up, reset to 1, exit are all
        captured for summary.json, and the returned batch sizes match."""
        import builtins
        answers = iter(["", "25", "n", "x"])
        original_input = builtins.input
        builtins.input = lambda *_: next(answers)
        try:
            decisions = []
            self.assertEqual(groups._prompt_batch_continue(1, 1, decisions), 1)    # approve
            self.assertEqual(groups._prompt_batch_continue(1, 1, decisions), 25)   # ramp up
            self.assertEqual(groups._prompt_batch_continue(25, 25, decisions), 1)  # back off
            with self.assertRaises(groups._InteractiveExit):
                groups._prompt_batch_continue(1, 1, decisions)                     # stop
        finally:
            builtins.input = original_input
        self.assertEqual([d["decision"] for d in decisions], ["approve", "resize", "reset_to_1", "exit"])
        self.assertEqual([(d["batch_size_before"], d["batch_size_after"]) for d in decisions],
                         [(1, 1), (1, 25), (25, 1), (1, 1)])
        self.assertTrue(all("ts" in d and "applied_count" in d for d in decisions))

    def test_remap_markdown_report(self):
        import tempfile
        summary = {
            "mode": "DRY-RUN", "ran_at": "2026-08-27T00:00:00+00:00",
            "target": {"alias": "nsx-lm3", "host": "nsx-lm3.lab.local", "domain_id": "default"},
            "groups_dir": "/g", "csv_remap": "/m.csv", "csv_invalid_rows": [],
            "csv_remap_scope": "ip_only_groups",
            "interactive_decisions": [{"ts": "2026-08-27T00:00:01+00:00", "applied_count": 1,
                                       "decision": "resize", "batch_size_before": 1, "batch_size_after": 25}],
            "totals": {"files_seen": 3, "ok": 1, "failed": 0, "skipped": 2,
                       "csv_no_change_skipped": 1, "csv_total_added_values": 2,
                       "total_ips_removed": 0, "additive_only_contract": "pass",
                       "interactive_mode": True, "interactive_batch_size_initial": 1,
                       "interactive_batch_size_final": 25, "interactive_exit_requested": False},
        }
        rows = [
            {"id": "ip-grp", "group_type": "ip-only", "status": "success_put", "csv_changed": True,
             "csv_added_count": 2, "csv_added_values": ["10.7.0.1", "10.7.0.2"],
             "ips_added": ["10.7.0.1", "10.7.0.2"],
             "csv_skipped_values": [{"value": "10.6.0.1-10.6.0.2", "reason": "range", "expression_index": 0}]},
            {"id": "steady", "group_type": "ip-only", "status": "skipped_no_change"},
            {"id": "gen", "group_type": "generic", "status": "dry_run", "csv_remap_skipped": "generic_group",
             "csv_unmapped_values": ["1.2.3.4"]},
        ]
        out = Path(tempfile.mkdtemp())
        path = groups._write_remap_markdown(out, summary, rows)
        md = path.read_text()
        for expected in ("# CSV IP remap dry-run: nsx-lm3", "Would add", "`10.7.0.1`",
                         "No changes needed (1)", "`steady`", "Generic groups, out of scope (1)",
                         "Never remapped by design", "range", "no CSV row covers", "`1.2.3.4`",
                         "Confidence ramp", "1 -> 25", "**pass**"):
            self.assertIn(expected, md)
        self.assertNotIn(chr(0x2014), md)

    def test_batch_prompt_non_tty_auto_approves_and_records(self):
        import builtins
        def raise_eof(*_): raise EOFError
        original_input = builtins.input
        builtins.input = raise_eof
        try:
            decisions = []
            self.assertEqual(groups._prompt_batch_continue(5, 10, decisions), 10)
        finally:
            builtins.input = original_input
        self.assertEqual(decisions[0]["decision"], "auto_approve_non_tty")


if __name__ == "__main__":
    unittest.main()
