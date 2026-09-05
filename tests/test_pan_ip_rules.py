#!/usr/bin/env python3
"""
tests/test_pan_ip_rules.py

Offline tests for the IP-to-rule matching engine. No network.

    python -m unittest tests/test_pan_ip_rules.py -v
"""

from __future__ import annotations

import logging
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "app") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "app"))

logging.disable(logging.CRITICAL)

import ipaddress  # noqa: E402

from palo import pan_ip_rules as pir  # noqa: E402


def addr(name, **fields):
    return {"@name": name, **fields}


def group(name, members):
    return {"@name": name, "static": {"member": members}}


def rule(name, source, destination, **extra):
    return {"@name": name, "source": {"member": source},
            "destination": {"member": destination}, **extra}


def net(s):
    e = pir.parse_ip_entry(s)
    assert e is not None, s
    return e


class TestParseIpLines(unittest.TestCase):
    def test_bare_ip_subnet_and_range(self):
        entries, invalid = pir.parse_ip_lines(
            "10.1.1.5\n# comment\n\n10.2.0.0/24  # inline\n10.5.0.1-10.5.0.9\n")
        self.assertEqual(invalid, [])
        self.assertEqual([e["kind"] for e in entries], ["host", "subnet", "range"])
        self.assertEqual(entries[0]["lo"], entries[0]["hi"])
        self.assertEqual(entries[2]["hi"] - entries[2]["lo"], 8)
        self.assertEqual(entries[0]["raw"], "10.1.1.5")

    def test_invalid_lines_collected(self):
        entries, invalid = pir.parse_ip_lines(
            "10.1.1.5\nnot-an-ip\n10.0.0.0/33\n10.5.0.9-10.5.0.1\n10.1.1.1-2001:db8::1\n")
        self.assertEqual(len(entries), 1)
        self.assertEqual(invalid, ["not-an-ip", "10.0.0.0/33",
                                   "10.5.0.9-10.5.0.1", "10.1.1.1-2001:db8::1"])


class TestApplyExclusions(unittest.TestCase):
    def run_it(self, targets_text, exclusions_text):
        targets, _ = pir.parse_ip_lines(targets_text)
        exclusions, _ = pir.parse_ip_lines(exclusions_text)
        return pir.apply_exclusions(targets, exclusions)

    def test_contained_target_excluded_with_reason(self):
        kept, excluded = self.run_it("10.3.1.150\n10.1.1.5\n", "10.3.0.0/16\n")
        self.assertEqual([t["raw"] for t in kept], ["10.1.1.5"])
        self.assertEqual(excluded[0]["raw"], "10.3.1.150")
        self.assertEqual(excluded[0]["excluded_by"], "10.3.0.0/16")

    def test_partial_overlap_kept_and_noted(self):
        kept, excluded = self.run_it("10.3.0.0/8\n", "10.3.0.0/16\n")
        self.assertEqual(excluded, [])
        self.assertEqual(kept[0]["partial_exclusions"], ["10.3.0.0/16"])

    def test_version_mismatch_never_excludes(self):
        kept, excluded = self.run_it("2001:db8::5\n", "0.0.0.0/0\n")
        self.assertEqual(excluded, [])
        self.assertNotIn("partial_exclusions", kept[0])


class TestTokenCovers(unittest.TestCase):
    def test_host_subnet_range(self):
        t = net("10.1.1.5/32")
        self.assertTrue(pir.token_covers(t, "10.1.1.5"))
        self.assertTrue(pir.token_covers(t, "10.1.1.0/24"))
        self.assertTrue(pir.token_covers(t, "10.1.1.1-10.1.1.10"))
        self.assertFalse(pir.token_covers(t, "10.1.1.6"))
        self.assertFalse(pir.token_covers(t, "10.1.2.0/24"))
        self.assertFalse(pir.token_covers(t, "10.1.1.6-10.1.1.10"))

    def test_subnet_target_overlaps(self):
        t = net("10.1.1.0/24")
        self.assertTrue(pir.token_covers(t, "10.1.1.200"))
        self.assertTrue(pir.token_covers(t, "10.1.0.0/16"))
        self.assertTrue(pir.token_covers(t, "10.1.1.250-10.1.2.5"))

    def test_range_target(self):
        t = net("10.1.1.5-10.1.1.20")
        self.assertTrue(pir.token_covers(t, "10.1.1.10"))
        self.assertTrue(pir.token_covers(t, "10.1.1.0/24"))
        self.assertTrue(pir.token_covers(t, "10.1.1.19-10.1.1.30"))
        self.assertFalse(pir.token_covers(t, "10.1.1.21"))
        self.assertFalse(pir.token_covers(t, "10.1.1.21-10.1.1.30"))

    def test_range_target_exclusion_containment(self):
        targets, _ = pir.parse_ip_lines("10.1.1.5-10.1.1.20\n10.1.1.5-10.1.2.5\n")
        exclusions, _ = pir.parse_ip_lines("10.1.1.0/24\n")
        kept, excluded = pir.apply_exclusions(targets, exclusions)
        self.assertEqual([t["raw"] for t in excluded], ["10.1.1.5-10.1.1.20"])
        self.assertEqual(kept[0]["partial_exclusions"], ["10.1.1.0/24"])

    def test_non_ip_and_version_mismatch(self):
        t = net("10.1.1.5/32")
        self.assertFalse(pir.token_covers(t, "example.com"))
        self.assertFalse(pir.token_covers(t, "2001:db8::/64"))
        self.assertFalse(pir.token_covers(net("2001:db8::5/128"), "10.0.0.0/8"))


class TestExpandGroup(unittest.TestCase):
    def setUp(self):
        self.addr_by_name = {
            "h-a": {"kind": "ip-netmask", "value": "10.1.1.5"},
            "h-b": {"kind": "ip-netmask", "value": "10.2.1.30"},
        }
        self.groups = {
            "outer": group("outer", ["h-a", "inner", "10.5.5.5"]),
            "inner": group("inner", ["h-b", "outer"]),  # cycle back to outer
        }

    def test_nested_expansion_with_via_chain_and_cycle(self):
        hits = pir.expand_group("outer", self.groups, self.addr_by_name)
        by_member = {h["member"]: h for h in hits}
        self.assertEqual(by_member["h-a"]["via"], "outer")
        self.assertEqual(by_member["h-b"]["via"], "outer > inner")
        self.assertEqual(by_member["10.5.5.5"]["kind"], "literal")
        self.assertEqual(len(hits), 3)  # cycle did not loop or duplicate


class TestMatchRules(unittest.TestCase):
    def setUp(self):
        self.addresses = [
            addr("h-10.1.1.5", **{"ip-netmask": "10.1.1.5"}),
            addr("n-10.2.1.0-24", **{"ip-netmask": "10.2.1.0/24"}),
            addr("r-10.3", **{"ip-range": "10.3.1.101-10.3.2.5"}),
            addr("fq-x", fqdn="x.lab.local"),
        ]
        self.groups = [group("grp", ["h-10.1.1.5", "r-10.3"])]
        self.targets, _ = pir.parse_ip_lines("10.1.1.5\n10.2.1.30\n10.3.1.150\n10.9.9.9\n")

    def match(self, rules):
        return pir.match_rules(rules, self.addresses, self.groups, self.targets,
                               scope="dg-4", rulebase="pre")

    def test_direct_object_and_literal_matches(self):
        res = self.match([rule("r1", ["h-10.1.1.5"], ["10.2.1.0/24"], action="allow")])
        r = res["matched_rules"][0]
        got = {(m["target"], m["side"], m["member"]) for m in r["matches"]}
        self.assertEqual(got, {("10.1.1.5", "source", "h-10.1.1.5"),
                               ("10.2.1.30", "destination", "10.2.1.0/24")})
        self.assertEqual(r["action"], "allow")

    def test_group_match_records_via(self):
        res = self.match([rule("r1", ["grp"], ["any"])])
        r = res["matched_rules"][0]
        vias = {(m["target"], m["via"]) for m in r["matches"]}
        self.assertEqual(vias, {("10.1.1.5", "grp"), ("10.3.1.150", "grp")})
        self.assertEqual(r["any_sides"], ["destination"])

    def test_any_any_rule_separated(self):
        res = self.match([rule("global-allow", ["any"], ["any"])])
        self.assertEqual(res["matched_rules"], [])
        self.assertEqual(res["any_any_rules"], ["global-allow"])

    def test_no_match_rule_omitted(self):
        res = self.match([rule("r1", ["fq-x"], ["10.8.8.0/24"])])
        self.assertEqual(res["matched_rules"], [])

    def test_disabled_flag_carried(self):
        res = self.match([rule("r1", ["h-10.1.1.5"], ["any"], disabled="yes")])
        self.assertTrue(res["matched_rules"][0]["disabled"])


class TestMatchExclusions(unittest.TestCase):
    def setUp(self):
        self.addresses = [
            addr("h-10.1.1.5", **{"ip-netmask": "10.1.1.5"}),
            addr("n-10.1.1.0-24", **{"ip-netmask": "10.1.1.0/24"}),
            addr("agg-10.0.0.0-8", **{"ip-netmask": "10.0.0.0/8"}),
        ]
        self.targets, _ = pir.parse_ip_lines("10.1.1.5\n")
        self.exclusions, _ = pir.parse_ip_lines("10.0.0.0/8\n")

    def match(self, rules):
        return pir.match_rules(rules, self.addresses, [], self.targets,
                               scope="dg-4", rulebase="pre",
                               match_exclusions=self.exclusions)

    def test_equal_value_suppressed_with_reason(self):
        res = self.match([rule("r1", ["agg-10.0.0.0-8"], ["any"])])
        self.assertEqual(res["matched_rules"], [])
        s = res["suppressed"][0]
        self.assertEqual((s["rule"], s["member"], s["excluded_by"]),
                         ("r1", "agg-10.0.0.0-8", "10.0.0.0/8"))

    def test_broader_value_suppressed(self):
        addresses = self.addresses + [addr("half-internet", **{"ip-netmask": "0.0.0.0/1"})]
        res = pir.match_rules([rule("r1", ["half-internet"], ["any"])],
                              addresses, [], self.targets, scope="s", rulebase="pre",
                              match_exclusions=self.exclusions)
        self.assertEqual(len(res["suppressed"]), 1)

    def test_narrower_value_still_matches(self):
        res = self.match([rule("r1", ["n-10.1.1.0-24", "agg-10.0.0.0-8"], ["any"])])
        self.assertEqual(len(res["matched_rules"]), 1)
        self.assertEqual(res["matched_rules"][0]["matches"][0]["member"], "n-10.1.1.0-24")
        self.assertEqual(len(res["suppressed"]), 1)

    def test_targets_never_dropped(self):
        # A /8-excluded world still searches a 10.x target: h-10.1.1.5 matches.
        res = self.match([rule("r1", ["h-10.1.1.5"], ["any"])])
        self.assertEqual(len(res["matched_rules"]), 1)
        self.assertEqual(res["suppressed"], [])


class TestMatchFlow(unittest.TestCase):
    def setUp(self):
        self.addresses = [
            addr("h-src", **{"ip-netmask": "10.1.1.5"}),
            addr("n-dst", **{"ip-netmask": "10.2.1.0/24"}),
        ]
        self.groups = [group("grp-src", ["h-src"])]
        self.services = [{"@name": "svc-443", "protocol": {"tcp": {"port": "443"}}},
                         {"@name": "svc-53u", "protocol": {"udp": {"port": "53"}}},
                         {"@name": "svc-hi", "protocol": {"tcp": {"port": "8000-9000"}}}]
        self.svc_groups = [{"@name": "web", "members": {"member": ["svc-443"]}}]

    def chain(self, *rules):
        return [{"scope": "dg-4", "rulebase": "pre", "rule": r} for r in rules]

    def flow(self, chain, **kw):
        return pir.match_flow(chain, self.addresses, self.groups,
                              self.services, self.svc_groups, **kw)

    def test_requires_at_least_one_ip(self):
        with self.assertRaises(ValueError):
            self.flow(self.chain(), port_spec=pir.parse_port_spec("443"))

    def test_full_flow_match_order_and_vias(self):
        c = self.chain(rule("r-no", ["n-dst"], ["any"]),
                       rule("r-yes", ["grp-src"], ["n-dst"], service={"member": ["svc-443"]}),
                       rule("r-any", ["any"], ["any"]))
        out = self.flow(c, src="10.1.1.5", dst="10.2.1.9",
                        port_spec=pir.parse_port_spec("tcp/443"))
        self.assertEqual([o["rule"] for o in out], ["r-yes", "r-any"])
        first = out[0]
        self.assertIn("via group grp-src", first["src_via"])
        self.assertEqual(first["dst_via"], "n-dst = 10.2.1.0/24")
        self.assertEqual(first["service_via"], "svc-443")

    def test_src_only_lookup(self):
        c = self.chain(rule("r1", ["h-src"], ["n-dst"]))
        out = self.flow(c, src="10.1.1.5")
        self.assertEqual(out[0]["dst_via"], "(not specified)")

    def test_port_filters_rules(self):
        c = self.chain(rule("r1", ["any"], ["any"], service={"member": ["svc-53u"]}))
        self.assertEqual(self.flow(c, src="10.1.1.5",
                                   port_spec=pir.parse_port_spec("tcp/53")), [])
        self.assertEqual(len(self.flow(c, src="10.1.1.5",
                                       port_spec=pir.parse_port_spec("udp/53"))), 1)
        self.assertEqual(len(self.flow(c, src="10.1.1.5",
                                       port_spec=pir.parse_port_spec("53"))), 1)

    def test_port_range_group_predefined_and_appdefault(self):
        c = self.chain(rule("r-range", ["any"], ["any"], service={"member": ["svc-hi"]}),
                       rule("r-grp", ["any"], ["any"], service={"member": ["web"]}),
                       rule("r-pre", ["any"], ["any"], service={"member": ["service-https"]}),
                       rule("r-appdef", ["any"], ["any"],
                            service={"member": ["application-default"]}))
        out = self.flow(c, src="10.1.1.5", port_spec=pir.parse_port_spec("tcp/8443"))
        self.assertEqual([o["rule"] for o in out], ["r-range", "r-appdef"])
        out = self.flow(c, src="10.1.1.5", port_spec=pir.parse_port_spec("443"))
        self.assertEqual([o["rule"] for o in out], ["r-grp", "r-pre", "r-appdef"])
        self.assertEqual(out[0]["service_via"], "svc-443 (in group web)")

    def test_port_spec_parsing(self):
        self.assertIsNone(pir.parse_port_spec(""))
        self.assertEqual(pir.parse_port_spec("tcp/443"), {"proto": "tcp", "port": 443})
        self.assertEqual(pir.parse_port_spec("53"), {"proto": None, "port": 53})
        for bad in ("abc", "tcp/", "icmp/8", "70000", "tcp/0"):
            with self.assertRaises(ValueError):
                pir.parse_port_spec(bad)

    def test_bad_ip_raises(self):
        with self.assertRaises(ValueError):
            self.flow(self.chain(), src="not-an-ip")


if __name__ == "__main__":
    unittest.main()
