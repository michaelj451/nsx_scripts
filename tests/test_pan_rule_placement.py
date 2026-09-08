#!/usr/bin/env python3
"""
tests/test_pan_rule_placement.py

Offline tests for the rule placement engine. No network.

    python -m unittest tests/test_pan_rule_placement.py -v
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

from palo import pan_rule_placement as prp  # noqa: E402


def route(dest, flags="A S", interface="", nexthop=""):
    return {"destination": dest, "flags": flags, "interface": interface,
            "nexthop": nexthop, "virtual-router": "default"}


def table(*routes):
    return prp.parse_routes(list(routes))


class TestParse(unittest.TestCase):
    def test_kinds_and_flags(self):
        r = prp.parse_route_entry(route("10.1.1.0/24", "A C", "ethernet1/2"))
        self.assertEqual((r["kind"], r["active"], r["prefixlen"]), ("connected", True, 24))
        r = prp.parse_route_entry(route("0.0.0.0/0", "A S", nexthop="10.2.1.1"))
        self.assertEqual((r["kind"], r["prefixlen"]), ("static", 0))
        r = prp.parse_route_entry(route("10.9.0.0/16", "A B E"))
        self.assertEqual(r["kind"], "dynamic")

    def test_garbage_skipped(self):
        self.assertIsNone(prp.parse_route_entry({"destination": "not-a-net"}))
        self.assertIsNone(prp.parse_route_entry({"flags": "A"}))


class TestBestRoute(unittest.TestCase):
    def setUp(self):
        self.routes = table(
            route("0.0.0.0/0", "A S", nexthop="10.0.0.1"),
            route("10.1.0.0/16", "A S", nexthop="10.0.0.2"),
            route("10.1.1.0/24", "A C", "ethernet1/2"),
            route("10.1.1.0/24", "S", "ethernet1/9"),   # inactive twin
        )

    def test_longest_prefix_wins(self):
        r = prp.best_route("10.1.1.5", self.routes)
        self.assertEqual((r["destination"], r["kind"]), ("10.1.1.0/24", "connected"))
        r = prp.best_route("10.1.9.9", self.routes)
        self.assertEqual(r["destination"], "10.1.0.0/16")

    def test_default_route_covers_everything_active_only(self):
        r = prp.best_route("192.168.50.1", self.routes)
        self.assertEqual(r["prefixlen"], 0)

    def test_no_routes_returns_none(self):
        self.assertIsNone(prp.best_route("10.1.1.5", []))

    def test_bad_ip_raises(self):
        with self.assertRaises(prp.PanPlacementError):
            prp.best_route("hostname", self.routes)


class TestRecommend(unittest.TestCase):
    """Lab-shaped scenario: fw3 owns 10.3.x, fw4 owns 10.4.x, both have
    defaults; fw5 has only a default route; fw6 is missing routes."""

    def setUp(self):
        self.tables = {
            "dg-3": {"device": "palo3", "routes": table(
                route("10.3.1.0/24", "A C", "ethernet1/2"),
                route("0.0.0.0/0", "A S", nexthop="10.0.0.1"))},
            "dg-4": {"device": "palo4", "routes": table(
                route("10.4.1.0/24", "A C", "ethernet1/2"),
                route("10.3.0.0/16", "A S", nexthop="10.0.0.3"),
                route("0.0.0.0/0", "A S", nexthop="10.0.0.1"))},
            "dg-5": {"device": "palo5", "routes": table(
                route("0.0.0.0/0", "A S", nexthop="10.0.0.1"))},
            "dg-6": {"device": "palo6", "routes": []},
        }

    def rec(self, src, dst):
        return prp.recommend_placement(src, dst, self.tables)

    def test_cross_firewall_flow_recommends_both(self):
        out = self.rec("10.3.1.5", "10.4.1.9")
        dgs = [r["dg"] for r in out["recommended"]]
        self.assertEqual(sorted(dgs), ["dg-3", "dg-4"])
        self.assertIsNone(out["note"])

    def test_default_only_firewall_never_recommended(self):
        out = self.rec("10.3.1.5", "10.4.1.9")
        recommended = [r["dg"] for r in out["recommended"]]
        self.assertNotIn("dg-5", recommended)
        self.assertNotIn("dg-6", recommended)
        verdicts = {c["dg"]: c["verdict"] for c in out["considered"]}
        self.assertIn("another firewall owns", verdicts["dg-5"])
        self.assertIn("another firewall owns", verdicts["dg-6"])

    def test_endpoint_owner_recommended_even_without_far_route(self):
        # No default routes anywhere: owners still recommended, with caution.
        tables = {
            "dg-3": {"device": "palo3", "routes": table(
                route("10.0.11.0/24", "A C", "ae1.1011"))},
            "dg-4": {"device": "palo4", "routes": table(
                route("10.0.12.0/24", "A C", "ae1.1012"))},
        }
        out = prp.recommend_placement("10.0.11.5", "10.0.12.9", tables)
        self.assertEqual(sorted(r["dg"] for r in out["recommended"]), ["dg-3", "dg-4"])
        dg3 = next(r for r in out["recommended"] if r["dg"] == "dg-3")
        self.assertTrue(any("NO route to the destination" in x for x in dg3["reasons"]))

    def test_local_flow_single_firewall(self):
        out = self.rec("10.3.1.5", "10.3.1.99")
        self.assertEqual([r["dg"] for r in out["recommended"]], ["dg-3"])
        self.assertTrue(any("source" in x for x in out["recommended"][0]["reasons"]))

    def test_internet_destination_anchors_on_source_only(self):
        out = self.rec("10.4.1.9", "8.8.8.8")
        self.assertEqual([r["dg"] for r in out["recommended"]], ["dg-4"])
        reasons = out["recommended"][0]["reasons"]
        self.assertTrue(any("most specific route to source" in x for x in reasons))
        self.assertTrue(any("destination reachable: default route only" in x for x in reasons))

    def test_connected_beats_static_for_anchor(self):
        # 10.3.1.5 : dg-3 has connected /24, dg-4 has static /16 -> dg-3 anchors src
        out = self.rec("10.3.1.5", "8.8.8.8")
        self.assertEqual([r["dg"] for r in out["recommended"]], ["dg-3"])

    def test_both_endpoints_unrouted_specifically(self):
        out = self.rec("172.16.1.1", "8.8.8.8")
        self.assertEqual(out["recommended"], [])
        self.assertIn("default", out["note"])


if __name__ == "__main__":
    unittest.main()
