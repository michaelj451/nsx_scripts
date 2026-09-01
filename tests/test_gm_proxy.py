#!/usr/bin/env python3
"""
tests/test_gm_proxy.py

Offline tests for the federation-global rule: a Global Manager run never
opens a session to a Local Manager. Group member counts
(report_groups_usage) and rule statistics (report_rules_usage) are proxied
THROUGH the GM with enforcement_point_path, one call per site, and summed.

    python -m unittest tests/test_gm_proxy.py -v
"""

from __future__ import annotations

import importlib.util
import logging
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "app") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "app"))

logging.disable(logging.CRITICAL)

from nsx.nsx_policy_client import NsxApiError, NsxPolicyClient  # noqa: E402


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


groups_usage = _load("report_groups_usage", "tools/reports/report_groups_usage.py")
rules_usage = _load("report_rules_usage", "tools/reports/report_rules_usage.py")

EPS = {
    "siteA": "/global-infra/sites/siteA/enforcement-points/default",
    "siteB": "/global-infra/sites/siteB/enforcement-points/default",
}


def _site_of(ep: str) -> str:
    return ep.split("/sites/")[1].split("/")[0]


class FakeGm:
    """Stands in for NsxPolicyClient pointed at a GM. Records every call so a
    test can assert that all of them carried an enforcement point and none
    went anywhere but the GM policy root."""
    POLICY_ROOT = "/global-manager/api/v1/global-infra"

    def __init__(self, pages=None, not_found_sites=(), stats=None, fail_sites=(),
                 lm_fqdns=None):
        self.calls = []
        self.pages = pages or {}
        self.not_found = set(not_found_sites)
        self.stats = stats or {}
        self.fail_sites = set(fail_sites)
        self.lm_fqdns = dict(lm_fqdns or {})

    def list_site_lm_fqdns(self):
        return dict(self.lm_fqdns)

    @staticmethod
    def _q(value):
        return str(value)

    def _get(self, path, params=None, timeout=30):
        params = dict(params or {})
        self.calls.append((path, params))
        site = _site_of(params["enforcement_point_path"])
        if site in self.not_found:
            raise Exception('[HTTP 404] GET failed: {"error_code": 600, "httpStatus": "NOT_FOUND"}')
        pages = self.pages.get(site, [[]])
        idx = int(params.get("cursor") or 0)
        out = {"results": pages[idx]}
        if idx + 1 < len(pages):
            out["cursor"] = str(idx + 1)
        return out

    def get_security_policy_statistics(self, security_policy_id, domain_id="default",
                                       enforcement_point_path=None, timeout=60):
        site = _site_of(enforcement_point_path)
        self.calls.append(("stats", site))
        if site in self.fail_sites:
            raise Exception("[HTTP 400] GET failed: 400 java.lang.NullPointerException")
        return {"results": [{"enforcement_point": enforcement_point_path,
                             "statistics": {"results": self.stats.get(site, [])}}]}


class GroupMembersViaGm(unittest.TestCase):
    def test_global_domain_fans_out_per_site_and_sums(self):
        gm = FakeGm(pages={"siteA": [[{"id": 1}, {"id": 2}], [{"id": 3}]],
                           "siteB": [[{"id": 9}]]})
        total, per_site = groups_usage._get_group_vm_count_federated(gm, EPS, "default", "g1")
        self.assertEqual(total, 4)
        self.assertEqual(per_site, {"siteA": 3, "siteB": 1})
        self.assertEqual({p["enforcement_point_path"] for _, p in gm.calls}, set(EPS.values()))
        self.assertTrue(all(path.startswith("/global-manager/") for path, _ in gm.calls))
        self.assertEqual(len(gm.calls), 3)   # two pages for siteA, one for siteB

    def test_location_scoped_domain_queries_its_own_site_only(self):
        gm = FakeGm(pages={"siteB": [[{"id": 1}]]})
        total, per_site = groups_usage._get_group_vm_count_federated(gm, EPS, "siteB", "g1")
        self.assertEqual(total, 1)
        self.assertEqual(list(per_site), ["siteB"])

    def test_not_found_at_a_site_is_zero_members_there(self):
        gm = FakeGm(pages={"siteA": [[{"id": 1}]]}, not_found_sites=("siteB",))
        total, per_site = groups_usage._get_group_vm_count_federated(gm, EPS, "default", "g1")
        self.assertEqual(total, 1)
        self.assertEqual(per_site["siteB"], 0)


class StatsViaGm(unittest.TestCase):
    def test_sums_across_sites(self):
        gm = FakeGm(stats={"siteA": [{"internal_rule_id": "r1", "hit_count": 5, "popularity_index": 2}],
                           "siteB": [{"internal_rule_id": "r1", "hit_count": 7, "popularity_index": 9}]})
        errors = []
        merged, ok = rules_usage._fetch_stats_via_gm(gm, EPS, "default", "p1", errors)
        self.assertEqual(ok, 2)
        self.assertEqual(merged["r1"]["hit_count"], 12)
        self.assertEqual(merged["r1"]["popularity_index"], 9)
        self.assertEqual(errors, [])

    def test_npe_on_every_site_is_recorded_with_no_fallback(self):
        gm = FakeGm(fail_sites=("siteA", "siteB"))
        errors = []
        merged, ok = rules_usage._fetch_stats_via_gm(gm, EPS, "default", "p1", errors, "Policy 1")
        self.assertEqual(merged, {})
        self.assertEqual(ok, 0)
        self.assertEqual(len(errors), 2)
        self.assertTrue(all(e["attempt"].startswith("policy_api_gm:") for e in errors))
        self.assertTrue(all(c[0] == "stats" for c in gm.calls))

    def test_location_scoped_domain_hits_its_own_site_only(self):
        gm = FakeGm(stats={"siteA": [{"internal_rule_id": "r1", "hit_count": 1}]})
        merged, ok = rules_usage._fetch_stats_via_gm(gm, EPS, "siteA", "p1", [])
        self.assertEqual(ok, 1)
        self.assertEqual([c[1] for c in gm.calls], ["siteA"])


class FakeLm:
    """Site LM answering the pre-Policy firewall API (sections + rule stats)."""

    def __init__(self, sections=None, stats=None):
        self.calls = []
        self.sections = sections or {}   # display_name -> section_id
        self.stats = stats or {}         # section_id -> [stat rows]

    def _get(self, path, params=None, timeout=30):
        self.calls.append(path)
        if path == "/api/v1/firewall/sections":
            return {"results": [{"display_name": d, "id": i}
                                for d, i in self.sections.items()]}
        sid = path.split("/sections/")[1].split("/")[0]
        return {"results": self.stats.get(sid, [])}


class LmStatsFallback(unittest.TestCase):
    """Federation-global statistics fallback: direct read-only LM sessions,
    addresses ONLY from the GM's site registry, counters summed per site."""

    def setUp(self):
        rules_usage._SECTION_INDEX_CACHE.clear()

    def test_clients_built_only_from_gm_discovered_addresses(self):
        gm = FakeGm(lm_fqdns={"siteA": "lm-a.corp.example",
                              "siteB": "lm-b.corp.example"})
        built = []

        def factory(host):
            built.append(host)
            return FakeLm()

        contacted, errors = ["gm.lab.local"], []
        clients = rules_usage._connect_lm_stats_clients(
            gm, contacted, errors, client_factory=factory)
        self.assertEqual(sorted(built), ["lm-a.corp.example", "lm-b.corp.example"])
        self.assertEqual(sorted(contacted),
                         ["gm.lab.local", "lm-a.corp.example", "lm-b.corp.example"])
        self.assertEqual(sorted(clients), ["siteA", "siteB"])
        self.assertEqual(errors, [])

    def test_unreachable_site_is_recorded_and_skipped(self):
        gm = FakeGm(lm_fqdns={"siteA": "lm-a.corp.example",
                              "siteB": "lm-b.corp.example"})

        def factory(host):
            if host == "lm-b.corp.example":
                raise Exception("connect timeout")
            return FakeLm()

        contacted, errors = [], []
        clients = rules_usage._connect_lm_stats_clients(
            gm, contacted, errors, client_factory=factory)
        self.assertEqual(sorted(clients), ["siteA"])
        self.assertEqual(contacted, ["lm-a.corp.example"])
        self.assertEqual([e["attempt"] for e in errors],
                         ["lm_fallback_connect:siteB"])

    def test_stats_summed_across_site_lms(self):
        lm_a = FakeLm(sections={"Policy 1": "s1"},
                      stats={"s1": [{"rule_id": "r1", "hit_count": 5}]})
        lm_b = FakeLm(sections={"Policy 1": "s9"},
                      stats={"s9": [{"rule_id": "r1", "hit_count": 7}]})
        errors = []
        merged = rules_usage._fetch_stats_via_lm_direct(
            {"siteA": lm_a, "siteB": lm_b}, "Policy 1", "default", "p1", errors)
        self.assertEqual(merged["r1"]["hit_count"], 12)
        self.assertEqual(errors, [])

    def test_site_without_section_is_recorded(self):
        lm_a = FakeLm(sections={"Policy 1": "s1"},
                      stats={"s1": [{"rule_id": "r1", "hit_count": 3}]})
        lm_b = FakeLm()   # policy not shadowed here
        errors = []
        merged = rules_usage._fetch_stats_via_lm_direct(
            {"siteA": lm_a, "siteB": lm_b}, "Policy 1", "default", "p1", errors)
        self.assertEqual(merged["r1"]["hit_count"], 3)
        self.assertEqual([e["attempt"] for e in errors],
                         ["old_firewall_api_lm:siteB"])


class ApiCallCounting(unittest.TestCase):
    """Every GET a report makes is tallied per manager for the evidence pack."""

    def setUp(self):
        rules_usage._SECTION_INDEX_CACHE.clear()
        rules_usage._API_CALLS.clear()
        groups_usage._API_CALLS.clear()

    def test_rules_usage_tallies_per_manager(self):
        lm = FakeLm(sections={"P": "s1"}, stats={"s1": [{"rule_id": "r1", "hit_count": 1}]})
        rules_usage._count_api_calls(lm, "lm-a.corp.example")
        rules_usage._fetch_stats_via_old_firewall_api(lm, "P")
        self.assertEqual(rules_usage._API_CALLS, {"lm-a.corp.example": 2})  # sections + stats
        self.assertEqual(len(lm.calls), 2)

    def test_groups_usage_tallies_per_manager(self):
        gm = FakeGm(pages={"siteA": [[{"id": 1}]], "siteB": [[{"id": 2}]]})
        groups_usage._count_api_calls(gm, "gm.lab.local")
        groups_usage._get_group_vm_count_federated(gm, EPS, "default", "g1")
        self.assertEqual(groups_usage._API_CALLS, {"gm.lab.local": 2})


class NoLocalManagerSessionsInGmMode(unittest.TestCase):
    """Static guard: report tools may not build site clients from local (.env)
    aliases. report_rules_usage's statistics fallback constructs LM clients
    ONLY from addresses the GM's site registry returned (see LmStatsFallback);
    the banned patterns below catch the old .env-alias style."""

    def test_no_site_client_construction(self):
        for rel in ("tools/reports/report_groups_usage.py",
                    "tools/reports/report_rules_usage.py",
                    "tools/reports/report_vms_in_rules.py",
                    "tools/reports/report_tag_map.py"):
            src = (REPO_ROOT / rel).read_text(encoding="utf-8")
            self.assertNotIn("NsxPolicyClient(nsxmanager=sid", src, rel)
            self.assertNotIn("site_clients", src, rel)
            self.assertNotIn("site_fabric", src, rel)
            self.assertNotIn("build_site_clients_for_federation", src, rel)


class ClientRefusesLmInFederationGlobal(unittest.TestCase):
    """federation_global=True with a non-GM host must raise in the
    constructor, before any HTTP session is opened."""

    def test_constructor_refuses_non_gm_host(self):
        with self.assertRaises(NsxApiError) as ctx:
            NsxPolicyClient(nsxmanager="nsx-lm1.lab.local",
                            federation_global=True)
        self.assertIn("Global Manager", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
