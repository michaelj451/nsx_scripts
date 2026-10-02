#!/usr/bin/env python3
"""
tests/test_vm_rule_snapshot.py

Offline tests for the VM rule snapshot: capture_vm_rule_data.py freezes what
report_vms_in_rules.py pulls live, and --from-snapshot answers the same
lookups (VM names and bare IPs) with zero NSX calls.

    python -m unittest tests/test_vm_rule_snapshot.py -v
"""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "app") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "app"))

logging.disable(logging.CRITICAL)

from nsx.vm_rule_data import (  # noqa: E402
    SNAPSHOT_FILE, collect_live, load_snapshot, resolve_snapshot_path, write_snapshot,
)


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


report = _load("report_vms_in_rules", "tools/reports/report_vms_in_rules.py")
capture = _load("capture_vm_rule_data", "tools/nsx/capture_vm_rule_data.py")

G = "/infra/domains/default/groups/"
# group id -> (VM members, evaluated IP members)
LAB = {
    "g-tag": (["vm-a"], ["10.6.0.101"]),
    "g-iponly": ([], ["10.6.0.0/24"]),
    "g-db": (["vm-b"], []),
    "g-unused": (["vm-b"], []),
}
RULES = {
    "pol-app": [
        {"id": "r1", "display_name": "web-to-db", "action": "ALLOW",
         "source_groups": [G + "g-tag"], "destination_groups": [G + "g-db"], "scope": ["ANY"]},
        {"id": "r2", "display_name": "subnet-out", "action": "ALLOW",
         "source_groups": [G + "g-iponly"], "destination_groups": ["ANY"], "scope": ["ANY"]},
        {"id": "r4", "display_name": "db-to-db", "action": "ALLOW",
         "source_groups": [G + "g-db"], "destination_groups": [G + "g-db"], "scope": ["ANY"]},
    ],
    "pol-default": [
        {"id": "r3", "display_name": "default", "action": "DROP",
         "source_groups": ["ANY"], "destination_groups": ["ANY"], "scope": ["ANY"]},
    ],
}


class FakeLm:
    """Stands in for NsxPolicyClient pointed at an LM. Fabric VM records carry
    no IPs of their own (as on real NSX); the addresses live on the VIFs."""
    POLICY_ROOT = "/policy/api/v1/infra"

    def __init__(self, vifs=True, ip_fail_group=None):
        self.vifs = vifs
        self.ip_fail_group = ip_fail_group

    def _q(self, s):
        return s

    def _policy_path(self, p):
        return self.POLICY_ROOT + p

    def list_virtual_machines(self):
        return [
            {"external_id": "vm-a", "display_name": "web01", "tags": [],
             "guest_info": {"computer_name": "web01"}},
            {"external_id": "vm-b", "display_name": "db01", "tags": []},
        ]

    def list_vm_vifs(self):
        if not self.vifs:
            return []
        return [{"owner_vm_id": "vm-a", "mac_address": "00:50:56:aa:bb:cc",
                 "ip_address_info": [{"ip_addresses": ["10.6.0.101"]}]}]

    def list_domains(self):
        return [{"id": "default"}]

    def list_groups(self, domain_id):
        return [{"id": g, "path": G + g, "display_name": g.upper()} for g in LAB]

    def list_policy_group_member_vms(self, group_id, domain_id):
        return [{"external_id": v, "display_name": v} for v in LAB[group_id][0]]

    def _get(self, path, params=None):
        gid = path.split("/groups/")[1].split("/")[0]
        if gid == self.ip_fail_group:
            raise RuntimeError("NSX API 500 internal error")
        return {"results": LAB[gid][1]}

    def list_security_policies(self, domain_id):
        return [{"id": pid, "path": f"/infra/domains/default/security-policies/{pid}",
                 "display_name": pid, "category": "Application"} for pid in RULES]

    def list_security_rules(self, security_policy_id, domain_id):
        return [dict(r) for r in RULES[security_policy_id]]


class FakeGm:
    """Stands in for NsxPolicyClient pointed at a GM. Any LM-only call fails
    the test; every member call must carry an enforcement point."""
    POLICY_ROOT = "/global-manager/api/v1/global-infra"
    SITES = {"siteA": ["vm-a"], "siteB": ["vm-b"]}

    def __init__(self):
        self.calls = []

    def _q(self, s):
        return s

    def _policy_path(self, p):
        return self.POLICY_ROOT + p

    def list_virtual_machines(self):
        raise AssertionError("GM run touched the LM-only fabric VM API")

    def list_vm_vifs(self):
        raise AssertionError("GM run touched the LM-only VIF API")

    def list_domains(self):
        return [{"id": "default"}]

    def list_groups(self, domain_id):
        return [{"id": g, "path": "/global-infra/domains/default/groups/" + g,
                 "display_name": g} for g in LAB]

    def list_security_policies(self, domain_id):
        return [{"id": "p", "path": "/global-infra/domains/default/security-policies/p",
                 "display_name": "p"}]

    def list_security_rules(self, security_policy_id, domain_id):
        return [{"id": "gr1", "source_groups": ["/global-infra/domains/default/groups/g-tag"],
                 "destination_groups": ["ANY"], "scope": ["ANY"]}]

    def _get(self, path, params=None):
        self.calls.append((path, dict(params or {})))
        if path.endswith("/sites"):
            return {"results": [{"id": s, "display_name": s.upper()} for s in self.SITES]}
        if path.endswith("/enforcement-points"):
            site = path.split("/sites/")[1].split("/")[0]
            return {"results": [{"path": f"/global-infra/sites/{site}/enforcement-points/default"}]}
        ep = params["enforcement_point_path"]
        site = ep.split("/sites/")[1].split("/")[0]
        gid = path.split("/groups/")[1].split("/")[0]
        if path.endswith("/members/virtual-machines"):
            return {"results": [{"external_id": v, "display_name": v.upper()}
                                for v in LAB[gid][0] if v in self.SITES[site]]}
        return {"results": LAB[gid][1]}


def _rules_by_entry(result):
    """entry display name -> sorted rule ids that hit it."""
    out = {name: [] for name in result["resolved"]}
    ext_to_name = {m["external_id"]: n for n, m in result["resolved"].items()}
    for h in result["hits"]:
        for ext in h["info"]["by_side"]:
            out[ext_to_name[ext]].append(h["rule"]["id"])
    return {k: sorted(v) for k, v in out.items()}


TARGETS = report.parse_targets(["web01, 10.6.0.55", "db01,10.6.0.101,nosuch"])


class ParseTargets(unittest.TestCase):
    def test_every_comma_token_is_its_own_entry(self):
        entries = report.parse_targets([" web01 ,, 10.6.0.101 ", "db 01"])
        self.assertEqual(entries, [("web01", None), ("10.6.0.101", None), ("db 01", None)])


class LmLookup(unittest.TestCase):
    def setUp(self):
        self.data = collect_live(FakeLm(), manager_host="lm.lab", is_gm=False)

    def test_vm_ips_come_from_vifs(self):
        vms = {v["display_name"]: v for v in self.data["vms"]}
        self.assertEqual(vms["web01"]["ips"], ["10.6.0.101"])
        self.assertEqual(vms["db01"]["ips"], [])

    def test_names_and_ips_hit_the_right_rules(self):
        result = report.analyze(self.data, TARGETS)
        self.assertEqual(result["not_found"], ["nosuch"])
        self.assertEqual(_rules_by_entry(result), {
            "web01": ["r1", "r2", "r3"],        # tag member + VIF IP inside the /24
            "db01": ["r1", "r3", "r4"],
            "10.6.0.55": ["r2", "r3"],          # IP-only group by CIDR
            "10.6.0.101": ["r1", "r2", "r3"],   # evaluated IP of the tag group
        })
        self.assertEqual(result["resolved"]["10.6.0.101"]["kind"], "IP")
        self.assertEqual(result["resolved"]["10.6.0.101"]["owner_vms"], ["web01"])
        self.assertEqual(result["resolved"]["10.6.0.55"]["owner_vms"], [])

    def test_without_vif_ips_a_name_misses_ip_only_groups(self):
        """The regression the VIF attach fixes: a fabric VM record has no IPs,
        so without VIFs web01 never meets the IP-only group behind r2."""
        data = collect_live(FakeLm(vifs=False), manager_host="lm.lab", is_gm=False)
        result = report.analyze(data, report.parse_targets(["web01"]))
        self.assertEqual(_rules_by_entry(result)["web01"], ["r1", "r3"])


class SnapshotRoundTrip(unittest.TestCase):
    def test_offline_answer_equals_live_answer(self):
        live = collect_live(FakeLm(), manager_host="lm.lab", is_gm=False)
        live_answer = report.analyze(live, TARGETS)
        with tempfile.TemporaryDirectory() as td:
            write_snapshot(Path(td) / SNAPSHOT_FILE, live, manager_alias="nsx-lm1")
            offline = load_snapshot(Path(td))
        offline_answer = report.analyze(offline, TARGETS)
        self.assertEqual(_rules_by_entry(offline_answer), _rules_by_entry(live_answer))
        self.assertEqual(
            {n: m["group_count"] for n, m in offline_answer["resolved"].items()},
            {n: m["group_count"] for n, m in live_answer["resolved"].items()})

    def test_fetch_error_marks_snapshot_incomplete(self):
        data = collect_live(FakeLm(ip_fail_group="g-iponly"), manager_host="lm.lab", is_gm=False)
        with tempfile.TemporaryDirectory() as td:
            doc = write_snapshot(Path(td) / SNAPSHOT_FILE, data, manager_alias="nsx-lm1")
        self.assertFalse(doc["complete"])
        self.assertEqual(doc["fetch_error_count"], 1)
        self.assertIn("g-iponly", doc["fetch_errors"][0])

    def test_path_resolution(self):
        data = collect_live(FakeLm(), manager_host="lm.lab", is_gm=False)
        with tempfile.TemporaryDirectory() as td:
            host = Path(td) / "lm.lab"
            bundle = host / "20260929_120000"
            write_snapshot(bundle / SNAPSHOT_FILE, data, manager_alias="nsx-lm1")
            (host / "latest").symlink_to(bundle.name)
            f = bundle / SNAPSHOT_FILE
            for given in (host, bundle, f):
                self.assertEqual(resolve_snapshot_path(given).resolve(), f.resolve())
            with self.assertRaises(SystemExit):
                resolve_snapshot_path(Path(td) / "nope")
            # No `latest` link (Windows without symlink rights): newest
            # bundle whose manifest says ok, skipping a newer failed one.
            (host / "latest").unlink()
            (bundle / "manifest.json").write_text(json.dumps({"ok": True}))
            failed = host / "20260930_000000"
            write_snapshot(failed / SNAPSHOT_FILE, data, manager_alias="nsx-lm1")
            (failed / "manifest.json").write_text(json.dumps({"ok": False}))
            self.assertEqual(resolve_snapshot_path(host).resolve(), f.resolve())
            f.write_text(json.dumps({"schema": "something-else"}))
            with self.assertRaises(SystemExit):
                load_snapshot(f)


class GmLookup(unittest.TestCase):
    def test_gm_collects_through_the_gm_only(self):
        gm = FakeGm()
        data = collect_live(gm, manager_host="gm.lab", is_gm=True)
        member_calls = [(p, q) for p, q in gm.calls if "/members/" in p]
        self.assertTrue(member_calls)
        for path, params in gm.calls:
            self.assertTrue(path.startswith(FakeGm.POLICY_ROOT), path)
        for path, params in member_calls:
            self.assertIn("enforcement_point_path", params)
            # only the rule-referenced group is member-fetched
            self.assertIn("/groups/g-tag/", path)
        self.assertEqual({v["external_id"] for v in data["vms"]}, {"vm-a"})
        self.assertEqual(data["vm_ext_to_site"], {"vm-a": "siteA"})
        result = report.analyze(data, report.parse_targets(["VM-A,10.6.0.101"]))
        self.assertEqual(_rules_by_entry(result), {"VM-A": ["gr1"], "10.6.0.101": ["gr1"]})


class CaptureTool(unittest.TestCase):
    def _run(self, client, td):
        with mock.patch.object(capture, "NsxPolicyClient", return_value=client), \
             mock.patch.object(capture, "resolve_manager", return_value="lm.lab"):
            return capture.capture_one("nsx-lm1", Path(td), retain=0)

    def test_complete_capture_becomes_latest(self):
        with tempfile.TemporaryDirectory() as td:
            m = self._run(FakeLm(), td)
            self.assertTrue(m["ok"])
            latest = Path(td) / "lm.lab" / "latest" / SNAPSHOT_FILE
            self.assertTrue(latest.is_file())
            self.assertEqual(m["counts"]["rules"], 4)

    def test_incomplete_capture_is_kept_but_not_latest(self):
        with tempfile.TemporaryDirectory() as td:
            m = self._run(FakeLm(ip_fail_group="g-tag"), td)
            self.assertFalse(m["ok"])
            self.assertEqual(m["fetch_error_count"], 1)
            self.assertTrue(Path(m["snapshot"]).is_file())
            self.assertFalse((Path(td) / "lm.lab" / "latest").exists())


if __name__ == "__main__":
    unittest.main()
