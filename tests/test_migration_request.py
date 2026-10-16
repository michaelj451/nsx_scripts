"""Migration request workflow (app/multisite/migration_request.py and
tools/multisite/migration_request.py), Mike 2026-10-07.

Covers: server input (names, bare IPs, name,ip), an IP resolving to the VM
that owns it, rule selection (default sections never copied), the
dependency walk (nested groups, nested services via nested_service_path,
policy-level applied-to), the Workflow A bundle layout the push tools read,
Workflow D scope (only the servers' groups that sit in a rule, only the
servers' addresses), the unchanged D builder run on the trimmed groups,
fingerprints and the server gate, and the phase commands.
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
sys.path.insert(0, str(ROOT / "tools" / "reports"))

from multisite import migration_request as mr  # noqa: E402

HOST = "src.lab.local"
D = "/infra/domains/default"
G = f"{D}/groups/"
P = f"{D}/security-policies/"


def _w(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(obj, sort_keys=False), encoding="utf-8")


def ipx(*a):
    return {"resource_type": "IPAddressExpression", "ip_addresses": list(a)}


def cond(v):
    return {"resource_type": "Condition", "member_type": "VirtualMachine", "key": "Tag",
            "operator": "EQUALS", "value": v}


def make_capture(root: Path) -> Path:
    """A small source capture in capture_nsx_state.py's --output-dir layout."""
    cap = root / "capture"
    base = cap / "nsx_export" / HOST / "domains" / "default"
    _w(base / "security-policies" / "app-pol" / "policy.yaml",
       {"id": "app-pol", "path": P + "app-pol", "display_name": "App policy", "category": "Application",
        "sequence_number": 10, "is_default": False, "scope": [G + "scope-g"]})
    _w(base / "security-policies" / "infra-pol" / "policy.yaml",
       {"id": "infra-pol", "path": P + "infra-pol", "display_name": "Infra policy",
        "category": "Infrastructure", "sequence_number": 5, "is_default": False})
    _w(base / "security-policies" / "dl3" / "policy.yaml",
       {"id": "default-layer3-section", "path": P + "default-layer3-section", "category": "Application",
        "sequence_number": 99, "is_default": True})
    rules = {
        ("app-pol", "0001_r1.yaml"): {"id": "r1", "display_name": "web to db", "parent_path": P + "app-pol",
                                      "sequence_number": 10, "action": "ALLOW", "rule_id": 1001,
                                      "source_groups": [G + "web"], "destination_groups": [G + "db"],
                                      "services": ["/infra/services/svc-bundle", "/infra/services/HTTPS"],
                                      "scope": ["ANY"]},
        ("app-pol", "0002_r2.yaml"): {"id": "r2", "display_name": "unrelated", "parent_path": P + "app-pol",
                                      "sequence_number": 20, "action": "ALLOW",
                                      "source_groups": [G + "other"], "destination_groups": ["ANY"],
                                      "services": ["ANY"], "scope": ["ANY"]},
        ("infra-pol", "0001_dns.yaml"): {"id": "dns", "display_name": "dns", "parent_path": P + "infra-pol",
                                         "sequence_number": 1, "action": "ALLOW",
                                         "source_groups": [G + "db"], "destination_groups": ["ANY"],
                                         "services": ["/infra/services/DNS-UDP"], "scope": ["ANY"]},
        ("dl3", "0001_default.yaml"): {"id": "default-layer3-rule", "parent_path": P + "default-layer3-section",
                                       "sequence_number": 1, "action": "DROP", "source_groups": ["ANY"],
                                       "destination_groups": ["ANY"], "services": ["ANY"], "scope": ["ANY"]},
    }
    for (pdir, fname), r in rules.items():
        _w(base / "security-policies" / pdir / "rules" / fname, r)
    groups = {
        "web": [cond("web"), {"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"},
                {"resource_type": "PathExpression", "paths": [G + "web-child", "/infra/segments/seg-1"]}],
        "web-child": [ipx("10.6.9.0/24")],
        "db": [ipx("10.6.1.5")],
        "scope-g": [cond("app")],
        "other": [cond("other")],
    }
    for gid, expr in groups.items():
        _w(base / "groups" / f"{gid}.yaml", {"id": gid, "path": G + gid, "display_name": gid.upper(),
                                              "expression": expr})
        additive = list(expr)
        if gid == "web":
            additive = expr + [{"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"},
                               ipx("10.6.0.101", "10.6.0.102")]
        _w(cap / "groups_additive" / "domains" / "default" / "groups" / f"{gid}.yaml",
           {"id": gid, "path": G + gid, "display_name": gid.upper(), "expression": additive})
    _w(base / "services" / "svc-bundle.yaml",
       {"id": "svc-bundle", "path": "/infra/services/svc-bundle",
        "service_entries": [{"resource_type": "NestedServiceServiceEntry",
                             "nested_service_path": "/infra/services/svc-a"}]})
    _w(base / "services" / "svc-a.yaml",
       {"id": "svc-a", "path": "/infra/services/svc-a",
        "service_entries": [{"resource_type": "L4PortSetServiceEntry", "l4_protocol": "TCP",
                             "destination_ports": ["8443"]}]})
    _w(base / "services" / "unused.yaml", {"id": "unused", "path": "/infra/services/unused"})
    return cap


def snapshot_data():
    """The shape load_snapshot() returns, for the same source."""
    vms = [{"external_id": "vm-1", "display_name": "web01", "ips": ["10.6.0.101"], "tags": [],
            "power_state": "VM_RUNNING"},
           {"external_id": "vm-2", "display_name": "web02", "ips": ["10.6.0.102"], "tags": []},
           {"external_id": "vm-3", "display_name": "dup-a", "ips": ["10.6.5.5"], "tags": []},
           {"external_id": "vm-4", "display_name": "dup-b", "ips": ["10.6.5.5"], "tags": []}]
    gbp = {G + g: {"id": g, "display_name": g.upper(), "path": G + g, "domain_id": "default"}
           for g in ("web", "web-child", "db", "scope-g", "other")}
    rules = []
    for pid, pname, cat, r in (
            ("app-pol", "App policy", "Application",
             {"id": "r1", "display_name": "web to db", "source_groups": [G + "web"],
              "destination_groups": [G + "db"], "scope": ["ANY"]}),
            ("app-pol", "App policy", "Application",
             {"id": "r2", "display_name": "unrelated", "source_groups": [G + "other"],
              "destination_groups": ["ANY"], "scope": ["ANY"]}),
            ("infra-pol", "Infra policy", "Infrastructure",
             {"id": "dns", "display_name": "dns", "source_groups": [G + "db"],
              "destination_groups": ["ANY"], "scope": ["ANY"]}),
            ("default-layer3-section", "Default", "Application",
             {"id": "default-layer3-rule", "source_groups": ["ANY"], "destination_groups": ["ANY"],
              "scope": ["ANY"]})):
        rules.append({**r, "_policy_id": pid, "_policy_display": pname, "_category": cat,
                      "_domain_id": "default"})
    return {"vms": vms, "vm_ext_to_site": {}, "groups_by_path": gbp,
            "group_to_members": {G + "web": {"vm-1", "vm-2"}, G + "db": set(), G + "scope-g": set(),
                                 G + "web-child": set(), G + "other": set()},
            "group_ips": {G + "web": {"10.6.0.101", "10.6.0.102", "10.6.9.0/24"}, G + "db": {"10.6.1.5"},
                          G + "web-child": {"10.6.9.0/24"}},
            "rules": rules, "domain_ids": ["default"]}


def analyze(data, entries):
    import report_vms_in_rules
    return report_vms_in_rules.analyze(data, entries)


class InputTests(unittest.TestCase):
    def test_list_lines(self):
        e, w = mr.parse_list_lines(["# c", "", "web01", "10.6.0.101", "planned,10.6.0.50,bad", " ,x"])
        self.assertEqual(e, [("web01", None), ("10.6.0.101", None), ("planned", ["10.6.0.50"])])
        self.assertEqual(len(w), 2)

    def test_tokens_are_separate(self):
        self.assertEqual(mr.parse_tokens(["web01, 10.6.0.101", "db"]),
                         [("web01", None), ("10.6.0.101", None), ("db", None)])

    def test_ip_resolves_to_its_only_owner_and_merges(self):
        vms = snapshot_data()["vms"]
        out, notes = mr.merge_entries([("web01", None), ("10.6.0.101", None), ("10.6.0.102", None)], vms)
        self.assertEqual(out, [("web01", ["10.6.0.101"]), ("web02", ["10.6.0.102"])])
        self.assertEqual(notes["web01"]["requested_as"], ["web01", "10.6.0.101"])
        self.assertEqual(notes["web02"]["found_by_ip"], "10.6.0.102")

    def test_shared_ip_stays_ambiguous(self):
        out, notes = mr.merge_entries([("10.6.5.5", None)], snapshot_data()["vms"])
        self.assertEqual(out, [("10.6.5.5", None)])
        self.assertEqual(notes["10.6.5.5"]["ambiguous"], ["dup-a", "dup-b"])

    def test_given_ip_of_another_vm_is_flagged(self):
        data = snapshot_data()
        cases = {"web01,10.6.0.102": ["address mismatch: 10.6.0.102 belongs to web02, not to web01"],
                 "web01,10.6.0.101": [],
                 "newsrv,10.6.0.101": ["address mismatch: 10.6.0.101 belongs to web01, not to newsrv"]}
        for line, want in cases.items():
            entries, _ = mr.parse_list_lines([line])
            merged, notes = mr.merge_entries(entries, data["vms"])
            rows = mr.server_rows(merged, notes, analyze(data, merged), data)
            got = [p.split(" (check")[0] for p in rows[0]["problems"] if p.startswith("address mismatch")]
            self.assertEqual(got, want, line)

    def test_suggestions(self):
        self.assertEqual(mr.suggest_names("web", snapshot_data()["vms"]), ["web01", "web02"])
        self.assertEqual(mr.suggest_names("wbe01", snapshot_data()["vms"])[0], "web01")


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cap = mr.load_capture(make_capture(self.tmp), HOST)
        self.data = snapshot_data()

    def _servers(self, entries):
        merged, notes = mr.merge_entries(entries, self.data["vms"])
        an = analyze(self.data, merged)
        return mr.server_rows(merged, notes, an, self.data), an

    def test_server_rows_and_rule_selection(self):
        rows, an = self._servers([("10.6.0.101", None), ("nosuchvm", None), ("10.6.5.5", None)])
        self.assertEqual([r["status"] for r in rows], ["ok", "not_found", "ambiguous"])
        self.assertEqual(rows[0]["vm"], "web01")
        self.assertEqual(rows[0]["found_by_ip"], "10.6.0.101")
        self.assertIn("WEB", rows[0]["groups"])
        ok = {r["external_id"] for r in rows if r["status"] == "ok"}
        hits = [{**h, "info": {**h["info"], "by_side": {e: s for e, s in h["info"]["by_side"].items()
                                                         if e in ok}}} for h in an["hits"]]
        hits = [h for h in hits if h["info"]["by_side"]]
        sel, exc = mr.select_rules(hits, self.cap)
        self.assertEqual([s["key"] for s in sel], ["app-pol/r1"])
        self.assertEqual([x["reason"] for x in exc], ["NSX default section (never copied)"])
        self.assertEqual(sel[0]["matched"], [{"server": "web01", "sides": ["Src"]}])
        # The source rule number (the capture's numeric rule_id), for vRNI and logs.
        self.assertEqual(sel[0]["rule_number"], 1001)

    def test_rules_follow_nsx_order(self):
        hits = [{"rule": r, "info": {"by_side": {"vm-1": ["Src"]}}, "ext_id_to_name": {"vm-1": "web01"}}
                for r in self.data["rules"][:3]]
        sel, _ = mr.select_rules(hits, self.cap)
        self.assertEqual([s["key"] for s in sel], ["infra-pol/dns", "app-pol/r1", "app-pol/r2"])

    def test_infrastructure_rules_left_out(self):
        hits = [{"rule": r, "info": {"by_side": {"vm-1": ["Src"]}}, "ext_id_to_name": {"vm-1": "web01"}}
                for r in self.data["rules"][:3]]
        sel, exc = mr.select_rules(hits, self.cap, exclude_categories=["Infrastructure"])
        self.assertEqual([s["key"] for s in sel], ["app-pol/r1", "app-pol/r2"])
        self.assertEqual([(x["key"], x["reason"], x["error"]) for x in exc],
                         [("infra-pol/dns", "Infrastructure rule (left out of migration requests)", False)])
        # A group used only by an Infrastructure rule gets no D sibling.
        cap = mr.load_capture(make_capture(Path(tempfile.mkdtemp())), HOST)
        cap.rules[("app-pol", "r1")]["destination_groups"] = [G + "other"]
        data = snapshot_data()
        data["group_to_members"][G + "db"] = {"vm-1"}
        merged, notes = mr.merge_entries([("web01", None)], data["vms"])
        rows = mr.server_rows(merged, notes, analyze(data, merged), data)
        scope, left = mr.d_scope(rows, data, cap, ["Infrastructure"])
        self.assertNotIn(G + "db", scope)
        self.assertIn({"group": "DB", "reason": "only in Infrastructure rules (left out of the request)"}, left)
        scope, _ = mr.d_scope(rows, data, cap)
        self.assertIn(G + "db", scope)

    def test_rule_approval_sheet(self):
        """Mike, 2026-10-15: every candidate starts at needs_approval: true; only
        rules set to false are copied."""
        cands = [{"key": "app-pol/r1", "rule_number": 1001, "policy_name": "App policy", "rule_name": "web to db",
                  "action": "ALLOW", "source_groups": [G + "web"], "destination_groups": [G + "db"],
                  "services": ["/infra/services/HTTPS"]},
                 {"key": "app-pol/r2", "rule_number": 1002, "policy_name": "App policy", "rule_name": "unrelated",
                  "action": "ALLOW", "source_groups": [G + "other"], "destination_groups": ["ANY"], "services": []}]
        sel, held, warn = mr.apply_rule_approval(cands, None)
        self.assertEqual(([s["approval"] for s in sel], held, warn), (["needs approval"] * 2, [], []))
        rec = {"request_id": "r1", "inputs": {"source_host": "lm1.h"}, "group_names": {G + "web": "WEB"}}
        sheet = self.tmp / "rule_approval.yaml"
        sheet.write_text(mr.approval_sheet_text(rec, cands, []), encoding="utf-8")
        self.assertIn("needs_approval: true", sheet.read_text())
        self.assertEqual(mr.read_approval_sheet(sheet)["pending"], ["app-pol/r1", "app-pol/r2"])
        # Approve r1 only: r1 is copied, r2 needs approval, a new candidate needs approval too.
        sheet.write_text(sheet.read_text().replace("needs_approval: true", "needs_approval: false", 1))
        decided = mr.read_approval_sheet(sheet)
        self.assertEqual(decided["approved"], ["app-pol/r1"])
        new = dict(cands[1], key="app-pol/r3", rule_number=1003)
        sel, held, warn = mr.apply_rule_approval(cands + [new], decided)
        self.assertEqual([s["key"] for s in sel], ["app-pol/r1"])
        self.assertEqual([(h["key"], h["reason"]) for h in held],
                         [("app-pol/r2", "needs approval (rule approval sheet)"),
                          ("app-pol/r3", "needs approval (new since the rule approval sheet was written)")])
        self.assertEqual(warn, [])
        # A recreated rule (new number) and an approved rule that is gone are flagged.
        sel, held, warn = mr.apply_rule_approval([dict(cands[0], rule_number=2001)],
                                                 {**decided, "approved": ["app-pol/r1", "gone/r9"]})
        self.assertEqual(len(warn), 2)
        self.assertIn("rule # was 1001 on the sheet, 2001 now", warn[0])
        bad = self.tmp / "bad.yaml"
        bad.write_text("rules:\n- key: app-pol/r1\n  needs_approval: maybe\n")
        with self.assertRaises(ValueError):
            mr.read_approval_sheet(bad)

    def test_d_scope_follows_the_approved_rules(self):
        rows, _ = self._servers([("web01", None)])
        scope, left = mr.d_scope(rows, self.data, self.cap, (), {"app-pol/r2"})
        self.assertNotIn(G + "web", scope)
        self.assertIn({"group": "WEB", "reason": "only in rules that need approval"}, left)
        scope, _ = mr.d_scope(rows, self.data, self.cap, (), {"app-pol/r1"})
        self.assertIn(G + "web", scope)

    def test_source_siblings_are_never_copied(self):
        """Mike, 2026-10-15: lm1's _avs_ips siblings must not be copied to the
        destination by Workflow A (found after a second request)."""
        import copy as _copy
        cap = _copy.deepcopy(self.cap)
        cap.groups[G + "web_avs_ips"] = {"id": "web_avs_ips", "path": G + "web_avs_ips",
                                         "expression": [{"resource_type": "IPAddressExpression",
                                                         "ip_addresses": ["10.8.0.101"]}]}
        cap.groups[G + "web_lm3_ips"] = {"id": "web_lm3_ips", "path": G + "web_lm3_ips",
                                         "description": "IP-only sibling of web; generated 2026-10-07",
                                         "expression": []}
        rule = cap.rules[("app-pol", "r1")]
        rule["source_groups"] = [G + "web", G + "web_avs_ips", G + "web_lm3_ips"]
        drop = mr.sibling_group_paths(cap, ["_np_ips", "_avs_ips"])
        self.assertEqual(drop, {G + "web_avs_ips", G + "web_lm3_ips"})     # by suffix and by description
        stripped, empty = mr.strip_sibling_refs(rule, drop)
        self.assertEqual((stripped["source_groups"], empty), ([G + "web"], []))
        _, empty = mr.strip_sibling_refs({"source_groups": [G + "web_avs_ips"]}, drop)
        self.assertEqual(empty, ["source_groups"])                          # would read as ANY: refused
        hit = {"rule": self.data["rules"][0], "info": {"by_side": {"vm-1": ["Src"]}},
               "ext_id_to_name": {"vm-1": "web01"}}
        sel, _ = mr.select_rules([hit], cap)
        clo = mr.dependency_closure(cap, sel, drop)
        self.assertNotIn(G + "web_avs_ips", clo["groups"])
        self.assertEqual(clo["sibling_groups"], sorted(drop))
        out = self.tmp / "bundle_sib"
        mr.write_bundle(out, cap, sel, clo, drop)
        doc = yaml.safe_load(next((out / "rules" / "security-policies").glob("*/rules/*.yaml")).read_text())
        self.assertEqual(doc["source_groups"], [G + "web"])
        self.assertFalse(list((out / "groups" / "groups").glob("web_*_ips*.yaml")))

    def test_closure_and_bundle(self):
        hit = {"rule": self.data["rules"][0], "info": {"by_side": {"vm-1": ["Src"]}},
               "ext_id_to_name": {"vm-1": "web01"}}
        sel, _ = mr.select_rules([hit], self.cap)
        clo = mr.dependency_closure(self.cap, sel)
        self.assertEqual(clo["groups"], sorted(G + g for g in ("web", "web-child", "db", "scope-g")))
        self.assertEqual(clo["services"], ["/infra/services/svc-a", "/infra/services/svc-bundle"])
        self.assertEqual(clo["builtin_services"], ["/infra/services/HTTPS"])
        self.assertEqual(clo["segment_paths"], ["/infra/segments/seg-1"])
        out = self.tmp / "bundle"
        man = mr.write_bundle(out, self.cap, sel, clo)
        self.assertEqual((man["rules"], man["groups"], man["services"]), (1, 4, 2))
        rule_files = list((out / "rules" / "security-policies").glob("*/rules/*.yaml"))
        self.assertEqual([f.name for f in rule_files], ["0001_r1.yaml"])
        doc = yaml.safe_load(rule_files[0].read_text())
        self.assertEqual(doc["_parent_policy_id"], "app-pol")
        self.assertTrue((out / "policies" / "security-policies" / "app-pol" / "policy.yaml").is_file())
        self.assertFalse((out / "policies" / "security-policies" / "infra-pol").exists())
        c_web = yaml.safe_load((out / "c_input" / "web.yaml").read_text())
        self.assertIn("10.6.0.101", json.dumps(c_web))

    def test_d_scope_and_trimmed_input(self):
        rows, _ = self._servers([("web01", None)])
        scope, left = mr.d_scope(rows, self.data, self.cap)
        self.assertEqual(sorted(scope), [G + "web"])
        self.assertEqual(scope[G + "web"]["servers"], {"web01": ["10.6.0.101"]})
        out = self.tmp / "d_input"
        mr.write_d_input(out, self.cap, scope)
        g = yaml.safe_load((out / "web.yaml").read_text())
        kinds = [e["resource_type"] for e in g["expression"]]
        self.assertIn("Condition", kinds)
        self.assertIn("PathExpression", kinds)
        self.assertEqual([e["ip_addresses"] for e in g["expression"]
                          if e["resource_type"] == "IPAddressExpression"], [["10.6.0.101"]])

    def test_d_scope_leaves_out_groups_in_no_rule(self):
        data = snapshot_data()
        data["group_to_members"][G + "scope-g"] = {"vm-1"}
        merged, notes = mr.merge_entries([("web01", None)], data["vms"])
        rows = mr.server_rows(merged, notes, analyze(data, merged), data)
        scope, left = mr.d_scope(rows, data, self.cap)
        self.assertNotIn(G + "scope-g", scope)
        self.assertIn({"group": "SCOPE-G", "reason": "not in any rule's source or destination"}, left)

    def test_d_builder_maps_only_the_servers_addresses(self):
        """The unchanged build_sibling_groups.py, run on the trimmed input."""
        rows, _ = self._servers([("web01", None)])
        scope, _ = mr.d_scope(rows, self.data, self.cap)
        din = self.tmp / "d_input"
        mr.write_d_input(din, self.cap, scope)
        csv = self.tmp / "map.csv"
        csv.write_text("old_subnet,new_subnet\n10.6.0.0/24,10.8.0.0/24\n", encoding="utf-8")
        r = subprocess.run([sys.executable, str(ROOT / "tools/nsx/build_sibling_groups.py"),
                            "--groups-dir", str(din), "--label", HOST, "--output-base", str(self.tmp / "d"),
                            "--appendix", "_lm3_ips", "--csv-remap", str(csv), "--skip-segment-groups"],
                           cwd=ROOT, capture_output=True, text=True,
                           env={**__import__("os").environ, "PYTHONPATH": str(ROOT / "app"),
                                "NSX_LOG_DIR": str(self.tmp / "logs")})
        smap = json.loads((self.tmp / "d" / "nsx_sibling_groups" / HOST / "sibling_map.json").read_text())
        # web has a segment member, so the builder skips it exactly as WF-D does.
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        self.assertEqual(smap["map"], [])
        self.assertEqual([x["reason_code"] for x in smap["no_sibling"]], ["segment_group"])

        # Without the segment member the sibling holds the server's mapped address only.
        g = yaml.safe_load((din / "web.yaml").read_text())
        g["expression"] = [e for e in g["expression"] if e["resource_type"] != "PathExpression"]
        (din / "web.yaml").write_text(yaml.safe_dump(g), encoding="utf-8")
        subprocess.run([sys.executable, str(ROOT / "tools/nsx/build_sibling_groups.py"),
                        "--groups-dir", str(din), "--label", HOST, "--output-base", str(self.tmp / "d"),
                        "--appendix", "_lm3_ips", "--csv-remap", str(csv), "--skip-segment-groups"],
                       cwd=ROOT, capture_output=True, text=True, check=True,
                       env={**__import__("os").environ, "PYTHONPATH": str(ROOT / "app"),
                            "NSX_LOG_DIR": str(self.tmp / "logs")})
        smap = json.loads((self.tmp / "d" / "nsx_sibling_groups" / HOST / "sibling_map.json").read_text())
        self.assertEqual([(m["sibling_id"], m["ips_sibling_mapped"]) for m in smap["map"]],
                         [("web_lm3_ips", ["10.8.0.101"])])

    def test_amendments(self):
        smap = {"map": [{"original_id": "web", "sibling_id": "web_lm3_ips", "original_display_name": "WEB"}]}
        rows = mr.amendments(mr.source_rules(self.cap), smap)
        self.assertEqual([(r["key"], r["adds"][0]["field"], r["adds"][0]["sibling"]) for r in rows],
                         [("app-pol/r1", "source_groups", "web_lm3_ips")])
        rule = dict(self.cap.rules[("app-pol", "r1")])
        rule["source_groups"] = [G + "web", G + "web_lm3_ips"]
        self.assertEqual(mr.amendments([(self.cap.policies["app-pol"], rule)], smap), [])


class ModelTests(unittest.TestCase):
    def _model(self, cap, ips=("10.6.0.101",), rule_tweak=None):
        if rule_tweak:
            cap.rules[("app-pol", "r1")] = {**cap.rules[("app-pol", "r1")], **rule_tweak}
        rec = {"servers": [{"key": "web01", "status": "ok", "vm": "web01", "external_id": "vm-1",
                            "ips": list(ips), "new_ips": {i: [i.replace("10.6", "10.8")] for i in ips}}],
               "rules": [{"key": "app-pol/r1", "policy_id": "app-pol", "rule_id": "r1"}],
               "c_amend": [], "d_amend": []}
        clo = {"groups": [G + "web"], "services": []}
        return mr.build_model(rec, cap, clo, {"map": []}, {"map": []}, None)

    def test_identical_and_changed(self):
        tmp = Path(tempfile.mkdtemp())
        a = self._model(mr.load_capture(make_capture(tmp), HOST))
        b = self._model(mr.load_capture(make_capture(tmp), HOST))
        self.assertEqual(a["digest"], b["digest"])
        self.assertEqual(mr.compare_models(a, b), {})
        # NSX metadata does not count as a change.
        c = self._model(mr.load_capture(make_capture(tmp), HOST), rule_tweak={"_revision": 7, "rule_id": 9})
        self.assertEqual(mr.compare_models(a, c), {})
        d = self._model(mr.load_capture(make_capture(tmp), HOST), rule_tweak={"action": "DROP"})
        self.assertEqual(mr.compare_models(a, d), {"rules": {"added": [], "removed": [],
                                                             "changed": ["app-pol/r1"]}})
        self.assertEqual(mr.server_gate(a, d), [])

    def test_gate_stops_on_server_change(self):
        tmp = Path(tempfile.mkdtemp())
        a = self._model(mr.load_capture(make_capture(tmp), HOST))
        b = self._model(mr.load_capture(make_capture(tmp), HOST), ips=("10.6.0.111",))
        problems = mr.server_gate(a, b)
        self.assertTrue(any("addresses were 10.6.0.101, now 10.6.0.111" in p for p in problems))


class ReportTests(unittest.TestCase):
    def test_server_change_is_listed_not_a_stop(self):
        """Mike, 2026-10-16: a changed server no longer stops the run."""
        run = {"request_id": "r", "created_at": "t", "source_host": "lm1.h", "captured_at": "t",
               "approved_digest": "a", "digest": "b"}
        md = mr.render_delta_md(run, {}, [], False, {}, ["web01: addresses were 10.6.0.101, now 10.6.0.111"])
        self.assertNotIn("STOPPED", md)
        self.assertIn("The request's servers changed since approval", md)
        self.assertIn("- web01: addresses were 10.6.0.101, now 10.6.0.111", md)
        stopped = mr.render_delta_md(run, {}, ["subnet map data/m.csv changed since approval"], False, {}, [])
        self.assertIn("STOPPED", stopped)

    def test_preview_counts(self):
        rows = [{"status": "dry_run", "exists_on_target": False}, {"status": "dry_run", "exists_on_target": True},
                {"status": "skipped_unchanged"}, {"status": "failed"}, {"status": "skipped"},
                {"status": "dry_run", "refs_added_total": 2}, {"status": "no_change"}]
        self.assertEqual(mr.preview_counts(rows),
                         {"new": 1, "update": 2, "unchanged": 2, "skipped": 1, "failed": 1})

    def test_palo_member_gaps(self):
        plan = {"writes": [{"kind": "address-group", "name": "web_np_ips",
                            "entry": {"static": {"member": ["a", "b", "c"]}}}]}
        doc = {"results": [{"kind": "address-group", "name": "web_np_ips", "differs": ["static"],
                            "existing": {"static": {"member": ["a"]}}}]}
        self.assertEqual(mr._palo_existing_gaps(doc, plan), [["web_np_ips", "2", "b, c"]])

    def test_ip_covered(self):
        self.assertTrue(mr.ip_covered("10.6.0.5", ["10.6.0.0/24"]))
        self.assertTrue(mr.ip_covered("10.6.0.5", ["10.6.0.1-10.6.0.9"]))
        self.assertFalse(mr.ip_covered("10.6.1.5", ["10.6.0.0/24", "10.6.0.5"]))


class RenderTests(unittest.TestCase):
    def test_request_report_renders_with_request_shaped_data(self):
        rec = {
            "request_id": "nsx-lm1_to_nsx-lm3/20261007_000000", "created_at": "t", "captured_at": "t",
            "inputs": {"name": "wave 1", "source_host": "lm1.h", "destination_host": "lm3.h",
                       "c_appendix": "_np_ips", "d_appendix": "_lm3_ips", "subnet_map": "data/m.csv"},
            "group_names": {G + "web": "WEB"},
            "summary": {"servers": 2, "servers_ok": 1, "servers_attention": 1, "rules": 1, "policies": 1,
                        "groups": 1, "services": 0, "c_siblings": 1, "d_siblings": 1, "d_rules_amended": 1,
                        "palo_writes": 0},
            "servers": [{"key": "web01", "requested_as": ["10.6.0.101"], "vm": "web01", "ips": ["10.6.0.101"],
                         "new_ips": {"10.6.0.101": ["10.8.0.101"]}, "groups": ["WEB"], "rules": 1,
                         "status": "ok", "problems": [], "suggestions": []},
                        {"key": "web1", "requested_as": ["web1"], "vm": None, "ips": [], "groups": [], "rules": 0,
                         "status": "not_found", "problems": ["no VM with this name on the source"],
                         "suggestions": ["web01"]}],
            "service_names": {"/infra/services/ICMP-ALL": "ICMP ALL"},
            "rules": [{"key": "app/r1", "policy_id": "app", "policy_name": "App", "rule_name": "web to db",
                       "disabled": False, "global": False,
                       "action": "ALLOW", "source_groups": [G + "web"], "destination_groups": ["ANY"],
                       "services": ["/infra/services/HTTPS", "/infra/services/ICMP-ALL"], "scope": ["ANY"],
                       "matched": [{"server": "web01", "sides": ["Src"]}]}],
            "excluded_rules": [], "bundle": {},
            "closure": {"groups": [G + "web"], "services": [], "builtin_services": ["/infra/services/HTTPS"],
                        "segment_paths": [], "context_profiles": [], "unresolved_groups": []},
            "c_siblings": [{"sibling_id": "web_np_ips", "sibling": "WEB_np_ips", "original": "WEB",
                            "ips": ["10.6.0.101"]}],
            "c_amend": [], "d_siblings": [{"sibling_id": "web_lm3_ips", "sibling": "WEB_lm3_ips", "original": "WEB",
                                           "server": "web01", "source_ip": "10.6.0.101", "mapped_ip": "10.8.0.101"}],
            "d_no_sibling": [], "d_amend": [{"policy_name": "App", "rule_name": "web to db",
                                             "adds": [{"field": "source_groups", "sibling": "web_lm3_ips",
                                                       "sibling_name": "WEB_lm3_ips"}]}],
            "palo": None, "warnings": [], "paths": {"record": "r", "bundle": "b", "c": "c", "d": "d"},
            "model": {"digest": "abc"}}
        md = mr.render_request_md(rec, {"a": {"rules": {"new": 1}}})
        self.assertIn("| web01 ", md)
        self.assertIn("10.6.0.101 to 10.8.0.101", md)
        self.assertIn("did you mean web01?", md)
        self.assertIn("WEB", md)
        # Display names, not ids (Mike, 2026-10-14).
        self.assertIn("HTTPS, ICMP ALL", md)
        self.assertIn("rule #", md)
        self.assertIn("WEB_np_ips", md)
        self.assertIn("WEB_lm3_ips (source)", md)
        self.assertNotIn("web_np_ips", md)
        self.assertNotIn("web_lm3_ips", md)
        names = mr.display_names(rec)
        delta = {"rules": {"added": [], "removed": [], "changed": ["app/r1"]},
                 "d_amend": {"added": ["app/r1 source_groups +web_lm3_ips"], "removed": [], "changed": []}}
        run = {"request_id": "r", "created_at": "t", "source_host": "lm1.h", "captured_at": "t",
               "approved_digest": "a", "digest": "b"}
        dmd = mr.render_delta_md(run, delta, [], False, names)
        self.assertIn("App / web to db", dmd)
        self.assertIn("App / web to db: source +WEB_lm3_ips", dmd)
        self.assertNotIn("app/r1", dmd)
        self.assertNotIn("\u2014", md)


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("migration_request_cli",
                                                      ROOT / "tools/multisite/migration_request.py")
        cls.cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.cli)

    def test_phase_targets_and_paths(self):
        work = Path("/w")
        inputs = {"source": "nsx-lm1", "destination": "nsx-lm3", "source_host": "lm1.h",
                  "destination_host": "lm3.h"}
        a = self.cli.phase_steps(work, inputs, "a", True)
        self.assertEqual([s["cmd"][4] for s in a], ["nsx-lm3"] * 4)
        self.assertIn(work / "bundle" / "rules" / "security-policies", a[3]["cmd"])
        self.assertIn("strip", a[1]["cmd"])
        self.assertEqual(a[0]["cmd"][-1], "--apply")
        c = self.cli.phase_steps(work, inputs, "c", False)
        self.assertEqual([s["cmd"][4] for s in c], ["nsx-lm3", "nsx-lm3"])
        self.assertIn(work / "c" / "nsx_sibling_groups" / "lm1.h" / "groups", c[0]["cmd"])
        d2a = self.cli.phase_steps(work, inputs, "d2a", False)
        d3 = self.cli.phase_steps(work, inputs, "d3", False)
        self.assertEqual(d2a[0]["cmd"][4], "nsx-lm1")
        self.assertEqual(d3[0]["cmd"][4], "nsx-lm1")
        self.assertIn(work / "d" / "rules_amend" / "lm1.h" / "push_report", d3[0]["cmd"])

    def test_server_list_default_and_overrides(self):
        tmp = Path(tempfile.mkdtemp())
        dflt = tmp / "migration_request_servers.txt"
        dflt.write_text("# wave 1\nweb01\n10.6.0.101\n", encoding="utf-8")
        e, w, src = self.cli.load_server_entries(None, None, default=dflt)
        self.assertEqual(e, [("web01", None), ("10.6.0.101", None)])
        self.assertEqual((w, src[0]["entries"], len(src[0]["sha256"])), ([], 2, 64))
        # Servers on the command line: the tracked file is not read.
        e, _, src = self.cli.load_server_entries(["db01"], None, default=dflt)
        self.assertEqual((e, src), ([("db01", None)], [{"command_line": 1}]))
        other = tmp / "other.txt"
        other.write_text("x,10.6.0.5\n", encoding="utf-8")
        e, _, _ = self.cli.load_server_entries(["db01"], str(other), default=dflt)
        self.assertEqual(e, [("x", ["10.6.0.5"]), ("db01", None)])
        empty = tmp / "empty.txt"
        empty.write_text("# only comments\n", encoding="utf-8")
        with self.assertRaises(SystemExit):
            self.cli.load_server_entries(None, None, default=empty)

    def test_change_record_on_every_push_and_palo_write(self):
        from common.description_note import append_note, change_note
        note = change_note("CHG1", "mike", "2026-10-14")
        self.assertEqual(note, "Ticket CHG1 | mike | 2026-10-14")
        self.assertEqual(change_note(None, "mike", "2026-10-14"), "Ticket none | mike | 2026-10-14")
        self.assertEqual(append_note("web servers", note), "web servers [Ticket CHG1 | mike | 2026-10-14]")
        self.assertEqual(append_note(append_note("x", note), note), append_note("x", note))
        long = append_note("y" * 2000, note, limit=100)
        self.assertEqual(len(long), 100)
        self.assertTrue(long.endswith(f"... [{note}]"))
        inputs = {"source": "nsx-lm1", "destination": "nsx-lm3", "source_host": "lm1.h",
                  "destination_host": "lm3.h", "change": {"ticket": "CHG1", "user": "mike", "date": "2026-10-14"}}
        for phase in ("a", "c", "d2a", "d3"):
            for st in self.cli.phase_steps(Path("/w"), inputs, phase, True):
                cmd = [str(c) for c in st["cmd"]]
                self.assertEqual(cmd[cmd.index("--description-note") + 1], note, st["label"])
        old = {k: v for k, v in inputs.items() if k != "change"}
        self.assertNotIn("--description-note", [str(c) for c in self.cli.phase_steps(Path("/w"), old, "a", True)[0]["cmd"]])
        plan = {"writes": [{"kind": "address", "entry": {"description": "NSX VM web01"}},
                           {"kind": "security-rule", "entry": {}}]}
        mr.tag_writes(plan, note)
        self.assertEqual([w["entry"]["description"] for w in plan["writes"]],
                         [f"NSX VM web01 [{note}]", f"[{note}]"])

    def test_d_appendix_from_env_or_command_line(self):
        from unittest import mock
        with mock.patch.dict("os.environ", {"OBJECT_APPENDIX_AVS": "_avs_ips"}):
            self.assertEqual(self.cli.d_appendix(None), "_avs_ips")
            self.assertEqual(self.cli.d_appendix("_x_ips"), "_x_ips")
        with mock.patch.dict("os.environ", {"OBJECT_APPENDIX_AVS": ""}):
            with self.assertRaises(SystemExit):
                self.cli.d_appendix(None)

    def test_device_group_from_env_or_command_line(self):
        from unittest import mock
        with mock.patch.dict("os.environ", {"PANORAMA_DEVICE_GROUP": "dg-5"}):
            self.assertEqual(self.cli.device_group(None), "dg-5")
            self.assertEqual(self.cli.device_group("dg-4"), "dg-4")
        with mock.patch.dict("os.environ", {"PANORAMA_DEVICE_GROUP": " "}):
            self.assertIsNone(self.cli.device_group(None))

    def test_approve_refuses_until_a_rule_is_approved(self):
        import argparse
        tmp = Path(tempfile.mkdtemp())
        base = {"request_id": "r", "errors": [], "model": {"digest": "d"}, "rules": [{"key": "p/r"}]}
        for inputs, rules in (({}, [{"key": "p/r"}]), ({"rule_approval": {"approved": []}}, [])):
            (tmp / "request.json").write_text(json.dumps({**base, "inputs": inputs, "rules": rules}))
            rc = self.cli.cmd_approve(argparse.Namespace(request=str(tmp), change_ref="C", approved_by="M",
                                                         accept_errors=False))
            self.assertEqual(rc, 2)
            self.assertFalse((tmp / "approval.json").exists())

    def test_rollback_reverse_order_with_allow_delete(self):
        inputs = {"source": "nsx-lm1", "destination": "nsx-lm3", "source_host": "lm1.h",
                  "destination_host": "lm3.h"}
        rb = self.cli.rollback_steps(Path("/w"), inputs, "a", False)
        self.assertEqual([s["label"] for s in rb],
                         ["a4_rules_revert", "a3_policies_revert", "a2_groups_revert", "a1_services_revert"])
        self.assertIn("--allow-delete", rb[2]["cmd"])
        self.assertEqual(self.cli.rollback_steps(Path("/w"), inputs, "d2a", True)[0]["cmd"][4], "nsx-lm1")


class ReportsFolderTests(unittest.TestCase):
    """reports/: every readable file of a request or run in one folder under
    numbered names (Mike, 2026-10-16)."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("mr_cli", ROOT / "tools" / "multisite" / "migration_request.py")
        cls.cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.cli)

    def _request(self) -> Path:
        req = Path(tempfile.mkdtemp())
        (req / "request.json").write_text(json.dumps({"request_id": "lm1_to_lm3/R"}))
        (req / "servers.txt").write_text("vm1\n")
        (req / "request.md").write_text("# Migration request\n")
        (req / "palo").mkdir()
        (req / "palo" / "plan.md").write_text("plan")
        for ts in ("20261016_100000", "20261016_110000"):
            (req / "palo" / f"push_{ts}_dryrun.md").write_text(ts)
        (req / "palo" / "pan_set_commands.txt").write_text("set x")
        return req

    def test_request_folder_names_and_sheet_kept(self):
        req = self._request()
        (req / mr.LEGACY_APPROVAL_SHEET).write_text("rules: []\n")
        out = self.cli.collect_reports(req)
        names = sorted(p.name for p in out.iterdir())
        self.assertEqual(names, ["00_README.md", "01_servers.txt", "02_approval_report.md",
                                 "03_rule_approval_sheet.yaml", "04_palo_plan.md", "05_palo_dry_run.md",
                                 "06_palo_paste_set_commands.txt"])
        self.assertEqual((out / "05_palo_dry_run.md").read_text(), "20261016_110000")
        self.assertIn("Not approved yet", (out / "00_README.md").read_text())
        # The operator's edits to the sheet survive a re-collect; stale copies go.
        (req / mr.APPROVAL_SHEET).write_text("edited\n")
        (out / "09_stale.md").write_text("old")
        (out / "notes.txt").write_text("mine")
        self.cli.collect_reports(req)
        self.assertEqual((req / mr.APPROVAL_SHEET).read_text(), "edited\n")
        self.assertFalse((out / "09_stale.md").exists())
        self.assertTrue((out / "notes.txt").exists())

    def test_run_folder_phase_numbers_and_palo_by_time(self):
        run = Path(tempfile.mkdtemp())
        (run / "run.json").write_text(json.dumps({"request_id": "r", "gate": {"passed": True}}))
        (run / "delta.md").write_text("delta")
        (run / "implementation.md").write_text("impl")
        for phase, mode, name in (("a", "dryrun", "avs_run_report.md"), ("a", "apply", "avs_run_report.md"),
                                  ("d3", "rollback_apply", "rollback_report.md")):
            (run / "report" / phase / mode).mkdir(parents=True)
            (run / "report" / phase / mode / name).write_text(f"{phase} {mode}")
        palo = run / "palo"
        palo.mkdir()
        for f in ("push_20261015_010000_dryrun.md", "push_20261015_010100_apply.md",
                  "push_20261015_010200_dryrun.md"):
            (palo / f).write_text(f)
        (run / "report" / "a" / "verify").mkdir()
        (run / "report" / "a" / "verify" / "verify_avs_run.json").write_text(json.dumps(
            {"ok": True, "checks_total": 1, "checks_failed": 0, "source": "nsx-lm1", "target": "nsx-lm3",
             "checks": [{"check": "V6", "subject": "all target groups", "ok": True, "detail": "resolves"}]}))
        phases = {"a": {"dryrun": {"at": "2026-10-15T00:59:00+00:00", "ok": True},
                        "apply": {"at": "2026-10-15T00:59:30+00:00", "ok": True},
                        "verify": {"at": "2026-10-15T00:59:40+00:00", "ok": True}},
                  "palo": {"dryrun": {"at": "2026-10-15T01:00:20+00:00", "ok": True},
                           "apply": {"at": "2026-10-15T01:01:30+00:00", "ok": True},
                           "verify": {"at": "2026-10-15T01:02:10+00:00", "ok": True}}}
        (run / "phases.json").write_text(json.dumps(phases))
        out = self.cli.collect_reports(run)
        names = sorted(p.name for p in out.iterdir())
        self.assertEqual(names, ["00_README.md", "01_changes_since_approval.md", "02_implementation_plan.md",
                                 "11_A_copy_rules_dry_run.md", "12_A_copy_rules_apply.md",
                                 "13_A_copy_rules_verify.md", "45_D_rule_amend_rollback_apply.md",
                                 "51_Palo_panorama_dry_run.md", "52_Palo_panorama_apply.md",
                                 "53_Palo_panorama_verify.md"])
        self.assertEqual((out / "51_Palo_panorama_dry_run.md").read_text(), "push_20261015_010000_dryrun.md")
        self.assertEqual((out / "53_Palo_panorama_verify.md").read_text(), "push_20261015_010200_dryrun.md")
        self.assertIn("| V6", (out / "13_A_copy_rules_verify.md").read_text())
        readme = (out / "00_README.md").read_text()
        self.assertIn("Gate **passed**", readme)
        self.assertLess(readme.index("| a     | verify"), readme.index("| palo  | dryrun"))


if __name__ == "__main__":
    unittest.main()
