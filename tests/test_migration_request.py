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

    def test_rules_follow_nsx_order(self):
        hits = [{"rule": r, "info": {"by_side": {"vm-1": ["Src"]}}, "ext_id_to_name": {"vm-1": "web01"}}
                for r in self.data["rules"][:3]]
        sel, _ = mr.select_rules(hits, self.cap)
        self.assertEqual([s["key"] for s in sel], ["infra-pol/dns", "app-pol/r1", "app-pol/r2"])

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
            "rules": [{"policy_name": "App", "rule_name": "web to db", "disabled": False, "global": False,
                       "action": "ALLOW", "source_groups": [G + "web"], "destination_groups": ["ANY"],
                       "services": ["/infra/services/HTTPS"], "scope": ["ANY"],
                       "matched": [{"server": "web01", "sides": ["Src"]}]}],
            "excluded_rules": [], "bundle": {},
            "closure": {"groups": [G + "web"], "services": [], "builtin_services": ["/infra/services/HTTPS"],
                        "segment_paths": [], "context_profiles": [], "unresolved_groups": []},
            "c_siblings": [{"sibling_id": "web_np_ips", "original": "WEB", "ips": ["10.6.0.101"]}],
            "c_amend": [], "d_siblings": [{"sibling_id": "web_lm3_ips", "original": "WEB", "server": "web01",
                                           "source_ip": "10.6.0.101", "mapped_ip": "10.8.0.101"}],
            "d_no_sibling": [], "d_amend": [{"policy_name": "App", "rule_name": "web to db",
                                             "adds": [{"field": "source_groups", "sibling": "web_lm3_ips"}]}],
            "palo": None, "warnings": [], "paths": {"record": "r", "bundle": "b", "c": "c", "d": "d"},
            "model": {"digest": "abc"}}
        md = mr.render_request_md(rec, {"a": {"rules": {"new": 1}}})
        self.assertIn("| web01 ", md)
        self.assertIn("10.6.0.101 to 10.8.0.101", md)
        self.assertIn("did you mean web01?", md)
        self.assertIn("WEB", md)
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

    def test_rollback_reverse_order_with_allow_delete(self):
        inputs = {"source": "nsx-lm1", "destination": "nsx-lm3", "source_host": "lm1.h",
                  "destination_host": "lm3.h"}
        rb = self.cli.rollback_steps(Path("/w"), inputs, "a", False)
        self.assertEqual([s["label"] for s in rb],
                         ["a4_rules_revert", "a3_policies_revert", "a2_groups_revert", "a1_services_revert"])
        self.assertIn("--allow-delete", rb[2]["cmd"])
        self.assertEqual(self.cli.rollback_steps(Path("/w"), inputs, "d2a", True)[0]["cmd"][4], "nsx-lm1")


if __name__ == "__main__":
    unittest.main()
